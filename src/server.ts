import Aedes from 'aedes';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import { Duplex } from 'stream';
import { verifyAuthToken } from '@michaelhart/meshcore-decoder';
import { getAirportInfo } from 'airport-utils';
import { RateLimiter } from './rate-limiter';
import { getClientIP } from './ip-utils';
import { AbuseDetector } from './abuse-detector';
import { loadMqttConfig, loadAbuseConfig } from './config';

// Load and validate configuration
const mqttConfig = loadMqttConfig();
const abuseConfig = loadAbuseConfig();

const WS_PORT = mqttConfig.wsPort;
const HOST = mqttConfig.host;
const EXPECTED_AUDIENCE = mqttConfig.expectedAudience;

// Helper function to validate IATA airport codes
function isValidIATACode(code: string): boolean {
  try {
    getAirportInfo(code);
    return true;
  } catch {
    return false;
  }
}

// Client types
enum ClientType {
  SUBSCRIBER = 'subscriber',
  PUBLISHER = 'publisher'
}

// Subscriber roles
enum SubscriberRole {
  ADMIN = 1,           // Full access + can delete retained messages
  FULL_ACCESS = 2,     // Full access, no hidden data
  LIMITED = 3          // All access but with hidden/sensitive data filtered
}

// Load subscriber users from environment variables
// Format: SUBSCRIBER_1=username:password:role, SUBSCRIBER_2=username:password:role, etc.
// Role: 1=admin (full+delete), 2=full_access (no hidden data), 3=limited (filtered data)
const subscriberUsers = new Map<string, string>();
const subscriberRoles = new Map<string, SubscriberRole>();

let subscriberIndex = 1;
while (true) {
  const subscriberEnvVar = process.env[`SUBSCRIBER_${subscriberIndex}`];
  if (!subscriberEnvVar) {
    break;
  }
  
  const parts = subscriberEnvVar.split(':').map(s => s.trim());
  const username = parts[0];
  const password = parts[1];
  const roleStr = parts[2];
  
  if (username && password) {
    subscriberUsers.set(username, password);
    
    // Parse and store role (default to LIMITED if not specified or invalid)
    let role = SubscriberRole.LIMITED;
    if (roleStr) {
      const roleNum = parseInt(roleStr);
      if (roleNum === 1 || roleNum === 2 || roleNum === 3) {
        role = roleNum as SubscriberRole;
      }
    }
    subscriberRoles.set(username, role);
    
    const roleNames = {
      [SubscriberRole.ADMIN]: 'admin',
      [SubscriberRole.FULL_ACCESS]: 'full_access', 
      [SubscriberRole.LIMITED]: 'limited'
    };
    console.log(`[CONFIG] Loaded subscriber user: ${username} (role: ${roleNames[role]})`);
  } else {
    console.warn(`[CONFIG] Invalid format for SUBSCRIBER_${subscriberIndex}: ${subscriberEnvVar}`);
  }
  
  subscriberIndex++;
}

if (subscriberUsers.size === 0) {
  console.log('[CONFIG] No subscriber users configured');
}

// Create Aedes MQTT broker
const aedes = new Aedes();

// Rate limiting for failed connections
const rateLimiter = new RateLimiter(60000, 10, 300000);

// Abuse detection
const abuseDetector = new AbuseDetector(abuseConfig);

// Helper to get client identifier for logging
function getClientLogPrefix(client: any): string {
  if (!client) return '[UNKNOWN]';
  
  const clientType = client.clientType;
  if (clientType === ClientType.PUBLISHER && client.publicKey) {
    return `[O:${client.publicKey.substring(0, 8)}]`;
  } else if (clientType === ClientType.SUBSCRIBER && client.username) {
    return `[S:${client.username}]`;
  }
  return `[C:${client.id}]`;
}

// Authentication handler
aedes.authenticate = async (client, username, password, callback) => {
  const logPrefix = `[C:${client.id}]`;
  console.log(`${logPrefix} [AUTH] Authentication attempt - Username: ${username}`);

  try {
    const usernameStr = username?.toString() || '';
    const passwordStr = password?.toString() || '';

    // Check if this is a subscriber login
    if (subscriberUsers.has(usernameStr)) {
      const expectedPassword = subscriberUsers.get(usernameStr);
      if (passwordStr === expectedPassword) {
        const role = subscriberRoles.get(usernameStr) || SubscriberRole.LIMITED;
        console.log(`${logPrefix} [AUTH] ✓ Subscriber authenticated (${usernameStr}, role: ${role})`);
        (client as any).clientType = ClientType.SUBSCRIBER;
        (client as any).username = usernameStr;
        (client as any).role = role;
        
        // Mark stream as authenticated
        const stream = (client as any).conn;
        if (stream && stream.clientIP) {
          stream.authenticated = true;
        }
        
        callback(null, true);
      } else {
        console.log(`${logPrefix} [AUTH] ✗ Subscriber authentication failed - Invalid password`);
        callback(null, false);
      }
      return;
    }

    // Otherwise, check for JWT-based publisher authentication
    // Username format: v1_{UPPERCASE_PUBLIC_KEY}
    if (!usernameStr.startsWith('v1_')) {
      console.log(`${logPrefix} [AUTH] ✗ Invalid username format: ${usernameStr}`);
      callback(null, false);
      return;
    }

    const publicKey = usernameStr.substring(3).toUpperCase().trim();
    
    // Validate public key format (should be 64 hex characters)
    if (!/^[0-9A-F]{64}$/i.test(publicKey)) {
      console.log(`${logPrefix} [AUTH] ✗ Invalid public key format: ${publicKey}`);
      console.log(`${logPrefix} [AUTH] Public key length: ${publicKey.length}, hex dump: ${Buffer.from(publicKey).toString('hex')}`);
      callback(null, false);
      return;
    }

    if (!passwordStr || passwordStr.length === 0) {
      console.log(`${logPrefix} [AUTH] ✗ No password provided`);
      callback(null, false);
      return;
    }

    // Verify the auth token using meshcore-decoder
    const tokenPayload = await verifyAuthToken(passwordStr, publicKey);
    console.debug(`${logPrefix} [AUTH] Token input: "${passwordStr}"`);

    
    if (!tokenPayload) {
      console.log(`${logPrefix} [AUTH] ✗ Invalid token signature`);
      console.debug(`${logPrefix} [AUTH] Token input: "${passwordStr}"`);      
      console.debug(`${logPrefix} [AUTH] Public key: ${publicKey}`);
      console.debug(`${logPrefix} [AUTH] Token hex: ${Buffer.from(passwordStr).toString('hex')}`);
      callback(null, false);
      return;
    }
    
    // Validate audience claim if configured
    if (EXPECTED_AUDIENCE && tokenPayload.aud !== EXPECTED_AUDIENCE) {
      console.log(`${logPrefix} [AUTH] ✗ Invalid audience: ${tokenPayload.aud} (expected: ${EXPECTED_AUDIENCE})`);
      callback(null, false);
      return;
    }
    
    const shortKey = publicKey.substring(0, 8);
    console.log(`[O:${shortKey}] [AUTH] ✓ Publisher authenticated${tokenPayload.aud ? ` [aud: ${tokenPayload.aud}]` : ''}`);
    // Store the public key and client type with the client for later use
    (client as any).publicKey = publicKey;
    (client as any).tokenPayload = tokenPayload;
    (client as any).clientType = ClientType.PUBLISHER;
    
    // Mark stream as authenticated
    const stream = (client as any).conn;
    if (stream && stream.clientIP) {
      stream.authenticated = true;
    }
    
    // Initialize abuse detection tracking
    const clientIP = stream?.clientIP;
    abuseDetector.initializeClient(publicKey, `v1_${publicKey}`, clientIP);
    
    callback(null, true);
  } catch (error) {
    console.error(`${logPrefix} [AUTH] Error during authentication:`, error);
    callback(null, false);
  }
};

// Authorization handler (control topic access)
aedes.authorizePublish = (client, packet, callback) => {
  if (!client) {
    callback(new Error('No client'));
    return;
  }
  
  const logPrefix = getClientLogPrefix(client);
  const clientType = (client as any).clientType;
  
  // Important: Strip retain flag from /status messages to prevent stale data on ingestor restart
  // LWT (offline) messages are also STATUS messages and should NOT be retained
  if (packet.topic.endsWith('/status') && packet.retain) {
    console.log(`${logPrefix} [AUTHZ] Stripping retain flag from STATUS message -> ${packet.topic}`);
    packet.retain = false;
  }
  
  // Subscriber clients cannot publish (subscribe-only)
  if (clientType === ClientType.SUBSCRIBER) {
    const role = (client as any).role || SubscriberRole.LIMITED;
    
    // Admin subscribers (role 1) can publish empty retained messages to delete them
    if (role === SubscriberRole.ADMIN && packet.retain && packet.payload.length === 0) {
      console.log(`${logPrefix} [AUTHZ] ✓ Admin delete authorized -> ${packet.topic}`);
      callback(null);
      return;
    }
    
    console.log(`${logPrefix} [AUTHZ] ✗ Publish denied (subscriber) -> ${packet.topic}`);
    callback(new Error('Subscriber clients are subscribe-only'));
    return;
  }
  
  // Publisher clients can only publish to meshcore/* topics
  if (clientType === ClientType.PUBLISHER) {
    if (!packet.topic.startsWith('meshcore/')) {
      console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (not meshcore/*)`);
      callback(new Error('Publishers can only publish to meshcore/* topics'));
      return;
    }

    // Validate topic format
    // Required format: meshcore/{IATA}/{PUBLIC_KEY}/subtopic
    // Examples:
    //   meshcore/SEA/ABCD1234.../packets
    //   meshcore/SEA/ABCD1234.../status
    //   meshcore/SEA/ABCD1234.../internal (ADMIN only)
    const topicParts = packet.topic.split('/').map(part => part.trim());
    if (topicParts.length < 4) {
      console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (must be meshcore/IATA/PUBKEY/subtopic format)`);
      callback(new Error('Topic must be meshcore/IATA/PUBKEY/subtopic format (4 parts required)'));
      return;
    }
    
    const locationCode = topicParts[1].trim();
    const iataRegex = /^[A-Z]{3}$/;
    
    // Reject XXX explicitly (default placeholder value)
    if (locationCode === 'XXX') {
      console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (XXX not valid, configure actual IATA)`);
      console.log(`${logPrefix} [DISCONNECT] Closing client - Invalid location code: XXX`);
      console.log(`${logPrefix} [DISCONNECT] Full topic: "${packet.topic}"`);
      callback(new Error('XXX is a placeholder - please configure your actual IATA location code'));
      client.close();
      return;
    }
    
    // Allow "test" as a special testing region
    if (locationCode.toLowerCase() === 'test') {
      console.log(`${logPrefix} [AUTHZ] ✓ Using TEST region -> ${packet.topic}`);
      // Continue to validation, don't return here
    } else {
      // First check format (must be 3 uppercase letters, no normalization)
      if (!iataRegex.test(locationCode)) {
        console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid format)`);
        console.log(`${logPrefix} [DISCONNECT] Closing client - Invalid location format`);
        console.log(`${logPrefix} [DISCONNECT] Location code: "${locationCode}" (length: ${locationCode.length})`);
        console.log(`${logPrefix} [DISCONNECT] Location hex: ${Buffer.from(locationCode).toString('hex')}`);
        console.log(`${logPrefix} [DISCONNECT] Full topic: "${packet.topic}"`);
        callback(new Error('Location must be exactly 3 uppercase letters (e.g., SEA, PDX, BOS) or "test"'));
        client.close();
        return;
      }
      
      // Then check if it's a valid IATA code
      if (!isValidIATACode(locationCode)) {
        console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid IATA)`);
        console.log(`${logPrefix} [DISCONNECT] Closing client - Invalid IATA code`);
        console.log(`${logPrefix} [DISCONNECT] Location code: "${locationCode}"`);
        console.log(`${logPrefix} [DISCONNECT] Full topic: "${packet.topic}"`);
        callback(new Error('Location must be a valid IATA international airport code or "test"'));
        client.close();
        return;
      }
    }
    
    // Validate public key in topic (required - topicParts[2])
    const topicPublicKey = topicParts[2].trim().toUpperCase();
    
    // Validate it looks like a public key (64 hex chars)
    if (!/^[0-9A-F]{64}$/i.test(topicPublicKey)) {
      console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid pubkey format)`);
      console.log(`${logPrefix} [DISCONNECT] Closing client - Invalid public key format in topic`);
      console.log(`${logPrefix} [DISCONNECT] Topic pubkey: "${topicPublicKey}" (length: ${topicPublicKey.length})`);
      console.log(`${logPrefix} [DISCONNECT] Topic pubkey hex: ${Buffer.from(topicPublicKey).toString('hex')}`);
      console.log(`${logPrefix} [DISCONNECT] Full topic: "${packet.topic}"`);
      callback(new Error('Public key in topic must be 64 hex characters'));
      client.close();
      return;
    }
    
    // Validate topic public key matches authenticated client
    const clientPublicKey = (client as any).publicKey.toUpperCase();
    if (topicPublicKey !== clientPublicKey) {
      console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (pubkey mismatch)`);
      console.log(`${logPrefix} [DISCONNECT] Closing client - Public key mismatch`);
      console.log(`${logPrefix} [DISCONNECT] Topic pubkey:  "${topicPublicKey}"`);
      console.log(`${logPrefix} [DISCONNECT] Client pubkey: "${clientPublicKey}"`);
      console.log(`${logPrefix} [DISCONNECT] Full topic: "${packet.topic}"`);
      callback(new Error('Public key in topic must match authenticated public key'));
      client.close();
      return;
    }

    // Normalize the topic to UPPERCASE for the public key component
    // This prevents duplicate topics with different casing (e.g., 7553b337... vs 7553B337...)
    // Reconstruct topic with uppercase location code and public key
    const normalizedLocation = locationCode.toUpperCase();
    const normalizedTopic = `meshcore/${normalizedLocation}/${clientPublicKey}/${topicParts.slice(3).join('/')}`;
    
    // Update the packet topic to the normalized version
    if (packet.topic !== normalizedTopic) {
      console.log(`${logPrefix} [AUTHZ] Normalized topic: ${packet.topic} -> ${normalizedTopic}`);
      packet.topic = normalizedTopic;
    }

    // Validate that the message contains origin_id matching the authenticated public key
    try {
      const payload = packet.payload.toString('utf-8');
      const message = JSON.parse(payload);
      
      if (!message.origin_id) {
        console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (missing origin_id)`);
        callback(new Error('Message must contain origin_id field'));
        return;
      }
      
      // Normalize both to uppercase for comparison
      const messageOriginId = message.origin_id.toUpperCase();
      const normalizedClientKey = clientPublicKey.toUpperCase();
      
      if (messageOriginId !== normalizedClientKey) {
        console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (origin_id mismatch)`);
        callback(new Error('origin_id must match authenticated public key'));
        return;
      }
      
      // Track with abuse detector (no enforcement, just tracking)
      const iata = topicParts[1];
      
      // Check IATA changes
      const publicKey = (client as any).publicKey;
      const trustState = abuseDetector.getClientStats(publicKey);
      if (trustState) {
        abuseDetector.checkIataChange(trustState, iata);
        
        // Record packet
        abuseDetector.recordPacket(client, packet);
      }
      
      console.log(`${logPrefix} [AUTHZ] ✓ Publish authorized -> ${packet.topic}`);
      
      // Publish JWT payload to /internal topic (ADMIN-only, contains PII)
      const tokenPayload = (client as any).tokenPayload;
      if (tokenPayload) {
        // Extract location from topic (meshcore/IATA/... or meshcore/IATA/PUBKEY/...)
        const location = topicParts[1];
        const internalTopic = `meshcore/${location}/${clientPublicKey}/internal`;
        
        // Get trust state for internal message
        const trustState = abuseDetector.getClientStats(clientPublicKey);
        let trustMetrics: any = null;
        
        if (trustState) {
          const clockQuality = trustState.clockTracking.erraticJumps.length === 0 ? 'stable' :
                             trustState.clockTracking.erraticJumps.length < 3 ? 'syncing' : 'erratic';
          
          trustMetrics = {
            status: trustState.status,
            enforcement_enabled: abuseConfig.enforcementEnabled,
            totalPacketsReceived: trustState.totalPacketsReceived,
            totalPacketsSilenced: trustState.totalPacketsSilenced,
            duplicateCount: trustState.duplicateCount,
            anomalyCount: trustState.anomalyCount,
            anomalies: trustState.anomalies.slice(0, 20).map(a => ({
              type: a.type,
              details: a.details,
              timestamp: a.timestamp,
            })),
            peakRateObserved: Math.round(trustState.peakRateObserved * 100) / 100,
            tokenBucket: {
              tokens: Math.round(trustState.tokenBucket.tokens * 10) / 10,
              capacity: trustState.tokenBucket.capacity,
            },
            iataTracking: {
              currentIata: trustState.currentIata,
              iataChangeCount24h: trustState.iataChangeCount24h,
              iataHistory: trustState.iataHistory.map(h => h.iata),
            },
            clockTracking: {
              estimatedOffset: trustState.clockTracking.estimatedOffset ? 
                Math.round(trustState.clockTracking.estimatedOffset / 1000) : undefined,
              erraticJumpCount: trustState.clockTracking.erraticJumps.length,
              lastDeviceTimestamp: trustState.clockTracking.lastDeviceTimestamp,
              clockQuality,
            },
            recentIPs: trustState.recentIPs.slice(0, 10).map(ip => ({
              ip: ip.ip,
              connectionCount: ip.connectionCount,
              lastSeen: ip.lastSeen,
            })),
          };
        }
        
        const internalMessage = {
          origin_id: clientPublicKey,
          timestamp: Date.now(),
          jwt_payload: tokenPayload,
          trust_state: trustMetrics,
        };
        
        // Publish to internal topic (retained so admins can see it later)
        aedes.publish({
          cmd: 'publish',
          topic: internalTopic,
          payload: Buffer.from(JSON.stringify(internalMessage)),
          qos: 0,
          dup: false,
          retain: true
        }, (err) => {
          if (err) {
            console.error(`${logPrefix} [INTERNAL] Failed to publish JWT payload:`, err);
          } else {
            console.log(`${logPrefix} [INTERNAL] Published JWT payload -> ${internalTopic}`);
          }
        });
      }
      
      callback(null);
    } catch (error) {
      console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (invalid JSON or validation error)`);
      callback(new Error('Invalid message format or origin_id validation failed'));
    }
    return;
  }
  
  // Unknown client type
  console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (unknown client type)`);
  callback(new Error('Unknown client type'));
};

aedes.authorizeSubscribe = (client, subscription, callback) => {
  if (!client) {
    callback(new Error('No client'));
    return;
  }
  
  const logPrefix = getClientLogPrefix(client);
  const clientType = (client as any).clientType;
  
  // Publisher clients cannot subscribe (publish-only)
  if (clientType === ClientType.PUBLISHER) {
    console.log(`${logPrefix} [AUTHZ] ✗ Subscribe denied (publisher) -> ${subscription.topic}`);
    console.log(`${logPrefix} [DISCONNECT] Closing client - Publishers cannot subscribe`);
    callback(new Error('Publisher clients are publish-only'));
    client.close();
    return;
  }
  
  // Subscriber clients can subscribe to any topic (they're listeners)
  if (clientType === ClientType.SUBSCRIBER) {
    console.log(`${logPrefix} [AUTHZ] ✓ Subscribe authorized -> ${subscription.topic}`);
    callback(null, subscription);
    return;
  }
  
  // Unknown client type
  console.log(`${logPrefix} [AUTHZ] ✗ Subscribe denied -> ${subscription.topic} (unknown client type)`);
  callback(new Error('Unknown client type'));
};

// Track last seen status timestamp per origin_id to prevent race conditions
const lastStatusTimestamps = new Map<string, number>();

// Authorization handler for forwarding messages to subscribers (filter sensitive data)
aedes.authorizeForward = (client, packet) => {
  if (!client) {
    return packet;
  }
  
  const clientType = (client as any).clientType;
  const role = (client as any).role;
  
  // Block $SYS/* messages for non-admin subscribers (only role 1 can see system topics)
  if (clientType === ClientType.SUBSCRIBER && role !== SubscriberRole.ADMIN) {
    if (packet.topic.startsWith('$SYS/')) {
      return null; // Block delivery of this message
    }
  }
  
  // Critical: Block /internal topics for non-admin subscribers (contains PII)
  if (clientType === ClientType.SUBSCRIBER && role !== SubscriberRole.ADMIN) {
    if (packet.topic.includes('/internal')) {
      return null; // Block delivery of this message
    }
  }
  
  // Prevent stale status messages from overwriting newer ones (LWT race condition)
  if (packet.topic.endsWith('/status') && packet.payload && packet.payload.length > 0) {
    try {
      const message = JSON.parse(packet.payload.toString());
      const originId = message.origin_id;
      const timestamp = message.timestamp ? new Date(message.timestamp).getTime() : 0;
      
      if (originId && timestamp) {
        const lastTimestamp = lastStatusTimestamps.get(originId) || 0;
        
        if (timestamp < lastTimestamp) {
          // This is a stale status message (probably a delayed LWT)
          console.log(`[FILTER] Blocking stale status message for ${originId.substring(0, 8)} (${new Date(timestamp).toISOString()} < ${new Date(lastTimestamp).toISOString()})`);
          return null; // Block this stale message
        }
        
        // Update the last seen timestamp
        lastStatusTimestamps.set(originId, timestamp);
      }
    } catch (error) {
      // If parsing fails, let it through (don't block non-JSON status messages)
      console.debug(`[FILTER] Failed to parse status message for timestamp check:`, error);
    }
  }
  
  // Only filter for LIMITED role subscribers (role 3)
  if (clientType === ClientType.SUBSCRIBER && role === SubscriberRole.LIMITED) {
    // Filter status messages (meshcore/*/status) to remove stats, model, and firmware_version
    if (packet.topic.endsWith('/status') && packet.payload && packet.payload.length > 0) {
      try {
        const message = JSON.parse(packet.payload.toString());
        
        // Track if we need to filter anything
        let filtered = false;
        
        // Remove the stats object if it exists
        if (message.stats) {
          delete message.stats;
          filtered = true;
        }
        
        // Remove model if it exists
        if (message.model !== undefined) {
          delete message.model;
          filtered = true;
        }
        
        // Remove firmware_version if it exists
        if (message.firmware_version !== undefined) {
          delete message.firmware_version;
          filtered = true;
        }
        
        // Only create new packet if we actually filtered something
        if (filtered) {
          return {
            ...packet,
            payload: Buffer.from(JSON.stringify(message))
          };
        }
      } catch (error) {
        // If JSON parsing fails, just return the original packet
        console.debug(`[FILTER] Failed to parse status message for filtering:`, error);
      }
    }
    
    // Filter packet messages (meshcore/*/packets) to remove SNR, RSSI, score
    if (packet.topic.endsWith('/packets') && packet.payload && packet.payload.length > 0) {
      try {
        const message = JSON.parse(packet.payload.toString());
        
        // Remove radio metrics if they exist
        let filtered = false;
        if (message.SNR !== undefined) {
          delete message.SNR;
          filtered = true;
        }
        if (message.RSSI !== undefined) {
          delete message.RSSI;
          filtered = true;
        }
        if (message.score !== undefined) {
          delete message.score;
          filtered = true;
        }
        
        // Only create new packet if we actually filtered something
        if (filtered) {
          return {
            ...packet,
            payload: Buffer.from(JSON.stringify(message))
          };
        }
      } catch (error) {
        // If JSON parsing fails, just return the original packet
        console.debug(`[FILTER] Failed to parse packet message for filtering:`, error);
      }
    }
  }
  
  // No filtering needed - return original packet
  return packet;
};

// Event handlers
aedes.on('client', (client) => {
  // Link stream to client if available
  (client as any).stream = (client as any).conn;
  
  const logPrefix = getClientLogPrefix(client);
  console.log(`${logPrefix} [CLIENT] Connected`);
  console.log(`${logPrefix} [CLIENT] Connection details - conn exists: ${!!(client as any).conn}, clientIP: ${(client as any).conn?.clientIP}`);
  
  // Track when this client connected for disconnect timing
  (client as any).connectedAt = Date.now();
  
  // Hook into the client's stream close event to see WHO closed it
  const stream = (client as any).stream;
  if (stream) {
    const originalClose = stream.close?.bind(stream);
    const originalDestroy = stream.destroy?.bind(stream);
    
    (stream as any).close = function(...args: any[]) {
      console.log(`${logPrefix} [STREAM] close() called (server-initiated close)`);
      if (originalClose) originalClose(...args);
    };
    
    (stream as any).destroy = function(...args: any[]) {
      console.log(`${logPrefix} [STREAM] destroy() called - error: ${args[0]?.message || 'none'}`);
      if (originalDestroy) originalDestroy(...args);
    };
  }
});

aedes.on('clientDisconnect', (client) => {
  const logPrefix = getClientLogPrefix(client);
  const connectedAt = (client as any).connectedAt;
  const duration = connectedAt ? Math.round((Date.now() - connectedAt) / 1000) : 'unknown';
  
  console.log(`${logPrefix} [CLIENT] Disconnected (connected for ${duration}s)`);
  
  // Log additional info to debug why this client disconnected
  if (client) {
    console.log(`${logPrefix} [CLIENT] Disconnect details - clientType: ${(client as any).clientType}, publicKey: ${(client as any).publicKey?.substring(0, 8)}`);
  }
});

aedes.on('publish', (packet, client) => {
  if (client) {
    const logPrefix = getClientLogPrefix(client);
    console.log(`${logPrefix} [PUBLISH] ${packet.topic} (${packet.payload.length} bytes)`);
  } else {
    console.log(`[PUBLISH] Internal -> ${packet.topic} (${packet.payload.length} bytes)`);
  }
});

aedes.on('subscribe', (subscriptions, client) => {
  const logPrefix = getClientLogPrefix(client);
  console.log(`${logPrefix} [SUBSCRIBE] Attempting to subscribe to: ${subscriptions.map(s => s.topic).join(', ')}`);
});

// Log when client sends DISCONNECT packet (graceful disconnect)
aedes.on('clientError', (client, err) => {
  const logPrefix = getClientLogPrefix(client);
  console.log(`${logPrefix} [ERROR] Client error: ${err.message}`);
});

// Create HTTP server for WebSocket
const httpServer = createServer((req, res) => {
  // If this is not a WebSocket upgrade request, redirect to analyzer
  if (!req.headers.upgrade || req.headers.upgrade.toLowerCase() !== 'websocket') {
    console.log(`[HTTP] Non-WebSocket request from ${getClientIP(req)}, redirecting to analyzer`);
    res.writeHead(301, { 'Location': 'https://analyzer.letsmesh.net/' });
    res.end();
    return;
  }
});

// Create WebSocket server
const wsServer = new WebSocketServer({ server: httpServer });

wsServer.on('connection', (ws, req) => {
  try {
    const clientIP = getClientIP(req);
    
    // Check if IP is blocked
    if (rateLimiter.isBlocked(clientIP)) {
      console.log(`[RATE_LIMIT] Rejecting connection from blocked IP: ${clientIP}`);
      // Terminate immediately without trying to send a close frame
      ws.terminate();
      return;
    }
    
    console.log(`[WEBSOCKET] New WebSocket connection from ${clientIP}`);
  
  // Enable WebSocket ping/pong to keep connection alive
  ws.on('ping', (data) => {
    console.log(`[WEBSOCKET] Received WebSocket PING from ${clientIP}, sending PONG`);
    ws.pong(data);
  });
  
  ws.on('pong', () => {
    console.log(`[WEBSOCKET] Received WebSocket PONG from ${clientIP}`);
  });
  
  // Handle WebSocket errors
  ws.on('error', (error) => {
    // Log other WebSocket errors
    console.error(`[WEBSOCKET] Error from ${clientIP}:`, error.message);
  });
  
  // Create a duplex stream from the WebSocket
  const stream = new Duplex({
    read() {
      // No-op, data is pushed via ws.on('message')
    },
    write(chunk, encoding, callback) {
      if (ws.readyState === ws.OPEN) {
        // Log MQTT PINGRESP packets (0xD0 = PINGRESP)
        if (chunk instanceof Buffer && chunk.length >= 2 && chunk[0] === 0xD0) {
          const clientInfo = (stream as any).client;
          if (clientInfo) {
            const logPrefix = getClientLogPrefix(clientInfo);
            console.log(`${logPrefix} [MQTT] Sending PINGRESP (PONG) to client`);
          } else {
            console.log(`[MQTT] Sending PINGRESP (PONG) to unauthenticated client`);
          }
        }
        
        ws.send(chunk, (error) => {
          // Suppress EPIPE errors - they're expected when client disconnects
          if (error && (error as any).code !== 'EPIPE') {
            const clientInfo = (stream as any).client;
            if (clientInfo) {
              const logPrefix = getClientLogPrefix(clientInfo);
              console.error(`${logPrefix} [WEBSOCKET] Send error:`, error);
            } else {
              console.error('[WEBSOCKET] Send error:', error);
            }
          }
          callback(error);
        });
      } else {
        callback(new Error('WebSocket not open'));
      }
    }
  });

  // Forward WebSocket messages to the stream
  ws.on('message', (data) => {
    // Log MQTT PINGREQ packets (0xC0 = PINGREQ) with client identifier
    if (data instanceof Buffer && data.length >= 2 && data[0] === 0xC0) {
      const clientInfo = (stream as any).client;
      if (clientInfo) {
        const logPrefix = getClientLogPrefix(clientInfo);
        console.log(`${logPrefix} [MQTT] Received PINGREQ (PING) from client`);
      } else {
        console.log('[MQTT] Received PINGREQ (PING) from unauthenticated client');
      }
    }
    stream.push(data);
  });

  // Store client IP on stream for logging
  (stream as any).clientIP = clientIP;
  (stream as any).authenticated = false;
  
  // Handle WebSocket close
  ws.on('close', (code, reason) => {
    const clientInfo = (stream as any).client;
    const wasAuthenticated = (stream as any).authenticated;
    
    // Check if client properly authenticated (has clientType set)
    const hasValidAuth = clientInfo && (clientInfo as any).clientType;
    
    if (hasValidAuth) {
      const logPrefix = getClientLogPrefix(clientInfo);
      console.log(`${logPrefix} [WEBSOCKET] Connection closed from ${clientIP} - Code: ${code}, Reason: ${reason.toString() || 'none'}`);
    } else {
      // Unauthenticated or invalid client - count as failed connection
      console.log(`[C:${clientInfo?.id || 'null'}] [WEBSOCKET] Connection closed (unauthenticated) from ${clientIP} - Code: ${code}, Reason: ${reason.toString() || 'none'}`);
      
      if (!wasAuthenticated) {
        const blocked = rateLimiter.recordFailure(clientIP);
        if (blocked) {
          console.log(`[RATE_LIMIT] IP ${clientIP} has been blocked`);
        }
      }
    }
    stream.push(null);
  });

  // Handle stream end
  stream.on('end', () => {
    const clientInfo = (stream as any).client;
    if (clientInfo) {
      const logPrefix = getClientLogPrefix(clientInfo);
      console.log(`${logPrefix} [STREAM] Stream ended, closing WebSocket`);
    } else {
      console.log('[STREAM] Stream ended (unauthenticated), closing WebSocket');
    }
    ws.close();
  });

  // Pass the stream to Aedes
  aedes.handle(stream);
  } catch (error) {
    console.error('[WEBSOCKET] Error handling connection:', error);
    try {
      ws.terminate();
    } catch (e) {
      // Ignore errors when terminating
    }
  }
});

httpServer.listen(WS_PORT, HOST, () => {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║         MeshCore MQTT Broker (WebSocket)                  ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log(`WebSocket MQTT listening on: ws://${HOST}:${WS_PORT}`);
  console.log('');
  console.log('Authentication Modes:');
  console.log(`  1. Subscribers (Subscribe-only): ${subscriberUsers.size} user(s) configured`);
  console.log('     Usernames:', Array.from(subscriberUsers.keys()).join(', '));
  console.log('');
  console.log('  2. Publishers (Publish-only):');
  console.log('     Username: v1_{PUBLIC_KEY}');
  console.log('     Password: JWT token signed with Ed25519 private key');
  console.log('     Validation:');
  console.log('       - origin_id must match authenticated public key');
  if (EXPECTED_AUDIENCE) {
    console.log(`       - Token audience must be: ${EXPECTED_AUDIENCE}`);
  }
  console.log('');
  console.log('Ready to accept connections...');
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n[SHUTDOWN] Closing MQTT broker...');
  abuseDetector.shutdown();
  aedes.close(() => {
    console.log('[SHUTDOWN] Broker closed');
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  console.log('\n[SHUTDOWN] Closing MQTT broker...');
  abuseDetector.shutdown();
  aedes.close(() => {
    console.log('[SHUTDOWN] Broker closed');
    process.exit(0);
  });
});
