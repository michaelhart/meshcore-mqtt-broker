import Aedes from 'aedes';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import { Duplex } from 'stream';
import { config as dotenvConfig } from 'dotenv';
import { verifyAuthToken } from '@michaelhart/meshcore-decoder';
import { getAirportInfo } from 'airport-utils';
import { RateLimiter } from './rate-limiter';
import { getClientIP } from './ip-utils';

// Load environment variables
dotenvConfig();

const WS_PORT = parseInt(process.env.MQTT_WS_PORT || '8883');
const HOST = process.env.MQTT_HOST || '0.0.0.0';
const EXPECTED_AUDIENCE = process.env.AUTH_EXPECTED_AUDIENCE || '';

// Helper function to validate IATA airport codes
function isValidIATACode(code: string): boolean {
  try {
    getAirportInfo(code);
    return true;
  } catch {
    return false;
  }
}

// Load subscriber users from environment variables
// Format: SUBSCRIBER_1=username:password, SUBSCRIBER_2=username:password, etc.
const subscriberUsers = new Map<string, string>();

let subscriberIndex = 1;
while (true) {
  const subscriberEnvVar = process.env[`SUBSCRIBER_${subscriberIndex}`];
  if (!subscriberEnvVar) {
    break;
  }
  
  const [username, password] = subscriberEnvVar.split(':').map(s => s.trim());
  if (username && password) {
    subscriberUsers.set(username, password);
    console.log(`[CONFIG] Loaded subscriber user: ${username}`);
  } else {
    console.warn(`[CONFIG] Invalid format for SUBSCRIBER_${subscriberIndex}: ${subscriberEnvVar}`);
  }
  
  subscriberIndex++;
}

if (subscriberUsers.size === 0) {
  console.log('[CONFIG] No subscriber users configured');
}

// Client types
enum ClientType {
  SUBSCRIBER = 'subscriber',
  PUBLISHER = 'publisher'
}

// Create Aedes MQTT broker
const aedes = new Aedes();

// Rate limiting for failed connections
const rateLimiter = new RateLimiter(60000, 10, 300000);

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
        console.log(`${logPrefix} [AUTH] ✓ Subscriber authenticated (${usernameStr})`);
        (client as any).clientType = ClientType.SUBSCRIBER;
        (client as any).username = usernameStr;
        
        // Mark stream as authenticated
        const stream = (client as any).stream;
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
    
    if (!tokenPayload) {
      console.log(`${logPrefix} [AUTH] ✗ Invalid token signature`);
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
    const stream = (client as any).stream;
    if (stream && stream.clientIP) {
      stream.authenticated = true;
    }
    
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
  
  // Subscriber clients cannot publish (subscribe-only)
  if (clientType === ClientType.SUBSCRIBER) {
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
    // Supported formats:
    //   meshcore/{IATA}/subtopic (e.g., meshcore/SEA/packets)
    //   meshcore/{IATA}/{PUBLIC_KEY}/subtopic (e.g., meshcore/SEA/ABCD1234.../packets)
    const topicParts = packet.topic.split('/').map(part => part.trim());
    if (topicParts.length < 3) {
      console.log(`${logPrefix} [AUTHZ] ✗ Publish denied -> ${packet.topic} (must be meshcore/AIRPORT/subtopic format)`);
      callback(new Error('Topic must be meshcore/AIRPORT/subtopic or meshcore/AIRPORT/PUBKEY/subtopic format'));
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
    
    // Check if topic includes public key (4 parts = meshcore/IATA/PUBKEY/subtopic)
    if (topicParts.length >= 4) {
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
    }

    // Validate that the message contains origin_id matching the authenticated public key
    const clientPublicKey = (client as any).publicKey;
    
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
      
      console.log(`${logPrefix} [AUTHZ] ✓ Publish authorized -> ${packet.topic}`);
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

// Event handlers
aedes.on('client', (client) => {
  // Link stream to client if available
  if ((client as any).conn && (client as any).conn.clientIP) {
    (client as any).stream = (client as any).conn;
  }
  
  const logPrefix = getClientLogPrefix(client);
  console.log(`${logPrefix} [CLIENT] Connected`);
});

aedes.on('clientDisconnect', (client) => {
  const logPrefix = getClientLogPrefix(client);
  console.log(`${logPrefix} [CLIENT] Disconnected`);
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
  console.log(`${logPrefix} [SUBSCRIBE] ${subscriptions.map(s => s.topic).join(', ')}`);
});

// Create HTTP server for WebSocket
const httpServer = createServer();

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
    console.log('[WEBSOCKET] Received PING, sending PONG');
    ws.pong(data);
  });
  
  ws.on('pong', () => {
    console.log('[WEBSOCKET] Received PONG');
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
            console.log(`${logPrefix} [MQTT] PONG sent`);
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
        console.log(`${logPrefix} [MQTT] PING received`);
      } else {
        console.log('[MQTT] PING from unknown client');
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
  aedes.close(() => {
    console.log('[SHUTDOWN] Broker closed');
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  console.log('\n[SHUTDOWN] Closing MQTT broker...');
  aedes.close(() => {
    console.log('[SHUTDOWN] Broker closed');
    process.exit(0);
  });
});
