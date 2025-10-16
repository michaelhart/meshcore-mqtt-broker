import Aedes from 'aedes';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import { Duplex } from 'stream';
import { config as dotenvConfig } from 'dotenv';
import { verifyAuthToken } from '@michaelhart/meshcore-decoder';
import { getAirportInfo } from 'airport-utils';

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

// Authentication handler
aedes.authenticate = async (client, username, password, callback) => {
  console.log(`[AUTH] Authentication attempt - Client: ${client.id}, Username: ${username}`);

  try {
    const usernameStr = username?.toString() || '';
    const passwordStr = password?.toString() || '';

    // Check if this is a subscriber login
    if (subscriberUsers.has(usernameStr)) {
      const expectedPassword = subscriberUsers.get(usernameStr);
      if (passwordStr === expectedPassword) {
        console.log(`[AUTH] ✓ Subscriber authenticated: ${client.id} (${usernameStr})`);
        (client as any).clientType = ClientType.SUBSCRIBER;
        (client as any).username = usernameStr;
        callback(null, true);
      } else {
        console.log(`[AUTH] ✗ Subscriber authentication failed for ${client.id} - Invalid password`);
        callback(null, false);
      }
      return;
    }

    // Otherwise, check for JWT-based publisher authentication
    // Username format: v1_{UPPERCASE_PUBLIC_KEY}
    if (!usernameStr.startsWith('v1_')) {
      console.log(`[AUTH] Invalid username format: ${usernameStr}`);
      callback(null, false);
      return;
    }

    const publicKey = usernameStr.substring(3).toUpperCase();
    
    // Validate public key format (should be 64 hex characters)
    if (!/^[0-9A-F]{64}$/i.test(publicKey)) {
      console.log(`[AUTH] Invalid public key format: ${publicKey}`);
      console.log(`[AUTH] Public key length: ${publicKey.length}, hex dump: ${Buffer.from(publicKey).toString('hex')}`);
      callback(null, false);
      return;
    }

    if (!passwordStr || passwordStr.length === 0) {
      console.log(`[AUTH] No password provided`);
      callback(null, false);
      return;
    }

    // Verify the auth token using meshcore-decoder
    const tokenPayload = await verifyAuthToken(passwordStr, publicKey);
    
    if (!tokenPayload) {
      console.log(`[AUTH] ✗ Authentication failed for ${client.id} - Invalid token signature`);
      callback(null, false);
      return;
    }
    
    // Validate audience claim if configured
    if (EXPECTED_AUDIENCE && tokenPayload.aud !== EXPECTED_AUDIENCE) {
      console.log(`[AUTH] ✗ Authentication failed for ${client.id} - Invalid audience: ${tokenPayload.aud} (expected: ${EXPECTED_AUDIENCE})`);
      callback(null, false);
      return;
    }
    
    console.log(`[AUTH] ✓ Publisher authenticated: ${client.id} (${publicKey.substring(0, 8)}...)${tokenPayload.aud ? ` [aud: ${tokenPayload.aud}]` : ''}`);
    // Store the public key and client type with the client for later use
    (client as any).publicKey = publicKey;
    (client as any).tokenPayload = tokenPayload;
    (client as any).clientType = ClientType.PUBLISHER;
    callback(null, true);
  } catch (error) {
    console.error(`[AUTH] Error during authentication:`, error);
    callback(null, false);
  }
};

// Authorization handler (control topic access)
aedes.authorizePublish = (client, packet, callback) => {
  if (!client) {
    callback(new Error('No client'));
    return;
  }
  
  const clientType = (client as any).clientType;
  
  // Subscriber clients cannot publish (subscribe-only)
  if (clientType === ClientType.SUBSCRIBER) {
    console.log(`[AUTHZ] ✗ Publish denied for subscriber: ${client.id} -> ${packet.topic}`);
    callback(new Error('Subscriber clients are subscribe-only'));
    return;
  }
  
  // Publisher clients can only publish to meshcore/* topics
  if (clientType === ClientType.PUBLISHER) {
    if (!packet.topic.startsWith('meshcore/')) {
      console.log(`[AUTHZ] ✗ Publish denied: ${client.id} -> ${packet.topic} (not meshcore/*)`);
      callback(new Error('Publishers can only publish to meshcore/* topics'));
      return;
    }

    // Validate topic format
    // Supported formats:
    //   meshcore/{IATA}/subtopic (e.g., meshcore/SEA/packets)
    //   meshcore/{IATA}/{PUBLIC_KEY}/subtopic (e.g., meshcore/SEA/ABCD1234.../packets)
    const topicParts = packet.topic.split('/');
    if (topicParts.length < 3) {
      console.log(`[AUTHZ] ✗ Publish denied: ${client.id} -> ${packet.topic} (must be meshcore/AIRPORT/subtopic format, no root publishing)`);
      callback(new Error('Topic must be meshcore/AIRPORT/subtopic or meshcore/AIRPORT/PUBKEY/subtopic format'));
      return;
    }
    
    const locationCode = topicParts[1];
    const iataRegex = /^[A-Z]{3}$/;
    
    // Reject XXX explicitly (default placeholder value)
    if (locationCode === 'XXX') {
      console.log(`[AUTHZ] ✗ Publish denied: ${client.id} -> ${packet.topic} (XXX is not a valid location code, please configure your actual IATA code)`);
      callback(new Error('XXX is a placeholder - please configure your actual IATA location code'));
      client.close(); // Disconnect the client
      return;
    }
    
    // Allow "test" as a special testing region
    if (locationCode.toLowerCase() === 'test') {
      console.log(`[AUTHZ] ✓ Using TEST region: ${client.id} -> ${packet.topic}`);
      // Continue to validation, don't return here
    } else {
      // First check format (must be 3 uppercase letters, no normalization)
      if (!iataRegex.test(locationCode)) {
        console.log(`[AUTHZ] ✗ Publish denied: ${client.id} -> ${packet.topic} (invalid format: ${locationCode}, must be 3 UPPERCASE letters or "test")`);
        callback(new Error('Location must be exactly 3 uppercase letters (e.g., SEA, PDX, BOS) or "test"'));
        client.close(); // Disconnect the client
        return;
      }
      
      // Then check if it's a valid IATA code
      if (!isValidIATACode(locationCode)) {
        console.log(`[AUTHZ] ✗ Publish denied: ${client.id} -> ${packet.topic} (invalid IATA code: ${locationCode}, not a recognized international airport)`);
        callback(new Error('Location must be a valid IATA international airport code or "test"'));
        client.close(); // Disconnect the client
        return;
      }
    }
    
    // Check if topic includes public key (4 parts = meshcore/IATA/PUBKEY/subtopic)
    if (topicParts.length >= 4) {
      const topicPublicKey = topicParts[2].toUpperCase();
      
      // Validate it looks like a public key (64 hex chars)
      if (!/^[0-9A-F]{64}$/i.test(topicPublicKey)) {
        console.log(`[AUTHZ] ✗ Publish denied: ${client.id} -> ${packet.topic} (invalid public key format in topic: ${topicPublicKey})`);
        callback(new Error('Public key in topic must be 64 hex characters'));
        client.close();
        return;
      }
      
      // Validate topic public key matches authenticated client
      const clientPublicKey = (client as any).publicKey.toUpperCase();
      if (topicPublicKey !== clientPublicKey) {
        console.log(`[AUTHZ] ✗ Publish denied: ${client.id} -> ${packet.topic} (topic public key ${topicPublicKey.substring(0, 8)}... doesn't match authenticated key ${clientPublicKey.substring(0, 8)}...)`);
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
        console.log(`[AUTHZ] ✗ Publish denied: ${client.id} -> ${packet.topic} (missing origin_id)`);
        callback(new Error('Message must contain origin_id field'));
        return;
      }
      
      // Normalize both to uppercase for comparison
      const messageOriginId = message.origin_id.toUpperCase();
      const normalizedClientKey = clientPublicKey.toUpperCase();
      
      if (messageOriginId !== normalizedClientKey) {
        console.log(`[AUTHZ] ✗ Publish denied: ${client.id} -> ${packet.topic} (origin_id mismatch: ${messageOriginId.substring(0, 8)}... != ${normalizedClientKey.substring(0, 8)}...)`);
        callback(new Error('origin_id must match authenticated public key'));
        return;
      }
      
      console.log(`[AUTHZ] ✓ Publish authorized: ${client.id} -> ${packet.topic}`);
      callback(null);
    } catch (error) {
      console.log(`[AUTHZ] ✗ Publish denied: ${client.id} -> ${packet.topic} (invalid JSON or validation error)`);
      callback(new Error('Invalid message format or origin_id validation failed'));
    }
    return;
  }
  
  // Unknown client type
  console.log(`[AUTHZ] ✗ Publish denied: ${client.id} -> ${packet.topic} (unknown client type)`);
  callback(new Error('Unknown client type'));
};

aedes.authorizeSubscribe = (client, subscription, callback) => {
  if (!client) {
    callback(new Error('No client'));
    return;
  }
  
  const clientType = (client as any).clientType;
  
  // Publisher clients cannot subscribe (publish-only)
  if (clientType === ClientType.PUBLISHER) {
    console.log(`[AUTHZ] ✗ Subscribe denied for publisher: ${client.id} -> ${subscription.topic}`);
    callback(new Error('Publisher clients are publish-only'));
    return;
  }
  
  // Subscriber clients can subscribe to any topic (they're listeners)
  if (clientType === ClientType.SUBSCRIBER) {
    const username = (client as any).username || 'unknown';
    console.log(`[AUTHZ] ✓ Subscribe authorized for subscriber: ${client.id} (${username}) -> ${subscription.topic}`);
    callback(null, subscription);
    return;
  }
  
  // Unknown client type
  console.log(`[AUTHZ] ✗ Subscribe denied: ${client.id} -> ${subscription.topic} (unknown client type)`);
  callback(new Error('Unknown client type'));
};

// Event handlers
aedes.on('client', (client) => {
  console.log(`[CLIENT] Connected: ${client.id}`);
});

aedes.on('clientDisconnect', (client) => {
  console.log(`[CLIENT] Disconnected: ${client.id}`);
});

aedes.on('publish', (packet, client) => {
  if (client) {
    console.log(`[PUBLISH] ${client.id} -> ${packet.topic} (${packet.payload.length} bytes)`);
  } else {
    console.log(`[PUBLISH] Internal -> ${packet.topic} (${packet.payload.length} bytes)`);
  }
});

aedes.on('subscribe', (subscriptions, client) => {
  console.log(`[SUBSCRIBE] ${client.id} -> ${subscriptions.map(s => s.topic).join(', ')}`);
});

// Create HTTP server for WebSocket
const httpServer = createServer();

// Create WebSocket server
const wsServer = new WebSocketServer({ server: httpServer });

wsServer.on('connection', (ws) => {
  console.log('[WEBSOCKET] New WebSocket connection');
  
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
        ws.send(chunk, (error) => {
          if (error) {
            console.error('[WEBSOCKET] Send error:', error);
            callback(error);
          } else {
            callback();
          }
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
        const clientType = (clientInfo as any).clientType;
        const identifier = clientType === ClientType.PUBLISHER 
          ? (clientInfo as any).publicKey?.substring(0, 8) + '...'
          : (clientInfo as any).username || clientInfo.id;
        console.log(`[MQTT] PING from ${identifier}`);
      } else {
        console.log('[MQTT] PING from unknown client');
      }
    }
    stream.push(data);
  });

  // Handle WebSocket close
  ws.on('close', () => {
    console.log('[WEBSOCKET] WebSocket closed');
    stream.push(null);
  });

  // Handle stream end
  stream.on('end', () => {
    ws.close();
  });

  // Pass the stream to Aedes
  aedes.handle(stream);
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
