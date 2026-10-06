# meshcore-mqtt-broker

A WebSocket-based MQTT broker with MeshCore public key authentication.

## Features

- **WebSocket MQTT**: Uses MQTT over WebSockets (not MQTT over TCP protocol)
- **Public Key Authentication**: Clients authenticate using their MeshCore public keys
- **Topic Authorization**: Controls access to meshcore/* topics
- **Client RX Topics** (opt-in): Lets mobile clients report their own RX coverage to an allowlisted consumer, see [Client RX topics](#client-rx-topics)

## Authentication

### Username Format
```
v1_{UPPERCASE_PUBLIC_KEY}
```

Example: `v1_7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400`

### Password Format
The password is a JWT-style authentication token signed with your MeshCore Ed25519 private key using orlp/ed25519, which is used in the MeshCore firmware and in the `@michaelhart/meshcore-decoder` library's `createAuthToken` function.

```javascript
import { createAuthToken } from '@michaelhart/meshcore-decoder';

const privateKey = 'YOUR_64_BYTE_PRIVATE_KEY_HEX'; // MeshCore format
const publicKey = 'YOUR_32_BYTE_PUBLIC_KEY_HEX';

const password = await createAuthToken(
  {
    publicKey: publicKey,
    aud: 'mqtt.yourdomain.com', // Must match AUTH_EXPECTED_AUDIENCE in .env
    iat: Math.floor(Date.now() / 1000),
    // Optional: add expiration
    // exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour
  },
  privateKey,
  publicKey
);
```

The token format is: `header.payload.signature` where the signature is verified using Ed25519.

## Configuration

All configuration is done via environment variables in a `.env` file.

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Edit `.env`:

```bash
# MQTT Server Settings
MQTT_WS_PORT=8883
MQTT_HOST=0.0.0.0

# Authentication Settings
# Expected audience claim in JWT tokens (leave empty to skip validation)
AUTH_EXPECTED_AUDIENCE=mqtt.yourdomain.com

# Subscribe-Only Users (read-only monitoring accounts)
# Format: SUBSCRIBER_N=username:password:role
# Role: 1=admin (full access + delete + PII), 2=full_access (no filtering), 3=limited (filtered)
# Add as many as you need by incrementing the number
SUBSCRIBER_1=admin:your-secure-password-here:1
SUBSCRIBER_2=viewer:another-secure-password:2
SUBSCRIBER_3=monitor:yet-another-password:3
```

**Subscribe-only users** can read messages but cannot publish. They're useful for monitoring, debugging, and administrative dashboards.

**Subscriber Roles**:
- **Role 1 (Admin)**: Full access including `/internal` topics (contains PII), `$SYS/*` system topics, and ability to delete retained messages
- **Role 2 (Full Access)**: Access to all public topics with no data filtering, cannot access `/internal` or `$SYS/*`
- **Role 3 (Limited)**: Access to public topics only with sensitive data filtered (SNR, RSSI, score, stats, model, firmware_version removed from messages)

## Installation

```bash
npm install
```

## Usage

### Development
```bash
npm run dev
```

### Production
```bash
npm run build
npm start
```

### Tests
```bash
npm test          # unit tests plus in-process broker integration tests
npm run typecheck # type check sources and tests
```

The integration tests start the broker in-process on an ephemeral port (the OS
picks a free one, so parallel runs do not collide) and connect real MQTT clients
to it. Set `BROKER_TEST_PORT` to pin the port, and `BROKER_TEST_VERBOSE=1` to
see the broker log while they run.

## Connecting Clients

### JavaScript/Node.js Example

```javascript
const mqtt = require('mqtt');
const { createAuthToken } = require('@michaelhart/meshcore-decoder');

const privateKey = 'YOUR_64_BYTE_PRIVATE_KEY_HEX'; // MeshCore format
const publicKey = '7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400';
const clientId = 'meshcore_test_client';

async function connect() {
  // Generate auth token
  const password = await createAuthToken(
    {
      publicKey: publicKey,
      aud: 'mqtt.yourdomain.com', // Must match AUTH_EXPECTED_AUDIENCE in .env
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 86400 // 24 hours
    },
    privateKey,
    publicKey
  );

  const client = mqtt.connect('ws://localhost:8883', {
    clientId: clientId,
    username: `v1_${publicKey}`,
    password: password
  });

  client.on('connect', () => {
    console.log('Connected!');
    client.subscribe('meshcore/#');
  });

  client.on('message', (topic, message) => {
    console.log(`${topic}: ${message.toString()}`);
  });
}

connect();
```

## Topics

Publishers can only publish to topics with the following format:

- `meshcore/{IATA_CODE}/{PUBLIC_KEY}/{subtopic}`

Examples:
- `meshcore/SEA/7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400/packets`
- `meshcore/SEA/7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400/status`
- `meshcore/PDX/7E7662676F7F0850A8A355BAAFBFC1EB7B4174C340442D7D7161C9474A2C9400/internal` (ADMIN-only - contains PII)

Where:
- `{IATA_CODE}` must be a valid 3-letter IATA airport code (e.g., SEA, PDX, BOS) or `test` for testing
- `{PUBLIC_KEY}` must be the full 64-character hex public key (matching your authenticated public key)
- `{subtopic}` can be any subtopic name (e.g., `packets`, `status`, `internal`)

**Important**: The `/internal` subtopic is ADMIN-only and contains PII (Personally Identifiable Information) from JWT payloads. Only subscribers with role 1 (admin) can access these topics.

All published messages must be valid JSON and contain an `origin_id` field matching your authenticated public key. In the future, this requirement and the origin_id field may be removed, as they are a part of the MQTT session. For now, this is largely for backwards compatibility.

Subscribers (read-only users) can subscribe to any topic including wildcards like `meshcore/#`.

## Client RX topics

Mobile clients can report the packets their own radio received, so coverage can
be measured from the client side instead of only from fixed observers:

- `meshcore/client/{PUBLIC_KEY}/packets`

These payloads typically contain a precise position, so the namespace is
**disabled by default** and is restricted when enabled:

- a publisher may only publish under its own public key, and only to the
  `packets` subtopic (exactly 4 topic segments, lowercase `client`);
- no IATA code is involved, so IATA validation and IATA change tracking are
  skipped. The abuse detector records the packet exactly as it does for an
  observer topic, which means the duplicate, rate and size counters are
  *tracked* but, like everywhere else in this broker, not enforced on publish;
- `origin_id` is not required in the payload (the topic already carries the
  authenticated public key);
- retained publishes are rejected, so a position is never stored in the broker;
- the publisher token must carry `exp` with a lifetime of at most 24 hours;
- packets are only delivered to subscriber usernames listed in
  `CLIENT_RX_SUBSCRIBERS`. The check runs per packet, so wildcard subscriptions
  such as `meshcore/#` are covered as well, and role 1 (admin) is not exempt.

| Variable | Default | Meaning |
| --- | --- | --- |
| `CLIENT_RX_ENABLED` | `false` | Set to `true` to accept the namespace. Anything else leaves the topic rejected. |
| `CLIENT_RX_SUBSCRIBERS` | *(empty)* | Comma separated subscriber usernames allowed to receive client RX packets. Empty means nobody receives them. |
| `CLIENT_RX_MAX_TOKEN_LIFETIME_S` | `86400` | Largest accepted `exp - iat` of a publishing token. Values above 86400 (24h) are capped. |

An out of range or non numeric `CLIENT_RX_MAX_TOKEN_LIFETIME_S` or
`CLIENT_RX_CLOCK_SKEW_S` is corrected rather than fatal, but the correction is
always logged as a `[CONFIG]` warning at start.

| `CLIENT_RX_CLOCK_SKEW_S` | `300` | How far `iat` may be in the future before the publish is rejected. Capped at 3600 (1h), because the skew is added to the lifetime budget. |

With `CLIENT_RX_ENABLED` unset the namespace is rejected and subscriptions are
answered as before. One deliberate difference remains in that state: the
per-packet forward guard always runs, so nothing under `meshcore/client/` is
delivered to anyone, not even an admin's empty retained "delete" publish.

See [docs/client-rx-topics.md](docs/client-rx-topics.md) for the full topic
contract and the client side token requirements.


## Deployment

This project is designed to be deployed via Nixpacks (e.g., to Dokploy) similar to the ingestor project.

The build process will:
1. Install dependencies
2. Compile TypeScript to JavaScript
3. Run the compiled server

For setting up with TLS using Cloudflare Tunnels, see [docs/cloudflare-tunnels.md](docs/cloudflare-tunnels.md). This is the recommended way to deploy the MQTT broker.


## License

MIT License

Copyright (c) 2025 Michael Hart michaelhart@michaelhart.me (https://github.com/michaelhart)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
