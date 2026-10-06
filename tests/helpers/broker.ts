/**
 * Test helpers: start the real broker in-process and talk to it with real
 * MQTT clients over WebSocket.
 *
 * src/server.ts starts listening when it is imported, so each test file sets
 * its own environment and port before importing it, and closes the broker
 * afterwards through the exported closeBroker().
 */
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Utils, createAuthToken } from '@michaelhart/meshcore-decoder';
import mqtt, { IClientOptions, MqttClient } from 'mqtt';

export const TEST_AUDIENCE = 'mqtt.test.invalid';
export const SUBSCRIBER_PASSWORD = 'test-subscriber-password';

export interface TestKeypair {
  privateKeyHex: string;
  publicKeyHex: string;
}

/**
 * Derive a throwaway orlp/ed25519 keypair from a label.
 *
 * The orlp private key is sha512(seed) with the standard Ed25519 clamping,
 * which is what ed25519_create_keypair() produces.
 */
export async function createTestKeypair(label: string): Promise<TestKeypair> {
  const seed = createHash('sha256').update(`meshcore-broker-test:${label}`).digest();
  const privateKey = createHash('sha512').update(seed).digest();
  privateKey[0] &= 248;
  privateKey[31] &= 63;
  privateKey[31] |= 64;

  const privateKeyHex = privateKey.toString('hex');
  const publicKeyHex = (await Utils.derivePublicKey(privateKeyHex)).toUpperCase();
  return { privateKeyHex, publicKeyHex };
}

export interface TokenClaims {
  iat?: number;
  exp?: number | null;
  aud?: string | null;
}

/** Sign a publisher token for a keypair. */
export async function createTestToken(keypair: TestKeypair, claims: TokenClaims = {}): Promise<string> {
  const iat = claims.iat ?? Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    publicKey: keypair.publicKeyHex,
    iat,
  };

  if (claims.exp !== null) {
    payload.exp = claims.exp ?? iat + 86400;
  }
  if (claims.aud !== null) {
    payload.aud = claims.aud ?? TEST_AUDIENCE;
  }

  return createAuthToken(payload as any, keypair.privateKeyHex, keypair.publicKeyHex);
}

/** Replace the signature of a token so it no longer verifies. */
export function forgeTokenSignature(token: string): string {
  const [header, payload, signature] = token.split('.');
  const forged = signature.replace(/[0-9a-f]/g, (c) => (c === '0' ? '1' : '0'));
  return `${header}.${payload}.${forged}`;
}

/** Everything the broker needs in the environment, with test-safe defaults. */
function baseEnv(port: number, persistencePath: string): Record<string, string> {
  return {
    MQTT_WS_PORT: String(port),
    MQTT_HOST: '127.0.0.1',
    AUTH_EXPECTED_AUDIENCE: TEST_AUDIENCE,
    SUBSCRIBER_MAX_CONNECTIONS_DEFAULT: '10',
    ABUSE_ENFORCEMENT_ENABLED: 'false',
    ABUSE_DUPLICATE_WINDOW_SIZE: '100',
    ABUSE_DUPLICATE_WINDOW_MS: '300000',
    ABUSE_DUPLICATE_THRESHOLD: '10',
    ABUSE_BUCKET_CAPACITY: '50',
    ABUSE_BUCKET_REFILL_RATE: '10',
    ABUSE_MAX_PACKET_SIZE: '255',
    ABUSE_MAX_TOPICS_PER_DAY: '50',
    ABUSE_ANOMALY_THRESHOLD: '100',
    ABUSE_MAX_IATA_CHANGES_24H: '50',
    ABUSE_TOPIC_HISTORY_SIZE: '50',
    ABUSE_TOPIC_HISTORY_WINDOW_MS: '86400000',
    ABUSE_PERSISTENCE_PATH: persistencePath,
    ABUSE_PERSISTENCE_INTERVAL_MS: '3600000',
  };
}

export interface TestBroker {
  port: number;
  url: string;
  /** Console lines the broker produced since the broker started. */
  logLines: () => string[];
  /** Client ids of the MQTT sessions the broker currently holds. */
  sessionIds: () => string[];
  stop: () => Promise<void>;
}

type ConsoleMethod = 'log' | 'info' | 'warn' | 'error' | 'debug';

/**
 * Capture console output so tests can assert on what the broker logs.
 *
 * The node:test reporter writes straight to stdout, so replacing the console
 * methods keeps the test output readable. Set BROKER_TEST_VERBOSE=1 to also
 * print the broker log.
 */
function captureConsole(): { lines: string[]; restore: () => void } {
  const lines: string[] = [];
  const methods: ConsoleMethod[] = ['log', 'info', 'warn', 'error', 'debug'];
  const originals = new Map<ConsoleMethod, (...args: any[]) => void>();
  const verbose = process.env.BROKER_TEST_VERBOSE === '1';

  for (const method of methods) {
    originals.set(method, console[method]);
    console[method] = (...args: any[]) => {
      lines.push(args.map((arg) => (typeof arg === 'string' ? arg : String(arg))).join(' '));
      if (verbose) {
        originals.get(method)!.apply(console, args);
      }
    };
  }

  return {
    lines,
    restore: () => {
      for (const method of methods) {
        console[method] = originals.get(method)!;
      }
    },
  };
}

/**
 * Import src/server.ts with the given environment and wait until it listens.
 *
 * Only one broker can run per process because the module is a singleton, so
 * each test file gets its own process (node:test) and its own data directory.
 *
 * The listening port is 0 by default, so the OS picks a free one and parallel
 * runs cannot collide; the real port is read back from the listening socket.
 * Set BROKER_TEST_PORT to pin it when watching the traffic from outside.
 */
export async function startTestBroker(env: Record<string, string> = {}): Promise<TestBroker> {
  const dataDir = mkdtempSync(join(tmpdir(), 'meshcore-broker-test-'));
  const requestedPort = Number(process.env.BROKER_TEST_PORT ?? 0);
  Object.assign(process.env, baseEnv(requestedPort, join(dataDir, 'abuse-detection.db')), env);

  const captured = captureConsole();
  const server = await import('../../src/server');

  while (!server.httpServer.listening) {
    await delay(10);
  }

  const address = server.httpServer.address();
  if (typeof address !== 'object' || address === null) {
    throw new Error(`the broker is not listening on a TCP socket (address: ${String(address)})`);
  }
  const port = address.port;

  return {
    port,
    url: `ws://127.0.0.1:${port}`,
    logLines: () => [...captured.lines],
    sessionIds: () => Object.keys((server.aedes as any).clients ?? {}),
    stop: async () => {
      await server.closeBroker();
      captured.restore();
      rmSync(dataDir, { recursive: true, force: true });
    },
  };
}

export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export interface ReceivedMessage {
  topic: string;
  payload: string;
}

export interface TestClient {
  clientId: string;
  client: MqttClient;
  messages: ReceivedMessage[];
  /** Resolves when the broker (or the client) closed the connection. */
  closed: Promise<void>;
  end: () => Promise<void>;
}

function wrap(clientId: string, client: MqttClient): TestClient {
  const messages: ReceivedMessage[] = [];
  client.on('message', (topic, payload) => {
    messages.push({ topic, payload: payload.toString('utf-8') });
  });

  const closed = new Promise<void>((resolve) => client.once('close', () => resolve()));

  return {
    clientId,
    client,
    messages,
    closed,
    end: () =>
      new Promise<void>((resolve) => {
        client.end(true, {}, () => resolve());
      }),
  };
}

async function connect(url: string, clientId: string, options: IClientOptions): Promise<TestClient> {
  const client = mqtt.connect(url, {
    clientId,
    reconnectPeriod: 0,
    connectTimeout: 5000,
    clean: true,
    protocolVersion: 4,
    ...options,
  });

  const wrapped = wrap(clientId, client);

  await new Promise<void>((resolve, reject) => {
    client.once('connect', () => resolve());
    client.once('error', (err) => reject(err));
    client.once('close', () => reject(new Error('connection closed before CONNACK')));
  });

  return wrapped;
}

/** Connect as a JWT publisher (username v1_{PUBLIC_KEY}, password = token). */
export function connectPublisher(
  broker: TestBroker,
  keypair: TestKeypair,
  token: string,
  clientId = `pub-${Math.random().toString(16).slice(2)}`
): Promise<TestClient> {
  return connect(broker.url, clientId, {
    username: `v1_${keypair.publicKeyHex}`,
    password: token,
  });
}

/** Connect as a configured subscriber and subscribe to the given topics. */
export async function connectSubscriber(
  broker: TestBroker,
  username: string,
  topics: string[] = ['meshcore/#']
): Promise<TestClient> {
  const subscriber = await connect(broker.url, `sub-${username}-${Math.random().toString(16).slice(2)}`, {
    username,
    password: SUBSCRIBER_PASSWORD,
  });

  for (const topic of topics) {
    const result = await subscribe(subscriber, topic);
    if (result !== 'granted') {
      throw new Error(`subscription to ${topic} was refused (${result})`);
    }
  }

  return subscriber;
}

/** Publish and resolve once the packet has been written to the socket. */
export function publish(
  publisher: TestClient,
  topic: string,
  payload: unknown,
  options: { retain?: boolean } = {}
): Promise<void> {
  const body = typeof payload === 'string' ? payload : JSON.stringify(payload);
  return new Promise<void>((resolve) => {
    publisher.client.publish(topic, body, { qos: 0, retain: options.retain ?? false }, () => resolve());
  });
}

/** Wait until the predicate holds, or fail after timeoutMs. */
export async function waitFor(
  predicate: () => boolean,
  description: string,
  timeoutMs = 3000
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) {
      return;
    }
    await delay(20);
  }
  throw new Error(`timed out after ${timeoutMs}ms waiting for ${description}`);
}

/** Give the broker time to deliver, then confirm nothing arrived. */
export async function settle(ms = 400): Promise<void> {
  await delay(ms);
}

/**
 * Subscribe to several filters in one SUBSCRIBE and report the granted QoS per
 * topic (128 = 0x80 = refused).
 *
 * Needed to show that refusing one filter leaves the rest of the SUBSCRIBE
 * intact instead of dropping the connection. mqtt.js reports any 0x80 in a
 * SUBACK as a subscribe error, but it attaches the SUBACK packet, and the
 * granted codes in it are what the broker actually answered - the connection
 * and the other filters are unaffected.
 */
export function subscribeMany(
  testClient: TestClient,
  topics: string[],
  timeoutMs = 2000
): Promise<{ topic: string; qos: number }[]> {
  const suback = new Promise<{ topic: string; qos: number }[]>((resolve, reject) => {
    testClient.client.subscribe(topics, { qos: 0 }, (err, granted) => {
      const fromSuback: number[] | undefined = (err as any)?.packet?.granted;
      if (fromSuback) {
        resolve(topics.map((topic, index) => ({ topic, qos: fromSuback[index] })));
        return;
      }
      if (err) {
        reject(err);
        return;
      }
      resolve((granted ?? []).map((g) => ({ topic: g.topic, qos: g.qos as number })));
    });
  });

  // A broker that refuses the whole SUBSCRIBE never sends a SUBACK, so fail
  // here rather than hanging until the test runner's own timeout.
  return Promise.race([
    suback,
    delay(timeoutMs).then<{ topic: string; qos: number }[]>(() => {
      throw new Error(`no SUBACK for ${topics.join(', ')} within ${timeoutMs}ms`);
    }),
  ]);
}

export type SubscribeOutcome = 'granted' | 'refused' | 'no-suback';

/**
 * Subscribe and report the outcome instead of throwing.
 *
 * A filter the broker answers with a negative SUBACK comes back as 'refused'.
 * A filter the broker refuses with an Error never gets a SUBACK at all - aedes
 * closes the MQTT session instead - so a timeout is also a valid outcome.
 */
export async function subscribe(
  testClient: TestClient,
  topic: string,
  timeoutMs = 1500
): Promise<SubscribeOutcome> {
  const settled = new Promise<SubscribeOutcome>((resolve) => {
    testClient.client.subscribe(topic, { qos: 0 }, (err, granted) => {
      if (err || !granted || granted.length === 0 || granted.some((g) => g.qos === 128)) {
        resolve('refused');
        return;
      }
      resolve('granted');
    });
  });

  return Promise.race([settled, delay(timeoutMs).then<SubscribeOutcome>(() => 'no-suback')]);
}

/**
 * Assert that the broker dropped this client's MQTT session.
 *
 * The broker's WebSocket adapter does not close the underlying socket when the
 * broker closes a client, so the client side can stay unaware; what matters is
 * that the broker unregistered the session and stops handling its packets.
 */
export async function expectSessionClosed(
  broker: TestBroker,
  clientId: string,
  timeoutMs = 3000
): Promise<void> {
  await waitFor(
    () => !broker.sessionIds().includes(clientId),
    `the broker to drop the session of ${clientId}`,
    timeoutMs
  );
}

/** Wait until the broker logged a line containing every fragment. */
export async function expectLogLine(
  broker: TestBroker,
  fragments: string[],
  timeoutMs = 3000
): Promise<void> {
  await waitFor(
    () => broker.logLines().some((entry) => fragments.every((fragment) => entry.includes(fragment))),
    `a log line containing: ${fragments.join(' | ')}`,
    timeoutMs
  );
}
