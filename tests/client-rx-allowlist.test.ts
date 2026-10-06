/**
 * In-process integration tests for a broker with the client RX feature on but
 * no allowlisted subscriber: publishing works, delivery goes nowhere.
 */
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import {
  SUBSCRIBER_PASSWORD,
  TestBroker,
  connectPublisher,
  connectSubscriber,
  createTestKeypair,
  createTestToken,
  expectLogLine,
  publish,
  settle,
  startTestBroker,
  subscribe,
  waitFor,
} from './helpers/broker';

const VIEWER = 'viewer';
const ADMIN = 'admin';

let broker: TestBroker;

before(async () => {
  broker = await startTestBroker({
    SUBSCRIBER_1: `${VIEWER}:${SUBSCRIBER_PASSWORD}:2`,
    SUBSCRIBER_2: `${ADMIN}:${SUBSCRIBER_PASSWORD}:1`,
    CLIENT_RX_ENABLED: 'true',
    // Deliberately bad: 0 is not a lifetime and 86400 is above the skew
    // ceiling. Both are corrected, and both must be reported at start.
    CLIENT_RX_MAX_TOKEN_LIFETIME_S: '0',
    CLIENT_RX_CLOCK_SKEW_S: '86400',
  });
});

after(async () => {
  await broker.stop();
});

test('an empty allowlist is called out at startup', async () => {
  await expectLogLine(broker, ['CLIENT_RX_ENABLED=true but CLIENT_RX_SUBSCRIBERS is empty']);
});

test('a corrected configuration value is reported at startup', async () => {
  // Falling back to 86400 - the loosest budget - is the opposite of what
  // CLIENT_RX_MAX_TOKEN_LIFETIME_S=0 asked for, so it may not happen quietly.
  await expectLogLine(broker, [
    'CLIENT_RX_MAX_TOKEN_LIFETIME_S=0 is not an integer >= 1 - using the default 86400',
  ]);
  await expectLogLine(broker, [
    'CLIENT_RX_CLOCK_SKEW_S=86400 is above the 3600 ceiling - using 3600',
  ]);
  await expectLogLine(broker, ['[CONFIG] Client RX topics: enabled', 'clock skew: 3600s']);
});

test('an empty allowlist delivers client RX packets to nobody', async () => {
  const keypair = await createTestKeypair('allowlist-empty');
  const viewer = await connectSubscriber(broker, VIEWER);
  const admin = await connectSubscriber(broker, ADMIN, ['meshcore/#', '$SYS/#']);
  const publisher = await connectPublisher(broker, keypair, await createTestToken(keypair));

  const topic = `meshcore/client/${keypair.publicKeyHex}/packets`;
  await publish(publisher, topic, { raw: 'ab'.repeat(8), lat: 1, lon: 2 });

  // The publish itself is authorized...
  await expectLogLine(broker, ['✓ Publish authorized (client RX)', topic]);
  await settle();

  // ...but nothing is delivered, not even to an admin subscriber.
  assert.deepEqual(
    viewer.messages.filter((m) => m.topic.startsWith('meshcore/client/')),
    []
  );
  assert.deepEqual(
    admin.messages.filter((m) => m.topic.startsWith('meshcore/client/')),
    []
  );
  assert.ok(broker.sessionIds().includes(publisher.clientId));

  await Promise.all([viewer.end(), admin.end(), publisher.end()]);
});

test('nobody can subscribe to the namespace explicitly', async () => {
  for (const username of [VIEWER, ADMIN]) {
    const subscriber = await connectSubscriber(broker, username, []);
    assert.equal(await subscribe(subscriber, `meshcore/client/#`), 'refused');
    // A negative SUBACK, not a dropped connection.
    assert.ok(broker.sessionIds().includes(subscriber.clientId));
    await subscriber.end();
  }
});

test('observer topics still reach every subscriber', async () => {
  const keypair = await createTestKeypair('allowlist-observer');
  const viewer = await connectSubscriber(broker, VIEWER);
  const publisher = await connectPublisher(broker, keypair, await createTestToken(keypair));

  const topic = `meshcore/SEA/${keypair.publicKeyHex}/packets`;
  const payload = { origin_id: keypair.publicKeyHex, raw: 'ef'.repeat(8) };
  await publish(publisher, topic, payload);

  await waitFor(() => viewer.messages.length > 0, 'the observer packet to be delivered');
  assert.deepEqual(viewer.messages, [{ topic, payload: JSON.stringify(payload) }]);

  await Promise.all([viewer.end(), publisher.end()]);
});
