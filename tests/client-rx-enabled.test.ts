/**
 * In-process integration tests for the client RX namespace with
 * CLIENT_RX_ENABLED=true and a single allowlisted subscriber.
 */
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';

import {
  SUBSCRIBER_PASSWORD,
  TestBroker,
  TestKeypair,
  connectPublisher,
  connectSubscriber,
  createTestKeypair,
  createTestToken,
  expectLogLine,
  expectSessionClosed,
  forgeTokenSignature,
  publish,
  settle,
  startTestBroker,
  subscribe,
  subscribeMany,
  waitFor,
} from './helpers/broker';

const ALLOWLISTED = 'ingest';
const NOT_ALLOWLISTED = 'viewer';
const ADMIN = 'admin';
const TYPO = 'ingset';

let broker: TestBroker;

before(async () => {
  broker = await startTestBroker({
    SUBSCRIBER_1: `${ALLOWLISTED}:${SUBSCRIBER_PASSWORD}:2`,
    SUBSCRIBER_2: `${NOT_ALLOWLISTED}:${SUBSCRIBER_PASSWORD}:2`,
    SUBSCRIBER_3: `${ADMIN}:${SUBSCRIBER_PASSWORD}:1`,
    CLIENT_RX_ENABLED: 'true',
    // TYPO is deliberate: it has no SUBSCRIBER_n, so it must be called out at
    // start without affecting the name that is spelled correctly.
    CLIENT_RX_SUBSCRIBERS: `${ALLOWLISTED},${TYPO}`,
  });
});

after(async () => {
  await broker.stop();
});

function clientTopic(keypair: TestKeypair): string {
  return `meshcore/client/${keypair.publicKeyHex}/packets`;
}

const RX_PAYLOAD = { raw: 'ab'.repeat(16), lat: 55.6761, lon: 12.5683, snr: -7 };

test('an allowlisted name with no SUBSCRIBER_n is called out at startup', async () => {
  await expectLogLine(broker, [
    `CLIENT_RX_SUBSCRIBERS lists 1 name(s) with no matching SUBSCRIBER_n: ${TYPO}`,
  ]);
  // The correctly spelled name is unaffected.
  await expectLogLine(broker, ['[CONFIG] Client RX topics: enabled', 'allowlisted subscribers: 2']);
});

test('a 24h token delivers client RX packets to the allowlisted subscriber only', async () => {
  const keypair = await createTestKeypair('rx-happy-path');
  const ingest = await connectSubscriber(broker, ALLOWLISTED);
  const viewer = await connectSubscriber(broker, NOT_ALLOWLISTED);
  const admin = await connectSubscriber(broker, ADMIN);
  const publisher = await connectPublisher(broker, keypair, await createTestToken(keypair));

  const topic = clientTopic(keypair);
  await publish(publisher, topic, RX_PAYLOAD);

  await waitFor(() => ingest.messages.length > 0, 'the allowlisted subscriber to receive the packet');
  assert.deepEqual(ingest.messages, [{ topic, payload: JSON.stringify(RX_PAYLOAD) }]);

  await settle();
  assert.deepEqual(viewer.messages, [], 'a subscriber outside the allowlist must receive nothing');
  assert.deepEqual(admin.messages, [], 'admin (role 1) is not exempt from the allowlist');
  assert.ok(broker.sessionIds().includes(publisher.clientId), 'the publisher stays connected');

  await Promise.all([ingest.end(), viewer.end(), admin.end(), publisher.end()]);
});

test('client RX packets do not need an origin_id in the payload', async () => {
  const keypair = await createTestKeypair('rx-no-origin-id');
  const ingest = await connectSubscriber(broker, ALLOWLISTED);
  const publisher = await connectPublisher(broker, keypair, await createTestToken(keypair));

  await publish(publisher, clientTopic(keypair), { raw: 'cd'.repeat(8), lat: 1.5, lon: 2.5 });

  await waitFor(() => ingest.messages.length > 0, 'the packet to be delivered');
  assert.ok(broker.sessionIds().includes(publisher.clientId));

  await Promise.all([ingest.end(), publisher.end()]);
});

test('a lowercase public key in the topic is normalized', async () => {
  const keypair = await createTestKeypair('rx-lowercase-key');
  const ingest = await connectSubscriber(broker, ALLOWLISTED);
  const publisher = await connectPublisher(broker, keypair, await createTestToken(keypair));

  await publish(publisher, `meshcore/client/${keypair.publicKeyHex.toLowerCase()}/packets`, RX_PAYLOAD);

  await waitFor(() => ingest.messages.length > 0, 'the normalized packet to be delivered');
  assert.equal(ingest.messages[0].topic, clientTopic(keypair));

  await Promise.all([ingest.end(), publisher.end()]);
});

test('the public key in the topic must be the publisher own key', async () => {
  const keypair = await createTestKeypair('rx-own-key');
  const other = await createTestKeypair('rx-other-key');
  const ingest = await connectSubscriber(broker, ALLOWLISTED);
  const publisher = await connectPublisher(broker, keypair, await createTestToken(keypair));

  await publish(publisher, clientTopic(other), RX_PAYLOAD);

  await expectSessionClosed(broker, publisher.clientId);
  await expectLogLine(broker, ['✗ Publish denied', clientTopic(other), '(pubkey mismatch)']);
  assert.deepEqual(ingest.messages, [], 'a packet under a foreign public key must not be delivered');

  await ingest.end();
});

test('a malformed topic inside the namespace is rejected', async () => {
  const keypair = await createTestKeypair('rx-malformed-topic');
  const ingest = await connectSubscriber(broker, ALLOWLISTED);
  const publisher = await connectPublisher(broker, keypair, await createTestToken(keypair));

  const topic = `meshcore/client/${keypair.publicKeyHex}/packets/extra`;
  await publish(publisher, topic, RX_PAYLOAD);

  await expectSessionClosed(broker, publisher.clientId);
  await expectLogLine(broker, ['✗ Publish denied', topic, '(invalid client RX topic)']);
  assert.deepEqual(ingest.messages, []);

  await ingest.end();
});

test('a retained client RX publish is rejected', async () => {
  const keypair = await createTestKeypair('rx-retained');
  const ingest = await connectSubscriber(broker, ALLOWLISTED);
  const publisher = await connectPublisher(broker, keypair, await createTestToken(keypair));

  await publish(publisher, clientTopic(keypair), RX_PAYLOAD, { retain: true });

  await expectSessionClosed(broker, publisher.clientId);
  await expectLogLine(broker, ['✗ Publish denied', clientTopic(keypair), '(retained client RX publish)']);
  assert.deepEqual(ingest.messages, [], 'a retained position must never be stored or delivered');

  // A subscriber connecting afterwards must not find a retained message either.
  const late = await connectSubscriber(broker, ALLOWLISTED);
  await settle();
  assert.deepEqual(late.messages, []);

  await Promise.all([ingest.end(), late.end()]);
});

test('a token without exp cannot publish client RX packets', async () => {
  const keypair = await createTestKeypair('rx-no-exp');
  const ingest = await connectSubscriber(broker, ALLOWLISTED);
  const publisher = await connectPublisher(broker, keypair, await createTestToken(keypair, { exp: null }));

  await publish(publisher, clientTopic(keypair), RX_PAYLOAD);

  await expectSessionClosed(broker, publisher.clientId);
  await expectLogLine(broker, ['✗ Publish denied', clientTopic(keypair), '(token missing_exp)']);
  assert.deepEqual(ingest.messages, []);

  await ingest.end();
});

test('a token that expires at or before iat cannot publish client RX packets', async () => {
  const keypair = await createTestKeypair('rx-nonpositive-lifetime');
  const ingest = await connectSubscriber(broker, ALLOWLISTED);
  // exp is still in the future, so the decoder lets the client connect, and
  // iat stays inside the accepted clock skew - only the lifetime is malformed.
  const iat = Math.floor(Date.now() / 1000) + 200;
  const publisher = await connectPublisher(broker, keypair, await createTestToken(keypair, { iat, exp: iat - 100 }));

  await publish(publisher, clientTopic(keypair), RX_PAYLOAD);

  await expectSessionClosed(broker, publisher.clientId);
  await expectLogLine(broker, ['✗ Publish denied', clientTopic(keypair), '(token nonpositive_lifetime)']);
  assert.deepEqual(ingest.messages, []);

  await ingest.end();
});

test('a token with a lifetime above 24h cannot publish client RX packets', async () => {
  const keypair = await createTestKeypair('rx-long-lifetime');
  const ingest = await connectSubscriber(broker, ALLOWLISTED);
  const iat = Math.floor(Date.now() / 1000);
  const publisher = await connectPublisher(
    broker,
    keypair,
    await createTestToken(keypair, { iat, exp: iat + 86401 })
  );

  await publish(publisher, clientTopic(keypair), RX_PAYLOAD);

  await expectSessionClosed(broker, publisher.clientId);
  await expectLogLine(broker, ['✗ Publish denied', clientTopic(keypair), '(token lifetime_too_long)']);
  assert.deepEqual(ingest.messages, []);

  await ingest.end();
});

test('a token that expires during the connection stops further publishes', async () => {
  const keypair = await createTestKeypair('rx-expires-midway');
  const ingest = await connectSubscriber(broker, ALLOWLISTED);
  const iat = Math.floor(Date.now() / 1000);
  const publisher = await connectPublisher(
    broker,
    keypair,
    await createTestToken(keypair, { iat, exp: iat + 2 })
  );

  const topic = clientTopic(keypair);
  await publish(publisher, topic, { ...RX_PAYLOAD, seq: 1 });
  await waitFor(() => ingest.messages.length === 1, 'the publish before expiry to be delivered');

  await settle(3000);
  await publish(publisher, topic, { ...RX_PAYLOAD, seq: 2 });

  await expectSessionClosed(broker, publisher.clientId);
  await expectLogLine(broker, ['✗ Publish denied', topic, '(token expired)']);
  assert.equal(ingest.messages.length, 1, 'the publish after expiry must be rejected');

  await ingest.end();
});

test('an already expired token cannot connect at all', async () => {
  const keypair = await createTestKeypair('rx-expired-at-connect');
  const iat = Math.floor(Date.now() / 1000) - 3600;

  const token = await createTestToken(keypair, { iat, exp: iat + 60 });

  await assert.rejects(() => connectPublisher(broker, keypair, token));
});

test('a subscriber outside the allowlist cannot subscribe to the namespace explicitly', async () => {
  for (const username of [NOT_ALLOWLISTED, ADMIN]) {
    const subscriber = await connectSubscriber(broker, username, []);
    const outcome = await subscribe(subscriber, 'meshcore/client/#');

    assert.equal(outcome, 'refused', `${username} must not be granted a client RX subscription`);
    await expectLogLine(broker, ['✗ Subscribe denied (client RX not allowlisted)', 'meshcore/client/#']);
    // Refusing the filter must not cost the subscriber its session.
    assert.ok(
      broker.sessionIds().includes(subscriber.clientId),
      `${username} must keep its session after a refused client RX subscription`
    );
    await subscriber.end();
  }

  const ingest = await connectSubscriber(broker, ALLOWLISTED, ['meshcore/client/#']);
  assert.ok(broker.sessionIds().includes(ingest.clientId));
  await ingest.end();
});

test('refusing one filter leaves the rest of the SUBSCRIBE working', async () => {
  // An admin dashboard subscribing to a topic list that happens to include
  // meshcore/client/# must keep every other topic in that list.
  const keypair = await createTestKeypair('rx-partial-suback');
  const admin = await connectSubscriber(broker, ADMIN, []);

  const granted = await subscribeMany(admin, [
    'meshcore/SEA/#',
    'meshcore/client/#',
    '$SYS/#',
  ]);

  assert.deepEqual(granted, [
    { topic: 'meshcore/SEA/#', qos: 0 },
    { topic: 'meshcore/client/#', qos: 128 },
    { topic: '$SYS/#', qos: 0 },
  ]);
  assert.ok(broker.sessionIds().includes(admin.clientId), 'the session must survive a negative SUBACK');

  // The granted observer filter still delivers.
  const publisher = await connectPublisher(broker, keypair, await createTestToken(keypair));
  const topic = `meshcore/SEA/${keypair.publicKeyHex}/packets`;
  const payload = { origin_id: keypair.publicKeyHex, raw: 'cd'.repeat(8) };
  await publish(publisher, topic, payload);

  await waitFor(
    () => admin.messages.some((m) => m.topic === topic),
    'the observer packet on the still-granted filter'
  );

  // ...and the refused filter delivers nothing.
  await publish(publisher, clientTopic(keypair), RX_PAYLOAD);
  await settle();
  assert.deepEqual(
    admin.messages.filter((m) => m.topic.startsWith('meshcore/client/')),
    [],
    'the refused filter must not deliver client RX packets'
  );

  await Promise.all([admin.end(), publisher.end()]);
});

test('a wildcard subscription outside the allowlist is granted but filtered', async () => {
  const keypair = await createTestKeypair('rx-wildcard-filtered');
  const viewer = await connectSubscriber(broker, NOT_ALLOWLISTED, ['meshcore/#', '#']);
  const publisher = await connectPublisher(broker, keypair, await createTestToken(keypair));

  await publish(publisher, clientTopic(keypair), RX_PAYLOAD);
  await settle();

  assert.deepEqual(viewer.messages, [], 'a wildcard subscription must not sidestep the allowlist');

  await Promise.all([viewer.end(), publisher.end()]);
});

test('observer topics are unchanged', async () => {
  const keypair = await createTestKeypair('observer-unchanged');
  const ingest = await connectSubscriber(broker, ALLOWLISTED);
  const viewer = await connectSubscriber(broker, NOT_ALLOWLISTED);
  const publisher = await connectPublisher(broker, keypair, await createTestToken(keypair));

  const topic = `meshcore/SEA/${keypair.publicKeyHex}/packets`;
  const payload = { origin_id: keypair.publicKeyHex, raw: 'ef'.repeat(8) };
  await publish(publisher, topic, payload);

  await waitFor(
    () => ingest.messages.length > 0 && viewer.messages.length > 0,
    'both subscribers to receive the observer packet'
  );
  assert.deepEqual(ingest.messages, [{ topic, payload: JSON.stringify(payload) }]);
  assert.deepEqual(viewer.messages, [{ topic, payload: JSON.stringify(payload) }]);
  assert.ok(broker.sessionIds().includes(publisher.clientId));

  await Promise.all([ingest.end(), viewer.end(), publisher.end()]);
});

test('an observer publish without origin_id is still rejected', async () => {
  const keypair = await createTestKeypair('observer-missing-origin');
  const ingest = await connectSubscriber(broker, ALLOWLISTED);
  const publisher = await connectPublisher(broker, keypair, await createTestToken(keypair));

  await publish(publisher, `meshcore/SEA/${keypair.publicKeyHex}/packets`, { raw: 'ab' });

  await expectSessionClosed(broker, publisher.clientId);
  assert.deepEqual(ingest.messages, []);

  await ingest.end();
});

test('an observer token without exp still works', async () => {
  const keypair = await createTestKeypair('observer-no-exp');
  const ingest = await connectSubscriber(broker, ALLOWLISTED);
  const publisher = await connectPublisher(broker, keypair, await createTestToken(keypair, { exp: null }));

  const topic = `meshcore/SEA/${keypair.publicKeyHex}/packets`;
  const payload = { origin_id: keypair.publicKeyHex, raw: '0f'.repeat(8) };
  await publish(publisher, topic, payload);

  await waitFor(() => ingest.messages.length > 0, 'observer delivery with an exp-less token');
  assert.ok(broker.sessionIds().includes(publisher.clientId));

  await Promise.all([ingest.end(), publisher.end()]);
});

test('no token material is logged for accepted, forged or expired logins', async () => {
  const keypair = await createTestKeypair('log-hygiene');
  const iat = Math.floor(Date.now() / 1000);

  const accepted = await createTestToken(keypair, { iat, exp: iat + 86400 });
  const forged = forgeTokenSignature(accepted);
  const expiredIat = iat - 7200;
  const expired = await createTestToken(keypair, { iat: expiredIat, exp: expiredIat + 60 });

  const publisher = await connectPublisher(broker, keypair, accepted);
  await publisher.end();
  await assert.rejects(() => connectPublisher(broker, keypair, forged));
  await assert.rejects(() => connectPublisher(broker, keypair, expired));

  const log = broker.logLines().join('\n');
  for (const [name, token] of [
    ['accepted', accepted],
    ['forged', forged],
    ['expired', expired],
  ] as const) {
    const [, payloadSegment, signature] = token.split('.');
    assert.equal(log.includes(token), false, `the ${name} token must not appear in the log`);
    assert.equal(
      log.includes(Buffer.from(token).toString('hex')),
      false,
      `the ${name} token hex must not appear in the log`
    );
    assert.equal(log.includes(signature), false, `the ${name} token signature must not appear in the log`);
    assert.equal(log.includes(payloadSegment), false, `the ${name} token payload must not appear in the log`);
  }

  // Anchored on purpose: a [CLAIMS] line must carry the claim *shape* and
  // nothing else, so an extra field appended to it fails here.
  const claimLines = broker.logLines().filter((line) => line.includes('[CLAIMS]'));
  assert.ok(claimLines.length > 0, 'every publisher login must log a [CLAIMS] line');
  for (const line of claimLines) {
    assert.match(
      line,
      /^\[O:[0-9A-F]{8}\] \[AUTH\] \[CLAIMS\] has_exp=(true|false) lifetime_h=(-?\d+|n\/a) has_aud=(true|false)$/,
      `the [CLAIMS] line must contain the claim shape only: ${line}`
    );
  }
  assert.ok(
    claimLines.some((line) => line === `[O:${keypair.publicKeyHex.slice(0, 8)}] [AUTH] [CLAIMS] has_exp=true lifetime_h=24 has_aud=true`),
    'the accepted 24h token must be reported as a 24h token'
  );
});
