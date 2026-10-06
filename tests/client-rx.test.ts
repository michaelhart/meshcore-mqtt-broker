import test from 'node:test';
import assert from 'node:assert/strict';

import {
  CLIENT_RX_CLOCK_SKEW_LIMIT_S,
  CLIENT_RX_DEFAULT_CLOCK_SKEW_S,
  CLIENT_RX_DEFAULT_MAX_TOKEN_LIFETIME_S,
  CLIENT_RX_MAX_TOKEN_LIFETIME_LIMIT_S,
  clientRxTopic,
  describeTokenClaims,
  findUnknownClientRxSubscribers,
  formatTokenClaimShape,
  isClientRxNamespace,
  isClientRxTopic,
  parseClientRxSubscribers,
  parseClientRxTopic,
  resolveClientRxConfig,
  shouldForwardClientRx,
  validateClientRxToken,
} from '../src/client-rx';

const PUBKEY = 'A'.repeat(64);
const OTHER_PUBKEY = 'B'.repeat(64);
const LIMITS = { maxTokenLifetimeS: 86400, clockSkewS: 300 };

test('isClientRxTopic accepts meshcore/client/{PUBKEY}/packets', () => {
  assert.equal(isClientRxTopic(`meshcore/client/${PUBKEY}/packets`), true);
  assert.equal(isClientRxTopic(`meshcore/client/${PUBKEY.toLowerCase()}/packets`), true);
});

test('isClientRxTopic requires exactly four segments', () => {
  assert.equal(isClientRxTopic(`meshcore/client/${PUBKEY}`), false);
  assert.equal(isClientRxTopic(`meshcore/client/${PUBKEY}/packets/extra`), false);
  assert.equal(isClientRxTopic(`meshcore/client/${PUBKEY}/packets/`), false);
  assert.equal(isClientRxTopic(`prefix/meshcore/client/${PUBKEY}/packets`), false);
});

test('isClientRxTopic requires the lowercase client literal', () => {
  assert.equal(isClientRxTopic(`meshcore/Client/${PUBKEY}/packets`), false);
  assert.equal(isClientRxTopic(`meshcore/CLIENT/${PUBKEY}/packets`), false);
  assert.equal(isClientRxTopic(`meshcore/clients/${PUBKEY}/packets`), false);
});

test('isClientRxTopic requires a 64 hex character public key', () => {
  assert.equal(isClientRxTopic('meshcore/client/abc/packets'), false);
  assert.equal(isClientRxTopic(`meshcore/client/${'A'.repeat(63)}/packets`), false);
  assert.equal(isClientRxTopic(`meshcore/client/${'A'.repeat(65)}/packets`), false);
  assert.equal(isClientRxTopic(`meshcore/client/${'Z'.repeat(64)}/packets`), false);
  assert.equal(isClientRxTopic(`meshcore/client/${' ' + 'A'.repeat(63)}/packets`), false);
});

test('isClientRxTopic only accepts the packets subtopic', () => {
  assert.equal(isClientRxTopic(`meshcore/client/${PUBKEY}/status`), false);
  assert.equal(isClientRxTopic(`meshcore/client/${PUBKEY}/internal`), false);
  assert.equal(isClientRxTopic(`meshcore/client/${PUBKEY}/Packets`), false);
});

test('parseClientRxTopic returns the uppercased public key', () => {
  assert.deepEqual(parseClientRxTopic(`meshcore/client/${PUBKEY.toLowerCase()}/packets`), {
    publicKey: PUBKEY,
  });
  assert.equal(parseClientRxTopic('meshcore/XYZ/pubkey/packets'), null);
});

test('clientRxTopic builds the canonical topic', () => {
  assert.equal(clientRxTopic(PUBKEY.toLowerCase()), `meshcore/client/${PUBKEY}/packets`);
});

test('isClientRxNamespace covers malformed topics inside the namespace', () => {
  assert.equal(isClientRxNamespace(`meshcore/client/${PUBKEY}/packets`), true);
  assert.equal(isClientRxNamespace('meshcore/client/anything/at/all'), true);
  assert.equal(isClientRxNamespace('meshcore/client/'), true);
  assert.equal(isClientRxNamespace('meshcore/SEA/pubkey/packets'), false);
  assert.equal(isClientRxNamespace('meshcore/clientele/x/packets'), false);
});

test('parseClientRxSubscribers trims, drops empties and dedupes', () => {
  assert.deepEqual(parseClientRxSubscribers('ingest'), ['ingest']);
  assert.deepEqual(parseClientRxSubscribers(' ingest , other '), ['ingest', 'other']);
  assert.deepEqual(parseClientRxSubscribers('ingest,,ingest,'), ['ingest']);
  assert.deepEqual(parseClientRxSubscribers(''), []);
  assert.deepEqual(parseClientRxSubscribers(undefined), []);
  assert.deepEqual(parseClientRxSubscribers('   '), []);
});

test('findUnknownClientRxSubscribers reports names with no SUBSCRIBER_n', () => {
  const known = new Set(['ingest', 'viewer']);
  assert.deepEqual(findUnknownClientRxSubscribers(['ingest'], known), []);
  assert.deepEqual(findUnknownClientRxSubscribers(['ingest', 'ingset'], known), ['ingset']);
  assert.deepEqual(findUnknownClientRxSubscribers(['a', 'b'], known), ['a', 'b']);
  // The match is exact, like the broker's own username lookup.
  assert.deepEqual(findUnknownClientRxSubscribers(['INGEST'], known), ['INGEST']);
  assert.deepEqual(findUnknownClientRxSubscribers([], known), []);
  assert.deepEqual(findUnknownClientRxSubscribers(['ingest'], new Set()), ['ingest']);
});

test('shouldForwardClientRx ignores topics outside the namespace', () => {
  for (const recipient of [
    { isSubscriber: true, username: 'nobody' },
    { isSubscriber: false },
  ]) {
    assert.equal(shouldForwardClientRx('meshcore/SEA/pubkey/packets', recipient, []), true);
    assert.equal(shouldForwardClientRx('$SYS/uptime', recipient, []), true);
  }
});

test('shouldForwardClientRx only delivers to allowlisted subscribers', () => {
  const topic = `meshcore/client/${PUBKEY}/packets`;
  assert.equal(shouldForwardClientRx(topic, { isSubscriber: true, username: 'ingest' }, ['ingest']), true);
  assert.equal(shouldForwardClientRx(topic, { isSubscriber: true, username: 'viewer' }, ['ingest']), false);
  assert.equal(shouldForwardClientRx(topic, { isSubscriber: true, username: 'admin' }, ['ingest']), false);
  assert.equal(shouldForwardClientRx(topic, { isSubscriber: true, username: 'INGEST' }, ['ingest']), false);
  assert.equal(shouldForwardClientRx(topic, { isSubscriber: false, username: 'ingest' }, ['ingest']), false);
  assert.equal(shouldForwardClientRx(topic, { isSubscriber: true }, ['ingest']), false);
});

test('shouldForwardClientRx delivers nothing when the allowlist is empty', () => {
  const topic = `meshcore/client/${PUBKEY}/packets`;
  assert.equal(shouldForwardClientRx(topic, { isSubscriber: true, username: 'ingest' }, []), false);
  assert.equal(shouldForwardClientRx('meshcore/client/anything', { isSubscriber: true, username: 'ingest' }, []), false);
});

test('shouldForwardClientRx also guards malformed topics in the namespace', () => {
  assert.equal(
    shouldForwardClientRx(`meshcore/client/${PUBKEY}/packets/extra`, { isSubscriber: true, username: 'viewer' }, ['ingest']),
    false
  );
});

test('validateClientRxToken accepts a 24h token', () => {
  const now = 1_700_000_000;
  const result = validateClientRxToken({ iat: now, exp: now + 86400 }, now, LIMITS);
  assert.deepEqual(result, { ok: true, lifetimeS: 86400 });
});

test('validateClientRxToken requires exp', () => {
  const now = 1_700_000_000;
  assert.equal(validateClientRxToken({ iat: now }, now, LIMITS).reason, 'missing_exp');
  assert.equal(validateClientRxToken({ iat: now, exp: null }, now, LIMITS).reason, 'missing_exp');
  assert.equal(validateClientRxToken({ iat: now, exp: '9999999999' }, now, LIMITS).reason, 'missing_exp');
});

test('validateClientRxToken requires iat', () => {
  const now = 1_700_000_000;
  assert.equal(validateClientRxToken({ exp: now + 10 }, now, LIMITS).reason, 'missing_iat');
  assert.equal(validateClientRxToken(null, now, LIMITS).reason, 'missing_iat');
  assert.equal(validateClientRxToken(undefined, now, LIMITS).reason, 'missing_iat');
});

test('validateClientRxToken rejects a lifetime above the budget', () => {
  const now = 1_700_000_000;
  assert.equal(validateClientRxToken({ iat: now, exp: now + 86401 }, now, LIMITS).reason, 'lifetime_too_long');
  assert.equal(validateClientRxToken({ iat: now, exp: now + 86400 }, now, LIMITS).ok, true);
  assert.equal(
    validateClientRxToken({ iat: now, exp: now + 3601 }, now, { maxTokenLifetimeS: 3600, clockSkewS: 300 }).reason,
    'lifetime_too_long'
  );
});

test('validateClientRxToken rejects a token that expires at or before iat', () => {
  const now = 1_700_000_000;
  assert.deepEqual(validateClientRxToken({ iat: now, exp: now }, now, LIMITS), {
    ok: false,
    reason: 'nonpositive_lifetime',
    lifetimeS: 0,
  });
  assert.deepEqual(validateClientRxToken({ iat: now + 200, exp: now + 100 }, now, LIMITS), {
    ok: false,
    reason: 'nonpositive_lifetime',
    lifetimeS: -100,
  });
  // One second of lifetime is still a lifetime.
  assert.equal(validateClientRxToken({ iat: now, exp: now + 1 }, now, LIMITS).ok, true);
});

test('validateClientRxToken rejects iat too far in the future', () => {
  const now = 1_700_000_000;
  assert.equal(validateClientRxToken({ iat: now + 301, exp: now + 400 }, now, LIMITS).reason, 'iat_in_future');
  assert.equal(validateClientRxToken({ iat: now + 300, exp: now + 400 }, now, LIMITS).ok, true);
});

test('validateClientRxToken rejects an expired token at publish time', () => {
  const iat = 1_700_000_000;
  assert.equal(validateClientRxToken({ iat, exp: iat + 60 }, iat + 61, LIMITS).reason, 'expired');
  assert.equal(validateClientRxToken({ iat, exp: iat + 60 }, iat + 60, LIMITS).ok, true);
});

test('validateClientRxToken checks lifetime before expiry', () => {
  const iat = 1_700_000_000;
  const result = validateClientRxToken({ iat, exp: iat + 999_999 }, iat + 1_000_000, LIMITS);
  assert.equal(result.reason, 'lifetime_too_long');
});

test('describeTokenClaims reports claim shape only', () => {
  const iat = 1_700_000_000;
  assert.deepEqual(describeTokenClaims({ iat, exp: iat + 86400, aud: 'mqtt.example.com' }), {
    has_exp: true,
    lifetime_hours: 24,
    has_aud: true,
  });
  assert.deepEqual(describeTokenClaims({ iat, exp: iat + 5400 }), {
    has_exp: true,
    lifetime_hours: 2,
    has_aud: false,
  });
  assert.deepEqual(describeTokenClaims({ iat }), {
    has_exp: false,
    lifetime_hours: null,
    has_aud: false,
  });
  assert.deepEqual(describeTokenClaims({ iat, exp: iat + 86400, aud: '' }).has_aud, false);
});

test('formatTokenClaimShape never leaks claim values', () => {
  const iat = 1_700_000_000;
  const line = formatTokenClaimShape(describeTokenClaims({ iat, exp: iat + 86400, aud: 'mqtt.example.com' }));
  assert.equal(line, 'has_exp=true lifetime_h=24 has_aud=true');
  assert.equal(line.includes('mqtt.example.com'), false);
  assert.equal(line.includes(String(iat)), false);

  assert.equal(formatTokenClaimShape(describeTokenClaims({ iat })), 'has_exp=false lifetime_h=n/a has_aud=false');
});

test('resolveClientRxConfig defaults to the feature being off', () => {
  assert.deepEqual(resolveClientRxConfig({}), {
    config: {
      enabled: false,
      subscribers: [],
      maxTokenLifetimeS: CLIENT_RX_DEFAULT_MAX_TOKEN_LIFETIME_S,
      clockSkewS: CLIENT_RX_DEFAULT_CLOCK_SKEW_S,
    },
    problems: [],
  });
  assert.equal(resolveClientRxConfig({ CLIENT_RX_ENABLED: 'TRUE' }).config.enabled, false);
  assert.equal(resolveClientRxConfig({ CLIENT_RX_ENABLED: '1' }).config.enabled, false);
  assert.equal(resolveClientRxConfig({ CLIENT_RX_ENABLED: 'true' }).config.enabled, true);
});

test('resolveClientRxConfig caps the token lifetime at 24h', () => {
  const capped = resolveClientRxConfig({ CLIENT_RX_MAX_TOKEN_LIFETIME_S: '999999' });
  assert.equal(capped.config.maxTokenLifetimeS, CLIENT_RX_MAX_TOKEN_LIFETIME_LIMIT_S);
  assert.deepEqual(capped.problems, [
    `CLIENT_RX_MAX_TOKEN_LIFETIME_S=999999 is above the ${CLIENT_RX_MAX_TOKEN_LIFETIME_LIMIT_S} ceiling - using ${CLIENT_RX_MAX_TOKEN_LIFETIME_LIMIT_S}`,
  ]);

  const exact = resolveClientRxConfig({ CLIENT_RX_MAX_TOKEN_LIFETIME_S: '3600' });
  assert.equal(exact.config.maxTokenLifetimeS, 3600);
  assert.deepEqual(exact.problems, []);
});

test('resolveClientRxConfig warns instead of silently using the default', () => {
  // 0, a negative value, trailing garbage and plain nonsense all fall back to
  // the *maximum* lifetime, which is the opposite of what was asked for, so
  // none of them may be corrected quietly.
  for (const raw of ['0', '-5', 'not-a-number', '3600abc', '1e3', ' ']) {
    const resolved = resolveClientRxConfig({ CLIENT_RX_MAX_TOKEN_LIFETIME_S: raw });
    assert.equal(
      resolved.config.maxTokenLifetimeS,
      CLIENT_RX_DEFAULT_MAX_TOKEN_LIFETIME_S,
      `${JSON.stringify(raw)} must fall back to the default lifetime`
    );
    if (raw.trim() === '') {
      // An unset variable is not a problem worth warning about.
      assert.deepEqual(resolved.problems, []);
      continue;
    }
    assert.deepEqual(resolved.problems, [
      `CLIENT_RX_MAX_TOKEN_LIFETIME_S=${raw.trim()} is not an integer >= 1 - using the default ${CLIENT_RX_DEFAULT_MAX_TOKEN_LIFETIME_S}`,
    ]);
  }
});

test('resolveClientRxConfig caps the clock skew at an hour', () => {
  assert.equal(CLIENT_RX_CLOCK_SKEW_LIMIT_S, 3600);

  const capped = resolveClientRxConfig({ CLIENT_RX_CLOCK_SKEW_S: '86400' });
  assert.equal(capped.config.clockSkewS, CLIENT_RX_CLOCK_SKEW_LIMIT_S);
  assert.deepEqual(capped.problems, [
    `CLIENT_RX_CLOCK_SKEW_S=86400 is above the ${CLIENT_RX_CLOCK_SKEW_LIMIT_S} ceiling - using ${CLIENT_RX_CLOCK_SKEW_LIMIT_S}`,
  ]);
  assert.equal(resolveClientRxConfig({ CLIENT_RX_CLOCK_SKEW_S: '3600' }).config.clockSkewS, 3600);
});

test('resolveClientRxConfig reads skew and subscribers', () => {
  const resolved = resolveClientRxConfig({
    CLIENT_RX_ENABLED: 'true',
    CLIENT_RX_SUBSCRIBERS: 'ingest, backup',
    CLIENT_RX_CLOCK_SKEW_S: '30',
  });
  assert.deepEqual(resolved, {
    config: {
      enabled: true,
      subscribers: ['ingest', 'backup'],
      maxTokenLifetimeS: CLIENT_RX_DEFAULT_MAX_TOKEN_LIFETIME_S,
      clockSkewS: 30,
    },
    problems: [],
  });

  // 0 is a legitimate skew, so it is accepted without a warning.
  const noSkew = resolveClientRxConfig({ CLIENT_RX_CLOCK_SKEW_S: '0' });
  assert.equal(noSkew.config.clockSkewS, 0);
  assert.deepEqual(noSkew.problems, []);

  const bogus = resolveClientRxConfig({ CLIENT_RX_CLOCK_SKEW_S: 'x' });
  assert.equal(bogus.config.clockSkewS, CLIENT_RX_DEFAULT_CLOCK_SKEW_S);
  assert.deepEqual(bogus.problems, [
    `CLIENT_RX_CLOCK_SKEW_S=x is not an integer >= 0 - using the default ${CLIENT_RX_DEFAULT_CLOCK_SKEW_S}`,
  ]);
});

test('a publisher public key never matches another client topic', () => {
  const parsed = parseClientRxTopic(`meshcore/client/${OTHER_PUBKEY}/packets`);
  assert.ok(parsed);
  assert.notEqual(parsed.publicKey, PUBKEY);
});
