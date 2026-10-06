# Client RX topics

Fixed observers publish what they receive to `meshcore/{IATA}/{PUBLIC_KEY}/...`.
Mobile clients can do the same for their own radio, which makes it possible to
measure coverage from the client side. Those reports carry a precise position,
so the namespace is opt-in and narrowly scoped.

## Topic contract

```
meshcore/client/{PUBLIC_KEY}/packets
```

- exactly 4 segments, with `client` in lowercase;
- `{PUBLIC_KEY}` is 64 hex characters and must equal the authenticated
  publisher's public key (compared case-insensitively, and normalized to
  uppercase in the delivered topic);
- `packets` is the only accepted subtopic;
- anything else below `meshcore/client/` is rejected.

Differences from an observer publish:

| | observer topic | client RX topic |
| --- | --- | --- |
| IATA code | required and validated | not part of the topic |
| IATA change tracking | yes | skipped |
| `origin_id` in payload | required | not required |
| retained publish | allowed (except `/status`) | rejected |
| `/internal` JWT mirror | published (admin only) | not published |
| duplicate, rate and size checks | tracked, not enforced | tracked, not enforced |
| token `exp` | optional | required, max 24h |

The broker does not inspect the payload of a client RX publish. It feeds the
packet to the abuse detector the same way an observer publish does, so the
duplicate, rate and size counters are kept up to date, but no publish is
refused on their account - `shouldSilencePacket()` is not consulted anywhere in
the broker today. Any geofencing or position generalization is the consumer's
responsibility.

## Token requirements

A client RX publish is only accepted while the publisher's token satisfies all
of the following, re-checked on **every** publish rather than only at connect
time:

- `exp` is present. The decoder only validates `exp` when the claim exists, so
  a token without it would otherwise never expire.
- `exp - iat` is positive. A token that expires at or before it was issued is
  malformed and is refused.
- `exp - iat` is at most `CLIENT_RX_MAX_TOKEN_LIFETIME_S` (default and hard cap
  86400 seconds).
- `iat` is no more than `CLIENT_RX_CLOCK_SKEW_S` in the future (default 300,
  hard cap 3600).
- `exp` has not passed. A token can expire in the middle of a long lived
  connection; that publish is rejected and the client is closed, so the client
  has to reconnect with a fresh token.

Example of a client token:

```javascript
import { createAuthToken } from '@michaelhart/meshcore-decoder';

const iat = Math.floor(Date.now() / 1000);
const password = await createAuthToken(
  {
    publicKey,
    aud: 'mqtt.yourdomain.com', // must match AUTH_EXPECTED_AUDIENCE
    iat,
    exp: iat + 86400,          // required for client RX, at most 24h
  },
  privateKey,
  publicKey
);
```

## Delivery

`authorizeForward` drops every packet under `meshcore/client/` unless the
receiving client is a subscriber whose username appears in
`CLIENT_RX_SUBSCRIBERS`:

- the check is per packet, so a wildcard subscription (`meshcore/#`, `#`) does
  not sidestep it;
- role 1 (admin) is not exempt;
- an empty allowlist delivers client RX data to nobody;
- while the feature is enabled, an *explicit* subscription inside the namespace
  from a subscriber that is not allowlisted is answered with a negative SUBACK
  (`0x80`) for that filter, so a misconfigured consumer fails loudly instead of
  silently receiving nothing. Only that filter is refused: the connection stays
  up and every other topic in the same SUBSCRIBE is granted as usual, so a
  dashboard subscribing to a topic list that happens to include
  `meshcore/client/#` does not lose its other subscriptions.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `CLIENT_RX_ENABLED` | `false` | Set to `true` to accept the namespace. |
| `CLIENT_RX_SUBSCRIBERS` | *(empty)* | Comma separated subscriber usernames allowed to receive client RX packets. Matched against `SUBSCRIBER_n` by exact string; a name with no match is reported at start. |
| `CLIENT_RX_MAX_TOKEN_LIFETIME_S` | `86400` | Largest accepted `exp - iat`. Capped at 86400. |
| `CLIENT_RX_CLOCK_SKEW_S` | `300` | How far `iat` may be in the future. Capped at 3600. |

A token is usable for up to `lifetime + skew` after it was minted, which is why
the skew ceiling (1 hour) is much lower than the lifetime ceiling (24 hours).

A value that is above its ceiling, below its floor or not an integer at all is
corrected rather than fatal - `CLIENT_RX_MAX_TOKEN_LIFETIME_S=0` and
`CLIENT_RX_MAX_TOKEN_LIFETIME_S=3600abc` both fall back to the default - but the
correction is always logged at start:

```
[CONFIG] CLIENT_RX_MAX_TOKEN_LIFETIME_S=0 is not an integer >= 1 - using the default 86400
[CONFIG] CLIENT_RX_CLOCK_SKEW_S=86400 is above the 3600 ceiling - using 3600
```

All four are optional. With none of them set the namespace is rejected and
subscriptions are answered as before, with one deliberate difference: the
per-packet forward guard runs regardless of `CLIENT_RX_ENABLED`, so a message
under `meshcore/client/` is never delivered, not even an admin's empty retained
"delete" publish. The remaining differences are log lines only (a `[CONFIG]`
line at start, a `[CLAIMS]` line per publisher login, and a more specific deny
reason).

## Logging

The broker logs the *shape* of every publisher token at login:

```
[O:7E766267] [AUTH] [CLAIMS] has_exp=true lifetime_h=24 has_aud=true
```

Only booleans and a rounded lifetime are logged - never the token, its
signature or its payload - so an operator can measure how many publishers
already send `exp` before deciding to require it for every publisher.
