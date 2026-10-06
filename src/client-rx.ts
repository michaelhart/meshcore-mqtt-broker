/**
 * Client RX coverage topics.
 *
 * Mobile clients can report the packets their radio received to
 * `meshcore/client/{PUBLIC_KEY}/packets`. Those payloads carry a precise
 * position, so the namespace is treated as sensitive:
 *
 *   - it is opt-in (CLIENT_RX_ENABLED),
 *   - a publisher may only use its own public key,
 *   - messages are never retained by the broker,
 *   - the publisher token must carry a short-lived `exp`,
 *   - and packets are only delivered to subscriber usernames that are
 *     explicitly allowlisted in CLIENT_RX_SUBSCRIBERS.
 *
 * Everything in this module is pure so it can be unit tested without a broker.
 */

/** Topic namespace reserved for client-reported RX coverage. */
export const CLIENT_RX_TOPIC_PREFIX = 'meshcore/client/';

/** Subtopic a client is allowed to publish to inside the namespace. */
export const CLIENT_RX_SUBTOPIC = 'packets';

/** Upper bound for CLIENT_RX_MAX_TOKEN_LIFETIME_S (24 hours). */
export const CLIENT_RX_MAX_TOKEN_LIFETIME_LIMIT_S = 86400;

/** Default token lifetime budget when CLIENT_RX_MAX_TOKEN_LIFETIME_S is unset. */
export const CLIENT_RX_DEFAULT_MAX_TOKEN_LIFETIME_S = 86400;

/** Default tolerance for a client clock running ahead of the broker. */
export const CLIENT_RX_DEFAULT_CLOCK_SKEW_S = 300;

/**
 * Upper bound for CLIENT_RX_CLOCK_SKEW_S (1 hour).
 *
 * The skew is added to the token lifetime budget: a token stays usable for up
 * to `lifetime + skew` after it was minted, so this ceiling is deliberately
 * much lower than the lifetime ceiling.
 */
export const CLIENT_RX_CLOCK_SKEW_LIMIT_S = 3600;

export interface ClientRxConfig {
  /** When false the namespace is rejected exactly like any other unknown topic. */
  enabled: boolean;
  /** Subscriber usernames allowed to receive client RX packets. */
  subscribers: string[];
  /** Maximum accepted `exp - iat` of a publisher token, in seconds. */
  maxTokenLifetimeS: number;
  /** Accepted amount of `iat` in the future, in seconds. */
  clockSkewS: number;
}

export interface ClientRxConfigResult {
  config: ClientRxConfig;
  /**
   * Problems found while parsing the environment, meant to be logged at start.
   * An out of range or non numeric value is corrected rather than fatal, but it
   * is never corrected silently: an operator who typed
   * CLIENT_RX_MAX_TOKEN_LIFETIME_S=0 asked for the strictest budget and would
   * otherwise get the loosest one.
   */
  problems: string[];
}

const PUBLIC_KEY_PATTERN = /^[0-9A-Fa-f]{64}$/;
const INTEGER_PATTERN = /^[+-]?\d+$/;

/**
 * True when a topic falls inside the client RX namespace.
 *
 * Used as the gate for both publish authorization and per-packet forwarding,
 * so that a wildcard subscription cannot sidestep the allowlist.
 */
export function isClientRxNamespace(topic: string): boolean {
  return topic.startsWith(CLIENT_RX_TOPIC_PREFIX);
}

/**
 * Parse `meshcore/client/{PUBLIC_KEY}/packets`.
 *
 * Returns null unless the topic has exactly 4 segments, uses the lowercase
 * `client` literal and carries a 64 hex character public key. The returned key
 * is uppercased so it can be compared with the authenticated public key.
 */
export function parseClientRxTopic(topic: string): { publicKey: string } | null {
  const parts = topic.split('/');
  if (parts.length !== 4) {
    return null;
  }

  const [root, namespace, publicKey, subtopic] = parts;
  if (root !== 'meshcore' || namespace !== 'client' || subtopic !== CLIENT_RX_SUBTOPIC) {
    return null;
  }
  if (!PUBLIC_KEY_PATTERN.test(publicKey)) {
    return null;
  }

  return { publicKey: publicKey.toUpperCase() };
}

/** True when a topic is a well formed client RX publish topic. */
export function isClientRxTopic(topic: string): boolean {
  return parseClientRxTopic(topic) !== null;
}

/** Canonical (uppercase public key) form of a client RX topic. */
export function clientRxTopic(publicKey: string): string {
  return `${CLIENT_RX_TOPIC_PREFIX}${publicKey.toUpperCase()}/${CLIENT_RX_SUBTOPIC}`;
}

/** Parse a comma separated CLIENT_RX_SUBSCRIBERS list into unique usernames. */
export function parseClientRxSubscribers(raw: string | undefined): string[] {
  if (!raw) {
    return [];
  }

  const seen = new Set<string>();
  for (const entry of raw.split(',')) {
    const username = entry.trim();
    if (username) {
      seen.add(username);
    }
  }
  return Array.from(seen);
}

/**
 * Allowlisted usernames that do not correspond to a configured subscriber.
 *
 * CLIENT_RX_SUBSCRIBERS is matched against SUBSCRIBER_n usernames by exact
 * string, so a typo means nobody ever receives anything. That is impossible to
 * tell apart from "correctly configured, no traffic yet", so it is reported at
 * start.
 */
export function findUnknownClientRxSubscribers(
  subscribers: readonly string[],
  knownUsernames: ReadonlySet<string>
): string[] {
  return subscribers.filter((username) => !knownUsernames.has(username));
}

export interface ClientRxRecipient {
  /** True only for authenticated subscriber (subscribe-only) clients. */
  isSubscriber: boolean;
  /** Subscriber username, as configured in SUBSCRIBER_n. */
  username?: string;
}

/**
 * Decide whether a single packet may be delivered to one client.
 *
 * Returns true for every topic outside the client RX namespace, so this can be
 * called for all forwarded packets. Inside the namespace, delivery requires an
 * allowlisted subscriber username - publishers and non-listed subscribers
 * (including admins) never receive client RX data.
 */
export function shouldForwardClientRx(
  topic: string,
  recipient: ClientRxRecipient,
  subscribers: readonly string[]
): boolean {
  if (!isClientRxNamespace(topic)) {
    return true;
  }
  if (!recipient.isSubscriber || !recipient.username) {
    return false;
  }
  return subscribers.includes(recipient.username);
}

export type ClientRxTokenRejection =
  | 'missing_iat'
  | 'missing_exp'
  | 'iat_in_future'
  | 'nonpositive_lifetime'
  | 'lifetime_too_long'
  | 'expired';

export interface ClientRxTokenResult {
  ok: boolean;
  reason?: ClientRxTokenRejection;
  /** `exp - iat` in seconds, when both claims are present. */
  lifetimeS?: number;
}

function asSeconds(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/**
 * Validate the time claims of a publisher token for a client RX publish.
 *
 * The token signature is checked at connect time by the decoder; the decoder
 * only looks at `exp` when it is present, and a long lived connection can
 * outlive its token, so the time claims are re-checked on every publish.
 */
export function validateClientRxToken(
  payload: { iat?: unknown; exp?: unknown } | null | undefined,
  nowS: number,
  limits: Pick<ClientRxConfig, 'maxTokenLifetimeS' | 'clockSkewS'>
): ClientRxTokenResult {
  const iat = asSeconds(payload?.iat);
  if (iat === null) {
    return { ok: false, reason: 'missing_iat' };
  }

  const exp = asSeconds(payload?.exp);
  if (exp === null) {
    return { ok: false, reason: 'missing_exp' };
  }

  const lifetimeS = exp - iat;
  if (iat > nowS + limits.clockSkewS) {
    return { ok: false, reason: 'iat_in_future', lifetimeS };
  }
  // A token that expires at or before it was issued is malformed. It is still
  // bounded by `exp`, so this is not a hole, but there is no reason to accept
  // it on a namespace that requires a deliberate short lifetime.
  if (lifetimeS <= 0) {
    return { ok: false, reason: 'nonpositive_lifetime', lifetimeS };
  }
  if (lifetimeS > limits.maxTokenLifetimeS) {
    return { ok: false, reason: 'lifetime_too_long', lifetimeS };
  }
  if (nowS > exp) {
    return { ok: false, reason: 'expired', lifetimeS };
  }

  return { ok: true, lifetimeS };
}

export interface TokenClaimShape {
  has_exp: boolean;
  /** Rounded `exp - iat` in hours, or null when the shape cannot be measured. */
  lifetime_hours: number | null;
  has_aud: boolean;
}

/**
 * Describe the *shape* of a token's claims for measurement logging.
 *
 * Deliberately returns booleans and a rounded duration only: no token, no
 * signature and no claim values are ever derived from the payload.
 */
export function describeTokenClaims(
  payload: { iat?: unknown; exp?: unknown; aud?: unknown } | null | undefined
): TokenClaimShape {
  const iat = asSeconds(payload?.iat);
  const exp = asSeconds(payload?.exp);
  const hasAud = typeof payload?.aud === 'string' && payload.aud.length > 0;

  return {
    has_exp: exp !== null,
    lifetime_hours: iat !== null && exp !== null ? Math.round((exp - iat) / 3600) : null,
    has_aud: hasAud,
  };
}

/** Render a claim shape as a single log friendly, value free string. */
export function formatTokenClaimShape(shape: TokenClaimShape): string {
  const lifetime = shape.lifetime_hours === null ? 'n/a' : `${shape.lifetime_hours}`;
  return `has_exp=${shape.has_exp} lifetime_h=${lifetime} has_aud=${shape.has_aud}`;
}

function parseBoundedInt(
  problems: string[],
  name: string,
  raw: string | undefined,
  fallback: number,
  min: number,
  max: number
): number {
  if (raw === undefined || raw.trim() === '') {
    return fallback;
  }

  const trimmed = raw.trim();
  // Number.parseInt would happily read "3600abc" as 3600.
  const parsed = INTEGER_PATTERN.test(trimmed) ? Number.parseInt(trimmed, 10) : Number.NaN;
  if (!Number.isFinite(parsed) || parsed < min) {
    problems.push(`${name}=${trimmed} is not an integer >= ${min} - using the default ${fallback}`);
    return fallback;
  }
  if (parsed > max) {
    problems.push(`${name}=${trimmed} is above the ${max} ceiling - using ${max}`);
    return max;
  }
  return parsed;
}

/**
 * Build the client RX configuration from an environment-like object.
 *
 * Every variable is optional: with none of them set the feature is disabled
 * and the namespace is rejected like any other unknown topic.
 */
export function resolveClientRxConfig(env: Record<string, string | undefined>): ClientRxConfigResult {
  const problems: string[] = [];

  const config: ClientRxConfig = {
    enabled: env.CLIENT_RX_ENABLED === 'true',
    subscribers: parseClientRxSubscribers(env.CLIENT_RX_SUBSCRIBERS),
    maxTokenLifetimeS: parseBoundedInt(
      problems,
      'CLIENT_RX_MAX_TOKEN_LIFETIME_S',
      env.CLIENT_RX_MAX_TOKEN_LIFETIME_S,
      CLIENT_RX_DEFAULT_MAX_TOKEN_LIFETIME_S,
      1,
      CLIENT_RX_MAX_TOKEN_LIFETIME_LIMIT_S
    ),
    clockSkewS: parseBoundedInt(
      problems,
      'CLIENT_RX_CLOCK_SKEW_S',
      env.CLIENT_RX_CLOCK_SKEW_S,
      CLIENT_RX_DEFAULT_CLOCK_SKEW_S,
      0,
      CLIENT_RX_CLOCK_SKEW_LIMIT_S
    ),
  };

  return { config, problems };
}
