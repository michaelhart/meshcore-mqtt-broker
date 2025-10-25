/**
 * Rate limiting for failed connection attempts by IP address
 */

interface RateLimitRecord {
  count: number;
  firstFailure: number;
  blockedUntil?: number;
}

export class RateLimiter {
  private failedConnectionsByIP = new Map<string, RateLimitRecord>();
  private readonly windowMs: number;
  private readonly maxFailedConnections: number;
  private readonly blockDurationMs: number;

  constructor(
    windowMs: number = 60000,        // 1 minute
    maxFailedConnections: number = 10,
    blockDurationMs: number = 300000  // 5 minutes
  ) {
    this.windowMs = windowMs;
    this.maxFailedConnections = maxFailedConnections;
    this.blockDurationMs = blockDurationMs;
  }

  /**
   * Check if an IP address is currently blocked
   */
  isBlocked(ip: string): boolean {
    const record = this.failedConnectionsByIP.get(ip);
    if (!record) return false;

    if (record.blockedUntil && Date.now() < record.blockedUntil) {
      return true;
    }

    // Reset if window expired
    if (Date.now() - record.firstFailure > this.windowMs) {
      this.failedConnectionsByIP.delete(ip);
      return false;
    }

    return false;
  }

  /**
   * Record a failed connection attempt from an IP
   * Returns true if the IP should now be blocked
   */
  recordFailure(ip: string): boolean {
    const now = Date.now();
    const record = this.failedConnectionsByIP.get(ip);

    if (!record) {
      this.failedConnectionsByIP.set(ip, { count: 1, firstFailure: now });
      return false;
    }

    // Reset if window expired
    if (now - record.firstFailure > this.windowMs) {
      this.failedConnectionsByIP.set(ip, { count: 1, firstFailure: now });
      return false;
    }

    record.count++;

    // Block if threshold exceeded
    if (record.count >= this.maxFailedConnections && !record.blockedUntil) {
      record.blockedUntil = now + this.blockDurationMs;
      console.log(
        `[RATE_LIMIT] Blocking IP ${ip} for ${this.blockDurationMs / 1000}s ` +
        `(${record.count} failed connections in ${this.windowMs / 1000}s)`
      );
      return true;
    }

    return false;
  }
}

