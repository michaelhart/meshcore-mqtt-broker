/**
 * IATA Region Connection Limiter
 * Limits the number of concurrent MQTT clients per distinct IATA airport code
 * 
 * Each client publishes to meshcore/{IATA}/{PUBLIC_KEY}/... topics.
 * This limiter ensures no more than a configurable number of clients
 * can operate per IATA code — preventing network congestion from a single
 * airport/region.
 */

export interface IataLimiterConfig {
  enabled: boolean;
  /** Max clients per IATA code (default: 3) */
  maxClientsPerIata: number;
}

interface IataRecord {
  clients: Set<string>;  // Set of client identifiers (public keys or client IDs)
}

export class IataLimiter {
  private config: IataLimiterConfig;
  private iataMap: Map<string, IataRecord> = new Map();
  private readonly stats = {
    totalClientsTracked: 0,
    totalClientsRejected: 0,
  };

  constructor(config: Partial<IataLimiterConfig> = {}) {
    this.config = {
      enabled: true,
      maxClientsPerIata: 3,
      clientIdentifier: 'publicKey',
      ...config,
    };

    if (this.config.enabled) {
      console.log(`[IATA] Initialized: max ${this.config.maxClientsPerIata} clients per IATA code`);
    } else {
      console.log('[IATA] DISABLED');
    }
  }

  /**
   * Check if a client from this IATA code is allowed to connect
   * Called from authorizePublish when a client first publishes to a meshcore/{IATA}/... topic
   */
  checkIataAccess(iataCode: string, clientIdentifier: string): boolean {
    // Always use publicKey as identifier
    if (!this.config.enabled) return true;

    const iataKey = iataCode.toUpperCase();
    let record = this.iataMap.get(iataKey);

    if (!record) {
      record = { clients: new Set() };
      this.iataMap.set(iataKey, record);
    }

    // Check if this IATA already has too many clients
    if (record.clients.size >= this.config.maxClientsPerIata) {
      this.stats.totalClientsRejected++;
      console.log(`[IATA] ✗ IATA limit exceeded for ${iataKey} (${record.clients.size}/${this.config.maxClientsPerIata})`);
      return false;
    }

    // Track this client
    record.clients.add(clientIdentifier);
    this.stats.totalClientsTracked++;
    console.log(`[IATA] ✓ Client allowed for IATA ${iataKey} (${record.clients.size}/${this.config.maxClientsPerIata})`);
    return true;
  }

  /**
   * Remove a client from IATA tracking
   */
  removeClient(iataCode: string, clientIdentifier: string): void {
    const iataKey = iataCode.toUpperCase();
    const record = this.iataMap.get(iataKey);

    if (record) {
      record.clients.delete(clientIdentifier);
      if (record.clients.size === 0) {
        this.iataMap.delete(iataKey);
        console.log(`[IATA] IATA ${iataKey} cleared (no more clients)`);
      } else {
        console.log(`[IATA] Client removed from IATA ${iataKey} (${record.clients.size}/${this.config.maxClientsPerIata} remaining)`);
      }
    }
  }

  getIataStats(): { totalTracked: number; totalRejected: number; activeIatas: number } {
    return {
      totalTracked: this.stats.totalClientsTracked,
      totalRejected: this.stats.totalClientsRejected,
      activeIatas: this.iataMap.size,
    };
  }
}