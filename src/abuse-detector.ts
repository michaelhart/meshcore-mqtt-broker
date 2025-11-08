import { createHash } from 'crypto';
import Database from 'better-sqlite3';

// ============================================================================
// Type Definitions
// ============================================================================

export interface ClientTrustState {
  // Identity
  publicKey: string;
  username: string;
  connectedAt: number;
  
  // Network tracking
  recentIPs: {
    ip: string;
    firstSeen: number;
    lastSeen: number;
    connectionCount: number;
  }[];
  
  // Status
  status: 'allowed' | 'muted' | 'would_mute';
  mutedAt?: number;
  muteReason?: string;
  
  // Rate limiting (leaky bucket)
  tokenBucket: {
    tokens: number;
    lastRefill: number;
    capacity: number;
    refillRate: number;
  };
  
  // Duplicate detection
  recentPacketHashes: {
    hash: string;
    timestamp: number;
    count: number;              // How many times this packet was seen
  }[];
  duplicateCount: number;       // Total duplicates seen (lifetime)
  duplicateRateWindow: {        // Track duplicate rate over time
    totalPackets: number;
    duplicatePackets: number;
    windowStart: number;
    windowMs: number;           // 5 minutes
  };
  
  // Counters (lifetime)
  totalPacketsReceived: number;
  totalPacketsSilenced: number;
  totalPacketsRelayed: number;
  
  // Behavioral metrics
  uniqueTopics: Set<string>;
  topicHistory: {
    topic: string;
    timestamp: number;
  }[];
  
  // IATA location tracking
  iataHistory: {
    iata: string;
    firstSeen: number;
    lastSeen: number;
  }[];
  currentIata?: string;
  iataChangeCount24h: number;
  
  // Clock tracking
  clockTracking: {
    version: number;                  // Schema version for clock tracking (increment to reset)
    estimatedOffset?: number;
    lastDeviceTimestamp?: number;
    lastBrokerTimestamp?: number;
    erraticJumps: {
      from: number;
      to: number;
      offsetChange: number;
      timestamp: number;
    }[];
  };
  
  // Anomaly tracking
  anomalyCount: number;
  anomalies: {
    type: string;
    details: string;
    timestamp: number;
  }[];
  
  // Performance/debugging
  lastPacketAt: number;
  avgPacketSize: number;
  peakRateObserved: number;
  peakRateWindow: {
    version: number;             // Schema version (increment to reset)
    packets: number[];
    windowMs: number;
  };
}

export interface AbuseConfig {
  // Duplicate detection
  duplicateWindowSize: number;
  duplicateWindowMs: number;
  duplicateThreshold: number;
  maxDuplicatesPerPacket: number;    // Allow N copies of same packet (repeaters)
  duplicateRateThreshold: number;    // Max % of packets that can be duplicates (0-1)
  duplicateRateWindowMs: number;     // Window to measure duplicate rate (5 min)
  
  // Rate limiting
  bucketCapacity: number;
  bucketRefillRate: number;
  
  // Anomaly detection
  maxPacketSize: number;
  maxTopicsPerDay: number;
  anomalyThreshold: number;
  
  // IATA change detection
  maxIataChanges24h: number;
  
  // Topic tracking
  topicHistorySize: number;
  topicHistoryWindowMs: number;
  
  // Persistence
  persistencePath: string;
  persistenceIntervalMs: number;
  
  // Enforcement
  enforcementEnabled: boolean;
}

interface SerializedTrustState {
  publicKey: string;
  username: string;
  connectedAt: number;
  recentIPs: {
    ip: string;
    firstSeen: number;
    lastSeen: number;
    connectionCount: number;
  }[];
  status: 'allowed' | 'muted' | 'would_mute';
  mutedAt?: number;
  muteReason?: string;
  tokenBucket: {
    tokens: number;
    lastRefill: number;
    capacity: number;
    refillRate: number;
  };
  recentPacketHashes: {
    hash: string;
    timestamp: number;
    count: number;
  }[];
  duplicateCount: number;
  duplicateRateWindow: {
    totalPackets: number;
    duplicatePackets: number;
    windowStart: number;
    windowMs: number;
  };
  totalPacketsReceived: number;
  totalPacketsSilenced: number;
  totalPacketsRelayed: number;
  uniqueTopics: string[];
  topicHistory: { topic: string; timestamp: number }[];
  iataHistory: { iata: string; firstSeen: number; lastSeen: number }[];
  currentIata?: string;
  iataChangeCount24h: number;
  clockTracking: {
    version: number;
    estimatedOffset?: number;
    lastDeviceTimestamp?: number;
    lastBrokerTimestamp?: number;
    erraticJumps: { from: number; to: number; offsetChange: number; timestamp: number }[];
  };
  anomalyCount: number;
  anomalies: { type: string; details: string; timestamp: number }[];
  lastPacketAt: number;
  avgPacketSize: number;
  peakRateObserved: number;
  peakRateWindow: {
    version: number;
    packets: number[];
    windowMs: number;
  };
}

// ============================================================================
// Abuse Detector Class
// ============================================================================

export class AbuseDetector {
  private config: AbuseConfig;
  private clients: Map<string, ClientTrustState> = new Map();
  private db: Database.Database;
  private persistenceInterval?: NodeJS.Timeout;
  
  // Global stats
  private stats = {
    totalClientsConnected: 0,
    totalClientsMuted: 0,
    totalPacketsSilenced: 0,
  };

  constructor(config: AbuseConfig) {
    this.config = config;
    
    // Initialize SQLite database
    this.db = new Database(config.persistencePath);
    this.initDatabase();
    this.loadFromDatabase();
    
    // Start periodic persistence
    this.persistenceInterval = setInterval(() => {
      this.saveToDatabase();
    }, config.persistenceIntervalMs);
    
    console.log(`[ABUSE] Initialized with persistence at: ${config.persistencePath}`);
  }

  private initDatabase(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS trust_states (
        public_key TEXT PRIMARY KEY,
        state_json TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `);
    
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_updated_at ON trust_states(updated_at)
    `);
  }

  private loadFromDatabase(): void {
    const stmt = this.db.prepare('SELECT public_key, state_json FROM trust_states');
    const rows = stmt.all() as { public_key: string; state_json: string }[];
    
    let loaded = 0;
    for (const row of rows) {
      try {
        const serialized: SerializedTrustState = JSON.parse(row.state_json);
        const state = this.deserializeTrustState(serialized);
        this.clients.set(row.public_key, state);
        loaded++;
        
        if (state.status === 'muted') {
          this.stats.totalClientsMuted++;
        }
      } catch (error) {
        console.error(`[ABUSE] Failed to load trust state for ${row.public_key}:`, error);
      }
    }
    
    console.log(`[ABUSE] Loaded ${loaded} trust states from database`);
  }

  private saveToDatabase(): void {
    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO trust_states (public_key, state_json, updated_at)
      VALUES (?, ?, ?)
    `);
    
    const now = Date.now();
    let saved = 0;
    
    for (const [publicKey, state] of this.clients.entries()) {
      try {
        const serialized = this.serializeTrustState(state);
        stmt.run(publicKey, JSON.stringify(serialized), now);
        saved++;
      } catch (error) {
        console.error(`[ABUSE] Failed to save trust state for ${publicKey}:`, error);
      }
    }
    
    if (saved > 0) {
      console.log(`[ABUSE] Saved ${saved} trust states to database`);
    }
  }

  private serializeTrustState(state: ClientTrustState): SerializedTrustState {
    return {
      publicKey: state.publicKey,
      username: state.username,
      connectedAt: state.connectedAt,
      recentIPs: state.recentIPs,
      status: state.status,
      mutedAt: state.mutedAt,
      muteReason: state.muteReason,
      tokenBucket: state.tokenBucket,
      recentPacketHashes: state.recentPacketHashes,
      duplicateCount: state.duplicateCount,
      duplicateRateWindow: state.duplicateRateWindow,
      totalPacketsReceived: state.totalPacketsReceived,
      totalPacketsSilenced: state.totalPacketsSilenced,
      totalPacketsRelayed: state.totalPacketsRelayed,
      uniqueTopics: Array.from(state.uniqueTopics),
      topicHistory: state.topicHistory,
      iataHistory: state.iataHistory,
      currentIata: state.currentIata,
      iataChangeCount24h: state.iataChangeCount24h,
      clockTracking: state.clockTracking,
      anomalyCount: state.anomalyCount,
      anomalies: state.anomalies,
      lastPacketAt: state.lastPacketAt,
      avgPacketSize: state.avgPacketSize,
      peakRateObserved: state.peakRateObserved,
      peakRateWindow: state.peakRateWindow,
    };
  }

  private deserializeTrustState(serialized: SerializedTrustState): ClientTrustState {
    const state = {
      ...serialized,
      uniqueTopics: new Set(serialized.uniqueTopics),
    };
    
    // Initialize duplicateRateWindow if missing
    if (!state.duplicateRateWindow) {
      state.duplicateRateWindow = {
        totalPackets: 0,
        duplicatePackets: 0,
        windowStart: Date.now(),
        windowMs: 300000, // 5 minutes
      };
    }
    
    // Initialize peakRateWindow if missing
    if (!state.peakRateWindow || !state.peakRateWindow.version || state.peakRateWindow.version < 1) {
      state.peakRateWindow = {
        version: 1,
        packets: [],
        windowMs: 86400000,
      };
      state.peakRateObserved = 0; // Reset bad old values
    }
    
    // Reset clock tracking if version is old or missing
    if (!state.clockTracking.version || state.clockTracking.version < 1) {
      state.clockTracking = {
        version: 1,
        erraticJumps: [],
      };
      state.anomalyCount = 0;
      state.anomalies = [];
    }
    
    return state;
  }

  public shutdown(): void {
    console.log('[ABUSE] Shutting down, saving final state...');
    this.saveToDatabase();
    
    if (this.persistenceInterval) {
      clearInterval(this.persistenceInterval);
    }
    
    this.db.close();
    console.log('[ABUSE] Shutdown complete');
  }

  // ============================================================================
  // Client Management
  // ============================================================================

  public initializeClient(publicKey: string, username: string, clientIP?: string): void {
    if (this.clients.has(publicKey)) {
      const existing = this.clients.get(publicKey)!;
      console.log(`[ABUSE] [${publicKey.substring(0, 8)}] Client reconnected (status: ${existing.status})`);
      existing.connectedAt = Date.now();
      
      // Update IP tracking
      if (clientIP) {
        this.recordIP(existing, clientIP);
      }
      
      return;
    }

    const state: ClientTrustState = {
      publicKey,
      username,
      connectedAt: Date.now(),
      recentIPs: [],
      status: 'allowed',
      tokenBucket: {
        tokens: this.config.bucketCapacity,
        lastRefill: Date.now(),
        capacity: this.config.bucketCapacity,
        refillRate: this.config.bucketRefillRate,
      },
      recentPacketHashes: [],
      duplicateCount: 0,
      duplicateRateWindow: {
        totalPackets: 0,
        duplicatePackets: 0,
        windowStart: Date.now(),
        windowMs: this.config.duplicateRateWindowMs,
      },
      totalPacketsReceived: 0,
      totalPacketsSilenced: 0,
      totalPacketsRelayed: 0,
      uniqueTopics: new Set(),
      topicHistory: [],
      iataHistory: [],
      iataChangeCount24h: 0,
      clockTracking: {
        version: 1,
        erraticJumps: [],
      },
      anomalyCount: 0,
      anomalies: [],
      lastPacketAt: Date.now(),
      avgPacketSize: 0,
      peakRateObserved: 0,
      peakRateWindow: {
        version: 1,
        packets: [],
        windowMs: 86400000, // 24 hours
      },
    };

    this.clients.set(publicKey, state);
    this.stats.totalClientsConnected++;
    
    // Record initial IP
    if (clientIP) {
      this.recordIP(state, clientIP);
    }
    
    console.log(`[ABUSE] [${publicKey.substring(0, 8)}] Initialized trust tracking`);
  }

  private recordIP(state: ClientTrustState, ip: string): void {
    const now = Date.now();
    const existing = state.recentIPs.find(entry => entry.ip === ip);
    
    if (existing) {
      existing.lastSeen = now;
      existing.connectionCount++;
    } else {
      state.recentIPs.push({
        ip,
        firstSeen: now,
        lastSeen: now,
        connectionCount: 1,
      });
      
      // Keep only most recent 100 IPs
      if (state.recentIPs.length > 100) {
        // Sort by lastSeen desc and keep top 100
        state.recentIPs.sort((a, b) => b.lastSeen - a.lastSeen);
        state.recentIPs = state.recentIPs.slice(0, 100);
      }
    }
  }

  public getClientStats(publicKey: string): ClientTrustState | undefined {
    return this.clients.get(publicKey);
  }

  public getAllStats() {
    return {
      ...this.stats,
      clients: Array.from(this.clients.entries()).map(([key, state]) => ({
        publicKey: key,
        status: state.status,
        totalPacketsReceived: state.totalPacketsReceived,
        totalPacketsSilenced: state.totalPacketsSilenced,
        duplicateCount: state.duplicateCount,
        anomalyCount: state.anomalyCount,
      })),
    };
  }

  // ============================================================================
  // Packet Processing
  // ============================================================================

  public recordPacket(client: any, packet: any): boolean {
    const publicKey = client.publicKey;
    const state = this.clients.get(publicKey);
    
    if (!state) {
      console.error(`[ABUSE] No trust state for ${publicKey}`);
      return false;
    }

    const now = Date.now();
    state.totalPacketsReceived++;
    state.lastPacketAt = now;

    // Update average packet size
    const payloadSize = packet.payload.length;
    if (state.avgPacketSize === 0) {
      state.avgPacketSize = payloadSize;
    } else {
      state.avgPacketSize = state.avgPacketSize * 0.9 + payloadSize * 0.1;
    }
    
    // Track packet rate over 24h window
    state.peakRateWindow.packets.push(now);
    
    // Clean old packets outside 24h window
    const windowStart = now - state.peakRateWindow.windowMs;
    state.peakRateWindow.packets = state.peakRateWindow.packets.filter(
      (timestamp: number) => timestamp > windowStart
    );
    
    // Calculate current rate (packets in last 10 seconds)
    const tenSecondsAgo = now - 10000;
    const recentPackets = state.peakRateWindow.packets.filter(
      (timestamp: number) => timestamp > tenSecondsAgo
    );
    const currentRate = recentPackets.length / 10; // packets per second
    
    // Update peak if current rate is higher
    if (currentRate > state.peakRateObserved) {
      state.peakRateObserved = currentRate;
    }
    
    // Reset peak if no packets in last hour (allows peak to decay)
    const oneHourAgo = now - 3600000;
    const packetsInLastHour = state.peakRateWindow.packets.filter(
      (timestamp: number) => timestamp > oneHourAgo
    );
    if (packetsInLastHour.length === 0) {
      state.peakRateObserved = 0;
    }

    // Check packet size based on raw LoRa packet data
    try {
      const message = JSON.parse(packet.payload.toString('utf-8'));
      if (message.raw) {
        // raw is hex string, so divide by 2 to get actual byte size
        const rawByteSize = message.raw.length / 2;
        
        // LoRa max packet size is ~255 bytes, anything beyond is suspicious
        if (rawByteSize > this.config.maxPacketSize) {
          console.log(`[ABUSE] [${publicKey.substring(0, 8)}] Anomalous raw packet size: ${rawByteSize} bytes (hex: ${message.raw.length} chars)`);
          this.recordAnomaly(state, 'packet_size', `Raw packet size ${rawByteSize} bytes exceeds limit ${this.config.maxPacketSize}`);
        }
      }
    } catch (error) {
      // If not JSON or no raw field, skip check
    }

    // Check rate limit
    if (!this.checkRateLimit(state)) {
      console.log(`[ABUSE] [${publicKey.substring(0, 8)}] Rate limit exceeded`);
      this.muteClient(state, 'rate_limit_exceeded');
      return false;
    }

    // Check for duplicates
    const payload = packet.payload.toString();
    if (!this.checkDuplicates(state, payload)) {
      console.log(`[ABUSE] [${publicKey.substring(0, 8)}] Duplicate packet detected`);
      return false;
    }

    return true;
  }

  public shouldSilencePacket(client: any): boolean {
    const publicKey = client.publicKey;
    const state = this.clients.get(publicKey);
    
    if (!state) {
      return false;
    }

    if (state.status === 'muted') {
      state.totalPacketsSilenced++;
      this.stats.totalPacketsSilenced++;
      return true;
    }

    return false;
  }

  // ============================================================================
  // Detection Methods
  // ============================================================================

  public checkDuplicates(state: ClientTrustState, payload: string): boolean {
    const hash = createHash('sha256').update(payload).digest('hex');
    const now = Date.now();

    // Clean old hashes (outside window)
    state.recentPacketHashes = state.recentPacketHashes.filter(
      item => now - item.timestamp < this.config.duplicateWindowMs
    );

    // Check if hash exists
    const existingHash = state.recentPacketHashes.find(item => item.hash === hash);
    
    // Reset duplicate rate window if expired
    if (now - state.duplicateRateWindow.windowStart > state.duplicateRateWindow.windowMs) {
      state.duplicateRateWindow.totalPackets = 0;
      state.duplicateRateWindow.duplicatePackets = 0;
      state.duplicateRateWindow.windowStart = now;
    }
    
    // Track total packets in window
    state.duplicateRateWindow.totalPackets++;
    
    if (existingHash) {
      existingHash.count++;
      existingHash.timestamp = now; // Update last seen
      state.duplicateCount++;
      state.duplicateRateWindow.duplicatePackets++;
      
      // Check 1: Too many copies of this specific packet
      if (existingHash.count > this.config.maxDuplicatesPerPacket) {
        this.recordAnomaly(
          state,
          'excessive_packet_copies',
          `Packet seen ${existingHash.count} times (max: ${this.config.maxDuplicatesPerPacket})`
        );
        
        if (state.anomalyCount >= this.config.anomalyThreshold) {
          this.muteClient(state, `anomaly_threshold_exceeded (${state.anomalyCount} anomalies)`);
        }
        
        return false; // Reject this copy
      }
      
      // Check 2: Overall duplicate rate too high
      if (state.duplicateRateWindow.totalPackets >= 20) { // Need at least 20 packets to judge
        const duplicateRate = state.duplicateRateWindow.duplicatePackets / state.duplicateRateWindow.totalPackets;
        
        if (duplicateRate > this.config.duplicateRateThreshold) {
          this.recordAnomaly(
            state,
            'high_duplicate_rate',
            `${Math.round(duplicateRate * 100)}% duplicates in last ${state.duplicateRateWindow.windowMs / 60000} min (max: ${this.config.duplicateRateThreshold * 100}%)`
          );
          
          if (state.anomalyCount >= this.config.anomalyThreshold) {
            this.muteClient(state, `anomaly_threshold_exceeded (${state.anomalyCount} anomalies)`);
          }
          
          return false;
        }
      }
      
      // Duplicate, but within acceptable limits
      return true;
    }

    // New unique packet - add to tracking
    state.recentPacketHashes.push({ hash, timestamp: now, count: 1 });
    
    // Limit size
    if (state.recentPacketHashes.length > this.config.duplicateWindowSize) {
      state.recentPacketHashes.shift();
    }

    return true;
  }

  public checkRateLimit(state: ClientTrustState): boolean {
    const now = Date.now();
    const timeSinceLastRefill = (now - state.tokenBucket.lastRefill) / 1000;
    
    // Refill tokens
    const tokensToAdd = timeSinceLastRefill * state.tokenBucket.refillRate;
    state.tokenBucket.tokens = Math.min(
      state.tokenBucket.capacity,
      state.tokenBucket.tokens + tokensToAdd
    );
    state.tokenBucket.lastRefill = now;

    // Check if we have tokens
    if (state.tokenBucket.tokens < 1) {
      return false;
    }

    // Consume token
    state.tokenBucket.tokens -= 1;
    return true;
  }

  public checkIataChange(state: ClientTrustState, iata: string): boolean {
    const now = Date.now();
    const twentyFourHoursAgo = now - 86400000;

    // Clean old history
    state.iataHistory = state.iataHistory.filter(
      item => item.lastSeen > twentyFourHoursAgo
    );

    // Check if this is a new IATA
    if (state.currentIata && state.currentIata !== iata) {
      const existingEntry = state.iataHistory.find(item => item.iata === iata);
      
      if (!existingEntry) {
        // New IATA
        state.iataChangeCount24h = state.iataHistory.length + 1;
        
        console.log(`[ABUSE] [${state.publicKey.substring(0, 8)}] IATA change detected (${state.currentIata} -> ${iata}, total: ${state.iataChangeCount24h}/${this.config.maxIataChanges24h} in 24h)`);
        
        if (state.iataChangeCount24h > this.config.maxIataChanges24h) {
          this.muteClient(state, `iata_changes_exceeded (${state.iataChangeCount24h} changes in 24h)`);
          return false;
        }
        
        state.iataHistory.push({
          iata,
          firstSeen: now,
          lastSeen: now,
        });
      } else {
        existingEntry.lastSeen = now;
      }
      
      state.currentIata = iata;
    } else if (!state.currentIata) {
      // First IATA
      state.currentIata = iata;
      state.iataHistory.push({
        iata,
        firstSeen: now,
        lastSeen: now,
      });
    } else {
      // Same IATA, update last seen
      const entry = state.iataHistory.find(item => item.iata === iata);
      if (entry) {
        entry.lastSeen = now;
      }
    }

    return true;
  }

  public checkAnomalies(state: ClientTrustState, packet: any): boolean {
    // Additional anomaly checks can be added here
    return true;
  }

  private recordAnomaly(state: ClientTrustState, type: string, details: string): void {
    state.anomalyCount++;
    state.anomalies.push({
      type,
      details,
      timestamp: Date.now(),
    });

    console.log(`[ABUSE] [${state.publicKey.substring(0, 8)}] Anomaly: ${type} - ${details}`);

    if (state.anomalyCount >= this.config.anomalyThreshold) {
      this.muteClient(state, `anomaly_threshold_exceeded (${state.anomalyCount} anomalies)`);
    }
  }

  public muteClient(state: ClientTrustState, reason: string): void {
    if (state.status === 'muted') {
      return;
    }

    // Only actually mute if enforcement is enabled
    if (this.config.enforcementEnabled) {
      state.status = 'muted';
      state.mutedAt = Date.now();
      state.muteReason = reason;
      this.stats.totalClientsMuted++;
      console.log(`[ABUSE] [${state.publicKey.substring(0, 8)}] MUTED (reason: ${reason})`);
    } else {
      console.log(`[ABUSE] [${state.publicKey.substring(0, 8)}] WOULD MUTE (reason: ${reason}) [enforcement disabled]`);
    }
  }
}

