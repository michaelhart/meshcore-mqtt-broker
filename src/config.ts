import { config as dotenvConfig } from 'dotenv';
import { AbuseConfig } from './abuse-detector';

// Load environment variables
dotenvConfig();

// Validate required environment variables
function validateRequiredEnvVars(vars: string[]): void {
  for (const envVar of vars) {
    if (process.env[envVar] === undefined) {
      console.error(`FATAL: Missing required environment variable: ${envVar}`);
      console.error(`Please check your .env file and ensure all variables from .env.example are set.`);
      process.exit(1);
    }
  }
}

// Validate and load MQTT configuration
export function loadMqttConfig() {
  validateRequiredEnvVars([
    'MQTT_WS_PORT',
    'MQTT_HOST',
    'AUTH_EXPECTED_AUDIENCE',
  ]);

  return {
    wsPort: parseInt(process.env.MQTT_WS_PORT!),
    host: process.env.MQTT_HOST!,
    expectedAudience: process.env.AUTH_EXPECTED_AUDIENCE!,
  };
}

// Validate and load abuse detection configuration
export function loadAbuseConfig(): AbuseConfig {
  validateRequiredEnvVars([
    'ABUSE_DUPLICATE_WINDOW_SIZE',
    'ABUSE_DUPLICATE_WINDOW_MS',
    'ABUSE_DUPLICATE_THRESHOLD',
    'ABUSE_BUCKET_CAPACITY',
    'ABUSE_BUCKET_REFILL_RATE',
    'ABUSE_MAX_PACKET_SIZE',
    'ABUSE_MAX_TOPICS_PER_DAY',
    'ABUSE_ANOMALY_THRESHOLD',
    'ABUSE_MAX_IATA_CHANGES_24H',
    'ABUSE_TOPIC_HISTORY_SIZE',
    'ABUSE_TOPIC_HISTORY_WINDOW_MS',
    'ABUSE_PERSISTENCE_PATH',
    'ABUSE_PERSISTENCE_INTERVAL_MS',
    'ABUSE_ENFORCEMENT_ENABLED',
  ]);

  return {
    duplicateWindowSize: parseInt(process.env.ABUSE_DUPLICATE_WINDOW_SIZE!),
    duplicateWindowMs: parseInt(process.env.ABUSE_DUPLICATE_WINDOW_MS!),
    duplicateThreshold: parseInt(process.env.ABUSE_DUPLICATE_THRESHOLD!),
    maxDuplicatesPerPacket: parseInt(process.env.ABUSE_MAX_DUPLICATES_PER_PACKET || '5'),
    duplicateRateThreshold: parseFloat(process.env.ABUSE_DUPLICATE_RATE_THRESHOLD || '0.3'),
    duplicateRateWindowMs: parseInt(process.env.ABUSE_DUPLICATE_RATE_WINDOW_MS || '300000'),
    bucketCapacity: parseInt(process.env.ABUSE_BUCKET_CAPACITY!),
    bucketRefillRate: parseFloat(process.env.ABUSE_BUCKET_REFILL_RATE!),
    maxPacketSize: parseInt(process.env.ABUSE_MAX_PACKET_SIZE!),
    maxTopicsPerDay: parseInt(process.env.ABUSE_MAX_TOPICS_PER_DAY!),
    anomalyThreshold: parseInt(process.env.ABUSE_ANOMALY_THRESHOLD!),
    maxIataChanges24h: parseInt(process.env.ABUSE_MAX_IATA_CHANGES_24H!),
    topicHistorySize: parseInt(process.env.ABUSE_TOPIC_HISTORY_SIZE!),
    topicHistoryWindowMs: parseInt(process.env.ABUSE_TOPIC_HISTORY_WINDOW_MS!),
    persistencePath: process.env.ABUSE_PERSISTENCE_PATH!,
    persistenceIntervalMs: parseInt(process.env.ABUSE_PERSISTENCE_INTERVAL_MS!),
    enforcementEnabled: process.env.ABUSE_ENFORCEMENT_ENABLED === 'true',
  };
}

