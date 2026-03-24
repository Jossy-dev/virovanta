import { fileURLToPath } from "url";
import os from "os";
import path from "path";
import {
  DEFAULT_API_TITLE_SUFFIX,
  DEFAULT_API_VERSION,
  DEFAULT_APP_NAME,
  DEFAULT_APP_SLUG,
  DEFAULT_CLIENT_AUDIENCE_SUFFIX,
  DEFAULT_LOCAL_PORT,
  DEFAULT_SHARED_REPORT_AUDIENCE_SUFFIX,
  DEFAULT_WEB_ORIGIN
} from "./appIdentity.js";

function envNumber(name, fallback, { min = Number.NEGATIVE_INFINITY, max = Number.POSITIVE_INFINITY } = {}) {
  const value = Number(process.env[name]);

  if (!Number.isFinite(value)) {
    return fallback;
  }

  return Math.min(max, Math.max(min, value));
}

function envBoolean(name, fallback) {
  const raw = process.env[name];

  if (raw == null) {
    return fallback;
  }

  const normalized = raw.trim().toLowerCase();

  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }

  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }

  return fallback;
}

function envString(name, fallback = "") {
  const raw = process.env[name];
  if (raw == null) {
    return fallback;
  }

  const value = raw.trim();
  return value || fallback;
}

function envEnum(name, allowedValues, fallback) {
  const value = envString(name, fallback).toLowerCase();
  if (allowedValues.includes(value)) {
    return value;
  }

  return fallback;
}

function normalizeSlug(value, fallback = "app") {
  const normalized = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

  return normalized || fallback;
}

export function resolveServiceMode(runtimeConfig) {
  if (runtimeConfig.runApiServer && runtimeConfig.runScanWorker) {
    return "all";
  }

  if (runtimeConfig.runApiServer) {
    return "api";
  }

  return "worker";
}

const srcDir = path.dirname(fileURLToPath(import.meta.url));
const serverDir = path.resolve(srcDir, "..");
const dataDir = path.resolve(serverDir, "data");
const isProduction = process.env.NODE_ENV === "production";
const env = process.env.NODE_ENV?.trim() || "development";

const appName = envString("APP_NAME", DEFAULT_APP_NAME);
const appSlug = normalizeSlug(envString("APP_SLUG", appName), DEFAULT_APP_SLUG);
const serviceName = envString("SERVICE_NAME", appSlug);
const apiVersion = envString("API_VERSION", DEFAULT_API_VERSION);
const apiTitle = envString("API_TITLE", `${appName} ${DEFAULT_API_TITLE_SUFFIX}`);
const port = envNumber("PORT", DEFAULT_LOCAL_PORT, { min: 1, max: 65535 });
const apiBaseUrl = envString("API_BASE_URL", `http://localhost:${port}`);
const authProvider = envEnum("AUTH_PROVIDER", ["local", "supabase"], "local");
const dataStoreDriver = envEnum("DATA_STORE_DRIVER", ["file", "postgres"], "file");
const queueProvider = envEnum("QUEUE_PROVIDER", ["local", "bullmq"], "local");
const rateLimitStore = envEnum("RATE_LIMIT_STORE", ["memory", "redis"], "memory");
const objectStorageProvider = envEnum("OBJECT_STORAGE_PROVIDER", ["none", "s3"], "none");

const defaultWebOrigin = envString("DEFAULT_WEB_ORIGIN", DEFAULT_WEB_ORIGIN);
const corsOriginRaw = envString("CORS_ORIGIN", defaultWebOrigin);
const corsOrigins = corsOriginRaw
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

const fallbackJwtSecret = envString("JWT_ACCESS_SECRET", "change-me-in-production-secret");
const fallbackReportShareSecret = envString("REPORT_SHARE_TOKEN_SECRET", fallbackJwtSecret);
const fallbackReportIntegritySecret = envString("REPORT_INTEGRITY_SECRET", fallbackReportShareSecret);
const databaseUrl = envString("DATABASE_URL", "");
const redisUrl = envString("REDIS_URL", "");
const supabaseUrl = envString("SUPABASE_URL", "");
const supabasePublishableKey = envString("SUPABASE_PUBLISHABLE_KEY", "");
const supabaseLegacyAnonKey = envString("SUPABASE_ANON_KEY", "");
const supabasePublicAuthKey = supabasePublishableKey || supabaseLegacyAnonKey;

function resolveSupabaseKeyMode(rawKey) {
  const key = String(rawKey || "").trim();
  if (!key) {
    return "missing";
  }

  if (key.startsWith("sb_publishable_")) {
    return "publishable";
  }

  if (key.startsWith("sb_secret_")) {
    return "secret";
  }

  if (key.startsWith("eyJ")) {
    return "legacy_jwt";
  }

  return "unknown";
}

const resolvedConfig = {
  env,
  isProduction,
  isTest: env === "test",
  appName,
  appSlug,
  serviceName,
  apiTitle,
  apiVersion,
  apiBaseUrl,
  authProvider,
  dataStoreDriver,
  queueProvider,
  rateLimitStore,
  objectStorageProvider,
  scanWorkerMode: envEnum("SCAN_WORKER_MODE", ["all", "file", "link"], "all"),
  runApiServer: envBoolean("RUN_API_SERVER", true),
  runScanWorker: envBoolean("RUN_SCAN_WORKER", true),
  port,
  uploadDir: envString("UPLOAD_DIR", path.join(os.tmpdir(), `${appSlug}-uploads`)),
  dataFilePath: envString("DATA_FILE_PATH", path.join(dataDir, `${appSlug}-store.json`)),
  stateStoreTable: envString("STATE_STORE_TABLE", `${serviceName.replace(/[^a-zA-Z0-9_]/g, "_")}_state`),
  databaseUrl,
  databaseSsl: envBoolean("DATABASE_SSL", isProduction),
  databaseSslRejectUnauthorized: envBoolean("DATABASE_SSL_REJECT_UNAUTHORIZED", true),
  maxUploadBytes: envNumber("MAX_UPLOAD_MB", 25, { min: 1, max: 500 }) * 1024 * 1024,
  maxBatchUploadFiles: envNumber("MAX_BATCH_UPLOAD_FILES", 10, { min: 1, max: 50 }),
  reportTtlMs: envNumber("REPORT_TTL_HOURS", 24 * 90, { min: 24 * 90, max: 24 * 365 }) * 60 * 60 * 1000,
  scanHistoryLimit: envNumber("SCAN_HISTORY_LIMIT", 2000, { min: 100, max: 50000 }),
  requestWindowMinutes: envNumber("REQUEST_WINDOW_MINUTES", 15, { min: 1, max: 1440 }),
  requestsPerWindow: envNumber("REQUESTS_PER_WINDOW", 240, { min: 10, max: 10000 }),
  authRateLimitWindowMinutes: envNumber("AUTH_RATE_LIMIT_WINDOW_MINUTES", 15, { min: 1, max: 1440 }),
  authLoginRequestsPerWindow: envNumber("AUTH_LOGIN_REQUESTS_PER_WINDOW", 10, { min: 3, max: 200 }),
  authMutationRequestsPerWindow: envNumber("AUTH_MUTATION_REQUESTS_PER_WINDOW", 20, { min: 5, max: 500 }),
  authLookupRequestsPerWindow: envNumber("AUTH_LOOKUP_REQUESTS_PER_WINDOW", 60, { min: 10, max: 1000 }),
  enableClamAv: envBoolean("ENABLE_CLAMAV", true),
  clamScanBinary: envString("CLAMSCAN_BINARY", "clamscan"),
  virusTotalApiKey: envString("VIRUSTOTAL_API_KEY", ""),
  redisUrl,
  redisTls: envBoolean("REDIS_TLS", false),
  queueName: envString("QUEUE_NAME", `${serviceName}-scan-jobs`),
  fileQueueName: envString("FILE_QUEUE_NAME", `${serviceName}-file-scan-jobs`),
  linkQueueName: envString("LINK_QUEUE_NAME", `${serviceName}-link-scan-jobs`),
  queueAttempts: envNumber("QUEUE_ATTEMPTS", 3, { min: 1, max: 20 }),
  queueBackoffMs: envNumber("QUEUE_BACKOFF_MS", 2000, { min: 100, max: 120000 }),
  objectStorageEndpoint: envString("OBJECT_STORAGE_ENDPOINT", ""),
  objectStorageRegion: envString("OBJECT_STORAGE_REGION", "us-west-000"),
  objectStorageBucket: envString("OBJECT_STORAGE_BUCKET", serviceName),
  objectStoragePrefix: envString("OBJECT_STORAGE_PREFIX", serviceName),
  objectStorageAccessKeyId: envString("OBJECT_STORAGE_ACCESS_KEY_ID", ""),
  objectStorageSecretAccessKey: envString("OBJECT_STORAGE_SECRET_ACCESS_KEY", ""),
  objectStorageForcePathStyle: envBoolean("OBJECT_STORAGE_FORCE_PATH_STYLE", true),
  objectStorageSignedUrlTtlSeconds: envNumber("OBJECT_STORAGE_SIGNED_URL_TTL_SECONDS", 900, {
    min: 60,
    max: 7 * 24 * 60 * 60
  }),
  supabaseUrl,
  supabaseAnonKey: supabasePublicAuthKey,
  supabaseKeyMode: resolveSupabaseKeyMode(supabasePublicAuthKey),
  supabaseJwtSecret: envString("SUPABASE_JWT_SECRET", ""),
  supabaseJwtIssuer: envString("SUPABASE_JWT_ISSUER", supabaseUrl ? `${supabaseUrl}/auth/v1` : ""),
  supabaseJwtAudience: envString("SUPABASE_JWT_AUDIENCE", "authenticated"),
  supabaseJwtAlgorithm: envString("SUPABASE_JWT_ALGORITHM", "HS256"),
  supabaseJwksUrl: envString(
    "SUPABASE_JWKS_URL",
    supabaseUrl ? `${supabaseUrl}/auth/v1/.well-known/jwks.json` : ""
  ),
  supabasePasswordResetRedirectUrl: envString("SUPABASE_PASSWORD_RESET_REDIRECT_URL", ""),
  supabaseAuthTimeoutMs: envNumber("SUPABASE_AUTH_TIMEOUT_MS", 10_000, { min: 1_000, max: 60_000 }),
  corsOriginRaw,
  corsOrigins,
  accessTokenTtlMinutes: envNumber("ACCESS_TOKEN_TTL_MINUTES", 15, { min: 5, max: 180 }),
  refreshTokenTtlDays: envNumber("REFRESH_TOKEN_TTL_DAYS", 14, { min: 1, max: 90 }),
  jwtAccessSecret: envString("JWT_ACCESS_SECRET", fallbackJwtSecret),
  jwtIssuer: envString("JWT_ISSUER", appSlug),
  jwtAudience: envString("JWT_AUDIENCE", `${appSlug}-${DEFAULT_CLIENT_AUDIENCE_SUFFIX}`),
  reportShareTokenSecret: fallbackReportShareSecret,
  reportIntegritySecret: fallbackReportIntegritySecret,
  reportIntegrityKeyId: envString("REPORT_INTEGRITY_KEY_ID", `${serviceName}-report-integrity-v1`),
  reportShareTokenIssuer: envString("REPORT_SHARE_TOKEN_ISSUER", appSlug),
  reportShareTokenAudience: envString(
    "REPORT_SHARE_TOKEN_AUDIENCE",
    `${appSlug}-${DEFAULT_SHARED_REPORT_AUDIENCE_SUFFIX}`
  ),
  reportShareTokenTtlMinutes: envNumber("REPORT_SHARE_TOKEN_TTL_MINUTES", 180, { min: 5, max: 24 * 30 }),
  scanSlaTargetMinutes: envNumber("SCAN_SLA_TARGET_MINUTES", 5, { min: 1, max: 120 }),
  serviceUptimeTargetPercent: envString("SERVICE_UPTIME_TARGET_PERCENT", "99.9"),
  scanWorkerConcurrency: envNumber("SCAN_WORKER_CONCURRENCY", 2, { min: 1, max: 8 }),
  urlScanTimeoutMs: envNumber("URL_SCAN_TIMEOUT_MS", 12_000, { min: 1_000, max: 45_000 }),
  urlScanMaxRedirects: envNumber("URL_SCAN_MAX_REDIRECTS", 4, { min: 0, max: 10 }),
  urlScanMaxBodyBytes: envNumber("URL_SCAN_MAX_BODY_BYTES", 200_000, { min: 32_000, max: 1_000_000 }),
  urlScanMaxDownloadBytes: envNumber("URL_SCAN_MAX_DOWNLOAD_BYTES", 5 * 1024 * 1024, {
    min: 256 * 1024,
    max: 25 * 1024 * 1024
  }),
  urlScanUserAgent: envString("URL_SCAN_USER_AGENT", `${serviceName}/url-scanner`),
  urlScanRateLimitRequestsPerWindow: envNumber("URL_SCAN_RATE_LIMIT_REQUESTS_PER_WINDOW", 30, { min: 1, max: 1000 }),
  urlScanRateLimitWindowMinutes: envNumber("URL_SCAN_RATE_LIMIT_WINDOW_MINUTES", 15, { min: 1, max: 1440 }),
  urlScanEnableBrowserRender: envBoolean("URL_SCAN_ENABLE_BROWSER_RENDER", false),
  urlScanBrowserTimeoutMs: envNumber("URL_SCAN_BROWSER_TIMEOUT_MS", 10_000, { min: 1_000, max: 60_000 }),
  urlScanEnableDownloadInspection: envBoolean("URL_SCAN_ENABLE_DOWNLOAD_INSPECTION", true),
  urlScanStrictEgress: envBoolean("URL_SCAN_STRICT_EGRESS", true),
  urlIntelTimeoutMs: envNumber("URL_INTEL_TIMEOUT_MS", 8_000, { min: 1_000, max: 30_000 }),
  googleSafeBrowsingApiKey: envString("GOOGLE_SAFE_BROWSING_API_KEY", ""),
  urlhausEnabled: envBoolean("URLHAUS_ENABLED", false),
  urlhausApiBaseUrl: envString("URLHAUS_API_BASE_URL", "https://urlhaus-api.abuse.ch/v1"),
  freeTierDailyScanLimit: envNumber("FREE_TIER_DAILY_SCAN_LIMIT", 40, { min: 1, max: 10000 }),
  publicQuickScanEnabled: envBoolean("PUBLIC_QUICK_SCAN_ENABLED", true),
  publicQuickScanMaxUploadBytes: envNumber("PUBLIC_QUICK_SCAN_MAX_UPLOAD_MB", 8, { min: 1, max: 50 }) * 1024 * 1024,
  publicQuickScanRequestsPerWindow: envNumber("PUBLIC_QUICK_SCAN_REQUESTS_PER_WINDOW", 30, { min: 1, max: 500 }),
  publicQuickScanWindowMinutes: envNumber("PUBLIC_QUICK_SCAN_WINDOW_MINUTES", 15, { min: 1, max: 1440 }),
  publicQuickScanFindingsLimit: envNumber("PUBLIC_QUICK_SCAN_FINDINGS_LIMIT", 8, { min: 1, max: 20 }),
  maxApiKeysPerUser: envNumber("MAX_API_KEYS_PER_USER", 10, { min: 1, max: 50 }),
  allowOpenRegistration: envBoolean("ALLOW_OPEN_REGISTRATION", true),
  logLevel: envString("LOG_LEVEL", isProduction ? "info" : "debug")
};

function assertRuntimeTopology(runtimeConfig) {
  const issues = [];

  if (!runtimeConfig.runApiServer && !runtimeConfig.runScanWorker) {
    issues.push("At least one of RUN_API_SERVER or RUN_SCAN_WORKER must be true.");
  }

  if (runtimeConfig.queueProvider === "local" && !runtimeConfig.runScanWorker) {
    issues.push("RUN_SCAN_WORKER must be true when QUEUE_PROVIDER=local.");
  }

  if (
    runtimeConfig.queueProvider === "bullmq" &&
    runtimeConfig.runScanWorker &&
    !runtimeConfig.runApiServer &&
    runtimeConfig.objectStorageProvider !== "s3"
  ) {
    issues.push("OBJECT_STORAGE_PROVIDER must be s3 when running remote BullMQ workers.");
  }

  if (issues.length > 0) {
    throw new Error(`Invalid runtime configuration:
- ${issues.join("\n- ")}`);
  }
}

function assertProductionSecurity(runtimeConfig) {
  if (!runtimeConfig.isProduction) {
    return;
  }

  const issues = [];

  if (runtimeConfig.jwtAccessSecret === "change-me-in-production-secret") {
    issues.push("JWT_ACCESS_SECRET must be set to a strong value in production.");
  }

  if (runtimeConfig.reportShareTokenSecret === "change-me-in-production-secret") {
    issues.push("REPORT_SHARE_TOKEN_SECRET must be set to a strong value in production.");
  }

  if (runtimeConfig.reportIntegritySecret === "change-me-in-production-secret") {
    issues.push("REPORT_INTEGRITY_SECRET must be set to a strong value in production.");
  }

  if (runtimeConfig.dataStoreDriver === "postgres" && !runtimeConfig.databaseUrl) {
    issues.push("DATABASE_URL is required when DATA_STORE_DRIVER=postgres.");
  }

  if (runtimeConfig.queueProvider === "bullmq" && !runtimeConfig.redisUrl) {
    issues.push("REDIS_URL is required when QUEUE_PROVIDER=bullmq.");
  }

  if (runtimeConfig.queueProvider === "bullmq" && runtimeConfig.objectStorageProvider !== "s3") {
    issues.push("OBJECT_STORAGE_PROVIDER must be s3 when QUEUE_PROVIDER=bullmq.");
  }

  if (runtimeConfig.rateLimitStore === "redis" && !runtimeConfig.redisUrl) {
    issues.push("REDIS_URL is required when RATE_LIMIT_STORE=redis.");
  }

  if (runtimeConfig.objectStorageProvider === "s3") {
    if (!runtimeConfig.objectStorageBucket) {
      issues.push("OBJECT_STORAGE_BUCKET is required when OBJECT_STORAGE_PROVIDER=s3.");
    }

    if (!runtimeConfig.objectStorageAccessKeyId || !runtimeConfig.objectStorageSecretAccessKey) {
      issues.push("OBJECT_STORAGE_ACCESS_KEY_ID and OBJECT_STORAGE_SECRET_ACCESS_KEY are required for OBJECT_STORAGE_PROVIDER=s3.");
    }
  }

  if (runtimeConfig.authProvider === "supabase") {
    if (!runtimeConfig.supabaseUrl) {
      issues.push("SUPABASE_URL is required when AUTH_PROVIDER=supabase.");
    }

    if (!runtimeConfig.supabaseAnonKey) {
      issues.push("SUPABASE_PUBLISHABLE_KEY is required when AUTH_PROVIDER=supabase.");
    }

    if (runtimeConfig.supabaseKeyMode !== "publishable") {
      issues.push(`SUPABASE_PUBLISHABLE_KEY must be an sb_publishable_ key (current mode: ${runtimeConfig.supabaseKeyMode}).`);
    }
  }

  if (!runtimeConfig.runApiServer && !runtimeConfig.runScanWorker) {
    issues.push("At least one of RUN_API_SERVER or RUN_SCAN_WORKER must be true.");
  }

  if (issues.length > 0) {
    throw new Error(`Invalid production configuration:\n- ${issues.join("\n- ")}`);
  }
}

function assertSupabaseAuthKeyMode(runtimeConfig) {
  if (runtimeConfig.authProvider !== "supabase") {
    return;
  }

  if (!runtimeConfig.supabaseAnonKey) {
    throw new Error("SUPABASE_PUBLISHABLE_KEY is required when AUTH_PROVIDER=supabase.");
  }

  if (runtimeConfig.supabaseKeyMode === "publishable") {
    return;
  }

  if (runtimeConfig.supabaseKeyMode === "legacy_jwt") {
    throw new Error(
      "Legacy Supabase JWT key detected. Set SUPABASE_PUBLISHABLE_KEY=sb_publishable_... and remove SUPABASE_ANON_KEY legacy JWT."
    );
  }

  if (runtimeConfig.supabaseKeyMode === "secret") {
    throw new Error("Supabase secret key detected for auth. Use SUPABASE_PUBLISHABLE_KEY (sb_publishable_...).");
  }

  throw new Error("Invalid Supabase key format. Set SUPABASE_PUBLISHABLE_KEY to an sb_publishable_ key.");
}

assertRuntimeTopology(resolvedConfig);
assertSupabaseAuthKeyMode(resolvedConfig);
assertProductionSecurity(resolvedConfig);

export const config = Object.freeze(resolvedConfig);

export function isCorsOriginAllowed(origin, allowedOrigins = config.corsOrigins) {
  if (!origin) {
    return true;
  }

  if (allowedOrigins.includes("*")) {
    return true;
  }

  return allowedOrigins.includes(origin);
}
