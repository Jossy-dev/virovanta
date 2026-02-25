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

function normalizeSlug(value, fallback = "app") {
  const normalized = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

  return normalized || fallback;
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

const defaultWebOrigin = envString("DEFAULT_WEB_ORIGIN", DEFAULT_WEB_ORIGIN);
const corsOriginRaw = envString("CORS_ORIGIN", defaultWebOrigin);
const corsOrigins = corsOriginRaw
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

const fallbackJwtSecret = envString("JWT_ACCESS_SECRET", "change-me-in-production-secret");

export const config = Object.freeze({
  env,
  isProduction,
  isTest: env === "test",
  appName,
  appSlug,
  serviceName,
  apiTitle,
  apiVersion,
  apiBaseUrl,
  port,
  uploadDir: envString("UPLOAD_DIR", path.join(os.tmpdir(), `${appSlug}-uploads`)),
  dataFilePath: envString("DATA_FILE_PATH", path.join(dataDir, `${appSlug}-store.json`)),
  maxUploadBytes: envNumber("MAX_UPLOAD_MB", 25, { min: 1, max: 500 }) * 1024 * 1024,
  reportTtlMs: envNumber("REPORT_TTL_HOURS", 24, { min: 1, max: 24 * 30 }) * 60 * 60 * 1000,
  scanHistoryLimit: envNumber("SCAN_HISTORY_LIMIT", 2000, { min: 100, max: 50000 }),
  requestWindowMinutes: envNumber("REQUEST_WINDOW_MINUTES", 15, { min: 1, max: 1440 }),
  requestsPerWindow: envNumber("REQUESTS_PER_WINDOW", 240, { min: 10, max: 10000 }),
  enableClamAv: envBoolean("ENABLE_CLAMAV", true),
  clamScanBinary: envString("CLAMSCAN_BINARY", "clamscan"),
  virusTotalApiKey: envString("VIRUSTOTAL_API_KEY", ""),
  corsOriginRaw,
  corsOrigins,
  accessTokenTtlMinutes: envNumber("ACCESS_TOKEN_TTL_MINUTES", 15, { min: 5, max: 180 }),
  refreshTokenTtlDays: envNumber("REFRESH_TOKEN_TTL_DAYS", 14, { min: 1, max: 90 }),
  jwtAccessSecret: envString("JWT_ACCESS_SECRET", fallbackJwtSecret),
  jwtIssuer: envString("JWT_ISSUER", appSlug),
  jwtAudience: envString("JWT_AUDIENCE", `${appSlug}-${DEFAULT_CLIENT_AUDIENCE_SUFFIX}`),
  reportShareTokenSecret: envString("REPORT_SHARE_TOKEN_SECRET", fallbackJwtSecret),
  reportShareTokenIssuer: envString("REPORT_SHARE_TOKEN_ISSUER", appSlug),
  reportShareTokenAudience: envString(
    "REPORT_SHARE_TOKEN_AUDIENCE",
    `${appSlug}-${DEFAULT_SHARED_REPORT_AUDIENCE_SUFFIX}`
  ),
  reportShareTokenTtlMinutes: envNumber("REPORT_SHARE_TOKEN_TTL_MINUTES", 180, { min: 5, max: 24 * 30 }),
  scanWorkerConcurrency: envNumber("SCAN_WORKER_CONCURRENCY", 2, { min: 1, max: 8 }),
  freeTierDailyScanLimit: envNumber("FREE_TIER_DAILY_SCAN_LIMIT", 40, { min: 1, max: 10000 }),
  publicQuickScanEnabled: envBoolean("PUBLIC_QUICK_SCAN_ENABLED", true),
  publicQuickScanMaxUploadBytes: envNumber("PUBLIC_QUICK_SCAN_MAX_UPLOAD_MB", 8, { min: 1, max: 50 }) * 1024 * 1024,
  publicQuickScanRequestsPerWindow: envNumber("PUBLIC_QUICK_SCAN_REQUESTS_PER_WINDOW", 30, { min: 1, max: 500 }),
  publicQuickScanWindowMinutes: envNumber("PUBLIC_QUICK_SCAN_WINDOW_MINUTES", 15, { min: 1, max: 1440 }),
  publicQuickScanFindingsLimit: envNumber("PUBLIC_QUICK_SCAN_FINDINGS_LIMIT", 8, { min: 1, max: 20 }),
  maxApiKeysPerUser: envNumber("MAX_API_KEYS_PER_USER", 10, { min: 1, max: 50 }),
  allowOpenRegistration: envBoolean("ALLOW_OPEN_REGISTRATION", true),
  logLevel: envString("LOG_LEVEL", isProduction ? "info" : "debug")
});

export function isCorsOriginAllowed(origin, allowedOrigins = config.corsOrigins) {
  if (!origin) {
    return true;
  }

  if (allowedOrigins.includes("*")) {
    return true;
  }

  return allowedOrigins.includes(origin);
}
