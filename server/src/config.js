import { fileURLToPath } from "url";
import os from "os";
import path from "path";

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

const srcDir = path.dirname(fileURLToPath(import.meta.url));
const serverDir = path.resolve(srcDir, "..");
const dataDir = path.resolve(serverDir, "data");

const corsOriginRaw = process.env.CORS_ORIGIN?.trim() || "http://localhost:5173";
const corsOrigins = corsOriginRaw
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

const isProduction = process.env.NODE_ENV === "production";
const fallbackJwtSecret = process.env.JWT_ACCESS_SECRET?.trim() || "virovanta-dev-secret-change-me";

export const config = Object.freeze({
  env: process.env.NODE_ENV?.trim() || "development",
  isProduction,
  isTest: process.env.NODE_ENV === "test",
  port: envNumber("PORT", 3001, { min: 1, max: 65535 }),
  uploadDir: process.env.UPLOAD_DIR?.trim() || path.join(os.tmpdir(), "virovanta-uploads"),
  dataFilePath: process.env.DATA_FILE_PATH?.trim() || path.join(dataDir, "virovanta-store.json"),
  maxUploadBytes: envNumber("MAX_UPLOAD_MB", 25, { min: 1, max: 500 }) * 1024 * 1024,
  reportTtlMs: envNumber("REPORT_TTL_HOURS", 24, { min: 1, max: 24 * 30 }) * 60 * 60 * 1000,
  scanHistoryLimit: envNumber("SCAN_HISTORY_LIMIT", 2000, { min: 100, max: 50000 }),
  requestWindowMinutes: envNumber("REQUEST_WINDOW_MINUTES", 15, { min: 1, max: 1440 }),
  requestsPerWindow: envNumber("REQUESTS_PER_WINDOW", 240, { min: 10, max: 10000 }),
  enableClamAv: envBoolean("ENABLE_CLAMAV", true),
  clamScanBinary: process.env.CLAMSCAN_BINARY?.trim() || "clamscan",
  virusTotalApiKey: process.env.VIRUSTOTAL_API_KEY?.trim() || "",
  corsOriginRaw,
  corsOrigins,
  accessTokenTtlMinutes: envNumber("ACCESS_TOKEN_TTL_MINUTES", 15, { min: 5, max: 180 }),
  refreshTokenTtlDays: envNumber("REFRESH_TOKEN_TTL_DAYS", 14, { min: 1, max: 90 }),
  jwtAccessSecret: process.env.JWT_ACCESS_SECRET?.trim() || fallbackJwtSecret,
  reportShareTokenSecret: process.env.REPORT_SHARE_TOKEN_SECRET?.trim() || fallbackJwtSecret,
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
  logLevel: process.env.LOG_LEVEL?.trim() || (isProduction ? "info" : "debug")
});

export function isCorsOriginAllowed(origin) {
  if (!origin) {
    return true;
  }

  if (corsOrigins.includes("*")) {
    return true;
  }

  return corsOrigins.includes(origin);
}
