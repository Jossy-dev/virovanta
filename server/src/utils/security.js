import crypto from "crypto";

export function hashSecret(secret) {
  return crypto.createHash("sha256").update(String(secret)).digest("hex");
}

export function generateOpaqueToken(bytes = 48) {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

export function todayDateStamp() {
  return new Date().toISOString().slice(0, 10);
}

export function safeText(value, { fallback = "", maxLength = 120 } = {}) {
  if (typeof value !== "string") {
    return fallback;
  }

  const normalized = value.trim().replace(/\s+/g, " ");

  if (!normalized) {
    return fallback;
  }

  return normalized.slice(0, maxLength);
}
