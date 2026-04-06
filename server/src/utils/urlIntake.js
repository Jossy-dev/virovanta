import { domainToASCII, domainToUnicode } from "url";

export const MAX_URL_LENGTH = 2048;
export const ALLOWED_TARGET_PORTS = new Set([80, 443]);

export function isPortAllowed(port) {
  if (port == null || port === "") {
    return true;
  }

  const value = Number(port);
  if (!Number.isFinite(value) || value <= 0 || value > 65535) {
    return false;
  }

  return ALLOWED_TARGET_PORTS.has(value);
}

export function normalizeUrlInput(input) {
  const rawInput = String(input || "").trim();
  if (!rawInput) {
    throw new Error("URL is required.");
  }

  if (rawInput.length > MAX_URL_LENGTH) {
    throw new Error(`URL exceeds maximum length of ${MAX_URL_LENGTH} characters.`);
  }

  const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(rawInput);
  if (hasScheme && !/^https?:\/\//i.test(rawInput)) {
    throw new Error("Only HTTP and HTTPS links are supported.");
  }

  const withProtocol = hasScheme ? rawInput : `https://${rawInput}`;
  let parsed;

  try {
    parsed = new URL(withProtocol);
  } catch {
    throw new Error("Invalid URL format.");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP and HTTPS links are supported.");
  }

  if (parsed.username || parsed.password) {
    throw new Error("Credentials in URL are not allowed.");
  }

  if (!isPortAllowed(parsed.port)) {
    throw new Error("Only standard web ports (80 and 443) are allowed.");
  }

  const normalizedHost = parsed.hostname.replace(/\.+$/, "").toLowerCase();
  const asciiHostname = domainToASCII(normalizedHost);
  if (!asciiHostname) {
    throw new Error("Hostname is invalid.");
  }

  const unicodeHostname = domainToUnicode(asciiHostname) || normalizedHost;

  parsed.hostname = asciiHostname;
  parsed.hash = "";

  return {
    inputUrl: rawInput,
    normalizedUrl: parsed.toString(),
    parsed,
    unicodeHostname,
    asciiHostname
  };
}
