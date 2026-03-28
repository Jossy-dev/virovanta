import crypto from "crypto";
import dns from "dns/promises";
import net from "net";
import tls from "tls";
import { domainToASCII, domainToUnicode } from "url";
import { config } from "../config.js";
import { getUrlReputationSnapshot } from "../utils/urlReputation.js";

const DEFAULT_SCAN_TIMEOUT_MS = 12_000;
const DEFAULT_MAX_REDIRECTS = 5;
const DEFAULT_MAX_BODY_BYTES = 250_000;
const DEFAULT_USER_AGENT = "ViroVanta-Website-Safety-Scanner/1.0 (+https://www.virovanta.com)";
const FALLBACK_BROWSER_USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
const MAX_URL_LENGTH = 2048;
const ALLOWED_TARGET_PORTS = new Set([80, 443]);
const CONTEXT_KEYWORDS = [
  "verify",
  "password",
  "signin",
  "login",
  "wallet",
  "payment",
  "invoice",
  "security alert",
  "account"
];
const HIGH_CONFIDENCE_PHISHING_PATTERNS = [
  /verify\s+your\s+account/i,
  /account\s+(?:has\s+been\s+)?(?:suspended|locked|restricted)/i,
  /confirm\s+your\s+identity/i,
  /urgent\s+action\s+required/i,
  /seed\s+phrase/i,
  /wallet\s+connect/i,
  /payment\s+failed/i,
  /click\s+(?:the\s+)?link\s+below/i,
  /unusual\s+activity\s+detected/i
];
const SUSPICIOUS_LINK_TLDS = new Set(["zip", "top", "xyz", "click", "rest", "shop", "monster", "quest"]);
const DANGEROUS_PROBE_PATHS = ["/.env", "/.git/config", "/config.php", "/backup.zip", "/phpinfo.php"];
const ADMIN_PROBE_PATHS = ["/admin", "/login", "/wp-admin", "/administrator"];
const HEADER_REQUIREMENTS = [
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy"
];
const IP_HOSTING_PROVIDERS = Object.freeze([
  {
    id: "ipwhois",
    buildUrl: (ip) => `https://ipwho.is/${encodeURIComponent(ip)}`,
    parse: (payload) => {
      if (!payload || payload.success === false) {
        return null;
      }

      return {
        country: payload.country || null,
        region: payload.region || null,
        city: payload.city || null,
        asn: payload.connection?.asn || null,
        organization: payload.connection?.org || null,
        isp: payload.connection?.isp || null
      };
    }
  },
  {
    id: "ipapi",
    buildUrl: (ip) => `https://ipapi.co/${encodeURIComponent(ip)}/json/`,
    parse: (payload) => {
      if (!payload || payload.error) {
        return null;
      }

      return {
        country: payload.country_name || payload.country || null,
        region: payload.region || null,
        city: payload.city || null,
        asn: payload.asn || null,
        organization: payload.org || payload.org_name || null,
        isp: payload.org || null
      };
    }
  },
  {
    id: "ipinfo",
    buildUrl: (ip) => `https://ipinfo.io/${encodeURIComponent(ip)}/json`,
    parse: (payload) => {
      if (!payload || payload.error) {
        return null;
      }

      return {
        country: payload.country || null,
        region: payload.region || null,
        city: payload.city || null,
        asn: payload.org ? String(payload.org).split(" ")[0] : null,
        organization: payload.org || null,
        isp: payload.org || null
      };
    }
  }
]);

const RDAP_FALLBACK_ENDPOINTS = Object.freeze({
  com: "https://rdap.verisign.com/com/v1/domain",
  net: "https://rdap.verisign.com/net/v1/domain",
  org: "https://rdap.publicinterestregistry.org/rdap/domain"
});
const IANA_RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";
const RDAP_BOOTSTRAP_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const RDAP_LOOKUP_REDIRECT_LIMIT = 2;
const KNOWN_MULTI_LABEL_PUBLIC_SUFFIXES = new Set([
  "ac.uk",
  "co.il",
  "co.in",
  "co.jp",
  "co.kr",
  "co.nz",
  "co.uk",
  "com.au",
  "com.br",
  "com.mx",
  "com.sg",
  "com.tr",
  "gov.uk",
  "net.au",
  "org.au",
  "org.uk"
]);

const IPV4_RESERVED_RANGES = [
  [ipV4ToNumber("0.0.0.0"), ipV4ToNumber("0.255.255.255")],
  [ipV4ToNumber("10.0.0.0"), ipV4ToNumber("10.255.255.255")],
  [ipV4ToNumber("100.64.0.0"), ipV4ToNumber("100.127.255.255")],
  [ipV4ToNumber("127.0.0.0"), ipV4ToNumber("127.255.255.255")],
  [ipV4ToNumber("169.254.0.0"), ipV4ToNumber("169.254.255.255")],
  [ipV4ToNumber("172.16.0.0"), ipV4ToNumber("172.31.255.255")],
  [ipV4ToNumber("192.0.0.0"), ipV4ToNumber("192.0.0.255")],
  [ipV4ToNumber("192.0.2.0"), ipV4ToNumber("192.0.2.255")],
  [ipV4ToNumber("192.168.0.0"), ipV4ToNumber("192.168.255.255")],
  [ipV4ToNumber("198.18.0.0"), ipV4ToNumber("198.19.255.255")],
  [ipV4ToNumber("198.51.100.0"), ipV4ToNumber("198.51.100.255")],
  [ipV4ToNumber("203.0.113.0"), ipV4ToNumber("203.0.113.255")],
  [ipV4ToNumber("224.0.0.0"), ipV4ToNumber("255.255.255.255")]
];
const rdapBootstrapCache = {
  loadedAt: 0,
  services: [],
  pending: null
};

function ipV4ToNumber(address) {
  return address.split(".").reduce((value, octet) => (value << 8) + Number(octet), 0) >>> 0;
}

function isIpv4Reserved(address) {
  const value = ipV4ToNumber(address);
  return IPV4_RESERVED_RANGES.some(([start, end]) => value >= start && value <= end);
}

function isIpv6Reserved(address) {
  const normalized = String(address || "").toLowerCase();
  if (!normalized) {
    return true;
  }

  if (normalized === "::" || normalized === "::1") {
    return true;
  }

  if (normalized.startsWith("fc") || normalized.startsWith("fd")) {
    return true;
  }

  if (normalized.startsWith("fe8") || normalized.startsWith("fe9") || normalized.startsWith("fea") || normalized.startsWith("feb")) {
    return true;
  }

  if (normalized.startsWith("2001:db8")) {
    return true;
  }

  if (normalized.startsWith("::ffff:")) {
    const mappedAddress = normalized.replace("::ffff:", "");
    if (net.isIP(mappedAddress) === 4) {
      return isIpv4Reserved(mappedAddress);
    }
  }

  return false;
}

function isIpReserved(address) {
  const version = net.isIP(address);
  if (version === 4) {
    return isIpv4Reserved(address);
  }

  if (version === 6) {
    return isIpv6Reserved(address);
  }

  return true;
}

function isHostnameUnsafe(hostname) {
  const normalized = String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/\.+$/, "");

  if (!normalized) {
    return true;
  }

  if (normalized === "localhost" || normalized.endsWith(".localhost")) {
    return true;
  }

  if (normalized.endsWith(".local") || normalized.endsWith(".internal") || normalized.endsWith(".arpa")) {
    return true;
  }

  if (!normalized.includes(".")) {
    return true;
  }

  return false;
}

function isPortAllowed(port) {
  if (port == null || port === "") {
    return true;
  }

  const value = Number(port);
  if (!Number.isFinite(value) || value <= 0 || value > 65535) {
    return false;
  }

  return ALLOWED_TARGET_PORTS.has(value);
}

function withTimeoutSignal(timeoutMs = DEFAULT_SCAN_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  return {
    signal: controller.signal,
    clear: () => clearTimeout(timeoutId)
  };
}

function normalizeTxtRecords(records) {
  if (!Array.isArray(records)) {
    return [];
  }

  return records
    .map((entry) => {
      if (Array.isArray(entry)) {
        return entry.join("");
      }

      return String(entry || "");
    })
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function safeParseDate(value) {
  if (!value) {
    return null;
  }

  const timestamp = Date.parse(String(value));
  return Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : null;
}

function parseRdapEventDate(events, eventKeywords = []) {
  if (!Array.isArray(events) || !Array.isArray(eventKeywords) || eventKeywords.length === 0) {
    return null;
  }

  const normalizedKeywords = eventKeywords.map((keyword) => String(keyword || "").toLowerCase()).filter(Boolean);
  const matchedEvent = events.find((event) => {
    const action = String(event?.eventAction || "").toLowerCase();
    return normalizedKeywords.some((keyword) => action.includes(keyword));
  });

  return safeParseDate(matchedEvent?.eventDate);
}

async function safeJsonResponse(response) {
  const contentType = String(response?.headers?.get?.("content-type") || "").toLowerCase();
  if (!contentType.includes("application/json") && !contentType.includes("rdap+json")) {
    return null;
  }

  try {
    return await response.json();
  } catch {
    return null;
  }
}

function normalizeLookupHostname(hostname) {
  return String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/\.+$/, "");
}

function normalizeRdapBaseUrl(url) {
  const normalized = String(url || "").trim();
  if (!/^https?:\/\//i.test(normalized)) {
    return null;
  }

  return normalized.replace(/\/+$/, "");
}

function buildRdapLookupUrl(baseUrl, hostname) {
  const normalizedBaseUrl = normalizeRdapBaseUrl(baseUrl);
  const normalizedHostname = normalizeLookupHostname(hostname);
  if (!normalizedBaseUrl || !normalizedHostname) {
    return null;
  }

  const hasDomainPath = /\/domain$/i.test(normalizedBaseUrl);
  return `${normalizedBaseUrl}${hasDomainPath ? "" : "/domain"}/${encodeURIComponent(normalizedHostname)}`;
}

function parseRdapBootstrapServices(payload) {
  if (!Array.isArray(payload?.services)) {
    return [];
  }

  return payload.services
    .map((entry) => {
      const suffixes = Array.isArray(entry?.[0]) ? entry[0].map(normalizeLookupHostname).filter(Boolean) : [];
      const baseUrls = Array.isArray(entry?.[1]) ? entry[1].map(normalizeRdapBaseUrl).filter(Boolean) : [];

      if (suffixes.length === 0 || baseUrls.length === 0) {
        return null;
      }

      return {
        suffixes,
        baseUrls
      };
    })
    .filter(Boolean);
}

async function getRdapBootstrapServices(timeoutMs) {
  const cacheIsFresh =
    Array.isArray(rdapBootstrapCache.services) &&
    rdapBootstrapCache.services.length > 0 &&
    Date.now() - rdapBootstrapCache.loadedAt < RDAP_BOOTSTRAP_CACHE_TTL_MS;
  if (cacheIsFresh) {
    return rdapBootstrapCache.services;
  }

  if (rdapBootstrapCache.pending) {
    return rdapBootstrapCache.pending;
  }

  rdapBootstrapCache.pending = (async () => {
    const timeoutHandle = withTimeoutSignal(Math.min(Number(timeoutMs) || DEFAULT_SCAN_TIMEOUT_MS, 6_000));
    const staleServices = Array.isArray(rdapBootstrapCache.services) ? rdapBootstrapCache.services : [];

    try {
      const response = await fetch(IANA_RDAP_BOOTSTRAP_URL, {
        method: "GET",
        headers: {
          accept: "application/json"
        },
        signal: timeoutHandle.signal
      });

      if (!response.ok) {
        return staleServices;
      }

      const payload = await safeJsonResponse(response);
      const services = parseRdapBootstrapServices(payload);
      if (services.length === 0) {
        return staleServices;
      }

      rdapBootstrapCache.loadedAt = Date.now();
      rdapBootstrapCache.services = services;
      return services;
    } catch {
      return staleServices;
    } finally {
      timeoutHandle.clear();
      rdapBootstrapCache.pending = null;
    }
  })();

  return rdapBootstrapCache.pending;
}

function buildHostnameSuffixCandidates(hostname) {
  const normalized = normalizeLookupHostname(hostname);
  const labels = normalized.split(".").filter(Boolean);
  const suffixes = [];

  for (let index = 0; index < labels.length; index += 1) {
    suffixes.push(labels.slice(index).join("."));
  }

  return suffixes;
}

function resolveBootstrapRdapBaseUrls(hostname, services = []) {
  const suffixCandidates = buildHostnameSuffixCandidates(hostname);
  for (const candidate of suffixCandidates) {
    const matchingService = services.find((service) => Array.isArray(service?.suffixes) && service.suffixes.includes(candidate));
    if (matchingService?.baseUrls?.length) {
      return matchingService.baseUrls;
    }
  }

  return [];
}

async function resolveRdapEndpoints(hostname, timeoutMs) {
  const normalized = normalizeLookupHostname(hostname);
  if (!normalized) {
    return [];
  }

  const labels = normalized.split(".");
  const tld = labels[labels.length - 1] || "";
  const fallbackEndpoint = RDAP_FALLBACK_ENDPOINTS[tld];
  const bootstrapServices = await getRdapBootstrapServices(timeoutMs);
  const bootstrapBaseUrls = resolveBootstrapRdapBaseUrls(normalized, bootstrapServices);

  return [
    ...bootstrapBaseUrls.map((baseUrl) => buildRdapLookupUrl(baseUrl, normalized)),
    `https://rdap.org/domain/${encodeURIComponent(normalized)}`,
    fallbackEndpoint ? `${fallbackEndpoint}/${encodeURIComponent(normalized)}` : null
  ].filter((value, index, items) => Boolean(value) && items.indexOf(value) === index);
}

async function fetchRdapPayload(endpoint, timeoutMs) {
  const timeoutHandle = withTimeoutSignal(timeoutMs);
  const redirects = [];
  let currentEndpoint = endpoint;

  try {
    for (let attempt = 0; attempt <= RDAP_LOOKUP_REDIRECT_LIMIT; attempt += 1) {
      const response = await fetch(currentEndpoint, {
        method: "GET",
        redirect: "manual",
        headers: {
          accept: "application/rdap+json,application/json"
        },
        signal: timeoutHandle.signal
      });

      const location = response.headers.get("location");
      const isRedirect = Number(response.status) >= 300 && Number(response.status) < 400 && Boolean(location);
      if (isRedirect) {
        if (attempt === RDAP_LOOKUP_REDIRECT_LIMIT) {
          return {
            ok: false,
            status: "redirect_limit_exceeded",
            finalUrl: currentEndpoint,
            redirects
          };
        }

        let nextEndpoint = null;
        try {
          nextEndpoint = new URL(location, currentEndpoint).toString();
        } catch {
          return {
            ok: false,
            status: "invalid_redirect_url",
            finalUrl: currentEndpoint,
            redirects
          };
        }

        redirects.push({
          from: currentEndpoint,
          to: nextEndpoint,
          statusCode: Number(response.status) || 0
        });
        currentEndpoint = nextEndpoint;
        continue;
      }

      if (!response.ok) {
        return {
          ok: false,
          status: `http_${response.status}`,
          finalUrl: currentEndpoint,
          redirects
        };
      }

      const payload = await safeJsonResponse(response);
      if (!payload || typeof payload !== "object") {
        return {
          ok: false,
          status: "invalid_payload",
          finalUrl: currentEndpoint,
          redirects
        };
      }

      return {
        ok: true,
        payload,
        finalUrl: currentEndpoint,
        redirects
      };
    }

    return {
      ok: false,
      status: "redirect_limit_exceeded",
      finalUrl: currentEndpoint,
      redirects
    };
  } catch (error) {
    return {
      ok: false,
      status: error?.name === "AbortError" ? "timeout" : "request_failed",
      finalUrl: currentEndpoint,
      redirects
    };
  } finally {
    timeoutHandle.clear();
  }
}

export function buildRdapLookupCandidates(hostname) {
  const normalized = normalizeLookupHostname(hostname);
  if (!normalized) {
    return [];
  }

  const labels = normalized.split(".").filter(Boolean);
  if (labels.length <= 2) {
    return [normalized];
  }

  const publicSuffix = labels.slice(-2).join(".");
  const registrableDomainSize = KNOWN_MULTI_LABEL_PUBLIC_SUFFIXES.has(publicSuffix) ? 3 : 2;
  const estimatedRegistrableDomain =
    labels.length >= registrableDomainSize ? labels.slice(-registrableDomainSize).join(".") : normalized;
  const candidates = [];

  for (const candidate of [estimatedRegistrableDomain, normalized]) {
    if (candidate && candidate.split(".").length >= 2 && !candidates.includes(candidate)) {
      candidates.push(candidate);
    }
  }

  for (let index = 1; index <= labels.length - 2; index += 1) {
    const candidate = labels.slice(index).join(".");
    if (candidate.split(".").length < 2 || candidates.includes(candidate)) {
      continue;
    }

    candidates.push(candidate);
  }

  return candidates.length > 0 ? candidates : [normalized];
}

function resolveRegistrarName(registrar) {
  return (
    registrar?.vcardArray?.[1]?.find((entry) => Array.isArray(entry) && entry[0] === "fn")?.[3] ||
    (Array.isArray(registrar?.publicIds) ? registrar.publicIds.map((entry) => entry?.identifier).find(Boolean) : null) ||
    null
  );
}

function extractVcardField(entity, fieldName) {
  const vcardEntries = Array.isArray(entity?.vcardArray?.[1]) ? entity.vcardArray[1] : [];
  const matchingEntry = vcardEntries.find((entry) => Array.isArray(entry) && String(entry[0] || "").toLowerCase() === String(fieldName || "").toLowerCase());
  return matchingEntry?.[3] ? String(matchingEntry[3]).trim() : null;
}

export function extractRdapMetadata(rdap, queriedDomain = "") {
  const entities = Array.isArray(rdap?.entities) ? rdap.entities : [];
  const registrar = Array.isArray(rdap?.entities)
    ? rdap.entities.find((entity) => Array.isArray(entity?.roles) && entity.roles.includes("registrar"))
    : null;
  const abuseContact = entities.find((entity) => Array.isArray(entity?.roles) && entity.roles.includes("abuse")) || null;
  const rdapNameservers = Array.isArray(rdap?.nameservers)
    ? rdap.nameservers.map((entry) => entry?.ldhName || entry?.unicodeName).filter(Boolean)
    : [];
  const registeredAt = parseRdapEventDate(rdap?.events, ["registration", "created"]) || null;
  const expiresAt = parseRdapEventDate(rdap?.events, ["expiration", "expiry"]) || null;
  const domainStatus = Array.isArray(rdap?.status) ? rdap.status.map((entry) => String(entry || "").trim()).filter(Boolean) : [];

  return {
    queriedDomain: normalizeLookupHostname(queriedDomain),
    payloadDomain: normalizeLookupHostname(rdap?.ldhName || rdap?.unicodeName || queriedDomain),
    registeredAt,
    expiresAt,
    registrarName: resolveRegistrarName(registrar),
    nameservers: rdapNameservers,
    whoisPrivacyLikely: JSON.stringify(rdap || {}).toLowerCase().includes("redacted"),
    registrationEvidence: registeredAt ? "explicit_rdap_event" : "unverified",
    domainStatus,
    dnssecSigned: Boolean(rdap?.secureDNS?.delegationSigned),
    abuseEmail: extractVcardField(abuseContact, "email")
  };
}

function hashText(value) {
  const normalized = String(value || "");
  return {
    md5: crypto.createHash("md5").update(normalized).digest("hex"),
    sha1: crypto.createHash("sha1").update(normalized).digest("hex"),
    sha256: crypto.createHash("sha256").update(normalized).digest("hex")
  };
}

function humanFileSize(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) {
    return "0 B";
  }

  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unit = 0;

  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }

  return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[unit]}`;
}

function toPlainHeaders(headers) {
  const normalized = {};

  if (!headers || typeof headers.entries !== "function") {
    return normalized;
  }

  for (const [key, value] of headers.entries()) {
    normalized[String(key || "").toLowerCase()] = String(value || "").trim();
  }

  return normalized;
}

function normalizeWebsiteUrlInput(input) {
  const rawInput = String(input || "").trim();
  if (!rawInput) {
    throw new Error("URL is required.");
  }

  if (rawInput.length > MAX_URL_LENGTH) {
    throw new Error(`URL exceeds maximum length of ${MAX_URL_LENGTH} characters.`);
  }

  const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(rawInput);
  if (hasScheme && !/^https?:\/\//i.test(rawInput)) {
    throw new Error("Only HTTP and HTTPS URLs are supported.");
  }

  const withProtocol = hasScheme ? rawInput : `https://${rawInput}`;
  let parsed;

  try {
    parsed = new URL(withProtocol);
  } catch {
    throw new Error("Invalid URL format.");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are supported.");
  }

  if (parsed.username || parsed.password) {
    throw new Error("Credentials in URL are not allowed.");
  }

  if (!isPortAllowed(parsed.port)) {
    throw new Error("Only ports 80 and 443 are allowed.");
  }

  const normalizedHost = parsed.hostname.replace(/\.+$/, "").toLowerCase();
  const asciiHostname = domainToASCII(normalizedHost);
  if (!asciiHostname) {
    throw new Error("Hostname is invalid.");
  }

  parsed.hostname = asciiHostname;
  parsed.hash = "";

  return {
    inputUrl: rawInput,
    normalizedUrl: parsed.toString(),
    parsed,
    asciiHostname,
    unicodeHostname: domainToUnicode(asciiHostname) || normalizedHost
  };
}

async function resolvePublicAddresses(hostname) {
  const normalizedHostname = String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/\.+$/, "");

  if (isHostnameUnsafe(normalizedHostname)) {
    return {
      allowed: false,
      reason: "local_hostname_blocked",
      addresses: []
    };
  }

  const ipVersion = net.isIP(normalizedHostname);
  if (ipVersion !== 0) {
    if (isIpReserved(normalizedHostname)) {
      return {
        allowed: false,
        reason: "private_ip_blocked",
        addresses: [normalizedHostname]
      };
    }

    return {
      allowed: true,
      reason: null,
      addresses: [normalizedHostname]
    };
  }

  try {
    const records = await dns.lookup(normalizedHostname, { all: true, verbatim: true });
    const addresses = [...new Set(records.map((record) => record?.address).filter(Boolean))];

    if (addresses.length === 0) {
      return {
        allowed: false,
        reason: "dns_resolution_failed",
        addresses: []
      };
    }

    const blockedAddress = addresses.find((address) => isIpReserved(address));
    if (blockedAddress) {
      return {
        allowed: false,
        reason: "private_dns_target_blocked",
        addresses
      };
    }

    return {
      allowed: true,
      reason: null,
      addresses
    };
  } catch {
    return {
      allowed: false,
      reason: "dns_resolution_failed",
      addresses: []
    };
  }
}

async function readBodySnippet(response, maxBytes) {
  if (!response?.body || maxBytes <= 0) {
    return {
      bodySnippet: "",
      byteLength: 0,
      truncated: false
    };
  }

  const reader = response.body.getReader();
  const chunks = [];
  let byteLength = 0;
  let truncated = false;

  try {
    while (byteLength < maxBytes) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }

      if (!value) {
        continue;
      }

      const remaining = maxBytes - byteLength;
      if (value.byteLength > remaining) {
        chunks.push(value.subarray(0, remaining));
        byteLength += remaining;
        truncated = true;
        break;
      }

      chunks.push(value);
      byteLength += value.byteLength;
    }
  } finally {
    reader.cancel().catch(() => {});
  }

  const decoder = new TextDecoder("utf-8", { fatal: false });
  const bodySnippet = chunks.map((chunk) => decoder.decode(chunk, { stream: true })).join("") + decoder.decode();

  return {
    bodySnippet,
    byteLength,
    truncated
  };
}

async function fetchWithSafeRedirectsForUserAgent(startUrl, runtimeConfig, userAgent) {
  const timeoutMs = Number(runtimeConfig?.urlScanTimeoutMs) || DEFAULT_SCAN_TIMEOUT_MS;
  const maxRedirects = Number(runtimeConfig?.urlScanMaxRedirects) || DEFAULT_MAX_REDIRECTS;
  const maxBodyBytes = Number(runtimeConfig?.urlScanMaxBodyBytes) || DEFAULT_MAX_BODY_BYTES;
  const redirects = [];
  const resolvedAddresses = new Map();
  let currentUrl = startUrl;

  for (let redirectStep = 0; redirectStep <= maxRedirects; redirectStep += 1) {
    const parsedUrl = new URL(currentUrl);

    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      return {
        status: "blocked",
        blockedReason: "unsupported_protocol",
        finalUrl: currentUrl,
        redirects,
        resolvedAddresses: Object.fromEntries(resolvedAddresses.entries()),
        attemptedUserAgent: userAgent
      };
    }

    if (!isPortAllowed(parsedUrl.port)) {
      return {
        status: "blocked",
        blockedReason: "unsafe_port_blocked",
        finalUrl: currentUrl,
        redirects,
        resolvedAddresses: Object.fromEntries(resolvedAddresses.entries()),
        attemptedUserAgent: userAgent
      };
    }

    const guard = await resolvePublicAddresses(parsedUrl.hostname);
    resolvedAddresses.set(parsedUrl.hostname, guard.addresses || []);
    if (!guard.allowed) {
      return {
        status: "blocked",
        blockedReason: guard.reason || "dns_resolution_failed",
        finalUrl: currentUrl,
        redirects,
        resolvedAddresses: Object.fromEntries(resolvedAddresses.entries()),
        attemptedUserAgent: userAgent
      };
    }

    const timeoutHandle = withTimeoutSignal(timeoutMs);

    try {
      const response = await fetch(currentUrl, {
        method: "GET",
        redirect: "manual",
        signal: timeoutHandle.signal,
        headers: {
          "user-agent": userAgent,
          accept: "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.6"
        }
      });

      const statusCode = Number(response.status) || 0;
      const location = response.headers.get("location");
      const isRedirect = statusCode >= 300 && statusCode < 400 && Boolean(location);

      if (!isRedirect) {
        const bodyData = await readBodySnippet(response, maxBodyBytes);

        return {
          status: "ok",
          finalUrl: currentUrl,
          redirects,
          resolvedAddresses: Object.fromEntries(resolvedAddresses.entries()),
          statusCode,
          headers: toPlainHeaders(response.headers),
          contentType: response.headers.get("content-type") || "",
          bodySnippet: bodyData.bodySnippet,
          byteLength: bodyData.byteLength,
          truncated: bodyData.truncated,
          attemptedUserAgent: userAgent
        };
      }

      if (redirectStep === maxRedirects) {
        return {
          status: "blocked",
          blockedReason: "max_redirects_exceeded",
          finalUrl: currentUrl,
          redirects,
          resolvedAddresses: Object.fromEntries(resolvedAddresses.entries()),
          attemptedUserAgent: userAgent
        };
      }

      let nextUrl;
      try {
        nextUrl = new URL(location, currentUrl).toString();
      } catch {
        return {
          status: "blocked",
          blockedReason: "invalid_redirect_url",
          finalUrl: currentUrl,
          redirects,
          resolvedAddresses: Object.fromEntries(resolvedAddresses.entries()),
          attemptedUserAgent: userAgent
        };
      }

      redirects.push({
        from: currentUrl,
        to: nextUrl,
        statusCode
      });
      currentUrl = nextUrl;
    } catch (error) {
      return {
        status: "error",
        blockedReason: error?.name === "AbortError" ? "fetch_timeout" : "fetch_failed",
        finalUrl: currentUrl,
        redirects,
        resolvedAddresses: Object.fromEntries(resolvedAddresses.entries()),
        attemptedUserAgent: userAgent
      };
    } finally {
      timeoutHandle.clear();
    }
  }

  return {
    status: "blocked",
    blockedReason: "max_redirects_exceeded",
    finalUrl: currentUrl,
    redirects,
    resolvedAddresses: Object.fromEntries(resolvedAddresses.entries()),
    attemptedUserAgent: userAgent
  };
}

async function fetchWithSafeRedirects(startUrl, runtimeConfig) {
  const primaryUserAgent = String(runtimeConfig?.urlScanUserAgent || "").trim() || DEFAULT_USER_AGENT;
  const userAgents = [...new Set([primaryUserAgent, DEFAULT_USER_AGENT, FALLBACK_BROWSER_USER_AGENT].filter(Boolean))];
  const attempts = [];

  for (const userAgent of userAgents) {
    const result = await fetchWithSafeRedirectsForUserAgent(startUrl, runtimeConfig, userAgent);
    attempts.push({
      userAgent,
      status: result.status,
      statusCode: result.statusCode || null,
      blockedReason: result.blockedReason || null
    });

    if (result.status === "blocked") {
      return {
        ...result,
        attempts
      };
    }

    if (result.status === "ok" && Number(result.statusCode) >= 200 && Number(result.statusCode) < 500) {
      return {
        ...result,
        attempts
      };
    }
  }

  return {
    status: "error",
    blockedReason: "fetch_failed_all_attempts",
    finalUrl: startUrl,
    redirects: [],
    resolvedAddresses: {},
    attempts
  };
}

function sanitizeFindingsValue(value, maxLength = 320) {
  return String(value == null ? "" : value).slice(0, maxLength);
}

function createFinding(severity, id, category, title, description, evidence = "", weight = 0) {
  return {
    id: String(id || "").trim() || "finding_unknown",
    severity: String(severity || "info"),
    category: String(category || "General"),
    weight: Number(weight) || 0,
    title: sanitizeFindingsValue(title, 120),
    description: sanitizeFindingsValue(description, 260),
    evidence: sanitizeFindingsValue(evidence, 300)
  };
}

async function analyzeDnsAndDomain(hostname, runtimeConfig) {
  const timeoutMs = Number(runtimeConfig?.urlScanTimeoutMs) || DEFAULT_SCAN_TIMEOUT_MS;
  const [aRecords, aaaaRecords, mxRecords, nsRecords, txtRecords, cnameRecords, soaRecord, dmarcTxtRecords] = await Promise.allSettled([
    dns.resolve4(hostname),
    dns.resolve6(hostname),
    dns.resolveMx(hostname),
    dns.resolveNs(hostname),
    dns.resolveTxt(hostname),
    dns.resolveCname(hostname),
    dns.resolveSoa(hostname),
    dns.resolveTxt(`_dmarc.${hostname}`)
  ]);

  const ipv4 = aRecords.status === "fulfilled" ? aRecords.value : [];
  const ipv6 = aaaaRecords.status === "fulfilled" ? aaaaRecords.value : [];
  const mx = mxRecords.status === "fulfilled" ? mxRecords.value.map((entry) => entry.exchange).filter(Boolean) : [];
  const ns = nsRecords.status === "fulfilled" ? nsRecords.value : [];
  const txt = txtRecords.status === "fulfilled" ? normalizeTxtRecords(txtRecords.value) : [];
  const dmarcRecords = dmarcTxtRecords.status === "fulfilled" ? normalizeTxtRecords(dmarcTxtRecords.value) : [];
  const cname = cnameRecords.status === "fulfilled" ? cnameRecords.value : [];
  const soa = soaRecord.status === "fulfilled" ? soaRecord.value : null;
  const spfRecord = txt.find((entry) => String(entry || "").toLowerCase().startsWith("v=spf1")) || null;
  const dmarcRecord = dmarcRecords.find((entry) => String(entry || "").toLowerCase().startsWith("v=dmarc1")) || null;

  let rdap = null;
  let rdapSource = null;
  let rdapSelectedDomain = null;
  let rdapMetadata = null;
  const rdapAttempts = [];
  let fallbackRdapResult = null;

  rdapLookup:
  for (const candidateDomain of buildRdapLookupCandidates(hostname)) {
    const endpoints = await resolveRdapEndpoints(candidateDomain, timeoutMs);
    for (const endpoint of endpoints) {
      const rdapResult = await fetchRdapPayload(endpoint, timeoutMs);
      if (!rdapResult.ok) {
        rdapAttempts.push({
          domain: candidateDomain,
          endpoint,
          finalUrl: rdapResult.finalUrl || endpoint,
          status: rdapResult.status,
          redirectCount: Array.isArray(rdapResult.redirects) ? rdapResult.redirects.length : 0
        });
        continue;
      }

      const payload = rdapResult.payload;
      const metadata = extractRdapMetadata(payload, candidateDomain);
      rdapAttempts.push({
        domain: candidateDomain,
        endpoint,
        finalUrl: rdapResult.finalUrl || endpoint,
        status: "ok",
        redirectCount: Array.isArray(rdapResult.redirects) ? rdapResult.redirects.length : 0,
        registrationEvidence: metadata.registrationEvidence
      });

      if (!fallbackRdapResult) {
        fallbackRdapResult = {
          payload,
          source: rdapResult.finalUrl || endpoint,
          selectedDomain: candidateDomain,
          metadata
        };
      }

      if (metadata.registeredAt) {
        rdap = payload;
        rdapSource = rdapResult.finalUrl || endpoint;
        rdapSelectedDomain = candidateDomain;
        rdapMetadata = metadata;
        break rdapLookup;
      }
    }
  }

  if (!rdap && fallbackRdapResult) {
    rdap = fallbackRdapResult.payload;
    rdapSource = fallbackRdapResult.source;
    rdapSelectedDomain = fallbackRdapResult.selectedDomain;
    rdapMetadata = fallbackRdapResult.metadata;
  }

  const registeredAt = rdapMetadata?.registeredAt || null;
  const expiresAt = rdapMetadata?.expiresAt || null;
  const registrarName = rdapMetadata?.registrarName || null;
  const rdapNameservers = Array.isArray(rdapMetadata?.nameservers) ? rdapMetadata.nameservers : [];
  const nameservers = rdapNameservers.length > 0 ? rdapNameservers : ns;

  const ageDays = Number.isFinite(Date.parse(registeredAt || ""))
    ? Math.floor((Date.now() - Date.parse(registeredAt)) / (24 * 60 * 60 * 1000))
    : null;
  const hasRedactedRegistrant = Boolean(rdapMetadata?.whoisPrivacyLikely);

  return {
    status: "completed",
    hostname,
    records: {
      a: ipv4,
      aaaa: ipv6,
      mx,
      ns,
      cname,
      txt: txt.slice(0, 12),
      soa:
        soa && typeof soa === "object"
          ? {
              nsname: soa.nsname || null,
              hostmaster: soa.hostmaster || null,
              serial: Number.isFinite(Number(soa.serial)) ? Number(soa.serial) : null
            }
          : null
    },
    registrar: registrarName,
    nameservers,
    registeredAt,
    expiresAt,
    ageDays: Number.isFinite(ageDays) ? ageDays : null,
    whoisPrivacyLikely: hasRedactedRegistrant,
    rdap: {
      domain: rdapSelectedDomain,
      payloadDomain: rdapMetadata?.payloadDomain || null,
      registrationEvidence: rdapMetadata?.registrationEvidence || "unknown",
      domainStatus: Array.isArray(rdapMetadata?.domainStatus) ? rdapMetadata.domainStatus.slice(0, 10) : [],
      dnssecSigned: typeof rdapMetadata?.dnssecSigned === "boolean" ? rdapMetadata.dnssecSigned : null,
      abuseEmail: rdapMetadata?.abuseEmail || null,
      source: rdapSource,
      attempts: rdapAttempts
    },
    mailAuth: {
      mxCount: mx.length,
      spfPresent: Boolean(spfRecord),
      spfRecord,
      dmarcPresent: Boolean(dmarcRecord),
      dmarcRecord
    }
  };
}

async function analyzeIpHosting(dnsDomainAnalysis, runtimeConfig) {
  const addresses = [
    ...(dnsDomainAnalysis?.records?.a || []),
    ...(dnsDomainAnalysis?.records?.aaaa || [])
  ].filter(Boolean);
  const primaryIp = addresses[0] || null;

  if (!primaryIp) {
    return {
      status: "unavailable",
      reason: "no_resolved_ip",
      primaryIp: null
    };
  }

  const timeoutMs = Number(runtimeConfig?.urlScanTimeoutMs) || DEFAULT_SCAN_TIMEOUT_MS;
  const providerAttempts = [];

  for (const provider of IP_HOSTING_PROVIDERS) {
    const timeoutHandle = withTimeoutSignal(Math.min(timeoutMs, 6_000));
    try {
      const response = await fetch(provider.buildUrl(primaryIp), {
        method: "GET",
        headers: {
          accept: "application/json"
        },
        signal: timeoutHandle.signal
      });

      if (!response.ok) {
        providerAttempts.push({
          provider: provider.id,
          status: `http_${response.status}`
        });
        continue;
      }

      const payload = await safeJsonResponse(response);
      const parsed = provider.parse(payload);
      if (!parsed) {
        providerAttempts.push({
          provider: provider.id,
          status: "invalid_payload"
        });
        continue;
      }

      providerAttempts.push({
        provider: provider.id,
        status: "ok"
      });

      return {
        status: "completed",
        provider: provider.id,
        primaryIp,
        ...parsed,
        attempts: providerAttempts
      };
    } catch (error) {
      providerAttempts.push({
        provider: provider.id,
        status: error?.name === "AbortError" ? "timeout" : "request_failed"
      });
    } finally {
      timeoutHandle.clear();
    }
  }

  return {
    status: "error",
    reason: "all_providers_failed",
    primaryIp,
    attempts: providerAttempts
  };
}

async function checkTlsMetadata(targetUrl, runtimeConfig) {
  let parsedUrl;
  try {
    parsedUrl = new URL(targetUrl);
  } catch {
    return {
      status: "unavailable",
      reason: "invalid_url"
    };
  }

  if (parsedUrl.protocol !== "https:") {
    return {
      status: "skipped",
      reason: "non_https_target"
    };
  }

  const timeoutMs = Number(runtimeConfig?.urlScanTimeoutMs) || DEFAULT_SCAN_TIMEOUT_MS;

  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: parsedUrl.hostname,
        port: Number(parsedUrl.port) || 443,
        servername: parsedUrl.hostname,
        rejectUnauthorized: false
      },
      () => {
        try {
          const certificate = socket.getPeerCertificate(true);
          const validFrom = certificate?.valid_from ? new Date(certificate.valid_from).toISOString() : null;
          const validTo = certificate?.valid_to ? new Date(certificate.valid_to).toISOString() : null;
          const expiresAtMs = validTo ? Date.parse(validTo) : null;
          const daysRemaining = Number.isFinite(expiresAtMs)
            ? Math.round((expiresAtMs - Date.now()) / (24 * 60 * 60 * 1000))
            : null;
          const subject = certificate?.subject || {};
          const issuer = certificate?.issuer || {};
          const selfSigned = Boolean(subject.CN && issuer.CN && subject.CN === issuer.CN);

          resolve({
            status: "completed",
            protocol: socket.getProtocol() || null,
            authorized: socket.authorized,
            authorizationError: socket.authorizationError || null,
            certSubject: subject.CN || null,
            certIssuer: issuer.CN || null,
            certValidFrom: validFrom,
            certValidTo: validTo,
            certDaysRemaining: Number.isFinite(daysRemaining) ? daysRemaining : null,
            certSelfSigned: selfSigned,
            certExpired: Number.isFinite(daysRemaining) ? daysRemaining < 0 : null
          });
        } catch {
          resolve({
            status: "error",
            reason: "certificate_parse_failed"
          });
        } finally {
          socket.end();
        }
      }
    );

    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      resolve({
        status: "timeout",
        reason: "tls_handshake_timeout"
      });
    });

    socket.on("error", (error) => {
      resolve({
        status: "error",
        reason: error?.code || "tls_connection_failed"
      });
    });
  });
}

function analyzeSecurityHeaders(headers) {
  const normalized = headers || {};
  const missing = [];

  for (const headerName of HEADER_REQUIREMENTS) {
    if (!normalized[headerName]) {
      missing.push(headerName);
    }
  }

  const values = {
    contentSecurityPolicy: normalized["content-security-policy"] || null,
    strictTransportSecurity: normalized["strict-transport-security"] || null,
    xFrameOptions: normalized["x-frame-options"] || null,
    xContentTypeOptions: normalized["x-content-type-options"] || null,
    referrerPolicy: normalized["referrer-policy"] || null
  };

  const qualitySignals = {
    cspWeak:
      values.contentSecurityPolicy != null &&
      (values.contentSecurityPolicy.includes("'unsafe-inline'") || values.contentSecurityPolicy.includes("'unsafe-eval'")),
    hstsMissingIncludeSubDomains:
      values.strictTransportSecurity != null &&
      !String(values.strictTransportSecurity || "")
        .toLowerCase()
        .includes("includesubdomains"),
    xFrameOptionsWeak:
      values.xFrameOptions != null &&
      !["deny", "sameorigin"].includes(String(values.xFrameOptions || "").toLowerCase()),
    nosniffPresent: String(values.xContentTypeOptions || "").toLowerCase() === "nosniff"
  };

  return {
    status: "completed",
    missing,
    values,
    qualitySignals
  };
}

function extractExternalScripts(html, baseUrl) {
  const scripts = [];
  if (!html) {
    return scripts;
  }

  const scriptRegex = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
  let match;

  while ((match = scriptRegex.exec(html))) {
    const source = String(match[1] || "").trim();
    if (!source) {
      continue;
    }

    try {
      const resolved = new URL(source, baseUrl).toString();
      scripts.push(resolved);
    } catch {
      scripts.push(source);
    }
  }

  return [...new Set(scripts)].slice(0, 60);
}

function extractExternalLinks(html, baseUrl) {
  const externalLinks = [];
  if (!html) {
    return externalLinks;
  }

  const anchorRegex = /<a[^>]+href=["']([^"']+)["'][^>]*>/gi;
  let match;

  while ((match = anchorRegex.exec(html))) {
    const href = String(match[1] || "").trim();
    if (!href || href.startsWith("#") || href.startsWith("mailto:") || href.startsWith("tel:")) {
      continue;
    }

    try {
      const resolved = new URL(href, baseUrl);
      const baseHost = new URL(baseUrl).hostname;
      if (resolved.hostname !== baseHost) {
        externalLinks.push(resolved.toString());
      }
    } catch {
      continue;
    }
  }

  return [...new Set(externalLinks)].slice(0, 80);
}

function analyzeContent({ html, finalUrl }) {
  const safeHtml = String(html || "");
  const textOnly = safeHtml
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  const lowerText = textOnly.toLowerCase();
  const matchedKeywords = CONTEXT_KEYWORDS.filter((word) => lowerText.includes(word));
  const matchedPhishingPhrases = HIGH_CONFIDENCE_PHISHING_PATTERNS.map((pattern) => {
    const match = textOnly.match(pattern);
    return match ? match[0] : null;
  }).filter(Boolean);
  const hiddenIframeMatches = safeHtml.match(/<iframe[^>]*(display\s*:\s*none|visibility\s*:\s*hidden|width=["']?0|height=["']?0)[^>]*>/gi) || [];
  const obfuscatedScriptMatches = safeHtml.match(/(?:eval\(|fromCharCode|atob\(|unescape\(|Function\s*\()/gi) || [];
  const passwordFields = safeHtml.match(/<input[^>]+type=["']?password["']?/gi) || [];
  const forms = safeHtml.match(/<form\b[^>]*>/gi) || [];
  const inlineScripts = safeHtml.match(/<script\b(?![^>]*\bsrc=)[^>]*>/gi) || [];
  const externalScripts = extractExternalScripts(safeHtml, finalUrl);
  const externalLinks = extractExternalLinks(safeHtml, finalUrl);
  const suspiciousExternalLinks = externalLinks.filter((link) => {
    try {
      const hostname = new URL(link).hostname;
      const tld = hostname.split(".").pop()?.toLowerCase() || "";
      return SUSPICIOUS_LINK_TLDS.has(tld);
    } catch {
      return false;
    }
  });
  const titleMatch = safeHtml.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const pageTitle = titleMatch ? String(titleMatch[1] || "").replace(/\s+/g, " ").trim() : null;
  const metaDescriptionMatch = safeHtml.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["'][^>]*>/i);
  const metaDescription = metaDescriptionMatch ? String(metaDescriptionMatch[1] || "").trim() : null;
  const phishingSignalScore =
    matchedPhishingPhrases.length * 3 +
    (passwordFields.length > 0 ? 1 : 0) +
    (suspiciousExternalLinks.length > 0 ? 2 : 0) +
    (hiddenIframeMatches.length > 0 ? 2 : 0) +
    (obfuscatedScriptMatches.length > 0 ? 2 : 0) +
    (matchedKeywords.length >= 4 ? 1 : 0);

  return {
    status: "completed",
    suspiciousKeywords: matchedKeywords,
    phishingPhrases: matchedPhishingPhrases,
    phishingSignalScore,
    hiddenIframes: hiddenIframeMatches.length,
    obfuscatedScriptIndicators: obfuscatedScriptMatches.length,
    passwordFieldCount: passwordFields.length,
    formCount: forms.length,
    inlineScriptCount: inlineScripts.length,
    externalScripts,
    externalLinkCount: externalLinks.length,
    suspiciousExternalLinkCount: suspiciousExternalLinks.length,
    suspiciousExternalLinks: suspiciousExternalLinks.slice(0, 20),
    pageTitle,
    metaDescription
  };
}

function analyzeRedirects(redirects = []) {
  const chain = Array.isArray(redirects) ? redirects : [];
  const crossDomainCount = chain.reduce((count, hop) => {
    try {
      const fromHost = new URL(hop.from).hostname;
      const toHost = new URL(hop.to).hostname;
      return fromHost !== toHost ? count + 1 : count;
    } catch {
      return count;
    }
  }, 0);

  return {
    status: "completed",
    count: chain.length,
    crossDomainCount,
    chain
  };
}

function parseProbePathname(value) {
  try {
    const parsed = new URL(value, "https://scanner.invalid");
    return parsed.pathname.toLowerCase();
  } catch {
    return String(value || "")
      .trim()
      .toLowerCase();
  }
}

function isLikelyHtmlResponse({ contentType, bodySnippet }) {
  const normalizedContentType = String(contentType || "").toLowerCase();
  if (normalizedContentType.includes("text/html") || normalizedContentType.includes("application/xhtml+xml")) {
    return true;
  }

  const snippet = String(bodySnippet || "").slice(0, 1_500).toLowerCase();
  return snippet.includes("<html") || snippet.includes("<body") || snippet.includes("<!doctype html");
}

function formatProbeEvidenceSummary(pathname, response) {
  const location = String(response?.location || "").trim();
  if (location) {
    return `${pathname} -> ${location}`;
  }

  return pathname;
}

function assessDangerousProbe(probePathName, response) {
  const pathname = parseProbePathname(probePathName);
  const status = Number(response?.status) || 0;
  const contentType = String(response?.contentType || "").trim();
  const contentDisposition = String(response?.headers?.["content-disposition"] || "").trim();
  const snippet = String(response?.bodySnippet || "");
  const lowerSnippet = snippet.toLowerCase();
  const likelyHtml = isLikelyHtmlResponse({
    contentType,
    bodySnippet: snippet
  });

  let confirmed = false;
  let evidenceType = null;
  let evidenceSummary = "";

  if (status === 200) {
    switch (pathname) {
      case "/.env": {
        const envAssignments = snippet.match(/(?:^|\n)\s*[A-Z][A-Z0-9_]{1,48}\s*=\s*.+/gm) || [];
        const secretMarkers = /(?:secret|token|password|passwd|api[_-]?key|access[_-]?key|client[_-]?secret|database_url|redis_url|supabase|postgres|mysql|smtp)/i.test(
          snippet
        );
        if (!likelyHtml && (envAssignments.length >= 2 || secretMarkers)) {
          confirmed = true;
          evidenceType = "dotenv";
          evidenceSummary = envAssignments.slice(0, 3).join(", ") || "Environment-style key/value pairs detected";
        }
        break;
      }
      case "/.git/config":
        if (!likelyHtml && /\[(?:core|remote|branch)\]/i.test(snippet)) {
          confirmed = true;
          evidenceType = "git_config";
          evidenceSummary = "[core] / [remote] sections detected";
        }
        break;
      case "/config.php":
        if (!likelyHtml && /<\?php|define\s*\(\s*['"]DB_|(?:db_(?:host|name|user|pass|password)|database_(?:host|name|user|pass|password))/i.test(snippet)) {
          confirmed = true;
          evidenceType = "php_source";
          evidenceSummary = "PHP source or database configuration markers detected";
        }
        break;
      case "/backup.zip":
        if (/application\/zip|application\/x-zip-compressed|application\/octet-stream/i.test(contentType) || /\.zip/i.test(contentDisposition) || snippet.startsWith("PK")) {
          confirmed = true;
          evidenceType = "archive";
          evidenceSummary = contentDisposition || contentType || "ZIP archive signature detected";
        }
        break;
      case "/phpinfo.php":
        if (/phpinfo\(\)|php version|zend engine/i.test(lowerSnippet)) {
          confirmed = true;
          evidenceType = "phpinfo";
          evidenceSummary = "phpinfo markers detected in response body";
        }
        break;
      default:
        break;
    }
  }

  return {
    path: pathname,
    status,
    reachable: confirmed,
    confirmed,
    evidenceType,
    evidenceSummary: evidenceSummary || formatProbeEvidenceSummary(pathname, response),
    contentType: contentType || null,
    location: String(response?.location || "").trim() || null
  };
}

function assessAdminProbe(probePathName, response) {
  const pathname = parseProbePathname(probePathName);
  const status = Number(response?.status) || 0;
  const snippet = String(response?.bodySnippet || "");
  const lowerSnippet = snippet.toLowerCase();
  const location = String(response?.location || "").trim();
  const locationPath = parseProbePathname(location);
  const titleMatch = snippet.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = titleMatch ? String(titleMatch[1] || "").replace(/\s+/g, " ").trim() : "";
  const looksAdminHtml =
    /\b(admin|administrator|dashboard)\b/i.test(title) ||
    /\b(log ?in|sign ?in|username|password|administrator)\b/i.test(lowerSnippet);

  const confirmed =
    status === 401 ||
    status === 403 ||
    (status === 200 && looksAdminHtml) ||
    ((status === 301 || status === 302 || status === 303 || status === 307 || status === 308) &&
      Boolean(locationPath) &&
      (locationPath.startsWith(pathname) || /\b(log ?in|admin|administrator|wp-login)\b/i.test(locationPath)));

  return {
    path: pathname,
    status,
    reachable: confirmed,
    confirmed,
    evidenceType: confirmed
      ? status === 401 || status === 403
        ? "auth_gate"
        : status === 200
          ? "admin_html"
          : "admin_redirect"
      : null,
    evidenceSummary: confirmed ? formatProbeEvidenceSummary(pathname, response) : pathname,
    location: location || null
  };
}

function detectTechnologies({ headers, html }) {
  const safeHtml = String(html || "");
  const lowerHtml = safeHtml.toLowerCase();
  const detected = [];

  const server = String(headers?.server || "").trim();
  if (server) {
    detected.push({
      category: "server",
      value: server
    });
  }

  const poweredBy = String(headers?.["x-powered-by"] || "").trim();
  if (poweredBy) {
    detected.push({
      category: "framework",
      value: poweredBy
    });
  }

  if (lowerHtml.includes("wp-content") || lowerHtml.includes("wordpress")) {
    detected.push({ category: "cms", value: "WordPress" });
  }
  if (lowerHtml.includes("cdn.shopify.com") || lowerHtml.includes("shopify")) {
    detected.push({ category: "platform", value: "Shopify" });
  }
  if (lowerHtml.includes("__next") || lowerHtml.includes("_next/static")) {
    detected.push({ category: "framework", value: "Next.js" });
  }
  if (lowerHtml.includes("reactroot") || lowerHtml.includes("react")) {
    detected.push({ category: "framework", value: "React" });
  }
  if (lowerHtml.includes("cloudflare")) {
    detected.push({ category: "network", value: "Cloudflare" });
  }

  const unique = new Map();
  for (const entry of detected) {
    const key = `${entry.category}:${entry.value}`.toLowerCase();
    if (!unique.has(key)) {
      unique.set(key, entry);
    }
  }

  return {
    status: "completed",
    technologies: Array.from(unique.values()).slice(0, 20)
  };
}

async function probePath(url, runtimeConfig) {
  const timeoutMs = Number(runtimeConfig?.urlScanTimeoutMs) || DEFAULT_SCAN_TIMEOUT_MS;
  const timeoutHandle = withTimeoutSignal(Math.min(timeoutMs, 6_000));
  const userAgent = String(runtimeConfig?.urlScanUserAgent || "").trim() || DEFAULT_USER_AGENT;

  try {
    const response = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: timeoutHandle.signal,
      headers: {
        "user-agent": userAgent,
        accept: "text/html,application/json;q=0.8,*/*;q=0.5"
      }
    });

    const bodyData =
      Number(response.status) >= 200 && Number(response.status) < 500
        ? await readBodySnippet(response, 24_000)
        : {
            bodySnippet: "",
            byteLength: 0,
            truncated: false
          };

    return {
      status: Number(response.status) || 0,
      headers: toPlainHeaders(response.headers),
      contentType: response.headers.get("content-type") || "",
      location: response.headers.get("location") || null,
      bodySnippet: bodyData.bodySnippet,
      byteLength: bodyData.byteLength,
      truncated: bodyData.truncated
    };
  } catch (error) {
    return {
      status: 0,
      reason: error?.name === "AbortError" ? "timeout" : "request_failed"
    };
  } finally {
    timeoutHandle.clear();
  }
}

async function runBasicVulnerabilityChecks({ finalUrl, runtimeConfig }) {
  let parsedFinal;
  try {
    parsedFinal = new URL(finalUrl);
  } catch {
    return {
      status: "error",
      reason: "invalid_final_url",
      exposures: [],
      adminEndpoints: []
    };
  }

  const baseOrigin = `${parsedFinal.protocol}//${parsedFinal.host}`;

  const [dangerousChecks, adminChecks] = await Promise.all([
    Promise.all(
      DANGEROUS_PROBE_PATHS.map(async (probePathName) => {
        const target = `${baseOrigin}${probePathName}`;
        const response = await probePath(target, runtimeConfig);
        return assessDangerousProbe(probePathName, response);
      })
    ),
    Promise.all(
      ADMIN_PROBE_PATHS.map(async (probePathName) => {
        const target = `${baseOrigin}${probePathName}`;
        const response = await probePath(target, runtimeConfig);
        return assessAdminProbe(probePathName, response);
      })
    )
  ]);

  return {
    status: "completed",
    exposures: dangerousChecks.filter((entry) => entry.confirmed),
    adminEndpoints: adminChecks.filter((entry) => entry.confirmed),
    probes: {
      dangerous: dangerousChecks,
      admin: adminChecks
    }
  };
}

async function analyzeDiscoveryFiles({ finalUrl, runtimeConfig }) {
  let parsedFinal;
  try {
    parsedFinal = new URL(finalUrl);
  } catch {
    return {
      status: "error",
      reason: "invalid_final_url",
      securityTxt: {
        found: false
      },
      robotsTxt: {
        found: false
      }
    };
  }

  const timeoutMs = Number(runtimeConfig?.urlScanTimeoutMs) || DEFAULT_SCAN_TIMEOUT_MS;
  const userAgent = String(runtimeConfig?.urlScanUserAgent || "").trim() || DEFAULT_USER_AGENT;
  const baseOrigin = `${parsedFinal.protocol}//${parsedFinal.host}`;

  async function fetchSmallText(pathname) {
    const timeoutHandle = withTimeoutSignal(Math.min(timeoutMs, 6_000));

    try {
      const response = await fetch(`${baseOrigin}${pathname}`, {
        method: "GET",
        redirect: "follow",
        signal: timeoutHandle.signal,
        headers: {
          "user-agent": userAgent,
          accept: "text/plain,text/*;q=0.9,*/*;q=0.5"
        }
      });

      const statusCode = Number(response.status) || 0;
      if (statusCode >= 400) {
        return {
          statusCode,
          body: ""
        };
      }

      const bodyData = await readBodySnippet(response, 60_000);
      return {
        statusCode,
        body: bodyData.bodySnippet
      };
    } catch (error) {
      return {
        statusCode: 0,
        reason: error?.name === "AbortError" ? "timeout" : "request_failed",
        body: ""
      };
    } finally {
      timeoutHandle.clear();
    }
  }

  const [securityTextResult, robotsResult] = await Promise.all([
    fetchSmallText("/.well-known/security.txt"),
    fetchSmallText("/robots.txt")
  ]);

  const securityLines = String(securityTextResult.body || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const contactLine = securityLines.find((line) => /^contact:/i.test(line)) || null;
  const expiresLine = securityLines.find((line) => /^expires:/i.test(line)) || null;
  const encryptionLine = securityLines.find((line) => /^encryption:/i.test(line)) || null;

  const robotsLines = String(robotsResult.body || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const disallowRules = robotsLines.filter((line) => /^disallow:/i.test(line));
  const sitemapRules = robotsLines.filter((line) => /^sitemap:/i.test(line));

  return {
    status: "completed",
    securityTxt: {
      statusCode: securityTextResult.statusCode || 0,
      found: (securityTextResult.statusCode || 0) >= 200 && (securityTextResult.statusCode || 0) < 400,
      contact: contactLine ? contactLine.replace(/^contact:\s*/i, "").trim() : null,
      expires: expiresLine ? expiresLine.replace(/^expires:\s*/i, "").trim() : null,
      encryption: encryptionLine ? encryptionLine.replace(/^encryption:\s*/i, "").trim() : null
    },
    robotsTxt: {
      statusCode: robotsResult.statusCode || 0,
      found: (robotsResult.statusCode || 0) >= 200 && (robotsResult.statusCode || 0) < 400,
      disallowCount: disallowRules.length,
      sitemapCount: sitemapRules.length
    }
  };
}

function verdictFromSafetyScore(score) {
  if (score >= 75) {
    return "safe";
  }

  if (score >= 45) {
    return "suspicious";
  }

  return "dangerous";
}

function reportVerdictFromSafetyVerdict(safetyVerdict) {
  if (safetyVerdict === "safe") {
    return "clean";
  }

  if (safetyVerdict === "dangerous") {
    return "malicious";
  }

  return "suspicious";
}

function buildRecommendations({ safetyVerdict, findings, moduleStatus }) {
  const recommendations = [];

  if (moduleStatus?.fetchStatus === "blocked") {
    recommendations.push("Access to this destination was blocked by SSRF protection. Keep this URL quarantined for manual review.");
  }

  if (safetyVerdict !== "safe") {
    recommendations.push("Do not enter credentials or payment information until this website is validated by your security team.");
    recommendations.push("Cross-check the domain against your approved allowlist and ownership records.");
  }

  if ((findings || []).some((entry) => entry.id === "website_headers_missing")) {
    recommendations.push("Harden response headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).");
  }

  if ((findings || []).some((entry) => entry.id === "website_suspicious_content")) {
    recommendations.push("Investigate the page content and script sources for phishing or obfuscation indicators.");
  }

  if ((findings || []).some((entry) => entry.id === "website_mail_auth_missing")) {
    recommendations.push("Publish and enforce SPF + DMARC records for domain-level anti-phishing protection.");
  }

  if ((findings || []).some((entry) => entry.id === "website_external_links_suspicious")) {
    recommendations.push("Review outbound links for suspicious top-level domains before trusting embedded destinations.");
  }

  if ((findings || []).some((entry) => entry.id === "website_sensitive_path_exposed")) {
    recommendations.push("Restrict access to sensitive endpoints and verify that configuration files are not publicly accessible.");
  }

  if (moduleStatus?.ipHostingStatus && moduleStatus.ipHostingStatus !== "completed") {
    recommendations.push("Repeat this scan from a stable network egress to enrich hosting intelligence fields.");
  }

  if (recommendations.length === 0) {
    recommendations.push("No critical website-risk indicators were observed in this scan. Continue with normal verification controls.");
  }

  recommendations.push("This scan is a safety assessment, not a guarantee that the site is fully secure.");
  return recommendations;
}

function safeSettledResult(settled, fallback) {
  if (settled?.status === "fulfilled") {
    return settled.value;
  }

  return fallback;
}

function clampScore(value) {
  return Math.max(0, Math.min(100, Math.round(Number(value) || 0)));
}

function scoreWebsiteSafety({ findings, modules }) {
  let score = 100;

  const headerMissingCount = Array.isArray(modules?.headers?.missing) ? modules.headers.missing.length : 0;
  score -= Math.min(20, headerMissingCount * 4);

  const ageDaysRaw = modules?.dnsDomain?.ageDays;
  const ageDays = typeof ageDaysRaw === "number" ? ageDaysRaw : Number.NaN;
  if (Number.isFinite(ageDays) && ageDays >= 0) {
    if (ageDays < 30) {
      score -= 15;
    } else if (ageDays < 90) {
      score -= 8;
    }
  }

  if (modules?.dnsDomain?.whoisPrivacyLikely) {
    score -= 4;
  }

  if (modules?.ssl?.status === "completed") {
    if (modules.ssl.certSelfSigned) {
      score -= 15;
    }
    if (modules.ssl.certExpired) {
      score -= 20;
    }
    if (!modules.ssl.authorized) {
      score -= 8;
    }
  } else if (modules?.url?.protocol === "http") {
    score -= 18;
  }

  if ((modules?.redirects?.count || 0) > 3) {
    score -= 8;
  }

  if ((modules?.redirects?.crossDomainCount || 0) > 0) {
    score -= 10;
  }

  const phishingSignalScore = Number(modules?.content?.phishingSignalScore) || 0;
  if (phishingSignalScore >= 7) {
    score -= 12;
  } else if (phishingSignalScore >= 4) {
    score -= 7;
  } else if (phishingSignalScore > 0) {
    score -= 3;
  }

  if ((modules?.content?.hiddenIframes || 0) > 0) {
    score -= 10;
  }

  if ((modules?.content?.obfuscatedScriptIndicators || 0) > 0) {
    score -= 12;
  }

  if ((modules?.content?.suspiciousExternalLinkCount || 0) > 0) {
    score -= Math.min(8, (Number(modules?.content?.suspiciousExternalLinkCount) || 0) * 2);
  }

  if (modules?.headers?.qualitySignals?.cspWeak) {
    score -= 5;
  }

  if (modules?.headers?.qualitySignals?.hstsMissingIncludeSubDomains) {
    score -= 3;
  }

  if (modules?.dnsDomain?.mailAuth?.mxCount > 0 && !modules?.dnsDomain?.mailAuth?.dmarcPresent) {
    score -= 5;
  }

  if (modules?.dnsDomain?.mailAuth?.mxCount > 0 && !modules?.dnsDomain?.mailAuth?.spfPresent) {
    score -= 4;
  }

  if ((modules?.vulnerabilityChecks?.exposures || []).length > 0) {
    score -= Math.min(30, modules.vulnerabilityChecks.exposures.length * 10);
  }

  const flaggedProviders = modules?.reputation?.flaggedProviders || [];
  if (Array.isArray(flaggedProviders) && flaggedProviders.length >= 2) {
    score -= 50;
  } else if (Array.isArray(flaggedProviders) && flaggedProviders.length === 1) {
    score -= 25;
  }

  const criticalFindings = (findings || []).filter((entry) => entry.severity === "critical").length;
  if (criticalFindings > 0) {
    score -= Math.min(25, criticalFindings * 8);
  }

  return clampScore(score);
}

function sortWebsiteFindings(findings = []) {
  return [...findings].sort((left, right) => {
    const order = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
    const severityDelta = (order[right.severity] || 0) - (order[left.severity] || 0);
    if (severityDelta !== 0) {
      return severityDelta;
    }

    return left.title.localeCompare(right.title);
  });
}

function buildWebsiteFindings({ modules, finalUrl }) {
  const findings = [];
  const dnsDomain = modules?.dnsDomain || {};
  const headers = modules?.headers || {};
  const content = modules?.content || {};
  const redirects = modules?.redirects || {};
  const reputation = modules?.reputation || {};
  const vulnerabilityChecks = modules?.vulnerabilityChecks || {};
  const fetchModule = modules?.fetch || {};
  const ssl = modules?.ssl || {};

  let parsedFinal = null;
  try {
    parsedFinal = new URL(finalUrl || modules?.url?.final || modules?.url?.normalized || "https://example.invalid");
  } catch {
    parsedFinal = new URL("https://example.invalid");
  }

  const ageDaysRaw = dnsDomain?.ageDays;
  const domainAgeDays = typeof ageDaysRaw === "number" ? ageDaysRaw : Number.NaN;
  if (fetchModule.status === "blocked") {
    findings.push(
      createFinding(
        "critical",
        "website_fetch_blocked",
        "Reachability",
        "Target blocked during fetch",
        "The website could not be fetched because the redirect or target violated safety rules.",
        fetchModule.blockedReason || "blocked",
        30
      )
    );
  } else if (fetchModule.status === "error") {
    findings.push(
      createFinding(
        "medium",
        "website_fetch_error",
        "Reachability",
        "Website fetch failed",
        "The scanner could not fetch content from the target website within policy limits.",
        fetchModule.blockedReason || "fetch_failed",
        12
      )
    );
  }

  if ((headers.missing || []).length > 0) {
    findings.push(
      createFinding(
        "medium",
        "website_headers_missing",
        "Headers",
        "Missing security headers",
        "The target is missing one or more recommended HTTP security headers.",
        headers.missing.join(", "),
        Math.min(20, headers.missing.length * 4)
      )
    );
  }

  if (Number.isFinite(domainAgeDays) && domainAgeDays >= 0 && domainAgeDays < 30) {
    findings.push(
      createFinding(
        "high",
        "website_domain_new",
        "Domain",
        "Newly registered domain",
        "The domain appears recently registered, which increases phishing risk.",
        `${domainAgeDays} days old`,
        15
      )
    );
  }

  if (dnsDomain.whoisPrivacyLikely) {
    findings.push(
      createFinding(
        "low",
        "website_whois_private",
        "Domain",
        "WHOIS registration appears privacy-protected",
        "WHOIS registration details appear partially redacted.",
        "Registrant details redacted",
        4
      )
    );
  }

  if (ssl.status === "completed") {
    if (ssl.certExpired) {
      findings.push(
        createFinding(
          "high",
          "website_ssl_expired",
          "TLS",
          "TLS certificate is expired",
          "The TLS certificate has expired.",
          ssl.certValidTo || "expired",
          20
        )
      );
    }

    if (ssl.certSelfSigned) {
      findings.push(
        createFinding(
          "high",
          "website_ssl_self_signed",
          "TLS",
          "TLS certificate is self-signed",
          "The TLS certificate is self-signed and may not be trustworthy.",
          ssl.certIssuer || "self-signed",
          15
        )
      );
    }
  } else if (parsedFinal.protocol === "http:") {
    findings.push(
      createFinding(
        "medium",
        "website_no_https",
        "TLS",
        "Website is served over HTTP",
        "The website does not enforce HTTPS transport.",
        finalUrl,
        18
      )
    );
  }

  if ((redirects.count || 0) > 3) {
    findings.push(
      createFinding(
        "medium",
        "website_redirect_chain_long",
        "Redirects",
        "Long redirect chain",
        "The target used multiple redirects before reaching the final destination.",
        `${redirects.count} redirects`,
        8
      )
    );
  }

  if ((redirects.crossDomainCount || 0) > 0) {
    findings.push(
      createFinding(
        "medium",
        "website_cross_domain_redirect",
        "Redirects",
        "Cross-domain redirect observed",
        "The redirect chain changed domains, which can hide final destination intent.",
        `${redirects.crossDomainCount} cross-domain redirect(s)`,
        10
      )
    );
  }

  if ((content.phishingSignalScore || 0) >= 4) {
    const suspiciousEvidence = [
      ...(content.phishingPhrases || []).slice(0, 5),
      ...(content.suspiciousKeywords || []).slice(0, 5)
    ];

    findings.push(
      createFinding(
        (content.phishingSignalScore || 0) >= 7 ? "high" : "medium",
        "website_suspicious_content",
        "Content",
        "Suspicious language indicators detected",
        "The page includes high-confidence phishing language patterns or risky combinations of signals.",
        suspiciousEvidence.join(", "),
        (content.phishingSignalScore || 0) >= 7 ? 10 : 5
      )
    );
  }

  if ((content.hiddenIframes || 0) > 0) {
    findings.push(
      createFinding(
        "high",
        "website_hidden_iframe",
        "Content",
        "Hidden iframe detected",
        "The page contains hidden iframe markup, which can be used for deceptive or malicious behavior.",
        `${content.hiddenIframes} hidden iframe(s)`,
        10
      )
    );
  }

  if ((content.obfuscatedScriptIndicators || 0) > 0) {
    findings.push(
      createFinding(
        "high",
        "website_script_obfuscation",
        "Content",
        "Obfuscated script indicators detected",
        "Script obfuscation markers were found in page content.",
        `${content.obfuscatedScriptIndicators} indicator(s)`,
        12
      )
    );
  }

  if ((content.suspiciousExternalLinkCount || 0) > 0) {
    findings.push(
      createFinding(
        "medium",
        "website_external_links_suspicious",
        "Content",
        "Suspicious outbound link targets detected",
        "The page links to one or more external domains with high-risk top-level domains.",
        (content.suspiciousExternalLinks || []).join(", "),
        Math.min(8, Number(content.suspiciousExternalLinkCount) * 2)
      )
    );
  }

  if ((dnsDomain?.mailAuth?.mxCount || 0) > 0 && (!dnsDomain?.mailAuth?.spfPresent || !dnsDomain?.mailAuth?.dmarcPresent)) {
    findings.push(
      createFinding(
        "low",
        "website_mail_auth_missing",
        "Domain",
        "Email anti-spoofing controls are incomplete",
        "SPF or DMARC protection appears missing for a domain that receives email.",
        `SPF: ${dnsDomain?.mailAuth?.spfPresent ? "present" : "missing"}, DMARC: ${dnsDomain?.mailAuth?.dmarcPresent ? "present" : "missing"}`,
        5
      )
    );
  }

  if (headers?.qualitySignals?.cspWeak) {
    findings.push(
      createFinding(
        "low",
        "website_csp_weak",
        "Headers",
        "Content-Security-Policy allows unsafe directives",
        "The CSP includes unsafe directives that reduce script injection protection.",
        headers?.values?.contentSecurityPolicy || "unsafe directives detected",
        5
      )
    );
  }

  const confirmedExposures = Array.isArray(vulnerabilityChecks.exposures) ? vulnerabilityChecks.exposures.filter((entry) => entry?.confirmed) : [];
  if (confirmedExposures.length > 0) {
    findings.push(
      createFinding(
        "critical",
        "website_sensitive_path_exposed",
        "Exposure",
        "Sensitive endpoint appears publicly reachable",
        "One or more sensitive paths responded with evidence of exposed configuration or backup data.",
        confirmedExposures.map((entry) => `${entry.path} (${entry.status}${entry.evidenceType ? `, ${entry.evidenceType}` : ""})`).join(", "),
        Math.min(30, confirmedExposures.length * 10)
      )
    );
  }

  const confirmedAdminEndpoints = Array.isArray(vulnerabilityChecks.adminEndpoints)
    ? vulnerabilityChecks.adminEndpoints.filter((entry) => entry?.confirmed)
    : [];
  if (confirmedAdminEndpoints.length > 0) {
    findings.push(
      createFinding(
        "low",
        "website_admin_paths_reachable",
        "Exposure",
        "Administrative paths are reachable",
        "Administrative endpoints appear reachable from the public internet and should be protected with strong controls.",
        confirmedAdminEndpoints.map((entry) => `${entry.path} (${entry.status})`).join(", "),
        4
      )
    );
  }

  if (reputation.flagged) {
    const flaggedProviderCount = Array.isArray(reputation.flaggedProviders) ? reputation.flaggedProviders.length : 0;
    findings.push(
      createFinding(
        flaggedProviderCount >= 2 ? "critical" : "high",
        "website_reputation_flagged",
        "Threat Intel",
        "Threat intelligence flagged this website",
        "External threat intelligence providers identified this target as risky.",
        (reputation.flaggedProviders || []).join(", "),
        flaggedProviderCount >= 2 ? 50 : 25
      )
    );
  }

  return findings;
}

function summarizeWebsiteAssessment({ modules, findings }) {
  const sortedFindings = sortWebsiteFindings(findings);
  const safetyScore = scoreWebsiteSafety({
    findings: sortedFindings,
    modules
  });
  const safetyVerdict = verdictFromSafetyScore(safetyScore);
  const reportVerdict = reportVerdictFromSafetyVerdict(safetyVerdict);
  const riskScore = clampScore(100 - safetyScore);
  const plainLanguageReasons = sortedFindings.length
    ? sortedFindings.slice(0, 6).map((entry) => entry.description)
    : ["No critical website-risk indicators were detected in this scan."];

  return {
    findings: sortedFindings,
    safetyScore,
    safetyVerdict,
    reportVerdict,
    riskScore,
    plainLanguageReasons,
    recommendations: buildRecommendations({
      safetyVerdict,
      findings: sortedFindings,
      moduleStatus: {
        fetchStatus: modules?.fetch?.status || "unknown",
        ipHostingStatus: modules?.ipHosting?.status || "unknown"
      }
    })
  };
}

function normalizeWebsiteModules(modules = {}) {
  const normalized = structuredClone(modules || {});
  const dnsDomain = normalized?.dnsDomain && typeof normalized.dnsDomain === "object" ? normalized.dnsDomain : {};
  const registeredAtTimestamp = Date.parse(dnsDomain?.registeredAt || "");
  const rawAgeDays = typeof dnsDomain?.ageDays === "number" ? dnsDomain.ageDays : Number.NaN;
  const derivedAgeDays = Number.isFinite(registeredAtTimestamp)
    ? Math.max(0, Math.floor((Date.now() - registeredAtTimestamp) / (24 * 60 * 60 * 1000)))
    : null;

  normalized.dnsDomain = {
    ...dnsDomain,
    ageDays: Number.isFinite(rawAgeDays) && rawAgeDays >= 0 ? Math.floor(rawAgeDays) : derivedAgeDays,
    rdap:
      dnsDomain?.rdap && typeof dnsDomain.rdap === "object"
        ? {
            ...dnsDomain.rdap,
            domainStatus: Array.isArray(dnsDomain.rdap.domainStatus) ? dnsDomain.rdap.domainStatus.filter(Boolean).slice(0, 10) : [],
            dnssecSigned: typeof dnsDomain.rdap.dnssecSigned === "boolean" ? dnsDomain.rdap.dnssecSigned : null,
            abuseEmail: dnsDomain.rdap.abuseEmail || null
          }
        : {
            domainStatus: [],
            dnssecSigned: null,
            abuseEmail: null,
            source: null,
            attempts: []
          }
  };

  const vulnerabilityChecks =
    normalized?.vulnerabilityChecks && typeof normalized.vulnerabilityChecks === "object" ? normalized.vulnerabilityChecks : {};
  const exposures = Array.isArray(vulnerabilityChecks.exposures) ? vulnerabilityChecks.exposures : [];
  const adminEndpoints = Array.isArray(vulnerabilityChecks.adminEndpoints) ? vulnerabilityChecks.adminEndpoints : [];

  normalized.vulnerabilityChecks = {
    ...vulnerabilityChecks,
    exposures: exposures
      .map((entry) => {
        if (!entry || typeof entry !== "object") {
          return null;
        }

        const hasEvidence = Boolean(entry.confirmed) || Boolean(entry.evidenceType) || Boolean(entry.evidenceSummary);
        if (!hasEvidence) {
          return null;
        }

        return {
          path: parseProbePathname(entry.path),
          status: Number(entry.status) || 0,
          reachable: true,
          confirmed: true,
          kind: entry.kind || null,
          evidenceType: entry.evidenceType || null,
          evidenceSummary: entry.evidenceSummary || String(entry.path || "").trim(),
          contentType: entry.contentType || null,
          location: entry.location || null
        };
      })
      .filter(Boolean),
    adminEndpoints: adminEndpoints
      .map((entry) => {
        if (!entry || typeof entry !== "object") {
          return null;
        }

        const status = Number(entry.status) || 0;
        const hasEvidence = Boolean(entry.confirmed) || Boolean(entry.evidenceType) || Boolean(entry.evidenceSummary) || status === 401 || status === 403;
        if (!hasEvidence) {
          return null;
        }

        return {
          path: parseProbePathname(entry.path),
          status,
          reachable: true,
          confirmed: true,
          evidenceType: entry.evidenceType || (status === 401 || status === 403 ? "auth_gate" : null),
          evidenceSummary: entry.evidenceSummary || String(entry.path || "").trim(),
          location: entry.location || null
        };
      })
      .filter(Boolean)
  };

  return normalized;
}

export function normalizeWebsiteSafetyReport(report) {
  if (!report || report.sourceType !== "website" || !report.websiteSafety || typeof report.websiteSafety !== "object") {
    return report;
  }

  const normalizedReport = structuredClone(report);
  const modules = normalizeWebsiteModules(normalizedReport.websiteSafety?.modules || {});
  const finalUrl = normalizedReport?.url?.final || normalizedReport?.websiteSafety?.url?.final || normalizedReport?.file?.originalName || "";
  const assessment = summarizeWebsiteAssessment({
    modules,
    findings: buildWebsiteFindings({
      modules,
      finalUrl
    })
  });
  const threatType = summarizeReputationThreatType(modules?.reputation);

  normalizedReport.verdict = assessment.reportVerdict;
  normalizedReport.riskScore = assessment.riskScore;
  normalizedReport.findings = assessment.findings;
  normalizedReport.recommendations = assessment.recommendations;
  normalizedReport.plainLanguageReasons = assessment.plainLanguageReasons;
  normalizedReport.websiteSafety = {
    ...normalizedReport.websiteSafety,
    score: assessment.safetyScore,
    verdict: assessment.safetyVerdict,
    modules
  };
  normalizedReport.technicalIndicators = {
    ...(normalizedReport.technicalIndicators || {}),
    redirectCount: Number(modules?.redirects?.count) || 0,
    crossDomainRedirects: Number(modules?.redirects?.crossDomainCount) || 0,
    missingSecurityHeaders: Array.isArray(modules?.headers?.missing) ? modules.headers.missing : [],
    fetchAttempts: Array.isArray(modules?.fetch?.attempts)
      ? modules.fetch.attempts
      : Array.isArray(normalizedReport?.technicalIndicators?.fetchAttempts)
        ? normalizedReport.technicalIndicators.fetchAttempts
        : [],
    spfPresent: Boolean(modules?.dnsDomain?.mailAuth?.spfPresent),
    dmarcPresent: Boolean(modules?.dnsDomain?.mailAuth?.dmarcPresent),
    securityTxtPresent: Boolean(modules?.discovery?.securityTxt?.found),
    robotsTxtPresent: Boolean(modules?.discovery?.robotsTxt?.found),
    threatType
  };
  normalizedReport.engines = {
    ...(normalizedReport.engines || {}),
    dnsDomain: {
      status: modules?.dnsDomain?.status || normalizedReport?.engines?.dnsDomain?.status || "completed"
    },
    ipHosting: {
      status: modules?.ipHosting?.status || normalizedReport?.engines?.ipHosting?.status || "completed"
    },
    ssl: {
      status: modules?.ssl?.status || normalizedReport?.engines?.ssl?.status || "completed"
    },
    headers: {
      status: modules?.headers?.status || normalizedReport?.engines?.headers?.status || "completed"
    },
    content: {
      status: modules?.content?.status || normalizedReport?.engines?.content?.status || "completed"
    },
    redirects: {
      status: modules?.redirects?.status || normalizedReport?.engines?.redirects?.status || "completed"
    },
    reputation: {
      status: normalizedReport?.engines?.reputation?.status || (modules?.reputation?.flagged ? "flagged" : "clean")
    },
    vulnerabilityChecks: {
      status: modules?.vulnerabilityChecks?.status || normalizedReport?.engines?.vulnerabilityChecks?.status || "completed"
    }
  };

  return normalizedReport;
}

function buildReportBase({ inputUrl, normalizedUrl, finalUrl, contentType = "", byteLength = 0 }) {
  const hashes = hashText(normalizedUrl);
  const parsedFinal = new URL(finalUrl || normalizedUrl);

  return {
    id: `scan_${crypto.randomUUID()}`,
    createdAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    sourceType: "website",
    file: {
      originalName: finalUrl || normalizedUrl,
      extension: "(website)",
      size: Number(byteLength) || 0,
      sizeDisplay: humanFileSize(Number(byteLength) || 0),
      declaredMimeType: "text/url",
      detectedMimeType: contentType || "unknown",
      detectedFileType: "website",
      magicType: "Website target",
      entropy: 0,
      printableRatio: 1,
      hashes
    },
    url: {
      input: inputUrl,
      normalized: normalizedUrl,
      final: finalUrl || normalizedUrl,
      protocol: parsedFinal.protocol.replace(/:$/, ""),
      hostname: parsedFinal.hostname
    }
  };
}

function buildBlockedWebsiteReport({ normalizedInput, reason }) {
  const reportBase = buildReportBase({
    inputUrl: normalizedInput.inputUrl,
    normalizedUrl: normalizedInput.normalizedUrl,
    finalUrl: normalizedInput.normalizedUrl
  });

  const finding = createFinding(
    "critical",
    "website_ssrf_blocked",
    "SSRF Protection",
    "Target blocked by SSRF safety guard",
    "The provided URL resolves to a local or private network target and cannot be scanned safely.",
    reason,
    40
  );

  const score = 5;
  const safetyVerdict = verdictFromSafetyScore(score);

  return {
    ...reportBase,
    verdict: reportVerdictFromSafetyVerdict(safetyVerdict),
    riskScore: 100 - score,
    findings: [finding],
    plainLanguageReasons: [finding.description],
    recommendations: [
      "This URL was blocked to prevent internal network probing. Validate the target and retry with a public hostname.",
      "This scan is a safety assessment, not a guarantee that the site is fully secure."
    ],
    technicalIndicators: {
      blockedReason: reason
    },
    engines: {
      normalization: { status: "completed" },
      ssrfGuard: { status: "blocked", reason }
    },
    websiteSafety: {
      score,
      verdict: safetyVerdict,
      checkedAt: new Date().toISOString(),
      url: reportBase.url,
      modules: {
        normalization: {
          input: normalizedInput.inputUrl,
          normalized: normalizedInput.normalizedUrl,
          asciiHostname: normalizedInput.asciiHostname,
          unicodeHostname: normalizedInput.unicodeHostname
        },
        dnsDomain: {
          status: "blocked",
          reason
        }
      }
    }
  };
}

function summarizeReputationThreatType(reputation) {
  if (!reputation?.flagged) {
    return null;
  }

  const threats = Array.isArray(reputation.flaggedThreats) ? reputation.flaggedThreats.filter(Boolean) : [];
  if (threats.length === 0) {
    return "SUSPICIOUS";
  }

  return threats[0];
}

export async function scanWebsiteSafetyTarget({ url, runtimeConfig = config }) {
  const normalizedInput = normalizeWebsiteUrlInput(url);
  const initialGuard = await resolvePublicAddresses(normalizedInput.asciiHostname);
  if (!initialGuard.allowed) {
    return buildBlockedWebsiteReport({
      normalizedInput,
      reason: initialGuard.reason || "private_target_blocked"
    });
  }

  const fetchResult = await fetchWithSafeRedirects(normalizedInput.normalizedUrl, runtimeConfig);
  const finalUrl = fetchResult.finalUrl || normalizedInput.normalizedUrl;

  const finalParsed = new URL(finalUrl);
  const finalGuard = await resolvePublicAddresses(finalParsed.hostname);
  if (!finalGuard.allowed) {
    return buildBlockedWebsiteReport({
      normalizedInput,
      reason: finalGuard.reason || "private_target_blocked"
    });
  }

  const moduleSettled = await Promise.allSettled([
    analyzeDnsAndDomain(finalParsed.hostname, runtimeConfig),
    checkTlsMetadata(finalUrl, runtimeConfig),
    getUrlReputationSnapshot({
      url: finalUrl,
      config: runtimeConfig
    }),
    runBasicVulnerabilityChecks({
      finalUrl,
      runtimeConfig
    }),
    analyzeDiscoveryFiles({
      finalUrl,
      runtimeConfig
    })
  ]);

  const dnsDomain = safeSettledResult(moduleSettled[0], {
    status: "error",
    reason: "dns_module_failed",
    records: { a: [], aaaa: [], mx: [], ns: [], cname: [], txt: [], soa: null },
    nameservers: [],
    ageDays: null,
    whoisPrivacyLikely: false,
    mailAuth: {
      mxCount: 0,
      spfPresent: false,
      spfRecord: null,
      dmarcPresent: false,
      dmarcRecord: null
    },
    rdap: {
      source: null,
      attempts: []
    }
  });
  const ssl = safeSettledResult(moduleSettled[1], {
    status: "error",
    reason: "ssl_module_failed"
  });
  const reputation = safeSettledResult(moduleSettled[2], {
    providers: [],
    flagged: false,
    flaggedProviders: [],
    flaggedThreats: []
  });
  const vulnerabilityChecks = safeSettledResult(moduleSettled[3], {
    status: "error",
    reason: "vulnerability_checks_failed",
    exposures: [],
    adminEndpoints: []
  });
  const discovery = safeSettledResult(moduleSettled[4], {
    status: "error",
    reason: "discovery_files_failed",
    securityTxt: {
      found: false
    },
    robotsTxt: {
      found: false
    }
  });

  const headers = analyzeSecurityHeaders(fetchResult.headers || {});
  const content = analyzeContent({
    html: fetchResult.bodySnippet || "",
    finalUrl
  });
  const redirects = analyzeRedirects(fetchResult.redirects || []);
  const technologies = detectTechnologies({
    headers: fetchResult.headers || {},
    html: fetchResult.bodySnippet || ""
  });
  const modules = {
    normalization: {
      input: normalizedInput.inputUrl,
      normalized: normalizedInput.normalizedUrl,
      asciiHostname: normalizedInput.asciiHostname,
      unicodeHostname: normalizedInput.unicodeHostname
    },
    dnsDomain,
    ipHosting: await analyzeIpHosting(dnsDomain, runtimeConfig),
    ssl,
    headers,
    content,
    redirects,
    reputation,
    technology: technologies,
    vulnerabilityChecks,
    discovery,
    fetch: {
      status: fetchResult.status,
      blockedReason: fetchResult.blockedReason || null,
      statusCode: fetchResult.statusCode || null,
      truncated: Boolean(fetchResult.truncated),
      byteLength: fetchResult.byteLength || 0,
      attempts: fetchResult.attempts || []
    },
    url: {
      input: normalizedInput.inputUrl,
      normalized: normalizedInput.normalizedUrl,
      final: finalUrl,
      protocol: finalParsed.protocol.replace(/:$/, ""),
      hostname: finalParsed.hostname
    }
  };
  const assessment = summarizeWebsiteAssessment({
    modules,
    findings: buildWebsiteFindings({
      modules,
      finalUrl
    })
  });

  const reportBase = buildReportBase({
    inputUrl: normalizedInput.inputUrl,
    normalizedUrl: normalizedInput.normalizedUrl,
    finalUrl,
    contentType: fetchResult.contentType || "",
    byteLength: Number(fetchResult.byteLength) || 0
  });

  const threatType = summarizeReputationThreatType(reputation);

  return {
    ...reportBase,
    verdict: assessment.reportVerdict,
    riskScore: assessment.riskScore,
    findings: assessment.findings,
    recommendations: assessment.recommendations,
    plainLanguageReasons: assessment.plainLanguageReasons,
    technicalIndicators: {
      redirectCount: redirects.count,
      crossDomainRedirects: redirects.crossDomainCount,
      missingSecurityHeaders: headers.missing,
      resolvedAddresses: fetchResult.resolvedAddresses || {},
      threatType,
      fetchAttempts: fetchResult.attempts || [],
      spfPresent: Boolean(dnsDomain?.mailAuth?.spfPresent),
      dmarcPresent: Boolean(dnsDomain?.mailAuth?.dmarcPresent),
      securityTxtPresent: Boolean(discovery?.securityTxt?.found),
      robotsTxtPresent: Boolean(discovery?.robotsTxt?.found)
    },
    engines: {
      normalization: { status: "completed" },
      fetch: {
        status: fetchResult.status,
        blockedReason: fetchResult.blockedReason || null,
        statusCode: fetchResult.statusCode || null
      },
      dnsDomain: { status: dnsDomain.status || "completed" },
      ipHosting: { status: modules.ipHosting.status || "completed" },
      ssl: { status: ssl.status || "completed" },
      headers: { status: headers.status },
      content: { status: content.status },
      redirects: { status: redirects.status },
      reputation: { status: reputation.flagged ? "flagged" : "clean" },
      technology: { status: technologies.status },
      vulnerabilityChecks: { status: vulnerabilityChecks.status || "completed" },
      discovery: { status: discovery.status || "completed" }
    },
    websiteSafety: {
      score: assessment.safetyScore,
      verdict: assessment.safetyVerdict,
      checkedAt: new Date().toISOString(),
      url: modules.url,
      modules
    },
    url: {
      ...reportBase.url,
      statusCode: fetchResult.statusCode || null,
      contentType: fetchResult.contentType || null,
      redirects: redirects.chain,
      resolvedAddresses: fetchResult.resolvedAddresses || {},
      truncated: Boolean(fetchResult.truncated)
    }
  };
}
