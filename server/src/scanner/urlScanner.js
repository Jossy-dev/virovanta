import crypto from "crypto";
import dns from "dns/promises";
import net from "net";
import os from "os";
import path from "path";
import tls from "tls";
import fs from "fs/promises";
import { config } from "../config.js";
import { isPortAllowed, normalizeUrlInput } from "../utils/urlIntake.js";
import { getUrlReputationSnapshot } from "../utils/urlReputation.js";

const DEFAULT_URL_TIMEOUT_MS = 12_000;
const DEFAULT_MAX_REDIRECTS = 4;
const DEFAULT_MAX_BODY_BYTES = 200_000;
const DOWNLOADABLE_CONTENT_TYPES = [
  "application/octet-stream",
  "application/x-msdownload",
  "application/x-dosexec",
  "application/x-sh",
  "application/x-bat",
  "application/zip",
  "application/x-rar-compressed",
  "application/x-7z-compressed",
  "application/pdf",
  "application/vnd.ms-excel",
  "application/vnd.openxmlformats-officedocument"
];
const DOWNLOADABLE_EXTENSIONS = new Set(["exe", "dll", "msi", "zip", "rar", "7z", "pdf", "doc", "docx", "xls", "xlsx", "js", "vbs", "ps1", "bat", "cmd", "scr", "jar", "apk"]);

const SUSPICIOUS_URL_KEYWORDS = [
  "login",
  "verify",
  "secure",
  "account",
  "update",
  "signin",
  "wallet",
  "payment",
  "invoice",
  "support",
  "airdrop",
  "gift"
];

const SUSPICIOUS_TLDS = new Set(["zip", "top", "xyz", "click", "rest", "shop", "monster", "quest"]);

const PHISHING_TEXT_PATTERNS = [
  /verify\s+your\s+account/i,
  /urgent\s+action\s+required/i,
  /your\s+account\s+has\s+been\s+suspended/i,
  /confirm\s+your\s+identity/i,
  /payment\s+failed/i
];

const SCRIPT_OBFUSCATION_PATTERN = /(?:eval\(|fromCharCode|atob\(|unescape\(|Function\s*\()/i;

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

function ipV4ToNumber(address) {
  return address.split(".").reduce((value, octet) => (value << 8) + Number(octet), 0) >>> 0;
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

function hashText(value) {
  return {
    md5: crypto.createHash("md5").update(value).digest("hex"),
    sha1: crypto.createHash("sha1").update(value).digest("hex"),
    sha256: crypto.createHash("sha256").update(value).digest("hex")
  };
}

function countSubdomains(hostname) {
  const labels = String(hostname || "")
    .split(".")
    .filter(Boolean);

  if (labels.length <= 2) {
    return 0;
  }

  return labels.length - 2;
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

  if (normalized.endsWith(".local") || normalized.endsWith(".internal")) {
    return true;
  }

  if (normalized.endsWith(".arpa")) {
    return true;
  }

  if (!normalized.includes(".")) {
    return true;
  }

  return false;
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
  const buffer = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)));

  return {
    bodySnippet,
    buffer,
    byteLength,
    truncated
  };
}

function buildFetchTimeoutController(timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => {
    controller.abort();
  }, timeoutMs);

  return {
    controller,
    clear: () => clearTimeout(timeout)
  };
}

function flattenResolvedAddresses(resolvedAddresses) {
  return [...resolvedAddresses.entries()].flatMap(([host, addresses]) => addresses.map((address) => `${host} -> ${address}`));
}

function shouldInspectAsDownload({ contentType, contentDisposition, finalUrl }) {
  const normalizedType = String(contentType || "")
    .split(";")[0]
    .trim()
    .toLowerCase();
  const normalizedDisposition = String(contentDisposition || "").toLowerCase();

  if (normalizedDisposition.includes("attachment")) {
    return true;
  }

  if (DOWNLOADABLE_CONTENT_TYPES.includes(normalizedType)) {
    return true;
  }

  try {
    const url = new URL(finalUrl);
    const extension = String(url.pathname.split(".").pop() || "")
      .toLowerCase()
      .trim();
    if (extension && DOWNLOADABLE_EXTENSIONS.has(extension)) {
      return true;
    }
  } catch {
    return false;
  }

  return false;
}

function parseContentDispositionFilename(contentDisposition) {
  const value = String(contentDisposition || "");
  if (!value) {
    return "";
  }

  const utf8Match = value.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    return decodeURIComponent(utf8Match[1]).replace(/[^\w.\-]+/g, "_").slice(0, 140);
  }

  const quotedMatch = value.match(/filename=\"?([^";]+)\"?/i);
  if (quotedMatch?.[1]) {
    return quotedMatch[1].replace(/[^\w.\-]+/g, "_").slice(0, 140);
  }

  return "";
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

  const timeoutMs = Number(runtimeConfig?.urlScanTimeoutMs) || DEFAULT_URL_TIMEOUT_MS;

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

async function runOptionalBrowserRender(targetUrl, runtimeConfig) {
  if (!runtimeConfig?.urlScanEnableBrowserRender) {
    return {
      status: "disabled",
      reason: "feature_disabled"
    };
  }

  let playwright;
  try {
    playwright = await import("playwright");
  } catch {
    return {
      status: "unavailable",
      reason: "playwright_not_installed"
    };
  }

  const timeoutMs = Number(runtimeConfig?.urlScanBrowserTimeoutMs) || 10_000;
  let browser = null;

  try {
    browser = await playwright.chromium.launch({
      headless: true,
      args: ["--disable-gpu", "--disable-dev-shm-usage"]
    });

    const context = await browser.newContext({
      javaScriptEnabled: true,
      bypassCSP: false
    });
    const page = await context.newPage();
    await page.goto(targetUrl, {
      timeout: timeoutMs,
      waitUntil: "domcontentloaded"
    });

    const pageTitle = (await page.title().catch(() => "")).slice(0, 220);
    const textContentLength = await page
      .evaluate(() => String(document?.body?.innerText || "").slice(0, 5000).length)
      .catch(() => 0);
    const hasPasswordField = await page
      .evaluate(() => Boolean(document?.querySelector('input[type="password"]')))
      .catch(() => false);

    await context.close();

    return {
      status: "completed",
      title: pageTitle || null,
      textContentLength: Number(textContentLength) || 0,
      hasPasswordField
    };
  } catch (error) {
    return {
      status: "error",
      reason: error?.name === "TimeoutError" ? "browser_timeout" : "browser_render_failed"
    };
  } finally {
    if (browser) {
      await browser.close().catch(() => {});
    }
  }
}

async function fetchWithSafeRedirects(startUrl, runtimeConfig) {
  const timeoutMs = Number(runtimeConfig.urlScanTimeoutMs) || DEFAULT_URL_TIMEOUT_MS;
  const maxRedirects = Number(runtimeConfig.urlScanMaxRedirects) || DEFAULT_MAX_REDIRECTS;
  const maxBodyBytes = Number(runtimeConfig.urlScanMaxBodyBytes) || DEFAULT_MAX_BODY_BYTES;
  const userAgent =
    String(runtimeConfig.urlScanUserAgent || "").trim() ||
    "ViroVanta-Link-Scanner/1.0 (+https://www.virovanta.com)";

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
        resolvedAddresses: flattenResolvedAddresses(resolvedAddresses)
      };
    }

    if (!isPortAllowed(parsedUrl.port)) {
      return {
        status: "blocked",
        blockedReason: "unsafe_port_blocked",
        finalUrl: currentUrl,
        redirects,
        resolvedAddresses: flattenResolvedAddresses(resolvedAddresses)
      };
    }

    const guard = await resolvePublicAddresses(parsedUrl.hostname);

    const addressBucket = resolvedAddresses.get(parsedUrl.hostname) || [];
    guard.addresses.forEach((address) => {
      if (!addressBucket.includes(address)) {
        addressBucket.push(address);
      }
    });
    resolvedAddresses.set(parsedUrl.hostname, addressBucket);

    if (!guard.allowed) {
      return {
        status: "blocked",
        blockedReason: guard.reason,
        finalUrl: currentUrl,
        redirects,
        resolvedAddresses: flattenResolvedAddresses(resolvedAddresses)
      };
    }

    const timeoutHandle = buildFetchTimeoutController(timeoutMs);

    try {
      const response = await fetch(currentUrl, {
        method: "GET",
        redirect: "manual",
        signal: timeoutHandle.controller.signal,
        headers: {
          "user-agent": userAgent,
          accept: "text/html,application/json;q=0.9,*/*;q=0.7"
        }
      });

      const statusCode = Number(response.status) || 0;
      const location = response.headers.get("location");
      const isRedirect = statusCode >= 300 && statusCode < 400 && location;

      if (!isRedirect) {
        const bodyData = await readBodySnippet(response, maxBodyBytes);
        return {
          status: "ok",
          finalUrl: currentUrl,
          redirects,
          resolvedAddresses: flattenResolvedAddresses(resolvedAddresses),
          statusCode,
          contentType: response.headers.get("content-type") || "unknown",
          contentDisposition: response.headers.get("content-disposition") || "",
          bodySnippet: bodyData.bodySnippet,
          bodyBuffer: bodyData.buffer,
          byteLength: bodyData.byteLength,
          truncated: bodyData.truncated
        };
      }

      if (redirectStep === maxRedirects) {
        return {
          status: "blocked",
          blockedReason: "max_redirects_exceeded",
          finalUrl: currentUrl,
          redirects,
          resolvedAddresses: flattenResolvedAddresses(resolvedAddresses)
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
          resolvedAddresses: flattenResolvedAddresses(resolvedAddresses)
        };
      }

      redirects.push({
        from: currentUrl,
        to: nextUrl,
        statusCode
      });
      currentUrl = nextUrl;
    } catch (error) {
      const reason = error?.name === "AbortError" ? "fetch_timeout" : "fetch_failed";

      return {
        status: "error",
        blockedReason: reason,
        finalUrl: currentUrl,
        redirects,
        resolvedAddresses: flattenResolvedAddresses(resolvedAddresses)
      };
    } finally {
      timeoutHandle.clear();
    }
  }

  return {
    status: "blocked",
    blockedReason: "max_redirects_exceeded",
    finalUrl: currentUrl,
    redirects: [],
    resolvedAddresses: []
  };
}

function countKeywordMatches(text) {
  const normalized = String(text || "").toLowerCase();
  if (!normalized) {
    return 0;
  }

  return SUSPICIOUS_URL_KEYWORDS.reduce((count, keyword) => {
    return normalized.includes(keyword) ? count + 1 : count;
  }, 0);
}

function extractTitleFromHtml(bodySnippet) {
  const match = String(bodySnippet || "").match(/<title[^>]*>([^<]{1,180})<\/title>/i);
  return match?.[1]?.trim() || null;
}

function buildRecommendations({ verdict, blockedReason, redirects, statusCode }) {
  const recommendations = [];

  if (blockedReason) {
    recommendations.push("Do not open this link from corporate devices until security review is complete.");
  }

  if (verdict !== "clean") {
    recommendations.push("Avoid entering passwords or payment details on this target.");
    recommendations.push("Validate the URL with your official domain allowlist before sharing internally.");
  }

  if ((redirects || []).length > 0) {
    recommendations.push("Review the redirect chain for unexpected domain changes.");
  }

  if (Number(statusCode) >= 400) {
    recommendations.push("Capture a screenshot and preserve headers for incident triage.");
  }

  if (recommendations.length === 0) {
    recommendations.push("No high-risk indicators detected from this first-pass URL scan.");
  }

  return recommendations;
}

function determineVerdict(riskScore, findings) {
  if (riskScore >= 75 || findings.some((finding) => finding.severity === "critical")) {
    return "malicious";
  }

  if (riskScore >= 40 || findings.some((finding) => finding.severity === "high")) {
    return "suspicious";
  }

  return "clean";
}

function finding(severity, id, category, weight, title, description, evidence) {
  return {
    id,
    severity,
    category,
    weight,
    title,
    description,
    evidence: String(evidence || "").slice(0, 300)
  };
}

function getBlockedReasonText(reason) {
  switch (reason) {
    case "unsupported_protocol":
      return "Only HTTP and HTTPS URLs are allowed.";
    case "unsafe_port_blocked":
      return "Target port is blocked. Only ports 80 and 443 are allowed.";
    case "local_hostname_blocked":
      return "Target resolves to a local/internal hostname and was blocked for SSRF safety.";
    case "private_ip_blocked":
      return "Target IP is private/reserved and was blocked for SSRF safety.";
    case "private_dns_target_blocked":
      return "DNS resolved to private/reserved address space and was blocked.";
    case "invalid_redirect_url":
      return "Redirect target is malformed and was blocked.";
    case "dns_resolution_failed":
      return "Target hostname could not be resolved.";
    case "max_redirects_exceeded":
      return "Redirect chain exceeded allowed limit.";
    case "fetch_timeout":
      return "Target did not respond within timeout.";
    default:
      return "Target request failed during URL scanning.";
  }
}

function sortFindings(findings) {
  const severityOrder = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1
  };

  return [...findings].sort((left, right) => {
    const severityDelta = (severityOrder[right.severity] || 0) - (severityOrder[left.severity] || 0);
    if (severityDelta !== 0) {
      return severityDelta;
    }

    return left.title.localeCompare(right.title);
  });
}

function buildUrlReportBase({ inputUrl, normalizedUrl, finalUrl, contentType, byteLength }) {
  const hashes = hashText(normalizedUrl);
  const finalParsed = new URL(finalUrl || normalizedUrl);

  return {
    id: `scan_${crypto.randomUUID()}`,
    createdAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    sourceType: "url",
    file: {
      originalName: finalUrl || normalizedUrl,
      extension: "(url)",
      size: Number(byteLength) || 0,
      sizeDisplay: humanFileSize(Number(byteLength) || 0),
      declaredMimeType: "text/url",
      detectedMimeType: contentType || "unknown",
      detectedFileType: "url",
      magicType: "URL target",
      entropy: 0,
      printableRatio: 1,
      hashes
    },
    url: {
      input: inputUrl,
      normalized: normalizedUrl,
      final: finalUrl || normalizedUrl,
      protocol: finalParsed.protocol.replace(/:$/, ""),
      hostname: finalParsed.hostname
    }
  };
}

export async function scanTargetUrl({ url, runtimeConfig = config, fileScanner = null }) {
  const { inputUrl, normalizedUrl, parsed, unicodeHostname, asciiHostname } = normalizeUrlInput(url);
  const findings = [];
  const matchedRules = [];
  let riskScore = 0;

  const addFinding = (ruleId, severity, category, weight, title, description, evidence) => {
    if (!matchedRules.includes(ruleId)) {
      matchedRules.push(ruleId);
    }

    findings.push(finding(severity, ruleId, category, weight, title, description, evidence));
    riskScore += Number(weight) || 0;
  };

  if (parsed.protocol !== "https:") {
    addFinding(
      "url_insecure_http",
      "medium",
      "Transport",
      16,
      "Insecure HTTP transport",
      "The target uses HTTP without TLS encryption.",
      parsed.protocol
    );
  }

  if (net.isIP(parsed.hostname) !== 0) {
    addFinding(
      "url_ip_literal",
      "high",
      "Domain",
      24,
      "IP-literal host",
      "The URL uses a direct IP address instead of a domain name, which is common in phishing and malware delivery.",
      parsed.hostname
    );
  }

  if (asciiHostname.includes("xn--") || unicodeHostname !== asciiHostname) {
    addFinding(
      "url_punycode_domain",
      "high",
      "Domain",
      22,
      "Punycode/IDN domain detected",
      "Internationalized/Punycode domains can be abused for look-alike phishing pages.",
      `${unicodeHostname} -> ${asciiHostname}`
    );
  }

  if (normalizedUrl.length > 180) {
    addFinding(
      "url_overly_long",
      "medium",
      "URL Structure",
      10,
      "Overly long URL",
      "Very long URLs can be used to hide suspicious path/query components.",
      `${normalizedUrl.length} characters`
    );
  }

  const subdomainCount = countSubdomains(parsed.hostname);
  if (subdomainCount >= 4) {
    addFinding(
      "url_excessive_subdomains",
      "medium",
      "URL Structure",
      10,
      "Excessive subdomain depth",
      "High subdomain depth can indicate deceptive URL construction.",
      `${subdomainCount} subdomains`
    );
  }

  const tld = parsed.hostname.split(".").pop()?.toLowerCase() || "";
  if (SUSPICIOUS_TLDS.has(tld)) {
    addFinding(
      "url_high_risk_tld",
      "medium",
      "Domain",
      12,
      "High-risk top-level domain",
      "This top-level domain is frequently observed in short-lived phishing campaigns.",
      tld
    );
  }

  const keywordMatches = countKeywordMatches(`${parsed.hostname}${parsed.pathname}${parsed.search}`);
  if (keywordMatches >= 2) {
    addFinding(
      "url_suspicious_keywords",
      "high",
      "Phishing",
      20,
      "Multiple phishing-style keywords",
      "The URL includes multiple words commonly used in credential theft pages.",
      `${keywordMatches} keyword matches`
    );
  } else if (keywordMatches === 1) {
    addFinding(
      "url_single_suspicious_keyword",
      "medium",
      "Phishing",
      10,
      "Suspicious keyword in URL",
      "The URL includes a keyword often seen in impersonation links.",
      "Single keyword match"
    );
  }

  const fetchResult = await fetchWithSafeRedirects(normalizedUrl, runtimeConfig);
  const finalUrl = fetchResult.finalUrl || normalizedUrl;
  const bodySnippet = fetchResult.bodySnippet || "";
  const contentType = fetchResult.contentType || "unknown";
  const title = extractTitleFromHtml(bodySnippet);
  const contentDisposition = fetchResult.contentDisposition || "";

  if (fetchResult.status === "blocked") {
    addFinding(
      "url_ssrf_blocked",
      "critical",
      "SSRF Protection",
      42,
      "Target blocked by SSRF safety guard",
      getBlockedReasonText(fetchResult.blockedReason),
      finalUrl
    );
  } else if (fetchResult.status === "error") {
    addFinding(
      "url_fetch_error",
      "medium",
      "Availability",
      12,
      "Unable to retrieve target content",
      getBlockedReasonText(fetchResult.blockedReason),
      finalUrl
    );
  }

  if ((fetchResult.redirects || []).length >= 3) {
    addFinding(
      "url_excessive_redirects",
      "medium",
      "Navigation",
      12,
      "Extended redirect chain",
      "Long redirect chains can be used to conceal final destination.",
      `${fetchResult.redirects.length} redirects`
    );
  }

  const crossDomainRedirect = (fetchResult.redirects || []).some((hop) => {
    try {
      return new URL(hop.from).hostname !== new URL(hop.to).hostname;
    } catch {
      return false;
    }
  });

  if (crossDomainRedirect) {
    addFinding(
      "url_cross_domain_redirect",
      "medium",
      "Navigation",
      14,
      "Cross-domain redirect detected",
      "The link redirected to a different hostname during retrieval.",
      finalUrl
    );
  }

  if (Number(fetchResult.statusCode) >= 400) {
    addFinding(
      "url_http_error_status",
      "medium",
      "HTTP",
      12,
      "HTTP error status observed",
      "The target returned an error response, which can indicate takedown, blocking, or unstable scam infrastructure.",
      String(fetchResult.statusCode)
    );
  }

  if (/<input[^>]+type=["']?password["']?/i.test(bodySnippet)) {
    addFinding(
      "url_password_form_detected",
      keywordMatches > 0 ? "high" : "medium",
      "Credential Harvesting",
      keywordMatches > 0 ? 22 : 14,
      "Password input field detected",
      "The page contains a password form. Confirm this destination belongs to the official organization before authentication.",
      title || finalUrl
    );
  }

  if (SCRIPT_OBFUSCATION_PATTERN.test(bodySnippet)) {
    addFinding(
      "url_obfuscated_script_indicators",
      "medium",
      "Script",
      14,
      "Obfuscated script indicators",
      "The page content includes script patterns commonly used to hide behavior.",
      "eval/fromCharCode/atob/function markers"
    );
  }

  if (PHISHING_TEXT_PATTERNS.some((pattern) => pattern.test(bodySnippet))) {
    addFinding(
      "url_phishing_language",
      "medium",
      "Phishing",
      14,
      "Phishing-style language detected",
      "The page uses urgent account-verification language commonly seen in scam pages.",
      title || finalUrl
    );
  }

  const tlsMeta = await checkTlsMetadata(finalUrl, runtimeConfig);
  if (tlsMeta.status === "completed") {
    if (tlsMeta.certSelfSigned) {
      addFinding(
        "url_tls_self_signed",
        "high",
        "TLS",
        20,
        "Self-signed TLS certificate",
        "The HTTPS certificate appears self-signed and should be treated with caution.",
        tlsMeta.certIssuer || finalUrl
      );
    }

    if (tlsMeta.certExpired) {
      addFinding(
        "url_tls_certificate_expired",
        "high",
        "TLS",
        18,
        "Expired TLS certificate",
        "The HTTPS certificate is expired.",
        tlsMeta.certValidTo || "expired certificate"
      );
    } else if (Number(tlsMeta.certDaysRemaining) >= 0 && Number(tlsMeta.certDaysRemaining) <= 14) {
      addFinding(
        "url_tls_certificate_expiring",
        "low",
        "TLS",
        6,
        "TLS certificate expiring soon",
        "The HTTPS certificate is nearing expiration.",
        `${tlsMeta.certDaysRemaining} days remaining`
      );
    }
  }

  const reputation = await getUrlReputationSnapshot({
    url: finalUrl,
    config: runtimeConfig
  });

  if (reputation.flagged) {
    addFinding(
      "url_reputation_flagged",
      "high",
      "Threat Intel",
      28,
      "External reputation providers flagged this URL",
      "One or more threat-intel providers marked this URL as risky.",
      reputation.flaggedProviders.join(", ")
    );
  }

  const browserRender = await runOptionalBrowserRender(finalUrl, runtimeConfig);
  if (browserRender.status === "completed" && browserRender.hasPasswordField && keywordMatches > 0) {
    addFinding(
      "url_browser_credential_prompt",
      "high",
      "Browser Analysis",
      16,
      "Rendered page prompts for credentials",
      "Headless browser rendering detected a password field on a keyword-heavy URL.",
      browserRender.title || finalUrl
    );
  }

  let downloadInspection = {
    status: "skipped",
    reason: "not_a_download_response"
  };

  if (runtimeConfig.urlScanEnableDownloadInspection && fetchResult.status === "ok") {
    const inspectAsDownload = shouldInspectAsDownload({
      contentType,
      contentDisposition,
      finalUrl
    });

    if (inspectAsDownload) {
      if (!fileScanner || typeof fileScanner !== "function") {
        downloadInspection = {
          status: "unavailable",
          reason: "file_scanner_unavailable"
        };
      } else if (!fetchResult.bodyBuffer || fetchResult.bodyBuffer.length === 0) {
        downloadInspection = {
          status: "unavailable",
          reason: "download_buffer_empty"
        };
      } else {
        const maxDownloadBytes = Number(runtimeConfig.urlScanMaxDownloadBytes) || 5 * 1024 * 1024;
        const downloadBuffer = fetchResult.bodyBuffer.subarray(0, Math.min(fetchResult.bodyBuffer.length, maxDownloadBytes));
        const parsedFinalUrl = new URL(finalUrl);
        const extension = path.extname(parsedFinalUrl.pathname || "").slice(0, 12);
        const inferredName =
          parseContentDispositionFilename(contentDisposition) ||
          `downloaded-artifact${extension || ".bin"}`.replace(/[^a-zA-Z0-9._-]+/g, "_");
        const tempFilePath = path.join(os.tmpdir(), `virovanta-link-artifact-${crypto.randomUUID()}${extension || ".bin"}`);

        try {
          await fs.writeFile(tempFilePath, downloadBuffer);
          const fileReport = await fileScanner({
            filePath: tempFilePath,
            originalName: inferredName,
            declaredMimeType: contentType
          });

          downloadInspection = {
            status: "completed",
            verdict: fileReport?.verdict || "clean",
            riskScore: Number(fileReport?.riskScore) || 0,
            findingCount: Array.isArray(fileReport?.findings) ? fileReport.findings.length : 0,
            fileName: inferredName
          };

          if (fileReport?.verdict === "malicious") {
            addFinding(
              "url_download_artifact_malicious",
              "critical",
              "Download Artifact",
              34,
              "Downloaded artifact appears malicious",
              "The downloaded file from this URL was scanned and marked malicious.",
              inferredName
            );
          } else if (fileReport?.verdict === "suspicious") {
            addFinding(
              "url_download_artifact_suspicious",
              "high",
              "Download Artifact",
              20,
              "Downloaded artifact appears suspicious",
              "The downloaded file from this URL triggered suspicious indicators.",
              inferredName
            );
          }
        } catch {
          downloadInspection = {
            status: "error",
            reason: "artifact_scan_failed"
          };
        } finally {
          await fs.unlink(tempFilePath).catch(() => {});
        }
      }
    }
  }

  const boundedRiskScore = Math.max(0, Math.min(100, Math.round(riskScore)));
  const sortedFindings = sortFindings(findings);
  const verdict = determineVerdict(boundedRiskScore, sortedFindings);

  const reportBase = buildUrlReportBase({
    inputUrl,
    normalizedUrl,
    finalUrl,
    contentType,
    byteLength: fetchResult.byteLength || 0
  });

  const plainLanguageReasons = sortedFindings.length
    ? sortedFindings.slice(0, 5).map((entry) => entry.description)
    : ["No high-risk indicators were detected in this URL scan."];

  const technicalIndicators = {
    redirectCount: (fetchResult.redirects || []).length,
    resolvedAddresses: fetchResult.resolvedAddresses || [],
    statusCode: fetchResult.statusCode || null,
    contentType,
    tls: tlsMeta,
    reputation,
    browserRender,
    downloadInspection
  };

  return {
    ...reportBase,
    verdict,
    riskScore: boundedRiskScore,
    findings: sortedFindings,
    plainLanguageReasons,
    technicalIndicators,
    engines: {
      heuristics: {
        status: "completed",
        matchedRules,
        findingCount: sortedFindings.length
      },
      urlFetch: {
        status: fetchResult.status,
        detail:
          fetchResult.status === "ok"
            ? "URL fetched successfully."
            : fetchResult.status === "blocked"
              ? getBlockedReasonText(fetchResult.blockedReason)
              : "URL retrieval failed.",
        statusCode: fetchResult.statusCode || null,
        finalUrl,
        redirects: fetchResult.redirects || [],
        truncated: Boolean(fetchResult.truncated)
      },
      ssrfGuard: {
        status: fetchResult.status === "blocked" ? "blocked" : "passed",
        blockedReason: fetchResult.blockedReason || null,
        resolvedAddresses: fetchResult.resolvedAddresses || []
      },
      tls: tlsMeta,
      reputation,
      browserRender,
      downloadInspection
    },
    recommendations: buildRecommendations({
      verdict,
      blockedReason: fetchResult.blockedReason || null,
      redirects: fetchResult.redirects || [],
      statusCode: fetchResult.statusCode || null
    }),
    url: {
      ...reportBase.url,
      unicodeHostname,
      asciiHostname,
      statusCode: fetchResult.statusCode || null,
      contentType,
      contentDisposition: contentDisposition || null,
      title,
      redirects: fetchResult.redirects || [],
      resolvedAddresses: fetchResult.resolvedAddresses || [],
      truncated: Boolean(fetchResult.truncated)
    }
  };
}
