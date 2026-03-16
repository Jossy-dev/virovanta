import { spawn } from "child_process";
import crypto from "crypto";
import fs from "fs";
import fsp from "fs/promises";
import os from "os";
import path from "path";
import { fileTypeFromFile } from "file-type";
import { simpleParser } from "mailparser";
import { config } from "../config.js";
import { scanTargetUrl } from "./urlScanner.js";

const MAX_SAMPLE_BYTES = 1024 * 1024;
const MAX_STRINGS = 500;
const MAX_EMAIL_URL_SCANS = 12;
const MAX_EMAIL_ATTACHMENT_SCANS = 6;
const MAX_EMAIL_ATTACHMENT_BYTES = 8 * 1024 * 1024;
const MAX_EMAIL_SCAN_DEPTH = 1;
const EMAIL_URL_REGEX = /\bhttps?:\/\/[^\s<>"'`]+/gi;
const EMAIL_AUTH_FAIL_STATES = new Set(["fail", "softfail", "temperror", "permerror"]);
const EMAIL_AUTH_PASS_STATES = new Set(["pass", "bestguesspass"]);
const EMAIL_AUTH_NONE_STATES = new Set(["none", "neutral"]);

const HIGH_RISK_EXTENSIONS = new Map([
  [".exe", "Windows executable"],
  [".dll", "Windows dynamic library"],
  [".scr", "Windows screen saver executable"],
  [".bat", "Batch script"],
  [".cmd", "Command script"],
  [".ps1", "PowerShell script"],
  [".js", "JavaScript file"],
  [".jse", "Encoded JavaScript file"],
  [".vbs", "VBScript file"],
  [".msi", "Windows installer package"],
  [".jar", "Java archive"],
  [".com", "DOS executable"],
  [".lnk", "Windows shortcut"],
  [".hta", "HTML application"],
  [".apk", "Android package"],
  [".sh", "Shell script"],
  [".iso", "Disk image"],
  [".elf", "ELF executable"],
  [".dylib", "Dynamic library"],
  [".so", "Shared object file"]
]);

const ARCHIVE_EXTENSIONS = new Set([".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".jar"]);

const DOCUMENT_EXTENSIONS = new Set([
  ".pdf",
  ".doc",
  ".docx",
  ".xls",
  ".xlsx",
  ".ppt",
  ".pptx",
  ".txt",
  ".rtf",
  ".jpg",
  ".jpeg",
  ".png",
  ".gif",
  ".svg"
]);

const PATTERN_RULES = [
  {
    id: "encoded_powershell",
    severity: "critical",
    category: "Execution",
    weight: 36,
    title: "Encoded PowerShell execution pattern",
    description: "Detected encoded PowerShell syntax commonly used for payload downloaders.",
    regex: /powershell(?:\.exe)?\s+-{1,2}(?:enc|encodedcommand)\b/i
  },
  {
    id: "invoke_expression",
    severity: "high",
    category: "Execution",
    weight: 24,
    title: "Dynamic script execution keyword",
    description: "Detected Invoke-Expression / IEX style dynamic execution markers.",
    regex: /(?:\bInvoke-Expression\b|\bIEX\b)/i
  },
  {
    id: "living_off_the_land",
    severity: "high",
    category: "Execution",
    weight: 24,
    title: "Living-off-the-land utilities",
    description: "Detected utilities often abused by malware for defense evasion and command execution.",
    regex: /(?:\bmshta\b|\brundll32\b|\bregsvr32\b|\bcertutil\b|\bbitsadmin\b)/i
  },
  {
    id: "obfuscated_javascript",
    severity: "medium",
    category: "Obfuscation",
    weight: 16,
    title: "Hidden JavaScript code pattern",
    description: "The file contains JavaScript written in a hidden/scrambled way, which attackers often use to conceal harmful behavior.",
    regex: /(?:eval\(|fromCharCode|atob\(|unescape\(|Function\s*\()/i
  },
  {
    id: "ransomware_commands",
    severity: "critical",
    category: "Impact",
    weight: 38,
    title: "Ransomware command pattern",
    description: "Detected commands associated with ransomware pre-encryption preparation.",
    regex: /(?:vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog|bcdedit\s+\/set\s+\{default\}\s+recoveryenabled\s+no)/i
  },
  {
    id: "crypto_miner",
    severity: "high",
    category: "Resource Abuse",
    weight: 24,
    title: "Cryptominer pattern",
    description: "Detected mining pool / miner keywords associated with cryptojacking payloads.",
    regex: /(?:xmrig|stratum\+tcp|coinhive)/i
  },
  {
    id: "long_base64_blob",
    severity: "medium",
    category: "Obfuscation",
    weight: 12,
    title: "Long base64 blob",
    description: "Large encoded strings can indicate packed or obfuscated payloads.",
    regex: /[A-Za-z0-9+/]{420,}={0,2}/
  }
];

const SEVERITY_SCORE = {
  critical: 38,
  high: 24,
  medium: 14,
  low: 6,
  info: 0
};

const SEVERITY_ORDER = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

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

function sanitizeFileName(name) {
  if (typeof name !== "string") {
    return "uploaded-file";
  }

  const normalized = name.trim().replace(/\s+/g, " ");
  if (!normalized) {
    return "uploaded-file";
  }

  return path.basename(normalized).slice(0, 180);
}

function calculateEntropy(buffer) {
  if (!buffer || buffer.length === 0) {
    return 0;
  }

  const frequencies = new Array(256).fill(0);
  for (const byte of buffer) {
    frequencies[byte] += 1;
  }

  let entropy = 0;
  const total = buffer.length;

  for (const frequency of frequencies) {
    if (!frequency) {
      continue;
    }

    const probability = frequency / total;
    entropy -= probability * Math.log2(probability);
  }

  return Number(entropy.toFixed(3));
}

function calculatePrintableRatio(buffer) {
  if (!buffer || buffer.length === 0) {
    return 0;
  }

  let printable = 0;

  for (const byte of buffer) {
    const isPrintableAscii = byte >= 32 && byte <= 126;
    const isWhitespace = byte === 9 || byte === 10 || byte === 13;

    if (isPrintableAscii || isWhitespace) {
      printable += 1;
    }
  }

  return Number((printable / buffer.length).toFixed(3));
}

function extractAsciiStrings(buffer, minimumLength = 6, maxStrings = MAX_STRINGS) {
  const strings = [];
  let current = "";

  for (const byte of buffer) {
    if (byte >= 32 && byte <= 126) {
      current += String.fromCharCode(byte);
      continue;
    }

    if (current.length >= minimumLength) {
      strings.push(current);
      if (strings.length >= maxStrings) {
        return strings;
      }
    }

    current = "";
  }

  if (current.length >= minimumLength && strings.length < maxStrings) {
    strings.push(current);
  }

  return strings;
}

function detectMagicType(sample) {
  if (!sample || sample.length < 4) {
    return null;
  }

  if (sample[0] === 0x4d && sample[1] === 0x5a) {
    return "Portable Executable (PE)";
  }

  if (sample[0] === 0x7f && sample[1] === 0x45 && sample[2] === 0x4c && sample[3] === 0x46) {
    return "ELF executable";
  }

  if (sample[0] === 0xcf && sample[1] === 0xfa && sample[2] === 0xed && sample[3] === 0xfe) {
    return "Mach-O 64-bit";
  }

  if (sample[0] === 0xfe && sample[1] === 0xed && sample[2] === 0xfa && sample[3] === 0xcf) {
    return "Mach-O 32-bit";
  }

  if (sample[0] === 0x50 && sample[1] === 0x4b && sample[2] === 0x03 && sample[3] === 0x04) {
    return "ZIP archive";
  }

  if (sample.toString("utf8", 0, 5) === "%PDF-") {
    return "PDF document";
  }

  if (sample[0] === 0x23 && sample[1] === 0x21) {
    return "Script with shebang";
  }

  return null;
}

function hasDoubleExtension(fileName) {
  const normalized = fileName.toLowerCase();
  return /\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|jpg|jpeg|png|gif)\.(exe|scr|js|vbs|bat|cmd|ps1|jar|com|hta)$/.test(
    normalized
  );
}

function normalizeHeaderValue(value) {
  if (value == null) {
    return [];
  }

  if (Array.isArray(value)) {
    return value.flatMap((entry) => normalizeHeaderValue(entry));
  }

  if (typeof value === "string") {
    return [value];
  }

  if (Buffer.isBuffer(value)) {
    return [value.toString("utf8")];
  }

  if (typeof value === "object") {
    if (typeof value.value === "string") {
      return [value.value];
    }

    if (typeof value.text === "string") {
      return [value.text];
    }

    if (typeof value.line === "string") {
      return [value.line];
    }
  }

  return [String(value)];
}

function getHeaderValues(parsedEmail, headerName) {
  const normalizedName = String(headerName || "").trim().toLowerCase();
  if (!normalizedName || !parsedEmail) {
    return [];
  }

  const fromHeaderLines = (parsedEmail.headerLines || [])
    .filter((entry) => String(entry?.key || "").toLowerCase() === normalizedName)
    .map((entry) => String(entry?.line || "").replace(/^[^:]+:\s*/i, "").trim())
    .filter(Boolean);

  let fromHeaderMap = [];
  if (parsedEmail.headers && typeof parsedEmail.headers.get === "function") {
    fromHeaderMap = normalizeHeaderValue(parsedEmail.headers.get(normalizedName));
  }

  return [...fromHeaderLines, ...fromHeaderMap]
    .map((value) => String(value || "").trim())
    .filter(Boolean);
}

function getPrimaryAddress(addressObject) {
  const addressList = Array.isArray(addressObject?.value) ? addressObject.value : [];
  const primary = addressList[0]?.address;
  return String(primary || "").trim().toLowerCase();
}

function getAddressDomain(address) {
  const normalized = String(address || "").trim().toLowerCase();
  if (!normalized.includes("@")) {
    return "";
  }

  return normalized.split("@").pop() || "";
}

function normalizeEmailAuthOutcome(rawStatus) {
  const normalized = String(rawStatus || "").trim().toLowerCase();
  if (!normalized) {
    return "unknown";
  }

  if (EMAIL_AUTH_PASS_STATES.has(normalized)) {
    return "pass";
  }

  if (EMAIL_AUTH_FAIL_STATES.has(normalized)) {
    return "fail";
  }

  if (EMAIL_AUTH_NONE_STATES.has(normalized)) {
    return "none";
  }

  return "unknown";
}

function parseAuthenticationResult(authValues, mechanism) {
  const pattern = new RegExp(`\\b${mechanism}=([a-z_]+)\\b`, "i");

  for (const value of authValues) {
    const match = String(value || "").match(pattern);
    if (match?.[1]) {
      const raw = match[1].toLowerCase();
      return {
        raw,
        status: normalizeEmailAuthOutcome(raw)
      };
    }
  }

  return {
    raw: null,
    status: "unknown"
  };
}

function parseReceivedSpfResult(receivedSpfValues) {
  const pattern = /\b(pass|fail|softfail|neutral|none|temperror|permerror)\b/i;

  for (const value of receivedSpfValues) {
    const match = String(value || "").match(pattern);
    if (match?.[1]) {
      const raw = match[1].toLowerCase();
      return {
        raw,
        status: normalizeEmailAuthOutcome(raw)
      };
    }
  }

  return {
    raw: null,
    status: "unknown"
  };
}

function evaluateEmailAuthentication({ authValues, receivedSpfValues }) {
  const spf = parseAuthenticationResult(authValues, "spf");
  const dkim = parseAuthenticationResult(authValues, "dkim");
  const dmarc = parseAuthenticationResult(authValues, "dmarc");

  if (spf.status === "unknown") {
    const receivedSpf = parseReceivedSpfResult(receivedSpfValues);
    if (receivedSpf.status !== "unknown") {
      return {
        spf: receivedSpf,
        dkim,
        dmarc
      };
    }
  }

  return {
    spf,
    dkim,
    dmarc
  };
}

function normalizeExtractedUrl(urlValue) {
  const trimmed = String(urlValue || "").trim();
  if (!trimmed) {
    return null;
  }

  const cleaned = trimmed.replace(/[),.;!?'"`]+$/g, "");
  if (!/^https?:\/\//i.test(cleaned)) {
    return null;
  }

  return cleaned.slice(0, 2048);
}

function extractUrlsFromEmail(parsedEmail) {
  const textCorpus = [
    typeof parsedEmail?.subject === "string" ? parsedEmail.subject : "",
    typeof parsedEmail?.text === "string" ? parsedEmail.text : "",
    typeof parsedEmail?.html === "string" ? parsedEmail.html : ""
  ]
    .filter(Boolean)
    .join("\n");

  const urls = new Set();
  for (const match of textCorpus.matchAll(EMAIL_URL_REGEX)) {
    const value = normalizeExtractedUrl(match[0]);
    if (value) {
      urls.add(value);
    }
  }

  return [...urls];
}

function buildFlaggedUrlEvidence({ flaggedLinks, flaggedCount, scannedCount }) {
  const base = `${flaggedCount}/${scannedCount} scanned links`;
  if (!Array.isArray(flaggedLinks) || flaggedLinks.length === 0) {
    return base;
  }

  const visibleLinks = flaggedLinks
    .slice(0, 3)
    .map((entry) => String(entry?.url || "").slice(0, 160))
    .filter(Boolean);

  if (visibleLinks.length === 0) {
    return base;
  }

  const remaining = Math.max(0, flaggedCount - visibleLinks.length);
  return `${base} | ${visibleLinks.join(" | ")}${remaining > 0 ? ` (+${remaining} more)` : ""}`;
}

function buildEmailUrlScanConfig(runtimeConfig = config) {
  const timeoutMs = Number(runtimeConfig.urlScanTimeoutMs) || 12_000;
  const maxRedirects = Number(runtimeConfig.urlScanMaxRedirects) || 4;
  const maxBodyBytes = Number(runtimeConfig.urlScanMaxBodyBytes) || 200_000;

  return {
    ...runtimeConfig,
    urlScanTimeoutMs: Math.min(timeoutMs, 8_000),
    urlScanMaxRedirects: Math.min(maxRedirects, 3),
    urlScanMaxBodyBytes: Math.min(maxBodyBytes, 120_000),
    urlScanEnableBrowserRender: false,
    urlScanEnableDownloadInspection: false
  };
}

function isEmailMimeType(mimeType) {
  const normalized = String(mimeType || "").trim().toLowerCase();
  if (!normalized) {
    return false;
  }

  return normalized.includes("message/rfc822") || normalized.includes("application/eml");
}

function sanitizeAttachmentFileName(name, index) {
  const fallback = `attachment-${index + 1}.bin`;
  const safeName = sanitizeFileName(name || fallback);
  if (!path.extname(safeName)) {
    return `${safeName}.bin`;
  }

  return safeName;
}

async function analyzeEmailFile({ filePath, scanDepth }) {
  if (scanDepth >= MAX_EMAIL_SCAN_DEPTH) {
    return {
      findings: [],
      engine: {
        status: "skipped",
        reason: "max_email_depth_reached",
        maxDepth: MAX_EMAIL_SCAN_DEPTH
      }
    };
  }

  let parsedEmail;
  try {
    const rawEmail = await fsp.readFile(filePath);
    parsedEmail = await simpleParser(rawEmail);
  } catch (error) {
    return {
      findings: [],
      engine: {
        status: "error",
        reason: "email_parse_failed",
        detail: error?.message || "Could not parse .eml content."
      }
    };
  }

  const findings = [];
  const fromAddress = getPrimaryAddress(parsedEmail.from);
  const replyToAddress = getPrimaryAddress(parsedEmail.replyTo);
  const fromDomain = getAddressDomain(fromAddress);
  const replyToDomain = getAddressDomain(replyToAddress);
  const senderMismatch = Boolean(fromDomain && replyToDomain && fromDomain !== replyToDomain);

  if (senderMismatch) {
    findings.push({
      id: "email_reply_to_mismatch",
      severity: "high",
      category: "Email Sender",
      weight: 24,
      title: "Sender and reply address mismatch",
      description: "The email asks replies to a different domain than the sender, a common phishing signal.",
      evidence: `${fromAddress} -> ${replyToAddress}`
    });
  }

  const authValues = [
    ...getHeaderValues(parsedEmail, "authentication-results"),
    ...getHeaderValues(parsedEmail, "arc-authentication-results")
  ];
  const receivedSpfValues = getHeaderValues(parsedEmail, "received-spf");
  const authentication = evaluateEmailAuthentication({
    authValues,
    receivedSpfValues
  });

  const authChecks = [
    {
      key: "spf",
      label: "SPF",
      failTitle: "SPF authentication failed",
      noneTitle: "SPF authentication missing",
      failDescription: "The sender domain did not pass SPF checks in this email.",
      noneDescription: "No SPF pass was recorded. Treat this email with added caution."
    },
    {
      key: "dkim",
      label: "DKIM",
      failTitle: "DKIM signature validation failed",
      noneTitle: "DKIM signature missing",
      failDescription: "DKIM verification did not pass, so message integrity could not be trusted.",
      noneDescription: "No DKIM pass was recorded for this email."
    },
    {
      key: "dmarc",
      label: "DMARC",
      failTitle: "DMARC policy check failed",
      noneTitle: "DMARC policy result missing",
      failDescription: "DMARC did not pass, which is a strong impersonation risk signal.",
      noneDescription: "No DMARC pass was recorded for this email."
    }
  ];

  for (const check of authChecks) {
    const result = authentication[check.key];
    if (result.status === "fail") {
      findings.push({
        id: `email_${check.key}_failed`,
        severity: "high",
        category: "Email Authentication",
        weight: 20,
        title: check.failTitle,
        description: check.failDescription,
        evidence: result.raw ? `${check.label}=${result.raw}` : check.label
      });
    } else if (result.status === "none") {
      findings.push({
        id: `email_${check.key}_missing`,
        severity: "low",
        category: "Email Authentication",
        weight: 6,
        title: check.noneTitle,
        description: check.noneDescription,
        evidence: check.label
      });
    }
  }

  const extractedUrls = extractUrlsFromEmail(parsedEmail);
  const urlsToScan = extractedUrls.slice(0, MAX_EMAIL_URL_SCANS);
  const urlScanResults = [];
  let maliciousUrlCount = 0;
  let suspiciousUrlCount = 0;
  const emailUrlScanConfig = buildEmailUrlScanConfig(config);

  for (const extractedUrl of urlsToScan) {
    try {
      const urlReport = await scanTargetUrl({
        url: extractedUrl,
        runtimeConfig: emailUrlScanConfig,
        fileScanner: null
      });

      const verdict = String(urlReport?.verdict || "clean").toLowerCase();
      if (verdict === "malicious") {
        maliciousUrlCount += 1;
      } else if (verdict === "suspicious") {
        suspiciousUrlCount += 1;
      }

      urlScanResults.push({
        url: urlReport?.url?.final || urlReport?.url?.normalized || extractedUrl,
        status: "completed",
        verdict,
        riskScore: Number(urlReport?.riskScore) || 0,
        findingCount: Array.isArray(urlReport?.findings) ? urlReport.findings.length : 0
      });
    } catch (error) {
      urlScanResults.push({
        url: extractedUrl,
        status: "error",
        error: error?.message || "URL scan failed."
      });
    }
  }

  const maliciousLinks = urlScanResults.filter(
    (entry) => entry.status === "completed" && entry.verdict === "malicious"
  );
  const suspiciousLinks = urlScanResults.filter(
    (entry) => entry.status === "completed" && entry.verdict === "suspicious"
  );

  if (maliciousUrlCount > 0) {
    findings.push({
      id: "email_embedded_links_malicious",
      severity: "critical",
      category: "Embedded Links",
      weight: 34,
      title: "Embedded link flagged malicious",
      description: "At least one URL inside the email was classified as malicious.",
      evidence: buildFlaggedUrlEvidence({
        flaggedLinks: maliciousLinks,
        flaggedCount: maliciousUrlCount,
        scannedCount: urlsToScan.length
      })
    });
  } else if (suspiciousUrlCount > 0) {
    findings.push({
      id: "email_embedded_links_suspicious",
      severity: "high",
      category: "Embedded Links",
      weight: 20,
      title: "Embedded link flagged suspicious",
      description: "One or more URLs inside the email were classified as suspicious.",
      evidence: buildFlaggedUrlEvidence({
        flaggedLinks: suspiciousLinks,
        flaggedCount: suspiciousUrlCount,
        scannedCount: urlsToScan.length
      })
    });
  }

  const attachments = Array.isArray(parsedEmail.attachments) ? parsedEmail.attachments : [];
  const attachmentsToScan = attachments.slice(0, MAX_EMAIL_ATTACHMENT_SCANS);
  const attachmentResults = [];
  const skippedAttachments = [];
  let maliciousAttachmentCount = 0;
  let suspiciousAttachmentCount = 0;

  if (attachments.length > MAX_EMAIL_ATTACHMENT_SCANS) {
    attachments
      .slice(MAX_EMAIL_ATTACHMENT_SCANS)
      .forEach((attachment, index) => {
        skippedAttachments.push({
          name: sanitizeAttachmentFileName(attachment?.filename, MAX_EMAIL_ATTACHMENT_SCANS + index),
          reason: "attachment_scan_limit_reached"
        });
      });
  }

  for (let index = 0; index < attachmentsToScan.length; index += 1) {
    const attachment = attachmentsToScan[index];
    const name = sanitizeAttachmentFileName(attachment?.filename, index);
    const contentType = String(attachment?.contentType || "application/octet-stream");
    const contentBuffer = Buffer.isBuffer(attachment?.content)
      ? attachment.content
      : Buffer.from(attachment?.content || "");

    if (contentBuffer.length === 0) {
      skippedAttachments.push({
        name,
        reason: "attachment_empty"
      });
      continue;
    }

    if (contentBuffer.length > MAX_EMAIL_ATTACHMENT_BYTES) {
      skippedAttachments.push({
        name,
        reason: "attachment_too_large",
        size: contentBuffer.length
      });
      continue;
    }

    const extension = path.extname(name).slice(0, 12) || ".bin";
    const tempPath = path.join(os.tmpdir(), `virovanta-email-attachment-${crypto.randomUUID()}${extension}`);

    try {
      await fsp.writeFile(tempPath, contentBuffer);
      const nestedReport = await scanUploadedFile({
        filePath: tempPath,
        originalName: name,
        declaredMimeType: contentType,
        scanDepth: scanDepth + 1
      });

      const verdict = String(nestedReport?.verdict || "clean").toLowerCase();
      if (verdict === "malicious") {
        maliciousAttachmentCount += 1;
      } else if (verdict === "suspicious") {
        suspiciousAttachmentCount += 1;
      }

      attachmentResults.push({
        name,
        status: "completed",
        contentType,
        size: contentBuffer.length,
        sizeDisplay: humanFileSize(contentBuffer.length),
        verdict,
        riskScore: Number(nestedReport?.riskScore) || 0,
        findingCount: Array.isArray(nestedReport?.findings) ? nestedReport.findings.length : 0
      });
    } catch (error) {
      attachmentResults.push({
        name,
        status: "error",
        contentType,
        size: contentBuffer.length,
        sizeDisplay: humanFileSize(contentBuffer.length),
        error: error?.message || "Attachment scan failed."
      });
    } finally {
      await fsp.unlink(tempPath).catch(() => {});
    }
  }

  if (maliciousAttachmentCount > 0) {
    findings.push({
      id: "email_attachment_malicious",
      severity: "critical",
      category: "Attachments",
      weight: 36,
      title: "Attachment flagged malicious",
      description: "At least one attachment in this email was classified as malicious.",
      evidence: `${maliciousAttachmentCount}/${attachmentResults.length} scanned attachments`
    });
  } else if (suspiciousAttachmentCount > 0) {
    findings.push({
      id: "email_attachment_suspicious",
      severity: "high",
      category: "Attachments",
      weight: 22,
      title: "Attachment flagged suspicious",
      description: "One or more email attachments were classified as suspicious.",
      evidence: `${suspiciousAttachmentCount}/${attachmentResults.length} scanned attachments`
    });
  }

  return {
    findings,
    engine: {
      status: "completed",
      subject: String(parsedEmail?.subject || "").slice(0, 240) || null,
      sender: {
        from: fromAddress || null,
        replyTo: replyToAddress || null,
        mismatch: senderMismatch
      },
      authentication,
      urlScans: {
        totalExtracted: extractedUrls.length,
        scannedCount: urlScanResults.filter((entry) => entry.status === "completed").length,
        skippedCount: Math.max(0, extractedUrls.length - urlsToScan.length),
        highRisk: {
          malicious: maliciousLinks,
          suspicious: suspiciousLinks
        },
        items: urlScanResults
      },
      attachments: {
        total: attachments.length,
        scannedCount: attachmentResults.filter((entry) => entry.status === "completed").length,
        skippedCount: skippedAttachments.length,
        items: attachmentResults,
        skipped: skippedAttachments
      }
    }
  };
}

function runCommand(command, args, timeoutMs = 90_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";

    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      const timeoutError = new Error("Command timed out");
      timeoutError.name = "AbortError";
      reject(timeoutError);
    }, timeoutMs);

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });

    child.on("close", (code) => {
      clearTimeout(timeout);
      resolve({ code, stdout, stderr });
    });
  });
}

async function profileFile(filePath) {
  return new Promise((resolve, reject) => {
    const md5 = crypto.createHash("md5");
    const sha1 = crypto.createHash("sha1");
    const sha256 = crypto.createHash("sha256");

    const sampleChunks = [];
    let sampleBytes = 0;
    let totalBytes = 0;

    const stream = fs.createReadStream(filePath);

    stream.on("data", (chunk) => {
      md5.update(chunk);
      sha1.update(chunk);
      sha256.update(chunk);
      totalBytes += chunk.length;

      if (sampleBytes >= MAX_SAMPLE_BYTES) {
        return;
      }

      const remaining = MAX_SAMPLE_BYTES - sampleBytes;
      const sample = chunk.subarray(0, remaining);
      sampleChunks.push(sample);
      sampleBytes += sample.length;
    });

    stream.on("error", (error) => {
      reject(error);
    });

    stream.on("end", () => {
      resolve({
        size: totalBytes,
        sample: Buffer.concat(sampleChunks, sampleBytes),
        hashes: {
          md5: md5.digest("hex"),
          sha1: sha1.digest("hex"),
          sha256: sha256.digest("hex")
        }
      });
    });
  });
}

async function runClamAvScan(filePath) {
  if (!config.enableClamAv) {
    return {
      status: "disabled",
      detail: "ClamAV scanning disabled by configuration."
    };
  }

  try {
    const { code, stdout, stderr } = await runCommand(config.clamScanBinary, ["--no-summary", filePath]);
    const output = `${stdout}\n${stderr}`.trim();
    const infectedMatch = output.match(/:\s(.+)\sFOUND$/m);

    if (infectedMatch) {
      return {
        status: "infected",
        signature: infectedMatch[1],
        detail: "ClamAV detected known malware signature."
      };
    }

    if (code === 0) {
      return {
        status: "clean",
        detail: "ClamAV reported no known signatures."
      };
    }

    return {
      status: "error",
      detail: output || `ClamAV exited with code ${code}.`
    };
  } catch (error) {
    if (error?.code === "ENOENT") {
      return {
        status: "unavailable",
        detail: `Could not find \`${config.clamScanBinary}\` in PATH.`
      };
    }

    if (error?.name === "AbortError") {
      return {
        status: "timeout",
        detail: "ClamAV scan timed out."
      };
    }

    return {
      status: "error",
      detail: error?.message || "Unexpected ClamAV failure."
    };
  }
}

async function runVirusTotalLookup(sha256Hash) {
  if (!config.virusTotalApiKey) {
    return {
      status: "disabled",
      detail: "VirusTotal API key not configured."
    };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12_000);

  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/files/${sha256Hash}`, {
      method: "GET",
      headers: {
        "x-apikey": config.virusTotalApiKey,
        accept: "application/json"
      },
      signal: controller.signal
    });

    if (response.status === 404) {
      return {
        status: "not_found",
        detail: "Hash not present in VirusTotal corpus."
      };
    }

    if (!response.ok) {
      return {
        status: "error",
        detail: `VirusTotal HTTP ${response.status}.`
      };
    }

    const payload = await response.json();
    const attributes = payload?.data?.attributes ?? {};
    const stats = attributes.last_analysis_stats ?? {};

    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const harmless = Number(stats.harmless || 0);
    const undetected = Number(stats.undetected || 0);
    const threatLabel = attributes.popular_threat_classification?.suggested_threat_label || null;
    const categories = (attributes.popular_threat_classification?.popular_threat_category || [])
      .map((entry) => entry.value)
      .filter(Boolean)
      .slice(0, 4);

    return {
      status: "found",
      detail: "VirusTotal hash intelligence available.",
      permalink: `https://www.virustotal.com/gui/file/${sha256Hash}`,
      malicious,
      suspicious,
      harmless,
      undetected,
      threatLabel,
      categories
    };
  } catch (error) {
    if (error?.name === "AbortError") {
      return {
        status: "timeout",
        detail: "VirusTotal lookup timed out."
      };
    }

    return {
      status: "error",
      detail: error?.message || "VirusTotal lookup failed."
    };
  } finally {
    clearTimeout(timeout);
  }
}

function determineVerdict(riskScore, findings, engines) {
  if (engines.clamav.status === "infected") {
    return "malicious";
  }

  if (engines.virustotal.status === "found" && (engines.virustotal.malicious > 0 || engines.virustotal.suspicious > 0)) {
    return "malicious";
  }

  if (riskScore >= 75 || findings.some((finding) => finding.severity === "critical")) {
    return "malicious";
  }

  if (riskScore >= 40 || findings.some((finding) => finding.severity === "high")) {
    return "suspicious";
  }

  return "clean";
}

function buildRecommendations({ verdict, findings, engines, extension, entropy }) {
  const recommendations = [];

  if (verdict !== "clean") {
    recommendations.push("Quarantine the file and avoid opening it on production systems.");
    recommendations.push("Run the sample in an isolated sandbox VM before any manual inspection.");
  }

  if (findings.some((finding) => finding.category === "Obfuscation") || entropy >= 7.2) {
    recommendations.push("Perform deeper static analysis (YARA rules + string deobfuscation)." );
  }

  if (engines.clamav.status === "unavailable") {
    recommendations.push("Install ClamAV and keep definitions updated for stronger signature coverage.");
  }

  if (engines.virustotal.status === "disabled") {
    recommendations.push("Add a VirusTotal API key for external reputation intelligence by file hash.");
  }

  if (ARCHIVE_EXTENSIONS.has(extension)) {
    recommendations.push("Enable archive-unpacking scans in a sandbox to inspect embedded payloads.");
  }

  if (recommendations.length === 0) {
    recommendations.push("No high-risk indicators were detected; keep normal endpoint controls enabled.");
  }

  return recommendations;
}

function sortFindings(findings) {
  return [...findings].sort((left, right) => {
    const severityDelta = SEVERITY_ORDER[right.severity] - SEVERITY_ORDER[left.severity];

    if (severityDelta !== 0) {
      return severityDelta;
    }

    return left.title.localeCompare(right.title);
  });
}

function pushFinding(findings, finding) {
  findings.push(finding);
  return finding.weight || SEVERITY_SCORE[finding.severity] || 0;
}

export async function scanUploadedFile({ filePath, originalName, declaredMimeType, scanDepth = 0 }) {
  const startedAt = new Date();
  const safeOriginalName = sanitizeFileName(originalName);
  const extension = path.extname(safeOriginalName).toLowerCase();

  const [{ size, sample, hashes }, detectedType] = await Promise.all([
    profileFile(filePath),
    fileTypeFromFile(filePath).catch(() => null)
  ]);

  const entropy = calculateEntropy(sample);
  const printableRatio = calculatePrintableRatio(sample);
  const extractedStrings = extractAsciiStrings(sample);
  const sampleText = sample.toString("utf8");
  const magicType = detectMagicType(sample);
  const detectedMimeType = detectedType?.mime || "unknown";
  const isEmailFile = extension === ".eml" || isEmailMimeType(declaredMimeType) || isEmailMimeType(detectedMimeType);

  let riskScore = 0;
  const findings = [];
  const matchedRules = [];

  if (HIGH_RISK_EXTENSIONS.has(extension)) {
    riskScore += pushFinding(findings, {
      id: "high_risk_extension",
      severity: "high",
      category: "File Type",
      weight: 20,
      title: "High-risk executable/script extension",
      description: `${extension} is commonly associated with executable or script payloads.`,
      evidence: HIGH_RISK_EXTENSIONS.get(extension)
    });
  }

  if (hasDoubleExtension(safeOriginalName)) {
    riskScore += pushFinding(findings, {
      id: "double_extension",
      severity: "high",
      category: "Masquerading",
      weight: 26,
      title: "Potential masquerading via double extension",
      description: "File name uses a trusted extension followed by an executable/script extension.",
      evidence: safeOriginalName
    });
  }

  if (extension === ".docm" || extension === ".xlsm" || extension === ".pptm") {
    riskScore += pushFinding(findings, {
      id: "macro_enabled_document",
      severity: "medium",
      category: "File Type",
      weight: 14,
      title: "Macro-enabled Office document",
      description: "Macro-enabled Office formats are frequently abused for malware delivery.",
      evidence: extension
    });
  }

  if (entropy >= 7.3 && size > 65 * 1024) {
    riskScore += pushFinding(findings, {
      id: "high_entropy",
      severity: "medium",
      category: "Obfuscation",
      weight: 14,
      title: "High entropy sample",
      description: "High entropy suggests packed, encrypted, or obfuscated content.",
      evidence: `Entropy ${entropy}`
    });
  }

  const patternCorpus = `${sampleText}\n${extractedStrings.join("\n")}`.slice(0, 2_000_000);

  for (const rule of PATTERN_RULES) {
    const match = patternCorpus.match(rule.regex);

    if (!match) {
      continue;
    }

    matchedRules.push(rule.id);
    riskScore += pushFinding(findings, {
      id: rule.id,
      severity: rule.severity,
      category: rule.category,
      weight: rule.weight,
      title: rule.title,
      description: rule.description,
      evidence: match[0].slice(0, 160)
    });
  }

  if (magicType === "Portable Executable (PE)" && DOCUMENT_EXTENSIONS.has(extension)) {
    riskScore += pushFinding(findings, {
      id: "type_mismatch",
      severity: "critical",
      category: "Masquerading",
      weight: 34,
      title: "Executable content with document extension",
      description: "File header indicates executable content while file name appears document-like.",
      evidence: `${safeOriginalName} -> ${magicType}`
    });
  }

  if (magicType === null && printableRatio < 0.25 && size > 150 * 1024) {
    riskScore += pushFinding(findings, {
      id: "unknown_binary_payload",
      severity: "medium",
      category: "Binary",
      weight: 12,
      title: "Unknown binary payload",
      description: "Binary file has low textual content and no recognized signature.",
      evidence: `Printable ratio ${printableRatio}`
    });
  }

  let email = {
    status: "skipped",
    reason: "not_email_message"
  };

  if (isEmailFile) {
    const emailAnalysis = await analyzeEmailFile({
      filePath,
      scanDepth
    });
    email = emailAnalysis.engine;

    for (const finding of emailAnalysis.findings) {
      riskScore += pushFinding(findings, finding);
    }
  }

  const clamav = await runClamAvScan(filePath);
  if (clamav.status === "infected") {
    riskScore += pushFinding(findings, {
      id: "clamav_signature_match",
      severity: "critical",
      category: "Signature",
      weight: 40,
      title: "ClamAV signature hit",
      description: "ClamAV matched a known malware signature.",
      evidence: clamav.signature || "Unknown signature"
    });
  }

  const virustotal = await runVirusTotalLookup(hashes.sha256);
  if (virustotal.status === "found" && (virustotal.malicious > 0 || virustotal.suspicious > 0)) {
    const severity = virustotal.malicious > 2 ? "critical" : "high";

    riskScore += pushFinding(findings, {
      id: "virustotal_detections",
      severity,
      category: "Reputation",
      weight: virustotal.malicious > 2 ? 36 : 24,
      title: "VirusTotal detections",
      description: "External reputation engines reported suspicious or malicious detections.",
      evidence: `${virustotal.malicious} malicious / ${virustotal.suspicious} suspicious`
    });
  }

  const boundedRiskScore = Math.max(0, Math.min(100, Math.round(riskScore)));
  const sortedFindings = sortFindings(findings);

  const engines = {
    heuristics: {
      status: "completed",
      matchedRules,
      findingCount: sortedFindings.length
    },
    email,
    clamav,
    virustotal
  };

  const verdict = determineVerdict(boundedRiskScore, sortedFindings, engines);

  const report = {
    id: `scan_${crypto.randomUUID()}`,
    createdAt: startedAt.toISOString(),
    completedAt: new Date().toISOString(),
    verdict,
    riskScore: boundedRiskScore,
    file: {
      originalName: safeOriginalName,
      extension: extension || "(none)",
      size,
      sizeDisplay: humanFileSize(size),
      declaredMimeType: declaredMimeType || "unknown",
      detectedMimeType,
      detectedFileType: detectedType?.ext || "unknown",
      magicType: magicType || "unknown",
      entropy,
      printableRatio,
      hashes
    },
    findings: sortedFindings,
    engines,
    recommendations: buildRecommendations({
      verdict,
      findings: sortedFindings,
      engines,
      extension,
      entropy
    })
  };

  return report;
}
