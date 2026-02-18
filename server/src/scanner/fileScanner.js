import { spawn } from "child_process";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileTypeFromFile } from "file-type";
import { config } from "../config.js";

const MAX_SAMPLE_BYTES = 1024 * 1024;
const MAX_STRINGS = 500;

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

export async function scanUploadedFile({ filePath, originalName, declaredMimeType }) {
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
      detectedMimeType: detectedType?.mime || "unknown",
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
