import crypto from "crypto";
import fs from "fs";
import fsp from "fs/promises";
import os from "os";
import path from "path";
import zlib from "zlib";
import { fileTypeFromFile } from "file-type";
import { simpleParser } from "mailparser";
import { config } from "../config.js";
import { scanTargetUrl } from "./urlScanner.js";
import { runClamAvScan, runYaraScan } from "./signatureEngines.js";

const MAX_SAMPLE_BYTES = 1024 * 1024;
const MAX_STRINGS = 500;
const MAX_STRUCTURED_INSPECTION_BYTES = 8 * 1024 * 1024;
const MAX_ARCHIVE_SCAN_DEPTH = 1;
const MAX_ARCHIVE_ENTRIES = 32;
const MAX_ARCHIVE_EXTRACT_ITEMS = 6;
const MAX_ARCHIVE_ENTRY_UNCOMPRESSED_BYTES = 4 * 1024 * 1024;
const MAX_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES = 24 * 1024 * 1024;
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

const OFFICE_OPEN_XML_EXTENSIONS = new Set([".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"]);
const LEGACY_OFFICE_EXTENSIONS = new Set([".doc", ".xls", ".ppt"]);
const HTML_EXTENSIONS = new Set([".html", ".htm", ".svg"]);
const SCRIPT_EXTENSIONS = new Set([".js", ".jse", ".vbs", ".ps1", ".bat", ".cmd", ".hta", ".sh"]);
const STRUCTURED_INSPECTION_EXTENSIONS = new Set([
  ".pdf",
  ".doc",
  ".docx",
  ".docm",
  ".xls",
  ".xlsx",
  ".xlsm",
  ".ppt",
  ".pptx",
  ".pptm",
  ".zip",
  ".jar",
  ".js",
  ".jse",
  ".ps1",
  ".lnk",
  ".html",
  ".htm",
  ".hta",
  ".svg",
  ".bat",
  ".cmd",
  ".vbs"
]);
const UNSUPPORTED_ARCHIVE_EXTENSIONS = new Set([".rar", ".7z", ".xz", ".bz2"]);

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

const STATIC_SIGNAL_PATTERNS = {
  downloadPrimitives: [
    { label: "Invoke-WebRequest", regex: /\binvoke-webrequest\b/i },
    { label: "DownloadString", regex: /\bdownloadstring\b/i },
    { label: "DownloadFile", regex: /\bdownloadfile\b/i },
    { label: "Net.WebClient", regex: /\bnet\.webclient\b/i },
    { label: "Start-BitsTransfer", regex: /\bstart-bitstransfer\b/i },
    { label: "BITSAdmin", regex: /\bbitsadmin\b/i },
    { label: "certutil URLCache", regex: /\bcertutil\b[^\n\r]{0,120}-urlcache\b/i },
    { label: "WinHTTP/XMLHTTP", regex: /\b(?:winhttprequest|msxml2\.xmlhttp|xmlhttp)\b/i },
    { label: "curl", regex: /(?:^|\s)curl(?:\.exe)?\s/i },
    { label: "wget", regex: /(?:^|\s)wget\s/i }
  ],
  executionPrimitives: [
    { label: "Invoke-Expression", regex: /\binvoke-expression\b|\biex\b/i },
    { label: "Start-Process", regex: /\bstart-process\b/i },
    { label: "ShellExecute", regex: /\bshellexecute\b/i },
    { label: "WScript.Shell Run", regex: /\bwscript\.shell\b|\b\.run\s*\(/i },
    { label: "PowerShell", regex: /\bpowershell(?:\.exe)?\b/i },
    { label: "cmd.exe", regex: /\bcmd\.exe\b/i },
    { label: "mshta", regex: /\bmshta\b/i },
    { label: "rundll32", regex: /\brundll32\b/i },
    { label: "regsvr32", regex: /\bregsvr32\b/i }
  ],
  persistenceRegistry: [
    { label: "reg add", regex: /\breg(?:\.exe)?\s+add\b/i },
    { label: "Run key", regex: /currentversion\\run(?:once|services|servicesonce)?\b/i },
    { label: "Policies Explorer Run", regex: /policies\\explorer\\run\b/i },
    { label: "Startup folder", regex: /start menu\\programs\\startup\b|user shell folders|shell folders/i }
  ],
  scheduledTask: [
    { label: "schtasks create", regex: /\bschtasks(?:\.exe)?\b[^\n\r]{0,120}\/create\b/i },
    { label: "task schedule", regex: /\/sc\s+(?:onlogon|onstart|once|daily|minute|hourly|weekly|monthly|onevent)\b/i },
    { label: "task run target", regex: /\/tr\b/i }
  ],
  regsvr32Proxy: [
    { label: "regsvr32", regex: /\bregsvr32(?:\.exe)?\b/i },
    { label: "scrobj.dll", regex: /\bscrobj\.dll\b/i },
    { label: "scriptlet", regex: /\.sct\b|scriptlet/i },
    { label: "/i switch", regex: /\s\/i(?::|\s)/i }
  ],
  mshtaSignals: [
    { label: "mshta", regex: /\bmshta(?:\.exe)?\b/i },
    { label: "remote hta/html", regex: /\bhttps?:\/\/[^\s"'<>]+\.hta\b|\bhttps?:\/\/[^\s"'<>]+\b/i },
    { label: "vbscript/javascript", regex: /\b(?:vbscript|javascript):/i }
  ],
  defenderTampering: [
    { label: "Set-MpPreference", regex: /\bset-mppreference\b/i },
    { label: "Add-MpPreference", regex: /\badd-mppreference\b/i },
    { label: "DisableRealtimeMonitoring", regex: /\bdisablerealtimemonitoring\b/i },
    { label: "ExclusionPath", regex: /\bexclusionpath\b/i },
    { label: "ExclusionProcess", regex: /\bexclusionprocess\b/i }
  ],
  browserDataTheft: [
    { label: "Login Data", regex: /\blogin data\b/i },
    { label: "Cookies", regex: /\bcookies\b/i },
    { label: "Web Data", regex: /\bweb data\b/i },
    { label: "Local State", regex: /\blocal state\b/i },
    { label: "DPAPI/Chromium decrypt", regex: /\bcryptunprotectdata\b|os_crypt|encrypted_key/i }
  ],
  serviceInstall: [
    { label: "sc create", regex: /\bsc(?:\.exe)?\s+create\b/i },
    { label: "binPath", regex: /\bbinpath\s*=/i },
    { label: "service autostart", regex: /\bstart\s*=\s*(?:auto|demand)\b/i }
  ],
  encodedPayload: [
    { label: "FromBase64String", regex: /\bfrombase64string\b/i },
    { label: "base64 decode", regex: /\bbase64\b/i },
    { label: "Reflection Assembly Load", regex: /\breflection\.assembly::load\b/i },
    { label: "EncodedCommand", regex: /\bencodedcommand\b|\s-enc(?:\s|$)/i }
  ],
  rundll32Proxy: [
    { label: "rundll32", regex: /\brundll32(?:\.exe)?\b/i },
    { label: "dll export target", regex: /\.dll[, ]+[A-Za-z0-9_#@]+/i },
    { label: "javascript/mshtml", regex: /javascript:|mshtml,runhtmlapplication/i }
  ]
};
const STATIC_URL_REGEX = /\bhttps?:\/\/[^\s<>"'`]+/gi;
const SUSPICIOUS_STRING_PATTERNS = [
  /\b(?:powershell(?:\.exe)?|cmd\.exe|mshta|rundll32|regsvr32|certutil|bitsadmin|schtasks|scrobj\.dll)\b/i,
  /\b(?:invoke-webrequest|downloadstring|downloadfile|frombase64string|encodedcommand|reflection\.assembly::load)\b/i,
  /\b(?:activexobject|wscript\.shell|adodb\.stream|xmlhttp|winhttprequest|savetofile)\b/i,
  /\b(?:currentversion\\run|policies\\explorer\\run|start menu\\programs\\startup)\b/i,
  /\b(?:login data|cookies|web data|local state|cryptunprotectdata|encrypted_key)\b/i,
  /\b(?:\/openaction|\/javascript|\/launch|\/embeddedfile|vbaproject\.bin|externallinks|oleobject|activex)\b/i,
  /\bhttps?:\/\/[^\s"'<>`]+/i,
  /[A-Za-z0-9+/]{180,}={0,2}/
];

const FINDING_WHY_IT_MATTERS_BY_ID = Object.freeze({
  type_mismatch:
    "Attackers often disguise executables as documents or images so users open them without realizing they contain runnable code.",
  double_extension:
    "Double extensions are a classic masquerading technique used to make a dangerous file look like a normal document or media file.",
  archive_nested_malicious:
    "Malicious content inside an archive can bypass shallow inspection and only become visible after extraction or user interaction.",
  archive_nested_suspicious:
    "Suspicious nested content means the outer archive may be acting as a delivery container for a second-stage payload.",
  archive_unsafe_paths:
    "Unsafe archive paths can overwrite files outside the intended extraction directory and are often associated with archive-based exploitation.",
  archive_encrypted_entries:
    "Encrypted archive members reduce scanner visibility and can hide content until the victim opens the archive with the supplied password.",
  pdf_active_content:
    "Scripted or automatic PDF actions can trigger risky behavior as soon as the document is opened in a viewer.",
  pdf_launch_or_rich_media:
    "Launch and rich-media features are uncommon in normal business PDFs and can be abused to start other content or processes.",
  pdf_embedded_file:
    "Embedded files can hide a second-stage payload inside an otherwise ordinary-looking PDF.",
  ooxml_macro_project:
    "Embedded macro projects are a common delivery mechanism for downloaders, credential theft, and follow-on execution.",
  ooxml_external_relationships:
    "External templates and relationships can pull remote content at open time, which raises phishing and payload-delivery risk.",
  legacy_office_embedded_content:
    "Embedded OLE content in legacy Office formats can conceal macros or payloads that do not appear in the visible document body.",
  javascript_dropper_chain:
    "A download-and-execute script chain is a strong indicator that the file is meant to retrieve and launch a second-stage payload.",
  powershell_dropper_chain:
    "PowerShell download-and-execute behavior is widely used for malware staging because it can fetch payloads and run them in the same script.",
  lnk_script_interpreter:
    "Shortcut files that invoke script interpreters are commonly used in phishing to hide the real execution target from the user.",
  lnk_remote_target:
    "Remote shortcut targets can pull payloads from attacker-controlled infrastructure after the user clicks the file.",
  html_external_credential_form:
    "Credential forms that post to external destinations are a common phishing pattern used to capture usernames and passwords.",
  regsvr32_scriptlet_proxy:
    "Regsvr32 scriptlet execution is a well-known proxy-execution technique used to run remote code through trusted system binaries.",
  mshta_remote_execution:
    "MSHTA can execute remote or inline script content through a trusted Windows binary, which is frequently abused in malware delivery.",
  rundll32_proxy_execution:
    "Rundll32 can execute attacker-controlled DLL exports or script-host patterns while blending in with legitimate Windows activity.",
  registry_runkey_persistence:
    "Run-key persistence can cause malware to launch automatically at logon, allowing a compromise to survive reboots.",
  scheduled_task_persistence:
    "Scheduled tasks are commonly abused to re-run malware automatically after login, reboot, or on a timer.",
  service_install_persistence:
    "Installing a Windows service can give malware durable execution and sometimes elevated privileges on the host.",
  defender_tampering:
    "Security-setting tampering can reduce visibility or make it easier for malware to execute without being blocked.",
  browser_data_theft:
    "Browser credential-store access is strongly associated with infostealers that target passwords, cookies, and session tokens.",
  encoded_payload_stager:
    "Encoded or in-memory staging makes analysis harder and often indicates an attempt to hide a second-stage payload from basic inspection.",
  yara_rule_match:
    "YARA matches indicate the file shares string, byte-pattern, or structural traits with known malware families or hunting rules and should be reviewed carefully.",
  high_entropy:
    "High entropy often appears when data is packed, encrypted, or otherwise transformed to make inspection more difficult.",
  unknown_binary_payload:
    "An unrecognized low-text binary can indicate a packed or uncommon payload that needs deeper tooling to classify safely."
});

const FINDING_WHY_IT_MATTERS_BY_CATEGORY = Object.freeze({
  Execution: "Execution-oriented findings matter because they indicate the file may directly run attacker-controlled code.",
  "Proxy Execution": "Proxy-execution findings matter because trusted system binaries are often abused to hide malicious execution.",
  Persistence: "Persistence findings matter because they can allow a compromise to survive reboot, logoff, or ordinary cleanup.",
  "Defense Evasion": "Defense-evasion findings matter because they reduce visibility and make malicious activity harder to detect or investigate.",
  Obfuscation: "Obfuscation findings matter because hidden or encoded content is commonly used to delay or evade static analysis.",
  "Credential Access": "Credential-access findings matter because they can expose passwords, cookies, tokens, or other sensitive secrets.",
  "Credential Capture": "Credential-capture findings matter because they can directly lead to account takeover or downstream fraud.",
  Masquerading: "Masquerading findings matter because they exploit user trust by making risky files look harmless.",
  "Archive Contents": "Archive-content findings matter because compressed containers are often used to hide or stage payloads.",
  "Archive Structure": "Archive-structure findings matter because unsafe or unusual container layouts can increase exploitation risk.",
  "Script Dropper": "Dropper findings matter because they show the sample may be designed to fetch and launch follow-on malware.",
  "File Type": "File-type findings matter because certain formats have a long history of abuse for code delivery and user deception.",
  "PDF Actions": "PDF action findings matter because they can trigger risky behavior when the document is opened.",
  "Embedded Content": "Embedded-content findings matter because additional payloads can be hidden inside otherwise ordinary files.",
  "External References": "External-reference findings matter because remote content retrieval can change what the user actually opens.",
  "Signature Rules": "Signature-rule findings matter because they indicate the sample resembles known malware or analyst-authored hunt logic.",
  "Shortcut Execution": "Shortcut execution findings matter because a click can launch hidden commands or remote payloads.",
  Redirection: "Redirection findings matter because the visible file may immediately send a user to a second-stage destination.",
  "Hidden Content": "Hidden-content findings matter because attacker-controlled content can be concealed from a casual user review."
});

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

const WEAK_SIGNAL_FINDING_IDS = new Set([
  "high_risk_extension",
  "macro_enabled_document",
  "high_entropy",
  "long_base64_blob",
  "archive_encrypted_entries",
  "archive_unsupported_compression",
  "archive_nested_inconclusive",
  "archive_nested_items_skipped",
  "ooxml_external_relationships",
  "ooxml_embedded_active_content",
  "legacy_office_embedded_content",
  "unknown_binary_payload",
  "email_spf_missing",
  "email_dkim_missing",
  "email_dmarc_missing",
  "html_meta_refresh_redirect",
  "html_hidden_frame"
]);

const STANDALONE_SUSPICIOUS_FINDING_IDS = new Set([
  "archive_unsafe_paths",
  "archive_nested_suspicious",
  "type_mismatch",
  "ooxml_macro_project",
  "pdf_launch_or_rich_media",
  "pdf_active_content",
  "pdf_embedded_file",
  "javascript_dropper_chain",
  "powershell_dropper_chain",
  "regsvr32_scriptlet_proxy",
  "mshta_remote_execution",
  "rundll32_proxy_execution",
  "defender_tampering",
  "browser_data_theft",
  "html_external_credential_form",
  "yara_rule_match"
]);

const STANDALONE_MALICIOUS_FINDING_IDS = new Set([
  "archive_nested_malicious",
  "regsvr32_scriptlet_proxy",
  "mshta_remote_execution"
]);

const VERDICT_TRUSTED_DETECTION_IDS = new Set(["clamav_signature_match", "external_reputation_detections"]);

const SCORE_CLASS_MULTIPLIERS = Object.freeze({
  strong: 0.95,
  moderate: 0.68,
  weak: 0.32
});

const SCORE_POSITION_MULTIPLIERS = Object.freeze([1, 0.65, 0.45, 0.3, 0.22, 0.16]);

const SCORE_REPEAT_CATEGORY_MULTIPLIERS = Object.freeze([1, 0.82, 0.68, 0.56]);

function summarizeFindingsBySeverity(findings) {
  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  for (const finding of findings || []) {
    const severity = String(finding?.severity || "info").toLowerCase();
    if (Object.prototype.hasOwnProperty.call(summary, severity)) {
      summary[severity] += 1;
    } else {
      summary.info += 1;
    }
  }

  return summary;
}

function getFindingSignalClass(finding) {
  const findingId = String(finding?.id || "").trim();
  const severity = String(finding?.severity || "").toLowerCase();

  if (WEAK_SIGNAL_FINDING_IDS.has(findingId) || severity === "low" || severity === "info") {
    return "weak";
  }

  if (STANDALONE_SUSPICIOUS_FINDING_IDS.has(findingId) || severity === "critical") {
    return "strong";
  }

  if (severity === "high") {
    return "moderate";
  }

  if (severity === "medium") {
    return "moderate";
  }

  return "weak";
}

function getPositionMultiplier(index) {
  if (index < SCORE_POSITION_MULTIPLIERS.length) {
    return SCORE_POSITION_MULTIPLIERS[index];
  }

  return SCORE_POSITION_MULTIPLIERS[SCORE_POSITION_MULTIPLIERS.length - 1];
}

function getCategoryRepeatMultiplier(index) {
  if (index < SCORE_REPEAT_CATEGORY_MULTIPLIERS.length) {
    return SCORE_REPEAT_CATEGORY_MULTIPLIERS[index];
  }

  return SCORE_REPEAT_CATEGORY_MULTIPLIERS[SCORE_REPEAT_CATEGORY_MULTIPLIERS.length - 1];
}

function buildRiskProfile(findings) {
  const sortedFindings = sortFindings(findings || []);
  const severityCounts = summarizeFindingsBySeverity(sortedFindings);
  const classCounts = {
    strong: 0,
    moderate: 0,
    weak: 0
  };
  const categoryCounts = new Map();
  let score = 0;
  let rawWeight = 0;
  let standaloneSuspiciousCount = 0;
  let trustedDetectionCount = 0;

  for (const finding of sortedFindings) {
    const signalClass = getFindingSignalClass(finding);
    const signalIndex = classCounts[signalClass];
    const positionMultiplier = getPositionMultiplier(signalIndex);
    const categoryKey = String(finding?.category || "General").trim() || "General";
    const categoryIndex = categoryCounts.get(categoryKey) || 0;
    const categoryMultiplier = getCategoryRepeatMultiplier(categoryIndex);
    const classMultiplier = SCORE_CLASS_MULTIPLIERS[signalClass];
    const weight = Number(finding?.weight) || SEVERITY_SCORE[finding?.severity] || 0;

    rawWeight += weight;
    score += weight * classMultiplier * positionMultiplier * categoryMultiplier;

    classCounts[signalClass] += 1;
    categoryCounts.set(categoryKey, categoryIndex + 1);

    if (STANDALONE_SUSPICIOUS_FINDING_IDS.has(String(finding?.id || "").trim())) {
      standaloneSuspiciousCount += 1;
    }

    if (VERDICT_TRUSTED_DETECTION_IDS.has(String(finding?.id || "").trim())) {
      trustedDetectionCount += 1;
    }
  }

  const uniqueCategoryCount = categoryCounts.size;
  const diversityBonus = Math.min(15, Math.max(0, uniqueCategoryCount - 1) * 3);
  const corroborationBonus =
    classCounts.strong >= 2 ? 8 : classCounts.strong >= 1 && classCounts.moderate >= 1 ? 4 : classCounts.moderate >= 2 ? 2 : 0;
  const boundedScore = Math.max(0, Math.min(100, Math.round(score + diversityBonus + corroborationBonus)));

  return {
    score: boundedScore,
    rawWeight: Math.max(0, Math.min(100, Math.round(rawWeight))),
    severityCounts,
    classCounts,
    uniqueCategoryCount,
    standaloneSuspiciousCount,
    trustedDetectionCount,
    findingsCount: sortedFindings.length
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

function extractUtf16Strings(buffer, minimumLength = 6, maxStrings = MAX_STRINGS) {
  if (!buffer || buffer.length < minimumLength * 2) {
    return [];
  }

  const text = buffer.toString("utf16le");
  const matches = text.match(/[\x20-\x7e]{6,}/g) || [];
  return matches.slice(0, maxStrings);
}

function combineExtractedStrings(...collections) {
  const seen = new Set();
  const combined = [];

  for (const collection of collections) {
    for (const value of collection || []) {
      const normalized = String(value || "").trim();
      if (!normalized) {
        continue;
      }

      if (seen.has(normalized)) {
        continue;
      }

      seen.add(normalized);
      combined.push(normalized);

      if (combined.length >= MAX_STRINGS) {
        return combined;
      }
    }
  }

  return combined;
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

  if (
    sample.length >= 8 &&
    sample[0] === 0xd0 &&
    sample[1] === 0xcf &&
    sample[2] === 0x11 &&
    sample[3] === 0xe0 &&
    sample[4] === 0xa1 &&
    sample[5] === 0xb1 &&
    sample[6] === 0x1a &&
    sample[7] === 0xe1
  ) {
    return "OLE compound document";
  }

  if (sample.toString("utf8", 0, 5) === "%PDF-") {
    return "PDF document";
  }

  if (
    sample.length >= 20 &&
    sample.readUInt32LE(0) === 0x0000004c &&
    sample.subarray(4, 20).equals(Buffer.from([0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]))
  ) {
    return "Windows shortcut";
  }

  if (sample[0] === 0x23 && sample[1] === 0x21) {
    return "Script with shebang";
  }

  return null;
}

function buildEvidencePreview(items, limit = 3) {
  const visibleItems = (items || [])
    .map((value) => String(value || "").trim())
    .filter(Boolean)
    .slice(0, limit);

  if (visibleItems.length === 0) {
    return "";
  }

  return visibleItems.join(" | ");
}

function sanitizeEvidenceSnippet(value, maxLength = 180) {
  const normalized = String(value || "")
    .replace(/\s+/g, " ")
    .trim();

  if (!normalized) {
    return "";
  }

  return normalized.length > maxLength ? `${normalized.slice(0, maxLength - 1)}…` : normalized;
}

function splitEvidenceItems(evidence, limit = 6) {
  return String(evidence || "")
    .split("|")
    .map((entry) => sanitizeEvidenceSnippet(entry))
    .filter(Boolean)
    .slice(0, limit);
}

function buildWhyItMatters(finding) {
  const findingId = String(finding?.id || "").trim();
  if (findingId && FINDING_WHY_IT_MATTERS_BY_ID[findingId]) {
    return FINDING_WHY_IT_MATTERS_BY_ID[findingId];
  }

  const category = String(finding?.category || "").trim();
  if (category && FINDING_WHY_IT_MATTERS_BY_CATEGORY[category]) {
    return FINDING_WHY_IT_MATTERS_BY_CATEGORY[category];
  }

  return "This finding increases the likelihood that the file could be unsafe to open without additional validation.";
}

function findingConfidenceImpact(finding) {
  const severity = String(finding?.severity || "").toLowerCase();
  const multiplier =
    severity === "critical" ? 1.2 : severity === "high" ? 1 : severity === "medium" ? 0.7 : severity === "low" ? 0.45 : 0.25;
  return Math.max(2, Math.round((Number(finding?.weight) || 0) * multiplier));
}

function buildCenteredSnippet(source, startIndex, length, radius = 56) {
  const normalized = String(source || "").replace(/\s+/g, " ");
  if (!normalized) {
    return "";
  }

  const start = Math.max(0, startIndex - radius);
  const end = Math.min(normalized.length, startIndex + Math.max(length, 1) + radius);
  const prefix = start > 0 ? "…" : "";
  const suffix = end < normalized.length ? "…" : "";
  return sanitizeEvidenceSnippet(`${prefix}${normalized.slice(start, end)}${suffix}`, 180);
}

function collectSuspiciousStrings(strings, limit = 12) {
  const suspicious = [];
  const seen = new Set();

  for (const value of strings || []) {
    const candidate = String(value || "");
    if (!candidate) {
      continue;
    }

    for (const pattern of SUSPICIOUS_STRING_PATTERNS) {
      const match = candidate.match(pattern);
      if (!match?.[0]) {
        continue;
      }

      const snippet = buildCenteredSnippet(candidate, match.index || 0, match[0].length);
      const dedupeKey = snippet.toLowerCase();
      if (!snippet || seen.has(dedupeKey)) {
        continue;
      }

      seen.add(dedupeKey);
      suspicious.push(snippet);
      break;
    }

    if (suspicious.length >= limit) {
      break;
    }
  }

  return suspicious;
}

function normalizeCompatibleType(extension, detectedFileType, magicType) {
  const normalizedExtension = String(extension || "").toLowerCase().replace(/^\./, "");
  const normalizedType = String(detectedFileType || "").toLowerCase().trim();
  const normalizedMagic = String(magicType || "").toLowerCase();

  if (!normalizedExtension || !normalizedType || normalizedType === "unknown") {
    return true;
  }

  const compatibleTypes = new Map([
    ["jpg", ["jpg", "jpeg"]],
    ["jpeg", ["jpg", "jpeg"]],
    ["htm", ["htm", "html"]],
    ["html", ["htm", "html"]],
    ["tgz", ["gz"]],
    ["docm", ["docx"]],
    ["xlsm", ["xlsx"]],
    ["pptm", ["pptx"]]
  ]);

  if (normalizedExtension === normalizedType) {
    return true;
  }

  if ((compatibleTypes.get(normalizedExtension) || []).includes(normalizedType)) {
    return true;
  }

  if (
    normalizedMagic === "zip archive" &&
    (OFFICE_OPEN_XML_EXTENSIONS.has(`.${normalizedExtension}`) || normalizedExtension === "zip" || normalizedExtension === "jar")
  ) {
    return true;
  }

  if (normalizedMagic === "ole compound document" && LEGACY_OFFICE_EXTENSIONS.has(`.${normalizedExtension}`)) {
    return true;
  }

  return false;
}

function buildStructureAnomalies({
  fileName,
  extension,
  declaredMimeType,
  detectedMimeType,
  detectedFileType,
  magicType,
  printableRatio,
  findings,
  archiveInspection,
  archiveSkippedCount
}) {
  const anomalies = [];
  const findingMap = new Map((findings || []).map((finding) => [finding.id, finding]));
  const normalizedExtension = String(extension || "").toLowerCase();

  if (findingMap.has("type_mismatch")) {
    anomalies.push({
      type: "extension_type_mismatch",
      severity: "critical",
      label: "Executable content is disguised behind a document-style extension",
      detail: `${fileName} presents as ${normalizedExtension || "unknown"} but the file header resolves as ${magicType || "unknown"}.`
    });
  } else if (!normalizeCompatibleType(normalizedExtension, detectedFileType, magicType)) {
    anomalies.push({
      type: "extension_type_mismatch",
      severity: "medium",
      label: "Extension and detected file identity do not line up cleanly",
      detail: `${fileName} uses ${normalizedExtension || "(none)"} while detection resolved as ${detectedFileType || "unknown"} / ${detectedMimeType || "unknown"}.`
    });
  }

  if (findingMap.has("double_extension")) {
    anomalies.push({
      type: "double_extension",
      severity: "high",
      label: "Double-extension masquerading pattern",
      detail: `${fileName} uses multiple extensions to look more trustworthy before exposing a runnable type.`
    });
  }

  if (findingMap.has("ooxml_macro_project")) {
    anomalies.push({
      type: "embedded_macro_project",
      severity: "high",
      label: "Macro project found inside an Office container",
      detail: "The package layout indicates embedded VBA content, which materially raises execution risk for document workflows."
    });
  }

  if (findingMap.has("archive_unsafe_paths")) {
    anomalies.push({
      type: "unsafe_archive_paths",
      severity: "high",
      label: "Archive entry paths attempt to escape the extraction directory",
      detail: "At least one archive member used traversal-style or absolute-style paths that are unsafe to expand automatically."
    });
  }

  if (findingMap.has("archive_encrypted_entries")) {
    anomalies.push({
      type: "encrypted_archive_members",
      severity: "medium",
      label: "Archive contains encrypted members",
      detail: "Encrypted members reduce scanner visibility until the archive is opened with a password."
    });
  }

  if (findingMap.has("archive_double_extension_payload")) {
    anomalies.push({
      type: "nested_double_extension",
      severity: "high",
      label: "Nested archive member uses a double-extension disguise",
      detail: "A file inside the archive was named to look like a document before exposing a runnable extension."
    });
  }

  if (findingMap.has("archive_risky_payloads")) {
    anomalies.push({
      type: "nested_runnable_payload",
      severity: "high",
      label: "Archive contains runnable payload types",
      detail: "The archive includes executable, script, or shortcut content that should be reviewed individually before opening."
    });
  }

  if (archiveSkippedCount > 0) {
    anomalies.push({
      type: "partial_archive_visibility",
      severity: "low",
      label: "Archive visibility was partial",
      detail: `${archiveSkippedCount} nested entr${archiveSkippedCount === 1 ? "y was" : "ies were"} skipped due to safety or extraction limits.`
    });
  }

  if (Number(printableRatio) < 0.2 && !magicType) {
    anomalies.push({
      type: "low_text_unknown_binary",
      severity: "medium",
      label: "Low-text binary with weak type identity",
      detail: `Printable ratio is ${printableRatio}, which suggests opaque binary content without a confidently recognized file signature.`
    });
  }

  if (
    declaredMimeType &&
    detectedMimeType &&
    declaredMimeType !== "unknown" &&
    detectedMimeType !== "unknown" &&
    declaredMimeType !== detectedMimeType
  ) {
    anomalies.push({
      type: "mime_declaration_mismatch",
      severity: "low",
      label: "Declared and detected MIME types differ",
      detail: `Upload declared ${declaredMimeType}, while content detection resolved as ${detectedMimeType}.`
    });
  }

  if (archiveInspection?.status === "unsupported" || archiveInspection?.status === "invalid") {
    anomalies.push({
      type: "archive_visibility_gap",
      severity: "medium",
      label: "Archive format reduced extraction depth",
      detail: `Archive inspection ended with status ${archiveInspection.status}${archiveInspection.reason ? ` (${archiveInspection.reason})` : ""}.`
    });
  }

  return anomalies.slice(0, 12);
}

function buildNestedFileSummaries(items, limit = 10) {
  return (Array.isArray(items) ? items : []).slice(0, limit).map((item) => ({
    name: item?.name || "nested-item",
    verdict: item?.verdict || "unknown",
    riskScore: Number(item?.riskScore) || 0,
    size: item?.size || 0,
    sizeDisplay: item?.sizeDisplay || humanFileSize(Number(item?.size) || 0),
    topFinding: item?.topFinding || "No notable findings"
  }));
}

function buildArchiveBlindSpots(archiveInspection, archiveSkippedCount) {
  const blindSpots = [];

  if (!archiveInspection || archiveInspection.status === "skipped") {
    return blindSpots;
  }

  if (archiveInspection.status === "unsupported") {
    blindSpots.push("Archive format was recognized but not fully expanded in the current runtime.");
  } else if (archiveInspection.status === "invalid") {
    blindSpots.push("Archive structure could not be fully parsed, which reduces nested-content visibility.");
  }

  if (archiveSkippedCount > 0) {
    blindSpots.push(`Nested extraction skipped ${archiveSkippedCount} archive entr${archiveSkippedCount === 1 ? "y" : "ies"} because of bounds or safety limits.`);
  }

  return blindSpots;
}

function buildCoverageSummary({
  file,
  engines,
  structuredAnalysis,
  archiveInspection,
  classification,
  archiveSkippedCount
}) {
  const blindSpots = [];
  const hasRecognizedIdentity =
    file.magicType !== "unknown" || file.detectedMimeType !== "unknown" || file.detectedFileType !== "unknown";

  if (!hasRecognizedIdentity) {
    blindSpots.push("File identity was only weakly recognized from headers and MIME detection.");
  }

  if (engines.clamav.status !== "clean" && engines.clamav.status !== "infected") {
    blindSpots.push(`ClamAV status was ${engines.clamav.status}, so signature coverage was limited.`);
  }

  if (engines.clamav?.definitions?.status === "stale") {
    blindSpots.push("ClamAV definitions are stale, which reduces signature freshness.");
  } else if (engines.clamav?.definitions?.status === "missing") {
    blindSpots.push("ClamAV definitions are missing, so known-malware coverage is incomplete.");
  }

  if (!["clean", "matched"].includes(engines.yara?.status || "")) {
    blindSpots.push(`YARA status was ${engines.yara?.status || "unknown"}, so rule-pack coverage was limited.`);
  }

  if (!["found", "not_found"].includes(engines.virustotal.status)) {
    blindSpots.push(`External hash-reputation coverage was ${engines.virustotal.status}.`);
  }

  blindSpots.push(...buildArchiveBlindSpots(archiveInspection, archiveSkippedCount));

  return {
    identity: hasRecognizedIdentity ? "recognized" : "limited",
    structuredInspectionBytes: Number(structuredAnalysis?.inspectedBytes) || 0,
    extractedStringCount: Number(structuredAnalysis?.extractedStringCount) || 0,
    archiveInspectionStatus: archiveInspection?.status || "skipped",
    archiveEntriesObserved: Array.isArray(archiveInspection?.entries) ? archiveInspection.entries.length : 0,
    archiveItemsExtracted: Array.isArray(archiveInspection?.nested?.items) ? archiveInspection.nested.items.length : 0,
    externalReputation:
      engines.virustotal.status === "found"
        ? "hash intelligence available"
        : engines.virustotal.status === "not_found"
          ? "hash not found"
          : "limited",
    yaraCoverage: engines.yara?.status || "disabled",
    signatureCoverage: engines.clamav.status,
    classificationConfidence: classification?.confidence || "medium",
    blindSpots: blindSpots.slice(0, 8)
  };
}

function buildConfidenceAssessment({
  verdict,
  classification,
  findings,
  riskScore,
  file,
  engines,
  structuredAnalysis,
  archiveInspection,
  archiveSkippedCount
}) {
  const factors = [];
  const addFactor = (impact, weight, label, detail) => {
    factors.push({
      impact,
      weight,
      label,
      detail
    });
  };

  const severityCounts = summarizeFindingsBySeverity(findings);
  let score = verdict === "malicious" ? 78 : verdict === "suspicious" ? 66 : verdict === "unknown" ? 42 : 60;

  if (engines.clamav.status === "infected") {
    score += 16;
    addFactor("raises", 16, "Known malware signature hit", "ClamAV matched a known malware signature, which strongly corroborates the verdict.");
  } else if (engines.clamav.status === "clean") {
    score += 4;
    addFactor("supports", 4, "Signature scan completed", "ClamAV completed without a known-malware signature match.");
  } else {
    score -= 4;
    addFactor("limits", -4, "Signature coverage gap", `ClamAV status was ${engines.clamav.status}, so signature-based corroboration was incomplete.`);
  }

  if (engines.clamav?.definitions?.status === "stale") {
    score -= 4;
    addFactor("limits", -4, "Stale ClamAV definitions", "ClamAV definitions were present but older than the configured freshness window.");
  } else if (engines.clamav?.definitions?.status === "missing") {
    score -= 8;
    addFactor("limits", -8, "Missing ClamAV definitions", "ClamAV could not rely on a local definition set, which reduces known-malware coverage.");
  }

  if (engines.yara?.status === "matched") {
    const matchCount = Array.isArray(engines.yara.matchedRules) ? engines.yara.matchedRules.length : 0;
    const weight = matchCount >= 3 ? 10 : 6;
    score += weight;
    addFactor(
      "raises",
      weight,
      "YARA rule-pack match",
      `YARA matched ${matchCount} rule${matchCount === 1 ? "" : "s"}, which adds curated malware-hunting corroboration.`
    );
  } else if (!["clean", "disabled"].includes(engines.yara?.status || "")) {
    score -= 3;
    addFactor("limits", -3, "YARA coverage gap", `YARA status was ${engines.yara?.status || "unknown"}, so rule-pack coverage was incomplete.`);
  }

  if (engines.virustotal.status === "found" && (Number(engines.virustotal.malicious) > 0 || Number(engines.virustotal.suspicious) > 0)) {
    const weight = Number(engines.virustotal.malicious) > 2 ? 14 : 10;
    score += weight;
    addFactor(
      "raises",
      weight,
      "External reputation corroboration",
      `${engines.virustotal.malicious} malicious and ${engines.virustotal.suspicious} suspicious detections were reported by the external reputation feed.`
    );
  } else if (engines.virustotal.status === "found") {
    score += 5;
    addFactor("supports", 5, "External reputation available", "An external hash-reputation source had coverage and did not report a malicious hit.");
  } else if (!["not_found"].includes(engines.virustotal.status)) {
    score -= 3;
    addFactor("limits", -3, "External reputation gap", `External hash-reputation status was ${engines.virustotal.status}, so outside hash intelligence was limited.`);
  }

  if (severityCounts.critical >= 2) {
    score += 12;
    addFactor("raises", 12, "Multiple critical findings", "Several critical findings point to corroborated malicious behavior rather than a single weak signal.");
  } else if (severityCounts.critical === 1) {
    score += 8;
    addFactor("raises", 8, "Critical finding present", "A critical finding was detected, which materially increases confidence in the verdict.");
  }

  if (severityCounts.high >= 2) {
    score += 7;
    addFactor("raises", 7, "Multiple high-severity findings", "Independent high-severity findings increase confidence that the behavior is not accidental noise.");
  } else if (severityCounts.high === 1) {
    score += 3;
    addFactor("supports", 3, "High-severity finding present", "A high-severity finding adds meaningful weight to the assessment.");
  }

  if (findings.length <= 1 && severityCounts.critical === 0 && severityCounts.high === 0 && riskScore < 25) {
    score -= 9;
    addFactor("limits", -9, "Thin evidence set", "The result is based on a very small number of weak indicators, so confidence should stay conservative.");
  }

  const hasRecognizedIdentity =
    file.magicType !== "unknown" || file.detectedMimeType !== "unknown" || file.detectedFileType !== "unknown";
  if (hasRecognizedIdentity) {
    score += 4;
    addFactor("supports", 4, "Recognized file identity", "Headers or MIME detection gave the scanner a credible file identity to reason over.");
  } else {
    score -= 10;
    addFactor("limits", -10, "Weak file identity", "The file could not be strongly identified from its content signature, which reduces confidence.");
  }

  if (Array.isArray(archiveInspection?.nested?.items) && archiveInspection.nested.items.length > 0) {
    const nestedHighRisk = archiveInspection.nested.items.filter((item) => ["malicious", "suspicious"].includes(String(item?.verdict || ""))).length;
    if (nestedHighRisk > 0) {
      score += 8;
      addFactor("raises", 8, "Nested file corroboration", `${nestedHighRisk} extracted archive item${nestedHighRisk === 1 ? "" : "s"} also scored as suspicious or malicious.`);
    }
  }

  if (archiveSkippedCount > 0) {
    score -= 7;
    addFactor("limits", -7, "Partial archive visibility", `${archiveSkippedCount} archive entr${archiveSkippedCount === 1 ? "y was" : "ies were"} skipped because of extraction safety limits.`);
  }

  if (classification?.confidence === "low") {
    score -= 8;
    addFactor("limits", -8, "Low-confidence verdict path", "The verdict logic already identified weak corroboration or limited visibility.");
  } else if (classification?.confidence === "high") {
    score += 4;
    addFactor("supports", 4, "High-confidence verdict path", "The verdict logic considered the overall signal set strongly corroborated.");
  }

  if (Number(file.entropy) >= 7.3 && verdict !== "clean") {
    score += 3;
    addFactor("supports", 3, "Packed or encoded content signal", "Elevated entropy supports the presence of transformed or concealed payload content.");
  }

  const boundedScore = Math.max(8, Math.min(98, Math.round(score)));
  const level = boundedScore >= 80 ? "high" : boundedScore >= 55 ? "medium" : "low";
  const coverage = buildCoverageSummary({
    file,
    engines,
    structuredAnalysis,
    archiveInspection,
    classification,
    archiveSkippedCount
  });

  let summary = "The report confidence is based on the quality and corroboration of the evidence collected.";
  if (verdict === "malicious") {
    summary =
      level === "high"
        ? "High-confidence malicious classification based on corroborated static, structural, or reputation evidence."
        : "Malicious indicators were found, but some visibility gaps still reduce overall certainty.";
  } else if (verdict === "suspicious") {
    summary =
      level === "high"
        ? "High-confidence suspicious classification with multiple meaningful risk signals."
        : "The file shows meaningful risk signals and should be reviewed before use, but deeper detonation could add certainty.";
  } else if (verdict === "unknown") {
    summary = "The scan found some indicators, but the evidence is not complete or corroborated enough for a stronger verdict.";
  } else if (verdict === "clean") {
    summary =
      level === "high"
        ? "No strong indicators were found and scan coverage was broad enough for a higher-confidence first-pass clean result."
        : "No strong indicators were found, but this remains a first-pass clean result rather than a safety guarantee.";
  }

  return {
    score: boundedScore,
    level,
    summary,
    factors: factors
      .slice()
      .sort((left, right) => Math.abs(right.weight) - Math.abs(left.weight))
      .slice(0, 8),
    coverage
  };
}

function enrichFindings(findings) {
  return (findings || []).map((finding) => ({
    ...finding,
    whyItMatters: buildWhyItMatters(finding),
    evidenceItems: splitEvidenceItems(finding?.evidence),
    confidenceImpact: findingConfidenceImpact(finding)
  }));
}

function buildTechnicalIndicators({
  file,
  safeOriginalName,
  structuredAnalysis,
  staticRuleAnalysis,
  archiveInspection,
  findings,
  matchedRules,
  confidence,
  declaredMimeType
}) {
  const archiveNestedItems = Array.isArray(archiveInspection?.nested?.items) ? archiveInspection.nested.items : [];
  const archiveSkippedItems = Array.isArray(archiveInspection?.nested?.skipped) ? archiveInspection.nested.skipped : [];
  const structureAnomalies = buildStructureAnomalies({
    fileName: safeOriginalName,
    extension: file.extension,
    declaredMimeType,
    detectedMimeType: file.detectedMimeType,
    detectedFileType: file.detectedFileType,
    magicType: file.magicType === "unknown" ? null : file.magicType,
    printableRatio: file.printableRatio,
    findings,
    archiveInspection,
    archiveSkippedCount: archiveSkippedItems.length
  });

  return {
    fileProfile: {
      originalName: safeOriginalName,
      extension: file.extension,
      declaredMimeType,
      detectedMimeType: file.detectedMimeType,
      detectedFileType: file.detectedFileType,
      magicType: file.magicType,
      size: file.size,
      sizeDisplay: file.sizeDisplay,
      entropy: file.entropy,
      printableRatio: file.printableRatio
    },
    confidence: {
      score: confidence.score,
      level: confidence.level,
      summary: confidence.summary
    },
    coverage: confidence.coverage,
    matchedRules: {
      heuristicRuleIds: matchedRules,
      compositeRuleIds: staticRuleAnalysis.matchedRules,
      findingIds: (findings || []).map((finding) => finding.id).slice(0, 24),
      staticSignalCounts: staticRuleAnalysis.signalCounts
    },
    evidence: {
      suspiciousStrings: collectSuspiciousStrings(structuredAnalysis?.strings || []),
      structureAnomalies,
      nestedFiles: buildNestedFileSummaries(archiveNestedItems),
      archiveSkipped: archiveSkippedItems.slice(0, 8).map((item) => ({
        name: item?.name || "(unknown)",
        reason: item?.reason || "skipped"
      }))
    },
    archive: {
      status: archiveInspection?.status || "skipped",
      reason: archiveInspection?.reason || null,
      entryCount: Array.isArray(archiveInspection?.entries) ? archiveInspection.entries.length : 0,
      extractedItemCount: archiveNestedItems.length,
      skippedItemCount: archiveSkippedItems.length
    }
  };
}

function collectStaticSignalMatches(textCorpus, patterns, limit = 6) {
  const hits = [];

  for (const pattern of patterns || []) {
    const match = String(textCorpus || "").match(pattern.regex);
    if (!match?.[0]) {
      continue;
    }

    hits.push({
      label: pattern.label,
      match: match[0].slice(0, 160)
    });

    if (hits.length >= limit) {
      break;
    }
  }

  return hits;
}

function extractStaticUrls(textCorpus, limit = 8) {
  const urls = [];
  const seen = new Set();

  for (const match of String(textCorpus || "").matchAll(STATIC_URL_REGEX)) {
    const normalized = normalizeExtractedUrl(match[0]);
    if (!normalized || seen.has(normalized)) {
      continue;
    }

    seen.add(normalized);
    urls.push(normalized);

    if (urls.length >= limit) {
      break;
    }
  }

  return urls;
}

function hasSignalMatch(matches, label) {
  return matches.some((entry) => entry.label === label);
}

function summarizeSignalMatches(matches, limit = 4) {
  return buildEvidencePreview(
    (matches || []).map((entry) => entry.label),
    limit
  );
}

function analyzeCompositeStaticRules({ textCorpus, extension, originalName }) {
  const corpus = String(textCorpus || "").slice(0, 2_000_000);
  const urls = extractStaticUrls(corpus);
  const signals = Object.fromEntries(
    Object.entries(STATIC_SIGNAL_PATTERNS).map(([key, patterns]) => [key, collectStaticSignalMatches(corpus, patterns)])
  );
  const findings = [];
  const matchedRules = [];

  const addFinding = (finding) => {
    findings.push(finding);
    matchedRules.push(finding.id);
  };

  const hasDownloadExecuteChain =
    signals.downloadPrimitives.length > 0 &&
    signals.executionPrimitives.length > 0 &&
    (urls.length > 0 || SCRIPT_EXTENSIONS.has(extension) || hasSignalMatch(signals.encodedPayload, "EncodedCommand"));

  if (hasDownloadExecuteChain) {
    addFinding({
      id: "download_execute_chain",
      severity: "critical",
      category: "Execution Chain",
      weight: 30,
      title: "Composite download-and-execute behavior",
      description: "The file combines downloader behavior with execution primitives, which is a common first-stage malware delivery pattern.",
      evidence: buildEvidencePreview([
        summarizeSignalMatches(signals.downloadPrimitives, 2),
        summarizeSignalMatches(signals.executionPrimitives, 2),
        urls[0] || originalName
      ], 4)
    });
  }

  if (
    hasSignalMatch(signals.persistenceRegistry, "reg add") &&
    (hasSignalMatch(signals.persistenceRegistry, "Run key") ||
      hasSignalMatch(signals.persistenceRegistry, "Policies Explorer Run") ||
      hasSignalMatch(signals.persistenceRegistry, "Startup folder"))
  ) {
    addFinding({
      id: "registry_runkey_persistence",
      severity: "high",
      category: "Persistence",
      weight: 24,
      title: "Registry Run-key persistence pattern",
      description: "The file references Windows autostart registry or Startup-folder persistence commonly used to relaunch malware at logon.",
      evidence: summarizeSignalMatches(signals.persistenceRegistry, 4)
    });
  }

  if (
    hasSignalMatch(signals.scheduledTask, "schtasks create") &&
    hasSignalMatch(signals.scheduledTask, "task schedule") &&
    hasSignalMatch(signals.scheduledTask, "task run target")
  ) {
    addFinding({
      id: "scheduled_task_persistence",
      severity: "high",
      category: "Persistence",
      weight: 24,
      title: "Scheduled-task persistence pattern",
      description: "The file includes creation of a scheduled task with a trigger and execution target, a common persistence mechanism.",
      evidence: summarizeSignalMatches(signals.scheduledTask, 4)
    });
  }

  if (
    hasSignalMatch(signals.regsvr32Proxy, "regsvr32") &&
    (hasSignalMatch(signals.regsvr32Proxy, "scrobj.dll") ||
      hasSignalMatch(signals.regsvr32Proxy, "scriptlet") ||
      hasSignalMatch(signals.regsvr32Proxy, "/i switch")) &&
    urls.length > 0
  ) {
    addFinding({
      id: "regsvr32_scriptlet_proxy",
      severity: "critical",
      category: "Proxy Execution",
      weight: 32,
      title: "Regsvr32 scriptlet proxy-execution pattern",
      description: "The file uses regsvr32 with scriptlet-style indicators, a known technique for proxy execution and remote code staging.",
      evidence: buildEvidencePreview([
        summarizeSignalMatches(signals.regsvr32Proxy, 3),
        urls[0]
      ], 3)
    });
  }

  if (
    hasSignalMatch(signals.mshtaSignals, "mshta") &&
    (hasSignalMatch(signals.mshtaSignals, "remote hta/html") || hasSignalMatch(signals.mshtaSignals, "vbscript/javascript"))
  ) {
    addFinding({
      id: "mshta_remote_execution",
      severity: "critical",
      category: "Proxy Execution",
      weight: 30,
      title: "MSHTA remote or scripted execution pattern",
      description: "The file invokes mshta with remote or inline script content, which is commonly abused to execute malicious payloads.",
      evidence: buildEvidencePreview([
        summarizeSignalMatches(signals.mshtaSignals, 3),
        urls[0] || originalName
      ], 3)
    });
  }

  if (
    (hasSignalMatch(signals.defenderTampering, "Set-MpPreference") || hasSignalMatch(signals.defenderTampering, "Add-MpPreference")) &&
    (hasSignalMatch(signals.defenderTampering, "DisableRealtimeMonitoring") ||
      hasSignalMatch(signals.defenderTampering, "ExclusionPath") ||
      hasSignalMatch(signals.defenderTampering, "ExclusionProcess"))
  ) {
    addFinding({
      id: "defender_tampering",
      severity: "high",
      category: "Defense Evasion",
      weight: 24,
      title: "Microsoft Defender tampering pattern",
      description: "The file appears to modify Defender preferences or exclusions in a way commonly used to reduce detection.",
      evidence: summarizeSignalMatches(signals.defenderTampering, 4)
    });
  }

  if (
    signals.browserDataTheft.length >= 3 ||
    (signals.browserDataTheft.length >= 2 && hasSignalMatch(signals.browserDataTheft, "DPAPI/Chromium decrypt"))
  ) {
    addFinding({
      id: "browser_data_theft",
      severity: "high",
      category: "Credential Access",
      weight: 22,
      title: "Browser credential or session theft pattern",
      description: "The file references browser credential stores together with decryption indicators associated with infostealer behavior.",
      evidence: summarizeSignalMatches(signals.browserDataTheft, 4)
    });
  }

  if (
    hasSignalMatch(signals.serviceInstall, "sc create") &&
    hasSignalMatch(signals.serviceInstall, "binPath") &&
    hasSignalMatch(signals.serviceInstall, "service autostart")
  ) {
    addFinding({
      id: "service_install_persistence",
      severity: "high",
      category: "Persistence",
      weight: 22,
      title: "Windows service installation pattern",
      description: "The file includes service creation details that can be used to establish persistence or privileged execution.",
      evidence: summarizeSignalMatches(signals.serviceInstall, 4)
    });
  }

  if (
    signals.encodedPayload.length >= 2 &&
    (signals.executionPrimitives.length > 0 || signals.downloadPrimitives.length > 0)
  ) {
    addFinding({
      id: "encoded_payload_stager",
      severity: "high",
      category: "Obfuscation",
      weight: 22,
      title: "Encoded payload staging pattern",
      description: "The file combines encoded or in-memory payload markers with execution or download behavior, which often indicates staged malware delivery.",
      evidence: buildEvidencePreview([
        summarizeSignalMatches(signals.encodedPayload, 3),
        summarizeSignalMatches(signals.executionPrimitives.length > 0 ? signals.executionPrimitives : signals.downloadPrimitives, 2)
      ], 4)
    });
  }

  if (
    hasSignalMatch(signals.rundll32Proxy, "rundll32") &&
    (hasSignalMatch(signals.rundll32Proxy, "dll export target") ||
      hasSignalMatch(signals.rundll32Proxy, "javascript/mshtml"))
  ) {
    addFinding({
      id: "rundll32_proxy_execution",
      severity: "high",
      category: "Proxy Execution",
      weight: 22,
      title: "Rundll32 proxy-execution pattern",
      description: "The file uses rundll32 with export or script-host style invocation patterns commonly abused for stealthy execution.",
      evidence: summarizeSignalMatches(signals.rundll32Proxy, 4)
    });
  }

  return {
    findings,
    matchedRules,
    signalCounts: Object.fromEntries(Object.entries(signals).map(([key, matches]) => [key, matches.length])),
    urlCount: urls.length
  };
}

function isArchiveExtension(extension) {
  return ARCHIVE_EXTENSIONS.has(extension) || extension === ".tgz";
}

function isTarMagic(buffer) {
  return buffer.length >= 265 && buffer.toString("utf8", 257, 262) === "ustar";
}

function inferArchiveChildNameFromGzip(fileName) {
  const safeName = path.basename(String(fileName || "").trim()) || "archive.gz";

  if (safeName.toLowerCase().endsWith(".tar.gz")) {
    return safeName.slice(0, -3);
  }

  if (safeName.toLowerCase().endsWith(".tgz")) {
    return `${safeName.slice(0, -4)}.tar`;
  }

  if (safeName.toLowerCase().endsWith(".gz")) {
    return safeName.slice(0, -3) || "decompressed.bin";
  }

  return `${safeName}.out`;
}

function normalizeArchiveEntryName(value) {
  const normalized = String(value || "")
    .replace(/\\/g, "/")
    .replace(/^\/+/, "")
    .trim();

  return normalized;
}

function isUnsafeArchiveEntryPath(entryName) {
  const normalized = normalizeArchiveEntryName(entryName);

  if (!normalized) {
    return true;
  }

  if (/^[A-Za-z]:/.test(normalized)) {
    return true;
  }

  return normalized.split("/").some((segment) => segment === "..");
}

function isArchiveDirectoryEntry(entryName, typeFlag = "") {
  return String(entryName || "").endsWith("/") || String(typeFlag || "") === "5";
}

function parseOctalInteger(value) {
  const normalized = String(value || "")
    .replace(/\0/g, "")
    .trim();

  if (!normalized) {
    return 0;
  }

  return Number.parseInt(normalized, 8);
}

function readZipEntriesFromCentralDirectory(buffer) {
  const minEocdSize = 22;
  const maxCommentSize = 0xffff;
  const startOffset = Math.max(0, buffer.length - (minEocdSize + maxCommentSize));
  let eocdOffset = -1;

  for (let index = buffer.length - minEocdSize; index >= startOffset; index -= 1) {
    if (buffer.readUInt32LE(index) === 0x06054b50) {
      eocdOffset = index;
      break;
    }
  }

  if (eocdOffset === -1) {
    return {
      status: "invalid",
      reason: "zip_end_of_central_directory_not_found",
      entries: []
    };
  }

  const totalEntries = buffer.readUInt16LE(eocdOffset + 10);
  const centralDirectorySize = buffer.readUInt32LE(eocdOffset + 12);
  const centralDirectoryOffset = buffer.readUInt32LE(eocdOffset + 16);

  if (centralDirectoryOffset + centralDirectorySize > buffer.length) {
    return {
      status: "invalid",
      reason: "zip_central_directory_out_of_bounds",
      entries: []
    };
  }

  const entries = [];
  const skipped = [];
  let offset = centralDirectoryOffset;

  while (offset + 46 <= buffer.length && entries.length + skipped.length < Math.max(totalEntries, MAX_ARCHIVE_ENTRIES)) {
    const signature = buffer.readUInt32LE(offset);
    if (signature !== 0x02014b50) {
      break;
    }

    const flags = buffer.readUInt16LE(offset + 8);
    const compressionMethod = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const fileNameLength = buffer.readUInt16LE(offset + 28);
    const extraFieldLength = buffer.readUInt16LE(offset + 30);
    const fileCommentLength = buffer.readUInt16LE(offset + 32);
    const localHeaderOffset = buffer.readUInt32LE(offset + 42);
    const fileNameStart = offset + 46;
    const fileNameEnd = fileNameStart + fileNameLength;

    if (fileNameEnd > buffer.length) {
      skipped.push({
        name: "(invalid entry)",
        reason: "zip_entry_name_out_of_bounds"
      });
      break;
    }

    const rawName = buffer.toString("utf8", fileNameStart, fileNameEnd);
    const entryName = normalizeArchiveEntryName(rawName);

    entries.push({
      entryName,
      flags,
      compressionMethod,
      compressedSize,
      uncompressedSize,
      localHeaderOffset,
      directory: isArchiveDirectoryEntry(entryName)
    });

    offset = fileNameEnd + extraFieldLength + fileCommentLength;
  }

  return {
    status: "completed",
    totalEntries,
    entries,
    skipped
  };
}

function resolveZipLocalFileData(buffer, entry) {
  const localHeaderOffset = Number(entry?.localHeaderOffset);
  if (!Number.isFinite(localHeaderOffset) || localHeaderOffset < 0 || localHeaderOffset + 30 > buffer.length) {
    return null;
  }

  if (buffer.readUInt32LE(localHeaderOffset) !== 0x04034b50) {
    return null;
  }

  const fileNameLength = buffer.readUInt16LE(localHeaderOffset + 26);
  const extraFieldLength = buffer.readUInt16LE(localHeaderOffset + 28);
  const dataOffset = localHeaderOffset + 30 + fileNameLength + extraFieldLength;
  const dataEnd = dataOffset + Number(entry.compressedSize || 0);

  if (dataOffset < 0 || dataEnd > buffer.length) {
    return null;
  }

  return {
    dataOffset,
    dataEnd
  };
}

function streamInflateBuffer(factory, input, outputLimit) {
  return new Promise((resolve, reject) => {
    const stream = factory();
    const chunks = [];
    let total = 0;

    const fail = (error) => {
      stream.destroy();
      reject(error);
    };

    stream.on("data", (chunk) => {
      total += chunk.length;
      if (total > outputLimit) {
        const error = new Error("Archive entry exceeds extraction limit.");
        error.code = "ARCHIVE_ENTRY_TOO_LARGE";
        fail(error);
        return;
      }
      chunks.push(chunk);
    });

    stream.on("error", reject);
    stream.on("end", () => resolve(Buffer.concat(chunks, total)));
    stream.end(input);
  });
}

async function inflateZipEntryData(compressedData, entry, outputLimit) {
  const method = Number(entry?.compressionMethod);

  if (method === 0) {
    if (compressedData.length > outputLimit) {
      const error = new Error("Stored archive entry exceeds extraction limit.");
      error.code = "ARCHIVE_ENTRY_TOO_LARGE";
      throw error;
    }
    return compressedData;
  }

  if (method === 8) {
    return streamInflateBuffer(() => zlib.createInflateRaw(), compressedData, outputLimit);
  }

  const error = new Error(`Unsupported ZIP compression method: ${method}`);
  error.code = "ZIP_METHOD_UNSUPPORTED";
  throw error;
}

function parseTarEntries(buffer) {
  const entries = [];
  let offset = 0;

  while (offset + 512 <= buffer.length && entries.length < MAX_ARCHIVE_ENTRIES) {
    const header = buffer.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      break;
    }

    const name = normalizeArchiveEntryName(header.toString("utf8", 0, 100).replace(/\0.*$/, ""));
    const prefix = normalizeArchiveEntryName(header.toString("utf8", 345, 500).replace(/\0.*$/, ""));
    const entryName = normalizeArchiveEntryName(prefix ? `${prefix}/${name}` : name);
    const typeFlag = header.toString("utf8", 156, 157);
    const size = parseOctalInteger(header.toString("utf8", 124, 136));
    const dataOffset = offset + 512;
    const nextOffset = dataOffset + Math.ceil(size / 512) * 512;

    if (dataOffset + size > buffer.length) {
      break;
    }

    entries.push({
      entryName,
      typeFlag,
      uncompressedSize: size,
      dataOffset,
      dataEnd: dataOffset + size,
      directory: isArchiveDirectoryEntry(entryName, typeFlag)
    });

    offset = nextOffset;
  }

  return entries;
}

async function gunzipWithLimit(buffer, outputLimit) {
  return streamInflateBuffer(() => zlib.createGunzip(), buffer, outputLimit);
}

async function inspectExtractedArchiveChildren({ entries, getEntryBuffer, scanDepth }) {
  const items = [];
  const skipped = [];
  let extractedItems = 0;
  let totalUncompressed = 0;

  for (const entry of entries) {
    const entryName = normalizeArchiveEntryName(entry?.entryName);
    const safeEntryName = entryName || "(unnamed entry)";

    if (entry?.directory) {
      skipped.push({ name: safeEntryName, reason: "directory" });
      continue;
    }

    if (!entryName) {
      skipped.push({ name: safeEntryName, reason: "empty_entry_name" });
      continue;
    }

    if (isUnsafeArchiveEntryPath(entryName)) {
      skipped.push({ name: safeEntryName, reason: "unsafe_entry_path" });
      continue;
    }

    const uncompressedSize = Number(entry?.uncompressedSize) || 0;
    if (uncompressedSize <= 0) {
      skipped.push({ name: safeEntryName, reason: "empty_entry" });
      continue;
    }

    if (uncompressedSize > MAX_ARCHIVE_ENTRY_UNCOMPRESSED_BYTES) {
      skipped.push({ name: safeEntryName, reason: "entry_too_large", uncompressedSize });
      continue;
    }

    if (extractedItems >= MAX_ARCHIVE_EXTRACT_ITEMS) {
      skipped.push({ name: safeEntryName, reason: "nested_item_limit_reached" });
      continue;
    }

    if (totalUncompressed + uncompressedSize > MAX_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES) {
      skipped.push({ name: safeEntryName, reason: "total_extraction_budget_exceeded", uncompressedSize });
      continue;
    }

    if (scanDepth >= MAX_ARCHIVE_SCAN_DEPTH) {
      skipped.push({ name: safeEntryName, reason: "nested_archive_depth_reached" });
      continue;
    }

    let entryBuffer;
    try {
      entryBuffer = await getEntryBuffer(entry);
    } catch (error) {
      skipped.push({ name: safeEntryName, reason: error?.code || "entry_extraction_failed" });
      continue;
    }

    const extension = path.extname(entryName).slice(0, 16) || ".bin";
    const tempPath = path.join(os.tmpdir(), `virovanta-archive-entry-${crypto.randomUUID()}${extension}`);

    try {
      await fsp.writeFile(tempPath, entryBuffer);
      const childReport = await scanUploadedFile({
        filePath: tempPath,
        originalName: path.basename(entryName),
        declaredMimeType: "application/octet-stream",
        scanDepth: scanDepth + 1
      });

      items.push({
        name: entryName,
        status: "completed",
        size: entryBuffer.length,
        sizeDisplay: humanFileSize(entryBuffer.length),
        verdict: childReport?.verdict || "clean",
        riskScore: Number(childReport?.riskScore) || 0,
        topFinding: childReport?.findings?.[0]?.title || "No notable findings"
      });
      extractedItems += 1;
      totalUncompressed += entryBuffer.length;
    } catch (error) {
      skipped.push({ name: safeEntryName, reason: error?.message || "nested_scan_failed" });
    } finally {
      await fsp.unlink(tempPath).catch(() => {});
    }
  }

  return {
    items,
    skipped,
    extractedItems,
    totalUncompressed
  };
}

async function inspectZipArchive({ analysisBuffer, scanDepth }) {
  const parsed = readZipEntriesFromCentralDirectory(analysisBuffer);
  if (parsed.status !== "completed") {
    return {
      status: parsed.status,
      reason: parsed.reason,
      findings: [],
      entries: [],
      nested: { items: [], skipped: [] }
    };
  }

  const entries = parsed.entries.slice(0, MAX_ARCHIVE_ENTRIES);
  const findings = [];
  const unsafeEntries = entries.filter((entry) => isUnsafeArchiveEntryPath(entry.entryName));
  if (unsafeEntries.length > 0) {
    findings.push({
      id: "archive_unsafe_paths",
      severity: "high",
      category: "Archive Structure",
      weight: 26,
      title: "Archive contains unsafe extraction paths",
      description: "Path traversal or absolute-style entry names can be used to write files outside the intended extraction directory.",
      evidence: buildEvidencePreview(unsafeEntries.map((entry) => entry.entryName), 4)
    });
  }

  const encryptedEntries = entries.filter((entry) => (Number(entry.flags) & 0x0001) === 0x0001);
  if (encryptedEntries.length > 0) {
    findings.push({
      id: "archive_encrypted_entries",
      severity: "medium",
      category: "Archive Visibility",
      weight: 14,
      title: "Archive contains encrypted entries",
      description: "Encrypted archive entries reduce static visibility and require manual review if the source is not trusted.",
      evidence: `${encryptedEntries.length} encrypted entr${encryptedEntries.length === 1 ? "y" : "ies"}`
    });
  }

  const unsupportedMethods = [...new Set(entries.map((entry) => Number(entry.compressionMethod)).filter((method) => ![0, 8].includes(method)))];
  if (unsupportedMethods.length > 0) {
    findings.push({
      id: "archive_unsupported_compression",
      severity: "medium",
      category: "Archive Visibility",
      weight: 12,
      title: "Archive uses unsupported compression methods",
      description: "Some entries could not be expanded because the archive uses methods outside the scanner's bounded extraction support.",
      evidence: unsupportedMethods.join(", ")
    });
  }

  const nested = await inspectExtractedArchiveChildren({
    entries,
    scanDepth,
    getEntryBuffer: async (entry) => {
      if ((Number(entry.flags) & 0x0001) === 0x0001) {
        const error = new Error("Encrypted entry not extracted.");
        error.code = "encrypted_entry";
        throw error;
      }

      const location = resolveZipLocalFileData(analysisBuffer, entry);
      if (!location) {
        const error = new Error("ZIP local header is invalid.");
        error.code = "invalid_local_header";
        throw error;
      }

      const compressedData = analysisBuffer.subarray(location.dataOffset, location.dataEnd);
      return inflateZipEntryData(compressedData, entry, MAX_ARCHIVE_ENTRY_UNCOMPRESSED_BYTES);
    }
  });

  return {
    status: "completed",
    findings,
    entries,
    nested
  };
}

async function inspectTarArchive({ buffer, scanDepth }) {
  const entries = parseTarEntries(buffer);
  const findings = [];

  const unsafeEntries = entries.filter((entry) => isUnsafeArchiveEntryPath(entry.entryName));
  if (unsafeEntries.length > 0) {
    findings.push({
      id: "archive_unsafe_paths",
      severity: "high",
      category: "Archive Structure",
      weight: 26,
      title: "Archive contains unsafe extraction paths",
      description: "Path traversal or absolute-style entry names can be used to write files outside the intended extraction directory.",
      evidence: buildEvidencePreview(unsafeEntries.map((entry) => entry.entryName), 4)
    });
  }

  const nested = await inspectExtractedArchiveChildren({
    entries,
    scanDepth,
    getEntryBuffer: async (entry) => buffer.subarray(entry.dataOffset, entry.dataEnd)
  });

  return {
    status: "completed",
    findings,
    entries,
    nested
  };
}

async function inspectArchiveFile({ filePath, originalName, extension, analysisBuffer, magicType, scanDepth }) {
  if (UNSUPPORTED_ARCHIVE_EXTENSIONS.has(extension)) {
    return {
      status: "unsupported",
      reason: "archive_format_not_supported",
      findings: [
        {
          id: "archive_format_unsupported",
          severity: "medium",
          category: "Archive Visibility",
          weight: 12,
          title: "Archive format is not expanded by the scanner",
          description: "This archive type is recognized, but bounded nested extraction is not available for it in the current runtime.",
          evidence: extension
        }
      ],
      entries: [],
      nested: { items: [], skipped: [] }
    };
  }

  if (magicType === "ZIP archive" || extension === ".zip" || extension === ".jar") {
    return inspectZipArchive({ analysisBuffer, scanDepth });
  }

  if (extension === ".tar" || isTarMagic(analysisBuffer)) {
    return inspectTarArchive({ buffer: analysisBuffer, scanDepth });
  }

  if (extension === ".gz" || extension === ".tgz") {
    const inflated = await gunzipWithLimit(analysisBuffer, MAX_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES);
    const inflatedName = inferArchiveChildNameFromGzip(originalName);

    if (extension === ".tgz" || inflatedName.toLowerCase().endsWith(".tar") || isTarMagic(inflated)) {
      const tarInspection = await inspectTarArchive({ buffer: inflated, scanDepth });
      return {
        ...tarInspection,
        containerName: inflatedName
      };
    }

    const nested = await inspectExtractedArchiveChildren({
      entries: [
        {
          entryName: inflatedName,
          uncompressedSize: inflated.length,
          directory: false
        }
      ],
      scanDepth,
      getEntryBuffer: async () => inflated
    });

    return {
      status: "completed",
      findings: [],
      entries: [
        {
          entryName: inflatedName,
          uncompressedSize: inflated.length,
          directory: false
        }
      ],
      nested
    };
  }

  return {
    status: "skipped",
    reason: "not_supported_archive_type",
    findings: [],
    entries: [],
    nested: { items: [], skipped: [] }
  };
}

function collectZipEntryNames(strings) {
  const entryNames = new Set();
  const patterns = [
    /(?:^|[^A-Za-z0-9._-])((?:\[[^\]]+\]|[A-Za-z0-9_.-]+)(?:\/[A-Za-z0-9_. -]+)+)/g,
    /(?:^|[^A-Za-z0-9._-])([A-Za-z0-9_. -]+\.(?:exe|dll|scr|js|jse|ps1|vbs|bat|cmd|lnk|hta|html|htm|docx|xlsx|xlsm|docm|zip|jar|iso))/gi
  ];

  for (const value of strings || []) {
    for (const pattern of patterns) {
      for (const match of value.matchAll(pattern)) {
        const normalized = String(match[1] || "")
          .trim()
          .replace(/^[/\\]+/, "")
          .replace(/[\\]+/g, "/");
        if (normalized) {
          entryNames.add(normalized);
        }
      }
    }
  }

  return [...entryNames].slice(0, 200);
}

function shouldReadStructuredBuffer({ extension, magicType, size }) {
  return (
    size > MAX_SAMPLE_BYTES &&
    size <= MAX_STRUCTURED_INSPECTION_BYTES &&
    (STRUCTURED_INSPECTION_EXTENSIONS.has(extension) ||
      magicType === "ZIP archive" ||
      magicType === "PDF document" ||
      magicType === "OLE compound document" ||
      magicType === "Windows shortcut")
  );
}

async function loadStructuredInspectionBuffer({ filePath, extension, magicType, size, sample }) {
  if (!shouldReadStructuredBuffer({ extension, magicType, size })) {
    return sample;
  }

  try {
    return await fsp.readFile(filePath);
  } catch {
    return sample;
  }
}

function analyzePdfContent({ textCorpus, findings }) {
  const normalizedText = textCorpus.toLowerCase();
  const hasJavascript = /\/javascript\b|\/js\b/.test(normalizedText);
  const hasOpenAction = /\/openaction\b|\/aa\b/.test(normalizedText);
  const hasLaunch = /\/launch\b/.test(normalizedText);
  const hasEmbeddedFile = /\/embeddedfile\b|\/filespec\b/.test(normalizedText);
  const hasRichMedia = /\/richmedia\b/.test(normalizedText);
  const submitTargets = [...textCorpus.matchAll(/\/submitform\b/gi)].length;

  if (hasJavascript || hasOpenAction) {
    findings.push({
      id: "pdf_active_content",
      severity: hasJavascript && hasOpenAction ? "high" : "medium",
      category: "PDF Actions",
      weight: hasJavascript && hasOpenAction ? 24 : 14,
      title: "PDF contains automatic or scripted actions",
      description: "PDF actions such as JavaScript or OpenAction can be abused to trigger code or risky viewer behavior when the document opens.",
      evidence: buildEvidencePreview(
        [
          hasJavascript ? "JavaScript object" : "",
          hasOpenAction ? "OpenAction/AA" : "",
          submitTargets > 0 ? `SubmitForm x${submitTargets}` : ""
        ],
        4
      )
    });
  }

  if (hasLaunch || hasRichMedia) {
    findings.push({
      id: "pdf_launch_or_rich_media",
      severity: "high",
      category: "PDF Actions",
      weight: 26,
      title: "PDF references launch or rich media features",
      description: "Launch actions and rich media objects are high-risk features that are uncommon in ordinary business PDFs.",
      evidence: buildEvidencePreview([hasLaunch ? "Launch action" : "", hasRichMedia ? "RichMedia object" : ""], 4)
    });
  }

  if (hasEmbeddedFile) {
    findings.push({
      id: "pdf_embedded_file",
      severity: "medium",
      category: "Embedded Content",
      weight: 16,
      title: "PDF contains embedded file references",
      description: "Embedded files can hide additional payloads inside an otherwise ordinary PDF document.",
      evidence: "EmbeddedFile / FileSpec markers present"
    });
  }
}

function analyzeOfficeOpenXml({ extension, zipEntryNames, textCorpus, findings }) {
  const lowerEntries = zipEntryNames.map((entry) => entry.toLowerCase());
  const hasMacroProject = lowerEntries.some((entry) => entry.endsWith("/vbaproject.bin") || entry === "vbaproject.bin");
  const hasExternalRelationships =
    lowerEntries.some((entry) => entry.includes("externallinks/")) ||
    /attachedtemplate|externallink|oleobject|ddeauto|mhtml:/i.test(textCorpus);
  const hasActiveContent =
    lowerEntries.some((entry) => entry.includes("activex") || entry.includes("embeddings/") || entry.includes("oleobject")) ||
    /activex|oleobject/i.test(textCorpus);

  if (hasMacroProject) {
    findings.push({
      id: "ooxml_macro_project",
      severity: extension.endsWith("x") ? "high" : "medium",
      category: "Office Macros",
      weight: extension.endsWith("x") ? 28 : 18,
      title: extension.endsWith("x") ? "Macro project found in macro-free Office container" : "Embedded Office macro project",
      description: extension.endsWith("x")
        ? "The package includes a VBA project even though the extension usually indicates a macro-free Office document."
        : "The Office package contains a VBA macro project.",
      evidence: buildEvidencePreview(zipEntryNames.filter((entry) => /vbaproject\.bin/i.test(entry)), 3) || "vbaProject.bin"
    });
  }

  if (hasExternalRelationships) {
    findings.push({
      id: "ooxml_external_relationships",
      severity: "medium",
      category: "External References",
      weight: 16,
      title: "Office package references external content",
      description: "External templates, links, or relationship targets can be abused for remote content retrieval or social-engineering delivery chains.",
      evidence:
        buildEvidencePreview(
          zipEntryNames.filter((entry) => /externallinks|_rels|oleobject/i.test(entry)),
          3
        ) || "External relationship markers"
    });
  }

  if (hasActiveContent) {
    findings.push({
      id: "ooxml_embedded_active_content",
      severity: "medium",
      category: "Embedded Content",
      weight: 16,
      title: "Office package includes embedded or ActiveX content",
      description: "Embedded OLE and ActiveX content raises the review priority for Office attachments.",
      evidence:
        buildEvidencePreview(
          zipEntryNames.filter((entry) => /activex|embeddings|oleobject/i.test(entry)),
          3
        ) || "Embedded/ActiveX package entries"
    });
  }
}

function analyzeLegacyOfficeDocument({ strings, findings }) {
  const lowerStrings = strings.map((value) => value.toLowerCase());
  const oleIndicators = ["ole10native", "objectpool", "equation.3", "package", "vba", "macros"];
  const matchedIndicators = oleIndicators.filter((indicator) => lowerStrings.some((value) => value.includes(indicator)));

  if (matchedIndicators.length > 0) {
    findings.push({
      id: "legacy_office_embedded_content",
      severity: "medium",
      category: "Embedded Content",
      weight: 18,
      title: "Legacy Office document contains embedded object indicators",
      description: "Older compound Office formats can hide macros or embedded payloads inside OLE object streams.",
      evidence: matchedIndicators.join(", ")
    });
  }
}

function analyzeArchiveContent({ zipEntryNames, findings }) {
  const lowerEntries = zipEntryNames.map((entry) => entry.toLowerCase());
  const riskyEntries = zipEntryNames.filter((entry) => HIGH_RISK_EXTENSIONS.has(path.extname(entry).toLowerCase()));
  const doubleExtensionEntries = zipEntryNames.filter((entry) => hasDoubleExtension(path.basename(entry)));

  if (riskyEntries.length > 0) {
    findings.push({
      id: "archive_risky_payloads",
      severity: "high",
      category: "Archive Contents",
      weight: 24,
      title: "Archive contains high-risk payload types",
      description: "Compressed payloads frequently hide scripts, shortcuts, and executables to evade simple attachment screening.",
      evidence: buildEvidencePreview(riskyEntries, 4)
    });
  }

  if (doubleExtensionEntries.length > 0) {
    findings.push({
      id: "archive_double_extension_payload",
      severity: "high",
      category: "Masquerading",
      weight: 26,
      title: "Archive contains double-extension payload names",
      description: "Files inside the archive are named to appear like documents or images before revealing an executable/script extension.",
      evidence: buildEvidencePreview(doubleExtensionEntries, 4)
    });
  }

  const hasShortcutAndPayload =
    lowerEntries.some((entry) => entry.endsWith(".lnk")) &&
    lowerEntries.some((entry) => /\.(?:js|jse|ps1|vbs|bat|cmd|hta|exe|dll|scr)$/i.test(entry));

  if (hasShortcutAndPayload) {
    findings.push({
      id: "archive_shortcut_dropper_chain",
      severity: "high",
      category: "Execution Chain",
      weight: 24,
      title: "Archive pairs shortcut files with executable or script content",
      description: "Shortcut-plus-script bundles are a common initial-access pattern used to launch a second-stage payload.",
      evidence: buildEvidencePreview(zipEntryNames.filter((entry) => /\.(?:lnk|js|jse|ps1|vbs|bat|cmd|hta|exe|dll|scr)$/i.test(entry)), 4)
    });
  }
}

function analyzeJavaScriptContent({ textCorpus, findings }) {
  const hasWsh = /(?:wscript\.shell|shell\.application|activexobject\s*\(\s*["']wscript\.shell["'])/i.test(textCorpus);
  const hasDownload =
    /(?:msxml2\.xmlhttp|xmlhttp|winhttprequest|adodb\.stream|download(?:file|string)?|savetofile|responsebody)/i.test(textCorpus);
  const hasExecution = /(?:\.run\s*\(|shellexecute|cmd\.exe|powershell(?:\.exe)?|mshta\b|rundll32\b)/i.test(textCorpus);

  if (hasWsh && hasDownload && hasExecution) {
    findings.push({
      id: "javascript_dropper_chain",
      severity: "critical",
      category: "Script Dropper",
      weight: 34,
      title: "JavaScript download-and-execute chain",
      description: "The script includes Windows Script Host and downloader components consistent with droppers.",
      evidence: buildEvidencePreview(["WScript/ActiveX", "XMLHTTP or WinHTTP", "ADODB or SaveToFile", "Run/ShellExecute"], 4)
    });
  } else if (hasWsh && (hasDownload || hasExecution)) {
    findings.push({
      id: "javascript_wsh_execution",
      severity: "high",
      category: "Execution",
      weight: 22,
      title: "JavaScript targets Windows Script Host execution",
      description: "Windows Script Host and ActiveX automation are frequently abused by Windows-based droppers.",
      evidence: buildEvidencePreview(["WScript/ActiveX", hasDownload ? "download primitive" : "", hasExecution ? "execution primitive" : ""], 4)
    });
  }
}

function analyzePowerShellContent({ textCorpus, findings }) {
  const hasDownload = /(?:invoke-webrequest|downloadstring|downloadfile|net\.webclient|start-bitstransfer)/i.test(textCorpus);
  const hasExecution = /(?:invoke-expression|\biex\b|\biex\s*\(|start-process|powershell(?:\.exe)?\s+-)/i.test(textCorpus);
  const hasBypass = /(?:-executionpolicy\s+bypass|set-executionpolicy\s+bypass|frombase64string|reflection\.assembly::load)/i.test(textCorpus);

  if (hasDownload && hasExecution) {
    findings.push({
      id: "powershell_dropper_chain",
      severity: "critical",
      category: "Script Dropper",
      weight: 36,
      title: "PowerShell download-and-execute chain",
      description: "The script combines download behavior with direct execution, which is strongly associated with malware delivery scripts.",
      evidence: buildEvidencePreview(["download primitive", "Invoke-Expression / Start-Process"], 4)
    });
  }

  if (hasBypass) {
    findings.push({
      id: "powershell_evasion_features",
      severity: "medium",
      category: "Defense Evasion",
      weight: 14,
      title: "PowerShell uses bypass or in-memory execution features",
      description: "Execution-policy bypass and in-memory loading are commonly used to reduce forensic visibility.",
      evidence: buildEvidencePreview(["ExecutionPolicy Bypass", "FromBase64String", "Assembly::Load"].filter((entry) => new RegExp(entry.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i").test(textCorpus)), 4)
    });
  }
}

function analyzeWindowsShortcut({ textCorpus, findings }) {
  const hasRemoteTarget = /(?:https?:\/\/|\\\\[A-Za-z0-9._$ -]+\\|ftp:\/\/)/i.test(textCorpus);
  const hasScriptInterpreter = /(?:powershell(?:\.exe)?|cmd\.exe|mshta\b|wscript(?:\.exe)?|cscript(?:\.exe)?|rundll32\b|regsvr32\b)/i.test(textCorpus);

  if (hasScriptInterpreter) {
    findings.push({
      id: "lnk_script_interpreter",
      severity: "high",
      category: "Shortcut Execution",
      weight: 24,
      title: "Shortcut references a script or LOLBin interpreter",
      description: "Shortcut files that invoke PowerShell, CMD, MSHTA, or similar interpreters are commonly weaponized.",
      evidence: buildEvidencePreview((textCorpus.match(/(?:powershell(?:\.exe)?|cmd\.exe|mshta\b|wscript(?:\.exe)?|cscript(?:\.exe)?|rundll32\b|regsvr32\b)/gi) || []), 4)
    });
  }

  if (hasRemoteTarget) {
    findings.push({
      id: "lnk_remote_target",
      severity: "high",
      category: "Shortcut Execution",
      weight: 24,
      title: "Shortcut references a remote target or network path",
      description: "Remote paths and URLs in shortcut targets are common in phishing and staged payload delivery.",
      evidence: buildEvidencePreview((textCorpus.match(/(?:https?:\/\/[^\s"'<>]+|\\\\[^\s"'<>]+)/gi) || []), 3)
    });
  }
}

function analyzeHtmlContent({ textCorpus, findings }) {
  const hasMetaRefresh = /<meta[^>]+http-equiv\s*=\s*["']?refresh["']?/i.test(textCorpus);
  const hasHiddenFrame = /<(?:iframe|frame)[^>]+(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*["']?0|height\s*=\s*["']?0)/i.test(textCorpus);
  const hasCredentialForm =
    /<input[^>]+type\s*=\s*["']?(?:password|email)["']?/i.test(textCorpus) &&
    /<form[^>]+action\s*=\s*["']https?:\/\//i.test(textCorpus);

  if (hasMetaRefresh) {
    findings.push({
      id: "html_meta_refresh_redirect",
      severity: "medium",
      category: "Redirection",
      weight: 14,
      title: "HTML file auto-redirects with meta refresh",
      description: "Meta refresh is often used in lure pages to bounce users toward a second-stage destination.",
      evidence: "meta http-equiv=refresh"
    });
  }

  if (hasHiddenFrame) {
    findings.push({
      id: "html_hidden_frame",
      severity: "medium",
      category: "Hidden Content",
      weight: 14,
      title: "HTML contains hidden frame content",
      description: "Hidden frames can be used to load remote content or conceal staged activity from the user.",
      evidence: "Hidden iframe/frame markers"
    });
  }

  if (hasCredentialForm) {
    findings.push({
      id: "html_external_credential_form",
      severity: "high",
      category: "Credential Capture",
      weight: 24,
      title: "HTML file contains credential form posting to an external target",
      description: "Password or email collection forms that submit to external URLs are a strong phishing signal in standalone HTML attachments.",
      evidence: buildEvidencePreview((textCorpus.match(/<form[^>]+action\s*=\s*["']https?:\/\/[^"']+/gi) || []), 2)
    });
  }
}

function analyzeStructuredFileType({
  extension,
  magicType,
  detectedMimeType,
  analysisBuffer,
  baseStrings
}) {
  const findings = [];
  const utf16Strings = extractUtf16Strings(analysisBuffer);
  const strings = combineExtractedStrings(baseStrings, utf16Strings);
  const textCorpus = `${analysisBuffer.toString("latin1", 0, Math.min(analysisBuffer.length, MAX_STRUCTURED_INSPECTION_BYTES))}\n${strings.join("\n")}`;
  const zipEntryNames =
    magicType === "ZIP archive" || ARCHIVE_EXTENSIONS.has(extension) || OFFICE_OPEN_XML_EXTENSIONS.has(extension)
      ? collectZipEntryNames(strings)
      : [];

  if (magicType === "PDF document" || extension === ".pdf") {
    analyzePdfContent({ textCorpus, findings });
  }

  if (OFFICE_OPEN_XML_EXTENSIONS.has(extension)) {
    analyzeOfficeOpenXml({ extension, zipEntryNames, textCorpus, findings });
  }

  if (LEGACY_OFFICE_EXTENSIONS.has(extension) || magicType === "OLE compound document") {
    analyzeLegacyOfficeDocument({ strings, findings });
  }

  if (ARCHIVE_EXTENSIONS.has(extension) || magicType === "ZIP archive") {
    analyzeArchiveContent({ zipEntryNames, findings });
  }

  if (extension === ".js" || extension === ".jse") {
    analyzeJavaScriptContent({ textCorpus, findings });
  }

  if (extension === ".ps1") {
    analyzePowerShellContent({ textCorpus, findings });
  }

  if (magicType === "Windows shortcut" || extension === ".lnk") {
    analyzeWindowsShortcut({ textCorpus, findings });
  }

  if (HTML_EXTENSIONS.has(extension) || extension === ".hta" || detectedMimeType.includes("html")) {
    analyzeHtmlContent({ textCorpus, findings });
  }

  return {
    findings,
    zipEntryNames,
    inspectedBytes: analysisBuffer.length,
    extractedStringCount: strings.length,
    strings,
    textCorpus
  };
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

async function runVirusTotalLookup(sha256Hash) {
  if (!config.virusTotalApiKey) {
    return {
      status: "disabled",
      detail: "External hash-reputation source is not configured."
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
        detail: "Hash was not present in the configured external reputation corpus."
      };
    }

    if (!response.ok) {
      return {
        status: "error",
        detail: `External reputation HTTP ${response.status}.`
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
      detail: "External hash-reputation intelligence available.",
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
        detail: "External reputation lookup timed out."
      };
    }

    return {
      status: "error",
      detail: error?.message || "External reputation lookup failed."
    };
  } finally {
    clearTimeout(timeout);
  }
}

function hasExternalBenignCoverage(engines) {
  return (
    engines.clamav.status === "clean" ||
    (engines.virustotal.status === "found" &&
      Number(engines.virustotal.malicious || 0) === 0 &&
      Number(engines.virustotal.suspicious || 0) === 0)
  );
}

function assessLowConfidenceVerdict({
  riskScore,
  findings,
  engines,
  detectedMimeType,
  detectedFileType,
  magicType,
  printableRatio,
  extension
}) {
  if (findings.length > 0 || riskScore > 0) {
    return {
      verdict: "unknown",
      confidence: "low",
      reason: "Weak indicators were found, but the current evidence is not strong enough to confirm malicious behavior."
    };
  }

  const hasRecognizedIdentity =
    magicType !== null ||
    detectedMimeType !== "unknown" ||
    (detectedFileType && detectedFileType !== "unknown");
  const looksLikePlainText = printableRatio >= 0.92 && !HIGH_RISK_EXTENSIONS.has(extension);

  if (!hasRecognizedIdentity && !looksLikePlainText && !hasExternalBenignCoverage(engines)) {
    return {
      verdict: "unknown",
      confidence: "low",
      reason: "The scan did not surface strong malicious signals, but file identity and reputation coverage are too limited to call this clean."
    };
  }

  return {
    verdict: "clean",
    confidence: hasExternalBenignCoverage(engines) ? "high" : "medium",
    reason: "No strong indicators were detected in the current scan coverage."
  };
}

function determineVerdictAssessment(context) {
  const riskProfile = context.riskProfile || buildRiskProfile(context.findings);
  const findingIds = new Set((context.findings || []).map((finding) => String(finding?.id || "").trim()));
  const severityCounts = riskProfile.severityCounts;
  const classCounts = riskProfile.classCounts;
  const hasTrustedDetection = riskProfile.trustedDetectionCount > 0;
  const hasStandaloneMaliciousSignal = [...findingIds].some((findingId) => STANDALONE_MALICIOUS_FINDING_IDS.has(findingId));
  const hasCorroboratedCriticalSignals =
    severityCounts.critical >= 2 && riskProfile.uniqueCategoryCount >= 2;
  const hasStrongCorroboration =
    classCounts.strong >= 2 && riskProfile.uniqueCategoryCount >= 2;
  const hasCriticalWithFollowOnSignals =
    severityCounts.critical >= 1 && (classCounts.strong >= 2 || classCounts.moderate >= 2);
  const hasSuspiciousCorroboration =
    riskProfile.standaloneSuspiciousCount > 0 ||
    (riskProfile.score >= 40 && (classCounts.strong >= 1 || classCounts.moderate >= 2)) ||
    (riskProfile.score >= 30 && classCounts.strong >= 2) ||
    (riskProfile.score >= 28 && classCounts.moderate >= 2);

  if (hasTrustedDetection) {
    return {
      verdict: "malicious",
      confidence: "high",
      reason: "Trusted malware-reputation detections strongly corroborated the file as malicious."
    };
  }

  if (hasStandaloneMaliciousSignal && riskProfile.score >= 28) {
    return {
      verdict: "malicious",
      confidence: "high",
      reason: "A high-confidence proxy-execution technique was observed that is strongly associated with malicious code delivery."
    };
  }

  if (
    hasCorroboratedCriticalSignals ||
    (riskProfile.score >= 72 && hasStrongCorroboration) ||
    (riskProfile.score >= 58 && hasCriticalWithFollowOnSignals)
  ) {
    return {
      verdict: "malicious",
      confidence: "high",
      reason: "Multiple independent high-confidence signals aligned on malicious behavior."
    };
  }

  if (hasSuspiciousCorroboration) {
    return {
      verdict: "suspicious",
      confidence: riskProfile.score >= 55 ? "high" : "medium",
      reason: "Risk signals were meaningful enough to warrant manual review, but the evidence was not strong enough to call the file malicious."
    };
  }

  return assessLowConfidenceVerdict({
    ...context,
    riskScore: riskProfile.score
  });
}

function buildPlainLanguageReasons({ verdict, findings, classification, confidence }) {
  const topFindingReasons = Array.isArray(findings)
    ? findings
        .slice(0, 4)
        .map((finding) => String(finding?.description || "").trim())
        .filter(Boolean)
    : [];

  const confidenceSummary = String(confidence?.summary || "").trim();

  if (topFindingReasons.length > 0) {
    return [confidenceSummary, ...topFindingReasons].filter(Boolean).slice(0, 5);
  }

  if (verdict === "clean") {
    return [confidenceSummary,
      "No strong indicators were found in this scan.",
      "This is a first-pass result based on current scan coverage, not a guarantee that the file is safe."
    ].filter(Boolean);
  }

  if (verdict === "unknown") {
    return [confidenceSummary,
      String(classification?.reason || "The scan was inconclusive.").trim(),
      "Treat the file as untrusted until deeper analysis or sandbox review confirms it is benign."
    ].filter(Boolean);
  }

  return [confidenceSummary, String(classification?.reason || "This scan requires analyst review.").trim()].filter(Boolean);
}

function buildRecommendations({ verdict, findings, engines, extension, entropy }) {
  const recommendations = [];

  if (verdict === "malicious" || verdict === "suspicious") {
    recommendations.push("Quarantine the file and avoid opening it on production systems.");
    recommendations.push("Run the sample in an isolated sandbox VM before any manual inspection.");
  }

  if (verdict === "unknown") {
    recommendations.push("Treat this result as inconclusive until the sample is reviewed with deeper tooling or sandbox detonation.");
    recommendations.push("Avoid opening the file on production endpoints until additional evidence confirms it is benign.");
  }

  if (findings.some((finding) => finding.category === "Obfuscation") || entropy >= 7.2) {
    recommendations.push(
      ["clean", "matched"].includes(engines.yara?.status || "")
        ? "Perform deeper static analysis and string deobfuscation."
        : "Perform deeper static analysis, including rule-pack execution and string deobfuscation."
    );
  }

  if (engines.yara?.status === "unavailable" || engines.yara?.status === "misconfigured") {
    recommendations.push("Install or repair YARA rule-pack execution so curated hunt rules can enrich file verdicts.");
  }

  if (engines.clamav.status === "unavailable" || engines.clamav?.definitions?.status === "missing") {
    recommendations.push("Install ClamAV and keep definitions updated for stronger signature coverage.");
  }

  if (engines.clamav?.definitions?.status === "stale") {
    recommendations.push("Refresh ClamAV definitions before relying on signature-only clean results.");
  }

  if (engines.virustotal.status === "disabled") {
    recommendations.push("Connect an external hash-reputation source if you want added reputation corroboration by file hash.");
  }

  if (isArchiveExtension(extension) || extension === ".tar") {
    recommendations.push("Enable archive-unpacking scans in a sandbox to inspect embedded payloads.");
  }

  if (findings.some((finding) => String(finding.id || "").startsWith("archive_nested_"))) {
    recommendations.push("Review extracted archive members individually before opening the archive on user workstations.");
  }

  if (recommendations.length === 0) {
    recommendations.push("No strong indicators were found in this pass, but continue normal endpoint protections and standard verification controls.");
  }

  if (verdict === "clean") {
    recommendations.push("Treat this as a first-pass clean result, not a guarantee that the file is safe in every environment.");
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
  const patternCorpus = `${sampleText}\n${extractedStrings.join("\n")}`.slice(0, 2_000_000);

  let rawRiskScore = 0;
  const findings = [];
  const matchedRules = [];
  const analysisBuffer = await loadStructuredInspectionBuffer({
    filePath,
    extension,
    magicType,
    size,
    sample
  });
  const structuredAnalysis = analyzeStructuredFileType({
    extension,
    magicType,
    detectedMimeType,
    analysisBuffer,
    baseStrings: extractedStrings
  });
  const staticRuleAnalysis = analyzeCompositeStaticRules({
    textCorpus: `${patternCorpus}\n${structuredAnalysis.textCorpus}\n${safeOriginalName}`,
    extension,
    originalName: safeOriginalName
  });
  const archiveInspection =
    isArchiveExtension(extension) || extension === ".tar" || magicType === "ZIP archive" || isTarMagic(analysisBuffer)
      ? await inspectArchiveFile({
          filePath,
          originalName: safeOriginalName,
          extension,
          analysisBuffer,
          magicType,
          scanDepth
        })
      : {
          status: "skipped",
          reason: "not_archive",
          findings: [],
          entries: [],
          nested: { items: [], skipped: [] }
        };

  if (HIGH_RISK_EXTENSIONS.has(extension)) {
    rawRiskScore += pushFinding(findings, {
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
    rawRiskScore += pushFinding(findings, {
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
    rawRiskScore += pushFinding(findings, {
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
    rawRiskScore += pushFinding(findings, {
      id: "high_entropy",
      severity: "medium",
      category: "Obfuscation",
      weight: 14,
      title: "High entropy sample",
      description: "High entropy suggests packed, encrypted, or obfuscated content.",
      evidence: `Entropy ${entropy}`
    });
  }

  for (const rule of PATTERN_RULES) {
    const match = patternCorpus.match(rule.regex);

    if (!match) {
      continue;
    }

    matchedRules.push(rule.id);
    rawRiskScore += pushFinding(findings, {
      id: rule.id,
      severity: rule.severity,
      category: rule.category,
      weight: rule.weight,
      title: rule.title,
      description: rule.description,
      evidence: match[0].slice(0, 160)
    });
  }

  for (const finding of staticRuleAnalysis.findings) {
    rawRiskScore += pushFinding(findings, finding);
  }

  if (magicType === "Portable Executable (PE)" && DOCUMENT_EXTENSIONS.has(extension)) {
    rawRiskScore += pushFinding(findings, {
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
    rawRiskScore += pushFinding(findings, {
      id: "unknown_binary_payload",
      severity: "medium",
      category: "Binary",
      weight: 12,
      title: "Unknown binary payload",
      description: "Binary file has low textual content and no recognized signature.",
      evidence: `Printable ratio ${printableRatio}`
    });
  }

  for (const finding of structuredAnalysis.findings) {
    rawRiskScore += pushFinding(findings, finding);
  }

  for (const finding of archiveInspection.findings || []) {
    const existing = findings.find((entry) => entry.id === finding.id);
    if (existing) {
      if (!existing.evidence && finding.evidence) {
        existing.evidence = finding.evidence;
      }
      continue;
    }

    rawRiskScore += pushFinding(findings, finding);
  }

  const archiveNestedItems = Array.isArray(archiveInspection?.nested?.items) ? archiveInspection.nested.items : [];
  const archiveMaliciousCount = archiveNestedItems.filter((item) => item?.verdict === "malicious").length;
  const archiveSuspiciousCount = archiveNestedItems.filter((item) => item?.verdict === "suspicious").length;
  const archiveUnknownCount = archiveNestedItems.filter((item) => item?.verdict === "unknown").length;

  if (archiveMaliciousCount > 0) {
    rawRiskScore += pushFinding(findings, {
      id: "archive_nested_malicious",
      severity: "critical",
      category: "Archive Contents",
      weight: 36,
      title: "Archive contains malicious nested content",
      description: "One or more extracted files inside the archive were classified as malicious.",
      evidence: `${archiveMaliciousCount}/${archiveNestedItems.length} extracted items`
    });
  } else if (archiveSuspiciousCount > 0) {
    rawRiskScore += pushFinding(findings, {
      id: "archive_nested_suspicious",
      severity: "high",
      category: "Archive Contents",
      weight: 24,
      title: "Archive contains suspicious nested content",
      description: "One or more extracted files inside the archive triggered high-risk findings during nested inspection.",
      evidence: `${archiveSuspiciousCount}/${archiveNestedItems.length} extracted items`
    });
  } else if (archiveUnknownCount > 0) {
    rawRiskScore += pushFinding(findings, {
      id: "archive_nested_inconclusive",
      severity: "medium",
      category: "Archive Contents",
      weight: 14,
      title: "Archive contains inconclusive nested content",
      description: "Nested items inside the archive could not be confidently classified as clean and should be reviewed before use.",
      evidence: `${archiveUnknownCount}/${archiveNestedItems.length} extracted items`
    });
  }

  const archiveSkippedCount = Array.isArray(archiveInspection?.nested?.skipped) ? archiveInspection.nested.skipped.length : 0;
  if (archiveSkippedCount > 0) {
    rawRiskScore += pushFinding(findings, {
      id: "archive_nested_items_skipped",
      severity: "low",
      category: "Archive Visibility",
      weight: 6,
      title: "Some archive entries were not expanded",
      description: "The scanner skipped some nested archive items because of format limits, size caps, depth limits, or unsafe paths.",
      evidence: `${archiveSkippedCount} skipped entr${archiveSkippedCount === 1 ? "y" : "ies"}`
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
      rawRiskScore += pushFinding(findings, finding);
    }
  }

  const yara = await runYaraScan(filePath, config);
  if (yara.status === "matched") {
    const matchedRuleCount = Array.isArray(yara.matchedRules) ? yara.matchedRules.length : 0;
    rawRiskScore += pushFinding(findings, {
      id: "yara_rule_match",
      severity: matchedRuleCount >= 3 ? "critical" : "high",
      category: "Signature Rules",
      weight: matchedRuleCount >= 3 ? 30 : 22,
      title: matchedRuleCount >= 3 ? "Multiple YARA rules matched" : "YARA rule matched",
      description:
        matchedRuleCount >= 3
          ? "Several YARA rules matched this file, which increases the likelihood that it overlaps with known malware or curated hunting logic."
          : "A YARA rule matched this file, which means it shares traits with known malware or analyst-authored hunt logic.",
      evidence: (yara.matchedRules || []).slice(0, 6).join(" | ")
    });
  }

  const clamav = await runClamAvScan(filePath, config);
  if (clamav.status === "infected") {
    rawRiskScore += pushFinding(findings, {
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

    rawRiskScore += pushFinding(findings, {
      id: "external_reputation_detections",
      severity,
      category: "Reputation",
      weight: virustotal.malicious > 2 ? 36 : 24,
      title: "External reputation detections",
      description: "External reputation engines reported suspicious or malicious detections.",
      evidence: `${virustotal.malicious} malicious / ${virustotal.suspicious} suspicious`
    });
  }

  const sortedFindings = sortFindings(findings);
  const riskProfile = buildRiskProfile(sortedFindings);
  const boundedRiskScore = riskProfile.score;

  const engines = {
    heuristics: {
      status: "completed",
      matchedRules,
      findingCount: sortedFindings.length
    },
    staticRules: {
      status: "completed",
      matchedRules: staticRuleAnalysis.matchedRules,
      urlCount: staticRuleAnalysis.urlCount,
      signalCounts: staticRuleAnalysis.signalCounts
    },
    fileTypeHeuristics: {
      status: "completed",
      inspectedBytes: structuredAnalysis.inspectedBytes,
      zipEntryCount: structuredAnalysis.zipEntryNames.length,
      extractedStringCount: structuredAnalysis.extractedStringCount
    },
    archiveInspection: {
      status: archiveInspection.status,
      reason: archiveInspection.reason || null,
      entryCount: Array.isArray(archiveInspection.entries) ? archiveInspection.entries.length : 0,
      extractedItemCount: archiveNestedItems.length,
      skippedItemCount: archiveSkippedCount,
      items: archiveNestedItems,
      skipped: archiveInspection?.nested?.skipped || []
    },
    riskScoring: {
      status: "completed",
      score: riskProfile.score,
      rawWeight: riskProfile.rawWeight,
      preNormalizedWeightSum: Math.max(0, Math.min(100, Math.round(rawRiskScore))),
      strongSignalCount: riskProfile.classCounts.strong,
      moderateSignalCount: riskProfile.classCounts.moderate,
      weakSignalCount: riskProfile.classCounts.weak,
      uniqueCategoryCount: riskProfile.uniqueCategoryCount,
      standaloneSuspiciousCount: riskProfile.standaloneSuspiciousCount,
      trustedDetectionCount: riskProfile.trustedDetectionCount,
      severityCounts: riskProfile.severityCounts
    },
    email,
    yara,
    clamav,
    externalReputation: virustotal,
    virustotal
  };

  const classification = determineVerdictAssessment({
    riskScore: boundedRiskScore,
    findings: sortedFindings,
    engines,
    riskProfile,
    detectedMimeType,
    detectedFileType: detectedType?.ext || "unknown",
    magicType,
    printableRatio,
    extension
  });
  const verdict = classification.verdict;
  const confidence = buildConfidenceAssessment({
    verdict,
    classification,
    findings: sortedFindings,
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
    engines,
    structuredAnalysis,
    archiveInspection,
    archiveSkippedCount
  });
  const enrichedFindings = enrichFindings(sortedFindings);
  const technicalIndicators = buildTechnicalIndicators({
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
    safeOriginalName,
    structuredAnalysis,
    staticRuleAnalysis,
    archiveInspection,
    findings: enrichedFindings,
    matchedRules,
    confidence,
    declaredMimeType: declaredMimeType || "unknown"
  });
  engines.classification = {
    status: "completed",
    confidence: classification.confidence,
    score: confidence.score,
    summary: confidence.summary,
    factors: confidence.factors,
    reason: classification.reason
  };

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
    findings: enrichedFindings,
    confidence,
    plainLanguageReasons: buildPlainLanguageReasons({
      verdict,
      findings: enrichedFindings,
      classification,
      confidence
    }),
    technicalIndicators,
    engines,
    recommendations: buildRecommendations({
      verdict,
      findings: enrichedFindings,
      engines,
      extension,
      entropy
    })
  };

  return report;
}
