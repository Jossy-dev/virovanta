const MAX_IOCS_PER_TYPE = 50;

const URL_REGEX = /\bhttps?:\/\/[^\s"'<>`]+/gi;
const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const EMAIL_REGEX = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,24}\b/gi;
const DOMAIN_REGEX = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;

const ATTACK_TECHNIQUES_BY_FINDING = Object.freeze({
  encoded_powershell: [
    {
      id: "T1059.001",
      name: "PowerShell",
      tactic: "Execution"
    }
  ],
  invoke_expression: [
    {
      id: "T1059.001",
      name: "PowerShell",
      tactic: "Execution"
    }
  ],
  living_off_the_land: [
    {
      id: "T1218",
      name: "System Binary Proxy Execution",
      tactic: "Defense Evasion"
    }
  ],
  obfuscated_javascript: [
    {
      id: "T1027",
      name: "Obfuscated/Compressed Files and Information",
      tactic: "Defense Evasion"
    }
  ],
  long_base64_blob: [
    {
      id: "T1027",
      name: "Obfuscated/Compressed Files and Information",
      tactic: "Defense Evasion"
    }
  ],
  ransomware_commands: [
    {
      id: "T1490",
      name: "Inhibit System Recovery",
      tactic: "Impact"
    }
  ],
  crypto_miner: [
    {
      id: "T1496",
      name: "Resource Hijacking",
      tactic: "Impact"
    }
  ],
  double_extension: [
    {
      id: "T1036",
      name: "Masquerading",
      tactic: "Defense Evasion"
    }
  ],
  type_mismatch: [
    {
      id: "T1036",
      name: "Masquerading",
      tactic: "Defense Evasion"
    }
  ],
  macro_enabled_document: [
    {
      id: "T1204.002",
      name: "User Execution: Malicious File",
      tactic: "Execution"
    }
  ],
  high_risk_extension: [
    {
      id: "T1204",
      name: "User Execution",
      tactic: "Execution"
    }
  ],
  unknown_binary_payload: [
    {
      id: "T1027",
      name: "Obfuscated/Compressed Files and Information",
      tactic: "Defense Evasion"
    }
  ]
});

function uniqueSorted(values) {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function normalizeIndicator(value) {
  return String(value || "")
    .trim()
    .replace(/[)\]}>,.;:!?]+$/g, "")
    .toLowerCase();
}

function collectTextCorpus(report) {
  const chunks = [];

  for (const finding of report?.findings || []) {
    chunks.push(finding?.title || "", finding?.description || "", finding?.evidence || "");
  }

  for (const recommendation of report?.recommendations || []) {
    chunks.push(recommendation || "");
  }

  chunks.push(
    report?.file?.originalName || "",
    report?.file?.detectedMimeType || "",
    report?.file?.magicType || "",
    report?.engines?.clamav?.detail || "",
    report?.engines?.virustotal?.detail || ""
  );

  return chunks
    .map((value) => String(value || "").trim())
    .filter(Boolean)
    .join("\n");
}

function cloneRegex(regex) {
  return new RegExp(regex.source, regex.flags);
}

function extractRegexMatches(text, regex, normalizer = normalizeIndicator) {
  if (!text) {
    return [];
  }

  return [...text.matchAll(cloneRegex(regex))]
    .map((match) => normalizer(match[0]))
    .filter(Boolean)
    .slice(0, MAX_IOCS_PER_TYPE * 4);
}

function extractIocs(report) {
  const hashes = [];
  const reportHashes = report?.file?.hashes || {};
  const pushHash = (algorithm, value) => {
    const normalized = String(value || "").trim().toLowerCase();
    if (!normalized) {
      return;
    }

    hashes.push({
      type: algorithm,
      value: normalized
    });
  };

  pushHash("md5", reportHashes.md5);
  pushHash("sha1", reportHashes.sha1);
  pushHash("sha256", reportHashes.sha256);

  const textCorpus = collectTextCorpus(report);
  const urls = uniqueSorted(extractRegexMatches(textCorpus, URL_REGEX)).slice(0, MAX_IOCS_PER_TYPE);
  const ips = uniqueSorted(extractRegexMatches(textCorpus, IPV4_REGEX)).slice(0, MAX_IOCS_PER_TYPE);
  const emails = uniqueSorted(extractRegexMatches(textCorpus, EMAIL_REGEX)).slice(0, MAX_IOCS_PER_TYPE);

  const strippedText = textCorpus.replace(cloneRegex(URL_REGEX), " ").replace(cloneRegex(EMAIL_REGEX), " ");
  const domains = uniqueSorted(extractRegexMatches(strippedText, DOMAIN_REGEX))
    .filter((candidate) => !ips.includes(candidate))
    .slice(0, MAX_IOCS_PER_TYPE);

  return {
    total: hashes.length + urls.length + domains.length + ips.length + emails.length,
    hashes,
    urls,
    domains,
    ips,
    emails
  };
}

function mapMitreAttackTechniques(report) {
  const techniquesById = new Map();

  for (const finding of report?.findings || []) {
    const findingId = String(finding?.id || "").trim();
    if (!findingId) {
      continue;
    }

    const mappings = ATTACK_TECHNIQUES_BY_FINDING[findingId] || [];
    for (const mapping of mappings) {
      const current = techniquesById.get(mapping.id) || {
        ...mapping,
        sourceFindingIds: []
      };

      if (!current.sourceFindingIds.includes(findingId)) {
        current.sourceFindingIds.push(findingId);
      }

      techniquesById.set(mapping.id, current);
    }
  }

  const techniques = [...techniquesById.values()]
    .map((entry) => ({
      ...entry,
      sourceFindingIds: [...entry.sourceFindingIds].sort((left, right) => left.localeCompare(right))
    }))
    .sort((left, right) => left.id.localeCompare(right.id));

  return {
    framework: "MITRE ATT&CK",
    version: "v14",
    tacticCount: uniqueSorted(techniques.map((item) => item.tactic)).length,
    techniqueCount: techniques.length,
    tactics: uniqueSorted(techniques.map((item) => item.tactic)),
    techniques
  };
}

export function enrichReportThreatIntel(report) {
  return {
    iocs: extractIocs(report),
    attackMapping: mapMitreAttackTechniques(report)
  };
}
