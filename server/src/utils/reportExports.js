function sanitizeFileComponent(value, fallback = "report") {
  const normalized = String(value || "")
    .trim()
    .replace(/[^a-zA-Z0-9._-]+/g, "_")
    .replace(/^_+|_+$/g, "");

  return normalized || fallback;
}

function csvCell(value) {
  const normalized = value == null ? "" : typeof value === "object" ? JSON.stringify(value) : String(value);
  if (/[",\n]/.test(normalized)) {
    return `"${normalized.replace(/"/g, "\"\"")}"`;
  }

  return normalized;
}

function createCsv(rows) {
  return rows.map((row) => row.map(csvCell).join(",")).join("\n");
}

function buildFindingRows(report) {
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  if (findings.length === 0) {
    return [["summary", "No findings", "", "", ""]];
  }

  return findings.map((finding, index) => [
    index + 1,
    finding?.severity || "info",
    finding?.title || "",
    finding?.description || "",
    finding?.indicator || ""
  ]);
}

function buildIndicatorRows(report) {
  const indicators = [];
  const iocs = report?.iocs || {};

  for (const url of Array.isArray(iocs.urls) ? iocs.urls : []) {
    indicators.push({
      type: "url",
      value: url
    });
  }

  for (const domain of Array.isArray(iocs.domains) ? iocs.domains : []) {
    indicators.push({
      type: "domain",
      value: domain
    });
  }

  for (const hash of Array.isArray(iocs.hashes) ? iocs.hashes : []) {
    indicators.push({
      type: "hash",
      value: hash
    });
  }

  return indicators;
}

function buildIndicatorStixObjects(report) {
  const indicators = buildIndicatorRows(report);
  const created = report?.completedAt || report?.createdAt || new Date().toISOString();

  return indicators.map((indicator, index) => {
    let pattern = "";
    if (indicator.type === "url") {
      pattern = `[url:value = '${String(indicator.value).replace(/'/g, "\\'")}']`;
    } else if (indicator.type === "domain") {
      pattern = `[domain-name:value = '${String(indicator.value).replace(/'/g, "\\'")}']`;
    } else {
      pattern = `[file:hashes.'SHA-256' = '${String(indicator.value).replace(/'/g, "\\'")}']`;
    }

    return {
      type: "indicator",
      spec_version: "2.1",
      id: `indicator--${sanitizeFileComponent(report?.id || "report")}-${index + 1}`,
      created,
      modified: created,
      name: `${String(indicator.type || "indicator").toUpperCase()} extracted from ${report?.id || "report"}`,
      description: `Indicator extracted from ${report?.sourceType || "scan"} report ${report?.id || ""}.`,
      indicator_types: ["malicious-activity"],
      pattern_type: "stix",
      pattern,
      labels: ["virovanta", `verdict:${report?.verdict || "unknown"}`]
    };
  });
}

export function buildReportExportFilename(report, extension) {
  const base = sanitizeFileComponent(report?.fileName || report?.file?.originalName || report?.id || "report");
  return `${base}.${extension}`;
}

export function buildReportJsonExport(report, extras = {}) {
  return {
    report,
    exportedAt: new Date().toISOString(),
    ...extras
  };
}

export function buildReportCsvExport(report) {
  const rows = [
    ["field", "value"],
    ["report_id", report?.id || ""],
    ["source_type", report?.sourceType || ""],
    ["verdict", report?.verdict || ""],
    ["risk_score", report?.riskScore ?? ""],
    ["target", report?.fileName || report?.url?.final || report?.url?.input || report?.file?.originalName || ""],
    ["completed_at", report?.completedAt || ""],
    ["plain_language_reasons", (Array.isArray(report?.plainLanguageReasons) ? report.plainLanguageReasons : []).join(" | ")],
    ["recommendations", (Array.isArray(report?.recommendations) ? report.recommendations : []).join(" | ")]
  ];

  const findingRows = [["finding_index", "severity", "title", "description", "indicator"], ...buildFindingRows(report)];
  const indicatorRows = [
    ["indicator_type", "value"],
    ...buildIndicatorRows(report).map((indicator) => [indicator.type, indicator.value])
  ];

  return [createCsv(rows), "", createCsv(findingRows), "", createCsv(indicatorRows)].join("\n");
}

export function buildReportStixExport(report) {
  const created = report?.completedAt || report?.createdAt || new Date().toISOString();
  const indicatorObjects = buildIndicatorStixObjects(report);

  return {
    type: "bundle",
    id: `bundle--${sanitizeFileComponent(report?.id || "report")}`,
    spec_version: "2.1",
    objects: [
      {
        type: "report",
        spec_version: "2.1",
        id: `report--${sanitizeFileComponent(report?.id || "report")}`,
        created,
        modified: created,
        name: `${report?.fileName || report?.file?.originalName || report?.id || "Scan report"} findings`,
        description: (Array.isArray(report?.plainLanguageReasons) ? report.plainLanguageReasons : []).join(" ") || "ViroVanta scan report export.",
        published: created,
        object_refs: indicatorObjects.map((object) => object.id),
        labels: ["threat-report", `verdict:${report?.verdict || "unknown"}`]
      },
      ...indicatorObjects
    ]
  };
}
