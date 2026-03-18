import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const HEADER_LIBRARY = Object.freeze([
  {
    key: "content-security-policy",
    label: "Content-Security-Policy",
    description: "Restricts script and resource execution sources."
  },
  {
    key: "strict-transport-security",
    label: "Strict-Transport-Security",
    description: "Forces HTTPS and mitigates downgrade attacks."
  },
  {
    key: "x-frame-options",
    label: "X-Frame-Options",
    description: "Protects against clickjacking in iframes."
  },
  {
    key: "x-content-type-options",
    label: "X-Content-Type-Options",
    description: "Prevents MIME type sniffing by browsers."
  },
  {
    key: "referrer-policy",
    label: "Referrer-Policy",
    description: "Controls referrer data leakage across origins."
  }
]);

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatDateTime(value) {
  const timestamp = Date.parse(String(value || ""));
  if (!Number.isFinite(timestamp)) {
    return "Not collected";
  }

  return new Date(timestamp).toISOString().replace("T", " ").replace(".000Z", " UTC");
}

function toTitleCase(value) {
  return String(value || "")
    .toLowerCase()
    .split(/[\s_-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function asTextList(value) {
  if (!Array.isArray(value) || value.length === 0) {
    return "None";
  }

  return value
    .map((entry) => String(entry == null ? "" : entry).trim())
    .filter(Boolean)
    .join(", ");
}

function toneForVerdict(verdict) {
  const normalized = String(verdict || "").toLowerCase();
  if (normalized === "safe" || normalized === "clean") {
    return {
      bg: "#E8FAEF",
      border: "#9AD8B3",
      text: "#0F6D39",
      label: "Safe"
    };
  }

  if (normalized === "dangerous" || normalized === "malicious") {
    return {
      bg: "#FFECEF",
      border: "#F4A3B1",
      text: "#B21F3B",
      label: "Dangerous"
    };
  }

  return {
    bg: "#FFF7E8",
    border: "#F0C37A",
    text: "#A56A07",
    label: "Suspicious"
  };
}

function toneForSeverity(severity) {
  const normalized = String(severity || "").toLowerCase();
  if (normalized === "critical" || normalized === "high") {
    return "risk-high";
  }
  if (normalized === "medium") {
    return "risk-medium";
  }
  return "risk-low";
}

function hashLabel(report) {
  return report?.file?.hashes?.sha256 || report?.file?.hashes?.sha1 || report?.file?.hashes?.md5 || "Not collected";
}

function buildScoreBreakdown(report) {
  const modules = report?.websiteSafety?.modules || {};
  const ssl = modules?.ssl || {};
  const headers = modules?.headers || {};
  const dns = modules?.dnsDomain || {};
  const reputation = modules?.reputation || {};
  const vulnerability = modules?.vulnerabilityChecks || {};

  const sslScore = ssl?.status === "completed" ? (ssl?.certExpired || ssl?.certSelfSigned ? 7 : 15) : 8;
  const headerMissing = asArray(headers?.missing).length;
  const headersScore = Math.max(0, 20 - headerMissing * 4);

  const ageDays = Number(dns?.ageDays);
  const domainScore = Number.isFinite(ageDays) && ageDays >= 0 ? (ageDays < 30 ? 4 : ageDays < 90 ? 9 : 15) : 10;

  const flaggedProviders = asArray(reputation?.flaggedProviders).length;
  const malwareScore = flaggedProviders >= 2 ? 0 : flaggedProviders === 1 ? 10 : 20;

  const exposures = asArray(vulnerability?.exposures).length;
  const exposureScore = exposures > 0 ? Math.max(0, 15 - exposures * 5) : 15;

  return [
    { label: "SSL", score: sslScore, max: 15, color: "var(--brand-blue)" },
    { label: "Headers", score: headersScore, max: 20, color: "var(--brand-purple)" },
    { label: "Domain", score: domainScore, max: 15, color: "var(--brand-blue-dark)" },
    { label: "Malware", score: malwareScore, max: 20, color: "#8B5CF6" },
    { label: "Exposure", score: exposureScore, max: 15, color: "#0EA5E9" }
  ];
}

function buildExecutiveHighlights(report) {
  const modules = report?.websiteSafety?.modules || {};
  const highlights = [];

  if (modules?.ssl?.status === "completed" && !modules?.ssl?.certExpired && !modules?.ssl?.certSelfSigned) {
    highlights.push("Secure SSL certificate detected");
  } else {
    highlights.push("SSL/TLS setup needs review");
  }

  const missingHeaders = asArray(modules?.headers?.missing);
  if (missingHeaders.length > 0) {
    highlights.push(`Missing ${missingHeaders.length} recommended security headers`);
  } else {
    highlights.push("Security header baseline present");
  }

  const redirectRisk = Number(modules?.redirects?.crossDomainCount) || 0;
  if (redirectRisk > 0) {
    highlights.push(`Cross-domain redirects detected (${redirectRisk})`);
  } else {
    highlights.push("No suspicious redirect behavior observed");
  }

  return highlights;
}

function groupFindingsByRisk(findings) {
  const groups = {
    high: [],
    medium: [],
    low: []
  };

  asArray(findings).forEach((finding) => {
    const severity = String(finding?.severity || "low").toLowerCase();
    if (severity === "critical" || severity === "high") {
      groups.high.push(finding);
      return;
    }

    if (severity === "medium") {
      groups.medium.push(finding);
      return;
    }

    groups.low.push(finding);
  });

  return groups;
}

async function resolveLogoDataUri() {
  const candidates = [
    process.env.REPORT_PDF_LOGO_PATH,
    path.resolve(__dirname, "../../../client/public/brand/virovanta-mark-dark-bg.png"),
    path.resolve(__dirname, "../../../client/public/brand/virovanta-mark-light-bg.png"),
    path.resolve(__dirname, "../../../client/public/logo.png")
  ].filter(Boolean);

  for (const candidate of candidates) {
    try {
      const bytes = await fs.readFile(candidate);
      if (bytes?.length) {
        return `data:image/png;base64,${bytes.toString("base64")}`;
      }
    } catch {
      // Ignore and continue.
    }
  }

  return null;
}

function ScoreBadge({ score = 0, verdict = "suspicious" }) {
  const tone = toneForVerdict(verdict);
  return `
    <div class="score-badge">
      <p class="score-kicker">Overall safety score</p>
      <div class="score-value-row">
        <div class="score-value">${escapeHtml(String(score))}<span>/100</span></div>
        <span class="verdict-pill" style="background:${tone.bg}; border-color:${tone.border}; color:${tone.text};">${escapeHtml(
          tone.label
        )}</span>
      </div>
    </div>
  `;
}

function RiskLabel({ severity = "low" }) {
  const tone = toneForSeverity(severity);
  return `<span class="risk-label ${escapeHtml(tone)}">${escapeHtml(toTitleCase(severity))}</span>`;
}

function ProgressBar({ label, value = 0, max = 100, color = "var(--brand-blue)" }) {
  const safeMax = Math.max(1, Number(max) || 1);
  const safeValue = Math.max(0, Math.min(safeMax, Number(value) || 0));
  const percent = Math.round((safeValue / safeMax) * 100);

  return `
    <div class="progress-item">
      <div class="progress-header">
        <span>${escapeHtml(label)}</span>
        <span>${safeValue}/${safeMax}</span>
      </div>
      <div class="progress-track">
        <span class="progress-fill" style="width:${percent}%; background:${escapeHtml(color)};"></span>
      </div>
    </div>
  `;
}

function HeaderRow({ label, value }) {
  return `
    <div class="header-row">
      <span class="header-row-label">${escapeHtml(label)}</span>
      <span class="header-row-value">${escapeHtml(value == null ? "Not collected" : String(value))}</span>
    </div>
  `;
}

function Table({ columns = [], rows = [] }) {
  const tableHead = columns.map((column) => `<th>${escapeHtml(column)}</th>`).join("");
  const tableRows = rows
    .map((row) => {
      const cells = row.map((cell) => `<td>${cell == null ? "" : cell}</td>`).join("");
      return `<tr>${cells}</tr>`;
    })
    .join("");

  return `
    <table class="data-table">
      <thead><tr>${tableHead}</tr></thead>
      <tbody>${tableRows}</tbody>
    </table>
  `;
}

function SectionCard({ title, subtitle = "", body = "" }) {
  return `
    <section class="section-card avoid-break">
      <div class="section-card-head">
        <h2>${escapeHtml(title)}</h2>
        ${subtitle ? `<p>${escapeHtml(subtitle)}</p>` : ""}
      </div>
      <div class="section-card-body">${body}</div>
    </section>
  `;
}

function buildSecurityHeadersTable(modules) {
  const missing = new Set(asArray(modules?.headers?.missing).map((header) => String(header || "").toLowerCase()));
  const values = modules?.headers?.values || {};

  const rows = HEADER_LIBRARY.map((header) => {
    const present = !missing.has(header.key);
    const value = Object.entries(values).find(([key]) => key.toLowerCase().includes(header.key.replace(/-/g, "")))?.[1];
    return [
      `<strong>${escapeHtml(header.label)}</strong>`,
      `<span class="status-pill ${present ? "status-pass" : "status-fail"}">${present ? "Present" : "Missing"}</span>`,
      escapeHtml(header.description),
      `<code>${escapeHtml(value || "Not collected")}</code>`
    ];
  });

  return Table({
    columns: ["Header", "Status", "Description", "Observed value"],
    rows
  });
}

function buildRedirectChain(modules) {
  const chain = asArray(modules?.redirects?.chain);
  if (chain.length === 0) {
    return `<p class="muted">No redirect chain captured for this target.</p>`;
  }

  return `
    <div class="chain-list">
      ${chain
        .map(
          (hop, index) => `
        <div class="chain-hop">
          <span class="chain-index">${index + 1}</span>
          <div class="chain-path">
            <p><strong>From:</strong> ${escapeHtml(hop?.from || "Unknown")}</p>
            <p><strong>To:</strong> ${escapeHtml(hop?.to || "Unknown")}</p>
            <p><strong>Status:</strong> ${escapeHtml(String(hop?.statusCode || "N/A"))}</p>
          </div>
        </div>
      `
        )
        .join("")}
    </div>
  `;
}

function buildRiskHighlights(findings, recommendations) {
  const grouped = groupFindingsByRisk(findings);

  function block(label, items, severity) {
    if (items.length === 0) {
      return `
        <div class="risk-group">
          <h3>${escapeHtml(label)}</h3>
          <p class="muted">No items in this severity group.</p>
        </div>
      `;
    }

    return `
      <div class="risk-group">
        <h3>${escapeHtml(label)}</h3>
        <div class="risk-items">
          ${items
            .map((item, index) => {
              const recommendation = asArray(recommendations)[index] || "Review this finding and apply security hardening controls.";
              return `
                <article class="risk-item">
                  ${RiskLabel({ severity: item?.severity || severity })}
                  <h4>${escapeHtml(item?.title || "Finding")}</h4>
                  <p>${escapeHtml(item?.description || "Not collected")}</p>
                  <p class="recommendation"><strong>Recommendation:</strong> ${escapeHtml(recommendation)}</p>
                </article>
              `;
            })
            .join("")}
        </div>
      </div>
    `;
  }

  return `
    <div class="risk-highlight-grid">
      ${block("High risk", grouped.high, "high")}
      ${block("Medium risk", grouped.medium, "medium")}
      ${block("Low risk", grouped.low, "low")}
    </div>
  `;
}

function reportSummaryText(report) {
  const findings = asArray(report?.findings);
  const high = findings.filter((item) => ["critical", "high"].includes(String(item?.severity || "").toLowerCase())).length;
  const medium = findings.filter((item) => String(item?.severity || "").toLowerCase() === "medium").length;
  const low = findings.length - high - medium;

  return `The scanner observed ${findings.length} notable finding(s): ${high} high, ${medium} medium, ${Math.max(0, low)} low severity indicator(s).`;
}

function coverPage({ report, scoreBreakdown, logoDataUri }) {
  const safetyScore = report?.websiteSafety?.score != null ? Number(report.websiteSafety.score) : Math.max(0, 100 - (Number(report?.riskScore) || 0));
  const verdict = report?.websiteSafety?.verdict || report?.verdict || "suspicious";
  const targetUrl = report?.url?.final || report?.url?.normalized || report?.file?.originalName || "Not collected";
  const scanDate = formatDateTime(report?.completedAt || report?.createdAt || new Date().toISOString());

  return `
    <section class="page page-cover">
      ${logoDataUri ? `<img class="watermark" src="${logoDataUri}" alt="ViroVanta watermark" />` : ""}
      <div class="cover-top">
        <div class="brand">
          ${logoDataUri ? `<img src="${logoDataUri}" alt="ViroVanta logo" />` : ""}
          <div>
            <p class="brand-name">ViroVanta</p>
            <p class="brand-subtitle">Website Safety Scanner</p>
          </div>
        </div>
      </div>
      <div class="cover-main">
        <h1>Website Security Report</h1>
        <p class="lead">Comprehensive trust and security assessment for public web properties.</p>
        <div class="cover-meta">
          ${HeaderRow({ label: "Target URL", value: targetUrl })}
          ${HeaderRow({ label: "Scan date", value: scanDate })}
          ${HeaderRow({ label: "Report ID", value: report?.id || "Not collected" })}
          ${HeaderRow({ label: "Target SHA256", value: hashLabel(report) })}
        </div>
      </div>
      <div class="cover-score-grid">
        ${ScoreBadge({ score: Math.round(safetyScore), verdict })}
        <div class="score-breakdown-mini">
          <p>Score distribution</p>
          ${scoreBreakdown
            .slice(0, 4)
            .map((row) => ProgressBar({ label: row.label, value: row.score, max: row.max, color: row.color }))
            .join("")}
        </div>
      </div>
    </section>
  `;
}

function mainReportPages({ report, scoreBreakdown, logoDataUri }) {
  const modules = report?.websiteSafety?.modules || {};
  const verdict = report?.websiteSafety?.verdict || report?.verdict || "suspicious";
  const verdictTone = toneForVerdict(verdict);
  const findings = asArray(report?.findings);
  const recommendations = asArray(report?.recommendations);
  const highlights = buildExecutiveHighlights(report);

  const executive = SectionCard({
    title: "Executive Summary",
    subtitle: "Plain-language overview of observed risks and trust posture.",
    body: `
      <div class="summary-grid">
        <div class="summary-text">
          <p>${escapeHtml(reportSummaryText(report))}</p>
          <ul>
            ${highlights
              .map((item) => `<li>${escapeHtml(item)}</li>`)
              .join("")}
          </ul>
        </div>
        <aside class="risk-summary" style="background:${verdictTone.bg}; border-color:${verdictTone.border}; color:${verdictTone.text};">
          <h3>Risk summary</h3>
          <p>${escapeHtml(verdictTone.label)} posture</p>
          <span>${escapeHtml(String(100 - (Number(report?.riskScore) || 0)))} / 100 confidence</span>
        </aside>
      </div>
    `
  });

  const scoreSection = SectionCard({
    title: "Score Breakdown",
    subtitle: "Weighted scoring across key security controls.",
    body: `
      <div class="progress-grid">
        ${scoreBreakdown.map((row) => ProgressBar(row)).join("")}
      </div>
    `
  });

  const sslCard = SectionCard({
    title: "SSL Security",
    subtitle: "Certificate and transport-level trust signals",
    body: `
      <div class="kv-grid">
        ${HeaderRow({ label: "Status", value: modules?.ssl?.status || "Not collected" })}
        ${HeaderRow({ label: "Protocol", value: modules?.ssl?.protocol || "Not collected" })}
        ${HeaderRow({ label: "Issuer", value: modules?.ssl?.certIssuer || "Not collected" })}
        ${HeaderRow({ label: "Expires", value: formatDateTime(modules?.ssl?.certValidTo) })}
        ${HeaderRow({ label: "Days remaining", value: modules?.ssl?.certDaysRemaining ?? "Not collected" })}
        ${HeaderRow({ label: "Self-signed", value: modules?.ssl?.certSelfSigned ? "Yes" : "No" })}
      </div>
    `
  });

  const domainCard = SectionCard({
    title: "Domain Information",
    subtitle: "Registration, DNS, and hosting intelligence",
    body: `
      <div class="kv-grid">
        ${HeaderRow({ label: "Domain age (days)", value: modules?.dnsDomain?.ageDays ?? "Not collected" })}
        ${HeaderRow({ label: "Registrar", value: modules?.dnsDomain?.registrar || "Not collected" })}
        ${HeaderRow({ label: "Registered", value: formatDateTime(modules?.dnsDomain?.registeredAt) })}
        ${HeaderRow({ label: "Expires", value: formatDateTime(modules?.dnsDomain?.expiresAt) })}
        ${HeaderRow({ label: "Primary IP", value: modules?.ipHosting?.primaryIp || "Not collected" })}
        ${HeaderRow({ label: "ASN", value: modules?.ipHosting?.asn || "Not collected" })}
        ${HeaderRow({ label: "Hosting org", value: modules?.ipHosting?.organization || "Not collected" })}
        ${HeaderRow({ label: "SPF present", value: modules?.dnsDomain?.mailAuth?.spfPresent ? "Yes" : "No" })}
        ${HeaderRow({ label: "DMARC present", value: modules?.dnsDomain?.mailAuth?.dmarcPresent ? "Yes" : "No" })}
      </div>
      <p class="muted"><strong>Nameservers:</strong> ${escapeHtml(asTextList(modules?.dnsDomain?.nameservers))}</p>
    `
  });

  const headerCard = SectionCard({
    title: "Security Headers",
    subtitle: "Response hardening controls",
    body: buildSecurityHeadersTable(modules)
  });

  const contentCard = SectionCard({
    title: "Content Analysis",
    subtitle: "Suspicious patterns, scripts, and external links",
    body: `
      <div class="kv-grid">
        ${HeaderRow({ label: "Phishing signal score", value: modules?.content?.phishingSignalScore ?? "Not collected" })}
        ${HeaderRow({ label: "Suspicious keywords", value: asTextList(modules?.content?.suspiciousKeywords) })}
        ${HeaderRow({ label: "Phishing phrases", value: asTextList(modules?.content?.phishingPhrases) })}
        ${HeaderRow({ label: "External links", value: modules?.content?.externalLinkCount ?? 0 })}
        ${HeaderRow({ label: "Suspicious external links", value: modules?.content?.suspiciousExternalLinkCount ?? 0 })}
        ${HeaderRow({ label: "Hidden iframes", value: modules?.content?.hiddenIframes ?? 0 })}
        ${HeaderRow({ label: "Obfuscated script indicators", value: modules?.content?.obfuscatedScriptIndicators ?? 0 })}
      </div>
      <p class="muted"><strong>External scripts:</strong> ${escapeHtml(asTextList(modules?.content?.externalScripts))}</p>
    `
  });

  const redirectCard = SectionCard({
    title: "Redirect Analysis",
    subtitle: "Observed redirect chain and cross-domain transitions",
    body: buildRedirectChain(modules)
  });

  const malwareRows = asArray(modules?.reputation?.providers).map((provider) => [
    `<strong>${escapeHtml(toTitleCase(provider?.provider || "provider"))}</strong>`,
    `<span class="status-pill ${provider?.status === "flagged" ? "status-fail" : "status-pass"}">${escapeHtml(
      toTitleCase(provider?.status || "unknown")
    )}</span>`,
    `<code>${escapeHtml(JSON.stringify(provider || {}))}</code>`
  ]);

  const malwareCard = SectionCard({
    title: "Malware and Reputation Check",
    subtitle: "Threat intelligence provider outcomes",
    body:
      malwareRows.length > 0
        ? Table({
            columns: ["Provider", "Result", "Detail"],
            rows: malwareRows
          })
        : `<p class="muted">No external threat intelligence providers returned data for this run.</p>`
  });

  const detailSection = SectionCard({
    title: "Detailed Findings",
    subtitle: "Category-level evidence and observed controls",
    body: `
      <div class="detail-grid">
        ${sslCard}
        ${domainCard}
        ${headerCard}
        ${contentCard}
        ${redirectCard}
        ${malwareCard}
      </div>
    `
  });

  const riskHighlights = SectionCard({
    title: "Risk Highlights",
    subtitle: "Issues grouped by severity with targeted recommendations",
    body: buildRiskHighlights(findings, recommendations)
  });

  const recommendationsSection = SectionCard({
    title: "Recommendations",
    subtitle: "Actionable next steps for remediation and hardening",
    body: `
      <ul class="recommendation-list">
        ${recommendations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
      </ul>
    `
  });

  const footerSection = SectionCard({
    title: "Disclaimer",
    subtitle: "Use this report as decision support, not absolute proof of safety",
    body: `
      <p class="muted">
        This report does not guarantee safety and should be combined with manual validation for critical security decisions.
      </p>
      <p class="muted generated-by">Generated by ViroVanta Website Safety Scanner</p>
    `
  });

  return `
    <section class="page">
      ${logoDataUri ? `<img class="watermark watermark-secondary" src="${logoDataUri}" alt="" />` : ""}
      ${executive}
      ${scoreSection}
      ${detailSection}
      ${riskHighlights}
      ${recommendationsSection}
      ${footerSection}
    </section>
  `;
}

function cssStyles() {
  return `
    :root {
      --bg: #F9FAFB;
      --card-bg: #FFFFFF;
      --line: #E5E7EB;
      --text: #0F172A;
      --text-soft: #5B6475;
      --brand-blue: #2563EB;
      --brand-blue-dark: #1D4ED8;
      --brand-purple: #7C3AED;
      --success-bg: #E8FAEF;
      --success-border: #A3D9B6;
      --danger-bg: #FFECEF;
      --danger-border: #F4A3B1;
      --warning-bg: #FFF7E8;
      --warning-border: #F0C37A;
    }

    * { box-sizing: border-box; }

    html, body {
      margin: 0;
      padding: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      line-height: 1.45;
    }

    .report-root {
      max-width: 1024px;
      margin: 0 auto;
      padding: 18px 12px 24px;
    }

    .page {
      background: var(--card-bg);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 24px;
      margin-bottom: 18px;
      position: relative;
      overflow: hidden;
      box-shadow: 0 12px 36px rgba(15, 23, 42, 0.06);
    }

    .page-cover {
      min-height: 1120px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }

    .watermark {
      position: absolute;
      right: -80px;
      bottom: -80px;
      width: 460px;
      opacity: 0.06;
      pointer-events: none;
    }

    .watermark-secondary {
      right: -110px;
      bottom: -120px;
      width: 420px;
      opacity: 0.045;
    }

    .brand {
      display: flex;
      gap: 12px;
      align-items: center;
    }

    .brand img {
      width: 48px;
      height: 48px;
      object-fit: contain;
      border-radius: 10px;
    }

    .brand-name {
      margin: 0;
      font-weight: 700;
      font-size: 18px;
      color: #0B2D1A;
    }

    .brand-subtitle {
      margin: 0;
      color: var(--text-soft);
      font-size: 13px;
    }

    .cover-main h1 {
      margin: 12px 0 6px;
      font-size: 42px;
      line-height: 1.15;
      letter-spacing: -0.02em;
      color: #0F172A;
    }

    .lead {
      margin: 0 0 22px;
      color: var(--text-soft);
      font-size: 15px;
    }

    .cover-meta {
      display: grid;
      gap: 8px;
      padding: 14px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: #FCFCFD;
    }

    .header-row {
      display: flex;
      justify-content: space-between;
      gap: 14px;
      border-bottom: 1px dashed #EAECEF;
      padding-bottom: 6px;
    }

    .header-row:last-child {
      border-bottom: 0;
      padding-bottom: 0;
    }

    .header-row-label {
      color: var(--text-soft);
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }

    .header-row-value {
      font-size: 12px;
      color: var(--text);
      max-width: 72%;
      text-align: right;
      word-break: break-word;
    }

    .cover-score-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
      align-items: stretch;
    }

    .score-badge,
    .score-breakdown-mini {
      border: 1px solid var(--line);
      background: #FAFCFF;
      border-radius: 14px;
      padding: 14px;
    }

    .score-kicker {
      margin: 0;
      color: var(--text-soft);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-weight: 700;
    }

    .score-value-row {
      margin-top: 12px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }

    .score-value {
      font-size: 46px;
      line-height: 1;
      letter-spacing: -0.03em;
      font-weight: 800;
      color: #0F172A;
    }

    .score-value span {
      font-size: 20px;
      color: #475569;
      margin-left: 4px;
    }

    .verdict-pill {
      display: inline-flex;
      align-items: center;
      border: 1px solid;
      border-radius: 999px;
      padding: 6px 12px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      white-space: nowrap;
    }

    .section-card {
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 16px;
      background: #fff;
      margin-bottom: 12px;
    }

    .section-card-head h2 {
      margin: 0;
      font-size: 18px;
      line-height: 1.25;
      letter-spacing: -0.01em;
    }

    .section-card-head p {
      margin: 6px 0 0;
      color: var(--text-soft);
      font-size: 13px;
    }

    .section-card-body {
      margin-top: 12px;
    }

    .summary-grid {
      display: grid;
      grid-template-columns: 1fr 280px;
      gap: 14px;
    }

    .summary-text p {
      margin: 0 0 10px;
    }

    .summary-text ul {
      margin: 0;
      padding-left: 18px;
      color: #1F2937;
    }

    .risk-summary {
      border: 1px solid;
      border-radius: 12px;
      padding: 12px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      justify-content: center;
    }

    .risk-summary h3,
    .risk-summary p {
      margin: 0;
    }

    .risk-summary span {
      font-size: 13px;
      font-weight: 700;
    }

    .progress-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px 14px;
    }

    .progress-item {
      display: grid;
      gap: 6px;
    }

    .progress-header {
      display: flex;
      justify-content: space-between;
      font-size: 12px;
      color: #334155;
      font-weight: 600;
    }

    .progress-track {
      height: 8px;
      border-radius: 999px;
      background: #E6EAF1;
      overflow: hidden;
    }

    .progress-fill {
      display: block;
      height: 100%;
      border-radius: inherit;
    }

    .detail-grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 10px;
    }

    .kv-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px 16px;
    }

    .data-table {
      width: 100%;
      border-collapse: collapse;
      border: 1px solid #E6EAF1;
      border-radius: 12px;
      overflow: hidden;
      font-size: 12px;
    }

    .data-table thead th {
      background: #F3F5F8;
      color: #1E293B;
      text-align: left;
      font-weight: 700;
      padding: 8px 10px;
      border-bottom: 1px solid #E1E6EE;
    }

    .data-table td {
      padding: 8px 10px;
      vertical-align: top;
      border-top: 1px solid #EDF1F6;
      color: #1F2937;
      word-break: break-word;
    }

    .status-pill {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 11px;
      font-weight: 700;
      border: 1px solid;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }

    .status-pass {
      color: #0F6D39;
      background: var(--success-bg);
      border-color: var(--success-border);
    }

    .status-fail {
      color: #B21F3B;
      background: var(--danger-bg);
      border-color: var(--danger-border);
    }

    .muted {
      margin: 10px 0 0;
      color: var(--text-soft);
      font-size: 12px;
      line-height: 1.5;
    }

    .chain-list {
      display: grid;
      gap: 10px;
    }

    .chain-hop {
      border: 1px dashed #CBD4E1;
      border-radius: 10px;
      padding: 10px;
      display: grid;
      grid-template-columns: 28px 1fr;
      gap: 8px;
    }

    .chain-index {
      width: 24px;
      height: 24px;
      border-radius: 999px;
      border: 1px solid #CAD4E2;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 11px;
      color: #475569;
      background: #F8FAFC;
      margin-top: 2px;
    }

    .chain-path p {
      margin: 0 0 4px;
      font-size: 12px;
      color: #1F2937;
      word-break: break-word;
    }

    .risk-highlight-grid {
      display: grid;
      gap: 12px;
    }

    .risk-group h3 {
      margin: 0 0 8px;
      font-size: 14px;
    }

    .risk-items {
      display: grid;
      gap: 8px;
    }

    .risk-item {
      border: 1px solid #E7EBF2;
      background: #FCFCFD;
      border-radius: 10px;
      padding: 10px;
    }

    .risk-item h4 {
      margin: 6px 0;
      font-size: 13px;
    }

    .risk-item p {
      margin: 0;
      font-size: 12px;
      color: #334155;
    }

    .risk-item .recommendation {
      margin-top: 7px;
    }

    .risk-label {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      font-weight: 700;
      border: 1px solid;
    }

    .risk-high {
      color: #B21F3B;
      border-color: #F4A3B1;
      background: #FFECEF;
    }

    .risk-medium {
      color: #A56A07;
      border-color: #F0C37A;
      background: #FFF7E8;
    }

    .risk-low {
      color: #0F6D39;
      border-color: #A3D9B6;
      background: #E8FAEF;
    }

    .recommendation-list {
      margin: 0;
      padding-left: 18px;
      display: grid;
      gap: 6px;
    }

    .recommendation-list li {
      font-size: 12.5px;
      color: #1F2937;
    }

    .generated-by {
      font-size: 11px;
      margin-top: 8px;
    }

    .avoid-break {
      break-inside: avoid;
      page-break-inside: avoid;
    }

    code {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 11px;
      color: #1E293B;
    }

    @media print {
      body {
        background: #fff;
      }

      .report-root {
        margin: 0;
        padding: 0;
      }

      .page {
        border: 0;
        border-radius: 0;
        padding: 0;
        margin: 0;
        box-shadow: none;
      }

      .page + .page {
        page-break-before: always;
      }
    }
  `;
}

export async function buildWebsiteSecurityReportHtml({ report, appName = "ViroVanta", logoDataUri = null } = {}) {
  const safeReport = report || {};
  const resolvedLogoDataUri = logoDataUri || (await resolveLogoDataUri());
  const scoreBreakdown = buildScoreBreakdown(safeReport);

  const html = `
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>${escapeHtml(appName)} Website Security Report</title>
        <style>${cssStyles()}</style>
      </head>
      <body>
        <main class="report-root">
          ${coverPage({
            report: safeReport,
            scoreBreakdown,
            logoDataUri: resolvedLogoDataUri
          })}
          ${mainReportPages({
            report: safeReport,
            scoreBreakdown,
            logoDataUri: resolvedLogoDataUri
          })}
        </main>
      </body>
    </html>
  `;

  return {
    html,
    logoDataUri: resolvedLogoDataUri
  };
}
