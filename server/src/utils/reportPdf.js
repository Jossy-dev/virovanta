import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { PDFDocument, StandardFonts, rgb } from "pdf-lib";
import puppeteer from "puppeteer-core";
import { buildWebsiteSecurityReportHtml } from "./reportHtmlTemplate.js";

const PAGE_WIDTH = 612;
const PAGE_HEIGHT = 792;
const PAGE_MARGIN_X = 46;
const PAGE_MARGIN_TOP = 56;
const PAGE_MARGIN_BOTTOM = 50;
const LINE_GAP = 4;
const TITLE_COLOR = rgb(0.07, 0.24, 0.17);
const BODY_COLOR = rgb(0.12, 0.15, 0.18);
const MUTED_COLOR = rgb(0.34, 0.39, 0.45);
const BORDER_COLOR = rgb(0.84, 0.88, 0.93);
const ACCENT_BG = rgb(0.08, 0.28, 0.18);
const MAX_FLAT_ENTRIES = 180;
const MAX_FLAT_DEPTH = 4;

const SOURCE_LABELS = Object.freeze({
  file: "File Security Scan",
  url: "URL Threat Scan",
  website: "Website Safety Assessment"
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
let cachedLogoBytes = null;

function clampScore(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return 0;
  }

  return Math.max(0, Math.min(100, Math.round(numeric)));
}

function toDisplayDate(value) {
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

function getSourceLabel(sourceType) {
  return SOURCE_LABELS[String(sourceType || "").toLowerCase()] || "Security Scan";
}

function formatValue(value) {
  if (value == null || value === "") {
    return "Not collected";
  }

  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    return String(value);
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return "None";
    }

    return value
      .map((entry) => String(entry || "").trim())
      .filter(Boolean)
      .join(", ");
  }

  if (typeof value === "object") {
    return "Object";
  }

  return String(value);
}

function summarizeFindingsBySeverity(findings) {
  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  const safeFindings = Array.isArray(findings) ? findings : [];
  for (const finding of safeFindings) {
    const severity = String(finding?.severity || "info").toLowerCase();
    if (Object.prototype.hasOwnProperty.call(summary, severity)) {
      summary[severity] += 1;
    } else {
      summary.info += 1;
    }
  }

  return summary;
}

function flattenObject(input, { prefix = "", depth = 0, maxDepth = MAX_FLAT_DEPTH, rows = [] } = {}) {
  if (rows.length >= MAX_FLAT_ENTRIES) {
    return rows;
  }

  if (depth > maxDepth) {
    if (prefix) {
      rows.push([prefix, "Depth limit reached"]);
    }
    return rows;
  }

  if (input == null || ["string", "number", "boolean"].includes(typeof input)) {
    if (prefix) {
      rows.push([prefix, formatValue(input)]);
    }
    return rows;
  }

  if (Array.isArray(input)) {
    const primitive = input.every((entry) => entry == null || ["string", "number", "boolean"].includes(typeof entry));

    if (primitive) {
      rows.push([prefix || "value", formatValue(input)]);
      return rows;
    }

    input.slice(0, 12).forEach((entry, index) => {
      flattenObject(entry, {
        prefix: `${prefix}[${index}]`,
        depth: depth + 1,
        maxDepth,
        rows
      });
    });

    if (input.length > 12) {
      rows.push([prefix || "value", `${input.length - 12} additional entries omitted`]);
    }

    return rows;
  }

  const safeObject = input && typeof input === "object" ? input : {};
  const entries = Object.entries(safeObject).sort((left, right) => left[0].localeCompare(right[0]));

  if (entries.length === 0 && prefix) {
    rows.push([prefix, "None"]);
    return rows;
  }

  entries.forEach(([key, nestedValue]) => {
    if (rows.length >= MAX_FLAT_ENTRIES) {
      return;
    }

    flattenObject(nestedValue, {
      prefix: prefix ? `${prefix}.${key}` : key,
      depth: depth + 1,
      maxDepth,
      rows
    });
  });

  return rows;
}

async function resolveLogoBytes() {
  if (cachedLogoBytes) {
    return cachedLogoBytes;
  }

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
        cachedLogoBytes = bytes;
        return bytes;
      }
    } catch {
      // Try next candidate.
    }
  }

  return null;
}

class PdfLayout {
  constructor({ pdfDoc, fontRegular, fontBold, logoImage = null }) {
    this.pdfDoc = pdfDoc;
    this.fontRegular = fontRegular;
    this.fontBold = fontBold;
    this.logoImage = logoImage;
    this.pages = [];
    this.currentPage = null;
    this.cursorY = PAGE_HEIGHT - PAGE_MARGIN_TOP;
    this.addPage();
  }

  addPage() {
    const page = this.pdfDoc.addPage([PAGE_WIDTH, PAGE_HEIGHT]);
    this.pages.push(page);
    this.currentPage = page;
    this.cursorY = PAGE_HEIGHT - PAGE_MARGIN_TOP;

    if (this.logoImage) {
      const maxWidth = PAGE_WIDTH * 0.46;
      const scaled = this.logoImage.scale(Math.min(maxWidth / this.logoImage.width, 0.9));
      const x = (PAGE_WIDTH - scaled.width) / 2;
      const y = (PAGE_HEIGHT - scaled.height) / 2;

      this.currentPage.drawImage(this.logoImage, {
        x,
        y,
        width: scaled.width,
        height: scaled.height,
        opacity: 0.07
      });
    }
  }

  lineHeight(fontSize) {
    return fontSize + LINE_GAP;
  }

  ensureSpace(lines = 1, fontSize = 11) {
    const needed = lines * this.lineHeight(fontSize);
    if (this.cursorY - needed < PAGE_MARGIN_BOTTOM) {
      this.addPage();
    }
  }

  drawTextLine(text, { x = PAGE_MARGIN_X, size = 11, bold = false, color = BODY_COLOR } = {}) {
    this.ensureSpace(1, size);
    this.currentPage.drawText(String(text || ""), {
      x,
      y: this.cursorY,
      size,
      font: bold ? this.fontBold : this.fontRegular,
      color
    });
    this.cursorY -= this.lineHeight(size);
  }

  wrapText(text, { size = 11, width = PAGE_WIDTH - PAGE_MARGIN_X * 2, font = this.fontRegular } = {}) {
    const normalized = String(text || "").replace(/\s+/g, " ").trim();
    if (!normalized) {
      return [""];
    }

    const words = normalized.split(" ");
    const lines = [];
    let current = "";

    words.forEach((word) => {
      const candidate = current ? `${current} ${word}` : word;
      if (font.widthOfTextAtSize(candidate, size) <= width) {
        current = candidate;
        return;
      }

      if (current) {
        lines.push(current);
        current = word;
        return;
      }

      let remaining = word;
      while (remaining.length > 0) {
        let chunkLength = remaining.length;
        while (chunkLength > 1 && font.widthOfTextAtSize(remaining.slice(0, chunkLength), size) > width) {
          chunkLength -= 1;
        }

        lines.push(remaining.slice(0, chunkLength));
        remaining = remaining.slice(chunkLength);
      }

      current = "";
    });

    if (current) {
      lines.push(current);
    }

    return lines;
  }

  paragraph(text, { size = 11, bold = false, indent = 0, color = BODY_COLOR } = {}) {
    const font = bold ? this.fontBold : this.fontRegular;
    const maxWidth = PAGE_WIDTH - PAGE_MARGIN_X * 2 - indent;
    const lines = this.wrapText(text, {
      size,
      width: maxWidth,
      font
    });

    lines.forEach((line) => {
      this.drawTextLine(line, {
        x: PAGE_MARGIN_X + indent,
        size,
        bold,
        color
      });
    });
  }

  bullet(text, { size = 11, indent = 0 } = {}) {
    const maxWidth = PAGE_WIDTH - PAGE_MARGIN_X * 2 - indent - 14;
    const lines = this.wrapText(text, {
      size,
      width: maxWidth,
      font: this.fontRegular
    });

    lines.forEach((line, index) => {
      this.drawTextLine(`${index === 0 ? "- " : "  "}${line}`, {
        x: PAGE_MARGIN_X + indent,
        size,
        bold: false,
        color: BODY_COLOR
      });
    });
  }

  sectionHeading(label) {
    this.cursorY -= 3;
    this.paragraph(String(label || "").toUpperCase(), {
      size: 12,
      bold: true,
      color: TITLE_COLOR
    });

    this.ensureSpace(1, 11);
    const y = this.cursorY + 5;
    this.currentPage.drawLine({
      start: { x: PAGE_MARGIN_X, y },
      end: { x: PAGE_WIDTH - PAGE_MARGIN_X, y },
      thickness: 1,
      color: BORDER_COLOR
    });
    this.cursorY -= 8;
  }

  keyValue(label, value, { indent = 0, hideIfMissing = false } = {}) {
    const formatted = formatValue(value);
    if (hideIfMissing && (formatted === "Not collected" || formatted === "None")) {
      return;
    }

    this.paragraph(`${label}: ${formatted}`, {
      size: 10.5,
      indent
    });
  }

  spacer(lines = 1, size = 11) {
    this.cursorY -= lines * this.lineHeight(size);
    if (this.cursorY < PAGE_MARGIN_BOTTOM) {
      this.addPage();
    }
  }

  drawTopBanner(report) {
    const bannerHeight = 66;
    const y = PAGE_HEIGHT - bannerHeight;
    this.currentPage.drawRectangle({
      x: 0,
      y,
      width: PAGE_WIDTH,
      height: bannerHeight,
      color: ACCENT_BG
    });

    this.currentPage.drawText("ViroVanta Security Report", {
      x: PAGE_MARGIN_X,
      y: PAGE_HEIGHT - 28,
      size: 18,
      color: rgb(1, 1, 1),
      font: this.fontBold
    });

    this.currentPage.drawText(getSourceLabel(report?.sourceType), {
      x: PAGE_MARGIN_X,
      y: PAGE_HEIGHT - 46,
      size: 11,
      color: rgb(0.88, 0.95, 0.91),
      font: this.fontRegular
    });

    this.cursorY = PAGE_HEIGHT - bannerHeight - 18;
  }

  finalizeFooters() {
    const totalPages = this.pages.length;
    this.pages.forEach((page, index) => {
      page.drawLine({
        start: { x: PAGE_MARGIN_X, y: 35 },
        end: { x: PAGE_WIDTH - PAGE_MARGIN_X, y: 35 },
        thickness: 0.8,
        color: BORDER_COLOR
      });

      page.drawText("ViroVanta security intelligence", {
        x: PAGE_MARGIN_X,
        y: 22,
        size: 9,
        font: this.fontRegular,
        color: MUTED_COLOR
      });

      page.drawText(`Page ${index + 1} of ${totalPages}`, {
        x: PAGE_WIDTH - PAGE_MARGIN_X - 70,
        y: 22,
        size: 9,
        font: this.fontRegular,
        color: MUTED_COLOR
      });
    });
  }
}

function addExecutiveSummary(layout, report) {
  const target = report?.url?.final || report?.url?.normalized || report?.file?.originalName || "Not collected";
  const verdict = toTitleCase(report?.verdict || "unknown");
  const riskScore = clampScore(report?.riskScore);
  const safetyScore = report?.websiteSafety?.score != null ? clampScore(report.websiteSafety.score) : clampScore(100 - riskScore);
  const severity = summarizeFindingsBySeverity(report?.findings || []);

  layout.keyValue("Report ID", report?.id || "Not collected");
  layout.keyValue("Generated At", toDisplayDate(report?.completedAt || report?.createdAt || new Date().toISOString()));
  layout.keyValue("Target", target);
  layout.keyValue("Verdict", verdict);
  layout.keyValue("Risk Score", `${riskScore}/100`);
  layout.keyValue("Safety Score", `${safetyScore}/100`);
  layout.keyValue(
    "Finding Severity Summary",
    `Critical ${severity.critical}, High ${severity.high}, Medium ${severity.medium}, Low ${severity.low}, Info ${severity.info}`
  );

  layout.spacer(0.5);
  layout.sectionHeading("Executive Summary");

  const reasons = Array.isArray(report?.plainLanguageReasons)
    ? report.plainLanguageReasons.map((item) => String(item || "").trim()).filter(Boolean)
    : [];

  if (reasons.length === 0) {
    layout.bullet("No plain-language summary was generated for this scan. Use the findings and indicators below for analyst review.");
  } else {
    reasons.slice(0, 8).forEach((reason) => layout.bullet(reason));
  }
}

function addScanMetadata(layout, report) {
  layout.sectionHeading("Scan Metadata");
  layout.keyValue("Source Type", toTitleCase(report?.sourceType || "unknown"));
  layout.keyValue("Created At", toDisplayDate(report?.createdAt));
  layout.keyValue("Completed At", toDisplayDate(report?.completedAt));
  layout.keyValue("Queued Job ID", report?.queuedJobId || "Not collected");
  layout.keyValue("Owner User ID", report?.ownerUserId || "Not collected");

  if (report?.websiteSafety?.checkedAt) {
    layout.keyValue("Website Safety Checked At", toDisplayDate(report.websiteSafety.checkedAt));
    layout.keyValue("Website Safety Verdict", toTitleCase(report?.websiteSafety?.verdict || "unknown"));
  }

  const artifacts = flattenObject(report?.artifacts || {}).slice(0, 18);
  if (artifacts.length > 0) {
    layout.spacer(0.3);
    layout.paragraph("Stored Artifacts", {
      size: 11,
      bold: true
    });
    artifacts.forEach(([key, value]) => layout.keyValue(key, value, { indent: 10 }));
  }
}

function addTargetProfile(layout, report) {
  layout.sectionHeading("Target And Artifact Profile");
  const file = report?.file || {};

  layout.keyValue("Display Name", file.originalName || "Not collected");
  layout.keyValue("File Extension", file.extension || "Not collected");
  layout.keyValue("Declared MIME", file.declaredMimeType || "Not collected");
  layout.keyValue("Detected MIME", file.detectedMimeType || "Not collected");
  layout.keyValue("Detected Type", file.detectedFileType || "Not collected");
  layout.keyValue("Magic Type", file.magicType || "Not collected");
  layout.keyValue("Artifact Size", file.sizeDisplay || file.size || "Not collected");
  layout.keyValue("Entropy", file.entropy == null ? "Not collected" : Number(file.entropy).toFixed(3));
  layout.keyValue("Printable Ratio", file.printableRatio == null ? "Not collected" : file.printableRatio);

  layout.spacer(0.2);
  layout.paragraph("Hashes", {
    size: 11,
    bold: true
  });
  layout.keyValue("MD5", file?.hashes?.md5 || "Not collected", { indent: 10 });
  layout.keyValue("SHA1", file?.hashes?.sha1 || "Not collected", { indent: 10 });
  layout.keyValue("SHA256", file?.hashes?.sha256 || "Not collected", { indent: 10 });

  if (report?.url) {
    layout.spacer(0.2);
    layout.paragraph("URL Context", {
      size: 11,
      bold: true
    });
    layout.keyValue("Input URL", report.url.input, { indent: 10 });
    layout.keyValue("Normalized URL", report.url.normalized, { indent: 10 });
    layout.keyValue("Final URL", report.url.final, { indent: 10 });
    layout.keyValue("Protocol", report.url.protocol, { indent: 10 });
    layout.keyValue("Hostname", report.url.hostname, { indent: 10 });
    layout.keyValue("HTTP Status", report.url.statusCode, { indent: 10, hideIfMissing: true });
    layout.keyValue("Content Type", report.url.contentType, { indent: 10, hideIfMissing: true });
    layout.keyValue("Body Truncated", report.url.truncated, { indent: 10, hideIfMissing: true });
  }
}

function addFindings(layout, report) {
  layout.sectionHeading("Findings");
  const findings = Array.isArray(report?.findings) ? report.findings : [];

  if (findings.length === 0) {
    layout.paragraph("No findings were recorded for this scan.");
    return;
  }

  findings.forEach((finding, index) => {
    layout.paragraph(`${index + 1}. [${String(finding?.severity || "info").toUpperCase()}] ${finding?.title || "Finding"}`, {
      size: 11,
      bold: true
    });
    layout.keyValue("Category", finding?.category || "General", { indent: 10 });
    layout.keyValue("Weight", finding?.weight, { indent: 10 });
    layout.paragraph(`Description: ${finding?.description || "Not collected"}`, {
      size: 10.5,
      indent: 10
    });
    layout.keyValue("Evidence", finding?.evidence || "Not collected", {
      indent: 10,
      hideIfMissing: true
    });
    layout.spacer(0.2);
  });
}

function addRecommendations(layout, report) {
  layout.sectionHeading("Recommendations");
  const recommendations = Array.isArray(report?.recommendations) ? report.recommendations : [];

  if (recommendations.length === 0) {
    layout.bullet("No explicit recommendation was generated. Apply your standard triage workflow.");
    return;
  }

  recommendations.forEach((item) => layout.bullet(item));
}

function addSectionFromFlatObject(layout, title, payload, { maxDepth = MAX_FLAT_DEPTH } = {}) {
  layout.sectionHeading(title);
  const rows = flattenObject(payload, {
    maxDepth
  });

  if (rows.length === 0) {
    layout.paragraph("No data collected in this section.");
    return;
  }

  rows.forEach(([key, value]) => {
    layout.keyValue(key, value, {
      hideIfMissing: false
    });
  });
}

function addWebsiteDeepAnalysis(layout, report) {
  if (report?.sourceType !== "website" || !report?.websiteSafety?.modules) {
    return;
  }

  const modules = report.websiteSafety.modules;
  layout.sectionHeading("Website Deep Analysis");

  layout.paragraph("Domain and DNS", {
    size: 11,
    bold: true
  });
  layout.keyValue("ASCII Hostname", modules?.normalization?.asciiHostname || "Not collected", { indent: 10 });
  layout.keyValue("Unicode Hostname", modules?.normalization?.unicodeHostname || "Not collected", { indent: 10 });
  layout.keyValue("Domain Age (Days)", modules?.dnsDomain?.ageDays, { indent: 10, hideIfMissing: true });
  layout.keyValue("Registrar", modules?.dnsDomain?.registrar, { indent: 10, hideIfMissing: true });
  layout.keyValue("Registered At", toDisplayDate(modules?.dnsDomain?.registeredAt), { indent: 10, hideIfMissing: true });
  layout.keyValue("Expires At", toDisplayDate(modules?.dnsDomain?.expiresAt), { indent: 10, hideIfMissing: true });
  layout.keyValue("Nameservers", modules?.dnsDomain?.nameservers, { indent: 10, hideIfMissing: true });
  layout.keyValue("A Records", modules?.dnsDomain?.records?.a, { indent: 10, hideIfMissing: true });
  layout.keyValue("AAAA Records", modules?.dnsDomain?.records?.aaaa, { indent: 10, hideIfMissing: true });
  layout.keyValue("MX Records", modules?.dnsDomain?.records?.mx, { indent: 10, hideIfMissing: true });
  layout.keyValue("SPF Present", modules?.dnsDomain?.mailAuth?.spfPresent, { indent: 10, hideIfMissing: true });
  layout.keyValue("DMARC Present", modules?.dnsDomain?.mailAuth?.dmarcPresent, { indent: 10, hideIfMissing: true });

  layout.spacer(0.3);
  layout.paragraph("IP, TLS, and Header Security", {
    size: 11,
    bold: true
  });
  layout.keyValue("Primary IP", modules?.ipHosting?.primaryIp, { indent: 10, hideIfMissing: true });
  layout.keyValue("Hosting Organization", modules?.ipHosting?.organization, { indent: 10, hideIfMissing: true });
  layout.keyValue("Hosting ASN", modules?.ipHosting?.asn, { indent: 10, hideIfMissing: true });
  layout.keyValue("Hosting Country", modules?.ipHosting?.country, { indent: 10, hideIfMissing: true });
  layout.keyValue("TLS Status", modules?.ssl?.status, { indent: 10, hideIfMissing: true });
  layout.keyValue("TLS Protocol", modules?.ssl?.protocol, { indent: 10, hideIfMissing: true });
  layout.keyValue("Certificate Issuer", modules?.ssl?.certIssuer, { indent: 10, hideIfMissing: true });
  layout.keyValue("Certificate Subject", modules?.ssl?.certSubject, { indent: 10, hideIfMissing: true });
  layout.keyValue("Certificate Valid To", toDisplayDate(modules?.ssl?.certValidTo), { indent: 10, hideIfMissing: true });
  layout.keyValue("Missing Security Headers", modules?.headers?.missing, { indent: 10, hideIfMissing: true });

  layout.spacer(0.3);
  layout.paragraph("Content, Redirect, Reputation, and Exposure", {
    size: 11,
    bold: true
  });
  layout.keyValue("Suspicious Keywords", modules?.content?.suspiciousKeywords, { indent: 10, hideIfMissing: true });
  layout.keyValue("Hidden Iframes", modules?.content?.hiddenIframes, { indent: 10, hideIfMissing: true });
  layout.keyValue("Obfuscated Script Indicators", modules?.content?.obfuscatedScriptIndicators, { indent: 10, hideIfMissing: true });
  layout.keyValue("External Link Count", modules?.content?.externalLinkCount, { indent: 10, hideIfMissing: true });
  layout.keyValue("Suspicious External Links", modules?.content?.suspiciousExternalLinks, { indent: 10, hideIfMissing: true });
  layout.keyValue("Redirect Count", modules?.redirects?.count, { indent: 10, hideIfMissing: true });
  layout.keyValue("Cross-domain Redirect Count", modules?.redirects?.crossDomainCount, { indent: 10, hideIfMissing: true });
  layout.keyValue("Threat Intel Flagged", modules?.reputation?.flagged, { indent: 10, hideIfMissing: true });
  layout.keyValue("Flagged Providers", modules?.reputation?.flaggedProviders, { indent: 10, hideIfMissing: true });
  layout.keyValue("Detected Technologies", (modules?.technology?.technologies || []).map((entry) => `${entry.category}: ${entry.value}`), {
    indent: 10,
    hideIfMissing: true
  });
  layout.keyValue("Sensitive Exposures", (modules?.vulnerabilityChecks?.exposures || []).map((entry) => `${entry.path} (${entry.status})`), {
    indent: 10,
    hideIfMissing: true
  });
  layout.keyValue("Reachable Admin Endpoints", (modules?.vulnerabilityChecks?.adminEndpoints || []).map((entry) => `${entry.path} (${entry.status})`), {
    indent: 10,
    hideIfMissing: true
  });
  layout.keyValue("security.txt Present", modules?.discovery?.securityTxt?.found, { indent: 10, hideIfMissing: true });
  layout.keyValue("robots.txt Present", modules?.discovery?.robotsTxt?.found, { indent: 10, hideIfMissing: true });
}

function addAnalystNotice(layout) {
  layout.sectionHeading("Analyst Notice");
  layout.paragraph(
    "This report reflects automated evidence captured at scan time. It reduces risk but cannot guarantee absolute safety. For business-critical decisions, include manual validation by a security analyst."
  );
}

async function buildLegacyScanReportPdf(report) {
  const pdfDoc = await PDFDocument.create();
  const fontRegular = await pdfDoc.embedFont(StandardFonts.TimesRoman);
  const fontBold = await pdfDoc.embedFont(StandardFonts.TimesRomanBold);

  let logoImage = null;
  const logoBytes = await resolveLogoBytes();
  if (logoBytes) {
    try {
      logoImage = await pdfDoc.embedPng(logoBytes);
    } catch {
      logoImage = null;
    }
  }

  const layout = new PdfLayout({
    pdfDoc,
    fontRegular,
    fontBold,
    logoImage
  });

  layout.drawTopBanner(report || {});
  addExecutiveSummary(layout, report || {});
  layout.spacer(0.6);
  addScanMetadata(layout, report || {});
  addTargetProfile(layout, report || {});
  addFindings(layout, report || {});
  addRecommendations(layout, report || {});
  addSectionFromFlatObject(layout, "Engine Execution Status", report?.engines || {}, {
    maxDepth: 3
  });
  addSectionFromFlatObject(layout, "Technical Indicators", report?.technicalIndicators || {}, {
    maxDepth: 4
  });
  addWebsiteDeepAnalysis(layout, report || {});
  addAnalystNotice(layout);
  layout.finalizeFooters();

  const pdfBytes = await pdfDoc.save({
    useObjectStreams: false,
    addDefaultPage: false
  });

  return Buffer.from(pdfBytes);
}

const CHROMIUM_EXECUTABLE_ENV_KEYS = Object.freeze([
  "REPORT_PDF_CHROMIUM_PATH",
  "PUPPETEER_EXECUTABLE_PATH",
  "CHROME_PATH",
  "CHROMIUM_PATH"
]);

const CHROMIUM_EXECUTABLE_CANDIDATES = Object.freeze([
  "/usr/bin/chromium-browser",
  "/usr/bin/chromium",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/google-chrome",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium"
]);

async function fileExists(targetPath) {
  try {
    await fs.access(targetPath);
    return true;
  } catch {
    return false;
  }
}

async function resolveChromiumExecutablePath() {
  for (const key of CHROMIUM_EXECUTABLE_ENV_KEYS) {
    const configuredPath = String(process.env[key] || "").trim();
    if (!configuredPath) {
      continue;
    }

    if (await fileExists(configuredPath)) {
      return configuredPath;
    }
  }

  for (const candidate of CHROMIUM_EXECUTABLE_CANDIDATES) {
    if (await fileExists(candidate)) {
      return candidate;
    }
  }

  return null;
}

function buildPdfFooterTemplate(appName) {
  const safeAppName = String(appName || "ViroVanta")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");

  return `
    <div style="width:100%; font-size:9px; color:#6b7280; padding:0 12mm; display:flex; justify-content:space-between; align-items:center; font-family:Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;">
      <span>This report does not guarantee safety. Use alongside analyst validation.</span>
      <span>Generated by ${safeAppName} • <span class="pageNumber"></span>/<span class="totalPages"></span></span>
    </div>
  `;
}

async function buildHtmlScanReportPdf(report) {
  const chromiumExecutablePath = await resolveChromiumExecutablePath();
  if (!chromiumExecutablePath) {
    throw new Error("Chromium executable not found for HTML report rendering.");
  }

  const appName = String(process.env.APP_NAME || "ViroVanta");
  const { html } = await buildWebsiteSecurityReportHtml({
    report,
    appName
  });

  const browser = await puppeteer.launch({
    executablePath: chromiumExecutablePath,
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage", "--font-render-hinting=medium"]
  });

  try {
    const page = await browser.newPage();
    await page.setContent(html, {
      waitUntil: ["domcontentloaded", "networkidle0"],
      timeout: 30_000
    });

    await page.emulateMediaType("screen");

    const pdfBuffer = await page.pdf({
      format: "A4",
      printBackground: true,
      margin: {
        top: "10mm",
        right: "10mm",
        bottom: "15mm",
        left: "10mm"
      },
      displayHeaderFooter: true,
      headerTemplate: "<div></div>",
      footerTemplate: buildPdfFooterTemplate(appName)
    });

    return Buffer.from(pdfBuffer);
  } finally {
    await browser.close().catch(() => {});
  }
}

export async function buildScanReportPdf(report) {
  const shouldUseHtmlRenderer = String(report?.sourceType || "").toLowerCase() === "website" || Boolean(report?.websiteSafety);
  if (!shouldUseHtmlRenderer) {
    return buildLegacyScanReportPdf(report);
  }

  try {
    return await buildHtmlScanReportPdf(report);
  } catch (error) {
    if (process.env.NODE_ENV !== "test") {
      const message = error?.message || "Unknown PDF rendering error";
      console.warn(`[reportPdf] Falling back to legacy PDF generator: ${message}`);
    }

    return buildLegacyScanReportPdf(report);
  }
}
