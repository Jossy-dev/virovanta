import { normalizeUrlInput } from "./urlIntake.js";

const HREF_ATTRIBUTE_REGEX = /href\s*=\s*(?:"([^"]+)"|'([^']+)'|([^'"\s>]+))/gi;
const EXPLICIT_URL_REGEX = /\bhttps?:\/\/[^\s<>"'`]+/gi;
const BARE_DOMAIN_REGEX =
  /\b(?:www\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{2,5})?(?:[/?#][^\s<>"'`]*)?/gi;
const LEADING_WRAPPER_REGEX = /^[<({["'`]+/;
const TRAILING_WRAPPER_REGEX = /[>)}\].,;!?'"`]+$/;
const SAFE_DOWNRANK_PATTERNS = [/unsubscribe/i, /doubleclick/i, /tracking/i, /pixel/i, /utm_/i];
const SUSPICIOUS_PATTERNS = [
  /login/i,
  /signin/i,
  /verify/i,
  /reset/i,
  /secure/i,
  /account/i,
  /wallet/i,
  /payment/i,
  /invoice/i
];

function normalizeExtractionText(message) {
  return String(message || "")
    .replace(/\r\n?/g, "\n")
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .replace(/&amp;/gi, "&")
    .replace(/\bhxxps\b/gi, "https")
    .replace(/\bhxxp\b/gi, "http")
    .replace(/\[\s*:\s*\]|\(\s*:\s*\)|\{\s*:\s*\}/g, ":")
    .replace(/\[\s*\/\s*\]|\(\s*\/\s*\)|\{\s*\/\s*\}/g, "/")
    .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}/g, ".");
}

function cleanExtractedValue(value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) {
    return "";
  }

  return trimmed.replace(LEADING_WRAPPER_REGEX, "").replace(TRAILING_WRAPPER_REGEX, "").trim();
}

function scoreCandidate(candidate) {
  const parsed = new URL(candidate.normalizedUrl);
  const lowerUrl = candidate.normalizedUrl.toLowerCase();
  let score = candidate.source === "href" ? 60 : candidate.source === "explicit" ? 45 : 25;

  if (parsed.pathname && parsed.pathname !== "/") {
    score += 10;
  }

  if (parsed.search) {
    score += 8;
  }

  if (SUSPICIOUS_PATTERNS.some((pattern) => pattern.test(lowerUrl))) {
    score += 22;
  }

  const labelCount = parsed.hostname.split(".").filter(Boolean).length;
  if (labelCount > 2) {
    score += Math.min(10, (labelCount - 2) * 2);
  }

  if (SAFE_DOWNRANK_PATTERNS.some((pattern) => pattern.test(lowerUrl))) {
    score -= 18;
  }

  return score;
}

function pushCandidate(candidates, seen, text, source, matchValue, index) {
  const cleaned = cleanExtractedValue(matchValue);
  if (!cleaned) {
    return;
  }

  if (!/^https?:\/\//i.test(cleaned) && (cleaned.includes("@") || text[Math.max(0, index - 1)] === "@")) {
    return;
  }

  let normalized;
  try {
    normalized = normalizeUrlInput(cleaned);
  } catch {
    return;
  }

  const key = normalized.normalizedUrl.toLowerCase();
  if (seen.has(key)) {
    return;
  }

  candidates.push({
    raw: cleaned,
    source,
    index,
    normalizedUrl: normalized.normalizedUrl,
    hostname: normalized.asciiHostname
  });
  seen.add(key);
}

export function extractUrlCandidatesFromMessage(message) {
  const text = normalizeExtractionText(message);
  const candidates = [];
  const seen = new Set();

  for (const match of text.matchAll(HREF_ATTRIBUTE_REGEX)) {
    const matchValue = match[1] || match[2] || match[3] || "";
    pushCandidate(candidates, seen, text, "href", matchValue, match.index || 0);
  }

  for (const match of text.matchAll(EXPLICIT_URL_REGEX)) {
    pushCandidate(candidates, seen, text, "explicit", match[0], match.index || 0);
  }

  for (const match of text.matchAll(BARE_DOMAIN_REGEX)) {
    pushCandidate(candidates, seen, text, "bare", match[0], match.index || 0);
  }

  return candidates
    .map((candidate) => ({
      ...candidate,
      score: scoreCandidate(candidate)
    }))
    .sort((left, right) => {
      if (right.score !== left.score) {
        return right.score - left.score;
      }

      if (left.source !== right.source) {
        const sourcePriority = {
          href: 0,
          explicit: 1,
          bare: 2
        };
        return sourcePriority[left.source] - sourcePriority[right.source];
      }

      return left.index - right.index;
    });
}

export function extractUrlScanTargetFromMessage(message) {
  const candidates = extractUrlCandidatesFromMessage(message);

  if (candidates.length === 0) {
    throw new Error("No HTTP or HTTPS link could be extracted from the pasted message.");
  }

  return {
    url: candidates[0].normalizedUrl,
    source: candidates[0].source,
    candidateCount: candidates.length,
    candidates
  };
}

function formatResolvedCandidates(candidates) {
  return candidates.map((candidate, index) => ({
    rank: index + 1,
    url: candidate.normalizedUrl,
    hostname: candidate.hostname,
    source: candidate.source,
    score: candidate.score,
    isPrimary: index === 0
  }));
}

export function resolveUrlScanCandidates({ url, message }) {
  const directUrl = String(url || "").trim();
  if (directUrl) {
    const normalized = normalizeUrlInput(directUrl);
    const candidates = [
      {
        rank: 1,
        url: normalized.normalizedUrl,
        hostname: normalized.asciiHostname,
        source: "direct",
        score: 100,
        isPrimary: true
      }
    ];

    return {
      inputMode: "url",
      primaryUrl: normalized.normalizedUrl,
      extracted: false,
      candidateCount: 1,
      source: "direct",
      candidates
    };
  }

  const pastedMessage = String(message || "").trim();
  if (!pastedMessage) {
    throw new Error("Paste a URL or a suspicious message to scan.");
  }

  const extracted = extractUrlScanTargetFromMessage(pastedMessage);
  const candidates = formatResolvedCandidates(extracted.candidates);

  return {
    inputMode: "message",
    primaryUrl: extracted.url,
    extracted: true,
    candidateCount: extracted.candidateCount,
    source: extracted.source,
    candidates
  };
}

export function resolveUrlScanTarget(payload) {
  const resolved = resolveUrlScanCandidates(payload);

  return {
    url: resolved.primaryUrl,
    inputMode: resolved.inputMode,
    extracted: resolved.extracted,
    candidateCount: resolved.candidateCount,
    source: resolved.source,
    candidates: resolved.candidates
  };
}
