export const REPORT_VERDICTS = Object.freeze(["clean", "unknown", "suspicious", "malicious"]);

export const REPORT_VERDICT_RANK = Object.freeze({
  clean: 1,
  unknown: 2,
  suspicious: 3,
  malicious: 4
});

export function normalizeReportVerdict(value, fallback = "clean") {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();

  return REPORT_VERDICTS.includes(normalized) ? normalized : fallback;
}

export function reportVerdictRank(value) {
  return REPORT_VERDICT_RANK[normalizeReportVerdict(value)] || REPORT_VERDICT_RANK.clean;
}

export function isFlaggedReportVerdict(value) {
  const verdict = normalizeReportVerdict(value);
  return verdict === "suspicious" || verdict === "malicious";
}

