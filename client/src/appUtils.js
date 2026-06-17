export const VERDICT_META = {
  clean: { label: "Clean", tone: "clean" },
  unknown: { label: "Inconclusive", tone: "unknown" },
  suspicious: { label: "Suspicious", tone: "suspicious" },
  malicious: { label: "Malicious", tone: "malicious" }
};

export const RISK_META = {
  low: { label: "Low risk", tone: "risk-low" },
  medium: { label: "Medium risk", tone: "risk-medium" },
  high: { label: "High risk", tone: "risk-high" }
};

export const HERO_HEADLINE = "Scan suspicious files in seconds before they hit your systems.";
export const HERO_TYPE_SPEED_MS = 210;
export const HERO_CYCLE_PAUSE_MS = 3200;
export const USERNAME_CHECK_DEBOUNCE_MS = 280;
export const SPRING_EASE = [0.22, 1, 0.36, 1];
export const DASHBOARD_THEME_STORAGE_KEY = "virovanta-dashboard-theme";

export function motionPreset(reducedMotion, delay = 0) {
  if (reducedMotion) {
    return {
      initial: false,
      animate: {}
    };
  }

  return {
    initial: { opacity: 0, y: 10 },
    animate: { opacity: 1, y: 0 },
    transition: { duration: 0.28, ease: SPRING_EASE, delay }
  };
}

export function readResetFlowState() {
  if (typeof window === "undefined") {
    return {
      active: false,
      accessToken: "",
      email: "",
      type: "",
      callbackActive: false,
      callbackKind: ""
    };
  }

  const searchParams = new URLSearchParams(window.location.search || "");
  const hashValue = String(window.location.hash || "").replace(/^#/, "");
  const hashParams = new URLSearchParams(hashValue);
  const pathname = String(window.location.pathname || "/").replace(/\/+$/, "") || "/";

  const accessToken = String(hashParams.get("access_token") || searchParams.get("access_token") || "").trim();
  const type = String(hashParams.get("type") || searchParams.get("type") || "").trim().toLowerCase();
  const email = String(hashParams.get("email") || searchParams.get("email") || "").trim().toLowerCase();

  const callbackActive = Boolean(accessToken);
  const callbackKind = type === "recovery" || pathname === "/reset-password" ? "recovery" : callbackActive ? "confirmation" : "";
  const active = callbackKind === "recovery";

  return {
    active,
    accessToken,
    email,
    type,
    callbackActive,
    callbackKind
  };
}

export function isEmailConflictError(error) {
  const message = String(error?.message || "");
  const code = String(error?.code || "");

  if (code === "AUTH_EMAIL_EXISTS") {
    return true;
  }

  return /already registered|already exists|email.+taken|user already exists/i.test(message);
}

export function resolveHeroBackgroundVariant(defaultVariant, variants) {
  if (typeof window === "undefined") {
    return defaultVariant;
  }

  const value = new URLSearchParams(window.location.search).get("hero");
  if (value && variants[value]) {
    return value;
  }

  return defaultVariant;
}

export function formatDateTime(value) {
  if (!value) {
    return "-";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "-";
  }

  return new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

export function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) {
    return "0 B";
  }

  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unitIndex = 0;

  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }

  return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[unitIndex]}`;
}

export function pluralize(label, count) {
  return `${count} ${label}${count === 1 ? "" : "s"}`;
}

export function parseErrorMessage(payload, fallback) {
  const validationDetails = Array.isArray(payload?.error?.details) ? payload.error.details : [];
  const primaryValidationDetail = validationDetails.find((detail) => String(detail?.message || "").trim());

  if (primaryValidationDetail) {
    const fieldLabel = String(primaryValidationDetail.path || "")
      .split(".")
      .filter((segment) => segment && !/^\d+$/.test(segment))
      .slice(-1)[0]
      ?.replace(/([a-z0-9])([A-Z])/g, "$1 $2")
      ?.replace(/[_-]+/g, " ")
      ?.trim();
    const normalizedFieldLabel = fieldLabel ? `${fieldLabel.charAt(0).toUpperCase()}${fieldLabel.slice(1)}` : "";
    const normalizedMessage = String(primaryValidationDetail.message || "").trim();

    if (/^required$/i.test(normalizedMessage) && normalizedFieldLabel) {
      return `${normalizedFieldLabel} is required.`;
    }

    if (normalizedFieldLabel) {
      return `${normalizedFieldLabel}: ${normalizedMessage}`;
    }

    return normalizedMessage;
  }

  if (payload?.error?.message) {
    return payload.error.message;
  }

  if (payload?.error && typeof payload.error === "string") {
    return payload.error;
  }

  if (typeof payload?.message === "string") {
    return payload.message;
  }

  return fallback;
}

export async function triggerBlobDownload(
  blob,
  filename,
  { documentRef = typeof document !== "undefined" ? document : null, urlApi = typeof URL !== "undefined" ? URL : null, windowRef = typeof window !== "undefined" ? window : null } = {}
) {
  if (!blob) {
    throw new Error("Download data is unavailable.");
  }

  if (!documentRef?.body || typeof documentRef.createElement !== "function") {
    throw new Error("Browser download is unavailable in this environment.");
  }

  if (!urlApi?.createObjectURL || !urlApi?.revokeObjectURL) {
    throw new Error("Blob downloads are unavailable in this browser.");
  }

  const objectUrl = urlApi.createObjectURL(blob);
  const anchor = documentRef.createElement("a");
  anchor.href = objectUrl;
  anchor.download = String(filename || "download");
  anchor.rel = "noopener";
  anchor.style.display = "none";
  documentRef.body.appendChild(anchor);

  const cleanup = () => {
    anchor.remove();
    urlApi.revokeObjectURL(objectUrl);
  };

  await new Promise((resolve, reject) => {
    const clickAndResolve = () => {
      try {
        anchor.click();
      } catch (error) {
        cleanup();
        reject(error);
        return;
      }

      if (typeof windowRef?.setTimeout === "function") {
        windowRef.setTimeout(cleanup, 30_000);
      } else {
        cleanup();
      }

      resolve();
    };

    if (typeof windowRef?.requestAnimationFrame === "function") {
      windowRef.requestAnimationFrame(clickAndResolve);
      return;
    }

    clickAndResolve();
  });
}

export function getRiskMeta(score) {
  if (!Number.isFinite(score)) {
    return RISK_META.medium;
  }

  if (score >= 75) {
    return RISK_META.high;
  }

  if (score >= 40) {
    return RISK_META.medium;
  }

  return RISK_META.low;
}

export function getDisplayFileType(file) {
  if (!file) {
    return "-";
  }

  const magicType = file.magicType?.trim();
  if (magicType && magicType.toLowerCase() !== "unknown") {
    return magicType;
  }

  const extension = file.extension?.trim();
  if (extension && extension !== "(none)") {
    return `${extension.replace(/^\./, "").toUpperCase()} file`;
  }

  return "Unidentified file";
}

export function getPlainFindingNote(finding) {
  if (finding?.id === "obfuscated_javascript") {
    return "This script looks intentionally hidden, which is a common way to mask harmful actions.";
  }

  if (finding?.id === "email_embedded_links_malicious" || finding?.id === "email_embedded_links_suspicious") {
    return finding?.evidence || finding?.description || "Suspicious links were found in this email.";
  }

  return finding?.description || "Potentially risky behavior detected in this file.";
}

export function formatVerdictLabel(value) {
  if (!value) {
    return "-";
  }

  const normalized = String(value).trim().toLowerCase();
  if (!normalized) {
    return "-";
  }

  if (normalized === "unknown") {
    return "Inconclusive";
  }

  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

export function getVerdictQualifier(value) {
  const normalized = String(value || "").trim().toLowerCase();

  if (normalized === "clean") {
    return "No strong indicators found";
  }

  if (normalized === "unknown") {
    return "More evidence needed";
  }

  if (normalized === "suspicious") {
    return "Manual review recommended";
  }

  if (normalized === "malicious") {
    return "High-confidence malicious signals";
  }

  return "";
}

export function getReportSummaryReason(report) {
  const explicitReason = Array.isArray(report?.plainLanguageReasons)
    ? report.plainLanguageReasons.find((item) => String(item || "").trim())
    : "";

  if (explicitReason) {
    return String(explicitReason).trim();
  }

  const normalizedVerdict = String(report?.verdict || "")
    .trim()
    .toLowerCase();

  if (normalizedVerdict === "clean") {
    return "No strong indicators were found in this first-pass scan.";
  }

  if (normalizedVerdict === "unknown") {
    return "The current scan evidence is inconclusive.";
  }

  if (normalizedVerdict === "suspicious") {
    return "This scan found risk signals that should be reviewed before trust is granted.";
  }

  if (normalizedVerdict === "malicious") {
    return "This scan found strong malicious indicators or trusted detections.";
  }

  return "";
}

export function isPendingJob(job) {
  return job?.status === "queued" || job?.status === "processing" || job?.status === "cancelling";
}

export function isTerminalJob(job) {
  return job?.status === "completed" || job?.status === "failed" || job?.status === "cancelled";
}

export function selectHighlightedJob(jobList, currentJobId = "") {
  const currentJob = typeof currentJobId === "string" ? null : currentJobId;
  const resolvedCurrentJobId = typeof currentJobId === "string" ? currentJobId : currentJobId?.id || "";

  if (!Array.isArray(jobList) || jobList.length === 0) {
    return isPendingJob(currentJob) ? currentJob : null;
  }

  const currentPendingJob = jobList.find((job) => job.id === resolvedCurrentJobId && isPendingJob(job));
  if (currentPendingJob) {
    return currentPendingJob;
  }

  if (isPendingJob(currentJob)) {
    return currentJob;
  }

  const nextPendingJob = jobList.find((job) => isPendingJob(job));
  if (nextPendingJob) {
    return nextPendingJob;
  }

  const matchingCurrentJob = jobList.find((job) => job.id === resolvedCurrentJobId);
  if (matchingCurrentJob) {
    return matchingCurrentJob;
  }

  return jobList[0];
}

function toTimestamp(value) {
  const parsed = Date.parse(String(value || ""));
  return Number.isFinite(parsed) ? parsed : 0;
}

function sortByMostRecent(items) {
  return [...items].sort((left, right) => {
    const rightTimestamp = toTimestamp(right?.completedAt || right?.createdAt);
    const leftTimestamp = toTimestamp(left?.completedAt || left?.createdAt);
    return rightTimestamp - leftTimestamp;
  });
}

export function mergeCollectionById(currentItems, incomingItems) {
  const map = new Map();

  for (const item of Array.isArray(currentItems) ? currentItems : []) {
    if (item?.id) {
      map.set(item.id, item);
    }
  }

  for (const item of Array.isArray(incomingItems) ? incomingItems : []) {
    if (!item?.id) {
      continue;
    }

    const existing = map.get(item.id) || {};
    map.set(item.id, {
      ...existing,
      ...item
    });
  }

  return sortByMostRecent(Array.from(map.values()));
}

function isFileSourceType(report) {
  return report?.sourceType !== "url" && report?.sourceType !== "website";
}

function normalizeEngineStatus(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function describeEngineUsage(label, engine, usedStatuses) {
  const status = normalizeEngineStatus(engine?.status);
  const used = usedStatuses.has(status);
  const readableStatus = status ? status.replace(/_/g, " ") : "unknown";

  return {
    label,
    used,
    badge: used ? "Used" : "Not Used",
    detail: `${label} status: ${readableStatus}`
  };
}

export function getFileScanEngineUsage(report) {
  if (!isFileSourceType(report)) {
    return [];
  }

  return [
    describeEngineUsage("ClamAV", report?.engines?.clamav, new Set(["clean", "infected"])),
    describeEngineUsage("YARA", report?.engines?.yara, new Set(["clean", "matched"]))
  ];
}

export function extractEmailIdentifier(email) {
  const normalized = String(email || "").trim().toLowerCase();
  if (!normalized.includes("@")) {
    return "";
  }

  return normalized.split("@")[0] || "";
}

export function buildPasswordChecklist(password, email, confirmPassword) {
  const value = String(password || "");
  const emailIdentifier = extractEmailIdentifier(email);
  const lowerValue = value.toLowerCase();

  return [
    {
      key: "length",
      label: "Use at least 12 characters",
      ok: value.length >= 12 && value.length <= 128
    },
    {
      key: "lower",
      label: "Add a lowercase letter",
      ok: /[a-z]/.test(value)
    },
    {
      key: "upper",
      label: "Add an uppercase letter",
      ok: /[A-Z]/.test(value)
    },
    {
      key: "number",
      label: "Add a number",
      ok: /[0-9]/.test(value)
    },
    {
      key: "symbol",
      label: "Add a symbol (for example: ! @ # $)",
      ok: /[^A-Za-z0-9]/.test(value)
    },
    {
      key: "emailIdentifier",
      label: "Do not include the first part of your email",
      ok: !emailIdentifier || !lowerValue.includes(emailIdentifier)
    },
    {
      key: "match",
      label: "Confirm password must match",
      ok: value.length > 0 && value === String(confirmPassword || "")
    }
  ];
}

export function resolveTheme() {
  if (typeof window === "undefined") {
    return "light";
  }

  const stored = window.localStorage.getItem(DASHBOARD_THEME_STORAGE_KEY);
  if (stored === "light" || stored === "dark") {
    return stored;
  }

  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function resolveDesktopViewport() {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
    return true;
  }

  return window.matchMedia("(min-width: 1024px)").matches;
}

export function getUserName(user) {
  const username = String(user?.username || user?.name || "").trim();
  if (username) {
    return username;
  }

  return "Operator";
}

export function getThemePalette(theme) {
  if (theme === "dark") {
    return {
      primary: "#34d399",
      secondary: "#60a5fa",
      axis: "#94a3b8",
      grid: "rgba(148, 163, 184, 0.18)",
      pie: ["#34d399", "#60a5fa", "#f59e0b", "#f87171"]
    };
  }

  return {
    primary: "#1f8f5c",
    secondary: "#2563eb",
    axis: "#64748b",
    grid: "rgba(100, 116, 139, 0.14)",
    pie: ["#1f8f5c", "#2563eb", "#d97706", "#ef4444"]
  };
}
