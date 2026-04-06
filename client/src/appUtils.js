export const VERDICT_META = {
  clean: { label: "Clean", tone: "clean" },
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

  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

export function isPendingJob(job) {
  return job?.status === "queued" || job?.status === "processing";
}

export function selectHighlightedJob(jobList, currentJobId = "") {
  if (!Array.isArray(jobList) || jobList.length === 0) {
    return null;
  }

  const currentPendingJob = jobList.find((job) => job.id === currentJobId && isPendingJob(job));
  if (currentPendingJob) {
    return currentPendingJob;
  }

  const nextPendingJob = jobList.find((job) => isPendingJob(job));
  if (nextPendingJob) {
    return nextPendingJob;
  }

  const currentJob = jobList.find((job) => job.id === currentJobId);
  if (currentJob) {
    return currentJob;
  }

  return jobList[0];
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
