import { useEffect, useMemo, useRef, useState } from "react";
import {
  APP_NAME,
  APP_TAGLINE,
  BRAND_MARKS,
  HERO_BG_DEFAULT,
  HERO_BG_VARIANTS,
  LOGO_ALT_TEXT,
  SESSION_STORAGE_KEY,
  buildApiUrl
} from "./appConfig";

const VERDICT_META = {
  clean: { label: "Clean", tone: "clean" },
  suspicious: { label: "Suspicious", tone: "suspicious" },
  malicious: { label: "Malicious", tone: "malicious" }
};

const RISK_META = {
  low: { label: "Low risk", tone: "risk-low" },
  medium: { label: "Medium risk", tone: "risk-medium" },
  high: { label: "High risk", tone: "risk-high" }
};

const HERO_HEADLINE = "Scan suspicious files in seconds before they hit your systems.";
const HERO_TYPE_SPEED_MS = 210;
const HERO_CYCLE_PAUSE_MS = 3200;

function resolveHeroBackgroundVariant() {
  if (typeof window === "undefined") {
    return HERO_BG_DEFAULT;
  }

  const value = new URLSearchParams(window.location.search).get("hero");
  if (value && HERO_BG_VARIANTS[value]) {
    return value;
  }

  return HERO_BG_DEFAULT;
}

function formatDateTime(value) {
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

function formatBytes(bytes) {
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

function parseErrorMessage(payload, fallback) {
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

function getRiskMeta(score) {
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

function getDisplayFileType(file) {
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

function getPlainFindingNote(finding) {
  if (finding?.id === "obfuscated_javascript") {
    return "This script looks intentionally hidden, which is a common way to mask harmful actions.";
  }

  return finding?.description || "Potentially risky behavior detected in this file.";
}

function formatVerdictLabel(value) {
  if (!value) {
    return "-";
  }

  const normalized = String(value).trim().toLowerCase();
  if (!normalized) {
    return "-";
  }

  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

export default function App() {
  const [authMode, setAuthMode] = useState("login");
  const [authForm, setAuthForm] = useState({
    email: "",
    password: "",
    name: ""
  });
  const [authLoading, setAuthLoading] = useState(true);
  const [authSubmitting, setAuthSubmitting] = useState(false);
  const [session, setSession] = useState(null);
  const [authError, setAuthError] = useState("");
  const [globalError, setGlobalError] = useState("");
  const [guestFile, setGuestFile] = useState(null);
  const [isGuestScanning, setIsGuestScanning] = useState(false);
  const [guestReport, setGuestReport] = useState(null);
  const [guestError, setGuestError] = useState("");
  const [isGuestDragActive, setIsGuestDragActive] = useState(false);
  const [guestStatus, setGuestStatus] = useState({
    loading: true,
    enabled: true,
    maxUploadMb: 8,
    message: ""
  });
  const [typedHeroHeadline, setTypedHeroHeadline] = useState("");

  const [selectedFile, setSelectedFile] = useState(null);
  const [isSubmittingScan, setIsSubmittingScan] = useState(false);
  const [activeJob, setActiveJob] = useState(null);
  const [jobs, setJobs] = useState([]);
  const [reports, setReports] = useState([]);
  const [activeReport, setActiveReport] = useState(null);
  const [apiKeys, setApiKeys] = useState([]);
  const [newApiKey, setNewApiKey] = useState("");
  const [newApiKeyName, setNewApiKeyName] = useState("Default Key");
  const [isCreatingKey, setIsCreatingKey] = useState(false);
  const [shareState, setShareState] = useState({
    url: "",
    expiresAt: ""
  });
  const [shareError, setShareError] = useState("");
  const [isCreatingShare, setIsCreatingShare] = useState(false);
  const [shareCopied, setShareCopied] = useState(false);

  const fileInputRef = useRef(null);
  const guestFileInputRef = useRef(null);

  const verdict = activeReport?.verdict || "clean";
  const verdictMeta = useMemo(() => VERDICT_META[verdict] || VERDICT_META.clean, [verdict]);
  const guestVerdictMeta = useMemo(() => VERDICT_META[guestReport?.verdict] || VERDICT_META.clean, [guestReport]);
  const guestRiskMeta = useMemo(() => getRiskMeta(guestReport?.riskScore), [guestReport?.riskScore]);
  const activeRiskMeta = useMemo(() => getRiskMeta(activeReport?.riskScore), [activeReport?.riskScore]);
  const activeReportId = activeReport?.id || null;
  const reportIntel = activeReport?.intel || null;
  const heroBackground = useMemo(() => {
    const variant = resolveHeroBackgroundVariant();
    return HERO_BG_VARIANTS[variant] || HERO_BG_VARIANTS[HERO_BG_DEFAULT];
  }, []);

  const quotaText = useMemo(() => {
    if (!session?.usage) {
      return "Usage unavailable";
    }

    if (session.usage.limit == null) {
      return "Unlimited quota (admin)";
    }

    return `${session.usage.used}/${session.usage.limit} scans used today`;
  }, [session]);

  const queueMetrics = useMemo(() => {
    return jobs.reduce(
      (accumulator, job) => {
        if (job.status === "queued") {
          accumulator.queued += 1;
        } else if (job.status === "processing") {
          accumulator.processing += 1;
        } else if (job.status === "completed") {
          accumulator.completed += 1;
        }

        return accumulator;
      },
      {
        queued: 0,
        processing: 0,
        completed: 0
      }
    );
  }, [jobs]);

  const latestReportLabel = useMemo(() => {
    const latest = reports[0]?.completedAt;
    return latest ? formatDateTime(latest) : "No reports yet";
  }, [reports]);

  useEffect(() => {
    if (typeof document !== "undefined") {
      document.title = APP_NAME;
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function bootstrap() {
      const stored = localStorage.getItem(SESSION_STORAGE_KEY);
      if (!stored) {
        if (!cancelled) {
          setAuthLoading(false);
        }
        return;
      }

      try {
        const parsed = JSON.parse(stored);
        if (!parsed?.accessToken || !parsed?.refreshToken) {
          throw new Error("Invalid session format");
        }

        if (!cancelled) {
          setSession(parsed);
          await loadDashboard(parsed);
        }
      } catch (_error) {
        localStorage.removeItem(SESSION_STORAGE_KEY);
        if (!cancelled) {
          setSession(null);
        }
      } finally {
        if (!cancelled) {
          setAuthLoading(false);
        }
      }
    }

    bootstrap();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let mounted = true;

    async function loadGuestStatus() {
      try {
        const payload = await apiRequest("/api/public/status", {
          authSession: null,
          retry: false
        });

        if (!mounted) {
          return;
        }

        setGuestStatus({
          loading: false,
          enabled: Boolean(payload?.quickScanEnabled),
          maxUploadMb: Number(payload?.maxUploadMb) || 8,
          message: payload?.message || ""
        });
      } catch (_error) {
        if (!mounted) {
          return;
        }

        setGuestStatus((current) => ({
          ...current,
          loading: false
        }));
      }
    }

    loadGuestStatus();

    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    if (session?.accessToken) {
      setTypedHeroHeadline(HERO_HEADLINE);
      return;
    }

    const reduceMotion =
      typeof window !== "undefined" &&
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    if (reduceMotion) {
      setTypedHeroHeadline(HERO_HEADLINE);
      return;
    }

    setTypedHeroHeadline("");
    let mounted = true;
    let timeoutId;
    let index = 0;

    const runTypingCycle = () => {
      if (!mounted) {
        return;
      }

      if (index <= HERO_HEADLINE.length) {
        setTypedHeroHeadline(HERO_HEADLINE.slice(0, index));
        index += 1;
        timeoutId = setTimeout(runTypingCycle, HERO_TYPE_SPEED_MS);
        return;
      }

      timeoutId = setTimeout(() => {
        if (!mounted) {
          return;
        }
        index = 0;
        setTypedHeroHeadline("");
        timeoutId = setTimeout(runTypingCycle, HERO_TYPE_SPEED_MS);
      }, HERO_CYCLE_PAUSE_MS);
    };

    timeoutId = setTimeout(runTypingCycle, HERO_TYPE_SPEED_MS);

    return () => {
      mounted = false;
      clearTimeout(timeoutId);
    };
  }, [session?.accessToken]);

  useEffect(() => {
    if (!session || !activeJob?.id || activeJob.status === "completed" || activeJob.status === "failed") {
      return;
    }

    const timer = setInterval(async () => {
      try {
        const payload = await apiRequest(`/api/scans/jobs/${activeJob.id}`, {
          authSession: session
        });

        setActiveJob(payload.job);
        await refreshJobs(session);

        if (payload.job.status === "completed" && payload.job.reportId) {
          await openReport(payload.job.reportId, session);
          await refreshReports(session);
        }
      } catch (error) {
        setGlobalError(error.message);
      }
    }, 1400);

    return () => clearInterval(timer);
  }, [activeJob, session]);

  useEffect(() => {
    setShareState({
      url: "",
      expiresAt: ""
    });
    setShareError("");
    setShareCopied(false);
  }, [activeReportId]);

  async function apiRequest(path, { method = "GET", body, formData, authSession = null, retry = true } = {}) {
    const headers = {};

    if (!formData) {
      headers["Content-Type"] = "application/json";
    }

    if (authSession?.accessToken) {
      headers.Authorization = `Bearer ${authSession.accessToken}`;
    }

    const response = await fetch(buildApiUrl(path), {
      method,
      headers,
      body: formData || (body ? JSON.stringify(body) : undefined)
    });

    const isJson = response.headers.get("content-type")?.includes("application/json");
    const payload = isJson ? await response.json() : null;

    if (response.status === 401 && authSession?.refreshToken && retry) {
      const refreshedSession = await refreshAuthSession(authSession.refreshToken);
      return apiRequest(path, {
        method,
        body,
        formData,
        authSession: refreshedSession,
        retry: false
      });
    }

    if (!response.ok) {
      throw new Error(parseErrorMessage(payload, `${method} ${path} failed with ${response.status}`));
    }

    return payload;
  }

  async function refreshAuthSession(refreshToken) {
    const payload = await apiRequest("/api/auth/refresh", {
      method: "POST",
      body: { refreshToken },
      authSession: null,
      retry: false
    });

    const nextSession = {
      accessToken: payload.accessToken,
      refreshToken: payload.refreshToken,
      user: payload.user,
      usage: null
    };

    setSession(nextSession);
    localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(nextSession));
    return nextSession;
  }

  async function loadDashboard(activeSession) {
    const mePayload = await apiRequest("/api/auth/me", { authSession: activeSession });

    const nextSession = {
      ...activeSession,
      user: mePayload.user,
      usage: mePayload.usage
    };

    setSession(nextSession);
    localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(nextSession));

    await Promise.all([refreshJobs(nextSession), refreshReports(nextSession), refreshApiKeys(nextSession)]);
  }

  async function refreshJobs(activeSession = session) {
    if (!activeSession) {
      return;
    }

    const payload = await apiRequest("/api/scans/jobs?limit=12", { authSession: activeSession });
    setJobs(payload.jobs || []);
  }

  async function refreshReports(activeSession = session) {
    if (!activeSession) {
      return;
    }

    const payload = await apiRequest("/api/scans/reports?limit=20", { authSession: activeSession });
    setReports(payload.reports || []);
  }

  async function refreshApiKeys(activeSession = session) {
    if (!activeSession) {
      return;
    }

    const payload = await apiRequest("/api/auth/api-keys", { authSession: activeSession });
    setApiKeys(payload.keys || []);
  }

  async function openReport(reportId, activeSession = session) {
    if (!activeSession) {
      return;
    }

    const payload = await apiRequest(`/api/scans/reports/${reportId}`, { authSession: activeSession });
    setActiveReport(payload.report || null);
  }

  async function submitAuth() {
    setAuthSubmitting(true);
    setAuthError("");

    try {
      const endpoint = authMode === "register" ? "/api/auth/register" : "/api/auth/login";
      const payload = await apiRequest(endpoint, {
        method: "POST",
        body: {
          email: authForm.email,
          password: authForm.password,
          ...(authMode === "register" ? { name: authForm.name } : {})
        },
        authSession: null,
        retry: false
      });

      const nextSession = {
        accessToken: payload.accessToken,
        refreshToken: payload.refreshToken,
        user: payload.user,
        usage: null
      };

      setSession(nextSession);
      localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(nextSession));
      await loadDashboard(nextSession);
    } catch (error) {
      setAuthError(error.message);
    } finally {
      setAuthSubmitting(false);
    }
  }

  async function logout() {
    if (session?.refreshToken) {
      try {
        await apiRequest("/api/auth/logout", {
          method: "POST",
          body: { refreshToken: session.refreshToken },
          authSession: null,
          retry: false
        });
      } catch (_error) {
        // Ignore logout transport errors.
      }
    }

    setSession(null);
    setActiveReport(null);
    setReports([]);
    setJobs([]);
    setApiKeys([]);
    setNewApiKey("");
    setShareState({
      url: "",
      expiresAt: ""
    });
    setShareError("");
    setShareCopied(false);
    localStorage.removeItem(SESSION_STORAGE_KEY);
  }

  async function submitScan() {
    if (!session || !selectedFile || isSubmittingScan) {
      return;
    }

    setGlobalError("");
    setIsSubmittingScan(true);

    try {
      const formData = new FormData();
      formData.append("file", selectedFile);

      const payload = await apiRequest("/api/scans/jobs", {
        method: "POST",
        formData,
        authSession: session
      });

      setActiveJob(payload.job);
      setSelectedFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }

      setSession((current) => {
        if (!current) {
          return current;
        }

        const next = {
          ...current,
          usage: {
            day: current.usage?.day || new Date().toISOString().slice(0, 10),
            used: payload.quota?.used ?? current.usage?.used,
            remaining: payload.quota?.remaining ?? current.usage?.remaining,
            limit: payload.quota?.limit ?? current.usage?.limit
          }
        };

        localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(next));
        return next;
      });

      await refreshJobs(session);
    } catch (error) {
      setGlobalError(error.message);
    } finally {
      setIsSubmittingScan(false);
    }
  }

  async function createApiKey() {
    if (!session || isCreatingKey) {
      return;
    }

    setIsCreatingKey(true);
    setGlobalError("");
    setNewApiKey("");

    try {
      const payload = await apiRequest("/api/auth/api-keys", {
        method: "POST",
        body: {
          name: newApiKeyName
        },
        authSession: session
      });

      setNewApiKey(payload.apiKey || "");
      await refreshApiKeys(session);
    } catch (error) {
      setGlobalError(error.message);
    } finally {
      setIsCreatingKey(false);
    }
  }

  async function revokeApiKey(keyId) {
    if (!session) {
      return;
    }

    setGlobalError("");

    try {
      await apiRequest(`/api/auth/api-keys/${keyId}`, {
        method: "DELETE",
        authSession: session
      });

      await refreshApiKeys(session);
    } catch (error) {
      setGlobalError(error.message);
    }
  }

  async function createReportShareLink() {
    if (!session || !activeReportId || isCreatingShare) {
      return;
    }

    setIsCreatingShare(true);
    setShareError("");
    setShareCopied(false);

    try {
      const payload = await apiRequest(`/api/scans/reports/${activeReportId}/share`, {
        method: "POST",
        authSession: session
      });

      const baseOrigin = typeof window !== "undefined" ? window.location.origin : "";
      const resolvedUrl = payload.shareUrl || (payload.publicApiPath ? `${baseOrigin}${payload.publicApiPath}` : "");

      setShareState({
        url: resolvedUrl,
        expiresAt: payload.expiresAt || ""
      });
    } catch (error) {
      setShareError(error.message || "Failed to generate share link.");
    } finally {
      setIsCreatingShare(false);
    }
  }

  async function copyShareLink() {
    if (!shareState.url) {
      return;
    }

    if (!navigator?.clipboard?.writeText) {
      setShareError("Clipboard is unavailable in this browser.");
      return;
    }

    try {
      await navigator.clipboard.writeText(shareState.url);
      setShareCopied(true);
    } catch (_error) {
      setShareError("Could not copy link.");
    }
  }

  function handleGuestFile(file) {
    if (!file) {
      return;
    }

    if (!guestStatus.enabled) {
      setGuestError("Guest quick scan is currently disabled.");
      return;
    }

    const maxUploadBytes = guestStatus.maxUploadMb * 1024 * 1024;
    if (file.size > maxUploadBytes) {
      setGuestFile(null);
      setGuestReport(null);
      setGuestError(`File exceeds guest limit of ${guestStatus.maxUploadMb} MB.`);
      return;
    }

    setGuestFile(file);
    setGuestReport(null);
    setGuestError("");
  }

  async function runGuestQuickScan() {
    if (!guestFile || isGuestScanning) {
      return;
    }

    if (!guestStatus.enabled) {
      setGuestError("Guest quick scan is currently unavailable.");
      return;
    }

    setGuestError("");
    setGuestReport(null);
    setIsGuestScanning(true);

    try {
      const formData = new FormData();
      formData.append("file", guestFile);

      const payload = await apiRequest("/api/public/quick-scan", {
        method: "POST",
        formData,
        authSession: null,
        retry: false
      });

      setGuestReport(payload.report || null);
    } catch (error) {
      setGuestError(error.message || "Quick scan failed.");
    } finally {
      setIsGuestScanning(false);
    }
  }

  if (authLoading) {
    return (
      <main className="app-shell centered">
        <section className="card loading-card">
          <div className="brand-lockup">
            <img src={BRAND_MARKS.lightSurface} alt={LOGO_ALT_TEXT} className="brand-mark brand-mark-small" />
            <h1>{APP_NAME}</h1>
          </div>
          <p>Loading secure session...</p>
        </section>
      </main>
    );
  }

  if (!session?.accessToken) {
    return (
      <main className="app-shell landing-shell">
        <section
          className="card landing-hero"
          style={{
            "--landing-hero-poster": `url("${heroBackground.posterSrc}")`
          }}
        >
          <video
            className="landing-hero-video"
            autoPlay
            muted
            loop
            playsInline
            preload="auto"
            poster={heroBackground.posterSrc}
            aria-hidden="true"
          >
            <source src={heroBackground.videoSrc} type="video/mp4" />
          </video>
          <div className="landing-hero-content">
            <div className="landing-hero-top">
              <img src={BRAND_MARKS.darkSurface} alt={LOGO_ALT_TEXT} className="landing-hero-logo" />
              <div className="landing-hero-brand">
                <strong>{APP_NAME}</strong>
                <span>{APP_TAGLINE}</span>
              </div>
            </div>
            <div className="landing-copy">
              <p className="eyebrow">Malware and Defect Detection Platform</p>
              <h1 className="hero-typing" aria-label={HERO_HEADLINE}>
                <span>{typedHeroHeadline}</span>
                <span className="typing-caret" aria-hidden="true" />
              </h1>
              <p className="subtext">
                {APP_NAME} analyzes uploaded files using layered heuristics and security engines, then returns a clear
                risk score, findings, and actionable recommendations.
              </p>
              <ul className="hero-points">
                <li>Real-time guest scan for rapid file checks</li>
                <li>Automated verdicts with clear, plain-language findings</li>
                <li>Full account workflow with saved reports and API keys</li>
              </ul>
            </div>
          </div>
        </section>

        <section className="card guest-card">
          <div className="section-head">
            <h2>Quick Guest Scan</h2>
            <span className="panel-tag">No account needed</span>
          </div>
          <p className="subtext">
            Drop one file and test the scanner instantly. Guest scans are for evaluation and are not saved to your
            account history.
          </p>
          <div className="guest-meta">
            <span className={`pill ${guestStatus.enabled ? "clean" : "failed"}`}>
              {guestStatus.loading ? "Checking status..." : guestStatus.enabled ? "Guest scan online" : "Guest scan unavailable"}
            </span>
            <span className="guest-meta-limit">Max upload {guestStatus.maxUploadMb} MB</span>
          </div>
          {guestStatus.message ? <p className="muted">{guestStatus.message}</p> : null}

          <label
            className={`upload-drop guest-drop ${guestFile ? "has-file" : ""} ${isGuestDragActive ? "drag-active" : ""} ${!guestStatus.enabled ? "disabled" : ""}`}
            onDragOver={(event) => {
              if (!guestStatus.enabled) {
                return;
              }
              event.preventDefault();
              setIsGuestDragActive(true);
            }}
            onDragLeave={() => setIsGuestDragActive(false)}
            onDrop={(event) => {
              if (!guestStatus.enabled) {
                return;
              }
              event.preventDefault();
              setIsGuestDragActive(false);
              handleGuestFile(event.dataTransfer.files?.[0] || null);
            }}
          >
            <input
              ref={guestFileInputRef}
              type="file"
              className="file-input-hidden"
              disabled={!guestStatus.enabled}
              onChange={(event) => handleGuestFile(event.target.files?.[0] || null)}
            />
            <span className="drop-title">{guestFile ? guestFile.name : "Drop file here or click to choose"}</span>
            <small>{guestFile ? formatBytes(guestFile.size) : "Fast guest scan with temporary upload processing"}</small>
          </label>

          <div className="upload-actions">
            <button
              type="button"
              className="primary"
              disabled={!guestFile || isGuestScanning || !guestStatus.enabled}
              onClick={runGuestQuickScan}
            >
              {isGuestScanning ? "Scanning..." : "Run Guest Scan"}
            </button>
            <button
              type="button"
              className="ghost"
              disabled={!guestFile || !guestStatus.enabled}
              onClick={() => {
                setGuestFile(null);
                setGuestReport(null);
                if (guestFileInputRef.current) {
                  guestFileInputRef.current.value = "";
                }
              }}
            >
              Clear
            </button>
          </div>

          {guestError ? <p className="error">{guestError}</p> : null}

          {guestReport ? (
            <div className="guest-report-box">
              <div className="report-header">
                <h3>Guest Result</h3>
                <span className={`pill ${guestVerdictMeta.tone}`}>{guestVerdictMeta.label}</span>
              </div>
              <div className="summary-grid">
                <div>
                  <span>Risk Score</span>
                  <strong className={`risk-score ${guestRiskMeta.tone}`}>{guestReport.riskScore}/100</strong>
                  <small className={`risk-label ${guestRiskMeta.tone}`}>{guestRiskMeta.label}</small>
                </div>
                <div>
                  <span>File Type</span>
                  <strong>{getDisplayFileType(guestReport.file)}</strong>
                </div>
              </div>
              {guestReport.findings.length > 0 ? (
                <ul className="guest-findings">
                  {guestReport.findings.slice(0, 3).map((finding) => (
                    <li key={`${finding.id}-${finding.title}`}>
                      <div className="guest-finding-copy">
                        <strong>{finding.title}</strong>
                        <small>{getPlainFindingNote(finding)}</small>
                      </div>
                      <span>{finding.severity}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="muted">No significant findings in guest scan.</p>
              )}
            </div>
          ) : null}
        </section>

        <section className="card auth-card landing-auth-card">
          <h2 className="auth-title">Create Account for Full Workflow</h2>
          <p className="subtext">Save reports, queue jobs, and generate API keys for automation.</p>

          <div className="auth-switch">
            <button type="button" className={authMode === "login" ? "active" : ""} onClick={() => setAuthMode("login")}>
              Sign in
            </button>
            <button
              type="button"
              className={authMode === "register" ? "active" : ""}
              onClick={() => setAuthMode("register")}
            >
              Create account
            </button>
          </div>

          {authMode === "register" ? (
            <label>
              Name
              <input
                value={authForm.name}
                onChange={(event) => setAuthForm((prev) => ({ ...prev, name: event.target.value }))}
                placeholder="Security Analyst"
              />
            </label>
          ) : null}

          <label>
            Email
            <input
              type="email"
              value={authForm.email}
              onChange={(event) => setAuthForm((prev) => ({ ...prev, email: event.target.value }))}
              placeholder="you@company.com"
            />
          </label>

          <label>
            Password
            <input
              type="password"
              value={authForm.password}
              onChange={(event) => setAuthForm((prev) => ({ ...prev, password: event.target.value }))}
              placeholder="Strong passphrase"
            />
          </label>

          <button type="button" className="primary" onClick={submitAuth} disabled={authSubmitting}>
            {authSubmitting ? "Submitting..." : authMode === "register" ? "Create account" : "Sign in"}
          </button>

          {authError ? <p className="error">{authError}</p> : null}
        </section>

        <footer className="landing-footer">
          <div className="footer-brand">
            <img src={BRAND_MARKS.lightSurface} alt={LOGO_ALT_TEXT} className="footer-logo" />
            <p>&copy; {new Date().getFullYear()} {APP_NAME}</p>
          </div>
          <p>Secure malware and anomaly scanning for teams and daily operations.</p>
        </footer>
      </main>
    );
  }

  return (
    <main className="app-shell dashboard-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <div className="ambient ambient-three" />

      <header className="topbar card topbar-card">
        <div className="topbar-brand">
          <img src={BRAND_MARKS.lightSurface} alt={LOGO_ALT_TEXT} className="topbar-logo" />
          <div>
            <p className="eyebrow">Secure Threat Intelligence Workspace</p>
            <h1>{APP_NAME}</h1>
            <p className="subtext">
              Signed in as <strong>{session.user?.email}</strong> ({session.user?.role})
            </p>
          </div>
        </div>
        <div className="top-actions">
          <span className="quota-pill">{quotaText}</span>
          <button type="button" onClick={logout} className="ghost">
            Log out
          </button>
        </div>
      </header>

      <section className="metric-strip">
        <article className="metric-tile">
          <span>Queued</span>
          <strong>{queueMetrics.queued}</strong>
        </article>
        <article className="metric-tile">
          <span>Processing</span>
          <strong>{queueMetrics.processing}</strong>
        </article>
        <article className="metric-tile">
          <span>Completed</span>
          <strong>{queueMetrics.completed}</strong>
        </article>
        <article className="metric-tile">
          <span>Latest report</span>
          <strong>{latestReportLabel}</strong>
        </article>
      </section>

      {globalError ? <p className="error global-error">{globalError}</p> : null}

      <section className="layout">
        <article className="card upload-card reveal">
          <div className="section-head">
            <h2>Submit Scan</h2>
            <span className="panel-tag">Instant Queue</span>
          </div>
          <p className="subtext">Free tier includes queueing, report retention, and API key access.</p>

          <label className={`upload-drop ${selectedFile ? "has-file" : ""}`}>
            <input
              ref={fileInputRef}
              type="file"
              className="file-input-hidden"
              onChange={(event) => setSelectedFile(event.target.files?.[0] || null)}
            />
            <span className="drop-title">{selectedFile ? selectedFile.name : "Drop or choose a file"}</span>
            <small>{selectedFile ? formatBytes(selectedFile.size) : "Single file upload, scanned asynchronously"}</small>
          </label>

          <div className="upload-actions">
            <button type="button" className="primary" onClick={submitScan} disabled={!selectedFile || isSubmittingScan}>
              {isSubmittingScan ? "Queueing..." : "Queue Scan Job"}
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => {
                setSelectedFile(null);
                if (fileInputRef.current) {
                  fileInputRef.current.value = "";
                }
              }}
              disabled={!selectedFile}
            >
              Clear
            </button>
          </div>

          {activeJob ? (
            <div className={`job-box ${activeJob.status}`}>
              <h3>Active Job</h3>
              <div className={`job-status ${activeJob.status}`}>
                <span className="status-dot" />
                <strong>{activeJob.status}</strong>
              </div>
              <p>
                <strong>{activeJob.id}</strong>
              </p>
              {activeJob.errorMessage ? <p className="error inline">{activeJob.errorMessage}</p> : null}
            </div>
          ) : null}

          <h3>Recent Jobs</h3>
          <div className="list compact">
            {jobs.length === 0 ? <p className="muted">No jobs yet.</p> : null}
            {jobs.map((job) => (
              <div className="item" key={job.id}>
                <div>
                  <strong>{job.originalName}</strong>
                  <small>{formatDateTime(job.createdAt)}</small>
                </div>
                <span className={`pill ${job.status}`}>{job.status}</span>
              </div>
            ))}
          </div>
        </article>

        <article className="card report-card reveal">
          <div className="report-header">
            <h2>Threat Report</h2>
            <span className={`pill ${verdictMeta.tone}`}>{verdictMeta.label}</span>
          </div>

          {!activeReport ? (
            <div className="empty-panel">
              <p className="muted">Select a report from history once a job completes.</p>
            </div>
          ) : (
            <>
              <div className="report-tools">
                <button type="button" className="ghost small" onClick={createReportShareLink} disabled={isCreatingShare}>
                  {isCreatingShare ? "Generating link..." : "Generate Share Link"}
                </button>
              </div>

              {shareState.url ? (
                <div className="share-box">
                  <span className="eyebrow">Shareable API Link</span>
                  <code className="share-link">{shareState.url}</code>
                  <div className="upload-actions">
                    <button type="button" className="ghost small" onClick={copyShareLink}>
                      {shareCopied ? "Copied" : "Copy link"}
                    </button>
                    <a className="ghost small open-link" href={shareState.url} target="_blank" rel="noreferrer">
                      Open
                    </a>
                  </div>
                  <small className="muted">Expires {formatDateTime(shareState.expiresAt)}</small>
                </div>
              ) : null}

              {shareError ? <p className="error">{shareError}</p> : null}

              <div className="summary-grid">
                <div>
                  <span>Risk Score</span>
                  <strong className={`risk-score ${activeRiskMeta.tone}`}>{activeReport.riskScore}/100</strong>
                  <small className={`risk-label ${activeRiskMeta.tone}`}>{activeRiskMeta.label}</small>
                </div>
                <div>
                  <span>File</span>
                  <strong>{activeReport.file.originalName}</strong>
                </div>
                <div>
                  <span>Detected Type</span>
                  <strong>{getDisplayFileType(activeReport.file)}</strong>
                </div>
                <div>
                  <span>Completed</span>
                  <strong>{formatDateTime(activeReport.completedAt)}</strong>
                </div>
              </div>

              <div className="mini-grid">
                <div>
                  <span>SHA256</span>
                  <code>{activeReport.file.hashes.sha256}</code>
                </div>
                <div>
                  <span>File Size</span>
                  <strong>{formatBytes(activeReport.file.size)}</strong>
                </div>
              </div>

              {reportIntel ? (
                <div className="intel-box">
                  <h3>Known File Intelligence</h3>
                  <div className="summary-grid intel-grid">
                    <div>
                      <span>Seen Before</span>
                      <strong>{reportIntel.hashSeenBefore ? "Yes" : "No"}</strong>
                    </div>
                    <div>
                      <span>Previous Matches</span>
                      <strong>{reportIntel.previousMatches ?? 0}</strong>
                    </div>
                    <div>
                      <span>Total Occurrences</span>
                      <strong>{reportIntel.totalOccurrences ?? 1}</strong>
                    </div>
                    <div>
                      <span>Known Worst Verdict</span>
                      <strong>{formatVerdictLabel(reportIntel.knownWorstVerdict)}</strong>
                    </div>
                    <div>
                      <span>First Seen</span>
                      <strong>{formatDateTime(reportIntel.firstSeenAt)}</strong>
                    </div>
                    <div>
                      <span>Last Seen</span>
                      <strong>{formatDateTime(reportIntel.lastSeenAt)}</strong>
                    </div>
                  </div>
                </div>
              ) : null}

              <h3>Findings</h3>
              {activeReport.findings.length === 0 ? (
                <p className="muted">No notable indicators detected.</p>
              ) : (
                <div className="findings">
                  {activeReport.findings.map((finding) => (
                    <div className={`finding ${finding.severity}`} key={`${finding.id}-${finding.title}`}>
                      <div className="item-head">
                        <strong>{finding.title}</strong>
                        <span>{finding.severity}</span>
                      </div>
                      <p>{finding.description}</p>
                      <small>{finding.evidence}</small>
                    </div>
                  ))}
                </div>
              )}

              <h3>Recommendations</h3>
              <ul className="recommendations">
                {activeReport.recommendations.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </>
          )}
        </article>

        <aside className="card side-card reveal">
          <div className="section-head">
            <h2>Report History</h2>
            <span className="panel-tag">Fast Access</span>
          </div>
          <div className="list">
            {reports.length === 0 ? <p className="muted">No reports yet.</p> : null}
            {reports.map((report) => (
              <button
                type="button"
                className={`item item-button ${report.id === activeReportId ? "active" : ""}`}
                key={report.id}
                onClick={() => openReport(report.id)}
              >
                <div>
                  <strong>{report.fileName}</strong>
                  <small>{formatDateTime(report.completedAt)}</small>
                </div>
                <span className={`pill ${report.verdict}`}>{report.verdict}</span>
              </button>
            ))}
          </div>

          <div className="section-head keys-heading">
            <h2>API Keys</h2>
            <span className="panel-tag">Automation</span>
          </div>
          <div className="api-key-create">
            <input value={newApiKeyName} onChange={(event) => setNewApiKeyName(event.target.value)} placeholder="Key name" />
            <button type="button" className="primary" onClick={createApiKey} disabled={isCreatingKey}>
              {isCreatingKey ? "Creating..." : "Create API Key"}
            </button>
          </div>

          {newApiKey ? (
            <div className="new-key-box">
              <strong>Copy this key now (shown once)</strong>
              <code>{newApiKey}</code>
            </div>
          ) : null}

          <div className="list compact">
            {apiKeys.length === 0 ? <p className="muted">No keys yet.</p> : null}
            {apiKeys.map((key) => (
              <div className="item" key={key.id}>
                <div>
                  <strong>{key.name}</strong>
                  <small>{key.keyPrefix}</small>
                </div>
                {key.revokedAt ? (
                  <span className="pill revoked">revoked</span>
                ) : (
                  <button type="button" className="ghost small" onClick={() => revokeApiKey(key.id)}>
                    Revoke
                  </button>
                )}
              </div>
            ))}
          </div>
        </aside>
      </section>
    </main>
  );
}
