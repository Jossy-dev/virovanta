import { Suspense, lazy, useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { BrowserRouter, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { Toaster, toast } from "sonner";
import {
  APP_NAME,
  APP_TAGLINE,
  BRAND_MARKS,
  HERO_BG_DEFAULT,
  HERO_BG_VARIANTS,
  LOGO_ALT_TEXT,
  SESSION_STORAGE_KEY,
  buildApiUrl,
  buildSiteUrl
} from "./appConfig";
import { buildAnalyticsData } from "./dashboard/dashboardUtils";
import { MARKETING_PAGES } from "./marketing/marketingContent";
import { getSeoForPath } from "./seo/routeSeo";
import {
  HERO_CYCLE_PAUSE_MS,
  HERO_HEADLINE,
  HERO_TYPE_SPEED_MS,
  formatBytes,
  formatDateTime,
  formatVerdictLabel,
  getDisplayFileType,
  getRiskMeta,
  getThemePalette,
  motionPreset,
  parseErrorMessage,
  pluralize,
  readResetFlowState,
  resolveHeroBackgroundVariant,
  resolveTheme,
  selectHighlightedJob
} from "./appUtils";

const LandingPage = lazy(() => import("./pages/LandingPage"));
const MarketingPage = lazy(() => import("./pages/MarketingPage"));
const SignInPage = lazy(() => import("./pages/SignInPage"));
const SignUpPage = lazy(() => import("./pages/SignUpPage"));
const ForgotPasswordPage = lazy(() => import("./pages/ForgotPasswordPage"));
const ResetPasswordPage = lazy(() => import("./pages/ResetPasswordPage"));
const SharedReportPage = lazy(() => import("./pages/SharedReportPage"));
const DashboardShell = lazy(() => import("./dashboard/DashboardShell"));

const DEFAULT_SCAN_LIMITS = Object.freeze({
  maxFilesPerBatch: 10,
  maxUploadMb: 25
});

const API_KEY_SCOPE_OPTIONS = Object.freeze([
  "jobs:read",
  "jobs:write",
  "reports:read",
  "reports:share",
  "analytics:read"
]);

const DEFAULT_API_KEY_SCOPES = Object.freeze([...API_KEY_SCOPE_OPTIONS]);

const SESSION_PERSISTENCE_LOCAL = "local";
const SESSION_PERSISTENCE_SESSION = "session";

function getBrowserStorage(mode) {
  if (typeof window === "undefined") {
    return null;
  }

  return mode === SESSION_PERSISTENCE_SESSION ? window.sessionStorage : window.localStorage;
}

function readPersistedSession() {
  const localStore = getBrowserStorage(SESSION_PERSISTENCE_LOCAL);
  const sessionStore = getBrowserStorage(SESSION_PERSISTENCE_SESSION);

  const localValue = localStore?.getItem(SESSION_STORAGE_KEY);
  if (localValue) {
    return { raw: localValue, mode: SESSION_PERSISTENCE_LOCAL };
  }

  const sessionValue = sessionStore?.getItem(SESSION_STORAGE_KEY);
  if (sessionValue) {
    return { raw: sessionValue, mode: SESSION_PERSISTENCE_SESSION };
  }

  return null;
}

function persistSessionSnapshot(nextSession) {
  const mode = nextSession?.persistenceMode === SESSION_PERSISTENCE_SESSION ? SESSION_PERSISTENCE_SESSION : SESSION_PERSISTENCE_LOCAL;
  const activeStore = getBrowserStorage(mode);
  const inactiveStore = getBrowserStorage(mode === SESSION_PERSISTENCE_SESSION ? SESSION_PERSISTENCE_LOCAL : SESSION_PERSISTENCE_SESSION);

  if (!activeStore) {
    return;
  }

  activeStore.setItem(
    SESSION_STORAGE_KEY,
    JSON.stringify({
      ...nextSession,
      persistenceMode: mode
    })
  );
  inactiveStore?.removeItem(SESSION_STORAGE_KEY);
}

function clearPersistedSession() {
  getBrowserStorage(SESSION_PERSISTENCE_LOCAL)?.removeItem(SESSION_STORAGE_KEY);
  getBrowserStorage(SESSION_PERSISTENCE_SESSION)?.removeItem(SESSION_STORAGE_KEY);
}

function SessionLoading({ message = "Loading secure session..." }) {
  const prefersReducedMotion = useReducedMotion();

  return (
    <motion.main className="app-shell centered" {...motionPreset(prefersReducedMotion)}>
      <motion.section className="card loading-card" {...motionPreset(prefersReducedMotion, 0.03)}>
        <div className="brand-lockup">
          <img src={BRAND_MARKS.lightSurface} alt={LOGO_ALT_TEXT} className="brand-mark brand-mark-small" />
          <h1>{APP_NAME}</h1>
        </div>
        <p>{message}</p>
      </motion.section>
    </motion.main>
  );
}

function PublicOnlyRoute({ session, children }) {
  if (session?.accessToken) {
    return <Navigate to="/app/dashboard" replace />;
  }

  return children;
}

function RequireAuth({ session, children }) {
  if (!session?.accessToken) {
    return <Navigate to="/signin" replace />;
  }

  return children;
}

function AppContent() {
  const prefersReducedMotion = useReducedMotion();
  const navigate = useNavigate();
  const location = useLocation();
  const [resetFlow, setResetFlow] = useState(() => readResetFlowState());
  const [resetAccessToken, setResetAccessToken] = useState(() => readResetFlowState().accessToken);
  const [resetEmail, setResetEmail] = useState(() => readResetFlowState().email);
  const [authLoading, setAuthLoading] = useState(true);
  const [session, setSession] = useState(null);
  const [guestStatus, setGuestStatus] = useState({
    loading: true,
    enabled: true,
    maxUploadMb: 8,
    message: ""
  });
  const [typedHeroHeadline, setTypedHeroHeadline] = useState("");
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [isSubmittingScan, setIsSubmittingScan] = useState(false);
  const [activeJob, setActiveJob] = useState(null);
  const [scanLimits, setScanLimits] = useState(DEFAULT_SCAN_LIMITS);
  const [jobs, setJobs] = useState([]);
  const [reports, setReports] = useState([]);
  const [analytics, setAnalytics] = useState(() => buildAnalyticsData());
  const [notifications, setNotifications] = useState([]);
  const [activeReport, setActiveReport] = useState(null);
  const [apiKeys, setApiKeys] = useState([]);
  const [newApiKey, setNewApiKey] = useState("");
  const [newApiKeyName, setNewApiKeyName] = useState("Default Key");
  const [newApiKeyScopes, setNewApiKeyScopes] = useState(DEFAULT_API_KEY_SCOPES);
  const [isCreatingKey, setIsCreatingKey] = useState(false);
  const [shareState, setShareState] = useState({
    url: "",
    expiresAt: ""
  });
  const [shareError, setShareError] = useState("");
  const [isCreatingShare, setIsCreatingShare] = useState(false);
  const [shareCopied, setShareCopied] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [dashboardTheme, setDashboardTheme] = useState(resolveTheme);
  const redirectTimerRef = useRef(null);
  const activeReportId = activeReport?.id || null;

  const heroBackground = useMemo(() => {
    const variant = resolveHeroBackgroundVariant(HERO_BG_DEFAULT, HERO_BG_VARIANTS);
    return HERO_BG_VARIANTS[variant] || HERO_BG_VARIANTS[HERO_BG_DEFAULT];
  }, []);

  const activeRiskMeta = useMemo(() => getRiskMeta(activeReport?.riskScore), [activeReport?.riskScore]);
  const quotaText = useMemo(() => {
    if (!session?.usage) {
      return "Usage unavailable";
    }

    if (session.usage.limit == null) {
      return "Unlimited quota";
    }

    return `${session.usage.used}/${session.usage.limit} scans used in the last 24 hours`;
  }, [session]);
  const currentDateLabel = useMemo(
    () =>
      new Intl.DateTimeFormat(undefined, {
        weekday: "long",
        month: "long",
        day: "numeric",
        year: "numeric"
      }).format(new Date()),
    []
  );
  const themePalette = useMemo(() => getThemePalette(dashboardTheme), [dashboardTheme]);

  useEffect(() => {
    const syncResetFlow = () => {
      const next = readResetFlowState();
      setResetFlow(next);
      setResetAccessToken(next.active ? next.accessToken : "");
      setResetEmail(next.email || "");
    };

    syncResetFlow();

    if (typeof window === "undefined") {
      return undefined;
    }

    window.addEventListener("popstate", syncResetFlow);
    window.addEventListener("hashchange", syncResetFlow);

    return () => {
      window.removeEventListener("popstate", syncResetFlow);
      window.removeEventListener("hashchange", syncResetFlow);
    };
  }, []);

  useEffect(() => {
    if (resetFlow.callbackKind !== "confirmation" || session?.accessToken) {
      return;
    }

    const query = new URLSearchParams();
    if (resetFlow.email) {
      query.set("email", resetFlow.email);
    }
    query.set("confirmed", "1");

    navigate(`/signin?${query.toString()}`, { replace: true });
  }, [navigate, resetFlow.callbackKind, resetFlow.email, session?.accessToken]);

  useEffect(() => {
    if (!resetFlow.active) {
      return;
    }

    const query = resetEmail ? `?email=${encodeURIComponent(resetEmail)}` : "";

    if (location.pathname !== "/reset-password") {
      navigate(`/reset-password${query}`, { replace: true });
      return;
    }

    const hasSensitiveHash = String(window.location.hash || "").includes("access_token=");
    if (hasSensitiveHash) {
      window.history.replaceState({}, "", `/reset-password${query}`);
    }
  }, [location.pathname, navigate, resetEmail, resetFlow.active]);

  useEffect(() => {
    if (typeof document === "undefined") {
      return;
    }

    document.documentElement.classList.toggle("dark", dashboardTheme === "dark");
    window.localStorage.setItem("virovanta-dashboard-theme", dashboardTheme);
  }, [dashboardTheme]);

  useEffect(() => {
    if (typeof document === "undefined") {
      return;
    }

    const seo = getSeoForPath(location.pathname || "/");
    document.title = seo.title;

    const upsertMeta = (attribute, key, content) => {
      if (!content) {
        return;
      }

      let element = document.head.querySelector(`meta[${attribute}="${key}"]`);
      if (!element) {
        element = document.createElement("meta");
        element.setAttribute(attribute, key);
        document.head.appendChild(element);
      }
      element.setAttribute("content", content);
    };

    const upsertLink = (rel, href, options = {}) => {
      if (!href) {
        return;
      }

      const selectorParts = [`link[rel="${rel}"]`];
      if (options.hreflang) {
        selectorParts.push(`[hreflang="${options.hreflang}"]`);
      }
      const selector = selectorParts.join("");

      let element = document.head.querySelector(selector);
      if (!element) {
        element = document.createElement("link");
        element.setAttribute("rel", rel);
        if (options.hreflang) {
          element.setAttribute("hreflang", options.hreflang);
        }
        document.head.appendChild(element);
      }
      element.setAttribute("href", href);
    };

    upsertMeta("name", "description", seo.description);
    upsertMeta("name", "robots", seo.robots);
    upsertMeta("name", "googlebot", seo.robots);
    upsertMeta("name", "theme-color", "#1f8f5c");
    upsertMeta("property", "og:type", seo.ogType);
    upsertMeta("property", "og:site_name", APP_NAME);
    upsertMeta("property", "og:title", seo.title);
    upsertMeta("property", "og:description", seo.description);
    upsertMeta("property", "og:url", seo.canonicalUrl);
    upsertMeta("property", "og:image", seo.imageUrl);
    upsertMeta("property", "og:image:secure_url", seo.imageUrl);
    upsertMeta("property", "og:image:width", "1200");
    upsertMeta("property", "og:image:height", "630");
    upsertMeta("property", "og:image:alt", seo.imageAlt);
    upsertMeta("property", "og:locale", seo.locale);
    upsertMeta("name", "twitter:card", "summary_large_image");
    upsertMeta("name", "twitter:title", seo.title);
    upsertMeta("name", "twitter:description", seo.description);
    upsertMeta("name", "twitter:image", seo.imageUrl);
    upsertMeta("name", "twitter:image:alt", seo.imageAlt);

    upsertLink("canonical", seo.canonicalUrl);
    upsertLink("alternate", seo.canonicalUrl, { hreflang: "en" });
    upsertLink("alternate", seo.canonicalUrl, { hreflang: "x-default" });
    upsertLink("icon", seo.faviconUrl);
    upsertLink("apple-touch-icon", seo.logoUrl);

    const structuredDataId = "virovanta-structured-data";
    const existingStructuredData = document.getElementById(structuredDataId);
    if (seo.structuredDataGraph?.length) {
      const serialized = JSON.stringify(seo.structuredDataGraph[0]);
      if (existingStructuredData) {
        existingStructuredData.textContent = serialized;
      } else {
        const script = document.createElement("script");
        script.id = structuredDataId;
        script.type = "application/ld+json";
        script.textContent = serialized;
        document.head.appendChild(script);
      }
    } else if (existingStructuredData) {
      existingStructuredData.remove();
    }
  }, [location.pathname]);

  useEffect(() => {
    let cancelled = false;

    async function bootstrap() {
      const stored = readPersistedSession();
      if (!stored?.raw) {
        if (!cancelled) {
          setAuthLoading(false);
        }
        return;
      }

      try {
        const parsed = JSON.parse(stored.raw);
        if (!parsed?.accessToken || !parsed?.refreshToken) {
          throw new Error("Invalid session format");
        }

        const hydratedSession = {
          ...parsed,
          persistenceMode: parsed.persistenceMode || stored.mode
        };

        if (!cancelled) {
          setSession(hydratedSession);
          await loadDashboard(hydratedSession);
        }
      } catch (_error) {
        clearPersistedSession();
        if (!cancelled) {
          setSession(null);
        }
      } finally {
        if (!cancelled) {
          setAuthLoading(false);
        }
      }
    }

    void bootstrap();

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

    void loadGuestStatus();

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
        await Promise.all([refreshJobs(session), refreshAnalytics(session)]);

        if (payload.job.status === "completed" && payload.job.reportId) {
          await openReport(payload.job.reportId, session);
          await Promise.all([refreshReports(session), refreshNotifications(session), refreshAnalytics(session)]);
        } else if (payload.job.status === "failed") {
          await Promise.all([refreshNotifications(session), refreshAnalytics(session)]);
        }
      } catch (error) {
        toast.error(error.message || "Could not refresh scan job.");
      }
    }, 1400);

    return () => clearInterval(timer);
  }, [activeJob, session]);

  useEffect(() => {
    setShareState({ url: "", expiresAt: "" });
    setShareError("");
    setShareCopied(false);
  }, [activeReportId]);

  useEffect(() => {
    return () => {
      if (redirectTimerRef.current) {
        clearTimeout(redirectTimerRef.current);
      }
    };
  }, []);

  async function apiRequest(path, { method = "GET", body, formData, authSession = null, retry = true } = {}) {
    const normalizedMethod = String(method || "GET").toUpperCase();
    const headers = {};

    if (!formData && body !== undefined) {
      headers["Content-Type"] = "application/json";
    }

    if (authSession?.accessToken) {
      headers.Authorization = `Bearer ${authSession.accessToken}`;
    }

    const response = await fetch(buildApiUrl(path), {
      method: normalizedMethod,
      headers,
      body: formData || (body ? JSON.stringify(body) : undefined)
    });

    const isJson = response.headers.get("content-type")?.includes("application/json");
    const payload = isJson ? await response.json() : null;

    if (response.status === 401 && authSession?.refreshToken && retry) {
      const refreshedSession = await refreshAuthSession(authSession.refreshToken, authSession);
      return apiRequest(path, {
        method: normalizedMethod,
        body,
        formData,
        authSession: refreshedSession,
        retry: false
      });
    }

    if (!response.ok) {
      const requestError = new Error(parseErrorMessage(payload, `${normalizedMethod} ${path} failed with ${response.status}`));
      requestError.status = response.status;
      requestError.code = payload?.error?.code || "";
      requestError.details = payload?.error?.details || null;
      throw requestError;
    }

    return payload;
  }

  async function refreshAuthSession(refreshToken, currentSession = session) {
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
      usage: null,
      persistenceMode: currentSession?.persistenceMode || SESSION_PERSISTENCE_LOCAL
    };

    setSession(nextSession);
    persistSessionSnapshot(nextSession);
    return nextSession;
  }

  async function loadDashboard(activeSession) {
    const mePayload = await apiRequest("/api/auth/me", { authSession: activeSession });

    const nextSession = {
      ...activeSession,
      user: mePayload.user,
      usage: mePayload.usage,
      persistenceMode: activeSession?.persistenceMode || SESSION_PERSISTENCE_LOCAL
    };

    setScanLimits({
      maxFilesPerBatch: Number(mePayload?.scanLimits?.maxFilesPerBatch) || DEFAULT_SCAN_LIMITS.maxFilesPerBatch,
      maxUploadMb: Number(mePayload?.scanLimits?.maxUploadMb) || DEFAULT_SCAN_LIMITS.maxUploadMb
    });
    setSession(nextSession);
    persistSessionSnapshot(nextSession);

    await Promise.all([
      refreshJobs(nextSession),
      refreshReports(nextSession),
      refreshApiKeys(nextSession),
      refreshNotifications(nextSession),
      refreshAnalytics(nextSession)
    ]);
  }

  async function refreshJobs(activeSession = session) {
    if (!activeSession) {
      return;
    }

    const payload = await apiRequest("/api/scans/jobs?limit=12", { authSession: activeSession });
    const nextJobs = Array.isArray(payload?.jobs) ? payload.jobs : [];
    setJobs(nextJobs);
    setActiveJob((current) => selectHighlightedJob(nextJobs, current?.id || ""));
  }

  async function refreshReports(activeSession = session) {
    if (!activeSession) {
      return;
    }

    const payload = await apiRequest("/api/scans/reports?limit=20", { authSession: activeSession });
    const nextReports = Array.isArray(payload?.reports) ? payload.reports : [];
    setReports(nextReports);

    if (nextReports.length === 0) {
      setActiveReport(null);
      return;
    }

    if (!activeReportId || !nextReports.some((report) => report.id === activeReportId)) {
      await openReport(nextReports[0].id, activeSession);
    }
  }

  async function refreshAnalytics(activeSession = session) {
    if (!activeSession) {
      setAnalytics(buildAnalyticsData());
      return;
    }

    const payload = await apiRequest("/api/scans/analytics", { authSession: activeSession });
    setAnalytics(buildAnalyticsData(payload?.analytics));
  }

  async function refreshApiKeys(activeSession = session) {
    if (!activeSession) {
      return;
    }

    const payload = await apiRequest("/api/auth/api-keys", { authSession: activeSession });
    setApiKeys(payload.keys || []);
  }

  async function refreshNotifications(activeSession = session) {
    if (!activeSession) {
      return;
    }

    const payload = await apiRequest("/api/auth/notifications?limit=20", { authSession: activeSession });
    setNotifications(Array.isArray(payload?.notifications) ? payload.notifications : []);
  }

  async function openReport(reportId, activeSession = session) {
    if (!activeSession) {
      return;
    }

    const payload = await apiRequest(`/api/scans/reports/${reportId}`, { authSession: activeSession });
    setActiveReport(payload.report || null);
  }

  async function loginUser({ email, password, rememberMe = true }) {
    const normalizedEmail = String(email || "").trim().toLowerCase();
    const payload = await apiRequest("/api/auth/login", {
      method: "POST",
      body: {
        email: normalizedEmail,
        password: String(password || "")
      },
      authSession: null,
      retry: false
    });

    const nextSession = {
      accessToken: payload.accessToken,
      refreshToken: payload.refreshToken,
      user: payload.user,
      usage: null,
      persistenceMode: rememberMe ? SESSION_PERSISTENCE_LOCAL : SESSION_PERSISTENCE_SESSION
    };

    setSession(nextSession);
    persistSessionSnapshot(nextSession);
    await loadDashboard(nextSession);
    return payload;
  }

  async function registerUser({ email, password, username }) {
    const normalizedEmail = String(email || "").trim().toLowerCase();
    const payload = await apiRequest("/api/auth/register", {
      method: "POST",
      body: {
        email: normalizedEmail,
        password: String(password || ""),
        name: String(username || "").trim()
      },
      authSession: null,
      retry: false
    });

    if (payload?.requiresEmailConfirmation) {
      return payload;
    }

    const nextSession = {
      accessToken: payload.accessToken,
      refreshToken: payload.refreshToken,
      user: payload.user,
      usage: null,
      persistenceMode: SESSION_PERSISTENCE_LOCAL
    };

    setSession(nextSession);
    persistSessionSnapshot(nextSession);
    await loadDashboard(nextSession);
    return payload;
  }

  async function checkUsernameAvailability(username) {
    return apiRequest(`/api/auth/username-availability?username=${encodeURIComponent(username)}`, {
      authSession: null,
      retry: false
    });
  }

  async function requestForgotPassword(email) {
    return apiRequest("/api/auth/forgot-password", {
      method: "POST",
      body: { email: String(email || "").trim().toLowerCase() },
      authSession: null,
      retry: false
    });
  }

  async function submitPasswordReset({ accessToken, password, email }) {
    const payload = await apiRequest("/api/auth/reset-password", {
      method: "POST",
      body: {
        accessToken,
        password,
        ...(email ? { email } : {})
      },
      authSession: null,
      retry: false
    });

    const query = email ? `?email=${encodeURIComponent(email)}` : "";
    if (typeof window !== "undefined") {
      if (redirectTimerRef.current) {
        clearTimeout(redirectTimerRef.current);
      }

      redirectTimerRef.current = setTimeout(() => {
        window.history.replaceState({}, "", `/signin${query}`);
        setResetAccessToken("");
        setResetFlow({
          active: false,
          accessToken: "",
          email
        });
      }, 900);
    }

    return payload;
  }

  async function runGuestQuickScan(file) {
    if (!file) {
      throw new Error("Select a file first.");
    }

    if (!guestStatus.enabled) {
      throw new Error("Guest quick scan is currently unavailable.");
    }

    const formData = new FormData();
    formData.append("file", file);

    const payload = await apiRequest("/api/public/quick-scan", {
      method: "POST",
      formData,
      authSession: null,
      retry: false
    });

    return payload.report || null;
  }

  function clearSelectedFiles() {
    setSelectedFiles([]);
  }

  function handleSelectedFiles(fileList) {
    const nextFiles = Array.from(fileList || []).filter(Boolean);
    if (nextFiles.length === 0) {
      clearSelectedFiles();
      return;
    }

    const maxFilesPerBatch = Number(scanLimits?.maxFilesPerBatch) || DEFAULT_SCAN_LIMITS.maxFilesPerBatch;
    if (nextFiles.length > maxFilesPerBatch) {
      toast.error(`You can queue up to ${maxFilesPerBatch} files at once.`);
    }

    setSelectedFiles(nextFiles.slice(0, maxFilesPerBatch));
  }

  async function logout() {
    if (session?.refreshToken) {
      try {
        await apiRequest("/api/auth/logout", {
          method: "POST",
          body: { refreshToken: session.refreshToken },
          authSession: session,
          retry: false
        });
      } catch (_error) {
        // Ignore logout transport errors.
      }
    }

    setSession(null);
    setScanLimits(DEFAULT_SCAN_LIMITS);
    setActiveReport(null);
    setReports([]);
    setNotifications([]);
    setJobs([]);
    setAnalytics(buildAnalyticsData());
    setActiveJob(null);
    setApiKeys([]);
    setNewApiKey("");
    setNewApiKeyScopes(DEFAULT_API_KEY_SCOPES);
    setSearchQuery("");
    clearSelectedFiles();
    setShareState({ url: "", expiresAt: "" });
    setShareError("");
    setShareCopied(false);
    clearPersistedSession();
    navigate("/signin", { replace: true });
  }

  async function submitScan() {
    if (!session || selectedFiles.length === 0 || isSubmittingScan) {
      return;
    }

    setIsSubmittingScan(true);

    try {
      const formData = new FormData();
      selectedFiles.forEach((file) => {
        formData.append("files", file);
      });

      const payload = await apiRequest("/api/scans/jobs", {
        method: "POST",
        formData,
        authSession: session
      });

      const queuedJobs = Array.isArray(payload?.jobs) ? payload.jobs : payload?.job ? [payload.job] : [];
      setActiveJob(queuedJobs[0] || null);
      clearSelectedFiles();

      setSession((current) => {
        if (!current) {
          return current;
        }

        const next = {
          ...current,
          usage: {
            windowStartedAt:
              payload.quota?.windowStartedAt ||
              current.usage?.windowStartedAt ||
              new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
            used: payload.quota?.used ?? current.usage?.used,
            remaining: payload.quota?.remaining ?? current.usage?.remaining,
            limit: payload.quota?.limit ?? current.usage?.limit
          }
        };

        persistSessionSnapshot(next);
        return next;
      });

      toast.success(queuedJobs.length > 1 ? `${pluralize("scan job", queuedJobs.length)} queued.` : "Scan job queued.");
      await Promise.all([refreshJobs(session), refreshNotifications(session), refreshAnalytics(session)]);
      navigate("/app/projects", { replace: false });
    } catch (error) {
      if (session && error?.code === "SCAN_QUOTA_EXCEEDED") {
        await refreshNotifications(session);
      }
      toast.error(error.message || "Could not queue scan jobs.");
      throw error;
    } finally {
      setIsSubmittingScan(false);
    }
  }

  async function createApiKey(requestInput = null) {
    if (!session || isCreatingKey) {
      return;
    }

    setIsCreatingKey(true);
    setNewApiKey("");

    try {
      const requestedName = String(requestInput?.name ?? newApiKeyName).trim();
      const requestedScopes = Array.isArray(requestInput?.scopes) ? requestInput.scopes : newApiKeyScopes;
      const normalizedScopes = requestedScopes
        .map((value) => String(value || "").trim().toLowerCase())
        .filter((value, index, source) => value && source.indexOf(value) === index && API_KEY_SCOPE_OPTIONS.includes(value));

      if (requestedName.length < 3) {
        toast.error("API key name must be at least 3 characters.");
        return;
      }

      if (normalizedScopes.length === 0) {
        toast.error("Select at least one scope for this API key.");
        return;
      }

      const responsePayload = await apiRequest("/api/auth/api-keys", {
        method: "POST",
        body: {
          name: requestedName,
          scopes: normalizedScopes
        },
        authSession: session
      });

      setNewApiKey(responsePayload.apiKey || "");
      setNewApiKeyName(requestedName);
      setNewApiKeyScopes(normalizedScopes);
      await Promise.all([refreshApiKeys(session), refreshNotifications(session)]);
      toast.success("API key created. Copy it now, it will not be shown again.");
    } catch (error) {
      toast.error(error.message || "Could not create API key.");
    } finally {
      setIsCreatingKey(false);
    }
  }

  async function markNotificationsViewed() {
    if (!session) {
      return;
    }

    const unreadCount = notifications.filter((item) => !item.readAt).length;
    if (unreadCount === 0) {
      return;
    }

    const readAt = new Date().toISOString();
    setNotifications((current) => current.map((item) => (item.readAt ? item : { ...item, readAt })));

    try {
      await apiRequest("/api/auth/notifications/read", {
        method: "POST",
        body: {},
        authSession: session
      });
    } catch (_error) {
      await refreshNotifications(session);
    }
  }

  async function revokeApiKey(keyId) {
    if (!session) {
      return;
    }

    try {
      await apiRequest(`/api/auth/api-keys/${keyId}`, {
        method: "DELETE",
        authSession: session
      });

      await Promise.all([refreshApiKeys(session), refreshNotifications(session)]);
    } catch (error) {
      toast.error(error.message || "Could not revoke API key.");
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

      const resolvedUrl = payload.shareToken
        ? buildSiteUrl(`/report/${payload.shareToken}`)
        : payload.shareUrl || (payload.publicApiPath ? buildSiteUrl(payload.publicApiPath) : "");

      setShareState({
        url: resolvedUrl,
        expiresAt: payload.expiresAt || ""
      });
      await refreshNotifications(session);
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

  async function loadSharedReport(token) {
    return apiRequest(`/api/public/shared-reports/${token}`, {
      authSession: null,
      retry: false
    });
  }

  if (authLoading) {
    return (
      <>
        <Toaster position="top-right" richColors closeButton expand />
        <SessionLoading />
      </>
    );
  }

  return (
    <>
      <Toaster position="top-right" richColors closeButton expand />
      <Suspense fallback={<SessionLoading message="Loading page..." />}>
        <Routes>
          <Route
            path="/"
            element={
              <PublicOnlyRoute session={session}>
                <LandingPage
                  appName={APP_NAME}
                  appTagline={APP_TAGLINE}
                  logoAltText={LOGO_ALT_TEXT}
                  brandMarks={BRAND_MARKS}
                  heroBackground={heroBackground}
                  typedHeroHeadline={typedHeroHeadline}
                  guestStatus={guestStatus}
                  runGuestQuickScan={runGuestQuickScan}
                />
              </PublicOnlyRoute>
            }
          />
          {MARKETING_PAGES.map((page) => (
            <Route
              key={page.path}
              path={page.path}
              element={
                <MarketingPage
                  appName={APP_NAME}
                  appTagline={APP_TAGLINE}
                  logoAltText={LOGO_ALT_TEXT}
                  brandMarks={BRAND_MARKS}
                  routePath={page.path}
                />
              }
            />
          ))}
          <Route
            path="/signin"
            element={
              <PublicOnlyRoute session={session}>
                <SignInPage
                  appName={APP_NAME}
                  appTagline={APP_TAGLINE}
                  logoAltText={LOGO_ALT_TEXT}
                  brandMarks={BRAND_MARKS}
                  onLogin={loginUser}
                />
              </PublicOnlyRoute>
            }
          />
          <Route
            path="/signup"
            element={
              <PublicOnlyRoute session={session}>
                <SignUpPage
                  appName={APP_NAME}
                  appTagline={APP_TAGLINE}
                  logoAltText={LOGO_ALT_TEXT}
                  brandMarks={BRAND_MARKS}
                  onRegister={registerUser}
                  onCheckUsernameAvailability={checkUsernameAvailability}
                  onRequestForgotPassword={requestForgotPassword}
                />
              </PublicOnlyRoute>
            }
          />
          <Route
            path="/forgot-password"
            element={
              <PublicOnlyRoute session={session}>
                <ForgotPasswordPage
                  appName={APP_NAME}
                  appTagline={APP_TAGLINE}
                  logoAltText={LOGO_ALT_TEXT}
                  brandMarks={BRAND_MARKS}
                  onRequestForgotPassword={requestForgotPassword}
                />
              </PublicOnlyRoute>
            }
          />
          <Route
            path="/reset-password"
            element={
              <ResetPasswordPage
                appName={APP_NAME}
                appTagline={APP_TAGLINE}
                logoAltText={LOGO_ALT_TEXT}
                brandMarks={BRAND_MARKS}
                resetAccessToken={resetAccessToken}
                resetEmail={resetEmail}
                onResetPassword={submitPasswordReset}
              />
            }
          />
          <Route
            path="/report/:token"
            element={
              <SharedReportPage
                appName={APP_NAME}
                logoAltText={LOGO_ALT_TEXT}
                brandMarks={BRAND_MARKS}
                onLoadSharedReport={loadSharedReport}
              />
            }
          />
          <Route
            path="/app/*"
            element={
              <RequireAuth session={session}>
                <DashboardShell
                  appName={APP_NAME}
                  logoSrc={BRAND_MARKS.lightSurface}
                  session={session}
                  searchQuery={searchQuery}
                  onSearchChange={setSearchQuery}
                  theme={dashboardTheme}
                  onToggleTheme={() => setDashboardTheme((current) => (current === "dark" ? "light" : "dark"))}
                  selectedFiles={selectedFiles}
                  scanLimits={scanLimits}
                  isSubmittingScan={isSubmittingScan}
                  jobs={jobs}
                  reports={reports}
                  activeJob={activeJob}
                  activeReport={activeReport}
                  activeRiskMeta={activeRiskMeta}
                  shareState={shareState}
                  shareError={shareError}
                  isCreatingShare={isCreatingShare}
                  shareCopied={shareCopied}
                  apiKeys={apiKeys}
                  newApiKey={newApiKey}
                  newApiKeyName={newApiKeyName}
                  newApiKeyScopes={newApiKeyScopes}
                  isCreatingKey={isCreatingKey}
                  setNewApiKeyName={setNewApiKeyName}
                  setNewApiKeyScopes={setNewApiKeyScopes}
                  notifications={notifications}
                  onLogout={logout}
                  onNotificationsViewed={markNotificationsViewed}
                  onSelectFiles={handleSelectedFiles}
                  onSubmitScan={submitScan}
                  onClearSelectedFiles={clearSelectedFiles}
                  onOpenReport={openReport}
                  onCreateShare={createReportShareLink}
                  onCopyShare={copyShareLink}
                  onCreateApiKey={createApiKey}
                  onRevokeApiKey={revokeApiKey}
                  formatDateTime={formatDateTime}
                  formatBytes={formatBytes}
                  pluralize={pluralize}
                  getDisplayFileType={getDisplayFileType}
                  formatVerdictLabel={formatVerdictLabel}
                  prefersReducedMotion={prefersReducedMotion}
                  currentDateLabel={currentDateLabel}
                  quotaText={quotaText}
                  analytics={analytics}
                  themePalette={themePalette}
                />
              </RequireAuth>
            }
          />
          <Route path="*" element={<Navigate to={session?.accessToken ? "/app/dashboard" : "/"} replace />} />
        </Routes>
      </Suspense>
    </>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  );
}
