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
  SESSION_ABSOLUTE_TIMEOUT_HOURS,
  SESSION_IDLE_TIMEOUT_MINUTES,
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
  parseErrorMessage,
  pluralize,
  readResetFlowState,
  resolveHeroBackgroundVariant,
  resolveTheme,
  selectHighlightedJob
} from "./appUtils";
import {
  loadDashboardShell,
  loadForgotPasswordPage,
  loadLandingPage,
  loadMarketingPage,
  loadResetPasswordPage,
  loadSharedReportPage,
  loadSignInPage,
  loadSignUpPage,
  loadStatusPage,
  ROUTE_PREFETCHERS
} from "./routeModules";
import { createEnterMotion, createPageTransitionMotion } from "./ui/motionSystem";
import { SkeletonBlock, SkeletonText } from "./ui/Skeleton";

const LandingPage = lazy(loadLandingPage);
const MarketingPage = lazy(loadMarketingPage);
const SignInPage = lazy(loadSignInPage);
const SignUpPage = lazy(loadSignUpPage);
const ForgotPasswordPage = lazy(loadForgotPasswordPage);
const ResetPasswordPage = lazy(loadResetPasswordPage);
const SharedReportPage = lazy(loadSharedReportPage);
const DashboardShell = lazy(loadDashboardShell);
const StatusPage = lazy(loadStatusPage);

const DEFAULT_SCAN_LIMITS = Object.freeze({
  maxFilesPerBatch: 10,
  maxUploadMb: 25
});

const API_KEY_SCOPE_OPTIONS = Object.freeze([
  "jobs:read",
  "jobs:write",
  "reports:read",
  "reports:share",
  "reports:delete",
  "analytics:read"
]);

const DEFAULT_API_KEY_SCOPES = Object.freeze([...API_KEY_SCOPE_OPTIONS]);

const SESSION_PERSISTENCE_LOCAL = "local";
const SESSION_PERSISTENCE_SESSION = "session";
const SESSION_HARD_MAX_AGE_MS = Math.max(60 * 60 * 1000, Math.floor(Number(SESSION_ABSOLUTE_TIMEOUT_HOURS) || 24) * 60 * 60 * 1000);
const SESSION_IDLE_MAX_AGE_MS = Math.max(5 * 60 * 1000, Math.floor(Number(SESSION_IDLE_TIMEOUT_MINUTES) || 60) * 60 * 1000);
const ACTIVITY_TOUCH_THROTTLE_MS = 15 * 1000;
const DASHBOARD_CACHE_VERSION = 1;
const DASHBOARD_CACHE_TTL_MS = 2 * 60 * 1000;
const DASHBOARD_CACHE_KEY = `${SESSION_STORAGE_KEY}-dashboard-cache`;
const ACCESS_TOKEN_FALLBACK_TTL_SECONDS = 15 * 60;
const ACCESS_TOKEN_REFRESH_SKEW_MS = 90 * 1000;
const ACCESS_TOKEN_MIN_REFRESH_DELAY_MS = 15 * 1000;
const ACCESS_TOKEN_UNKNOWN_REFRESH_DELAY_MS = 5 * 60 * 1000;
const AUTH_INVALID_CODES = new Set([
  "AUTH_REFRESH_INVALID",
  "AUTH_TOKEN_INVALID",
  "AUTH_UNAUTHORIZED",
  "AUTH_REQUIRED",
  "AUTH_SESSION_EXPIRED",
  "AUTH_SESSION_IDLE_EXPIRED"
]);

function resolveSessionStartedAt(value, fallbackMs = Date.now()) {
  const parsed = Date.parse(String(value || ""));
  if (Number.isFinite(parsed)) {
    return new Date(parsed).toISOString();
  }

  return new Date(fallbackMs).toISOString();
}

function resolveSessionLastActivityAt(value, fallbackMs = Date.now()) {
  const parsed = Date.parse(String(value || ""));
  if (Number.isFinite(parsed)) {
    return new Date(parsed).toISOString();
  }

  return new Date(fallbackMs).toISOString();
}

function getSessionStartedAtMs(sessionLike) {
  const parsed = Date.parse(String(sessionLike?.sessionStartedAt || ""));
  return Number.isFinite(parsed) ? parsed : NaN;
}

function getSessionLastActivityAtMs(sessionLike) {
  const parsed = Date.parse(String(sessionLike?.lastActivityAt || ""));
  return Number.isFinite(parsed) ? parsed : NaN;
}

function isSessionHardExpired(sessionLike) {
  const startedAtMs = getSessionStartedAtMs(sessionLike);
  if (!Number.isFinite(startedAtMs)) {
    return false;
  }

  return Date.now() - startedAtMs >= SESSION_HARD_MAX_AGE_MS;
}

function isSessionIdleExpired(sessionLike) {
  const lastActivityAtMs = getSessionLastActivityAtMs(sessionLike);
  if (!Number.isFinite(lastActivityAtMs)) {
    return false;
  }

  return Date.now() - lastActivityAtMs >= SESSION_IDLE_MAX_AGE_MS;
}

function getSessionHardExpiryDelay(sessionLike) {
  const startedAtMs = getSessionStartedAtMs(sessionLike);
  if (!Number.isFinite(startedAtMs)) {
    return SESSION_HARD_MAX_AGE_MS;
  }

  const remainingMs = startedAtMs + SESSION_HARD_MAX_AGE_MS - Date.now();
  return Math.max(0, remainingMs);
}

function getSessionIdleExpiryDelay(sessionLike) {
  const lastActivityAtMs = getSessionLastActivityAtMs(sessionLike);
  if (!Number.isFinite(lastActivityAtMs)) {
    return SESSION_IDLE_MAX_AGE_MS;
  }

  const remainingMs = lastActivityAtMs + SESSION_IDLE_MAX_AGE_MS - Date.now();
  return Math.max(0, remainingMs);
}

function createSessionExpiredError() {
  const error = new Error("Session expired. Please sign in again.");
  error.status = 401;
  error.code = "AUTH_SESSION_EXPIRED";
  return error;
}

function createSessionIdleExpiredError() {
  const error = new Error("Session timed out due to inactivity. Please sign in again.");
  error.status = 401;
  error.code = "AUTH_SESSION_IDLE_EXPIRED";
  return error;
}

function resolveAccessTokenExpiresAt(expiresInSeconds) {
  const ttlSeconds = Number(expiresInSeconds);
  const safeTtlSeconds = Number.isFinite(ttlSeconds) && ttlSeconds > 0 ? ttlSeconds : ACCESS_TOKEN_FALLBACK_TTL_SECONDS;
  return new Date(Date.now() + safeTtlSeconds * 1000).toISOString();
}

function resolveSessionPersistenceMode(mode, fallback = SESSION_PERSISTENCE_LOCAL) {
  return mode === SESSION_PERSISTENCE_SESSION ? SESSION_PERSISTENCE_SESSION : fallback;
}

function isAuthInvalidError(error) {
  const code = String(error?.code || "").trim().toUpperCase();
  if (AUTH_INVALID_CODES.has(code)) {
    return true;
  }

  return Number(error?.status) === 401;
}

function getTokenRefreshDelay(accessTokenExpiresAt) {
  const expiresAtMs = Date.parse(String(accessTokenExpiresAt || ""));
  if (!Number.isFinite(expiresAtMs)) {
    return ACCESS_TOKEN_UNKNOWN_REFRESH_DELAY_MS;
  }

  const refreshInMs = expiresAtMs - Date.now() - ACCESS_TOKEN_REFRESH_SKEW_MS;
  return Math.max(ACCESS_TOKEN_MIN_REFRESH_DELAY_MS, refreshInMs);
}

function shouldRefreshAccessToken(sessionLike) {
  if (!sessionLike?.refreshToken) {
    return false;
  }

  const expiresAtMs = Date.parse(String(sessionLike?.accessTokenExpiresAt || ""));
  if (!Number.isFinite(expiresAtMs)) {
    return false;
  }

  return expiresAtMs - Date.now() <= ACCESS_TOKEN_REFRESH_SKEW_MS;
}

function buildSessionFromAuthPayload(payload, previousSession = {}) {
  const nowMs = Date.now();
  const sessionStartedAt = resolveSessionStartedAt(previousSession?.sessionStartedAt, nowMs);
  const lastActivityAt = resolveSessionLastActivityAt(previousSession?.lastActivityAt, nowMs);

  return {
    accessToken: payload.accessToken,
    refreshToken: payload.refreshToken,
    user: payload.user || previousSession?.user || null,
    usage: previousSession?.usage || null,
    persistenceMode: resolveSessionPersistenceMode(previousSession?.persistenceMode, SESSION_PERSISTENCE_LOCAL),
    accessTokenExpiresAt: resolveAccessTokenExpiresAt(payload?.expiresInSeconds),
    sessionStartedAt,
    lastActivityAt
  };
}

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

function normalizeDashboardSnapshot(payload = {}) {
  return {
    jobs: Array.isArray(payload.jobs) ? payload.jobs : [],
    reports: Array.isArray(payload.reports) ? payload.reports : [],
    notifications: Array.isArray(payload.notifications) ? payload.notifications : [],
    apiKeys: Array.isArray(payload.apiKeys) ? payload.apiKeys : [],
    analytics: payload.analytics && typeof payload.analytics === "object" ? payload.analytics : buildAnalyticsData(),
    activeReport: payload.activeReport && typeof payload.activeReport === "object" ? payload.activeReport : null
  };
}

function readDashboardCache(sessionLike) {
  const mode = resolveSessionPersistenceMode(sessionLike?.persistenceMode, SESSION_PERSISTENCE_LOCAL);
  const userId = String(sessionLike?.user?.id || "").trim();
  if (!userId) {
    return null;
  }

  const storage = getBrowserStorage(mode);
  const raw = storage?.getItem(DASHBOARD_CACHE_KEY);
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw);
    if (Number(parsed?.version) !== DASHBOARD_CACHE_VERSION) {
      return null;
    }

    if (String(parsed?.userId || "") !== userId) {
      return null;
    }

    const cachedAtMs = Number(parsed?.cachedAtMs);
    if (!Number.isFinite(cachedAtMs) || Date.now() - cachedAtMs > DASHBOARD_CACHE_TTL_MS) {
      return null;
    }

    return normalizeDashboardSnapshot(parsed);
  } catch {
    return null;
  }
}

function writeDashboardCache(sessionLike, snapshot = {}) {
  const mode = resolveSessionPersistenceMode(sessionLike?.persistenceMode, SESSION_PERSISTENCE_LOCAL);
  const userId = String(sessionLike?.user?.id || "").trim();
  if (!userId) {
    return;
  }

  const storage = getBrowserStorage(mode);
  if (!storage) {
    return;
  }

  const normalized = normalizeDashboardSnapshot(snapshot);
  storage.setItem(
    DASHBOARD_CACHE_KEY,
    JSON.stringify({
      version: DASHBOARD_CACHE_VERSION,
      userId,
      cachedAtMs: Date.now(),
      ...normalized
    })
  );
}

function clearDashboardCache() {
  getBrowserStorage(SESSION_PERSISTENCE_LOCAL)?.removeItem(DASHBOARD_CACHE_KEY);
  getBrowserStorage(SESSION_PERSISTENCE_SESSION)?.removeItem(DASHBOARD_CACHE_KEY);
}

function SessionLoading({ message = "Loading secure session..." }) {
  const prefersReducedMotion = useReducedMotion();

  return (
    <motion.main className="app-shell centered" {...createEnterMotion(prefersReducedMotion)}>
      <motion.section
        className="card grid w-full max-w-[560px] gap-3 p-4 sm:p-5"
        {...createEnterMotion(prefersReducedMotion, { delay: 0.03 })}
      >
        <div className="inline-flex items-center gap-2.5">
          <img src={BRAND_MARKS.lightSurface} alt={LOGO_ALT_TEXT} className="h-11 w-11 object-contain" />
          <h1>{APP_NAME}</h1>
        </div>
        <div
          className="flex items-center gap-3 rounded-xl border border-[var(--line)] bg-[var(--surface-soft)] px-3 py-3"
          role="status"
          aria-live="polite"
          aria-busy="true"
        >
          <div className="grid flex-1 gap-0.5">
            <p className="text-[0.92rem] font-semibold text-[var(--text)]">Securing your workspace</p>
            <p className="text-sm leading-6 text-[var(--text-soft)]">{message}</p>
            <div className="mt-2 grid gap-2">
              <SkeletonBlock className="h-2.5 w-full" />
              <SkeletonBlock className="h-2.5 w-3/4" />
            </div>
          </div>
        </div>
        <div className="rounded-xl border border-[var(--line)] bg-[var(--surface-soft)] px-3 py-3">
          <SkeletonText lines={3} />
        </div>
      </motion.section>
    </motion.main>
  );
}

function DashboardRouteSkeleton() {
  return (
    <main className="dashboard-page min-h-screen overflow-x-clip">
      <div className="mx-auto flex w-full max-w-[1760px] min-w-0 flex-col gap-4 overflow-x-clip px-3 py-3 sm:px-4 sm:py-4 lg:flex-row lg:gap-6 lg:px-8">
        <aside className="dashboard-shell-surface hidden h-[calc(100vh-2rem)] w-[280px] shrink-0 p-4 lg:flex lg:flex-col">
          <div className="mb-6 flex items-center gap-3">
            <SkeletonBlock className="h-11 w-11 rounded-2xl" />
            <div className="grid flex-1 gap-2">
              <SkeletonBlock className="h-3.5 w-2/3" />
              <SkeletonBlock className="h-2.5 w-1/2" />
            </div>
          </div>
          <div className="grid gap-2">
            {Array.from({ length: 6 }, (_value, index) => (
              <SkeletonBlock key={`nav-skeleton-${index}`} className="h-14 w-full rounded-2xl" />
            ))}
          </div>
        </aside>
        <section className="min-w-0 flex-1 space-y-4">
          <div className="dashboard-shell-surface p-3 sm:p-4">
            <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto_auto]">
              <SkeletonBlock className="h-11 w-full rounded-2xl" />
              <SkeletonBlock className="h-11 w-11 rounded-2xl" />
              <SkeletonBlock className="h-11 w-40 rounded-2xl" />
            </div>
          </div>
          <div className="dashboard-shell-surface p-4 sm:p-6" role="status" aria-live="polite" aria-busy="true">
            <SkeletonBlock className="h-3 w-24" />
            <SkeletonBlock className="mt-3 h-8 w-64" />
            <SkeletonBlock className="mt-3 h-3 w-5/6" />
            <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
              {Array.from({ length: 3 }, (_value, index) => (
                <SkeletonBlock key={`metric-skeleton-${index}`} className="h-24 w-full rounded-3xl" />
              ))}
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}

function AuthRouteSkeleton() {
  return (
    <main className="auth-page">
      <div className="auth-page-grid" aria-hidden="true" />
      <div className="auth-page-inner">
        <section className="auth-panel auth-panel-main" role="status" aria-live="polite" aria-busy="true">
          <SkeletonBlock className="h-3 w-28" />
          <SkeletonBlock className="mt-4 h-8 w-48" />
          <SkeletonBlock className="mt-3 h-3 w-11/12" />
          <div className="mt-6 grid gap-4">
            <SkeletonBlock className="h-[62px] w-full rounded-2xl" />
            <SkeletonBlock className="h-[62px] w-full rounded-2xl" />
            <SkeletonBlock className="h-11 w-full rounded-2xl" />
          </div>
        </section>
      </div>
    </main>
  );
}

function PublicRouteSkeleton() {
  return (
    <main className="app-shell landing-shell">
      <section className="card landing-hero p-4 sm:p-5" role="status" aria-live="polite" aria-busy="true">
        <div className="grid gap-4">
          <div className="flex items-center justify-between gap-3">
            <SkeletonBlock className="h-11 w-44 rounded-2xl" />
            <SkeletonBlock className="h-9 w-32 rounded-full" />
          </div>
          <SkeletonBlock className="h-4 w-40" />
          <SkeletonBlock className="h-10 w-[70%]" />
          <SkeletonBlock className="h-4 w-[80%]" />
          <SkeletonBlock className="h-4 w-[65%]" />
        </div>
      </section>
      <section className="card guest-card p-4 sm:p-5">
        <SkeletonText lines={6} />
      </section>
    </main>
  );
}

function RouteSkeleton({ pathname = "/" }) {
  const prefersReducedMotion = useReducedMotion();
  const fallbackMotion = createEnterMotion(prefersReducedMotion, { duration: 0.2, y: 6 });

  let Content = PublicRouteSkeleton;
  if (pathname.startsWith("/app")) {
    Content = DashboardRouteSkeleton;
  } else if (
    pathname === "/signin" ||
    pathname === "/signup" ||
    pathname === "/forgot-password" ||
    pathname === "/reset-password"
  ) {
    Content = AuthRouteSkeleton;
  }

  return (
    <motion.div {...fallbackMotion}>
      <Content />
    </motion.div>
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

function RouteTransitionIndicator({ routeKey }) {
  const prefersReducedMotion = useReducedMotion();
  const [visible, setVisible] = useState(false);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    if (prefersReducedMotion) {
      return undefined;
    }

    setVisible(true);
    setProgress(16);

    const timers = [
      setTimeout(() => setProgress(48), 45),
      setTimeout(() => setProgress(76), 150),
      setTimeout(() => setProgress(100), 260),
      setTimeout(() => {
        setVisible(false);
        setProgress(0);
      }, 420)
    ];

    return () => {
      timers.forEach((timer) => clearTimeout(timer));
    };
  }, [prefersReducedMotion, routeKey]);

  return (
    <AnimatePresence>
      {visible ? (
        <motion.div
          className="pointer-events-none fixed left-0 right-0 top-0 z-[120] h-0.5 origin-left bg-viro-500 shadow-[0_0_16px_rgba(31,143,92,0.65)]"
          initial={{ scaleX: 0, opacity: 0.9 }}
          animate={{ scaleX: progress / 100, opacity: progress >= 100 ? 0 : 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.2, ease: "easeOut" }}
        />
      ) : null}
    </AnimatePresence>
  );
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
  const [isDeletingReport, setIsDeletingReport] = useState(false);
  const [shareCopied, setShareCopied] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [dashboardTheme, setDashboardTheme] = useState(resolveTheme);
  const [dashboardSyncing, setDashboardSyncing] = useState(false);
  const redirectTimerRef = useRef(null);
  const refreshInFlightRef = useRef(null);
  const invalidationInFlightRef = useRef(false);
  const lastActivityTouchRef = useRef(0);
  const dashboardCacheRef = useRef(null);
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
  const routeTransitionKey = `${location.pathname}${location.search}`;

  useEffect(() => {
    if (typeof window === "undefined") {
      return undefined;
    }

    let cancelled = false;
    let fallbackTimer = null;
    let idleHandle = null;
    const importTimers = [];

    const schedulePrefetch = () => {
      ROUTE_PREFETCHERS.forEach((loader, index) => {
        const timer = window.setTimeout(() => {
          if (cancelled) {
            return;
          }

          void loader().catch(() => {});
        }, 120 * index);
        importTimers.push(timer);
      });
    };

    if (typeof window.requestIdleCallback === "function") {
      idleHandle = window.requestIdleCallback(schedulePrefetch, { timeout: 1200 });
    } else {
      fallbackTimer = window.setTimeout(schedulePrefetch, 650);
    }

    return () => {
      cancelled = true;
      if (fallbackTimer != null) {
        window.clearTimeout(fallbackTimer);
      }
      if (idleHandle != null && typeof window.cancelIdleCallback === "function") {
        window.cancelIdleCallback(idleHandle);
      }
      importTimers.forEach((timer) => window.clearTimeout(timer));
    };
  }, []);

  function clearClientSessionState() {
    lastActivityTouchRef.current = 0;
    dashboardCacheRef.current = null;
    setDashboardSyncing(false);
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
    clearDashboardCache();
  }

  function invalidateSessionAndRedirect({ showToast = true, message = "Session expired. Please sign in again." } = {}) {
    if (invalidationInFlightRef.current) {
      return;
    }

    invalidationInFlightRef.current = true;
    refreshInFlightRef.current = null;
    clearClientSessionState();
    clearPersistedSession();
    if (showToast) {
      toast.error(message);
    }
    navigate("/signin", { replace: true });
  }

  function touchSessionActivity({ force = false } = {}) {
    if (!session?.accessToken) {
      return;
    }

    const nowMs = Date.now();
    if (!force && nowMs - lastActivityTouchRef.current < ACTIVITY_TOUCH_THROTTLE_MS) {
      return;
    }

    lastActivityTouchRef.current = nowMs;

    setSession((current) => {
      if (!current?.accessToken) {
        return current;
      }

      const currentLastActivityMs = getSessionLastActivityAtMs(current);
      if (!force && Number.isFinite(currentLastActivityMs) && nowMs - currentLastActivityMs < ACTIVITY_TOUCH_THROTTLE_MS) {
        return current;
      }

      const nextSession = {
        ...current,
        lastActivityAt: new Date(nowMs).toISOString()
      };
      persistSessionSnapshot(nextSession);
      return nextSession;
    });
  }

  function applyDashboardSnapshot(snapshot) {
    const normalized = normalizeDashboardSnapshot(snapshot);
    setJobs(normalized.jobs);
    setReports(normalized.reports);
    setNotifications(normalized.notifications);
    setApiKeys(normalized.apiKeys);
    setAnalytics(normalized.analytics);
    setActiveReport(normalized.activeReport);
    setActiveJob((current) => selectHighlightedJob(normalized.jobs, current?.id || ""));
  }

  function updateDashboardCache(activeSession, patch = {}) {
    if (!activeSession?.user?.id) {
      return;
    }

    const baseline =
      dashboardCacheRef.current && dashboardCacheRef.current.userId === activeSession.user.id
        ? dashboardCacheRef.current
        : {
            userId: activeSession.user.id,
            ...normalizeDashboardSnapshot()
          };

    const nextSnapshot = {
      userId: activeSession.user.id,
      ...normalizeDashboardSnapshot({
        ...baseline,
        ...patch
      })
    };

    dashboardCacheRef.current = nextSnapshot;
    writeDashboardCache(activeSession, nextSnapshot);
  }

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
    if (session?.accessToken) {
      invalidationInFlightRef.current = false;
      const activityMs = getSessionLastActivityAtMs(session);
      lastActivityTouchRef.current = Number.isFinite(activityMs) ? activityMs : Date.now();
    }
  }, [session?.accessToken, session?.lastActivityAt]);

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

        let hydratedSession = {
          ...parsed,
          persistenceMode: resolveSessionPersistenceMode(parsed.persistenceMode, stored.mode),
          sessionStartedAt: resolveSessionStartedAt(parsed.sessionStartedAt),
          lastActivityAt: resolveSessionLastActivityAt(parsed.lastActivityAt, Date.parse(parsed.sessionStartedAt || "") || Date.now())
        };

        if (isSessionHardExpired(hydratedSession)) {
          throw createSessionExpiredError();
        }

        if (isSessionIdleExpired(hydratedSession)) {
          throw createSessionIdleExpiredError();
        }

        if (shouldRefreshAccessToken(hydratedSession)) {
          hydratedSession = await refreshAuthSession(hydratedSession.refreshToken, hydratedSession);
        }

        if (!cancelled) {
          setSession(hydratedSession);
        }

        await loadDashboard(hydratedSession);
      } catch (_error) {
        if (isAuthInvalidError(_error) || String(_error?.message || "").toLowerCase().includes("invalid session format")) {
          clearPersistedSession();
          if (!cancelled) {
            clearClientSessionState();
          }
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
    if (!session?.accessToken || !session?.refreshToken) {
      return undefined;
    }

    let cancelled = false;
    let timerId;

    const scheduleRefresh = () => {
      const delay = getTokenRefreshDelay(session.accessTokenExpiresAt);
      timerId = setTimeout(async () => {
        if (cancelled) {
          return;
        }

        if (isSessionHardExpired(session)) {
          invalidateSessionAndRedirect();
          return;
        }

        if (isSessionIdleExpired(session)) {
          invalidateSessionAndRedirect({
            message: "Session timed out due to inactivity. Please sign in again."
          });
          return;
        }

        try {
          await refreshAuthSession(session.refreshToken, session);
        } catch (error) {
          if (isAuthInvalidError(error)) {
            invalidateSessionAndRedirect();
          }
        }
      }, delay);
    };

    scheduleRefresh();

    return () => {
      cancelled = true;
      clearTimeout(timerId);
    };
  }, [session?.accessToken, session?.refreshToken, session?.accessTokenExpiresAt]);

  useEffect(() => {
    if (!session?.accessToken) {
      return undefined;
    }

    const delay = getSessionHardExpiryDelay(session);
    const timerId = setTimeout(() => {
      invalidateSessionAndRedirect();
    }, delay);

    return () => clearTimeout(timerId);
  }, [session?.accessToken, session?.sessionStartedAt]);

  useEffect(() => {
    if (!session?.accessToken) {
      return undefined;
    }

    const delay = getSessionIdleExpiryDelay(session);
    const timerId = setTimeout(() => {
      invalidateSessionAndRedirect({
        message: "Session timed out due to inactivity. Please sign in again."
      });
    }, delay);

    return () => clearTimeout(timerId);
  }, [session?.accessToken, session?.lastActivityAt]);

  useEffect(() => {
    if (!session?.accessToken || typeof window === "undefined" || typeof document === "undefined") {
      return undefined;
    }

    const handleActivity = () => {
      touchSessionActivity();
    };

    const handleVisibility = () => {
      if (document.visibilityState === "visible") {
        touchSessionActivity({ force: true });
      }
    };

    const activityEvents = ["pointerdown", "keydown", "touchstart", "scroll", "focus"];
    activityEvents.forEach((eventName) => {
      window.addEventListener(eventName, handleActivity, { passive: true });
    });
    document.addEventListener("visibilitychange", handleVisibility);

    touchSessionActivity({ force: true });

    return () => {
      activityEvents.forEach((eventName) => {
        window.removeEventListener(eventName, handleActivity);
      });
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  }, [session?.accessToken]);

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
    if (authSession?.accessToken && isSessionHardExpired(authSession)) {
      invalidateSessionAndRedirect();
      throw createSessionExpiredError();
    }

    if (authSession?.accessToken && isSessionIdleExpired(authSession)) {
      invalidateSessionAndRedirect({
        message: "Session timed out due to inactivity. Please sign in again."
      });
      throw createSessionIdleExpiredError();
    }

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
      try {
        const refreshedSession = await refreshAuthSession(authSession.refreshToken, authSession);
        return apiRequest(path, {
          method: normalizedMethod,
          body,
          formData,
          authSession: refreshedSession,
          retry: false
        });
      } catch (refreshError) {
        if (isAuthInvalidError(refreshError)) {
          invalidateSessionAndRedirect();
        }
        throw refreshError;
      }
    }

    if (response.status === 401 && authSession?.accessToken && (!authSession?.refreshToken || !retry)) {
      invalidateSessionAndRedirect();
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
    if (isSessionHardExpired(currentSession)) {
      throw createSessionExpiredError();
    }

    if (isSessionIdleExpired(currentSession)) {
      throw createSessionIdleExpiredError();
    }

    const normalizedRefreshToken = String(refreshToken || "").trim();
    if (!normalizedRefreshToken) {
      const error = new Error("Refresh token missing.");
      error.code = "AUTH_REFRESH_INVALID";
      error.status = 401;
      throw error;
    }

    if (refreshInFlightRef.current) {
      return refreshInFlightRef.current;
    }

    const refreshPromise = (async () => {
      const payload = await apiRequest("/api/auth/refresh", {
        method: "POST",
        body: { refreshToken: normalizedRefreshToken },
        authSession: null,
        retry: false
      });

      const nextSession = buildSessionFromAuthPayload(payload, {
        ...currentSession,
        user: payload.user || currentSession?.user || null,
        persistenceMode: resolveSessionPersistenceMode(currentSession?.persistenceMode, SESSION_PERSISTENCE_LOCAL)
      });

      setSession(nextSession);
      persistSessionSnapshot(nextSession);
      return nextSession;
    })().finally(() => {
      if (refreshInFlightRef.current === refreshPromise) {
        refreshInFlightRef.current = null;
      }
    });

    refreshInFlightRef.current = refreshPromise;
    return refreshPromise;
  }

  async function refreshDashboardData(activeSession, { showSyncIndicator = false } = {}) {
    if (!activeSession?.accessToken) {
      return;
    }

    if (showSyncIndicator) {
      setDashboardSyncing(true);
    }

    try {
      await Promise.allSettled([
        refreshJobs(activeSession),
        refreshReports(activeSession),
        refreshApiKeys(activeSession),
        refreshNotifications(activeSession),
        refreshAnalytics(activeSession)
      ]);
    } finally {
      if (showSyncIndicator) {
        setDashboardSyncing(false);
      }
    }
  }

  async function loadDashboard(activeSession, { background = true } = {}) {
    const mePayload = await apiRequest("/api/auth/me", { authSession: activeSession });

    const nextSession = {
      ...activeSession,
      user: mePayload.user,
      usage: mePayload.usage,
      persistenceMode: resolveSessionPersistenceMode(activeSession?.persistenceMode, SESSION_PERSISTENCE_LOCAL),
      accessTokenExpiresAt: activeSession?.accessTokenExpiresAt || resolveAccessTokenExpiresAt(ACCESS_TOKEN_FALLBACK_TTL_SECONDS)
    };

    setScanLimits({
      maxFilesPerBatch: Number(mePayload?.scanLimits?.maxFilesPerBatch) || DEFAULT_SCAN_LIMITS.maxFilesPerBatch,
      maxUploadMb: Number(mePayload?.scanLimits?.maxUploadMb) || DEFAULT_SCAN_LIMITS.maxUploadMb
    });
    setSession(nextSession);
    persistSessionSnapshot(nextSession);
    touchSessionActivity({ force: true });

    const cachedSnapshot = readDashboardCache(nextSession);
    if (cachedSnapshot) {
      dashboardCacheRef.current = {
        userId: nextSession.user.id,
        ...cachedSnapshot
      };
      applyDashboardSnapshot(cachedSnapshot);
    }

    if (background) {
      void refreshDashboardData(nextSession, { showSyncIndicator: true });
      return nextSession;
    }

    await refreshDashboardData(nextSession, { showSyncIndicator: false });
    return nextSession;
  }

  async function refreshJobs(activeSession = session) {
    if (!activeSession) {
      return;
    }

    const payload = await apiRequest("/api/scans/jobs?limit=12", { authSession: activeSession });
    const nextJobs = Array.isArray(payload?.jobs) ? payload.jobs : [];
    setJobs(nextJobs);
    setActiveJob((current) => selectHighlightedJob(nextJobs, current?.id || ""));
    updateDashboardCache(activeSession, { jobs: nextJobs });
  }

  async function refreshReports(activeSession = session) {
    if (!activeSession) {
      return;
    }

    const payload = await apiRequest("/api/scans/reports?limit=20", { authSession: activeSession });
    const nextReports = Array.isArray(payload?.reports) ? payload.reports : [];
    setReports(nextReports);
    updateDashboardCache(activeSession, { reports: nextReports });

    if (nextReports.length === 0) {
      setActiveReport(null);
      updateDashboardCache(activeSession, { activeReport: null });
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
    const nextAnalytics = buildAnalyticsData(payload?.analytics);
    setAnalytics(nextAnalytics);
    updateDashboardCache(activeSession, { analytics: nextAnalytics });
  }

  async function refreshApiKeys(activeSession = session) {
    if (!activeSession) {
      return;
    }

    const payload = await apiRequest("/api/auth/api-keys", { authSession: activeSession });
    const nextKeys = Array.isArray(payload?.keys) ? payload.keys : [];
    setApiKeys(nextKeys);
    updateDashboardCache(activeSession, { apiKeys: nextKeys });
  }

  async function refreshNotifications(activeSession = session) {
    if (!activeSession) {
      return;
    }

    const payload = await apiRequest("/api/auth/notifications?limit=20", { authSession: activeSession });
    const nextNotifications = Array.isArray(payload?.notifications) ? payload.notifications : [];
    setNotifications(nextNotifications);
    updateDashboardCache(activeSession, { notifications: nextNotifications });
  }

  async function fetchNotificationsPage({ limit = 10, offset = 0 } = {}, activeSession = session) {
    if (!activeSession) {
      return {
        notifications: [],
        unreadCount: 0,
        totalCount: 0,
        limit: Math.max(1, Math.min(100, Number(limit) || 10)),
        offset: Math.max(0, Number(offset) || 0),
        hasMore: false
      };
    }

    const safeLimit = Math.max(1, Math.min(100, Number(limit) || 10));
    const safeOffset = Math.max(0, Number(offset) || 0);
    const payload = await apiRequest(`/api/auth/notifications?limit=${safeLimit}&offset=${safeOffset}`, {
      authSession: activeSession
    });

    return {
      notifications: Array.isArray(payload?.notifications) ? payload.notifications : [],
      unreadCount: Number.isFinite(Number(payload?.unreadCount)) ? Number(payload.unreadCount) : 0,
      totalCount: Number.isFinite(Number(payload?.totalCount))
        ? Number(payload.totalCount)
        : Array.isArray(payload?.notifications)
          ? payload.notifications.length
          : 0,
      limit: Number.isFinite(Number(payload?.limit)) ? Number(payload.limit) : safeLimit,
      offset: Number.isFinite(Number(payload?.offset)) ? Number(payload.offset) : safeOffset,
      hasMore: Boolean(payload?.hasMore)
    };
  }

  async function openReport(reportId, activeSession = session) {
    if (!activeSession) {
      return null;
    }

    const payload = await apiRequest(`/api/scans/reports/${reportId}`, { authSession: activeSession });
    const nextReport = payload.report || null;
    setActiveReport(nextReport);
    updateDashboardCache(activeSession, { activeReport: nextReport });
    return nextReport;
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

    const nextSession = buildSessionFromAuthPayload(payload, {
      user: payload.user,
      usage: null,
      persistenceMode: rememberMe ? SESSION_PERSISTENCE_LOCAL : SESSION_PERSISTENCE_SESSION
    });

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

    const nextSession = buildSessionFromAuthPayload(payload, {
      user: payload.user,
      usage: null,
      persistenceMode: SESSION_PERSISTENCE_LOCAL
    });

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

  function applyQuotaFromResponse(quota) {
    setSession((current) => {
      if (!current || !quota) {
        return current;
      }

      const next = {
        ...current,
        usage: {
          windowStartedAt:
            quota.windowStartedAt ||
            current.usage?.windowStartedAt ||
            new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
          used: quota.used ?? current.usage?.used,
          remaining: quota.remaining ?? current.usage?.remaining,
          limit: quota.limit ?? current.usage?.limit
        }
      };

      persistSessionSnapshot(next);
      return next;
    });
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

    refreshInFlightRef.current = null;
    clearClientSessionState();
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
      applyQuotaFromResponse(payload?.quota);

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

  async function submitUrlScan(url) {
    if (!session || isSubmittingScan) {
      return;
    }

    const trimmedUrl = String(url || "").trim();
    if (!trimmedUrl) {
      throw new Error("Paste a URL to scan.");
    }

    setIsSubmittingScan(true);

    try {
      const payload = await apiRequest("/api/scans/links/jobs", {
        method: "POST",
        body: { url: trimmedUrl },
        authSession: session
      });

      const queuedJob = payload?.job || null;
      setActiveJob(queuedJob);
      applyQuotaFromResponse(payload?.quota);

      toast.success("URL scan job queued.");
      await Promise.all([refreshJobs(session), refreshNotifications(session), refreshAnalytics(session)]);
      navigate("/app/projects", { replace: false });
      return queuedJob;
    } catch (error) {
      if (session && error?.code === "SCAN_QUOTA_EXCEEDED") {
        await refreshNotifications(session);
      }
      toast.error(error.message || "Could not queue URL scan job.");
      throw error;
    } finally {
      setIsSubmittingScan(false);
    }
  }

  async function submitWebsiteSafetyScan(url) {
    if (!session || isSubmittingScan) {
      return;
    }

    const trimmedUrl = String(url || "").trim();
    if (!trimmedUrl) {
      throw new Error("Paste a URL to scan.");
    }

    setIsSubmittingScan(true);

    try {
      const payload = await apiRequest("/api/scans/website/jobs", {
        method: "POST",
        body: { url: trimmedUrl },
        authSession: session
      });

      const queuedJob = payload?.job || null;
      setActiveJob(queuedJob);
      applyQuotaFromResponse(payload?.quota);

      toast.success("Website safety scan queued.");
      await Promise.all([refreshJobs(session), refreshNotifications(session), refreshAnalytics(session), refreshReports(session)]);
      navigate("/app/website-safety", { replace: false });
      return queuedJob;
    } catch (error) {
      if (session && error?.code === "SCAN_QUOTA_EXCEEDED") {
        await refreshNotifications(session);
      }
      toast.error(error.message || "Could not queue website safety scan.");
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

  async function handleNotificationSelect(notification) {
    if (!session) {
      return;
    }

    const entityType = String(notification?.entityType || "")
      .trim()
      .toLowerCase();
    const entityId = String(notification?.entityId || "").trim();

    if (!entityType || !entityId) {
      return;
    }

    if (entityType === "report") {
      try {
        const report = await openReport(entityId, session);
        if (!report?.id) {
          throw new Error("Report is not available anymore.");
        }

        if (report.sourceType === "website") {
          navigate("/app/website-safety", { replace: false });
        } else {
          navigate("/app/history", { replace: false });
        }
      } catch (error) {
        toast.error(error?.message || "Could not open notification report.");
      }
      return;
    }

    if (entityType === "job") {
      try {
        const payload = await apiRequest(`/api/scans/jobs/${entityId}`, {
          authSession: session
        });
        const job = payload?.job || null;
        if (!job) {
          throw new Error("Scan job is no longer available.");
        }

        setActiveJob(job);
        await refreshJobs(session);

        if (job.reportId) {
          const report = await openReport(job.reportId, session);
          if (report?.sourceType === "website") {
            navigate("/app/website-safety", { replace: false });
          } else {
            navigate("/app/history", { replace: false });
          }
          return;
        }

        if (job.sourceType === "website") {
          navigate("/app/website-safety", { replace: false });
        } else {
          navigate("/app/projects", { replace: false });
        }
      } catch (error) {
        toast.error(error?.message || "Could not open notification job.");
      }
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

  async function deleteReport(reportId) {
    if (!session || !reportId || isDeletingReport) {
      return;
    }

    setIsDeletingReport(true);
    setShareError("");
    setShareState({ url: "", expiresAt: "" });
    setShareCopied(false);

    try {
      const payload = await apiRequest(`/api/scans/reports/${reportId}`, {
        method: "DELETE",
        authSession: session
      });

      toast.success("Report deleted.");
      await Promise.all([refreshReports(session), refreshAnalytics(session), refreshNotifications(session)]);
    } catch (error) {
      toast.error(error.message || "Could not delete report.");
    } finally {
      setIsDeletingReport(false);
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

  async function downloadReportPdf(reportId) {
    if (!session?.accessToken || !reportId) {
      throw new Error("A signed-in session is required to download this PDF.");
    }

    let activeSession = session;
    if (shouldRefreshAccessToken(activeSession)) {
      activeSession = await refreshAuthSession(activeSession.refreshToken, activeSession);
    }

    const fetchPdf = async (accessToken) =>
      fetch(buildApiUrl(`/api/scans/reports/${encodeURIComponent(reportId)}/pdf`), {
        method: "GET",
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      });

    let response = await fetchPdf(activeSession.accessToken);
    if (response.status === 401 && activeSession.refreshToken) {
      const refreshedSession = await refreshAuthSession(activeSession.refreshToken, activeSession);
      response = await fetchPdf(refreshedSession.accessToken);
      activeSession = refreshedSession;
    }

    if (!response.ok) {
      let errorMessage = "Could not download report PDF.";
      try {
        const payload = await response.json();
        if (payload?.error?.message) {
          errorMessage = payload.error.message;
        }
      } catch {
        // no-op
      }

      throw new Error(errorMessage);
    }

    const blob = await response.blob();
    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = `${String(reportId || "report").replace(/[^a-zA-Z0-9._-]+/g, "_")}.pdf`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(objectUrl);
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
      <RouteTransitionIndicator routeKey={routeTransitionKey} />
      <Suspense fallback={<RouteSkeleton pathname={location.pathname} />}>
        <AnimatePresence mode="wait" initial={false}>
          <motion.div key={routeTransitionKey} className="min-h-screen" {...createPageTransitionMotion(prefersReducedMotion)}>
            <Routes location={location}>
              <Route
                path="/"
                element={
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
                  <ForgotPasswordPage
                    appName={APP_NAME}
                    appTagline={APP_TAGLINE}
                    logoAltText={LOGO_ALT_TEXT}
                    brandMarks={BRAND_MARKS}
                    onRequestForgotPassword={requestForgotPassword}
                  />
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
                path="/status"
                element={
                  <StatusPage
                    appName={APP_NAME}
                    appTagline={APP_TAGLINE}
                    logoAltText={LOGO_ALT_TEXT}
                    brandMarks={BRAND_MARKS}
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
                      isDeletingReport={isDeletingReport}
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
                      onFetchNotificationsPage={fetchNotificationsPage}
                      onSelectNotification={handleNotificationSelect}
                      onSelectFiles={handleSelectedFiles}
                      onSubmitScan={submitScan}
                      onSubmitUrlScan={submitUrlScan}
                      onSubmitWebsiteSafetyScan={submitWebsiteSafetyScan}
                      onClearSelectedFiles={clearSelectedFiles}
                      onOpenReport={openReport}
                      onDownloadReportPdf={downloadReportPdf}
                      onCreateShare={createReportShareLink}
                      onDeleteReport={deleteReport}
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
                      isSyncingData={dashboardSyncing}
                      analytics={analytics}
                      themePalette={themePalette}
                    />
                  </RequireAuth>
                }
              />
              <Route path="*" element={<Navigate to={session?.accessToken ? "/app/dashboard" : "/"} replace />} />
            </Routes>
          </motion.div>
        </AnimatePresence>
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
