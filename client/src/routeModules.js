const prefetchCache = new Set();

export const loadLandingPage = () => import("./pages/LandingPage");
export const loadMarketingPage = () => import("./pages/MarketingPage");
export const loadSignInPage = () => import("./pages/SignInPage");
export const loadSignUpPage = () => import("./pages/SignUpPage");
export const loadForgotPasswordPage = () => import("./pages/ForgotPasswordPage");
export const loadResetPasswordPage = () => import("./pages/ResetPasswordPage");
export const loadSharedReportPage = () => import("./pages/SharedReportPage");
export const loadDashboardShell = () => import("./dashboard/DashboardShell");
export const loadStatusPage = () => import("./pages/StatusPage");

const ROUTE_MODULE_LOADERS = Object.freeze({
  "/": loadLandingPage,
  "/features": loadMarketingPage,
  "/how-it-works": loadMarketingPage,
  "/pricing": loadMarketingPage,
  "/status": loadStatusPage,
  "/signin": loadSignInPage,
  "/signup": loadSignUpPage,
  "/forgot-password": loadForgotPasswordPage,
  "/reset-password": loadResetPasswordPage,
  "/app": loadDashboardShell,
  "/report": loadSharedReportPage
});

export const ROUTE_PREFETCHERS = Object.freeze([
  loadDashboardShell,
  loadSignInPage,
  loadSignUpPage,
  loadForgotPasswordPage,
  loadResetPasswordPage,
  loadMarketingPage,
  loadStatusPage
]);

function normalizeRoutePath(pathname) {
  const path = String(pathname || "").trim();
  if (!path) {
    return "/";
  }

  if (path.startsWith("/app/")) {
    return "/app";
  }

  if (path.startsWith("/report/")) {
    return "/report";
  }

  return path;
}

export function prefetchRouteModule(pathname) {
  const key = normalizeRoutePath(pathname);
  const loader = ROUTE_MODULE_LOADERS[key];

  if (!loader || prefetchCache.has(key)) {
    return;
  }

  prefetchCache.add(key);
  void loader().catch(() => {
    prefetchCache.delete(key);
  });
}
