import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { BarChart3, BookOpenText, FileBarChart2, Globe2, LayoutDashboard, Settings2, ShieldCheck } from "lucide-react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { getUserName, resolveDesktopViewport } from "../appUtils";
import { Sidebar } from "./components/Sidebar";
import { Navbar } from "./components/Navbar";
import { cn } from "./dashboardUtils";
import { createEnterMotion, createPageTransitionMotion } from "../ui/motionSystem";
import { SkeletonBlock, SkeletonText } from "../ui/Skeleton";

function lazyNamed(importer, exportName) {
  return lazy(() => importer().then((module) => ({ default: module[exportName] })));
}

const DashboardOverview = lazyNamed(() => import("./views/DashboardOverview"), "DashboardOverview");
const AnalyticsView = lazyNamed(() => import("./views/AnalyticsView"), "AnalyticsView");
const ProjectsView = lazyNamed(() => import("./views/ProjectsView"), "ProjectsView");
const WebsiteSafetyView = lazyNamed(() => import("./views/WebsiteSafetyView"), "WebsiteSafetyView");
const ReportsView = lazyNamed(() => import("./views/ReportsView"), "ReportsView");
const SettingsView = lazyNamed(() => import("./views/SettingsView"), "SettingsView");
const DocsView = lazyNamed(() => import("./views/DocsView"), "DocsView");

const NAV_ITEMS = [
  {
    id: "dashboard",
    path: "/app/dashboard",
    label: "Dashboard",
    description: "Operations overview",
    icon: LayoutDashboard
  },
  {
    id: "analytics",
    path: "/app/analytics",
    label: "Analytics",
    description: "Scan trends and verdicts",
    icon: BarChart3
  },
  {
    id: "projects",
    path: "/app/projects",
    label: "Projects",
    description: "Upload and queue",
    icon: ShieldCheck
  },
  {
    id: "websiteSafety",
    path: "/app/website-safety",
    label: "Website Safety",
    description: "Web app trust scan",
    icon: Globe2
  },
  {
    id: "history",
    path: "/app/history",
    label: "History",
    description: "Saved reports and findings",
    icon: FileBarChart2
  },
  {
    id: "settings",
    path: "/app/settings",
    label: "Settings",
    description: "Keys and preferences",
    icon: Settings2
  },
  {
    id: "docs",
    path: "/app/docs",
    label: "Docs",
    description: "API guides and examples",
    icon: BookOpenText
  }
];

const VERDICT_FILTER_VALUES = Object.freeze(["clean", "suspicious", "malicious"]);

function normalizeVerdictFilterValue(value) {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();

  if (VERDICT_FILTER_VALUES.includes(normalized)) {
    return normalized;
  }

  return "";
}

function SectionLoading() {
  const prefersReducedMotion = useReducedMotion();
  const loadingMotion = createEnterMotion(prefersReducedMotion, { delay: 0, y: 8, duration: 0.2 });

  return (
    <motion.section className="dashboard-shell-surface p-6 sm:p-8" {...loadingMotion}>
      <div className="flex min-h-[72px] items-start gap-3" role="status" aria-live="polite" aria-busy="true">
        <div className="flex-1">
          <p className="dashboard-label">Loading view</p>
          <h3 className="mt-2 text-xl font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">
            Preparing workspace section
          </h3>
          <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">Loading the selected dashboard area.</p>
          <div className="mt-3 grid gap-2">
            <SkeletonBlock className="h-2.5 w-3/4" />
            <SkeletonBlock className="h-2.5 w-1/2" />
          </div>
          <div className="mt-4 rounded-2xl border border-slate-200/80 p-4 dark:border-slate-800/80">
            <SkeletonText lines={3} />
          </div>
        </div>
      </div>
    </motion.section>
  );
}

export default function DashboardShell({
  appName,
  logoSrc,
  session,
  searchQuery,
  onSearchChange,
  theme,
  onToggleTheme,
  selectedFiles,
  scanLimits,
  isSubmittingScan,
  jobs,
  reports,
  activeJob,
  activeReport,
  activeRiskMeta,
  shareState,
  shareError,
  isCreatingShare,
  isDeletingReport,
  shareCopied,
  apiKeys,
  notifications,
  newApiKey,
  newApiKeyName,
  newApiKeyScopes,
  isCreatingKey,
  setNewApiKeyName,
  setNewApiKeyScopes,
  onLogout,
  onNotificationsViewed,
  onFetchNotificationsPage,
  onSelectNotification,
  onSelectFiles,
  onSubmitScan,
  onSubmitUrlScan,
  onSubmitWebsiteSafetyScan,
  onClearSelectedFiles,
  onOpenReport,
  onDownloadReportPdf,
  onCreateShare,
  onDeleteReport,
  onCopyShare,
  onCreateApiKey,
  onRevokeApiKey,
  formatDateTime,
  formatBytes,
  pluralize,
  getDisplayFileType,
  formatVerdictLabel,
  prefersReducedMotion,
  currentDateLabel,
  quotaText,
  isSyncingData = false,
  analytics,
  themePalette
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [isDesktop, setIsDesktop] = useState(resolveDesktopViewport);

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
      return undefined;
    }

    const mediaQuery = window.matchMedia("(min-width: 1024px)");
    const handleChange = (event) => {
      setIsDesktop(event.matches);
    };

    setIsDesktop(mediaQuery.matches);

    if (typeof mediaQuery.addEventListener === "function") {
      mediaQuery.addEventListener("change", handleChange);
      return () => mediaQuery.removeEventListener("change", handleChange);
    }

    mediaQuery.addListener(handleChange);
    return () => mediaQuery.removeListener(handleChange);
  }, []);

  useEffect(() => {
    if (isDesktop) {
      setMobileSidebarOpen(false);
    }
  }, [isDesktop]);

  useEffect(() => {
    if (typeof document === "undefined") {
      return undefined;
    }

    const { body } = document;
    const previousOverflow = body.style.overflow;
    body.style.overflow = !isDesktop && mobileSidebarOpen ? "hidden" : "";

    return () => {
      body.style.overflow = previousOverflow;
    };
  }, [isDesktop, mobileSidebarOpen]);

  const activeItem = useMemo(() => {
    return (
      NAV_ITEMS.find((item) => location.pathname === item.path || location.pathname.startsWith(`${item.path}/`)) || null
    );
  }, [location.pathname]);
  const verdictFilter = useMemo(() => {
    const params = new URLSearchParams(location.search || "");
    return normalizeVerdictFilterValue(params.get("verdict"));
  }, [location.search]);

  const userName = useMemo(() => getUserName(session?.user), [session?.user]);
  const effectiveSidebarCollapsed = isDesktop ? sidebarCollapsed : false;
  const maxFilesPerBatch = Number(scanLimits?.maxFilesPerBatch) || 10;
  const maxUploadMb = Number(scanLimits?.maxUploadMb) || 25;
  const storedReportCount = Number(analytics?.summary?.totalReports) || 0;

  if (!activeItem) {
    return <Navigate to="/app/dashboard" replace />;
  }

  const pageMotion = createPageTransitionMotion(prefersReducedMotion, { duration: 0.22, y: 8 });

  const openProjects = () => {
    navigate("/app/projects");
    toast.message("Project workspace opened.");
  };

  const openHistory = (nextVerdictFilter = "") => {
    const normalizedVerdictFilter = normalizeVerdictFilterValue(nextVerdictFilter);
    navigate(normalizedVerdictFilter ? `/app/history?verdict=${encodeURIComponent(normalizedVerdictFilter)}` : "/app/history");
    toast.message(normalizedVerdictFilter ? `Showing ${normalizedVerdictFilter} reports.` : "History view opened.");
  };

  const openHistoryByVerdict = (verdictLabel) => {
    const normalizedVerdictFilter = normalizeVerdictFilterValue(verdictLabel);
    if (!normalizedVerdictFilter) {
      return;
    }

    openHistory(normalizedVerdictFilter);
  };

  const openReportWorkspace = (reportId) => {
    if (!reportId) {
      return;
    }

    navigate("/app/history");
    void onOpenReport(reportId);
  };

  return (
    <div className={theme === "dark" ? "dark" : ""}>
      <main className="dashboard-page min-h-screen overflow-x-clip">
        <div className="mx-auto flex w-full max-w-[1760px] min-w-0 flex-col gap-4 overflow-x-clip px-3 py-3 sm:px-4 sm:py-4 lg:flex-row lg:gap-6 lg:px-8">
          <Sidebar
            items={NAV_ITEMS}
            activePath={activeItem.path}
            onSelect={(path) => {
              navigate(path);
              setMobileSidebarOpen(false);
            }}
            logoSrc={logoSrc}
            appName={appName}
            tagline="Security dashboard"
            collapsed={effectiveSidebarCollapsed}
            isDesktop={isDesktop}
            mobileOpen={mobileSidebarOpen}
            onToggleCollapse={() => setSidebarCollapsed((current) => !current)}
            onCloseMobile={() => setMobileSidebarOpen(false)}
          />

          <div className={cn("min-w-0 flex-1 overflow-x-clip", !isDesktop && mobileSidebarOpen && "overflow-hidden")}>
            <Navbar
              searchQuery={searchQuery}
              onSearchChange={onSearchChange}
              onOpenMobileSidebar={() => setMobileSidebarOpen(true)}
              theme={theme}
              onToggleTheme={onToggleTheme}
              notifications={notifications}
              onNotificationsViewed={onNotificationsViewed}
              onFetchNotificationsPage={onFetchNotificationsPage}
              onSelectNotification={onSelectNotification}
              user={session?.user}
              onLogout={onLogout}
            />

            <div className="mb-5 flex flex-col gap-3 sm:mb-6 lg:flex-row lg:items-end lg:justify-between">
              <div>
                <p className="dashboard-label">{activeItem.label}</p>
                <h2 className="mt-2 text-2xl font-semibold tracking-[-0.05em] text-slate-950 dark:text-white sm:text-3xl">
                  {activeItem.description}
                </h2>
              </div>
              <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap">
                {isSyncingData ? (
                  <div className="inline-flex items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-4 py-2 text-sm text-emerald-800 dark:border-emerald-900/70 dark:bg-emerald-950/40 dark:text-emerald-200">
                    <span className="relative inline-flex h-3 w-3 items-center justify-center" aria-hidden="true">
                      <span className="absolute h-3 w-3 rounded-full bg-emerald-400/70 motion-safe:animate-ping motion-reduce:animate-none" />
                      <span className="relative h-2 w-2 rounded-full bg-emerald-600 motion-safe:animate-pulse motion-reduce:animate-none" />
                    </span>
                    <span>Syncing latest data</span>
                  </div>
                ) : null}
                <div className="dashboard-brand-outline">{quotaText}</div>
                <div className="rounded-full border border-slate-200 bg-white px-4 py-2 text-sm text-slate-500 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-400">
                  {storedReportCount} reports stored
                </div>
              </div>
            </div>

            <AnimatePresence mode="wait">
              <motion.section key={activeItem.id} {...pageMotion}>
                <Suspense fallback={<SectionLoading />}>
                  {activeItem.id === "dashboard" ? (
                    <DashboardOverview
                      userName={userName}
                      currentDateLabel={currentDateLabel}
                      quotaText={quotaText}
                      selectedFiles={selectedFiles}
                      searchQuery={searchQuery}
                      maxFilesPerBatch={maxFilesPerBatch}
                      maxUploadMb={maxUploadMb}
                      isSubmittingScan={isSubmittingScan}
                      onSelectFiles={onSelectFiles}
                      onSubmitScan={onSubmitScan}
                      onSubmitUrlScan={onSubmitUrlScan}
                      onClearSelectedFiles={onClearSelectedFiles}
                      jobs={jobs}
                      reports={reports}
                      activeJob={activeJob}
                      analytics={analytics}
                      onOpenReportWorkspace={openReportWorkspace}
                      formatDateTime={formatDateTime}
                      formatBytes={formatBytes}
                      pluralize={pluralize}
                      onCreateProject={openProjects}
                      onOpenReports={openHistory}
                    />
                  ) : null}

                  {activeItem.id === "analytics" ? (
                    <AnalyticsView
                      analytics={analytics}
                      formatDateTime={formatDateTime}
                      themePalette={themePalette}
                      onSelectPosture={openHistoryByVerdict}
                    />
                  ) : null}

                  {activeItem.id === "projects" ? (
                    <ProjectsView
                      selectedFiles={selectedFiles}
                      searchQuery={searchQuery}
                      maxFilesPerBatch={maxFilesPerBatch}
                      maxUploadMb={maxUploadMb}
                      quotaText={quotaText}
                      isSubmittingScan={isSubmittingScan}
                      onSelectFiles={onSelectFiles}
                      onSubmitScan={onSubmitScan}
                      onSubmitUrlScan={onSubmitUrlScan}
                      onClearSelectedFiles={onClearSelectedFiles}
                      jobs={jobs}
                      activeJob={activeJob}
                      onOpenReportWorkspace={openReportWorkspace}
                      formatDateTime={formatDateTime}
                      formatBytes={formatBytes}
                      pluralize={pluralize}
                    />
                  ) : null}

                  {activeItem.id === "websiteSafety" ? (
                    <WebsiteSafetyView
                      searchQuery={searchQuery}
                      jobs={jobs}
                      reports={reports}
                      activeReport={activeReport}
                      isSubmittingScan={isSubmittingScan}
                      onSubmitWebsiteSafetyScan={onSubmitWebsiteSafetyScan}
                      onOpenReport={onOpenReport}
                      onDownloadReportPdf={onDownloadReportPdf}
                      formatDateTime={formatDateTime}
                      formatVerdictLabel={formatVerdictLabel}
                    />
                  ) : null}

                  {activeItem.id === "history" ? (
                    <ReportsView
                      reports={reports}
                      activeReport={activeReport}
                      searchQuery={searchQuery}
                      verdictFilter={verdictFilter}
                      onClearVerdictFilter={() => openHistory("")}
                      onOpenReport={onOpenReport}
                      onCreateShare={onCreateShare}
                      onDeleteReport={onDeleteReport}
                      shareState={shareState}
                      shareError={shareError}
                      isCreatingShare={isCreatingShare}
                      isDeletingReport={isDeletingReport}
                      shareCopied={shareCopied}
                      onCopyShare={onCopyShare}
                      activeRiskMeta={activeRiskMeta}
                      formatDateTime={formatDateTime}
                      formatBytes={formatBytes}
                      getDisplayFileType={getDisplayFileType}
                      formatVerdictLabel={formatVerdictLabel}
                    />
                  ) : null}

                  {activeItem.id === "settings" ? (
                    <SettingsView
                      session={session}
                      theme={theme}
                      onToggleTheme={onToggleTheme}
                      newApiKeyName={newApiKeyName}
                      setNewApiKeyName={setNewApiKeyName}
                      onCreateApiKey={onCreateApiKey}
                      isCreatingKey={isCreatingKey}
                      newApiKey={newApiKey}
                      apiKeys={apiKeys}
                      newApiKeyScopes={newApiKeyScopes}
                      onRevokeApiKey={onRevokeApiKey}
                      setNewApiKeyScopes={setNewApiKeyScopes}
                    />
                  ) : null}

                  {activeItem.id === "docs" ? <DocsView /> : null}
                </Suspense>
              </motion.section>
            </AnimatePresence>
          </div>
        </div>
      </main>
    </div>
  );
}
