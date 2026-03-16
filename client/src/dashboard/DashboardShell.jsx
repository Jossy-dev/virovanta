import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { BarChart3, FileBarChart2, LayoutDashboard, Settings2, ShieldCheck } from "lucide-react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { getUserName, resolveDesktopViewport } from "../appUtils";
import { Sidebar } from "./components/Sidebar";
import { Navbar } from "./components/Navbar";
import { cn } from "./dashboardUtils";

function lazyNamed(importer, exportName) {
  return lazy(() => importer().then((module) => ({ default: module[exportName] })));
}

const DashboardOverview = lazyNamed(() => import("./views/DashboardOverview"), "DashboardOverview");
const AnalyticsView = lazyNamed(() => import("./views/AnalyticsView"), "AnalyticsView");
const ProjectsView = lazyNamed(() => import("./views/ProjectsView"), "ProjectsView");
const ReportsView = lazyNamed(() => import("./views/ReportsView"), "ReportsView");
const SettingsView = lazyNamed(() => import("./views/SettingsView"), "SettingsView");

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
  }
];

function SectionLoading() {
  return (
    <section className="dashboard-shell-surface p-6 sm:p-8">
      <p className="dashboard-label">Loading view</p>
      <h3 className="mt-2 text-xl font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">Preparing workspace section</h3>
      <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">Loading the selected dashboard area.</p>
    </section>
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
  onSelectFiles,
  onSubmitScan,
  onClearSelectedFiles,
  onOpenReport,
  onCreateShare,
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

  const userName = useMemo(() => getUserName(session?.user), [session?.user]);
  const effectiveSidebarCollapsed = isDesktop ? sidebarCollapsed : false;
  const maxFilesPerBatch = Number(scanLimits?.maxFilesPerBatch) || 10;
  const maxUploadMb = Number(scanLimits?.maxUploadMb) || 25;
  const storedReportCount = Number(analytics?.summary?.totalReports) || 0;

  if (!activeItem) {
    return <Navigate to="/app/dashboard" replace />;
  }

  const pageMotion = prefersReducedMotion
    ? { initial: false, animate: {}, exit: {} }
    : {
        initial: { opacity: 0, y: 10 },
        animate: { opacity: 1, y: 0 },
        exit: { opacity: 0, y: -10 },
        transition: { duration: 0.22, ease: [0.22, 1, 0.36, 1] }
      };

  const openProjects = () => {
    navigate("/app/projects");
    toast.message("Project workspace opened.");
  };

  const openHistory = () => {
    navigate("/app/history");
    toast.message("History view opened.");
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
                      onClearSelectedFiles={onClearSelectedFiles}
                      jobs={jobs}
                      activeJob={activeJob}
                      onOpenReportWorkspace={openReportWorkspace}
                      formatDateTime={formatDateTime}
                      formatBytes={formatBytes}
                      pluralize={pluralize}
                    />
                  ) : null}

                  {activeItem.id === "history" ? (
                    <ReportsView
                      reports={reports}
                      activeReport={activeReport}
                      searchQuery={searchQuery}
                      onOpenReport={onOpenReport}
                      onCreateShare={onCreateShare}
                      shareState={shareState}
                      shareError={shareError}
                      isCreatingShare={isCreatingShare}
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
                </Suspense>
              </motion.section>
            </AnimatePresence>
          </div>
        </div>
      </main>
    </div>
  );
}
