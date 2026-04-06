import { useCallback, useEffect, useMemo, useState } from "react";
import { Download, Globe2, ShieldCheck, ShieldX, TerminalSquare } from "lucide-react";
import { WidgetCard } from "../components/WidgetCard";
import { filterCollection } from "../dashboardUtils";
import { SkeletonBlock } from "../../ui/Skeleton";
import ButtonSpinner from "../../ui/ButtonSpinner";

const REPORTS_PAGE_SIZE = 12;
const MAX_INDICATOR_ROWS = 28;
const PENDING_JOB_STATES = new Set(["queued", "processing"]);

function normalizePendingJob(job, fallbackTarget = "") {
  if (!job?.id) {
    return null;
  }

  const status = String(job.status || "queued").toLowerCase();
  return {
    id: job.id,
    reportId: job.reportId || null,
    status: status || "queued",
    targetUrl: String(job.targetUrl || job.originalName || fallbackTarget || "").trim(),
    createdAt: job.createdAt || new Date().toISOString()
  };
}

function pendingStatusLabel(status) {
  if (status === "processing") {
    return "Processing";
  }

  if (status === "completed") {
    return "Finalizing";
  }

  return "Pending";
}

function resolveSafetyScore(report) {
  if (report?.websiteSafety?.score != null) {
    return Math.max(0, Math.min(100, Number(report.websiteSafety.score) || 0));
  }

  const riskScore = Math.max(0, Math.min(100, Number(report?.riskScore) || 0));
  return 100 - riskScore;
}

function resolveSafetyVerdict(report) {
  const explicitVerdict = String(report?.websiteSafety?.verdict || "")
    .trim()
    .toLowerCase();
  if (["safe", "suspicious", "dangerous"].includes(explicitVerdict)) {
    return explicitVerdict;
  }

  const score = resolveSafetyScore(report);
  if (score >= 75) {
    return "safe";
  }

  if (score >= 45) {
    return "suspicious";
  }

  return "dangerous";
}

function verdictPillClass(verdict) {
  if (verdict === "dangerous") {
    return "bg-rose-50 text-rose-700 dark:bg-rose-500/10 dark:text-rose-300";
  }

  if (verdict === "suspicious") {
    return "bg-amber-50 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300";
  }

  return "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300";
}

function findingSeverityBadgeClass(severity) {
  const normalized = String(severity || "info").toLowerCase();

  if (normalized === "critical") {
    return "bg-rose-100 text-rose-700 dark:bg-rose-500/15 dark:text-rose-200";
  }

  if (normalized === "high") {
    return "bg-orange-100 text-orange-700 dark:bg-orange-500/15 dark:text-orange-200";
  }

  if (normalized === "medium") {
    return "bg-amber-100 text-amber-700 dark:bg-amber-500/15 dark:text-amber-200";
  }

  if (normalized === "low") {
    return "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-200";
  }

  return "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-200";
}

function pluralize(count, singular) {
  return `${count} ${singular}${count === 1 ? "" : "s"}`;
}

function formatDomainAge(ageDays, { includeDays = false } = {}) {
  const normalizedAgeDays = Number(ageDays);
  if (!Number.isFinite(normalizedAgeDays) || normalizedAgeDays < 0) {
    return "Unknown";
  }

  const totalDays = Math.max(0, Math.round(normalizedAgeDays));
  if (totalDays < 45) {
    return pluralize(totalDays, "day");
  }

  const totalMonths = Math.max(1, Math.floor(totalDays / 30.4375));
  if (totalDays < 548) {
    const monthLabel = pluralize(totalMonths, "month");
    return includeDays ? `${monthLabel} (${pluralize(totalDays, "day")})` : monthLabel;
  }

  const totalYears = Math.max(1, Math.floor(totalDays / 365.25));
  const remainingDays = totalDays - Math.floor(totalYears * 365.25);
  const remainingMonths = Math.max(0, Math.floor(remainingDays / 30.4375));
  const yearLabel = pluralize(totalYears, "year");
  const ageLabel = remainingMonths > 0 ? `${yearLabel}, ${pluralize(remainingMonths, "month")}` : yearLabel;
  return includeDays ? `${ageLabel} (${pluralize(totalDays, "day")})` : ageLabel;
}

function summarizeSeverityCounts(findings) {
  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  if (!Array.isArray(findings)) {
    return summary;
  }

  findings.forEach((finding) => {
    const severity = String(finding?.severity || "info").toLowerCase();
    if (Object.prototype.hasOwnProperty.call(summary, severity)) {
      summary[severity] += 1;
    } else {
      summary.info += 1;
    }
  });

  return summary;
}

function formatValue(value) {
  if (value == null || value === "") {
    return "N/A";
  }

  if (Array.isArray(value)) {
    if (value.length === 0) {
      return "None";
    }

    return value
      .map((entry) => String(entry || "").trim())
      .filter(Boolean)
      .join(", ");
  }

  if (typeof value === "boolean") {
    return value ? "Yes" : "No";
  }

  if (typeof value === "object") {
    return "Object";
  }

  return String(value);
}

function flattenIndicators(value, prefix = "", rows = [], depth = 0) {
  if (rows.length >= MAX_INDICATOR_ROWS) {
    return rows;
  }

  if (value == null || ["string", "number", "boolean"].includes(typeof value)) {
    if (prefix) {
      rows.push({
        key: prefix,
        value: formatValue(value)
      });
    }
    return rows;
  }

  if (depth >= 3) {
    if (prefix) {
      rows.push({
        key: prefix,
        value: "Depth limit reached"
      });
    }
    return rows;
  }

  if (Array.isArray(value)) {
    const primitive = value.every((entry) => entry == null || ["string", "number", "boolean"].includes(typeof entry));
    if (primitive) {
      rows.push({
        key: prefix || "value",
        value: formatValue(value)
      });
      return rows;
    }

    value.slice(0, 8).forEach((entry, index) => {
      flattenIndicators(entry, `${prefix}[${index}]`, rows, depth + 1);
    });

    if (value.length > 8) {
      rows.push({
        key: prefix || "value",
        value: `${value.length - 8} additional entries omitted`
      });
    }
    return rows;
  }

  const entries = Object.entries(value);
  if (entries.length === 0 && prefix) {
    rows.push({
      key: prefix,
      value: "None"
    });
    return rows;
  }

  entries.forEach(([key, nestedValue]) => {
    if (rows.length >= MAX_INDICATOR_ROWS) {
      return;
    }

    const composedKey = prefix ? `${prefix}.${key}` : key;
    flattenIndicators(nestedValue, composedKey, rows, depth + 1);
  });

  return rows;
}

function SourceStatusBadge({ verdict }) {
  if (verdict === "dangerous") {
    return <ShieldX size={16} className="text-rose-500 dark:text-rose-300" />;
  }

  if (verdict === "suspicious") {
    return <TerminalSquare size={16} className="text-amber-500 dark:text-amber-300" />;
  }

  return <ShieldCheck size={16} className="text-emerald-500 dark:text-emerald-300" />;
}

function WebsiteReportDetailsSkeleton({ reportName = "Loading report details" }) {
  return (
    <>
      <WidgetCard title="Selected report" subtitle={reportName}>
        <div className="space-y-4" role="status" aria-live="polite" aria-busy="true">
          <div className="flex flex-wrap items-center gap-2">
            <SkeletonBlock className="h-7 w-20 rounded-full" />
            <SkeletonBlock className="h-7 w-24 rounded-full" />
            <SkeletonBlock className="h-7 w-20 rounded-full" />
          </div>

          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {Array.from({ length: 7 }, (_value, index) => (
              <div key={`website-details-skeleton-stat-${index}`} className="rounded-2xl border border-slate-200/80 px-3 py-3 dark:border-slate-800/80">
                <SkeletonBlock className="h-3 w-20" />
                <SkeletonBlock className="mt-2 h-4 w-16" />
              </div>
            ))}
          </div>

          <div className="rounded-2xl border border-viro-200/80 bg-viro-50/60 px-3 py-3 dark:border-viro-800/70 dark:bg-viro-900/25">
            <SkeletonBlock className="h-3 w-32" />
            <SkeletonBlock className="mt-2 h-3 w-full" />
            <SkeletonBlock className="mt-2 h-3 w-5/6" />
          </div>

          <SkeletonBlock className="h-10 w-full rounded-full" />
        </div>
      </WidgetCard>

      <WidgetCard title="Module checks" subtitle="Security and trust analysis layers">
        <div className="space-y-3" aria-hidden="true">
          <SkeletonBlock className="h-20 w-full rounded-2xl" />
          <SkeletonBlock className="h-20 w-full rounded-2xl" />
          <SkeletonBlock className="h-20 w-full rounded-2xl" />
        </div>
      </WidgetCard>

      <WidgetCard title="Findings" subtitle="Loading findings">
        <div className="space-y-3" aria-hidden="true">
          <SkeletonBlock className="h-16 w-full rounded-2xl" />
          <SkeletonBlock className="h-16 w-full rounded-2xl" />
        </div>
      </WidgetCard>
    </>
  );
}

export function WebsiteSafetyView({
  searchQuery,
  jobs,
  reports,
  activeReport,
  isSubmittingScan,
  onSubmitWebsiteSafetyScan = async () => {},
  onOpenReport = async () => {},
  onDownloadReportPdf = async () => {},
  formatDateTime,
  formatVerdictLabel
}) {
  const [urlTarget, setUrlTarget] = useState("");
  const [submitError, setSubmitError] = useState("");
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);
  const [downloadError, setDownloadError] = useState("");
  const [visibleReportCount, setVisibleReportCount] = useState(REPORTS_PAGE_SIZE);
  const [optimisticPendingJobs, setOptimisticPendingJobs] = useState([]);
  const [pendingSelectedReportId, setPendingSelectedReportId] = useState("");

  const websiteJobs = useMemo(
    () => filterCollection(jobs, searchQuery, ["originalName", "status", "id", "targetUrl", "sourceType"]).filter((job) => job.sourceType === "website"),
    [jobs, searchQuery]
  );
  const websiteReports = useMemo(
    () => filterCollection(reports, searchQuery, ["fileName", "verdict", "id", "sourceType"]).filter((report) => report.sourceType === "website"),
    [reports, searchQuery]
  );
  const visibleReportIds = useMemo(() => new Set(websiteReports.map((report) => report.id)), [websiteReports]);
  const serverPendingJobs = useMemo(() => {
    return websiteJobs
      .map((job) => normalizePendingJob(job))
      .filter(Boolean)
      .filter((job) => {
        if (job.reportId && visibleReportIds.has(job.reportId)) {
          return false;
        }

        if (PENDING_JOB_STATES.has(job.status)) {
          return true;
        }

        return job.status === "completed";
      });
  }, [websiteJobs, visibleReportIds]);
  const pendingJobs = useMemo(() => {
    const serverIds = new Set(serverPendingJobs.map((job) => job.id));
    const fallback = optimisticPendingJobs.filter((job) => !serverIds.has(job.id));
    return [...serverPendingJobs, ...fallback];
  }, [optimisticPendingJobs, serverPendingJobs]);
  const websiteResultRows = useMemo(() => {
    const reportRows = websiteReports.map((report) => ({
      id: `report:${report.id}`,
      type: "report",
      timestampMs: Date.parse(report.completedAt || report.createdAt || "") || 0,
      report
    }));
    const pendingRows = pendingJobs.map((job) => ({
      id: `job:${job.id}`,
      type: "pending",
      timestampMs: Date.parse(job.createdAt || "") || 0,
      job
    }));

    return [...reportRows, ...pendingRows].sort((left, right) => right.timestampMs - left.timestampMs);
  }, [pendingJobs, websiteReports]);
  const visibleResultRows = useMemo(
    () => websiteResultRows.slice(0, visibleReportCount),
    [websiteResultRows, visibleReportCount]
  );
  const canLoadMoreReports = websiteResultRows.length > visibleReportCount;
  const selectedWebsiteReport = useMemo(() => {
    if (!activeReport || activeReport.sourceType !== "website") {
      return null;
    }

    return websiteReports.some((report) => report.id === activeReport.id) ? activeReport : null;
  }, [activeReport, websiteReports]);
  const selectedListReportId = pendingSelectedReportId || selectedWebsiteReport?.id || "";
  const pendingSelectedReportSummary = useMemo(() => {
    if (!pendingSelectedReportId) {
      return null;
    }

    return websiteReports.find((report) => report.id === pendingSelectedReportId) || null;
  }, [pendingSelectedReportId, websiteReports]);
  const isReportDetailsLoading = Boolean(pendingSelectedReportId) && pendingSelectedReportId !== selectedWebsiteReport?.id;
  const hasSelectedOrPendingReport = Boolean(selectedWebsiteReport || pendingSelectedReportSummary);
  const selectedWebsiteModules = selectedWebsiteReport?.websiteSafety?.modules || {};
  const selectedDnsDomain = selectedWebsiteModules?.dnsDomain || {};
  const selectedLookupDomain = String(selectedDnsDomain?.rdap?.domain || selectedDnsDomain?.rdap?.payloadDomain || "").trim();
  const selectedWebsiteHostname = String(selectedWebsiteReport?.url?.hostname || selectedWebsiteModules?.url?.hostname || "").trim();
  const selectedAgeUsesParentDomain = Boolean(selectedLookupDomain && selectedWebsiteHostname && selectedLookupDomain !== selectedWebsiteHostname);
  const domainAgeLabel = selectedAgeUsesParentDomain ? "Parent domain age" : "Domain age";
  const formattedDomainAge = formatDomainAge(selectedDnsDomain?.ageDays);
  const formattedDomainAgeWithDays = formatDomainAge(selectedDnsDomain?.ageDays, { includeDays: true });
  const registrationEvidenceLabel =
    selectedDnsDomain?.rdap?.registrationEvidence === "explicit_rdap_event"
      ? "Verified registry registration date"
      : selectedDnsDomain?.registeredAt
        ? "Derived from registry registration date"
        : "Registration date unavailable";
  const selectedSafetyVerdict = resolveSafetyVerdict(selectedWebsiteReport);
  const selectedSafetyScore = resolveSafetyScore(selectedWebsiteReport);
  const selectedFindings = Array.isArray(selectedWebsiteReport?.findings) ? selectedWebsiteReport.findings : [];
  const findingSeveritySummary = useMemo(() => summarizeSeverityCounts(selectedFindings), [selectedFindings]);
  const indicatorRows = useMemo(
    () => flattenIndicators(selectedWebsiteReport?.technicalIndicators || {}),
    [selectedWebsiteReport]
  );
  const flaggedProviderCount = useMemo(
    () => (selectedWebsiteModules?.reputation?.flaggedProviders || []).filter(Boolean).length,
    [selectedWebsiteModules]
  );
  const sensitiveExposureCount = useMemo(
    () => (selectedWebsiteModules?.vulnerabilityChecks?.exposures || []).length,
    [selectedWebsiteModules]
  );
  const redirectCount = Number(selectedWebsiteModules?.redirects?.count) || 0;
  const missingHeaderCount = (selectedWebsiteModules?.headers?.missing || []).length;
  const fetchAttemptCount = (selectedWebsiteModules?.fetch?.attempts || []).length;
  const spfPresent = Boolean(selectedWebsiteModules?.dnsDomain?.mailAuth?.spfPresent);
  const dmarcPresent = Boolean(selectedWebsiteModules?.dnsDomain?.mailAuth?.dmarcPresent);
  const securityTxtPresent = Boolean(selectedWebsiteModules?.discovery?.securityTxt?.found);
  const robotsTxtPresent = Boolean(selectedWebsiteModules?.discovery?.robotsTxt?.found);
  const plainLanguageReasons = useMemo(
    () =>
      (Array.isArray(selectedWebsiteReport?.plainLanguageReasons) ? selectedWebsiteReport.plainLanguageReasons : [])
        .map((entry) => String(entry || "").trim())
        .filter(Boolean)
        .slice(0, 6),
    [selectedWebsiteReport]
  );

  const handleSelectReport = useCallback(
    (reportId) => {
      if (!reportId || reportId === selectedListReportId) {
        return;
      }

      setPendingSelectedReportId(reportId);
      Promise.resolve(onOpenReport(reportId)).catch(() => {
        setPendingSelectedReportId((current) => (current === reportId ? "" : current));
      });
    },
    [onOpenReport, selectedListReportId]
  );

  useEffect(() => {
    if (optimisticPendingJobs.length === 0) {
      return;
    }

    const serverJobIds = new Set(websiteJobs.map((job) => job.id));
    const nextOptimistic = optimisticPendingJobs.filter((job) => {
      if (serverJobIds.has(job.id)) {
        return false;
      }

      return !(job.reportId && visibleReportIds.has(job.reportId));
    });

    const changed =
      nextOptimistic.length !== optimisticPendingJobs.length ||
      nextOptimistic.some((job, index) => job.id !== optimisticPendingJobs[index]?.id);

    if (changed) {
      setOptimisticPendingJobs(nextOptimistic);
    }
  }, [optimisticPendingJobs, visibleReportIds, websiteJobs]);

  useEffect(() => {
    if (!pendingSelectedReportId) {
      return;
    }

    if (selectedWebsiteReport?.id === pendingSelectedReportId) {
      setPendingSelectedReportId("");
    }
  }, [pendingSelectedReportId, selectedWebsiteReport?.id]);

  useEffect(() => {
    if (!pendingSelectedReportId) {
      return;
    }

    if (!websiteReports.some((report) => report.id === pendingSelectedReportId)) {
      setPendingSelectedReportId("");
    }
  }, [pendingSelectedReportId, websiteReports]);

  async function handleSubmit(event) {
    event.preventDefault();
    const normalizedUrl = String(urlTarget || "").trim();
    if (!normalizedUrl) {
      setSubmitError("Paste a URL to run website safety analysis.");
      return;
    }

    setSubmitError("");
    setDownloadError("");

    try {
      const queuedJob = await onSubmitWebsiteSafetyScan(normalizedUrl);
      const pendingJob = normalizePendingJob(queuedJob, normalizedUrl);
      if (pendingJob) {
        setOptimisticPendingJobs((current) => [
          pendingJob,
          ...current.filter((job) => job.id !== pendingJob.id)
        ]);
      }
      setUrlTarget("");
    } catch (error) {
      setSubmitError(error?.message || "Could not queue website safety scan.");
    }
  }

  async function handleDownloadPdf() {
    if (!selectedWebsiteReport?.id || isDownloadingPdf) {
      return;
    }

    setIsDownloadingPdf(true);
    setDownloadError("");

    try {
      await onDownloadReportPdf(selectedWebsiteReport.id);
    } catch (error) {
      setDownloadError(error?.message || "Could not download report PDF.");
    } finally {
      setIsDownloadingPdf(false);
    }
  }

  return (
    <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
      <div className="space-y-6">
        <section className="dashboard-shell-surface p-4 sm:p-6">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <p className="dashboard-label">Website safety scanner</p>
              <h2 className="text-xl font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">Analyze web application safety posture</h2>
              <p className="mt-2 max-w-3xl text-sm leading-7 text-slate-500 dark:text-slate-400">
                Submit a public URL to run DNS, TLS, security-header, content, redirect, reputation, and safe exposure checks in the background.
              </p>
            </div>
            <span className="dashboard-brand-outline inline-flex items-center gap-2">
              <Globe2 size={15} />
              Separate from URL threat scan
            </span>
          </div>

          <form className="mt-6 rounded-3xl border border-slate-200/80 bg-slate-50 p-4 dark:border-slate-800/80 dark:bg-slate-900/50" onSubmit={handleSubmit}>
            <p className="text-sm font-semibold text-slate-950 dark:text-white">Website URL</p>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Use a full domain or URL. The scanner enforces SSRF-safe network rules.</p>
            <div className="mt-3 flex flex-col gap-3 sm:flex-row sm:items-center">
              <label htmlFor="website-safety-url-input" className="sr-only">
                Website URL
              </label>
              <input
                id="website-safety-url-input"
                type="url"
                inputMode="url"
                autoComplete="url"
                placeholder="https://example.com"
                value={urlTarget}
                onChange={(event) => setUrlTarget(event.target.value)}
                className="w-full rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-900 outline-none transition focus:border-viro-500 focus:ring-2 focus:ring-viro-200 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100 dark:focus:border-viro-400 dark:focus:ring-viro-900"
              />
              <button type="submit" disabled={isSubmittingScan} className="dashboard-brand-button w-full justify-center sm:w-auto">
                {isSubmittingScan ? "Queueing..." : "Run Safety Scan"}
              </button>
            </div>
            {submitError ? <p className="mt-3 text-sm text-rose-600 dark:text-rose-300">{submitError}</p> : null}
          </form>
        </section>

        <section className="space-y-4">
          <div>
            <p className="dashboard-label">Results</p>
            <h2 className="text-xl font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">Website safety reports</h2>
          </div>
          <div className="dashboard-shell-surface p-0">
            <div className="dashboard-scrollbar max-h-[44vh] overflow-y-auto rounded-none border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-950">
              {visibleResultRows.length === 0 ? (
                <p className="px-4 py-4 text-sm text-slate-500 dark:text-slate-400">No website safety reports available.</p>
              ) : (
                visibleResultRows.map((row, index) => {
                  const isAlternateRow = index % 2 === 1;

                  if (row.type === "pending") {
                    const pendingJob = row.job;
                    const pendingLabel = pendingStatusLabel(pendingJob.status);
                    return (
                      <div
                        key={row.id}
                        className={`w-full rounded-none border-b border-slate-200/80 px-4 py-4 text-left transition-colors duration-150 last:border-b-0 dark:border-slate-800/80 ${
                          isAlternateRow
                            ? "bg-slate-50/70 dark:bg-slate-900/65"
                            : "bg-white dark:bg-slate-950"
                        }`}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <p className="break-all text-sm font-semibold text-slate-900 dark:text-slate-100">
                            {pendingJob.targetUrl || "Website target"}
                          </p>
                          <span className="inline-flex items-center gap-1.5 rounded-full bg-amber-50 px-2 py-1 text-[11px] font-medium text-amber-700 dark:bg-amber-500/10 dark:text-amber-300">
                            <span className="h-2 w-2 animate-pulse rounded-full bg-amber-500 dark:bg-amber-300" />
                            {pendingLabel}
                          </span>
                        </div>
                        <p className="mt-1 text-xs text-slate-500 dark:text-slate-300">{formatDateTime(pendingJob.createdAt)}</p>
                        <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">Running checks in background. Report will appear here when ready.</p>
                      </div>
                    );
                  }

                  const report = row.report;
                  const isActive = report.id === selectedListReportId;
                  const isPendingActive = report.id === pendingSelectedReportId && pendingSelectedReportId !== selectedWebsiteReport?.id;
                  const safetyVerdict = resolveSafetyVerdict(report);

                  return (
                    <button
                      key={row.id}
                      type="button"
                      onClick={() => {
                        handleSelectReport(report.id);
                      }}
                      className={`w-full cursor-pointer rounded-none border-b border-slate-200/80 px-4 py-4 text-left transition-colors duration-150 last:border-b-0 dark:border-slate-800/80 ${
                        isActive
                          ? "bg-viro-600 text-white dark:bg-viro-500 dark:text-white"
                          : isAlternateRow
                            ? "bg-slate-50/70 hover:bg-viro-50/70 dark:bg-slate-900/65 dark:hover:bg-viro-900/25"
                            : "bg-white hover:bg-slate-50 dark:bg-slate-950 dark:hover:bg-viro-900/20"
                      }`}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <p className={`break-all text-sm font-semibold ${isActive ? "text-white" : "text-slate-900 dark:text-slate-100"}`}>{report.fileName}</p>
                        {isPendingActive ? (
                          <span className="inline-flex items-center gap-1 text-[10px] font-medium uppercase tracking-[0.12em] text-white/80 dark:text-white/80">
                            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-white/90" />
                            Loading
                          </span>
                        ) : (
                          <div className="mt-0.5">
                            <SourceStatusBadge verdict={safetyVerdict} />
                          </div>
                        )}
                      </div>
                      <p className={`mt-1 text-xs ${isActive ? "text-white/80" : "text-slate-500 dark:text-slate-300"}`}>{formatDateTime(report.completedAt)}</p>
                      <div className="mt-2 flex flex-wrap items-center gap-2">
                        <span
                          className={`inline-flex rounded-full px-2 py-1 text-[11px] font-medium ${
                            isActive ? "bg-white/20 text-white" : verdictPillClass(safetyVerdict)
                          }`}
                        >
                          {safetyVerdict}
                        </span>
                        <span
                          className={`inline-flex rounded-full px-2 py-1 text-[11px] ${
                            isActive ? "bg-white/20 text-white" : "bg-slate-100 text-slate-600 dark:bg-slate-900 dark:text-slate-300"
                          }`}
                        >
                          Risk {Math.max(0, Math.min(100, Number(report.riskScore) || 0))}
                        </span>
                      </div>
                    </button>
                  );
                })
              )}
            </div>
            {canLoadMoreReports ? (
              <div className="border-t border-slate-200 px-4 py-3 dark:border-slate-800">
                <button type="button" className="dashboard-brand-outline w-full justify-center" onClick={() => setVisibleReportCount((current) => current + REPORTS_PAGE_SIZE)}>
                  Load more reports
                </button>
              </div>
            ) : null}
          </div>
        </section>
      </div>

      <div className="space-y-4">
        {!hasSelectedOrPendingReport ? (
          <WidgetCard title="No website report selected" subtitle="Select a report from the list">
            <p className="text-sm leading-7 text-slate-500 dark:text-slate-400">Choose a website safety report to inspect DNS, TLS, headers, content, and exposure findings.</p>
          </WidgetCard>
        ) : isReportDetailsLoading ? (
          <WebsiteReportDetailsSkeleton reportName={pendingSelectedReportSummary?.fileName || "Loading report details"} />
        ) : !selectedWebsiteReport ? (
          <WidgetCard title="No website report selected" subtitle="Select a report from the list">
            <p className="text-sm leading-7 text-slate-500 dark:text-slate-400">Choose a website safety report to inspect DNS, TLS, headers, content, and exposure findings.</p>
          </WidgetCard>
        ) : (
          <>
            <WidgetCard title="Selected report" subtitle={selectedWebsiteReport?.url?.final || selectedWebsiteReport.file?.originalName}>
              <div className="space-y-4">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`inline-flex rounded-full px-3 py-1.5 text-xs font-semibold ${verdictPillClass(selectedSafetyVerdict)}`}>
                    {selectedSafetyVerdict}
                  </span>
                  <span className="inline-flex rounded-full bg-slate-100 px-3 py-1.5 text-xs font-medium text-slate-700 dark:bg-slate-900 dark:text-slate-300">
                    Safety {selectedSafetyScore}/100
                  </span>
                  <span className="inline-flex rounded-full bg-slate-100 px-3 py-1.5 text-xs font-medium text-slate-700 dark:bg-slate-900 dark:text-slate-300">
                    Risk {Math.max(0, Math.min(100, Number(selectedWebsiteReport?.riskScore) || 0))}/100
                  </span>
                </div>

                <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                  <div className="rounded-2xl border border-slate-200/80 px-3 py-3 dark:border-slate-800/80">
                    <p className="dashboard-label">{domainAgeLabel}</p>
                    <p className="mt-1 text-sm font-semibold text-slate-950 dark:text-white">
                      {formattedDomainAge}
                    </p>
                  </div>
                  <div className="rounded-2xl border border-slate-200/80 px-3 py-3 dark:border-slate-800/80">
                    <p className="dashboard-label">Findings</p>
                    <p className="mt-1 text-sm font-semibold text-slate-950 dark:text-white">{selectedFindings.length}</p>
                  </div>
                  <div className="rounded-2xl border border-slate-200/80 px-3 py-3 dark:border-slate-800/80">
                    <p className="dashboard-label">Missing headers</p>
                    <p className="mt-1 text-sm font-semibold text-slate-950 dark:text-white">{missingHeaderCount}</p>
                  </div>
                  <div className="rounded-2xl border border-slate-200/80 px-3 py-3 dark:border-slate-800/80">
                    <p className="dashboard-label">Redirects</p>
                    <p className="mt-1 text-sm font-semibold text-slate-950 dark:text-white">{redirectCount}</p>
                  </div>
                  <div className="rounded-2xl border border-slate-200/80 px-3 py-3 dark:border-slate-800/80">
                    <p className="dashboard-label">Flagged intel providers</p>
                    <p className="mt-1 text-sm font-semibold text-slate-950 dark:text-white">{flaggedProviderCount}</p>
                  </div>
                  <div className="rounded-2xl border border-slate-200/80 px-3 py-3 dark:border-slate-800/80">
                    <p className="dashboard-label">Sensitive exposures</p>
                    <p className="mt-1 text-sm font-semibold text-slate-950 dark:text-white">{sensitiveExposureCount}</p>
                  </div>
                  <div className="rounded-2xl border border-slate-200/80 px-3 py-3 dark:border-slate-800/80">
                    <p className="dashboard-label">Fetch attempts</p>
                    <p className="mt-1 text-sm font-semibold text-slate-950 dark:text-white">{fetchAttemptCount || 1}</p>
                  </div>
                </div>

                <div className="rounded-2xl border border-viro-200/80 bg-viro-50/60 px-3 py-3 dark:border-viro-800/70 dark:bg-viro-900/25">
                  <p className="dashboard-label text-viro-700 dark:text-viro-200">Executive summary</p>
                  {plainLanguageReasons.length === 0 ? (
                    <p className="mt-1 text-sm text-slate-700 dark:text-slate-200">No plain-language summary available for this report yet.</p>
                  ) : (
                    <ul className="mt-2 space-y-2 text-sm text-slate-700 dark:text-slate-200">
                      {plainLanguageReasons.map((reason) => (
                        <li key={reason} className="flex items-start gap-2">
                          <span className="mt-1.5 h-1.5 w-1.5 rounded-full bg-viro-600 dark:bg-viro-300" />
                          <span>{reason}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>

                <button
                  type="button"
                  onClick={handleDownloadPdf}
                  disabled={isDownloadingPdf}
                  aria-busy={isDownloadingPdf}
                  className="dashboard-brand-outline inline-flex w-full items-center justify-center gap-2 disabled:cursor-progress disabled:opacity-55"
                >
                  {isDownloadingPdf ? <ButtonSpinner className="text-current" /> : <Download size={14} />}
                  {isDownloadingPdf ? "Preparing PDF..." : "Download PDF report"}
                </button>
                {downloadError ? <p className="text-sm text-rose-600 dark:text-rose-300">{downloadError}</p> : null}
              </div>
            </WidgetCard>

            <WidgetCard title="Module checks" subtitle="Security and trust analysis layers">
              <div className="space-y-4 text-sm text-slate-600 dark:text-slate-300">
                <div className="rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="font-semibold text-slate-900 dark:text-slate-100">Domain and infrastructure</p>
                  <div className="mt-2 grid gap-2 text-sm sm:grid-cols-2">
                    <p>Registrar: {selectedDnsDomain?.registrar || "Unknown"}</p>
                    <p>{domainAgeLabel}: {formattedDomainAgeWithDays}</p>
                    <p>Registration evidence: {registrationEvidenceLabel}</p>
                    <p>Lookup domain: {selectedLookupDomain || selectedWebsiteHostname || "Unavailable"}</p>
                    <p>Registered at: {selectedDnsDomain?.registeredAt ? formatDateTime(selectedDnsDomain.registeredAt) : "Unknown"}</p>
                    <p>Expires at: {selectedDnsDomain?.expiresAt ? formatDateTime(selectedDnsDomain.expiresAt) : "Unknown"}</p>
                    <p>Primary IP: {selectedWebsiteModules?.ipHosting?.primaryIp || "Unavailable"}</p>
                    <p>ASN: {selectedWebsiteModules?.ipHosting?.asn || "Unavailable"}</p>
                    <p>DNSSEC: {selectedDnsDomain?.rdap?.dnssecSigned === true ? "Signed" : selectedDnsDomain?.rdap?.dnssecSigned === false ? "Not signed" : "Unknown"}</p>
                    <p>RDAP abuse contact: {selectedDnsDomain?.rdap?.abuseEmail || "Unavailable"}</p>
                    <p className="sm:col-span-2">
                      Nameservers: {(selectedDnsDomain?.nameservers || []).slice(0, 6).join(", ") || "Unavailable"}
                    </p>
                    <p className="sm:col-span-2">
                      RDAP status: {(selectedDnsDomain?.rdap?.domainStatus || []).slice(0, 6).join(", ") || "Unavailable"}
                    </p>
                    <p>SPF: {spfPresent ? "Present" : "Missing"}</p>
                    <p>DMARC: {dmarcPresent ? "Present" : "Missing"}</p>
                  </div>
                </div>

                <div className="rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="font-semibold text-slate-900 dark:text-slate-100">Transport and header security</p>
                  <div className="mt-2 grid gap-2 text-sm sm:grid-cols-2">
                    <p>TLS status: {selectedWebsiteModules?.ssl?.status || "Unknown"}</p>
                    <p>Cert issuer: {selectedWebsiteModules?.ssl?.certIssuer || "Unknown"}</p>
                    <p>Cert expires: {selectedWebsiteModules?.ssl?.certValidTo ? formatDateTime(selectedWebsiteModules.ssl.certValidTo) : "Unknown"}</p>
                    <p>Days remaining: {selectedWebsiteModules?.ssl?.certDaysRemaining ?? "Unknown"}</p>
                    <p className="sm:col-span-2">Missing headers: {formatValue(selectedWebsiteModules?.headers?.missing)}</p>
                  </div>
                </div>

                <div className="rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="font-semibold text-slate-900 dark:text-slate-100">Content and behavior</p>
                  <div className="mt-2 grid gap-2 text-sm sm:grid-cols-2">
                    <p>Suspicious keywords: {formatValue(selectedWebsiteModules?.content?.suspiciousKeywords)}</p>
                    <p>Hidden iframes: {Number(selectedWebsiteModules?.content?.hiddenIframes) || 0}</p>
                    <p>Obfuscation indicators: {Number(selectedWebsiteModules?.content?.obfuscatedScriptIndicators) || 0}</p>
                    <p>Password fields: {Number(selectedWebsiteModules?.content?.passwordFieldCount) || 0}</p>
                    <p className="sm:col-span-2">
                      External scripts: {(selectedWebsiteModules?.content?.externalScripts || []).slice(0, 4).join(", ") || "None"}
                    </p>
                  </div>
                </div>

                <div className="rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
                  <p className="font-semibold text-slate-900 dark:text-slate-100">Threat intelligence and exposure</p>
                  <div className="mt-2 grid gap-2 text-sm sm:grid-cols-2">
                    <p>Reputation flagged: {selectedWebsiteModules?.reputation?.flagged ? "Yes" : "No"}</p>
                    <p>Threat types: {formatValue(selectedWebsiteModules?.reputation?.flaggedThreats)}</p>
                    <p>Cross-domain redirects: {Number(selectedWebsiteModules?.redirects?.crossDomainCount) || 0}</p>
                    <p>Sensitive exposures: {sensitiveExposureCount}</p>
                    <p className="sm:col-span-2">
                      Reachable admin endpoints:{" "}
                      {formatValue(
                        (selectedWebsiteModules?.vulnerabilityChecks?.adminEndpoints || []).map((entry) => `${entry.path} (${entry.status})`)
                      )}
                    </p>
                    <p>security.txt: {securityTxtPresent ? "Present" : "Missing"}</p>
                    <p>robots.txt: {robotsTxtPresent ? "Present" : "Missing"}</p>
                  </div>
                </div>
              </div>
            </WidgetCard>

            <WidgetCard title="Finding severity breakdown" subtitle="Prioritized by risk">
              <div className="grid gap-3 sm:grid-cols-2">
                {Object.entries(findingSeveritySummary).map(([severity, count]) => (
                  <div key={severity} className="rounded-2xl border border-slate-200/80 px-3 py-3 dark:border-slate-800/80">
                    <p className="dashboard-label">{severity}</p>
                    <p className="mt-1 text-lg font-semibold text-slate-950 dark:text-white">{count}</p>
                  </div>
                ))}
              </div>
            </WidgetCard>

            <WidgetCard title="Findings" subtitle={formatVerdictLabel(selectedWebsiteReport.verdict)}>
              {selectedFindings.length > 0 ? (
                <div className="space-y-3">
                  {selectedFindings.map((finding) => (
                    <div key={`${finding.id}-${finding.title}`} className="rounded-2xl border border-slate-200/80 px-3 py-3 dark:border-slate-800/80">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">{finding.title}</p>
                        <span className={`inline-flex rounded-full px-2 py-1 text-[11px] font-semibold ${findingSeverityBadgeClass(finding.severity)}`}>
                          {String(finding.severity || "info").toLowerCase()}
                        </span>
                      </div>
                      <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                        Category: {finding.category || "General"} {finding.weight != null ? `• Weight: ${finding.weight}` : ""}
                      </p>
                      <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">{finding.description}</p>
                      {finding.evidence ? (
                        <p className="mt-2 rounded-xl bg-slate-100 px-2.5 py-2 text-xs text-slate-600 dark:bg-slate-900 dark:text-slate-300">
                          Evidence: {finding.evidence}
                        </p>
                      ) : null}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-slate-500 dark:text-slate-400">No findings were recorded for this website safety scan.</p>
              )}
            </WidgetCard>

            <WidgetCard title="Technical indicators" subtitle="Low-level telemetry snapshot">
              {indicatorRows.length > 0 ? (
                <div className="space-y-2">
                  {indicatorRows.map((entry) => (
                    <div key={`${entry.key}-${entry.value}`} className="rounded-xl border border-slate-200/80 px-3 py-2.5 dark:border-slate-800/80">
                      <p className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500 dark:text-slate-400">{entry.key}</p>
                      <p className="mt-1 text-sm text-slate-700 dark:text-slate-200">{entry.value}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-slate-500 dark:text-slate-400">No technical indicators available for this report.</p>
              )}
            </WidgetCard>
          </>
        )}
      </div>
    </div>
  );
}
