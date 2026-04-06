import { useEffect, useMemo, useRef, useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { ArrowRight, Check, FolderOpen, Link2, ListFilter, ShieldAlert, UploadCloud, X } from "lucide-react";
import { DataTable } from "../components/DataTable";
import { WidgetCard } from "../components/WidgetCard";
import { cn, filterCollection } from "../dashboardUtils";
import Button from "../../ui/Button";
import Modal from "../../ui/Modal";
import { createStaggerContainerVariants, createStaggerItemVariants } from "../../ui/motionSystem";
import { looksLikeDirectUrlScanInput } from "../../urlScanIntake";

const JOBS_PER_PAGE = 10;
const EMPTY_URL_CANDIDATE_MODAL = Object.freeze({
  open: false,
  inputMode: "message",
  primaryUrl: "",
  candidates: [],
  selectedUrls: []
});

function getUrlCandidateSourceLabel(source) {
  if (source === "href") {
    return "HTML link";
  }

  if (source === "explicit") {
    return "Inline URL";
  }

  if (source === "bare") {
    return "Domain match";
  }

  return "Direct link";
}

export function ProjectsView({
  selectedFiles,
  searchQuery,
  maxFilesPerBatch,
  maxUploadMb,
  quotaText,
  isSubmittingScan,
  onSelectFiles,
  onSubmitScan,
  onResolveUrlScanTargets = async () => null,
  onSubmitUrlScans = async () => {},
  onClearSelectedFiles,
  jobs,
  activeJob,
  onOpenReportWorkspace,
  formatDateTime,
  formatBytes,
  pluralize,
  showHeader = true,
  showQuotaBadge = true
}) {
  const prefersReducedMotion = useReducedMotion();
  const fileInputRef = useRef(null);
  const [urlTarget, setUrlTarget] = useState("");
  const [urlSubmissionError, setUrlSubmissionError] = useState("");
  const [urlCandidateModal, setUrlCandidateModal] = useState(EMPTY_URL_CANDIDATE_MODAL);
  const [jobsPage, setJobsPage] = useState(1);

  useEffect(() => {
    if (selectedFiles.length === 0 && fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  }, [selectedFiles]);

  const selectedUploadBytes = useMemo(
    () => selectedFiles.reduce((total, file) => total + (Number(file?.size) || 0), 0),
    [selectedFiles]
  );

  const filteredJobs = useMemo(
    () => filterCollection(jobs, searchQuery, ["originalName", "status", "id", "targetUrl", "sourceType"]),
    [jobs, searchQuery]
  );
  const totalJobPages = Math.max(1, Math.ceil(filteredJobs.length / JOBS_PER_PAGE));
  const paginatedJobs = useMemo(() => {
    const start = (jobsPage - 1) * JOBS_PER_PAGE;
    return filteredJobs.slice(start, start + JOBS_PER_PAGE);
  }, [filteredJobs, jobsPage]);

  useEffect(() => {
    setJobsPage(1);
  }, [searchQuery]);

  useEffect(() => {
    if (jobsPage > totalJobPages) {
      setJobsPage(totalJobPages);
    }
  }, [jobsPage, totalJobPages]);

  const pendingJobs = jobs.filter((job) => job.status === "queued" || job.status === "processing").length;
  const completedJobs = jobs.filter((job) => job.status === "completed").length;
  const selectedFileNames = selectedFiles.map((file) => file?.name).filter(Boolean);
  const normalizedUrlTarget = String(urlTarget || "").trim();
  const urlInputLooksLikeDirectLink = looksLikeDirectUrlScanInput(normalizedUrlTarget);
  const selectedCandidateCount = urlCandidateModal.selectedUrls.length;
  const allCandidatesSelected =
    urlCandidateModal.candidates.length > 0 && selectedCandidateCount === urlCandidateModal.candidates.length;
  const selectedFileListVariants = createStaggerContainerVariants(prefersReducedMotion, {
    staggerChildren: 0.03,
    delayChildren: 0.02
  });
  const selectedFileItemVariants = createStaggerItemVariants(prefersReducedMotion, {
    y: 4,
    duration: 0.16
  });

  function closeUrlCandidateModal() {
    setUrlCandidateModal(EMPTY_URL_CANDIDATE_MODAL);
  }

  function toggleUrlCandidateSelection(targetUrl) {
    setUrlCandidateModal((current) => {
      const nextSelectedUrls = current.selectedUrls.includes(targetUrl)
        ? current.selectedUrls.filter((item) => item !== targetUrl)
        : [...current.selectedUrls, targetUrl];

      return {
        ...current,
        selectedUrls: nextSelectedUrls
      };
    });
  }

  function setAllUrlCandidateSelections(selectAll) {
    setUrlCandidateModal((current) => ({
      ...current,
      selectedUrls: selectAll ? current.candidates.map((candidate) => candidate.url) : []
    }));
  }

  async function handleSubmitUrlScan(event) {
    event.preventDefault();

    if (!normalizedUrlTarget) {
      setUrlSubmissionError("Paste a URL or a suspicious message to scan.");
      return;
    }

    setUrlSubmissionError("");

    try {
      if (urlInputLooksLikeDirectLink) {
        await onSubmitUrlScans([normalizedUrlTarget]);
        setUrlTarget("");
        return;
      }

      const resolution = await onResolveUrlScanTargets(normalizedUrlTarget);
      const candidates = Array.isArray(resolution?.candidates) ? resolution.candidates : [];

      if (candidates.length <= 1) {
        const primaryUrl = resolution?.primaryUrl || candidates[0]?.url || normalizedUrlTarget;
        await onSubmitUrlScans([primaryUrl], { extracted: Boolean(resolution?.extracted) });
        setUrlTarget("");
        return;
      }

      setUrlCandidateModal({
        open: true,
        inputMode: resolution?.inputMode || "message",
        primaryUrl: resolution?.primaryUrl || candidates[0]?.url || "",
        candidates,
        selectedUrls: candidates.map((candidate) => candidate.url)
      });
    } catch (error) {
      setUrlSubmissionError(error?.message || "Could not queue URL scan job.");
    }
  }

  async function handleConfirmUrlCandidateScan() {
    if (selectedCandidateCount === 0) {
      setUrlSubmissionError("Select at least one link to scan.");
      return;
    }

    setUrlSubmissionError("");

    try {
      await onSubmitUrlScans(urlCandidateModal.selectedUrls, {
        extracted: urlCandidateModal.inputMode === "message"
      });
      closeUrlCandidateModal();
      setUrlTarget("");
    } catch (error) {
      setUrlSubmissionError(error?.message || "Could not queue URL scan jobs.");
    }
  }

  const columns = [
    {
      key: "file",
      label: "File",
      render: (row) => (
        <div>
          <div className="break-all font-medium text-slate-950 dark:text-white">{row.originalName}</div>
          <div className="mt-1 flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
            <span>{row.id}</span>
            <span className="rounded-full border border-slate-200 px-2 py-0.5 dark:border-slate-700">
              {row.sourceType === "url" ? "URL scan" : row.sourceType === "website" ? "Website safety" : "File scan"}
            </span>
          </div>
        </div>
      )
    },
    {
      key: "status",
      label: "Status",
      render: (row) => (
        <span className="inline-flex rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">
          {row.status}
        </span>
      )
    },
    {
      key: "createdAt",
      label: "Queued",
      render: (row) => formatDateTime(row.createdAt)
    },
    {
      key: "report",
      label: "Report",
      render: (row) =>
        row.reportId ? (
          <button
            type="button"
            className="inline-flex items-center gap-1 text-sm font-medium text-viro-600 transition hover:text-viro-700 dark:text-emerald-300 dark:hover:text-emerald-200"
            onClick={() => onOpenReportWorkspace(row.reportId)}
          >
            Open
            <ArrowRight size={14} />
          </button>
        ) : (
          <span className="text-sm text-slate-400 dark:text-slate-500">{row.status === "failed" ? "Failed" : "Not ready"}</span>
        )
    }
  ];

  return (
    <div className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
      <div className="space-y-6">
        <section className="dashboard-shell-surface p-4 sm:p-6">
          {showHeader ? (
            <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <p className="dashboard-label">Projects</p>
                <h2 className="text-xl font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">Scan intake workspace</h2>
                <p className="mt-2 max-w-xl text-sm leading-7 text-slate-500 dark:text-slate-400">
                  Queue one or more files. Each upload is processed asynchronously and lands in reports when analysis is complete.
                </p>
              </div>
              {showQuotaBadge ? (
                <span className="rounded-full border border-slate-200 px-3 py-2 text-xs font-medium text-slate-500 dark:border-slate-800 dark:text-slate-400">
                  {quotaText}
                </span>
              ) : null}
            </div>
          ) : null}

          <div
            className={`dashboard-grid-overlay rounded-3xl border border-dashed border-viro-200 bg-viro-50/45 p-4 sm:p-6 dark:border-viro-800 dark:bg-viro-900/20 ${
              showHeader ? "mt-6" : ""
            }`.trim()}
          >
            <label className="flex cursor-pointer flex-col gap-3">
              <div className="dashboard-brand-icon inline-flex h-12 w-12 items-center justify-center rounded-2xl border bg-white dark:bg-slate-950">
                <UploadCloud size={20} />
              </div>
              <div>
                <p className="text-base font-semibold text-slate-950 dark:text-white">
                  {selectedFiles.length > 0 ? `${pluralize("file", selectedFiles.length)} selected` : "Drop files or browse"}
                </p>
                <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                  Up to {maxFilesPerBatch} files per batch, {maxUploadMb} MB per file.
                </p>
              </div>
              <input
                ref={fileInputRef}
                type="file"
                multiple
                aria-label="Select scan files"
                className="hidden"
                onChange={(event) => onSelectFiles(event.target.files)}
              />
            </label>
          </div>

          <div className="mt-4 rounded-3xl border border-slate-200/80 bg-white/80 p-4 shadow-[0_18px_48px_-34px_rgba(15,23,42,0.38)] backdrop-blur-sm dark:border-slate-800/80 dark:bg-slate-950/70">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <p className="text-sm font-semibold text-slate-950 dark:text-white">
                    {selectedFiles.length > 0 ? `${pluralize("file", selectedFiles.length)} ready to queue` : "Queue a scan job"}
                  </p>
                  <p className="text-sm text-slate-500 dark:text-slate-400">
                    {selectedFiles.length > 0 ? `${formatBytes(selectedUploadBytes)} total selected` : "Choose one or more files, then queue them for asynchronous analysis."}
                  </p>
                </div>
              </div>
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
                {selectedFiles.length > 0 ? (
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    className="w-full sm:w-auto"
                    onClick={onClearSelectedFiles}
                  >
                    Clear
                  </Button>
                ) : null}
                <Button
                  type="button"
                  variant="primary"
                  size="lg"
                  className="w-full sm:w-auto"
                  onClick={onSubmitScan}
                  disabled={selectedFiles.length === 0 || isSubmittingScan}
                >
                  <FolderOpen size={16} />
                  {isSubmittingScan ? "Queueing..." : selectedFiles.length > 1 ? `Queue ${pluralize("job", selectedFiles.length)}` : "Queue Scan Job"}
                </Button>
              </div>
            </div>
            {selectedFiles.length > 0 ? (
              <motion.div
                className="mt-4 flex flex-wrap gap-2"
                variants={selectedFileListVariants}
                initial="hidden"
                animate="show"
              >
                {selectedFileNames.map((name, index) => (
                  <motion.span
                    key={`${name}-${index}`}
                    variants={selectedFileItemVariants}
                    className="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs text-slate-600 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-300"
                  >
                    {name}
                  </motion.span>
                ))}
              </motion.div>
            ) : null}
          </div>

          <form
            className="mt-5 rounded-3xl border border-slate-200/80 bg-slate-50 p-4 dark:border-slate-800/80 dark:bg-slate-900/50"
            onSubmit={handleSubmitUrlScan}
          >
            <p className="text-sm font-semibold text-slate-950 dark:text-white">Paste suspicious link or full message</p>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
              Paste a direct link, phishing email body, or chat message.
            </p>
            <div className="mt-3 flex flex-col gap-3">
              <label htmlFor="authenticated-url-scan-input" className="sr-only">
                Suspicious link or pasted message
              </label>
              <textarea
                id="authenticated-url-scan-input"
                rows={6}
                spellCheck="false"
                placeholder={`Subject: Unusual sign-in attempt\n\nWe noticed suspicious activity. Review now at hxxps[:]//secure-example[.]com/login\n\nOr paste a direct link like https://example.com/login`}
                value={urlTarget}
                onChange={(event) => setUrlTarget(event.target.value)}
                className={`min-h-[148px] w-full resize-y rounded-2xl border bg-white px-4 py-3 text-sm text-slate-900 outline-none transition-all duration-200 placeholder:text-slate-400 focus:border-viro-500 focus:ring-2 focus:ring-viro-200 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-100 dark:placeholder:text-slate-500 dark:focus:border-viro-400 dark:focus:ring-viro-900 ${
                  urlSubmissionError
                    ? "border-rose-400 focus:border-rose-500 focus:ring-rose-200 dark:border-rose-600 dark:focus:border-rose-500 dark:focus:ring-rose-900/40"
                    : "border-slate-200"
                }`}
                aria-invalid={urlSubmissionError ? "true" : "false"}
              />
              <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
                <p className="text-xs leading-6 text-slate-500 dark:text-slate-400">
                  Only the extracted scan target is saved with the job. The pasted message body is used for extraction and is not kept in report history.
                </p>
                <Button
                  type="submit"
                  variant="primary"
                  size="md"
                  className="w-full sm:w-auto"
                  disabled={isSubmittingScan}
                >
                  {isSubmittingScan ? "Queueing..." : urlInputLooksLikeDirectLink ? "Queue URL Scan" : "Extract & Queue Scan"}
                </Button>
              </div>
            </div>
            {urlSubmissionError ? (
              <p className="mt-3 text-sm text-red-600 dark:text-red-400">{urlSubmissionError}</p>
            ) : null}
          </form>
        </section>

        <section className="space-y-4">
          <div>
            <p className="dashboard-label">Queue activity</p>
            <h2 className="text-xl font-semibold tracking-[-0.03em] text-slate-950 dark:text-white">Current jobs</h2>
          </div>
          <DataTable
            columns={columns}
            rows={paginatedJobs}
            page={jobsPage}
            totalPages={totalJobPages}
            onPageChange={(nextPage) => {
              const boundedPage = Math.min(Math.max(1, nextPage), totalJobPages);
              setJobsPage(boundedPage);
            }}
            emptyMessage="No jobs have been queued yet."
          />
        </section>
      </div>

      <div className="space-y-4">
        <WidgetCard title="Live queue" subtitle="Current workspace health">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
              <p className="dashboard-label">Pending</p>
              <p className="mt-2 text-2xl font-semibold tracking-[-0.04em] text-slate-950 dark:text-white">{pendingJobs}</p>
            </div>
            <div className="rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
              <p className="dashboard-label">Completed</p>
              <p className="mt-2 text-2xl font-semibold tracking-[-0.04em] text-slate-950 dark:text-white">{completedJobs}</p>
            </div>
          </div>
        </WidgetCard>

        <WidgetCard title="Focused job" subtitle="Current attention target">
          {activeJob ? (
            <div className="rounded-2xl border border-slate-200/80 px-4 py-4 dark:border-slate-800/80">
              <p className="text-sm font-semibold text-slate-950 dark:text-white">{activeJob.originalName}</p>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                {activeJob.sourceType === "url" ? "URL scan job" : activeJob.sourceType === "website" ? "Website safety job" : "File scan job"}
              </p>
              <p className="mt-2 inline-flex rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600 dark:bg-slate-900 dark:text-slate-300">
                {activeJob.status}
              </p>
              <p className="mt-3 text-sm text-slate-500 dark:text-slate-400">{formatDateTime(activeJob.createdAt)}</p>
            </div>
          ) : (
            <p className="text-sm leading-7 text-slate-500 dark:text-slate-400">No active jobs yet. New submissions will appear here.</p>
          )}
        </WidgetCard>
      </div>

      <Modal
        open={urlCandidateModal.open}
        onClose={() => {
          if (!isSubmittingScan) {
            closeUrlCandidateModal();
          }
        }}
        ariaLabel="Choose suspicious links to scan"
        maxWidthClassName="max-w-5xl"
      >
        <div className="flex items-start justify-between gap-4 border-b border-slate-200 px-5 py-5 dark:border-slate-800">
          <div>
            <p className="dashboard-label">Link review</p>
            <h3 className="mt-1 text-lg font-semibold text-slate-950 dark:text-white">Multiple links found</h3>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500 dark:text-slate-400">
              We ranked the extracted links from strongest to weakest candidate. All links are selected by default so you can scan the whole message at once or trim the set first.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs font-medium text-slate-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300">
              {selectedCandidateCount}/{urlCandidateModal.candidates.length} selected
            </span>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              className="h-9 w-9 rounded-xl p-0"
              aria-label="Close link selection dialog"
              onClick={closeUrlCandidateModal}
              disabled={isSubmittingScan}
            >
              <X size={16} />
            </Button>
          </div>
        </div>

        <div className="grid gap-5 overflow-y-auto p-5 lg:grid-cols-[1.8fr_0.95fr]">
          <div className="space-y-3">
            {urlCandidateModal.candidates.map((candidate) => {
              const selected = urlCandidateModal.selectedUrls.includes(candidate.url);

              return (
                <label
                  key={candidate.url}
                  className={cn(
                    "group flex cursor-pointer items-start gap-4 rounded-3xl border px-4 py-4 transition-colors",
                    selected
                      ? "border-viro-300 bg-viro-50/70 shadow-[0_20px_50px_-38px_rgba(5,150,105,0.55)] dark:border-viro-700 dark:bg-viro-900/25"
                      : "border-slate-200 bg-white hover:border-slate-300 dark:border-slate-800 dark:bg-slate-950 dark:hover:border-slate-700"
                  )}
                >
                  <input
                    type="checkbox"
                    className="sr-only"
                    checked={selected}
                    onChange={() => toggleUrlCandidateSelection(candidate.url)}
                  />
                  <span
                    className={cn(
                      "mt-1 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-md border transition-colors",
                      selected
                        ? "border-viro-600 bg-viro-600 text-white dark:border-viro-500 dark:bg-viro-500"
                        : "border-slate-300 bg-white text-transparent dark:border-slate-700 dark:bg-slate-950"
                    )}
                    aria-hidden="true"
                  >
                    <Check size={13} />
                  </span>

                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded-full bg-slate-950 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.12em] text-white dark:bg-white dark:text-slate-950">
                        {candidate.rank === 1 ? "Best match" : `Candidate ${candidate.rank}`}
                      </span>
                      <span className="rounded-full border border-slate-200 px-2.5 py-1 text-[11px] font-medium text-slate-500 dark:border-slate-700 dark:text-slate-400">
                        {getUrlCandidateSourceLabel(candidate.source)}
                      </span>
                    </div>

                    <div className="mt-3 flex items-start gap-3">
                      <span className="mt-0.5 inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-2xl border border-slate-200 bg-white text-slate-600 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300">
                        <Link2 size={16} />
                      </span>
                      <div className="min-w-0">
                        <p className="truncate text-sm font-semibold text-slate-950 dark:text-white">{candidate.hostname}</p>
                        <p className="mt-1 break-all text-sm leading-6 text-slate-500 dark:text-slate-400">{candidate.url}</p>
                      </div>
                    </div>
                  </div>
                </label>
              );
            })}
          </div>

          <aside className="rounded-3xl border border-slate-200 bg-slate-50/90 p-4 dark:border-slate-800 dark:bg-slate-900/60">
            <div className="rounded-2xl border border-slate-200/80 bg-white/90 p-4 dark:border-slate-800/80 dark:bg-slate-950/80">
              <div className="flex items-center gap-3">
                <span className="inline-flex h-10 w-10 items-center justify-center rounded-2xl border border-viro-200 bg-viro-50 text-viro-700 dark:border-viro-800 dark:bg-viro-900/30 dark:text-emerald-200">
                  <ShieldAlert size={18} />
                </span>
                <div>
                  <p className="text-sm font-semibold text-slate-950 dark:text-white">Selection summary</p>
                  <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">Queue only the links you want reviewed.</p>
                </div>
              </div>

              <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-1">
                <div className="rounded-2xl border border-slate-200 px-3 py-3 dark:border-slate-800">
                  <p className="dashboard-label">Detected</p>
                  <p className="mt-2 text-2xl font-semibold tracking-[-0.04em] text-slate-950 dark:text-white">
                    {urlCandidateModal.candidates.length}
                  </p>
                </div>
                <div className="rounded-2xl border border-slate-200 px-3 py-3 dark:border-slate-800">
                  <p className="dashboard-label">Queued next</p>
                  <p className="mt-2 text-2xl font-semibold tracking-[-0.04em] text-slate-950 dark:text-white">
                    {selectedCandidateCount}
                  </p>
                </div>
              </div>

              <div className="mt-4 flex flex-wrap gap-2">
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  onClick={() => setAllUrlCandidateSelections(true)}
                  disabled={allCandidatesSelected || isSubmittingScan}
                >
                  <Check size={14} />
                  Select all
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={() => setAllUrlCandidateSelections(false)}
                  disabled={selectedCandidateCount === 0 || isSubmittingScan}
                >
                  <ListFilter size={14} />
                  Clear selection
                </Button>
              </div>

              <p className="mt-4 text-xs leading-6 text-slate-500 dark:text-slate-400">
                Links stay ranked best-to-worst. The first row is the strongest candidate based on phishing-style path terms, inline placement, and link structure.
              </p>
            </div>
          </aside>
        </div>

        <div className="flex flex-col gap-3 border-t border-slate-200 px-5 py-4 dark:border-slate-800 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              {selectedCandidateCount === 0
                ? "Select at least one link to continue."
                : allCandidatesSelected
                  ? "All detected links will be queued for scanning."
                  : `${selectedCandidateCount} selected link${selectedCandidateCount === 1 ? "" : "s"} will be queued.`}
            </p>
            {urlSubmissionError ? (
              <p className="mt-2 text-sm text-red-600 dark:text-red-400">{urlSubmissionError}</p>
            ) : null}
          </div>
          <div className="flex flex-col gap-3 sm:flex-row">
            <Button type="button" variant="secondary" onClick={closeUrlCandidateModal} disabled={isSubmittingScan}>
              Cancel
            </Button>
            <Button type="button" variant="primary" onClick={handleConfirmUrlCandidateScan} disabled={selectedCandidateCount === 0 || isSubmittingScan}>
              {isSubmittingScan ? "Queueing..." : allCandidatesSelected ? "Scan All" : "Scan"}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
