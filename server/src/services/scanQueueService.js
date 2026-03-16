import crypto from "crypto";
import fs from "fs/promises";
import path from "path";
import { Queue, Worker } from "bullmq";
import { createRedisClient } from "../infrastructure/redis/createRedisClient.js";
import { HttpError } from "../utils/httpError.js";
import { signReport, verifySignedReport } from "../utils/reportIntegrity.js";
import { enrichReportThreatIntel } from "../utils/threatIntel.js";
import { linkReportSchema } from "../validation/scanSchemas.js";

const VERDICT_RANK = {
  clean: 1,
  suspicious: 2,
  malicious: 3
};

function worstVerdictForReports(reports) {
  if (!Array.isArray(reports) || reports.length === 0) {
    return "clean";
  }

  let worst = "clean";

  for (const report of reports) {
    const verdict = report?.verdict || "clean";
    if ((VERDICT_RANK[verdict] || 1) > (VERDICT_RANK[worst] || 1)) {
      worst = verdict;
    }
  }

  return worst;
}

function buildReportIntel(report, historicalReports) {
  const sha256 = report?.file?.hashes?.sha256 || null;
  if (!sha256) {
    return {
      sha256: null,
      hashSeenBefore: false,
      previousMatches: 0,
      totalOccurrences: 1,
      firstSeenAt: null,
      lastSeenAt: null,
      knownWorstVerdict: "clean"
    };
  }

  const previousMatches = historicalReports.filter((item) => item?.file?.hashes?.sha256 === sha256);
  const observedTimes = previousMatches
    .map((item) => Date.parse(item.completedAt || item.createdAt || ""))
    .filter((value) => Number.isFinite(value))
    .sort((left, right) => left - right);

  return {
    sha256,
    hashSeenBefore: previousMatches.length > 0,
    previousMatches: previousMatches.length,
    totalOccurrences: previousMatches.length + 1,
    firstSeenAt: Number.isFinite(observedTimes[0]) ? new Date(observedTimes[0]).toISOString() : null,
    lastSeenAt: observedTimes.length > 0 ? new Date(observedTimes[observedTimes.length - 1]).toISOString() : null,
    knownWorstVerdict: worstVerdictForReports(previousMatches)
  };
}

function toJobSummary(job) {
  const sourceType = job.sourceType === "url" ? "url" : "file";

  return {
    id: job.id,
    sourceType,
    status: job.status,
    createdAt: job.createdAt,
    startedAt: job.startedAt || null,
    completedAt: job.completedAt || null,
    originalName: job.originalName,
    fileSize: job.fileSize,
    targetUrl: sourceType === "url" ? job.targetUrl || null : null,
    reportId: job.reportId || null,
    errorMessage: job.errorMessage || null
  };
}

function toReportSummary(report) {
  const sourceType = report?.sourceType === "url" ? "url" : "file";
  const fileName = report?.file?.originalName || report?.url?.final || report?.url?.input || "Unknown target";
  const fileSize = Number(report?.file?.size) || 0;

  return {
    id: report.id,
    sourceType,
    createdAt: report.createdAt,
    completedAt: report.completedAt,
    verdict: report.verdict,
    riskScore: report.riskScore,
    fileName,
    fileSize,
    findingCount: Array.isArray(report?.findings) ? report.findings.length : 0,
    topFinding: report?.findings?.[0]?.title || "No notable findings",
    intel: report.intel || null,
    iocCount: Number(report?.iocs?.total) || 0
  };
}

function isReportVisible(report) {
  return !report?.deletedAt;
}

function describeQueueItem(item) {
  if (item?.sourceType === "url") {
    return item?.targetUrl || item?.originalName || "URL target";
  }

  return item?.originalName || "uploaded file";
}

const ANALYTICS_WINDOW_DAYS = 30;
const ANALYTICS_MONTH_BUCKETS = 6;

function parseTimestamp(value) {
  const timestamp = Date.parse(value || "");
  return Number.isFinite(timestamp) ? timestamp : null;
}

function createAnalyticsMonthBuckets(count = ANALYTICS_MONTH_BUCKETS) {
  const now = new Date();
  const buckets = [];

  for (let index = count - 1; index >= 0; index -= 1) {
    buckets.push(new Date(now.getFullYear(), now.getMonth() - index, 1));
  }

  return buckets;
}

function getMonthBucketKey(date) {
  return `${date.getFullYear()}-${date.getMonth()}`;
}

function average(values) {
  if (!Array.isArray(values) || values.length === 0) {
    return 0;
  }

  return values.reduce((sum, value) => sum + (Number(value) || 0), 0) / values.length;
}

function summarizeReports(reports) {
  const cleanReports = reports.filter((report) => report?.verdict === "clean").length;
  const suspiciousReports = reports.filter((report) => report?.verdict === "suspicious").length;
  const maliciousReports = reports.filter((report) => report?.verdict === "malicious").length;
  const flaggedReports = suspiciousReports + maliciousReports;
  const averageRiskScore = average(reports.map((report) => report?.riskScore));

  return {
    totalReports: reports.length,
    cleanReports,
    suspiciousReports,
    maliciousReports,
    flaggedReports,
    cleanRate: reports.length > 0 ? (cleanReports / reports.length) * 100 : 0,
    averageRiskScore,
    highestRiskScore: reports.reduce((highest, report) => Math.max(highest, Number(report?.riskScore) || 0), 0)
  };
}

function summarizeJobs(jobs) {
  return {
    totalJobs: jobs.length,
    activeJobs: jobs.filter((job) => job?.status === "queued" || job?.status === "processing").length,
    queuedJobs: jobs.filter((job) => job?.status === "queued").length,
    processingJobs: jobs.filter((job) => job?.status === "processing").length,
    completedJobs: jobs.filter((job) => job?.status === "completed").length,
    failedJobs: jobs.filter((job) => job?.status === "failed").length
  };
}

function buildWindowSummary({ reports, jobs }) {
  const now = Date.now();
  const windowMs = ANALYTICS_WINDOW_DAYS * 24 * 60 * 60 * 1000;
  const currentWindowStart = now - windowMs;
  const previousWindowStart = currentWindowStart - windowMs;

  const inCurrentWindow = (timestamp) => timestamp != null && timestamp >= currentWindowStart && timestamp <= now;
  const inPreviousWindow = (timestamp) => timestamp != null && timestamp >= previousWindowStart && timestamp < currentWindowStart;

  const currentReports = reports.filter((report) => inCurrentWindow(parseTimestamp(report?.completedAt || report?.createdAt)));
  const previousReports = reports.filter((report) => inPreviousWindow(parseTimestamp(report?.completedAt || report?.createdAt)));
  const currentJobs = jobs.filter((job) => inCurrentWindow(parseTimestamp(job?.createdAt || job?.completedAt)));
  const previousJobs = jobs.filter((job) => inPreviousWindow(parseTimestamp(job?.createdAt || job?.completedAt)));

  const buildSnapshot = (windowReports, windowJobs) => {
    const reportSummary = summarizeReports(windowReports);
    const jobSummary = summarizeJobs(windowJobs);

    return {
      reports: reportSummary.totalReports,
      flaggedReports: reportSummary.flaggedReports,
      cleanRate: reportSummary.cleanRate,
      averageRiskScore: reportSummary.averageRiskScore,
      failedJobs: jobSummary.failedJobs
    };
  };

  return {
    days: ANALYTICS_WINDOW_DAYS,
    current: buildSnapshot(currentReports, currentJobs),
    previous: buildSnapshot(previousReports, previousJobs)
  };
}

function resolveFileTypeLabel(report) {
  const detected = String(report?.file?.detectedFileType || "").trim();
  if (detected && detected.toLowerCase() !== "unknown") {
    return detected.toUpperCase();
  }

  const extension = String(report?.file?.extension || path.extname(report?.file?.originalName || ""))
    .replace(/^\./, "")
    .trim();

  return extension ? extension.toUpperCase() : "Unknown";
}

function toAnalyticsReportSummary(report) {
  if (!report) {
    return null;
  }

  return {
    id: report.id,
    fileName: report?.file?.originalName || report?.fileName || "Unknown file",
    verdict: report?.verdict || "clean",
    riskScore: Number(report?.riskScore) || 0,
    completedAt: report?.completedAt || report?.createdAt || null
  };
}

function buildAnalyticsSnapshot({ jobs, reports }) {
  const reportSummary = summarizeReports(reports);
  const jobSummary = summarizeJobs(jobs);
  const windows = buildWindowSummary({ reports, jobs });
  const monthBuckets = createAnalyticsMonthBuckets();
  const monthMap = new Map(
    monthBuckets.map((date) => [
      getMonthBucketKey(date),
      {
        month: new Intl.DateTimeFormat("en-US", { month: "short" }).format(date),
        reports: 0,
        flagged: 0,
        jobs: 0
      }
    ])
  );

  for (const report of reports) {
    const timestamp = parseTimestamp(report?.completedAt || report?.createdAt);
    if (timestamp == null) {
      continue;
    }

    const key = getMonthBucketKey(new Date(new Date(timestamp).getFullYear(), new Date(timestamp).getMonth(), 1));
    const bucket = monthMap.get(key);
    if (!bucket) {
      continue;
    }

    bucket.reports += 1;
    if (report?.verdict === "suspicious" || report?.verdict === "malicious") {
      bucket.flagged += 1;
    }
  }

  for (const job of jobs) {
    const timestamp = parseTimestamp(job?.createdAt || job?.completedAt);
    if (timestamp == null) {
      continue;
    }

    const key = getMonthBucketKey(new Date(new Date(timestamp).getFullYear(), new Date(timestamp).getMonth(), 1));
    const bucket = monthMap.get(key);
    if (!bucket) {
      continue;
    }

    bucket.jobs += 1;
  }

  const fileTypeCounts = reports.reduce((accumulator, report) => {
    const label = resolveFileTypeLabel(report);
    accumulator.set(label, (accumulator.get(label) || 0) + 1);
    return accumulator;
  }, new Map());

  const latestReport = reports
    .slice()
    .sort(
      (left, right) =>
        (parseTimestamp(right?.completedAt || right?.createdAt) || 0) - (parseTimestamp(left?.completedAt || left?.createdAt) || 0)
    )[0];

  const highestRiskReport = reports
    .slice()
    .sort((left, right) => {
      const riskDelta = (Number(right?.riskScore) || 0) - (Number(left?.riskScore) || 0);
      if (riskDelta !== 0) {
        return riskDelta;
      }

      return (parseTimestamp(right?.completedAt || right?.createdAt) || 0) - (parseTimestamp(left?.completedAt || left?.createdAt) || 0);
    })[0];

  return {
    generatedAt: new Date().toISOString(),
    comparisonWindowDays: windows.days,
    summary: {
      ...jobSummary,
      ...reportSummary
    },
    windows,
    timeSeries: Array.from(monthMap.values()),
    postureBreakdown: [
      { label: "Clean", value: reportSummary.cleanReports },
      { label: "Suspicious", value: reportSummary.suspiciousReports },
      { label: "Malicious", value: reportSummary.maliciousReports }
    ],
    queueBreakdown: [
      { label: "Queued", value: jobSummary.queuedJobs },
      { label: "Processing", value: jobSummary.processingJobs },
      { label: "Completed", value: jobSummary.completedJobs },
      { label: "Failed", value: jobSummary.failedJobs }
    ],
    riskDistribution: [
      {
        label: "0-24",
        value: reports.filter((report) => (Number(report?.riskScore) || 0) <= 24).length
      },
      {
        label: "25-49",
        value: reports.filter((report) => {
          const riskScore = Number(report?.riskScore) || 0;
          return riskScore >= 25 && riskScore <= 49;
        }).length
      },
      {
        label: "50-74",
        value: reports.filter((report) => {
          const riskScore = Number(report?.riskScore) || 0;
          return riskScore >= 50 && riskScore <= 74;
        }).length
      },
      {
        label: "75-100",
        value: reports.filter((report) => (Number(report?.riskScore) || 0) >= 75).length
      }
    ],
    fileTypeBreakdown: Array.from(fileTypeCounts.entries())
      .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
      .slice(0, 5)
      .map(([label, value]) => ({ label, value })),
    latestReport: toAnalyticsReportSummary(latestReport),
    highestRiskReport: toAnalyticsReportSummary(highestRiskReport)
  };
}

export class ScanQueueService {
  constructor({ store, scanner, urlScanner, logger, config, objectStorageService = null, notificationService = null }) {
    this.store = store;
    this.scanner = scanner;
    this.urlScanner = urlScanner;
    this.logger = logger;
    this.config = config;
    this.objectStorageService = objectStorageService;
    this.notificationService = notificationService;
    this.queue = [];
    this.processing = 0;
    this.started = false;
    this.bullFileQueue = null;
    this.bullLinkQueue = null;
    this.bullFileWorker = null;
    this.bullLinkWorker = null;
    this.bullQueueRedis = null;
    this.bullWorkerRedis = null;
  }

  async start() {
    if (this.started) {
      return;
    }

    this.started = true;

    if (this.config.queueProvider === "bullmq") {
      await this.#startBullQueue();
      return;
    }

    if (!this.config.runScanWorker) {
      throw new Error("RUN_SCAN_WORKER must be true when QUEUE_PROVIDER=local.");
    }

    await this.store.write((state) => {
      const now = new Date().toISOString();

      for (const job of state.jobs) {
        if (job.status === "queued" || job.status === "processing") {
          job.status = "failed";
          job.completedAt = now;
          job.updatedAt = now;
          job.errorMessage = "Scan interrupted by service restart.";
        }
      }
    });

    this.#drainQueue();
  }

  async stop() {
    if (this.bullFileWorker) {
      await this.bullFileWorker.close();
      this.bullFileWorker = null;
    }

    if (this.bullLinkWorker) {
      await this.bullLinkWorker.close();
      this.bullLinkWorker = null;
    }

    if (this.bullFileQueue) {
      await this.bullFileQueue.close();
      this.bullFileQueue = null;
    }

    if (this.bullLinkQueue) {
      await this.bullLinkQueue.close();
      this.bullLinkQueue = null;
    }

    if (this.bullWorkerRedis) {
      await this.bullWorkerRedis.quit().catch(() => {});
      this.bullWorkerRedis = null;
    }

    if (this.bullQueueRedis) {
      await this.bullQueueRedis.quit().catch(() => {});
      this.bullQueueRedis = null;
    }
  }

  async #createQueuedJob({ userId, sourceType, originalName, mimeType, fileSize, targetUrl = null }) {
    const now = new Date().toISOString();

    return this.store.write((state) => {
      const user = state.users.find((candidate) => candidate.id === userId);
      if (!user) {
        throw new HttpError(404, "User not found.", { code: "SCAN_USER_NOT_FOUND" });
      }

      const nextJob = {
        id: `job_${crypto.randomUUID()}`,
        userId,
        sourceType,
        targetUrl: sourceType === "url" ? targetUrl : null,
        status: "queued",
        originalName,
        mimeType,
        fileSize,
        createdAt: now,
        updatedAt: now,
        startedAt: null,
        completedAt: null,
        reportId: null,
        errorMessage: null
      };

      state.jobs.unshift(nextJob);

      state.auditEvents.unshift({
        id: `audit_${crypto.randomUUID()}`,
        userId,
        action: "scan.job.queued",
        ipAddress: null,
        userAgent: "",
        metadata: {
          jobId: nextJob.id,
          sourceType: nextJob.sourceType,
          fileSize: nextJob.fileSize,
          originalName: nextJob.originalName,
          targetUrl: nextJob.targetUrl
        },
        createdAt: now
      });

      return nextJob;
    });
  }

  async #markEnqueueFailed(jobId, reason = "Could not enqueue scan job.") {
    const failedAt = new Date().toISOString();

    await this.store.write((state) => {
      const editableJob = state.jobs.find((candidate) => candidate.id === jobId);
      if (!editableJob) {
        return;
      }

      editableJob.status = "failed";
      editableJob.completedAt = failedAt;
      editableJob.updatedAt = failedAt;
      editableJob.errorMessage = reason;
    });
  }

  async enqueueScan({ userId, filePath, originalName, mimeType, fileSize }) {
    const job = await this.#createQueuedJob({
      userId,
      sourceType: "file",
      originalName,
      mimeType,
      fileSize,
      targetUrl: null
    });

    const queueItem = {
      jobId: job.id,
      userId,
      sourceType: "file",
      targetUrl: null,
      filePath: null,
      originalName,
      mimeType,
      fileSize,
      stagedUpload: null
    };

    try {
      if (this.config.queueProvider === "bullmq") {
        if (!this.objectStorageService?.enabled) {
          throw new Error("Object storage must be enabled when QUEUE_PROVIDER=bullmq.");
        }

        queueItem.stagedUpload = await this.objectStorageService.uploadFileFromPath({
          localPath: filePath,
          key: this.objectStorageService.buildQueueUploadKey({
            userId,
            jobId: job.id,
            originalName
          }),
          contentType: mimeType || "application/octet-stream",
          metadata: {
            service: this.config.serviceName,
            user_id: userId,
            job_id: job.id,
            purpose: "queue-ingress"
          }
        });

        await this.#enqueueBullItem(queueItem);
      } else {
        queueItem.filePath = filePath;
        this.queue.push(queueItem);
        this.#drainQueue();
      }
    } catch (error) {
      if (queueItem.stagedUpload?.key && this.objectStorageService?.enabled) {
        await this.objectStorageService
          .deleteObject({
            key: queueItem.stagedUpload.key
          })
          .catch(() => {});
      }
      await this.#markEnqueueFailed(job.id);

      throw new HttpError(503, "Could not enqueue scan job.", {
        code: "SCAN_QUEUE_UNAVAILABLE",
        details: {
          reason: error?.message || "Queue provider unavailable."
        }
      });
    } finally {
      if (this.config.queueProvider === "bullmq") {
        await fs.unlink(filePath).catch(() => {});
      }
    }

    return toJobSummary(job);
  }

  async enqueueUrlScan({ userId, url }) {
    if (typeof this.urlScanner !== "function") {
      throw new HttpError(503, "URL scanner is unavailable.", {
        code: "URL_SCANNER_UNAVAILABLE"
      });
    }

    const targetUrl = String(url || "").trim();
    const job = await this.#createQueuedJob({
      userId,
      sourceType: "url",
      originalName: targetUrl,
      mimeType: "text/url",
      fileSize: 0,
      targetUrl
    });

    const queueItem = {
      jobId: job.id,
      userId,
      sourceType: "url",
      targetUrl,
      filePath: null,
      originalName: targetUrl,
      mimeType: "text/url",
      fileSize: 0,
      stagedUpload: null
    };

    try {
      if (this.config.queueProvider === "bullmq") {
        await this.#enqueueBullItem(queueItem);
      } else {
        this.queue.push(queueItem);
        this.#drainQueue();
      }
    } catch (error) {
      await this.#markEnqueueFailed(job.id);

      throw new HttpError(503, "Could not enqueue URL scan job.", {
        code: "SCAN_QUEUE_UNAVAILABLE",
        details: {
          reason: error?.message || "Queue provider unavailable."
        }
      });
    }

    return toJobSummary(job);
  }

  async getJobForUser(jobId, user) {
    const job = await this.store.read((state) => state.jobs.find((candidate) => candidate.id === jobId) || null);

    if (!job) {
      throw new HttpError(404, "Scan job not found.", { code: "SCAN_JOB_NOT_FOUND" });
    }

    if (user.role !== "admin" && job.userId !== user.id) {
      throw new HttpError(403, "Forbidden.", { code: "SCAN_FORBIDDEN" });
    }

    return toJobSummary(job);
  }

  async listJobsForUser(user, limit = 20) {
    return this.store.read((state) => {
      const safeLimit = Math.max(1, Math.min(100, Number(limit) || 20));

      return state.jobs
        .filter((job) => user.role === "admin" || job.userId === user.id)
        .slice(0, safeLimit)
        .map(toJobSummary);
    });
  }

  async getReportForUser(reportId, user) {
    const report = await this.store.read((state) => state.reports.find((candidate) => candidate.id === reportId) || null);

    if (!report || !isReportVisible(report)) {
      throw new HttpError(404, "Scan report not found.", { code: "SCAN_REPORT_NOT_FOUND" });
    }

    if (user.role !== "admin" && report.ownerUserId !== user.id) {
      throw new HttpError(403, "Forbidden.", { code: "SCAN_FORBIDDEN" });
    }

    return report;
  }

  async listReportsForUser(user, limit = 20) {
    return this.store.read((state) => {
      const safeLimit = Math.max(1, Math.min(100, Number(limit) || 20));

      return state.reports
        .filter((report) => isReportVisible(report) && (user.role === "admin" || report.ownerUserId === user.id))
        .slice(0, safeLimit)
        .map(toReportSummary);
    });
  }

  async getAnalyticsForUser(user) {
    return this.store.read((state) => {
      const jobs = state.jobs.filter((job) => user.role === "admin" || job.userId === user.id);
      const reports = state.reports.filter(
        (report) => isReportVisible(report) && (user.role === "admin" || report.ownerUserId === user.id)
      );
      return buildAnalyticsSnapshot({ jobs, reports });
    });
  }

  async getReportById(reportId, { includeDeleted = false } = {}) {
    return this.store.read((state) => {
      const report = state.reports.find((candidate) => candidate.id === reportId) || null;
      if (!report) {
        return null;
      }

      if (!includeDeleted && !isReportVisible(report)) {
        return null;
      }

      return report;
    });
  }

  async deleteReportForUser(reportId, user) {
    const deletedAt = new Date().toISOString();

    const result = await this.store.write((state) => {
      const report = state.reports.find((candidate) => candidate.id === reportId);
      if (!report) {
        throw new HttpError(404, "Scan report not found.", { code: "SCAN_REPORT_NOT_FOUND" });
      }

      if (user.role !== "admin" && report.ownerUserId !== user.id) {
        throw new HttpError(403, "Forbidden.", { code: "SCAN_FORBIDDEN" });
      }

      if (report.deletedAt) {
        const expiresAt = Date.parse(report.completedAt || report.createdAt || "");
        const retentionMs = Number(this.config.reportTtlMs) || 0;

        return {
          id: report.id,
          deletedAt: report.deletedAt,
          retentionExpiresAt:
            Number.isFinite(expiresAt) && retentionMs > 0 ? new Date(expiresAt + retentionMs).toISOString() : null,
          alreadyDeleted: true
        };
      }

      report.deletedAt = deletedAt;
      report.deletedByUserId = user.id;

      const expiresAt = Date.parse(report.completedAt || report.createdAt || "");
      const retentionMs = Number(this.config.reportTtlMs) || 0;

      state.auditEvents.unshift({
        id: `audit_${crypto.randomUUID()}`,
        userId: user.id,
        action: "scan.report.deleted",
        ipAddress: null,
        userAgent: "",
        metadata: {
          reportId: report.id,
          ownerUserId: report.ownerUserId,
          sourceType: report.sourceType || "file"
        },
        createdAt: deletedAt
      });

      return {
        id: report.id,
        deletedAt,
        retentionExpiresAt: Number.isFinite(expiresAt) && retentionMs > 0 ? new Date(expiresAt + retentionMs).toISOString() : null,
        alreadyDeleted: false
      };
    });

    await this.notificationService?.create({
      userId: user.id,
      type: "report_deleted",
      tone: "warning",
      title: "Report hidden",
      detail: "The report has been removed from workspace history and will age out at retention expiry.",
      entityType: "report",
      entityId: reportId,
      dedupeKey: `report-deleted:${reportId}`
    });

    return result;
  }

  verifyReportIntegrity(report) {
    return verifySignedReport(report, {
      secret: this.config.reportIntegritySecret
    });
  }

  async #startBullQueue() {
    if (!this.config.redisUrl) {
      throw new Error("REDIS_URL is required when QUEUE_PROVIDER=bullmq.");
    }

    this.bullQueueRedis = createRedisClient(this.config, {
      purpose: "queue",
      maxRetriesPerRequest: 3
    });

    this.bullFileQueue = new Queue(this.config.fileQueueName || this.config.queueName, {
      connection: this.bullQueueRedis
    });

    this.bullLinkQueue = new Queue(this.config.linkQueueName || `${this.config.queueName}-link`, {
      connection: this.bullQueueRedis
    });

    if (!this.config.runScanWorker) {
      this.logger.info(
        { fileQueueName: this.config.fileQueueName, linkQueueName: this.config.linkQueueName },
        "Scan queues initialized in API-only mode."
      );
      return;
    }

    await this.store.write((state) => {
      const now = new Date().toISOString();

      for (const job of state.jobs) {
        if (job.status === "processing") {
          job.status = "queued";
          job.updatedAt = now;
          job.startedAt = null;
          job.errorMessage = null;
        }
      }
    });

    this.bullWorkerRedis = createRedisClient(this.config, {
      purpose: "queue-worker",
      maxRetriesPerRequest: null
    });

    const runFileWorker = this.config.scanWorkerMode === "all" || this.config.scanWorkerMode === "file";
    const runLinkWorker = this.config.scanWorkerMode === "all" || this.config.scanWorkerMode === "link";

    if (!runFileWorker && !runLinkWorker) {
      throw new Error("SCAN_WORKER_MODE must be one of all, file, or link.");
    }

    if (runFileWorker) {
      this.bullFileWorker = new Worker(
        this.config.fileQueueName || this.config.queueName,
        async (job) => {
          await this.#processQueueItem(job.data);
        },
        {
          connection: this.bullWorkerRedis,
          concurrency: this.config.scanWorkerConcurrency
        }
      );

      this.bullFileWorker.on("failed", (job, error) => {
        this.logger.error({ err: error, bullJobId: job?.id, queue: "file" }, "BullMQ file worker job failed");
      });
      this.bullFileWorker.on("error", (error) => {
        this.logger.error({ err: error, queue: "file" }, "BullMQ file worker error");
      });
    }

    if (runLinkWorker) {
      this.bullLinkWorker = new Worker(
        this.config.linkQueueName || `${this.config.queueName}-link`,
        async (job) => {
          await this.#processQueueItem(job.data);
        },
        {
          connection: this.bullWorkerRedis,
          concurrency: this.config.scanWorkerConcurrency
        }
      );

      this.bullLinkWorker.on("failed", (job, error) => {
        this.logger.error({ err: error, bullJobId: job?.id, queue: "link" }, "BullMQ link worker job failed");
      });
      this.bullLinkWorker.on("error", (error) => {
        this.logger.error({ err: error, queue: "link" }, "BullMQ link worker error");
      });
    }

    this.logger.info(
      {
        fileQueueName: this.config.fileQueueName || this.config.queueName,
        linkQueueName: this.config.linkQueueName || `${this.config.queueName}-link`,
        concurrency: this.config.scanWorkerConcurrency,
        scanWorkerMode: this.config.scanWorkerMode
      },
      "BullMQ workers started."
    );
  }

  async #enqueueBullItem(item) {
    const sourceType = item?.sourceType === "url" ? "url" : "file";
    const queue = sourceType === "url" ? this.bullLinkQueue : this.bullFileQueue;
    if (!queue) {
      throw new Error(`BullMQ ${sourceType} queue is not initialized.`);
    }

    const jobName = sourceType === "url" ? "link_scan" : "file_scan";

    await queue.add(jobName, item, {
      jobId: item.jobId,
      attempts: this.config.queueAttempts,
      backoff: {
        type: "exponential",
        delay: this.config.queueBackoffMs
      },
      removeOnComplete: 500,
      removeOnFail: 1000
    });
  }

  #drainQueue() {
    while (this.processing < this.config.scanWorkerConcurrency && this.queue.length > 0) {
      const item = this.queue.shift();
      if (!item) {
        return;
      }

      this.processing += 1;

      this.#processQueueItem(item)
        .catch((error) => {
          this.logger.error({ error, jobId: item.jobId }, "Scan queue item failed unexpectedly");
        })
        .finally(() => {
          this.processing = Math.max(0, this.processing - 1);
          this.#drainQueue();
        });
    }
  }

  async #persistArtifacts(item, report, scanFilePath) {
    if (!this.objectStorageService?.enabled) {
      return null;
    }

    let uploadArtifact = null;
    if (item.sourceType !== "url") {
      if (!scanFilePath && !item.stagedUpload) {
        throw new Error("File scan artifacts are unavailable.");
      }

      uploadArtifact =
        item.stagedUpload ||
        (await this.objectStorageService.uploadFileFromPath({
          localPath: scanFilePath,
          key: this.objectStorageService.buildUploadKey({
            userId: item.userId,
            jobId: item.jobId,
            originalName: item.originalName
          }),
          contentType: item.mimeType || "application/octet-stream",
          metadata: {
            service: this.config.serviceName,
            user_id: item.userId,
            job_id: item.jobId
          }
        }));
    }

    const reportArtifact = await this.objectStorageService.uploadJson({
      key: this.objectStorageService.buildReportKey({
        userId: item.userId,
        reportId: report.id
      }),
      payload: report,
      metadata: {
        service: this.config.serviceName,
        user_id: item.userId,
        report_id: report.id
      }
    });

    return {
      upload: uploadArtifact,
      report: reportArtifact
    };
  }

  async #processQueueItem(item) {
    const startedAt = new Date().toISOString();

    await this.store.write((state) => {
      const job = state.jobs.find((candidate) => candidate.id === item.jobId);
      if (!job) {
        return;
      }

      job.status = "processing";
      job.startedAt = startedAt;
      job.updatedAt = startedAt;
    });

    const sourceType = item?.sourceType === "url" ? "url" : "file";
    let scanFilePath = sourceType === "file" ? item.filePath : null;
    let shouldDeleteScanFile = Boolean(scanFilePath);

    try {
      let report = null;

      if (sourceType === "url") {
        if (typeof this.urlScanner !== "function") {
          throw new Error("URL scanner is unavailable.");
        }

        const targetUrl = String(item.targetUrl || item.originalName || "").trim();
        if (!targetUrl) {
          throw new Error("URL scan target is missing.");
        }

        report = await this.urlScanner({
          url: targetUrl
        });

        const validatedLinkReport = linkReportSchema.safeParse(report);
        if (!validatedLinkReport.success) {
          throw new Error("URL report schema validation failed.");
        }

        report = validatedLinkReport.data;
      } else {
        if (!scanFilePath) {
          const stagedKey = item.stagedUpload?.key;

          if (!stagedKey || !this.objectStorageService?.enabled) {
            throw new Error("Scan source file is unavailable for worker processing.");
          }

          const extension = path.extname(item.originalName || "").slice(0, 16);
          scanFilePath = path.join(this.config.uploadDir, `worker-${item.jobId}-${crypto.randomUUID()}${extension}`);

          await this.objectStorageService.downloadFileToPath({
            key: stagedKey,
            localPath: scanFilePath
          });

          shouldDeleteScanFile = true;
        }

        report = await this.scanner({
          filePath: scanFilePath,
          originalName: item.originalName,
          declaredMimeType: item.mimeType
        });
      }

      const completedAt = new Date().toISOString();
      const persistedReport = await this.store.write((state) => {
        const job = state.jobs.find((candidate) => candidate.id === item.jobId);

        if (!job) {
          return null;
        }

        const visibleHistoricalReports = state.reports.filter((candidate) => isReportVisible(candidate));
        const intel = buildReportIntel(report, visibleHistoricalReports);
        const threatIntel = enrichReportThreatIntel(report);

        const signedReport = signReport(
          {
            ...report,
            sourceType,
            ownerUserId: item.userId,
            queuedJobId: item.jobId,
            completedAt,
            intel,
            ...threatIntel,
            artifacts: null
          },
          {
            secret: this.config.reportIntegritySecret,
            keyId: this.config.reportIntegrityKeyId
          }
        );

        state.reports.unshift(signedReport);

        job.status = "completed";
        job.reportId = signedReport.id;
        job.completedAt = completedAt;
        job.updatedAt = completedAt;
        job.errorMessage = null;
        job.sourceType = sourceType;
        job.targetUrl = sourceType === "url" ? item.targetUrl || null : null;

        state.auditEvents.unshift({
          id: `audit_${crypto.randomUUID()}`,
          userId: item.userId,
          action: "scan.job.completed",
          ipAddress: null,
          userAgent: "",
          metadata: {
            jobId: job.id,
            reportId: signedReport.id,
            sourceType,
            targetUrl: sourceType === "url" ? item.targetUrl || null : null,
            verdict: signedReport.verdict,
            riskScore: signedReport.riskScore
          },
          createdAt: completedAt
        });

        return signedReport;
      });

      if (!persistedReport) {
        return;
      }

      let artifacts = null;
      try {
        artifacts = await this.#persistArtifacts(item, persistedReport, scanFilePath);
      } catch (error) {
        this.logger.error({ err: error, jobId: item.jobId }, "Artifact persistence failed. Continuing with completed scan report.");
      }

      if (artifacts) {
        await this.store.write((state) => {
          const storedReport = state.reports.find((candidate) => candidate.id === persistedReport.id);
          if (!storedReport) {
            return;
          }

          storedReport.artifacts = artifacts;
        });
      }

      await this.notificationService?.create({
        userId: item.userId,
        type: "report_ready",
        tone: report.verdict === "malicious" ? "danger" : report.verdict === "suspicious" ? "warning" : "success",
        title: "Report ready",
        detail: `${describeQueueItem(item)} finished scanning with a ${report.verdict} verdict.`,
        entityType: "report",
        entityId: persistedReport.id,
        dedupeKey: `report-ready:${persistedReport.id}`
      });
    } catch (error) {
      const failedAt = new Date().toISOString();

      await this.store.write((state) => {
        const job = state.jobs.find((candidate) => candidate.id === item.jobId);

        if (!job) {
          return;
        }

        job.status = "failed";
        job.completedAt = failedAt;
        job.updatedAt = failedAt;
        job.errorMessage = error?.message || "Scan failed.";

        state.auditEvents.unshift({
          id: `audit_${crypto.randomUUID()}`,
          userId: item.userId,
          action: "scan.job.failed",
          ipAddress: null,
          userAgent: "",
          metadata: {
            jobId: job.id,
            sourceType,
            targetUrl: sourceType === "url" ? item.targetUrl || null : null,
            errorMessage: job.errorMessage
          },
          createdAt: failedAt
        });
      });

      await this.notificationService?.create({
        userId: item.userId,
        type: "scan_failed",
        tone: "danger",
        title: "Scan failed",
        detail: `${describeQueueItem(item)} could not be scanned. ${error?.message || "Try again or inspect the target manually."}`,
        entityType: "job",
        entityId: item.jobId,
        dedupeKey: `scan-failed:${item.jobId}`
      });

      if (item.stagedUpload?.key && this.objectStorageService?.enabled) {
        await this.objectStorageService
          .deleteObject({
            key: item.stagedUpload.key
          })
          .catch(() => {});
      }

      this.logger.error({ error, jobId: item.jobId }, "Scan processing failed");
    } finally {
      if (shouldDeleteScanFile && scanFilePath) {
        await fs.unlink(scanFilePath).catch(() => {});
      }
    }
  }
}
