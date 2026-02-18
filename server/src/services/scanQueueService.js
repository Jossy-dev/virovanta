import crypto from "crypto";
import fs from "fs/promises";
import { HttpError } from "../utils/httpError.js";

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
  return {
    id: job.id,
    status: job.status,
    createdAt: job.createdAt,
    startedAt: job.startedAt || null,
    completedAt: job.completedAt || null,
    originalName: job.originalName,
    fileSize: job.fileSize,
    reportId: job.reportId || null,
    errorMessage: job.errorMessage || null
  };
}

function toReportSummary(report) {
  return {
    id: report.id,
    createdAt: report.createdAt,
    completedAt: report.completedAt,
    verdict: report.verdict,
    riskScore: report.riskScore,
    fileName: report.file.originalName,
    fileSize: report.file.size,
    findingCount: report.findings.length,
    topFinding: report.findings[0]?.title || "No notable findings",
    intel: report.intel || null
  };
}

export class ScanQueueService {
  constructor({ store, scanner, logger, config }) {
    this.store = store;
    this.scanner = scanner;
    this.logger = logger;
    this.config = config;
    this.queue = [];
    this.processing = 0;
    this.started = false;
  }

  async start() {
    if (this.started) {
      return;
    }

    this.started = true;

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

  async enqueueScan({ userId, filePath, originalName, mimeType, fileSize }) {
    const now = new Date().toISOString();

    const job = await this.store.write((state) => {
      const user = state.users.find((candidate) => candidate.id === userId);
      if (!user) {
        throw new HttpError(404, "User not found.", { code: "SCAN_USER_NOT_FOUND" });
      }

      const nextJob = {
        id: `job_${crypto.randomUUID()}`,
        userId,
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
          fileSize: nextJob.fileSize,
          originalName: nextJob.originalName
        },
        createdAt: now
      });

      return nextJob;
    });

    this.queue.push({
      jobId: job.id,
      userId,
      filePath,
      originalName,
      mimeType,
      fileSize
    });

    this.#drainQueue();

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

    if (!report) {
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
        .filter((report) => user.role === "admin" || report.ownerUserId === user.id)
        .slice(0, safeLimit)
        .map(toReportSummary);
    });
  }

  async getReportById(reportId) {
    return this.store.read((state) => state.reports.find((candidate) => candidate.id === reportId) || null);
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

    try {
      const report = await this.scanner({
        filePath: item.filePath,
        originalName: item.originalName,
        declaredMimeType: item.mimeType
      });

      const completedAt = new Date().toISOString();

      await this.store.write((state) => {
        const job = state.jobs.find((candidate) => candidate.id === item.jobId);

        if (!job) {
          return;
        }

        const intel = buildReportIntel(report, state.reports);

        const persistedReport = {
          ...report,
          ownerUserId: item.userId,
          queuedJobId: item.jobId,
          completedAt,
          intel
        };

        state.reports.unshift(persistedReport);

        job.status = "completed";
        job.reportId = persistedReport.id;
        job.completedAt = completedAt;
        job.updatedAt = completedAt;
        job.errorMessage = null;

        state.auditEvents.unshift({
          id: `audit_${crypto.randomUUID()}`,
          userId: item.userId,
          action: "scan.job.completed",
          ipAddress: null,
          userAgent: "",
          metadata: {
            jobId: job.id,
            reportId: persistedReport.id,
            verdict: persistedReport.verdict,
            riskScore: persistedReport.riskScore
          },
          createdAt: completedAt
        });
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
            errorMessage: job.errorMessage
          },
          createdAt: failedAt
        });
      });

      this.logger.error({ error, jobId: item.jobId }, "Scan processing failed");
    } finally {
      await fs.unlink(item.filePath).catch(() => {});
    }
  }
}
