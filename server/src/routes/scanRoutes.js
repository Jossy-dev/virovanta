import crypto from "crypto";
import fs from "fs/promises";
import path from "path";
import { Router } from "express";
import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import multer from "multer";
import { config as defaultConfig } from "../config.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { HttpError } from "../utils/httpError.js";
import {
  buildReportCsvExport,
  buildReportExportFilename,
  buildReportJsonExport,
  buildReportStixExport
} from "../utils/reportExports.js";
import { createReportShareToken } from "../utils/reportShareToken.js";
import { buildScanReportPdf } from "../utils/reportPdf.js";
import { API_KEY_SCOPES } from "../utils/apiKeyScopes.js";
import { buildAuthRateLimitKey, buildRateLimitHandler } from "../utils/rateLimit.js";
import { resolveUrlScanCandidates, resolveUrlScanTarget } from "../utils/urlExtraction.js";
import { normalizeUrlInput } from "../utils/urlIntake.js";
import { validateSchema } from "../utils/validation.js";
import {
  linkScanJobSchema,
  linkScanResolveSchema,
  paginationSchema,
  reportCommentCreateSchema,
  reportShareCreateSchema,
  reportWorkflowUpdateSchema,
  websiteSafetyScanJobSchema
} from "../validation/scanSchemas.js";

function sanitizeExtension(fileName) {
  const extension = path.extname(fileName || "").toLowerCase();
  return extension.replace(/[^.a-z0-9]/g, "").slice(0, 12);
}

function collectUploadedFiles(req) {
  const groupedFiles = req.files && typeof req.files === "object" ? req.files : {};
  const singleFieldFiles = Array.isArray(groupedFiles.file) ? groupedFiles.file : [];
  const batchFieldFiles = Array.isArray(groupedFiles.files) ? groupedFiles.files : [];
  return [...singleFieldFiles, ...batchFieldFiles];
}

function normalizeRequestedUrls(urls) {
  const normalizedUrls = [];
  const seen = new Set();

  for (const value of Array.isArray(urls) ? urls : []) {
    const trimmed = String(value || "").trim();
    if (!trimmed) {
      continue;
    }

    const normalized = normalizeUrlInput(trimmed).normalizedUrl;
    const key = normalized.toLowerCase();
    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    normalizedUrls.push(normalized);
  }

  if (normalizedUrls.length === 0) {
    throw new Error("Select at least one link to scan.");
  }

  return normalizedUrls;
}

export function createScanRouter({
  requireAuth,
  requireApiKeyScopes = () => (_req, _res, next) => next(),
  scanQueueService,
  authService,
  workspaceService = null,
  notificationService = null,
  preventSensitiveCaching,
  config = defaultConfig
}) {
  const scanRouter = Router();
  const jobPollingRateLimiter = rateLimit({
    windowMs: config.jobPollingWindowMinutes * 60 * 1000,
    limit: config.jobPollingRequestsPerWindow,
    keyGenerator: (req) => buildAuthRateLimitKey(req, { prefix: "scan-job-poll" }),
    standardHeaders: true,
    legacyHeaders: false,
    handler: buildRateLimitHandler({
      code: "SCAN_POLL_RATE_LIMIT_EXCEEDED",
      message: "Job polling rate limit exceeded. Reduce polling frequency and retry shortly.",
      details: (_req, _res, options) => ({
        scope: "job_polling",
        limit: options.limit,
        windowMs: options.windowMs
      })
    })
  });
  const linkScanRateLimiter = rateLimit({
    windowMs: config.urlScanRateLimitWindowMinutes * 60 * 1000,
    limit: config.urlScanRateLimitRequestsPerWindow,
    keyGenerator: (req) => req.auth?.user?.id || ipKeyGenerator(req.ip || ""),
    standardHeaders: true,
    legacyHeaders: false,
    handler: buildRateLimitHandler({
      code: "URL_SCAN_RATE_LIMIT_EXCEEDED",
      message: "URL scan submission rate limit exceeded. Retry shortly."
    })
  });
  const websiteSafetyRateLimiter = rateLimit({
    windowMs: config.urlScanRateLimitWindowMinutes * 60 * 1000,
    limit: config.urlScanRateLimitRequestsPerWindow,
    keyGenerator: (req) => req.auth?.user?.id || ipKeyGenerator(req.ip || ""),
    standardHeaders: true,
    legacyHeaders: false,
    handler: buildRateLimitHandler({
      code: "WEBSITE_SCAN_RATE_LIMIT_EXCEEDED",
      message: "Website safety submission rate limit exceeded. Retry shortly."
    })
  });
  const storage = multer.diskStorage({
    destination: (_req, _file, callback) => {
      callback(null, config.uploadDir);
    },
    filename: (_req, file, callback) => {
      const extension = sanitizeExtension(file.originalname);
      callback(null, `${Date.now()}-${crypto.randomUUID()}${extension}`);
    }
  });

  const upload = multer({
    storage,
    limits: {
      fileSize: config.maxUploadBytes,
      files: config.maxBatchUploadFiles
    }
  });

  scanRouter.use(requireAuth, preventSensitiveCaching());

  scanRouter.get(
    "/jobs",
    jobPollingRateLimiter,
    requireApiKeyScopes(API_KEY_SCOPES.JOBS_READ),
    asyncHandler(async (req, res) => {
      const { limit, sourceType } = validateSchema(paginationSchema, req.query);
      const jobs = await scanQueueService.listJobsForUser(req.auth.user, limit, sourceType);
      res.json({ jobs });
    })
  );

  scanRouter.get(
    "/jobs/:jobId",
    jobPollingRateLimiter,
    requireApiKeyScopes(API_KEY_SCOPES.JOBS_READ),
    asyncHandler(async (req, res) => {
      const job = await scanQueueService.getJobForUser(req.params.jobId, req.auth.user);
      res.json({ job });
    })
  );

  scanRouter.post(
    "/links/resolve",
    requireApiKeyScopes(API_KEY_SCOPES.JOBS_WRITE),
    linkScanRateLimiter,
    asyncHandler(async (req, res) => {
      const { url, message } = validateSchema(linkScanResolveSchema, req.body || {});

      try {
        const resolution = resolveUrlScanCandidates({ url, message });
        res.json({ resolution });
      } catch (error) {
        throw new HttpError(400, error?.message || "Could not determine which links to review.", {
          code: "URL_SCAN_TARGET_INVALID"
        });
      }
    })
  );

  scanRouter.post(
    "/links/jobs",
    requireApiKeyScopes(API_KEY_SCOPES.JOBS_WRITE),
    linkScanRateLimiter,
    asyncHandler(async (req, res) => {
      const { url, urls, message } = validateSchema(linkScanJobSchema, req.body || {});
      let normalizedUrls = [];
      let resolvedTarget;

      try {
        if (Array.isArray(urls) && urls.length > 0) {
          normalizedUrls = normalizeRequestedUrls(urls);
        } else {
          resolvedTarget = resolveUrlScanTarget({ url, message });
          normalizedUrls = [resolvedTarget.url];
        }
      } catch (error) {
        throw new HttpError(400, error?.message || "Could not determine which link to scan.", {
          code: "URL_SCAN_TARGET_INVALID"
        });
      }

      const requestedCount = normalizedUrls.length;
      const quota =
        requestedCount > 1
          ? await authService.consumeDailyQuotaBatch(req.auth.user.id, requestedCount)
          : await authService.consumeDailyQuota(req.auth.user.id);

      if (!quota.allowed) {
        throw new HttpError(
          429,
          requestedCount > 1 ? "Daily scan quota exceeded for this URL scan batch." : "Daily scan quota exceeded for URL scans.",
          {
            code: "SCAN_QUOTA_EXCEEDED",
            details: {
              ...quota,
              requested: requestedCount
            }
          }
        );
      }

      const jobs = [];
      for (const targetUrl of normalizedUrls) {
        const job = await scanQueueService.enqueueUrlScan({
          userId: req.auth.user.id,
          url: targetUrl
        });
        jobs.push(job);
      }

      res.status(202).json({
        job: jobs[0] || null,
        jobs,
        acceptedUrls: jobs.length,
        quota,
        extracted:
          resolvedTarget?.extracted
            ? {
                url: resolvedTarget.url,
                candidateCount: resolvedTarget.candidateCount,
                source: resolvedTarget.source
              }
            : null
      });
    })
  );

  scanRouter.post(
    "/website/jobs",
    requireApiKeyScopes(API_KEY_SCOPES.JOBS_WRITE),
    websiteSafetyRateLimiter,
    asyncHandler(async (req, res) => {
      const { url } = validateSchema(websiteSafetyScanJobSchema, req.body || {});
      const quota = await authService.consumeDailyQuota(req.auth.user.id);

      if (!quota.allowed) {
        throw new HttpError(429, "Daily scan quota exceeded for website safety scans.", {
          code: "SCAN_QUOTA_EXCEEDED",
          details: {
            ...quota,
            requested: 1
          }
        });
      }

      const job = await scanQueueService.enqueueWebsiteSafetyScan({
        userId: req.auth.user.id,
        url
      });

      res.status(202).json({
        job,
        quota
      });
    })
  );

  scanRouter.post(
    "/jobs",
    requireApiKeyScopes(API_KEY_SCOPES.JOBS_WRITE),
    upload.fields([
      { name: "file", maxCount: 1 },
      { name: "files", maxCount: config.maxBatchUploadFiles }
    ]),
    asyncHandler(async (req, res) => {
      const uploadedFiles = collectUploadedFiles(req);
      const queuedJobs = [];
      const queuedFilePaths = new Set();

      if (uploadedFiles.length === 0) {
        throw new HttpError(400, "Upload missing. Send files in field 'files'.", {
          code: "SCAN_UPLOAD_MISSING"
        });
      }

      try {
        const quota = await authService.consumeDailyQuotaBatch(req.auth.user.id, uploadedFiles.length);
        if (!quota.allowed) {
          const allowedCount = quota.remaining == null ? uploadedFiles.length : Math.max(0, quota.remaining);
          throw new HttpError(429, "Daily scan quota exceeded for this upload batch.", {
            code: "SCAN_QUOTA_EXCEEDED",
            details: {
              ...quota,
              requested: uploadedFiles.length,
              allowedCount
            }
          });
        }

        for (const file of uploadedFiles) {
          const job = await scanQueueService.enqueueScan({
            userId: req.auth.user.id,
            filePath: file.path,
            originalName: file.originalname,
            mimeType: file.mimetype,
            fileSize: file.size
          });
          queuedFilePaths.add(file.path);
          queuedJobs.push(job);
        }

        res.status(202).json({
          job: queuedJobs[0] || null,
          jobs: queuedJobs,
          acceptedFiles: queuedJobs.length,
          quota
        });
      } finally {
        await Promise.all(
          uploadedFiles.map(async (file) => {
            if (!queuedFilePaths.has(file.path)) {
              await fs.unlink(file.path).catch(() => {});
            }
          })
        );
      }
    })
  );

  scanRouter.get(
    "/reports",
    requireApiKeyScopes(API_KEY_SCOPES.REPORTS_READ),
    asyncHandler(async (req, res) => {
      const { limit, sourceType } = validateSchema(paginationSchema, req.query);
      const reports = await scanQueueService.listReportsForUser(req.auth.user, limit, sourceType);
      res.json({ reports });
    })
  );

  scanRouter.get(
    "/reports/:reportId",
    requireApiKeyScopes(API_KEY_SCOPES.REPORTS_READ),
    asyncHandler(async (req, res) => {
      const report = await scanQueueService.getReportForUser(req.params.reportId, req.auth.user);
      res.json({ report });
    })
  );

  scanRouter.get(
    "/reports/:reportId/workflow",
    requireApiKeyScopes(API_KEY_SCOPES.REPORTS_READ),
    asyncHandler(async (req, res) => {
      const report = await scanQueueService.getReportForUser(req.params.reportId, req.auth.user);
      const workflow = await scanQueueService.store.getOrCreateReportWorkflow({
        reportId: report.id,
        ownerUserId: report.ownerUserId,
        now: new Date().toISOString()
      });
      const comments = await scanQueueService.store.listReportComments(report.id, report.ownerUserId);
      const shares = await scanQueueService.store.listReportShares({
        reportId: report.id,
        ownerUserId: report.ownerUserId
      });
      res.json({ workflow, comments, shares });
    })
  );

  scanRouter.patch(
    "/reports/:reportId/workflow",
    requireApiKeyScopes(API_KEY_SCOPES.WORKFLOW_WRITE),
    asyncHandler(async (req, res) => {
      const report = await scanQueueService.getReportForUser(req.params.reportId, req.auth.user);
      const payload = validateSchema(reportWorkflowUpdateSchema, req.body || {});
      const updatedAt = new Date().toISOString();
      const workflow = await scanQueueService.store.updateReportWorkflow({
        reportId: report.id,
        ownerUserId: report.ownerUserId,
        updates: payload,
        updatedAt
      });

      await scanQueueService.store.createAuditEvent?.({
        userId: req.auth.user.id,
        action: "report.workflow.updated",
        metadata: {
          reportId: report.id,
          fields: Object.keys(payload)
        },
        createdAt: updatedAt
      });

      await notificationService?.create({
        userId: req.auth.user.id,
        type: "report_workflow_updated",
        tone: "info",
        title: "Report workflow updated",
        detail: `${report.fileName || "Report"} workflow fields were updated.`,
        entityType: "report",
        entityId: report.id,
        dedupeKey: `report-workflow-updated:${report.id}:${updatedAt}`
      });

      await workspaceService?.dispatchEvent?.({
        userId: req.auth.user.id,
        eventType: "report.workflow.updated",
        payload: {
          reportId: report.id,
          workflow
        },
        entityType: "report",
        entityId: report.id
      });

      res.json({ workflow });
    })
  );

  scanRouter.post(
    "/reports/:reportId/comments",
    requireApiKeyScopes(API_KEY_SCOPES.WORKFLOW_WRITE),
    asyncHandler(async (req, res) => {
      const report = await scanQueueService.getReportForUser(req.params.reportId, req.auth.user);
      const payload = validateSchema(reportCommentCreateSchema, req.body || {});
      const createdAt = new Date().toISOString();
      const comment = await scanQueueService.store.createReportComment({
        reportId: report.id,
        ownerUserId: report.ownerUserId,
        authorUserId: req.auth.user.id,
        authorName: req.auth.user.name || req.auth.user.username || req.auth.user.email || "Analyst",
        body: payload.body,
        createdAt
      });

      await scanQueueService.store.createAuditEvent?.({
        userId: req.auth.user.id,
        action: "report.comment.created",
        metadata: {
          reportId: report.id,
          commentId: comment.id
        },
        createdAt
      });

      await notificationService?.create({
        userId: req.auth.user.id,
        type: "report_comment_created",
        tone: "info",
        title: "Comment added",
        detail: `${report.fileName || "Report"} now includes a new analyst note.`,
        entityType: "report",
        entityId: report.id,
        dedupeKey: `report-comment:${comment.id}`
      });

      await workspaceService?.dispatchEvent?.({
        userId: req.auth.user.id,
        eventType: "report.comment.created",
        payload: {
          reportId: report.id,
          comment
        },
        entityType: "report",
        entityId: report.id
      });

      res.status(201).json({ comment });
    })
  );

  scanRouter.get(
    "/reports/:reportId/export.json",
    requireApiKeyScopes(API_KEY_SCOPES.REPORTS_READ),
    asyncHandler(async (req, res) => {
      const report = await scanQueueService.getReportForUser(req.params.reportId, req.auth.user);
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", `attachment; filename="${buildReportExportFilename(report, "json")}"`);
      res.status(200).send(JSON.stringify(buildReportJsonExport(report), null, 2));
    })
  );

  scanRouter.get(
    "/reports/:reportId/export.csv",
    requireApiKeyScopes(API_KEY_SCOPES.REPORTS_READ),
    asyncHandler(async (req, res) => {
      const report = await scanQueueService.getReportForUser(req.params.reportId, req.auth.user);
      res.setHeader("Content-Type", "text/csv; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="${buildReportExportFilename(report, "csv")}"`);
      res.status(200).send(buildReportCsvExport(report));
    })
  );

  scanRouter.get(
    "/reports/:reportId/export.stix",
    requireApiKeyScopes(API_KEY_SCOPES.REPORTS_READ),
    asyncHandler(async (req, res) => {
      const report = await scanQueueService.getReportForUser(req.params.reportId, req.auth.user);
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", `attachment; filename="${buildReportExportFilename(report, "stix.json")}"`);
      res.status(200).send(JSON.stringify(buildReportStixExport(report), null, 2));
    })
  );

  scanRouter.get(
    "/reports/:reportId/pdf",
    requireApiKeyScopes(API_KEY_SCOPES.REPORTS_READ),
    asyncHandler(async (req, res) => {
      const report = await scanQueueService.getReportForUser(req.params.reportId, req.auth.user);
      const pdfBuffer = await buildScanReportPdf(report);
      const safeReportId = String(report.id || "report").replace(/[^a-zA-Z0-9._-]+/g, "_");

      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", `attachment; filename="${safeReportId}.pdf"`);
      res.setHeader("Cache-Control", "private, no-store, max-age=0");
      res.status(200).send(pdfBuffer);
    })
  );

  scanRouter.get(
    "/reports/:reportId/shares",
    requireApiKeyScopes(API_KEY_SCOPES.REPORTS_READ),
    asyncHandler(async (req, res) => {
      const report = await scanQueueService.getReportForUser(req.params.reportId, req.auth.user);
      const shares = await scanQueueService.store.listReportShares({
        reportId: report.id,
        ownerUserId: report.ownerUserId
      });
      res.json({ shares });
    })
  );

  scanRouter.delete(
    "/reports/:reportId",
    requireApiKeyScopes(API_KEY_SCOPES.REPORTS_DELETE),
    asyncHandler(async (req, res) => {
      const deletion = await scanQueueService.deleteReportForUser(req.params.reportId, req.auth.user);
      res.json({
        deleted: true,
        reportId: deletion.id,
        deletedAt: deletion.deletedAt,
        retentionExpiresAt: deletion.retentionExpiresAt,
        alreadyDeleted: Boolean(deletion.alreadyDeleted)
      });
    })
  );

  scanRouter.get(
    "/reports/:reportId/integrity",
    requireApiKeyScopes(API_KEY_SCOPES.REPORTS_READ),
    asyncHandler(async (req, res) => {
      const report = await scanQueueService.getReportForUser(req.params.reportId, req.auth.user);
      const integrity = scanQueueService.verifyReportIntegrity(report);
      res.json({
        reportId: report.id,
        integrity
      });
    })
  );

  scanRouter.get(
    "/analytics",
    requireApiKeyScopes(API_KEY_SCOPES.ANALYTICS_READ),
    asyncHandler(async (req, res) => {
      const analytics = await scanQueueService.getAnalyticsForUser(req.auth.user);
      res.json({ analytics });
    })
  );

  scanRouter.post(
    "/reports/:reportId/share",
    requireApiKeyScopes(API_KEY_SCOPES.REPORTS_SHARE),
    asyncHandler(async (req, res) => {
      const report = await scanQueueService.getReportForUser(req.params.reportId, req.auth.user);
      const payload = validateSchema(reportShareCreateSchema, req.body || {});
      const workspace = workspaceService ? await workspaceService.getWorkspaceSnapshot(req.auth.user.id) : null;
      const maxTtlHours = Number(workspace?.entitlements?.limits?.shareTtlHours) || Number(payload.ttlHours || 72);
      if (Number(payload.ttlHours || 72) > maxTtlHours) {
        throw new HttpError(400, `Share link duration exceeds the workspace limit of ${maxTtlHours} hours.`, {
          code: "REPORT_SHARE_TTL_LIMIT"
        });
      }
      const createdAt = new Date().toISOString();
      const expiresAt = new Date(Date.now() + Number(payload.ttlHours || 72) * 60 * 60 * 1000).toISOString();
      const shareRecord = await scanQueueService.store.createReportShare({
        reportId: report.id,
        ownerUserId: report.ownerUserId,
        label: payload.label || "",
        expiresAt,
        createdAt
      });
      const share = createReportShareToken({
        reportId: report.id,
        ownerUserId: report.ownerUserId,
        shareId: shareRecord.id,
        config
      });

      const publicApiPath = `/api/public/shared-reports/${share.token}`;
      const protocol = req.headers["x-forwarded-proto"]?.toString().split(",")[0]?.trim() || req.protocol;
      const host = req.get("host");
      const shareUrl = host ? `${protocol}://${host}${publicApiPath}` : publicApiPath;

      await notificationService?.create({
        userId: req.auth.user.id,
        type: "report_share_created",
        tone: "info",
        title: "Share link created",
        detail: `${report.file?.originalName || report.fileName || "Report"} is ready to share externally.`,
        entityType: "report",
        entityId: report.id
      });

      await scanQueueService.store.createAuditEvent?.({
        userId: req.auth.user.id,
        action: "report.share.created",
        metadata: {
          reportId: report.id,
          shareId: shareRecord.id
        },
        createdAt
      });

      await workspaceService?.dispatchEvent?.({
        userId: req.auth.user.id,
        eventType: "report.share.created",
        payload: {
          reportId: report.id,
          shareId: shareRecord.id,
          label: shareRecord.label,
          expiresAt: shareRecord.expiresAt,
          shareUrl
        },
        entityType: "report",
        entityId: report.id
      });

      res.json({
        shareId: shareRecord.id,
        shareToken: share.token,
        expiresAt: shareRecord.expiresAt || share.expiresAt,
        publicApiPath,
        shareUrl,
        label: shareRecord.label
      });
    })
  );

  scanRouter.delete(
    "/reports/:reportId/shares/:shareId",
    requireApiKeyScopes(API_KEY_SCOPES.REPORTS_SHARE),
    asyncHandler(async (req, res) => {
      const report = await scanQueueService.getReportForUser(req.params.reportId, req.auth.user);
      const revokedAt = new Date().toISOString();
      const share = await scanQueueService.store.revokeReportShare({
        shareId: req.params.shareId,
        ownerUserId: report.ownerUserId,
        revokedAt
      });

      if (!share || share.reportId !== report.id) {
        throw new HttpError(404, "Share link not found.", {
          code: "REPORT_SHARE_NOT_FOUND"
        });
      }

      await scanQueueService.store.createAuditEvent?.({
        userId: req.auth.user.id,
        action: "report.share.revoked",
        metadata: {
          reportId: report.id,
          shareId: share.id
        },
        createdAt: revokedAt
      });

      await workspaceService?.dispatchEvent?.({
        userId: req.auth.user.id,
        eventType: "report.share.revoked",
        payload: {
          reportId: report.id,
          shareId: share.id,
          revokedAt
        },
        entityType: "report",
        entityId: report.id
      });

      res.json({
        revoked: true,
        share
      });
    })
  );

  return scanRouter;
}
