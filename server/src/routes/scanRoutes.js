import crypto from "crypto";
import fs from "fs/promises";
import path from "path";
import { Router } from "express";
import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import multer from "multer";
import { config as defaultConfig } from "../config.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { HttpError } from "../utils/httpError.js";
import { createReportShareToken } from "../utils/reportShareToken.js";
import { buildScanReportPdf } from "../utils/reportPdf.js";
import { API_KEY_SCOPES } from "../utils/apiKeyScopes.js";
import { validateSchema } from "../utils/validation.js";
import { linkScanJobSchema, paginationSchema, websiteSafetyScanJobSchema } from "../validation/scanSchemas.js";

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

export function createScanRouter({
  requireAuth,
  requireApiKeyScopes = () => (_req, _res, next) => next(),
  scanQueueService,
  authService,
  notificationService = null,
  preventSensitiveCaching,
  config = defaultConfig
}) {
  const scanRouter = Router();
  const linkScanRateLimiter = rateLimit({
    windowMs: config.urlScanRateLimitWindowMinutes * 60 * 1000,
    limit: config.urlScanRateLimitRequestsPerWindow,
    keyGenerator: (req) => req.auth?.user?.id || ipKeyGenerator(req.ip || ""),
    standardHeaders: true,
    legacyHeaders: false
  });
  const websiteSafetyRateLimiter = rateLimit({
    windowMs: config.urlScanRateLimitWindowMinutes * 60 * 1000,
    limit: config.urlScanRateLimitRequestsPerWindow,
    keyGenerator: (req) => req.auth?.user?.id || ipKeyGenerator(req.ip || ""),
    standardHeaders: true,
    legacyHeaders: false
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
    requireApiKeyScopes(API_KEY_SCOPES.JOBS_READ),
    asyncHandler(async (req, res) => {
      const { limit, sourceType } = validateSchema(paginationSchema, req.query);
      const jobs = await scanQueueService.listJobsForUser(req.auth.user, limit, sourceType);
      res.json({ jobs });
    })
  );

  scanRouter.get(
    "/jobs/:jobId",
    requireApiKeyScopes(API_KEY_SCOPES.JOBS_READ),
    asyncHandler(async (req, res) => {
      const job = await scanQueueService.getJobForUser(req.params.jobId, req.auth.user);
      res.json({ job });
    })
  );

  scanRouter.post(
    "/links/jobs",
    requireApiKeyScopes(API_KEY_SCOPES.JOBS_WRITE),
    linkScanRateLimiter,
    asyncHandler(async (req, res) => {
      const { url } = validateSchema(linkScanJobSchema, req.body || {});
      const quota = await authService.consumeDailyQuota(req.auth.user.id);

      if (!quota.allowed) {
        throw new HttpError(429, "Daily scan quota exceeded for URL scans.", {
          code: "SCAN_QUOTA_EXCEEDED",
          details: {
            ...quota,
            requested: 1
          }
        });
      }

      const job = await scanQueueService.enqueueUrlScan({
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
      const share = createReportShareToken({
        reportId: report.id,
        ownerUserId: report.ownerUserId,
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

      res.json({
        shareToken: share.token,
        expiresAt: share.expiresAt,
        publicApiPath,
        shareUrl
      });
    })
  );

  return scanRouter;
}
