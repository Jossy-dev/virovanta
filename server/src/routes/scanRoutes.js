import crypto from "crypto";
import fs from "fs/promises";
import path from "path";
import { Router } from "express";
import multer from "multer";
import { config as defaultConfig } from "../config.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { HttpError } from "../utils/httpError.js";
import { createReportShareToken } from "../utils/reportShareToken.js";
import { validateSchema } from "../utils/validation.js";
import { paginationSchema } from "../validation/scanSchemas.js";

function sanitizeExtension(fileName) {
  const extension = path.extname(fileName || "").toLowerCase();
  return extension.replace(/[^.a-z0-9]/g, "").slice(0, 12);
}

export function createScanRouter({ requireAuth, scanQueueService, authService, config = defaultConfig }) {
  const scanRouter = Router();
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
      files: 1
    }
  });

  scanRouter.use(requireAuth);

  scanRouter.get(
    "/jobs",
    asyncHandler(async (req, res) => {
      const { limit } = validateSchema(paginationSchema, req.query);
      const jobs = await scanQueueService.listJobsForUser(req.auth.user, limit);
      res.json({ jobs });
    })
  );

  scanRouter.get(
    "/jobs/:jobId",
    asyncHandler(async (req, res) => {
      const job = await scanQueueService.getJobForUser(req.params.jobId, req.auth.user);
      res.json({ job });
    })
  );

  scanRouter.post(
    "/jobs",
    upload.single("file"),
    asyncHandler(async (req, res) => {
      let queued = false;

      if (!req.file) {
        throw new HttpError(400, "Upload missing. Send a single file in field 'file'.", {
          code: "SCAN_UPLOAD_MISSING"
        });
      }

      try {
        const quota = await authService.consumeDailyQuota(req.auth.user.id);
        if (!quota.allowed) {
          throw new HttpError(429, "Daily scan quota exceeded for free tier.", {
            code: "SCAN_QUOTA_EXCEEDED",
            details: quota
          });
        }

        const job = await scanQueueService.enqueueScan({
          userId: req.auth.user.id,
          filePath: req.file.path,
          originalName: req.file.originalname,
          mimeType: req.file.mimetype,
          fileSize: req.file.size
        });

        queued = true;

        res.status(202).json({
          job,
          quota
        });
      } finally {
        if (!queued) {
          await fs.unlink(req.file.path).catch(() => {});
        }
      }
    })
  );

  scanRouter.get(
    "/reports",
    asyncHandler(async (req, res) => {
      const { limit } = validateSchema(paginationSchema, req.query);
      const reports = await scanQueueService.listReportsForUser(req.auth.user, limit);
      res.json({ reports });
    })
  );

  scanRouter.get(
    "/reports/:reportId",
    asyncHandler(async (req, res) => {
      const report = await scanQueueService.getReportForUser(req.params.reportId, req.auth.user);
      res.json({ report });
    })
  );

  scanRouter.post(
    "/reports/:reportId/share",
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

      res.json({
        shareToken: share.token,
        expiresAt: share.expiresAt,
        publicApiPath,
        shareUrl: host ? `${protocol}://${host}${publicApiPath}` : publicApiPath
      });
    })
  );

  return scanRouter;
}
