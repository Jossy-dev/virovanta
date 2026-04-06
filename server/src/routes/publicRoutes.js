import crypto from "crypto";
import fs from "fs/promises";
import path from "path";
import rateLimit from "express-rate-limit";
import { Router } from "express";
import multer from "multer";
import { asyncHandler } from "../utils/asyncHandler.js";
import { HttpError } from "../utils/httpError.js";
import { verifyReportShareToken } from "../utils/reportShareToken.js";

function sanitizeExtension(fileName) {
  const extension = path.extname(fileName || "").toLowerCase();
  return extension.replace(/[^.a-z0-9]/g, "").slice(0, 12);
}

function toPublicReport(report, findingsLimit = 8) {
  const sourceType = report?.sourceType === "url" ? "url" : report?.sourceType === "website" ? "website" : "file";

  return {
    id: report.id,
    sourceType,
    createdAt: report.createdAt,
    completedAt: report.completedAt,
    verdict: report.verdict,
    riskScore: report.riskScore,
    file: {
      originalName: report.file.originalName,
      extension: report.file.extension,
      size: report.file.size,
      sizeDisplay: report.file.sizeDisplay,
      detectedMimeType: report.file.detectedMimeType,
      magicType: report.file.magicType,
      entropy: report.file.entropy,
      hashes: report.file.hashes
    },
    findings: report.findings.slice(0, findingsLimit),
    plainLanguageReasons: Array.isArray(report.plainLanguageReasons) ? report.plainLanguageReasons.slice(0, findingsLimit) : [],
    technicalIndicators: report.technicalIndicators || null,
    websiteSafety: report.websiteSafety || null,
    url: report.url || null,
    engines: report.engines,
    recommendations: report.recommendations,
    intel: report.intel || null,
    iocs: report.iocs || null,
    attackMapping: report.attackMapping || null,
    signature: report.signature || null
  };
}

export function createPublicRouter({ scanner, config, scanQueueService, store, preventSensitiveCaching }) {
  const publicRouter = Router();

  const uploadStorage = multer.diskStorage({
    destination: (_req, _file, callback) => {
      callback(null, config.uploadDir);
    },
    filename: (_req, file, callback) => {
      const extension = sanitizeExtension(file.originalname);
      callback(null, `guest-${Date.now()}-${crypto.randomUUID()}${extension}`);
    }
  });

  const upload = multer({
    storage: uploadStorage,
    limits: {
      fileSize: config.publicQuickScanMaxUploadBytes,
      files: 1
    }
  });

  const publicLimiter = rateLimit({
    windowMs: config.publicQuickScanWindowMinutes * 60 * 1000,
    limit: config.publicQuickScanRequestsPerWindow,
    standardHeaders: true,
    legacyHeaders: false
  });

  publicRouter.use(publicLimiter);

  publicRouter.get("/status", (_req, res) => {
    const reportRetentionDays = Math.round(config.reportTtlMs / (24 * 60 * 60 * 1000));
    const now = new Date().toISOString();

    res.json({
      status: "operational",
      timestamp: now,
      quickScanEnabled: config.publicQuickScanEnabled,
      maxUploadMb: Math.round(config.publicQuickScanMaxUploadBytes / (1024 * 1024)),
      message: "Guest quick scan allows temporary test uploads without account creation.",
      reliability: {
        deterministicErrorResponses: true,
        scanSlaTargetMinutes: Number(config.scanSlaTargetMinutes) || 5,
        uptimeTargetPercent: String(config.serviceUptimeTargetPercent || "99.9")
      },
      limits: {
        guestQuickScan: {
          maxUploadMb: Math.round(config.publicQuickScanMaxUploadBytes / (1024 * 1024)),
          requestsPerWindow: Number(config.publicQuickScanRequestsPerWindow) || 0,
          windowMinutes: Number(config.publicQuickScanWindowMinutes) || 0
        },
        authenticated: {
          maxUploadMb: Math.round(config.maxUploadBytes / (1024 * 1024)),
          maxFilesPerBatch: Number(config.maxBatchUploadFiles) || 0,
          dailyScanLimit: Number(config.freeTierDailyScanLimit) || 0,
          linkScanRequestsPerWindow: Number(config.urlScanRateLimitRequestsPerWindow) || 0,
          linkScanWindowMinutes: Number(config.urlScanRateLimitWindowMinutes) || 0,
          websiteSafetyRequestsPerWindow: Number(config.urlScanRateLimitRequestsPerWindow) || 0,
          websiteSafetyWindowMinutes: Number(config.urlScanRateLimitWindowMinutes) || 0
        }
      },
      compliance: {
        reportsPrivateByDefault: true,
        userDeleteMode: "delete",
        reportRetentionDays,
        note: "Deleting a report removes it from user history."
      }
    });
  });

  publicRouter.get(
    "/shared-reports/:token",
    preventSensitiveCaching({ privateCache: false }),
    asyncHandler(async (req, res) => {
      if (!scanQueueService?.getReportById) {
        throw new HttpError(503, "Shared report service is unavailable.", {
          code: "SHARED_REPORT_UNAVAILABLE"
        });
      }

      const claims = verifyReportShareToken(req.params.token, config);
      if (claims.shareId && store?.findReportShareById) {
        const share = await store.findReportShareById(claims.shareId);
        if (
          !share ||
          share.reportId !== claims.reportId ||
          share.ownerUserId !== claims.ownerUserId ||
          share.revokedAt ||
          (share.expiresAt && Date.parse(share.expiresAt) <= Date.now())
        ) {
          throw new HttpError(404, "Shared report not found.", {
            code: "SHARED_REPORT_NOT_FOUND"
          });
        }

        await store.markReportShareAccessed?.({
          shareId: share.id,
          accessedAt: new Date().toISOString()
        });
      }

      const report = await scanQueueService.getReportById(claims.reportId);

      if (!report || report.ownerUserId !== claims.ownerUserId) {
        throw new HttpError(404, "Shared report not found.", {
          code: "SHARED_REPORT_NOT_FOUND"
        });
      }

      const integrity =
        typeof scanQueueService.verifyReportIntegrity === "function" ? scanQueueService.verifyReportIntegrity(report) : null;

      res.json({
        report: toPublicReport(report, config.publicQuickScanFindingsLimit),
        integrity,
        shared: true
      });
    })
  );

  publicRouter.post(
    "/quick-scan",
    upload.single("file"),
    preventSensitiveCaching({ privateCache: false }),
    asyncHandler(async (req, res) => {
      if (!config.publicQuickScanEnabled) {
        throw new HttpError(403, "Guest quick scan is currently disabled.", {
          code: "PUBLIC_QUICK_SCAN_DISABLED"
        });
      }

      if (!req.file) {
        throw new HttpError(400, "Upload missing. Send a single file in field 'file'.", {
          code: "PUBLIC_QUICK_SCAN_UPLOAD_MISSING"
        });
      }

      try {
        const report = await scanner({
          filePath: req.file.path,
          originalName: req.file.originalname,
          declaredMimeType: req.file.mimetype
        });

        res.json({
          report: toPublicReport(report, config.publicQuickScanFindingsLimit),
          mode: "guest",
          note: "Guest scans are not stored and are intended for quick testing only."
        });
      } finally {
        await fs.unlink(req.file.path).catch(() => {});
      }
    })
  );

  return publicRouter;
}
