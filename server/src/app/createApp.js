import cors from "cors";
import express from "express";
import rateLimit from "express-rate-limit";
import fs from "fs/promises";
import helmet from "helmet";
import pino from "pino";
import pinoHttp from "pino-http";
import { config, isCorsOriginAllowed } from "../config.js";
import { createAuthMiddleware, requireRole } from "../middleware/authMiddleware.js";
import { errorHandler, notFoundHandler } from "../middleware/errorHandler.js";
import { requestContext } from "../middleware/requestContext.js";
import { createAdminRouter } from "../routes/adminRoutes.js";
import { createAuthRouter } from "../routes/authRoutes.js";
import { createPublicRouter } from "../routes/publicRoutes.js";
import { createScanRouter } from "../routes/scanRoutes.js";
import { scanUploadedFile } from "../scanner/fileScanner.js";
import { AuthService } from "../services/authService.js";
import { ScanQueueService } from "../services/scanQueueService.js";
import { PersistentStore } from "../store/persistentStore.js";

function buildOpenApiSpec() {
  return {
    openapi: "3.1.0",
    info: {
      title: "ViroVanta API",
      version: "2.0.0",
      description: "Authenticated file-scanning API with async job processing and structured threat reports."
    },
    servers: [
      {
        url: "http://localhost:3001"
      }
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer"
        },
        apiKeyAuth: {
          type: "apiKey",
          in: "header",
          name: "x-api-key"
        }
      }
    }
  };
}

export async function createApp(options = {}) {
  const scanner = options.scanner || scanUploadedFile;
  const runtimeConfig = {
    ...config,
    ...(options.configOverrides || {})
  };

  const logger = options.logger || pino({ level: runtimeConfig.logLevel });

  const store = new PersistentStore({
    filePath: options.dataFilePath || runtimeConfig.dataFilePath,
    reportTtlMs: runtimeConfig.reportTtlMs,
    maxReports: runtimeConfig.scanHistoryLimit
  });

  await fs.mkdir(runtimeConfig.uploadDir, { recursive: true });
  await store.init();

  const authService = new AuthService({
    store,
    config: runtimeConfig,
    logger
  });

  const scanQueueService = new ScanQueueService({
    store,
    scanner,
    config: runtimeConfig,
    logger
  });

  await scanQueueService.start();

  const requireAuth = createAuthMiddleware(authService);

  const app = express();

  app.disable("x-powered-by");
  app.set("trust proxy", 1);

  app.use(requestContext);
  app.use(
    pinoHttp({
      logger,
      quietReqLogger: true,
      customProps(req) {
        return {
          requestId: req.requestId
        };
      }
    })
  );

  app.use(
    helmet({
      crossOriginResourcePolicy: false,
      referrerPolicy: {
        policy: "no-referrer"
      }
    })
  );

  app.use(
    cors({
      origin(origin, callback) {
        if (isCorsOriginAllowed(origin)) {
          return callback(null, true);
        }

        return callback(new Error("CORS origin denied"));
      },
      methods: ["GET", "POST", "DELETE"],
      allowedHeaders: ["Content-Type", "Authorization", "x-api-key", "x-request-id"],
      maxAge: 600
    })
  );

  app.use(
    rateLimit({
      windowMs: runtimeConfig.requestWindowMinutes * 60 * 1000,
      limit: runtimeConfig.requestsPerWindow,
      standardHeaders: true,
      legacyHeaders: false
    })
  );

  app.use(express.json({ limit: "256kb" }));

  app.get("/api/health", async (_req, res) => {
    const metrics = await authService.getAdminMetrics();

    res.json({
      status: "ok",
      service: "virovanta",
      version: "2.0.0",
      uptimeSeconds: Number(process.uptime().toFixed(1)),
      capabilities: {
        auth: true,
        apiKeys: true,
        asyncScanQueue: true,
        clamavEnabled: runtimeConfig.enableClamAv,
        virusTotalEnabled: Boolean(runtimeConfig.virusTotalApiKey)
      },
      metrics
    });
  });

  app.get("/api/openapi.json", (_req, res) => {
    res.json(buildOpenApiSpec());
  });

  app.use(
    "/api/public",
    createPublicRouter({
      scanner,
      config: runtimeConfig,
      scanQueueService
    })
  );
  app.use("/api/auth", createAuthRouter({ authService, requireAuth }));
  app.use(
    "/api/scans",
    createScanRouter({
      requireAuth,
      scanQueueService,
      authService,
      config: runtimeConfig
    })
  );
  app.use("/api/admin", createAdminRouter({ authService, requireAuth, requireRole }));

  app.use("/api", notFoundHandler);
  app.use(errorHandler(logger, runtimeConfig));

  app.locals.services = {
    store,
    authService,
    scanQueueService,
    config: runtimeConfig
  };

  return {
    app,
    services: app.locals.services,
    logger,
    config: runtimeConfig
  };
}
