import cors from "cors";
import express from "express";
import rateLimit from "express-rate-limit";
import fs from "fs/promises";
import helmet from "helmet";
import pino from "pino";
import pinoHttp from "pino-http";
import { config, isCorsOriginAllowed, mergeRuntimeConfig, resolveServiceMode, validateRuntimeConfig } from "../config.js";
import {
  createAuthMiddleware,
  preventSensitiveCaching,
  requireApiKeyScopes,
  requireAuthMethod,
  requireRole
} from "../middleware/authMiddleware.js";
import { errorHandler, notFoundHandler } from "../middleware/errorHandler.js";
import { requestContext } from "../middleware/requestContext.js";
import { createAdminRouter } from "../routes/adminRoutes.js";
import { createAuthRouter } from "../routes/authRoutes.js";
import { createPublicRouter } from "../routes/publicRoutes.js";
import { createScanRouter } from "../routes/scanRoutes.js";
import { createWorkspaceRouter } from "../routes/workspaceRoutes.js";
import { scanUploadedFile } from "../scanner/fileScanner.js";
import { scanTargetUrl } from "../scanner/urlScanner.js";
import { scanWebsiteSafetyTarget } from "../scanner/websiteSafetyScanner.js";
import { AuthService } from "../services/authService.js";
import { NotificationService } from "../services/notificationService.js";
import { ScanQueueService } from "../services/scanQueueService.js";
import { WorkspaceService } from "../services/workspaceService.js";
import { ObjectStorageService } from "../services/storage/objectStorageService.js";
import { PersistentStore } from "../store/persistentStore.js";

function buildOpenApiSpec(runtimeConfig) {
  return {
    openapi: "3.1.0",
    info: {
      title: runtimeConfig.apiTitle,
      version: runtimeConfig.apiVersion,
      description: "Authenticated file-scanning API with async job processing and structured threat reports."
    },
    servers: [
      {
        url: runtimeConfig.apiBaseUrl
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
  const runtimeConfig = validateRuntimeConfig(mergeRuntimeConfig(config, options.configOverrides || {}));
  const urlScanner =
    options.urlScanner ||
    (async ({ url }) =>
      scanTargetUrl({
        url,
        runtimeConfig,
        fileScanner: scanner
      }));
  const websiteSafetyScanner =
    options.websiteSafetyScanner ||
    (async ({ url }) =>
      scanWebsiteSafetyTarget({
        url,
        runtimeConfig
      }));

  const logger = options.logger || pino({ level: runtimeConfig.logLevel });

  const store = new PersistentStore({
    filePath: options.dataFilePath || runtimeConfig.dataFilePath,
    reportTtlMs: runtimeConfig.reportTtlMs,
    maxReports: runtimeConfig.scanHistoryLimit,
    driver: runtimeConfig.dataStoreDriver,
    databaseUrl: runtimeConfig.databaseUrl,
    databaseSsl: runtimeConfig.databaseSsl,
    databaseSslRejectUnauthorized: runtimeConfig.databaseSslRejectUnauthorized,
    stateTable: runtimeConfig.stateStoreTable
  });

  await fs.mkdir(runtimeConfig.uploadDir, { recursive: true });
  await store.init();

  const objectStorageService = new ObjectStorageService({
    config: runtimeConfig,
    logger
  });

  const authService = new AuthService({
    store,
    config: runtimeConfig,
    logger,
    notificationService: new NotificationService({
      store,
      logger
    })
  });

  const workspaceService = new WorkspaceService({
    store,
    config: runtimeConfig,
    logger,
    notificationService: authService.notificationService
  });

  const scanQueueService = new ScanQueueService({
    store,
    scanner,
    urlScanner,
    websiteSafetyScanner,
    config: runtimeConfig,
    logger,
    objectStorageService,
    notificationService: authService.notificationService,
    workspaceService
  });

  const startQueueService = async () => scanQueueService.start();

  const shouldAwaitQueueStartup =
    !runtimeConfig.runApiServer || runtimeConfig.queueProvider === "local" || runtimeConfig.runScanWorker;

  if (!shouldAwaitQueueStartup && runtimeConfig.runApiServer) {
    startQueueService().catch((error) => {
      logger.error(
        {
          err: error
        },
        "Scan queue failed to initialize. API will continue in degraded mode."
      );
    });
  } else {
    await startQueueService();
  }

  async function collectRuntimeState() {
    const [storeStatus, queueStatus] = await Promise.all([
      store.getOperationalStatus().catch((error) => ({
        status: "error",
        ready: false,
        driver: runtimeConfig.dataStoreDriver,
        alerts: [
          {
            component: "store",
            severity: "error",
            message: error?.message || "Store health check failed.",
            code: error?.code || null,
            occurredAt: new Date().toISOString()
          }
        ]
      })),
      Promise.resolve(scanQueueService.getOperationalStatus())
    ]);
    const objectStorageStatus = objectStorageService.getOperationalStatus();
    const rateLimitStatus = {
      status: "ok",
      ready: true,
      store: "memory",
      connectionState: "memory"
    };

    const alerts = [...(storeStatus.alerts || []), ...(queueStatus.alerts || [])];

    const ready = Boolean(storeStatus.ready) && Boolean(queueStatus.ready) && Boolean(rateLimitStatus.ready);

    return {
      status: ready ? "ok" : "degraded",
      ready,
      mode: resolveServiceMode(runtimeConfig),
      service: runtimeConfig.serviceName,
      version: runtimeConfig.apiVersion,
      uptimeSeconds: Number(process.uptime().toFixed(1)),
      components: {
        store: storeStatus,
        queue: queueStatus,
        objectStorage: objectStorageStatus,
        rateLimit: rateLimitStatus
      },
      alerts
    };
  }

  const requireAuth = createAuthMiddleware(authService);
  const buildRateLimiter = ({ limit, windowMinutes }) =>
    rateLimit({
      windowMs: windowMinutes * 60 * 1000,
      limit,
      standardHeaders: true,
      legacyHeaders: false
    });

  const authRateLimiters = {
    login: buildRateLimiter({
      prefix: "auth-login",
      limit: runtimeConfig.authLoginRequestsPerWindow,
      windowMinutes: runtimeConfig.authRateLimitWindowMinutes
    }),
    mutation: buildRateLimiter({
      prefix: "auth-mutation",
      limit: runtimeConfig.authMutationRequestsPerWindow,
      windowMinutes: runtimeConfig.authRateLimitWindowMinutes
    }),
    lookup: buildRateLimiter({
      prefix: "auth-lookup",
      limit: runtimeConfig.authLookupRequestsPerWindow,
      windowMinutes: runtimeConfig.authRateLimitWindowMinutes
    })
  };

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
        if (isCorsOriginAllowed(origin, runtimeConfig.corsOrigins)) {
          return callback(null, true);
        }

        return callback(new Error("CORS origin denied"));
      },
      methods: ["GET", "POST", "DELETE"],
      allowedHeaders: ["Content-Type", "Authorization", "x-api-key", "x-request-id"],
      maxAge: 600
    })
  );

  const sendPingResponse = (res) => {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.type("text/plain").status(200).send("pong");
  };

  app.get("/ping", (_req, res) => {
    sendPingResponse(res);
  });

  app.get("/api/ping", (_req, res) => {
    sendPingResponse(res);
  });

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
    res.json({
      status: "ok",
      service: runtimeConfig.serviceName,
      version: runtimeConfig.apiVersion,
      uptimeSeconds: Number(process.uptime().toFixed(1))
    });
  });

  app.get("/api/health/live", async (_req, res) => {
    res.json({
      status: "ok",
      mode: resolveServiceMode(runtimeConfig),
      service: runtimeConfig.serviceName,
      version: runtimeConfig.apiVersion,
      uptimeSeconds: Number(process.uptime().toFixed(1))
    });
  });

  app.get("/api/health/ready", async (_req, res) => {
    const runtime = await collectRuntimeState();
    res.status(runtime.ready ? 200 : 503).json(runtime);
  });

  app.get("/api/openapi.json", (_req, res) => {
    res.json(buildOpenApiSpec(runtimeConfig));
  });

  app.use(
    "/api/public",
    createPublicRouter({
      scanner,
      config: runtimeConfig,
      scanQueueService,
      store,
      preventSensitiveCaching
    })
  );
  app.use(
    "/api/auth",
    createAuthRouter({
      authService,
      workspaceService,
      requireAuth,
      requireAuthMethod,
      preventSensitiveCaching,
      rateLimiters: authRateLimiters,
      config: runtimeConfig
    })
  );
  app.use(
    "/api/scans",
    createScanRouter({
      requireAuth,
      requireApiKeyScopes,
      scanQueueService,
      authService,
      workspaceService,
      notificationService: authService.notificationService,
      preventSensitiveCaching,
      config: runtimeConfig
    })
  );
  app.use(
    "/api/workspace",
    createWorkspaceRouter({
      workspaceService,
      requireAuth,
      requireAuthMethod,
      preventSensitiveCaching,
      scanQueueService
    })
  );
  app.use(
    "/api/admin",
    createAdminRouter({
      authService,
      requireAuth,
      requireAuthMethod,
      requireRole,
      preventSensitiveCaching,
      runtimeInfoProvider: collectRuntimeState
    })
  );

  app.use("/api", notFoundHandler);
  app.use(errorHandler(logger, runtimeConfig));

  app.locals.services = {
    store,
    authService,
    notificationService: authService.notificationService,
    scanQueueService,
    workspaceService,
    objectStorageService,
    config: runtimeConfig,
    runtimeInfoProvider: collectRuntimeState
  };

  return {
    app,
    services: app.locals.services,
    logger,
    config: runtimeConfig
  };
}
