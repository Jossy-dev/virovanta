import cors from "cors";
import express from "express";
import rateLimit from "express-rate-limit";
import fs from "fs/promises";
import helmet from "helmet";
import pino from "pino";
import pinoHttp from "pino-http";
import { RedisStore } from "rate-limit-redis";
import { config, isCorsOriginAllowed } from "../config.js";
import { createRedisClient } from "../infrastructure/redis/createRedisClient.js";
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
import { scanUploadedFile } from "../scanner/fileScanner.js";
import { scanTargetUrl } from "../scanner/urlScanner.js";
import { AuthService } from "../services/authService.js";
import { NotificationService } from "../services/notificationService.js";
import { ScanQueueService } from "../services/scanQueueService.js";
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
  const runtimeConfig = {
    ...config,
    ...(options.configOverrides || {})
  };
  const urlScanner =
    options.urlScanner ||
    (async ({ url }) =>
      scanTargetUrl({
        url,
        runtimeConfig,
        fileScanner: scanner
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

  const rateLimitRedisClient =
    runtimeConfig.rateLimitStore === "redis" ? createRedisClient(runtimeConfig, { purpose: "rate-limit" }) : null;

  const createRateLimitStore =
    rateLimitRedisClient != null
      ? (prefix) =>
          new RedisStore({
            prefix: `${runtimeConfig.serviceName}:${prefix}:`,
            sendCommand: (...args) => rateLimitRedisClient.call(...args)
          })
      : null;

  const authService = new AuthService({
    store,
    config: runtimeConfig,
    logger,
    notificationService: new NotificationService({
      store,
      logger
    })
  });

  const scanQueueService = new ScanQueueService({
    store,
    scanner,
    urlScanner,
    config: runtimeConfig,
    logger,
    objectStorageService,
    notificationService: authService.notificationService
  });

  await scanQueueService.start();

  const requireAuth = createAuthMiddleware(authService);
  const buildRateLimiter = ({ prefix, limit, windowMinutes }) =>
    rateLimit({
      windowMs: windowMinutes * 60 * 1000,
      limit,
      ...(createRateLimitStore ? { store: createRateLimitStore(prefix) } : {}),
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

  app.use(
    rateLimit({
      windowMs: runtimeConfig.requestWindowMinutes * 60 * 1000,
      limit: runtimeConfig.requestsPerWindow,
      ...(createRateLimitStore ? { store: createRateLimitStore("global") } : {}),
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

  app.get("/api/openapi.json", (_req, res) => {
    res.json(buildOpenApiSpec(runtimeConfig));
  });

  app.use(
    "/api/public",
    createPublicRouter({
      scanner,
      config: runtimeConfig,
      scanQueueService,
      createRateLimitStore,
      preventSensitiveCaching
    })
  );
  app.use(
    "/api/auth",
    createAuthRouter({
      authService,
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
      notificationService: authService.notificationService,
      preventSensitiveCaching,
      config: runtimeConfig
    })
  );
  app.use("/api/admin", createAdminRouter({ authService, requireAuth, requireAuthMethod, requireRole, preventSensitiveCaching }));

  app.use("/api", notFoundHandler);
  app.use(errorHandler(logger, runtimeConfig));

  app.locals.services = {
    store,
    authService,
    notificationService: authService.notificationService,
    scanQueueService,
    objectStorageService,
    rateLimitRedisClient,
    config: runtimeConfig
  };

  return {
    app,
    services: app.locals.services,
    logger,
    config: runtimeConfig
  };
}
