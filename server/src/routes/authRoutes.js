import { Router } from "express";
import { asyncHandler } from "../utils/asyncHandler.js";
import { validateSchema } from "../utils/validation.js";
import {
  createApiKeySchema,
  forgotPasswordSchema,
  loginSchema,
  logoutSchema,
  markNotificationsReadSchema,
  notificationsQuerySchema,
  resetPasswordSchema,
  refreshSchema,
  registerSchema,
  usernameAvailabilityQuerySchema
} from "../validation/authSchemas.js";

export function createAuthRouter({ authService, workspaceService, requireAuth, requireAuthMethod, preventSensitiveCaching, rateLimiters, config }) {
  const authRouter = Router();
  const requireInteractiveAuth = [requireAuth, requireAuthMethod("bearer")];

  authRouter.use(preventSensitiveCaching());

  authRouter.post(
    "/register",
    rateLimiters.mutation,
    asyncHandler(async (req, res) => {
      const payload = validateSchema(registerSchema, req.body);

      const result = await authService.register(payload, {
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"]
      });

      const statusCode = result?.requiresEmailConfirmation ? 202 : 201;
      res.status(statusCode).json(result);
    })
  );

  authRouter.post(
    "/login",
    rateLimiters.login,
    asyncHandler(async (req, res) => {
      const payload = validateSchema(loginSchema, req.body);
      const result = await authService.login(payload, {
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"]
      });

      res.json(result);
    })
  );

  authRouter.post(
    "/refresh",
    rateLimiters.mutation,
    asyncHandler(async (req, res) => {
      const payload = validateSchema(refreshSchema, req.body);

      const result = await authService.refreshSession(payload.refreshToken, {
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"]
      });

      res.json(result);
    })
  );

  authRouter.post(
    "/logout",
    rateLimiters.mutation,
    asyncHandler(async (req, res) => {
      const payload = validateSchema(logoutSchema, req.body || {});

      await authService.logout(
        {
          refreshToken: payload.refreshToken || null,
          accessToken: req.headers.authorization?.match(/^Bearer\s+(.+)$/i)?.[1] || null
        },
        {
          ipAddress: req.ip,
          userAgent: req.headers["user-agent"]
        }
      );

      res.status(204).send();
    })
  );

  authRouter.post(
    "/forgot-password",
    rateLimiters.mutation,
    asyncHandler(async (req, res) => {
      const payload = validateSchema(forgotPasswordSchema, req.body);

      await authService.requestPasswordReset(payload.email, {
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"]
      });

      res.status(202).json({
        accepted: true,
        message: "If the email exists, reset instructions will be sent."
      });
    })
  );

  authRouter.post(
    "/reset-password",
    rateLimiters.mutation,
    asyncHandler(async (req, res) => {
      const payload = validateSchema(resetPasswordSchema, req.body);

      const result = await authService.resetPassword(payload, {
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"]
      });

      res.status(200).json(result);
    })
  );

  authRouter.get(
    "/username-availability",
    rateLimiters.lookup,
    asyncHandler(async (req, res) => {
      const payload = validateSchema(usernameAvailabilityQuerySchema, req.query || {});
      const result = await authService.checkUsernameAvailability(payload.username);
      res.json(result);
    })
  );

  authRouter.get(
    "/me",
    requireAuth,
    asyncHandler(async (req, res) => {
      const user = await authService.getUserById(req.auth.user.id);
      const usage = await authService.getUsage(req.auth.user.id);
      const workspace = workspaceService ? await workspaceService.getWorkspaceSnapshot(req.auth.user.id) : null;

      res.json({
        user,
        usage,
        workspace,
        authMethod: req.auth.method,
        scanLimits: {
          maxFilesPerBatch: config.maxBatchUploadFiles,
          maxUploadMb: Math.round(config.maxUploadBytes / (1024 * 1024))
        }
      });
    })
  );

  authRouter.get(
    "/notifications",
    ...requireInteractiveAuth,
    asyncHandler(async (req, res) => {
      const payload = validateSchema(notificationsQuerySchema, req.query || {});
      const result = await authService.listNotifications(req.auth.user.id, payload.limit, payload.offset);
      res.json(result);
    })
  );

  authRouter.post(
    "/notifications/read",
    ...requireInteractiveAuth,
    asyncHandler(async (req, res) => {
      const payload = validateSchema(markNotificationsReadSchema, req.body || {});
      const result = await authService.markNotificationsRead(req.auth.user.id, payload.ids);
      res.json(result);
    })
  );

  authRouter.get(
    "/api-keys",
    ...requireInteractiveAuth,
    asyncHandler(async (req, res) => {
      const keys = await authService.listApiKeys(req.auth.user.id);
      res.json({ keys });
    })
  );

  authRouter.post(
    "/api-keys",
    ...requireInteractiveAuth,
    asyncHandler(async (req, res) => {
      const payload = validateSchema(createApiKeySchema, req.body);
      const result = await authService.createApiKey(req.auth.user.id, payload.name, payload.scopes);
      res.status(201).json(result);
    })
  );

  authRouter.delete(
    "/api-keys/:keyId",
    ...requireInteractiveAuth,
    asyncHandler(async (req, res) => {
      await authService.revokeApiKey(req.auth.user.id, req.params.keyId);
      res.status(204).send();
    })
  );

  return authRouter;
}
