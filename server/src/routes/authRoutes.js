import { Router } from "express";
import { asyncHandler } from "../utils/asyncHandler.js";
import { validateSchema } from "../utils/validation.js";
import { createApiKeySchema, loginSchema, refreshSchema, registerSchema } from "../validation/authSchemas.js";

export function createAuthRouter({ authService, requireAuth }) {
  const authRouter = Router();

  authRouter.post(
    "/register",
    asyncHandler(async (req, res) => {
      const payload = validateSchema(registerSchema, req.body);

      const result = await authService.register(payload, {
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"]
      });

      res.status(201).json(result);
    })
  );

  authRouter.post(
    "/login",
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
    asyncHandler(async (req, res) => {
      const payload = validateSchema(refreshSchema, req.body);

      await authService.logout(payload.refreshToken, {
        ipAddress: req.ip,
        userAgent: req.headers["user-agent"]
      });

      res.status(204).send();
    })
  );

  authRouter.get(
    "/me",
    requireAuth,
    asyncHandler(async (req, res) => {
      const user = await authService.getUserById(req.auth.user.id);
      const usage = await authService.getUsage(req.auth.user.id);

      res.json({ user, usage, authMethod: req.auth.method });
    })
  );

  authRouter.get(
    "/api-keys",
    requireAuth,
    asyncHandler(async (req, res) => {
      const keys = await authService.listApiKeys(req.auth.user.id);
      res.json({ keys });
    })
  );

  authRouter.post(
    "/api-keys",
    requireAuth,
    asyncHandler(async (req, res) => {
      const payload = validateSchema(createApiKeySchema, req.body);
      const result = await authService.createApiKey(req.auth.user.id, payload.name);
      res.status(201).json(result);
    })
  );

  authRouter.delete(
    "/api-keys/:keyId",
    requireAuth,
    asyncHandler(async (req, res) => {
      await authService.revokeApiKey(req.auth.user.id, req.params.keyId);
      res.status(204).send();
    })
  );

  return authRouter;
}
