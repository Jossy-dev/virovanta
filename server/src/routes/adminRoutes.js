import { Router } from "express";
import { asyncHandler } from "../utils/asyncHandler.js";

export function createAdminRouter({
  authService,
  requireAuth,
  requireAuthMethod,
  requireRole,
  preventSensitiveCaching,
  runtimeInfoProvider = null
}) {
  const adminRouter = Router();

  adminRouter.use(requireAuth, requireAuthMethod("bearer"), requireRole("admin"), preventSensitiveCaching());

  adminRouter.get(
    "/metrics",
    asyncHandler(async (_req, res) => {
      const [metrics, runtime] = await Promise.all([
        authService.getAdminMetrics(),
        runtimeInfoProvider ? runtimeInfoProvider() : Promise.resolve(null)
      ]);

      res.json(runtime ? { metrics, runtime } : { metrics });
    })
  );

  adminRouter.get(
    "/audit",
    asyncHandler(async (req, res) => {
      const limit = Number(req.query.limit) || 100;
      const events = await authService.listAuditEvents(limit);
      res.json({ events });
    })
  );

  return adminRouter;
}
