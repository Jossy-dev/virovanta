import { Router } from "express";
import { asyncHandler } from "../utils/asyncHandler.js";

export function createAdminRouter({ authService, requireAuth, requireRole }) {
  const adminRouter = Router();

  adminRouter.use(requireAuth, requireRole("admin"));

  adminRouter.get(
    "/metrics",
    asyncHandler(async (_req, res) => {
      const metrics = await authService.getAdminMetrics();
      res.json({ metrics });
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
