import { Router } from "express";
import { asyncHandler } from "../utils/asyncHandler.js";
import { validateSchema } from "../utils/validation.js";
import {
  auditFeedQuerySchema,
  createMonitorSchema,
  createWebhookSchema,
  listWebhookDeliveriesQuerySchema,
  startTrialSchema
} from "../validation/workspaceSchemas.js";

function toPublicWebhook(webhook) {
  return {
    id: webhook.id,
    name: webhook.name,
    targetUrl: webhook.targetUrl,
    events: Array.isArray(webhook.events) ? webhook.events : [],
    createdAt: webhook.createdAt,
    deletedAt: webhook.deletedAt || null,
    secretPreview: webhook.secret ? `${String(webhook.secret).slice(0, 8)}...` : null
  };
}

export function createWorkspaceRouter({
  workspaceService,
  requireAuth,
  requireAuthMethod,
  preventSensitiveCaching,
  scanQueueService
}) {
  const workspaceRouter = Router();
  const requireInteractiveAuth = [requireAuth, requireAuthMethod("bearer")];

  workspaceRouter.use(preventSensitiveCaching(), ...requireInteractiveAuth);

  workspaceRouter.get(
    "/summary",
    asyncHandler(async (req, res) => {
      const workspace = await workspaceService.getWorkspaceSnapshot(req.auth.user.id);
      res.json({ workspace });
    })
  );

  workspaceRouter.get(
    "/audit",
    asyncHandler(async (req, res) => {
      const { limit } = validateSchema(auditFeedQuerySchema, req.query || {});
      const events = await workspaceService.listAuditFeed(req.auth.user.id, limit);
      res.json({ events });
    })
  );

  workspaceRouter.post(
    "/trial/start",
    asyncHandler(async (req, res) => {
      validateSchema(startTrialSchema, req.body || {});
      const workspace = await workspaceService.startTrial(req.auth.user.id);
      await workspaceService.store.createAuditEvent?.({
        userId: req.auth.user.id,
        action: "workspace.trial.started",
        metadata: {
          planId: workspace?.profile?.effectivePlanId || null
        }
      });
      res.status(202).json({ workspace });
    })
  );

  workspaceRouter.get(
    "/monitors",
    asyncHandler(async (req, res) => {
      const monitors = await workspaceService.listMonitors(req.auth.user.id);
      res.json({ monitors });
    })
  );

  workspaceRouter.post(
    "/monitors",
    asyncHandler(async (req, res) => {
      const payload = validateSchema(createMonitorSchema, req.body || {});
      const monitor = await workspaceService.createMonitor(req.auth.user.id, payload);
      await workspaceService.store.createAuditEvent?.({
        userId: req.auth.user.id,
        action: "workspace.monitor.created",
        metadata: {
          monitorId: monitor.id,
          targetType: monitor.targetType
        }
      });
      res.status(201).json({ monitor });
    })
  );

  workspaceRouter.post(
    "/monitors/:monitorId/run",
    asyncHandler(async (req, res) => {
      const job = await workspaceService.runMonitorNow(req.auth.user, req.params.monitorId, {
        enqueueUrlScan: (params) => scanQueueService.enqueueUrlScan(params),
        enqueueWebsiteSafetyScan: (params) => scanQueueService.enqueueWebsiteSafetyScan(params)
      });
      res.status(202).json({ job });
    })
  );

  workspaceRouter.delete(
    "/monitors/:monitorId",
    asyncHandler(async (req, res) => {
      const monitor = await workspaceService.deleteMonitor(req.auth.user.id, req.params.monitorId);
      await workspaceService.store.createAuditEvent?.({
        userId: req.auth.user.id,
        action: "workspace.monitor.deleted",
        metadata: {
          monitorId: monitor?.id || req.params.monitorId
        }
      });
      res.json({ monitor, deleted: true });
    })
  );

  workspaceRouter.get(
    "/webhooks",
    asyncHandler(async (req, res) => {
      const webhooks = await workspaceService.listWebhooks(req.auth.user.id);
      res.json({ webhooks: webhooks.map(toPublicWebhook) });
    })
  );

  workspaceRouter.post(
    "/webhooks",
    asyncHandler(async (req, res) => {
      const payload = validateSchema(createWebhookSchema, req.body || {});
      const webhook = await workspaceService.createWebhook(req.auth.user.id, payload);
      await workspaceService.store.createAuditEvent?.({
        userId: req.auth.user.id,
        action: "workspace.webhook.created",
        metadata: {
          webhookId: webhook.id
        }
      });
      res.status(201).json({
        webhook: toPublicWebhook(webhook),
        signingSecret: webhook.secret
      });
    })
  );

  workspaceRouter.post(
    "/webhooks/:webhookId/test",
    asyncHandler(async (req, res) => {
      const delivery = await workspaceService.testWebhook(req.auth.user.id, req.params.webhookId);
      await workspaceService.store.createAuditEvent?.({
        userId: req.auth.user.id,
        action: "workspace.webhook.tested",
        metadata: {
          webhookId: req.params.webhookId,
          deliveryId: delivery?.id || null
        }
      });
      res.status(202).json({ delivery });
    })
  );

  workspaceRouter.delete(
    "/webhooks/:webhookId",
    asyncHandler(async (req, res) => {
      const webhook = await workspaceService.deleteWebhook(req.auth.user.id, req.params.webhookId);
      await workspaceService.store.createAuditEvent?.({
        userId: req.auth.user.id,
        action: "workspace.webhook.deleted",
        metadata: {
          webhookId: webhook?.id || req.params.webhookId
        }
      });
      res.json({ webhook: webhook ? toPublicWebhook(webhook) : null, deleted: true });
    })
  );

  workspaceRouter.get(
    "/webhooks/deliveries",
    asyncHandler(async (req, res) => {
      const { limit } = validateSchema(listWebhookDeliveriesQuerySchema, req.query || {});
      const deliveries = await workspaceService.listWebhookDeliveries(req.auth.user.id, limit);
      res.json({ deliveries });
    })
  );

  return workspaceRouter;
}
