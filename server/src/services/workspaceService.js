import crypto from "crypto";
import { HttpError } from "../utils/httpError.js";
import {
  buildStartedTrialProfile,
  buildWorkspaceEntitlements,
  buildWorkspaceSnapshot,
  createDefaultWorkspaceProfile
} from "../utils/workspaceEntitlements.js";

const DEFAULT_MONITOR_CADENCE_HOURS = 24;
const DEFAULT_WEBHOOK_TIMEOUT_MS = 8_000;

function toIsoOrNull(value) {
  if (!value) {
    return null;
  }

  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date.toISOString();
}

function normalizeMonitorTarget(target) {
  const trimmed = String(target || "").trim();
  if (!trimmed) {
    return "";
  }

  try {
    const parsed = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
    parsed.hash = "";
    return parsed.toString().replace(/\/+$/, "");
  } catch {
    return trimmed.toLowerCase();
  }
}

function buildMonitorSnapshot(report) {
  if (!report) {
    return null;
  }

  const redirects =
    Number(report?.websiteSafety?.modules?.redirects?.count) ||
    Number(report?.technicalIndicators?.redirectCount) ||
    0;
  const missingHeaders =
    Array.isArray(report?.websiteSafety?.modules?.headers?.missing)
      ? report.websiteSafety.modules.headers.missing.length
      : Array.isArray(report?.websiteSafety?.modules?.securityHeaders?.missing)
        ? report.websiteSafety.modules.securityHeaders.missing.length
        : 0;
  const exposures = Array.isArray(report?.websiteSafety?.modules?.vulnerabilityChecks?.exposures)
    ? report.websiteSafety.modules.vulnerabilityChecks.exposures.length
    : 0;

  return {
    verdict: report.verdict || "clean",
    riskScore: Number(report.riskScore) || 0,
    finalUrl: report?.url?.final || report?.websiteSafety?.url?.final || report?.url?.input || "",
    redirectCount: redirects,
    registrar: report?.websiteSafety?.modules?.dnsDomain?.registrar || null,
    registeredAt: report?.websiteSafety?.modules?.dnsDomain?.registeredAt || null,
    exposures,
    missingHeaders,
    flaggedIntelProviders: Array.isArray(report?.engines?.flaggedProviders) ? report.engines.flaggedProviders.length : 0
  };
}

function diffMonitorSnapshots(previousSnapshot, nextSnapshot) {
  if (!previousSnapshot || !nextSnapshot) {
    return {
      changed: false,
      summary: []
    };
  }

  const summary = [];

  if (previousSnapshot.verdict !== nextSnapshot.verdict) {
    summary.push(`Verdict changed from ${previousSnapshot.verdict} to ${nextSnapshot.verdict}.`);
  }

  if (previousSnapshot.riskScore !== nextSnapshot.riskScore) {
    summary.push(`Risk score changed from ${previousSnapshot.riskScore} to ${nextSnapshot.riskScore}.`);
  }

  if (previousSnapshot.finalUrl !== nextSnapshot.finalUrl) {
    summary.push("Final destination changed.");
  }

  if (previousSnapshot.redirectCount !== nextSnapshot.redirectCount) {
    summary.push(`Redirect count changed from ${previousSnapshot.redirectCount} to ${nextSnapshot.redirectCount}.`);
  }

  if (previousSnapshot.missingHeaders !== nextSnapshot.missingHeaders) {
    summary.push(`Missing security headers changed from ${previousSnapshot.missingHeaders} to ${nextSnapshot.missingHeaders}.`);
  }

  if (previousSnapshot.exposures !== nextSnapshot.exposures) {
    summary.push(`Sensitive exposure findings changed from ${previousSnapshot.exposures} to ${nextSnapshot.exposures}.`);
  }

  if (previousSnapshot.registrar !== nextSnapshot.registrar && nextSnapshot.registrar) {
    summary.push("Registrar metadata changed.");
  }

  return {
    changed: summary.length > 0,
    summary
  };
}

async function safeJson(response) {
  const contentType = String(response.headers.get("content-type") || "");
  if (!contentType.includes("application/json")) {
    return null;
  }

  try {
    return await response.json();
  } catch {
    return null;
  }
}

export class WorkspaceService {
  constructor({ store, config, logger, notificationService = null }) {
    this.store = store;
    this.config = config;
    this.logger = logger;
    this.notificationService = notificationService;
  }

  async getWorkspaceProfile(userId) {
    const existing = await this.store.getWorkspaceProfile(userId);
    if (existing) {
      return existing;
    }

    const created = createDefaultWorkspaceProfile(userId);
    await this.store.upsertWorkspaceProfile(created);
    return created;
  }

  async getWorkspaceSnapshot(userId) {
    const [profile, usage, counts] = await Promise.all([
      this.getWorkspaceProfile(userId),
      this.store.getUsageSnapshot({
        userId,
        limit: this.config.freeTierDailyScanLimit
      }),
      this.store.getWorkspaceCounts(userId)
    ]);

    return buildWorkspaceSnapshot({
      profile,
      config: this.config,
      usage,
      counts,
      now: new Date()
    });
  }

  async startTrial(userId) {
    const profile = await this.getWorkspaceProfile(userId);
    const entitlements = buildWorkspaceEntitlements(profile, this.config, new Date());

    if (entitlements.trial.status === "active") {
      throw new HttpError(409, "Trial is already active.", {
        code: "WORKSPACE_TRIAL_ALREADY_ACTIVE"
      });
    }

    if (entitlements.trial.status === "converted") {
      throw new HttpError(409, "Trial is no longer available for this workspace.", {
        code: "WORKSPACE_TRIAL_UNAVAILABLE"
      });
    }

    const nextProfile = buildStartedTrialProfile(profile, new Date());
    await this.store.upsertWorkspaceProfile(nextProfile);

    await this.notificationService?.create({
      userId,
      type: "trial_started",
      tone: "success",
      title: "Pro trial started",
      detail: `Your ${entitlements.trial.trialPlanId || "pro"} trial is now active.`,
      entityType: "workspace",
      entityId: nextProfile.id,
      dedupeKey: `workspace-trial:${userId}:${nextProfile.trialStartedAt}`
    });

    return this.getWorkspaceSnapshot(userId);
  }

  async listAuditFeed(userId, limit = 50) {
    return this.store.listAuditEventsForUser(userId, limit);
  }

  async listMonitors(userId) {
    return this.store.listMonitorsForUser(userId);
  }

  async createMonitor(userId, input) {
    const [profile, counts] = await Promise.all([this.getWorkspaceProfile(userId), this.store.getWorkspaceCounts(userId)]);
    const entitlements = buildWorkspaceEntitlements(profile, this.config, new Date());

    if (Number(entitlements.limits.monitors) >= 0 && counts.monitorsActive >= entitlements.limits.monitors) {
      throw new HttpError(429, "Monitor limit reached for the current workspace plan.", {
        code: "WORKSPACE_MONITOR_LIMIT_REACHED",
        details: {
          limit: entitlements.limits.monitors,
          used: counts.monitorsActive
        }
      });
    }

    const now = new Date();
    const cadenceHours = Math.max(1, Math.floor(Number(input?.cadenceHours) || DEFAULT_MONITOR_CADENCE_HOURS));
    const monitor = await this.store.createMonitor({
      userId,
      name: String(input?.name || "").trim(),
      targetType: input?.targetType,
      target: String(input?.target || "").trim(),
      normalizedTarget: normalizeMonitorTarget(input?.target),
      cadenceHours,
      notes: String(input?.notes || "").trim(),
      nextCheckAt: new Date(now.getTime() + cadenceHours * 60 * 60 * 1000).toISOString(),
      createdAt: now.toISOString()
    });

    await this.notificationService?.create({
      userId,
      type: "monitor_created",
      tone: "info",
      title: "Monitor added",
      detail: `${monitor.name} is now being tracked for changes.`,
      entityType: "monitor",
      entityId: monitor.id,
      dedupeKey: `monitor-created:${monitor.id}`
    });

    return monitor;
  }

  async deleteMonitor(userId, monitorId) {
    const monitor = await this.store.deleteMonitor({
      userId,
      monitorId,
      deletedAt: new Date().toISOString()
    });

    if (!monitor) {
      throw new HttpError(404, "Monitor not found.", {
        code: "MONITOR_NOT_FOUND"
      });
    }

    return monitor;
  }

  async runMonitorNow(user, monitorId, { enqueueUrlScan, enqueueWebsiteSafetyScan }) {
    const monitor = await this.store.findMonitorById(monitorId);
    if (!monitor || monitor.userId !== user.id) {
      throw new HttpError(404, "Monitor not found.", {
        code: "MONITOR_NOT_FOUND"
      });
    }

    if (monitor.targetType === "website") {
      return enqueueWebsiteSafetyScan({
        userId: user.id,
        url: monitor.target
      });
    }

    return enqueueUrlScan({
      userId: user.id,
      url: monitor.target
    });
  }

  async dispatchDueMonitors({ limit = 10, enqueueUrlScan, enqueueWebsiteSafetyScan }) {
    const monitors = await this.store.claimDueMonitors({
      now: new Date().toISOString(),
      limit
    });

    if (!Array.isArray(monitors) || monitors.length === 0) {
      return {
        claimed: 0,
        enqueued: 0,
        jobs: [],
        monitors: []
      };
    }

    const jobs = [];
    for (const monitor of monitors) {
      const enqueue =
        monitor.targetType === "website"
          ? enqueueWebsiteSafetyScan
          : enqueueUrlScan;

      if (typeof enqueue !== "function") {
        continue;
      }

      try {
        const job = await enqueue({
          userId: monitor.userId,
          url: monitor.target
        });
        jobs.push({
          monitorId: monitor.id,
          targetType: monitor.targetType,
          job
        });
      } catch (error) {
        this.logger.warn({ err: error, monitorId: monitor.id }, "Could not enqueue due monitor run");
      }
    }

    return {
      claimed: monitors.length,
      enqueued: jobs.length,
      jobs,
      monitors
    };
  }

  async listWebhooks(userId) {
    return this.store.listWebhooksForUser(userId);
  }

  async listWebhookDeliveries(userId, limit = 20) {
    return this.store.listWebhookDeliveriesForUser(userId, limit);
  }

  async createWebhook(userId, input) {
    const [profile, counts] = await Promise.all([this.getWorkspaceProfile(userId), this.store.getWorkspaceCounts(userId)]);
    const entitlements = buildWorkspaceEntitlements(profile, this.config, new Date());

    if (Number(entitlements.limits.webhooks) >= 0 && counts.webhooksActive >= entitlements.limits.webhooks) {
      throw new HttpError(429, "Webhook limit reached for the current workspace plan.", {
        code: "WORKSPACE_WEBHOOK_LIMIT_REACHED",
        details: {
          limit: entitlements.limits.webhooks,
          used: counts.webhooksActive
        }
      });
    }

    const secret = crypto.randomBytes(24).toString("hex");
    return this.store.createWebhook({
      userId,
      name: String(input?.name || "").trim(),
      targetUrl: String(input?.url || "").trim(),
      events: Array.isArray(input?.events) ? input.events : [],
      secret,
      createdAt: new Date().toISOString()
    });
  }

  async deleteWebhook(userId, webhookId) {
    const removed = await this.store.deleteWebhook({
      userId,
      webhookId,
      deletedAt: new Date().toISOString()
    });

    if (!removed) {
      throw new HttpError(404, "Webhook endpoint not found.", {
        code: "WEBHOOK_NOT_FOUND"
      });
    }

    return removed;
  }

  async dispatchEvent({ userId, eventType, payload, entityType = null, entityId = null }) {
    const webhooks = await this.store.listWebhooksForUser(userId);
    const activeWebhooks = webhooks.filter((webhook) => !webhook.deletedAt && Array.isArray(webhook.events) && webhook.events.includes(eventType));

    if (activeWebhooks.length === 0) {
      return {
        dispatched: 0
      };
    }

    const deliveries = [];
    for (const webhook of activeWebhooks) {
      deliveries.push(await this.#deliverWebhook(webhook, { eventType, payload, entityType, entityId }));
    }

    return {
      dispatched: deliveries.length,
      deliveries
    };
  }

  async testWebhook(userId, webhookId) {
    const webhook = await this.store.findWebhookById(webhookId);
    if (!webhook || webhook.userId !== userId || webhook.deletedAt) {
      throw new HttpError(404, "Webhook endpoint not found.", {
        code: "WEBHOOK_NOT_FOUND"
      });
    }

    return this.#deliverWebhook(webhook, {
      eventType: "monitor.run.completed",
      payload: {
        sample: true,
        message: "This is a test delivery from ViroVanta."
      },
      entityType: "webhook",
      entityId: webhook.id
    });
  }

  async recordCompletedReport(report) {
    if (!report?.ownerUserId || (report?.sourceType !== "url" && report?.sourceType !== "website")) {
      return;
    }

    const target = normalizeMonitorTarget(report?.url?.input || report?.url?.final || report?.websiteSafety?.url?.input || "");
    if (!target) {
      return;
    }

    const monitors = await this.store.listMatchingMonitors({
      userId: report.ownerUserId,
      normalizedTargets: [target, normalizeMonitorTarget(report?.url?.final)]
    });

    if (monitors.length === 0) {
      await this.dispatchEvent({
        userId: report.ownerUserId,
        eventType: "report.ready",
        payload: {
          reportId: report.id,
          verdict: report.verdict,
          riskScore: report.riskScore,
          sourceType: report.sourceType,
          target: report?.url?.final || report?.url?.input || report?.fileName || report?.file?.originalName || null
        },
        entityType: "report",
        entityId: report.id
      });
      return;
    }

    const snapshot = buildMonitorSnapshot(report);
    for (const monitor of monitors) {
      const diff = diffMonitorSnapshots(monitor.lastSnapshot, snapshot);
      const updated = await this.store.updateMonitorSnapshot({
        monitorId: monitor.id,
        reportId: report.id,
        verdict: report.verdict,
        riskScore: report.riskScore,
        snapshot,
        lastChangeSummary: diff.summary,
        checkedAt: new Date().toISOString(),
        nextCheckAt: new Date(Date.now() + (Number(monitor.cadenceHours) || DEFAULT_MONITOR_CADENCE_HOURS) * 60 * 60 * 1000).toISOString()
      });

      if (diff.changed) {
        await this.notificationService?.create({
          userId: monitor.userId,
          type: "monitor_change_detected",
          tone: report.verdict === "malicious" ? "danger" : report.verdict === "suspicious" ? "warning" : "info",
          title: "Monitored target changed",
          detail: `${monitor.name} changed since the last run. ${diff.summary[0] || "Review the updated report."}`,
          entityType: "monitor",
          entityId: monitor.id,
          dedupeKey: `monitor-change:${monitor.id}:${report.id}`
        });

        await this.dispatchEvent({
          userId: monitor.userId,
          eventType: "monitor.change.detected",
          payload: {
            monitorId: monitor.id,
            reportId: report.id,
            changes: diff.summary,
            verdict: report.verdict,
            riskScore: report.riskScore
          },
          entityType: "monitor",
          entityId: monitor.id
        });
      }

      await this.dispatchEvent({
        userId: monitor.userId,
        eventType: "monitor.run.completed",
        payload: {
          monitorId: monitor.id,
          reportId: report.id,
          verdict: report.verdict,
          riskScore: report.riskScore,
          changed: diff.changed,
          changes: diff.summary
        },
        entityType: "monitor",
        entityId: updated?.id || monitor.id
      });
    }

    await this.dispatchEvent({
      userId: report.ownerUserId,
      eventType: "report.ready",
      payload: {
        reportId: report.id,
        verdict: report.verdict,
        riskScore: report.riskScore,
        sourceType: report.sourceType,
        target: report?.url?.final || report?.url?.input || report?.fileName || report?.file?.originalName || null
      },
      entityType: "report",
      entityId: report.id
    });
  }

  async #deliverWebhook(webhook, eventEnvelope) {
    const deliveredAt = new Date().toISOString();
    const body = {
      id: `evt_${crypto.randomUUID()}`,
      type: eventEnvelope.eventType,
      createdAt: deliveredAt,
      entityType: eventEnvelope.entityType || null,
      entityId: eventEnvelope.entityId || null,
      data: eventEnvelope.payload || {}
    };
    const serializedBody = JSON.stringify(body);
    const signature = crypto.createHmac("sha256", String(webhook.secret || "")).update(serializedBody).digest("hex");

    let response = null;
    let statusCode = null;
    let responseBody = null;
    let errorMessage = null;

    try {
      response = await fetch(webhook.targetUrl, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-virovanta-signature": signature,
          "x-virovanta-event": eventEnvelope.eventType
        },
        body: serializedBody,
        signal: AbortSignal.timeout(DEFAULT_WEBHOOK_TIMEOUT_MS)
      });
      statusCode = response.status;
      responseBody = await safeJson(response);
      if (!response.ok) {
        errorMessage = `Webhook returned ${response.status}.`;
      }
    } catch (error) {
      errorMessage = error?.message || "Webhook delivery failed.";
      this.logger.warn({ err: error, webhookId: webhook.id }, "Webhook delivery failed");
    }

    const delivery = await this.store.createWebhookDelivery({
      webhookId: webhook.id,
      userId: webhook.userId,
      eventType: eventEnvelope.eventType,
      requestBody: body,
      responseStatus: statusCode,
      responseBody,
      errorMessage,
      deliveredAt
    });

    return delivery;
  }
}
