import { z } from "zod";

const MONITOR_TARGET_TYPES = ["url", "website"];
const WEBHOOK_EVENT_TYPES = [
  "report.ready",
  "report.deleted",
  "report.share.created",
  "report.share.revoked",
  "report.workflow.updated",
  "report.comment.created",
  "monitor.change.detected",
  "monitor.run.completed"
];

export const startTrialSchema = z.object({}).passthrough();

export const createMonitorSchema = z.object({
  name: z.string().trim().min(2).max(120),
  targetType: z.enum(MONITOR_TARGET_TYPES),
  target: z.string().trim().min(4).max(2048),
  cadenceHours: z.number().int().min(1).max(24 * 30).optional(),
  notes: z.string().trim().max(800).optional().default("")
});

export const createWebhookSchema = z.object({
  name: z.string().trim().min(2).max(120),
  url: z.string().trim().url().max(2048),
  events: z.array(z.enum(WEBHOOK_EVENT_TYPES)).min(1).max(WEBHOOK_EVENT_TYPES.length)
});

export const listWebhookDeliveriesQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).optional().default(20)
});

export const auditFeedQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).optional().default(20)
});

export const WEBHOOK_EVENT_VALUES = Object.freeze([...WEBHOOK_EVENT_TYPES]);
