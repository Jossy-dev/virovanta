import { isIP } from "node:net";
import { z } from "zod";

const MONITOR_TARGET_TYPES = ["url", "website"];
const MONITOR_STATUS_VALUES = ["active", "paused"];
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

function isValidMonitorTarget(value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) {
    return false;
  }

  try {
    const parsed = new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
    const hostname = String(parsed.hostname || "").trim().toLowerCase();
    const hasQualifiedHostname = hostname.includes(".") || hostname === "localhost" || isIP(hostname) !== 0;
    return ["http:", "https:"].includes(parsed.protocol) && Boolean(hostname) && hasQualifiedHostname;
  } catch {
    return false;
  }
}

export const createMonitorSchema = z
  .object({
    name: z.string().trim().min(2, "Name must be at least 2 characters.").max(120),
    targetType: z.enum(MONITOR_TARGET_TYPES),
    target: z.string().trim().max(2048),
    cadenceHours: z.number().int().min(1).max(24 * 30).optional(),
    notes: z.string().trim().max(800).optional().default("")
  })
  .superRefine((value, context) => {
    const normalizedTarget = String(value.target || "").trim();
    const targetLabel = value.targetType === "website" ? "Website target" : "URL target";

    if (!normalizedTarget) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["target"],
        message: `${targetLabel} is required.`
      });
      return;
    }

    if (!isValidMonitorTarget(normalizedTarget)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["target"],
        message:
          value.targetType === "website"
            ? "Enter a valid website URL or hostname."
            : "Enter a valid URL or hostname."
      });
    }
  });

export const updateMonitorStatusSchema = z.object({
  status: z.enum(MONITOR_STATUS_VALUES)
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
