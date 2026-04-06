import { z } from "zod";

export const SCAN_SOURCE_TYPES = Object.freeze(["file", "url", "website"]);

export const scanSourceTypeSchema = z.enum(SCAN_SOURCE_TYPES);

export const paginationSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20),
  sourceType: scanSourceTypeSchema.optional()
});

export const linkScanResolveSchema = z
  .object({
    url: z.string().trim().max(2048, "URL is too long.").optional(),
    message: z.string().trim().max(50_000, "Message is too long.").optional()
  })
  .superRefine((value, ctx) => {
    const hasUrl = typeof value.url === "string" && value.url.trim().length > 0;
    const hasMessage = typeof value.message === "string" && value.message.trim().length > 0;

    if (!hasUrl && !hasMessage) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["url"],
        message: "Paste a URL or a suspicious message to scan."
      });
    }
  });

export const linkScanJobSchema = z
  .object({
    url: z.string().trim().max(2048, "URL is too long.").optional(),
    urls: z.array(z.string().trim().max(2048, "URL is too long.")).max(25, "Too many links selected.").optional(),
    message: z.string().trim().max(50_000, "Message is too long.").optional()
  })
  .superRefine((value, ctx) => {
    const hasUrl = typeof value.url === "string" && value.url.trim().length > 0;
    const hasUrls = Array.isArray(value.urls) && value.urls.some((entry) => String(entry || "").trim().length > 0);
    const hasMessage = typeof value.message === "string" && value.message.trim().length > 0;

    if (!hasUrl && !hasUrls && !hasMessage) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["url"],
        message: "Paste a URL or a suspicious message to scan."
      });
    }
  });

export const websiteSafetyScanJobSchema = z.object({
  url: z
    .string()
    .trim()
    .min(4, "URL is required.")
    .max(2048, "URL is too long.")
});

export const reportWorkflowUpdateSchema = z.object({
  caseStatus: z.enum(["new", "triage", "investigating", "closed"]).optional(),
  severity: z.enum(["low", "medium", "high", "critical"]).optional(),
  assigneeLabel: z.string().trim().max(120).optional(),
  clientLabel: z.string().trim().max(120).optional(),
  recommendedAction: z.string().trim().max(240).optional(),
  notesSummary: z.string().trim().max(1200).optional()
});

export const reportCommentCreateSchema = z.object({
  body: z.string().trim().min(2).max(4_000)
});

export const reportShareCreateSchema = z.object({
  label: z.string().trim().max(120).optional().default(""),
  ttlHours: z.number().int().min(1).max(24 * 30).optional().default(72)
});

const findingSchema = z.object({
  id: z.string().min(1),
  severity: z.string().min(1),
  category: z.string().min(1),
  weight: z.number().int().nonnegative(),
  title: z.string().min(1),
  description: z.string().min(1),
  evidence: z.string().optional().default("")
});

const reportFileSchema = z
  .object({
    originalName: z.string().min(1),
    extension: z.string().min(1),
    size: z.number().int().nonnegative(),
    sizeDisplay: z.string().min(1),
    declaredMimeType: z.string().min(1),
    detectedMimeType: z.string().min(1),
    detectedFileType: z.string().min(1),
    hashes: z.object({
      md5: z.string().min(1),
      sha1: z.string().min(1),
      sha256: z.string().min(1)
    })
  })
  .passthrough();

const reportUrlSchema = z
  .object({
    input: z.string().min(1),
    normalized: z.string().min(1),
    final: z.string().min(1),
    protocol: z.string().min(1),
    hostname: z.string().min(1)
  })
  .passthrough();

export const linkReportSchema = z.object({
  id: z.string().min(1),
  createdAt: z.string().min(1).optional(),
  completedAt: z.string().min(1).optional(),
  sourceType: z.literal("url"),
  verdict: z.enum(["clean", "suspicious", "malicious"]),
  riskScore: z.number().min(0).max(100),
  file: reportFileSchema,
  findings: z.array(findingSchema),
  recommendations: z.array(z.string()),
  plainLanguageReasons: z.array(z.string()).optional(),
  technicalIndicators: z.unknown().optional(),
  engines: z.record(z.string(), z.unknown()),
  url: reportUrlSchema
});

export const websiteSafetyReportSchema = z.object({
  id: z.string().min(1),
  createdAt: z.string().min(1).optional(),
  completedAt: z.string().min(1).optional(),
  sourceType: z.literal("website"),
  verdict: z.enum(["clean", "suspicious", "malicious"]),
  riskScore: z.number().min(0).max(100),
  file: reportFileSchema,
  findings: z.array(findingSchema),
  recommendations: z.array(z.string()),
  plainLanguageReasons: z.array(z.string()).optional(),
  technicalIndicators: z.unknown().optional(),
  websiteSafety: z.object({
    score: z.number().min(0).max(100),
    verdict: z.enum(["safe", "suspicious", "dangerous"]),
    checkedAt: z.string().min(1),
    url: z.object({
      input: z.string().min(1),
      normalized: z.string().min(1),
      final: z.string().min(1),
      hostname: z.string().min(1),
      protocol: z.string().min(1)
    }),
    modules: z.record(z.string(), z.unknown())
  }),
  engines: z.record(z.string(), z.unknown()),
  url: reportUrlSchema
});
