import { z } from "zod";

export const SCAN_SOURCE_TYPES = Object.freeze(["file", "url", "website"]);

export const scanSourceTypeSchema = z.enum(SCAN_SOURCE_TYPES);

export const paginationSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20),
  sourceType: scanSourceTypeSchema.optional()
});

export const linkScanJobSchema = z.object({
  url: z
    .string()
    .trim()
    .min(4, "URL is required.")
    .max(2048, "URL is too long.")
});

export const websiteSafetyScanJobSchema = z.object({
  url: z
    .string()
    .trim()
    .min(4, "URL is required.")
    .max(2048, "URL is too long.")
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
