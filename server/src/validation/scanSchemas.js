import { z } from "zod";

export const paginationSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20)
});

export const linkScanJobSchema = z.object({
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

export const linkReportSchema = z.object({
  id: z.string().min(1),
  sourceType: z.literal("url"),
  verdict: z.enum(["clean", "suspicious", "malicious"]),
  riskScore: z.number().min(0).max(100),
  file: z.object({
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
  }),
  findings: z.array(findingSchema),
  recommendations: z.array(z.string()),
  plainLanguageReasons: z.array(z.string()).optional(),
  technicalIndicators: z.unknown().optional(),
  engines: z.record(z.string(), z.unknown()),
  url: z.object({
    input: z.string().min(1),
    normalized: z.string().min(1),
    final: z.string().min(1),
    protocol: z.string().min(1),
    hostname: z.string().min(1)
  })
});
