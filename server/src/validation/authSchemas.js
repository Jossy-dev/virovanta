import { z } from "zod";

export const registerSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(12).max(128),
  name: z.string().trim().min(2).max(80).optional()
});

export const loginSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(1).max(256)
});

export const refreshSchema = z.object({
  refreshToken: z.string().min(30).max(4096)
});

export const createApiKeySchema = z.object({
  name: z.string().trim().min(3).max(40)
});
