import { z } from "zod";

const usernameSchema = z.string().trim().min(2).max(80);

export const registerSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(12).max(128),
  name: usernameSchema.optional()
});

export const loginSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(1).max(256)
});

export const refreshSchema = z.object({
  refreshToken: z.string().min(30).max(4096)
});

export const forgotPasswordSchema = z.object({
  email: z.string().email().max(254)
});

export const resetPasswordSchema = z
  .object({
    password: z.string().min(12).max(128),
    accessToken: z.string().min(20).max(4096).optional(),
    resetToken: z.string().min(20).max(4096).optional(),
    email: z.string().email().max(254).optional()
  })
  .superRefine((value, context) => {
    if (!value.accessToken && !value.resetToken) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["accessToken"],
        message: "accessToken or resetToken is required."
      });
    }
  });

export const logoutSchema = z.object({
  refreshToken: z.string().min(30).max(4096).optional()
});

export const usernameAvailabilityQuerySchema = z.object({
  username: usernameSchema
});

export const createApiKeySchema = z.object({
  name: z.string().trim().min(3).max(40)
});

export const notificationsQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).optional().default(20)
});

export const markNotificationsReadSchema = z.object({
  ids: z.array(z.string().trim().min(1).max(128)).max(100).optional().default([])
});
