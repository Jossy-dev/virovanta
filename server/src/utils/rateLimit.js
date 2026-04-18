import { ipKeyGenerator } from "express-rate-limit";

export function buildAuthRateLimitKey(req, { prefix = "rate-limit" } = {}) {
  const normalizedPrefix = String(prefix || "rate-limit").trim() || "rate-limit";

  if (req.auth?.apiKey?.id) {
    return `${normalizedPrefix}:api-key:${req.auth.apiKey.id}`;
  }

  if (req.auth?.user?.id) {
    return `${normalizedPrefix}:user:${req.auth.user.id}`;
  }

  return `${normalizedPrefix}:ip:${ipKeyGenerator(req.ip || "")}`;
}

export function buildRateLimitHandler({ code = "RATE_LIMIT_EXCEEDED", message = "Too many requests.", details = null } = {}) {
  return function rateLimitHandler(req, res, _next, options = {}) {
    const resolvedMessage = typeof message === "function" ? message(req, res, options) : message;
    const resolvedDetails = typeof details === "function" ? details(req, res, options) : details;

    return res.status(options.statusCode || 429).json({
      error: {
        code,
        message: resolvedMessage || "Too many requests.",
        details: resolvedDetails || null
      },
      requestId: req.requestId
    });
  };
}

export function isScanPollingRequest(req) {
  const method = String(req.method || "").trim().toUpperCase();
  const requestPath = String(req.path || req.originalUrl || "").trim();

  if (method !== "GET") {
    return false;
  }

  return /^\/api\/scans\/jobs(?:\/[^/]+)?$/.test(requestPath);
}
