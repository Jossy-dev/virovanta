import { HttpError } from "../utils/httpError.js";

export function createAuthMiddleware(authService) {
  return async function requireAuth(req, _res, next) {
    try {
      const authorization = req.headers.authorization || "";
      const bearerMatch = authorization.match(/^Bearer\s+(.+)$/i);
      const apiKey = req.headers["x-api-key"];

      if (bearerMatch?.[1]) {
        const authResult = await authService.authenticateAccessToken(bearerMatch[1]);
        req.auth = {
          user: authResult.user,
          method: authResult.authMethod
        };
        return next();
      }

      if (typeof apiKey === "string" && apiKey.trim()) {
        const authResult = await authService.authenticateApiKey(apiKey.trim());
        req.auth = {
          user: authResult.user,
          method: authResult.authMethod
        };
        return next();
      }

      throw new HttpError(401, "Authentication required.", { code: "AUTH_REQUIRED" });
    } catch (error) {
      next(error);
    }
  };
}

export function requireRole(...roles) {
  return function roleGuard(req, _res, next) {
    if (!req.auth?.user) {
      return next(new HttpError(401, "Authentication required.", { code: "AUTH_REQUIRED" }));
    }

    if (!roles.includes(req.auth.user.role)) {
      return next(new HttpError(403, "Insufficient permissions.", { code: "AUTH_FORBIDDEN" }));
    }

    return next();
  };
}
