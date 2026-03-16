import { HttpError } from "../utils/httpError.js";
import { hasRequiredApiKeyScopes, normalizeApiKeyScopes } from "../utils/apiKeyScopes.js";

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
          method: authResult.authMethod,
          apiKey: null
        };
        return next();
      }

      if (typeof apiKey === "string" && apiKey.trim()) {
        const authResult = await authService.authenticateApiKey(apiKey.trim());
        req.auth = {
          user: authResult.user,
          method: authResult.authMethod,
          apiKey: authResult.apiKey || null
        };
        return next();
      }

      throw new HttpError(401, "Authentication required.", { code: "AUTH_REQUIRED" });
    } catch (error) {
      next(error);
    }
  };
}

export function requireApiKeyScopes(...requiredScopes) {
  return function apiKeyScopeGuard(req, _res, next) {
    if (!req.auth?.user) {
      return next(new HttpError(401, "Authentication required.", { code: "AUTH_REQUIRED" }));
    }

    if (req.auth.method !== "api_key") {
      return next();
    }

    const normalizedRequiredScopes = normalizeApiKeyScopes(requiredScopes, {
      fallbackToAll: false
    });

    if (normalizedRequiredScopes.length === 0) {
      return next();
    }

    const grantedScopes = normalizeApiKeyScopes(req.auth.apiKey?.scopes, {
      fallbackToAll: true
    });

    if (hasRequiredApiKeyScopes(grantedScopes, normalizedRequiredScopes)) {
      return next();
    }

    return next(
      new HttpError(403, "API key does not include required scope permissions.", {
        code: "AUTH_API_KEY_SCOPE_REQUIRED",
        details: {
          requiredScopes: normalizedRequiredScopes,
          grantedScopes
        }
      })
    );
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

export function requireAuthMethod(...methods) {
  return function authMethodGuard(req, _res, next) {
    if (!req.auth?.user) {
      return next(new HttpError(401, "Authentication required.", { code: "AUTH_REQUIRED" }));
    }

    if (!methods.includes(req.auth.method)) {
      return next(
        new HttpError(403, "This endpoint requires interactive bearer authentication.", {
          code: "AUTH_METHOD_FORBIDDEN",
          details: {
            allowedMethods: methods
          }
        })
      );
    }

    return next();
  };
}

export function preventSensitiveCaching({ privateCache = true } = {}) {
  return function noStore(_req, res, next) {
    const cacheControlValue = `${privateCache ? "private, " : ""}no-store, max-age=0, must-revalidate`;
    res.setHeader("Cache-Control", cacheControlValue);
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.vary("Authorization");
    res.vary("x-api-key");
    return next();
  };
}
