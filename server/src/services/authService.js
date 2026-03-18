import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { HttpError } from "../utils/httpError.js";
import { normalizeApiKeyScopes } from "../utils/apiKeyScopes.js";
import { generateOpaqueToken, hashSecret, normalizeEmail, safeText } from "../utils/security.js";

const TOKEN_ALGORITHM = "HS256";
const AUTH_SUPABASE_UNAVAILABLE_CODE = "AUTH_SUPABASE_UNAVAILABLE";
const AUTH_SUPABASE_REQUEST_FAILED_CODE = "AUTH_SUPABASE_REQUEST_FAILED";
const AUTH_SUPABASE_CONFIRM_EMAIL_CODE = "AUTH_SUPABASE_EMAIL_CONFIRMATION_REQUIRED";
const PASSWORD_RESET_TTL_MS = 30 * 60 * 1000;
const USERNAME_SUGGESTION_COUNT = 3;
const ROLLING_USAGE_WINDOW_MS = 24 * 60 * 60 * 1000;

function passwordPolicyCheck(password, email) {
  if (password.length < 12 || password.length > 128) {
    return "Password must be between 12 and 128 characters.";
  }

  if (!/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
    return "Password must include upper, lower, number, and symbol characters.";
  }

  const emailPrefix = normalizeEmail(email).split("@")[0];
  if (emailPrefix && password.toLowerCase().includes(emailPrefix)) {
    return "Password must not contain your email identifier.";
  }

  return null;
}

function normalizeUsername(value) {
  return String(value || "").trim().toLowerCase();
}

function fallbackUsernameFromEmail(email) {
  const emailPrefix = normalizeEmail(email).split("@")[0] || "user";
  const cleaned = emailPrefix.replace(/[^a-zA-Z0-9._-]+/g, "_").replace(/^_+|_+$/g, "");
  return cleaned || "user";
}

function resolveUsername(name, email) {
  const fallback = fallbackUsernameFromEmail(email);
  const candidate = safeText(name, { fallback, maxLength: 80 }).trim();
  return candidate.length >= 2 ? candidate : `${fallback}_01`;
}

function buildUsernameSuggestions(preferredUsername, users, count = USERNAME_SUGGESTION_COUNT) {
  const taken = new Set((users || []).map((user) => normalizeUsername(user?.name)));
  const rawBase = normalizeUsername(preferredUsername)
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  const base = (rawBase || "virovanta_user").slice(0, 24);
  const suggestions = [];
  const keywords = ["secure", "ops", "shield", "intel", "guard", "scan", "core", "alpha", "delta"];

  const push = (candidateRaw) => {
    if (suggestions.length >= count) {
      return;
    }

    const candidate = String(candidateRaw || "")
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, "_")
      .replace(/^_+|_+$/g, "")
      .slice(0, 80);

    if (candidate.length < 2) {
      return;
    }

    const normalizedCandidate = normalizeUsername(candidate);
    if (taken.has(normalizedCandidate) || suggestions.includes(candidate)) {
      return;
    }

    suggestions.push(candidate);
  };

  const randomKeywordOrder = keywords
    .map((keyword) => ({ keyword, rank: crypto.randomInt(0, 1_000_000) }))
    .sort((left, right) => left.rank - right.rank)
    .map((entry) => entry.keyword);

  for (const keyword of randomKeywordOrder) {
    if (suggestions.length >= count) {
      break;
    }

    push(`${base}_${keyword}`);
  }

  push(`${base}_${new Date().getFullYear()}`);

  let suffix = crypto.randomInt(11, 120);
  while (suggestions.length < count && suffix < 1000) {
    push(`${base}_${suffix}`);
    suffix += crypto.randomInt(7, 37);
  }

  return suggestions;
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    username: user.name,
    name: user.name,
    role: user.role,
    createdAt: user.createdAt,
    lastLoginAt: user.lastLoginAt || null
  };
}

function publicApiKey(key) {
  return {
    id: key.id,
    name: key.name,
    keyPrefix: key.keyPrefix,
    scopes: normalizeApiKeyScopes(key.scopes, { fallbackToAll: true }),
    createdAt: key.createdAt,
    lastUsedAt: key.lastUsedAt || null,
    revokedAt: key.revokedAt || null
  };
}

function getRollingUsageStats(state, userId, nowTimestamp = Date.now()) {
  const windowStartedAtTimestamp = nowTimestamp - ROLLING_USAGE_WINDOW_MS;
  const used = (state.jobs || []).reduce((count, job) => {
    if (job?.userId !== userId) {
      return count;
    }

    const createdAtTimestamp = Date.parse(job?.createdAt || "");
    if (!Number.isFinite(createdAtTimestamp)) {
      return count;
    }

    return createdAtTimestamp >= windowStartedAtTimestamp ? count + 1 : count;
  }, 0);

  return {
    windowStartedAt: new Date(windowStartedAtTimestamp).toISOString(),
    used
  };
}

function buildUsageSnapshot(state, user, limit, nowTimestamp = Date.now()) {
  const { windowStartedAt, used } = getRollingUsageStats(state, user.id, nowTimestamp);

  if (user.role === "admin") {
    return {
      windowStartedAt,
      used,
      remaining: null,
      limit: null
    };
  }

  return {
    windowStartedAt,
    used,
    remaining: Math.max(0, limit - used),
    limit
  };
}

function parseSupabaseError(payload, fallbackMessage) {
  if (!payload || typeof payload !== "object") {
    return fallbackMessage;
  }

  return (
    String(payload.msg || payload.error_description || payload.error || payload.message || "")
      .trim()
      .slice(0, 240) || fallbackMessage
  );
}

function parseSupabaseSignupUser(payload) {
  if (!payload || typeof payload !== "object") {
    return null;
  }

  if (payload.user && typeof payload.user === "object") {
    return payload.user;
  }

  if (payload.id || payload.email || payload.user_metadata) {
    return payload;
  }

  return null;
}

function isSupabaseExistingEmailSignup(payload, requestedEmail) {
  const user = parseSupabaseSignupUser(payload);
  if (!user) {
    return false;
  }

  const requestEmail = normalizeEmail(requestedEmail);
  const payloadEmail = normalizeEmail(user.email || "");
  if (requestEmail && payloadEmail && requestEmail !== payloadEmail) {
    return false;
  }

  if (Array.isArray(user.identities) && user.identities.length === 0) {
    return true;
  }

  return false;
}

export class AuthService {
  constructor({ store, config, logger, notificationService = null }) {
    this.store = store;
    this.config = config;
    this.logger = logger;
    this.notificationService = notificationService;
    this.supabaseJwks = this.#createSupabaseJwks();
  }

  async #notifyUsageThreshold(userId, quota, { requestedScans = 1 } = {}) {
    if (!this.notificationService || quota?.limit == null) {
      return;
    }

    const limit = Number(quota.limit) || 0;
    const remaining = Number(quota.remaining);
    if (!limit || !Number.isFinite(remaining)) {
      return;
    }

    const warningThreshold = Math.max(3, Math.ceil(limit * 0.1));
    const normalizedRequestedScans = Math.max(1, Math.floor(Number(requestedScans) || 1));
    const isBlocked = quota.allowed === false;
    if (!isBlocked && remaining > warningThreshold) {
      return;
    }

    const stage = remaining === 0 ? "reached" : isBlocked ? "blocked" : "warning";
    const title =
      remaining === 0
        ? "Usage limit reached"
        : isBlocked
          ? "Batch exceeds remaining usage"
          : "Usage limit almost reached";
    const tone = remaining === 0 ? "danger" : "warning";
    const detail =
      remaining === 0
        ? "You have used all available scans in the current 24-hour window."
        : isBlocked
          ? `This action needs ${normalizedRequestedScans} scans, but only ${remaining} remain in the current 24-hour window.`
          : `${remaining} scan${remaining === 1 ? "" : "s"} left in the current 24-hour window.`;

    await this.notificationService.create({
      userId,
      type: "usage_limit_warning",
      tone,
      title,
      detail,
      entityType: "quota",
      entityId: quota.windowStartedAt || null,
      dedupeKey: `usage-limit:${quota.windowStartedAt || "rolling-window"}:${stage}`
    });
  }

  #createSupabaseJwks() {
    if (!this.config.supabaseJwksUrl) {
      return null;
    }

    try {
      return createRemoteJWKSet(new URL(this.config.supabaseJwksUrl));
    } catch (error) {
      this.logger?.warn?.({ err: error }, "Invalid SUPABASE_JWKS_URL. Falling back to Supabase /user verification.");
      return null;
    }
  }

  #supabaseBaseUrl() {
    return String(this.config.supabaseUrl || "").trim().replace(/\/+$/, "");
  }

  #isSupabaseConfigured() {
    return Boolean(this.#supabaseBaseUrl() && this.config.supabaseAnonKey);
  }

  async #supabaseRequest(path, { method = "GET", body = null, accessToken = "" } = {}) {
    if (!this.#isSupabaseConfigured()) {
      throw new HttpError(503, "Supabase Auth is not configured.", {
        code: AUTH_SUPABASE_UNAVAILABLE_CODE
      });
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => {
      controller.abort();
    }, this.config.supabaseAuthTimeoutMs);

    let response;

    try {
      response = await fetch(`${this.#supabaseBaseUrl()}${path}`, {
        method,
        headers: {
          apikey: this.config.supabaseAnonKey,
          ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
          ...(body != null ? { "Content-Type": "application/json" } : {})
        },
        body: body != null ? JSON.stringify(body) : undefined,
        signal: controller.signal
      });
    } catch (error) {
      if (error?.name === "AbortError") {
        throw new HttpError(504, "Supabase Auth request timed out.", {
          code: AUTH_SUPABASE_UNAVAILABLE_CODE
        });
      }

      throw new HttpError(503, "Supabase Auth service is unavailable.", {
        code: AUTH_SUPABASE_UNAVAILABLE_CODE
      });
    } finally {
      clearTimeout(timeout);
    }

    let payload = null;
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      payload = await response.json().catch(() => null);
    }

    if (!response.ok) {
      throw new HttpError(response.status, parseSupabaseError(payload, "Supabase Auth request failed."), {
        code: AUTH_SUPABASE_REQUEST_FAILED_CODE,
        details: payload
      });
    }

    return payload;
  }

  #extractSupabaseClaims(input) {
    const source = input?.user || input || {};
    const userId = String(source.id || source.sub || "").trim();
    const email = normalizeEmail(source.email || source.user_metadata?.email || "");
    const name = safeText(source.user_metadata?.name || source.user_metadata?.full_name || email.split("@")[0], {
      fallback: email.split("@")[0] || "user",
      maxLength: 80
    });

    return {
      userId,
      email,
      name
    };
  }

  async #upsertLocalUserFromSupabase(userPayload, context = {}) {
    const { userId, email, name } = this.#extractSupabaseClaims(userPayload);

    if (!userId || !email) {
      throw new HttpError(401, "Supabase token missing required claims.", {
        code: "AUTH_TOKEN_INVALID"
      });
    }

    const now = new Date().toISOString();

    const user = await this.store.write((state) => {
      const existing = state.users.find((candidate) => candidate.id === userId || candidate.email === email);

      if (existing) {
        existing.id = userId;
        existing.email = email;
        existing.name = existing.name || name;
        existing.status = "active";
        existing.updatedAt = now;
        existing.lastLoginAt = now;
        existing.authSource = "supabase";
        existing.refreshTokens = Array.isArray(existing.refreshTokens) ? existing.refreshTokens : [];
        existing.apiKeys = Array.isArray(existing.apiKeys) ? existing.apiKeys : [];
        existing.usage = existing.usage || {
          windowStartedAt: now,
          scans: 0
        };

        state.auditEvents.unshift({
          id: `audit_${crypto.randomUUID()}`,
          userId: existing.id,
          action: context.action || "auth.supabase_synced",
          ipAddress: context.ipAddress || null,
          userAgent: safeText(context.userAgent, { fallback: "" }),
          metadata: {
            provider: "supabase"
          },
          createdAt: now
        });

        return existing;
      }

      const nextUser = {
        id: userId,
        email,
        name,
        role: "user",
        status: "active",
        passwordHash: null,
        authSource: "supabase",
        createdAt: now,
        updatedAt: now,
        lastLoginAt: now,
        refreshTokens: [],
        apiKeys: [],
        usage: {
          windowStartedAt: now,
          scans: 0
        }
      };

      state.users.unshift(nextUser);

      state.auditEvents.unshift({
        id: `audit_${crypto.randomUUID()}`,
        userId: nextUser.id,
        action: context.action || "auth.supabase_linked",
        ipAddress: context.ipAddress || null,
        userAgent: safeText(context.userAgent, { fallback: "" }),
        metadata: {
          provider: "supabase"
        },
        createdAt: now
      });

      return nextUser;
    });

    return user;
  }

  async #createSupabaseSessionResponse(payload, context = {}) {
    const accessToken = String(payload?.access_token || "").trim();
    const refreshToken = String(payload?.refresh_token || "").trim();
    const expiresInSeconds = Number(payload?.expires_in) || this.config.accessTokenTtlMinutes * 60;

    if (!accessToken || !refreshToken) {
      throw new HttpError(401, "Supabase session is incomplete.", {
        code: "AUTH_TOKEN_INVALID"
      });
    }

    const user = await this.#upsertLocalUserFromSupabase(payload?.user || payload, context);

    return {
      user: publicUser(user),
      accessToken,
      refreshToken,
      expiresInSeconds
    };
  }

  issueAccessToken(user) {
    const nowSeconds = Math.floor(Date.now() / 1000);

    return jwt.sign(
      {
        sub: user.id,
        email: user.email,
        role: user.role,
        iat: nowSeconds
      },
      this.config.jwtAccessSecret,
      {
        algorithm: TOKEN_ALGORITHM,
        expiresIn: `${this.config.accessTokenTtlMinutes}m`,
        issuer: this.config.jwtIssuer,
        audience: this.config.jwtAudience
      }
    );
  }

  async authenticateAccessToken(token) {
    if (this.config.authProvider === "supabase") {
      const supabaseUser = await this.#authenticateSupabaseAccessToken(token);
      return {
        user: supabaseUser,
        authMethod: "bearer"
      };
    }

    const localUser = await this.#authenticateLocalAccessToken(token);
    return {
      user: localUser,
      authMethod: "bearer"
    };
  }

  async #authenticateLocalAccessToken(token) {
    const payload = jwt.verify(token, this.config.jwtAccessSecret, {
      algorithms: [TOKEN_ALGORITHM],
      issuer: this.config.jwtIssuer,
      audience: this.config.jwtAudience
    });

    const user = await this.store.read((state) => state.users.find((candidate) => candidate.id === payload.sub) || null);
    if (!user || user.status !== "active") {
      throw new HttpError(401, "Unauthorized.", { code: "AUTH_UNAUTHORIZED" });
    }

    return user;
  }

  async #authenticateSupabaseAccessToken(token) {
    if (this.config.supabaseJwtSecret) {
      try {
        const verifyOptions = {
          algorithms: [this.config.supabaseJwtAlgorithm || "HS256"]
        };

        if (this.config.supabaseJwtIssuer) {
          verifyOptions.issuer = this.config.supabaseJwtIssuer;
        }

        if (this.config.supabaseJwtAudience) {
          verifyOptions.audience = this.config.supabaseJwtAudience;
        }

        const payload = jwt.verify(token, this.config.supabaseJwtSecret, verifyOptions);
        return this.#upsertLocalUserFromSupabase(payload, { action: "auth.supabase_token_verified" });
      } catch {
        throw new HttpError(401, "Invalid or expired token.", { code: "AUTH_TOKEN_INVALID" });
      }
    }

    if (this.supabaseJwks) {
      try {
        const verifyOptions = {};

        if (this.config.supabaseJwtIssuer) {
          verifyOptions.issuer = this.config.supabaseJwtIssuer;
        }

        if (this.config.supabaseJwtAudience) {
          verifyOptions.audience = this.config.supabaseJwtAudience;
        }

        const { payload } = await jwtVerify(token, this.supabaseJwks, verifyOptions);
        return this.#upsertLocalUserFromSupabase(payload, { action: "auth.supabase_jwks_verified" });
      } catch {
        // Fallback to Supabase /user introspection for compatibility.
      }
    }

    const profile = await this.#supabaseRequest("/auth/v1/user", {
      method: "GET",
      accessToken: token
    }).catch(() => {
      throw new HttpError(401, "Invalid or expired token.", { code: "AUTH_TOKEN_INVALID" });
    });

    return this.#upsertLocalUserFromSupabase(profile, { action: "auth.supabase_user_verified" });
  }

  async authenticateApiKey(rawKey) {
    const keyHash = hashSecret(rawKey);

    const match = await this.store.read((state) => {
      for (const user of state.users) {
        const key = (user.apiKeys || []).find((candidate) => candidate.keyHash === keyHash && !candidate.revokedAt);

        if (key) {
          return { user, key };
        }
      }

      return null;
    });

    if (!match || match.user.status !== "active") {
      throw new HttpError(401, "Invalid API key.", { code: "AUTH_API_KEY_INVALID" });
    }

    const now = new Date().toISOString();

    await this.store.write((state) => {
      const user = state.users.find((candidate) => candidate.id === match.user.id);
      if (!user) {
        return;
      }

      const key = (user.apiKeys || []).find((candidate) => candidate.id === match.key.id);
      if (key) {
        key.lastUsedAt = now;
      }
    });

    return {
      user: match.user,
      authMethod: "api_key",
      apiKey: {
        id: match.key.id,
        name: match.key.name,
        keyPrefix: match.key.keyPrefix,
        scopes: normalizeApiKeyScopes(match.key.scopes, { fallbackToAll: true }),
        createdAt: match.key.createdAt,
        lastUsedAt: now
      }
    };
  }

  async register({ email, password, name }, context = {}) {
    const normalizedEmail = normalizeEmail(email);
    const username = resolveUsername(name, normalizedEmail);

    if (this.config.authProvider === "supabase") {
      if (!this.config.allowOpenRegistration) {
        throw new HttpError(403, "Registration is disabled.", { code: "AUTH_REGISTRATION_DISABLED" });
      }

      const passwordError = passwordPolicyCheck(password, normalizedEmail);
      if (passwordError) {
        throw new HttpError(400, passwordError, { code: "AUTH_WEAK_PASSWORD" });
      }

      const existingLocalEmail = await this.store.read((state) =>
        state.users.some((candidate) => normalizeEmail(candidate.email) === normalizedEmail)
      );

      if (existingLocalEmail) {
        throw new HttpError(409, "Email already registered.", { code: "AUTH_EMAIL_EXISTS" });
      }

      const usernameAvailability = await this.checkUsernameAvailability(username);
      if (!usernameAvailability.available) {
        throw new HttpError(409, "Username already taken.", {
          code: "AUTH_USERNAME_EXISTS",
          details: {
            suggestions: usernameAvailability.suggestions
          }
        });
      }

      let payload;
      try {
        payload = await this.#supabaseRequest("/auth/v1/signup", {
          method: "POST",
          body: {
            email: normalizedEmail,
            password,
            data: {
              name: username
            }
          }
        });
      } catch (error) {
        if (error instanceof HttpError && error.code === AUTH_SUPABASE_REQUEST_FAILED_CODE) {
          const supabaseErrorText = `${String(error.message || "")} ${JSON.stringify(error.details || {})}`.toLowerCase();
          if (supabaseErrorText.includes("already registered") || supabaseErrorText.includes("user already exists")) {
            throw new HttpError(409, "Email already registered.", { code: "AUTH_EMAIL_EXISTS" });
          }
        }

        throw error;
      }

      if (!payload?.access_token || !payload?.refresh_token) {
        if (isSupabaseExistingEmailSignup(payload, normalizedEmail)) {
          throw new HttpError(409, "Email already registered.", { code: "AUTH_EMAIL_EXISTS" });
        }

        const signupUser = parseSupabaseSignupUser(payload);
        if (signupUser) {
          await this.#upsertLocalUserFromSupabase(signupUser, {
            ipAddress: context.ipAddress,
            userAgent: context.userAgent,
            action: "auth.supabase_register_pending"
          });
        }

        return {
          requiresEmailConfirmation: true,
          email: normalizedEmail,
          message: "Registration submitted. Confirm your email, then sign in.",
          code: AUTH_SUPABASE_CONFIRM_EMAIL_CODE
        };
      }

      return this.#createSupabaseSessionResponse(payload, {
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        action: "auth.supabase_register"
      });
    }

    if (!this.config.allowOpenRegistration) {
      throw new HttpError(403, "Registration is disabled.", { code: "AUTH_REGISTRATION_DISABLED" });
    }

    const passwordError = passwordPolicyCheck(password, normalizedEmail);

    if (passwordError) {
      throw new HttpError(400, passwordError, { code: "AUTH_WEAK_PASSWORD" });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const now = new Date().toISOString();

    const result = await this.store.write((state) => {
      const existing = state.users.find((candidate) => candidate.email === normalizedEmail);
      if (existing) {
        throw new HttpError(409, "Email already registered.", { code: "AUTH_EMAIL_EXISTS" });
      }

      const requestedUsername = normalizeUsername(username);
      const existingUsername = state.users.find((candidate) => normalizeUsername(candidate.name) === requestedUsername);
      if (existingUsername) {
        throw new HttpError(409, "Username already taken.", {
          code: "AUTH_USERNAME_EXISTS",
          details: {
            suggestions: buildUsernameSuggestions(username, state.users)
          }
        });
      }

      const user = {
        id: `usr_${crypto.randomUUID()}`,
        email: normalizedEmail,
        name: username,
        role: state.users.length === 0 ? "admin" : "user",
        status: "active",
        passwordHash,
        createdAt: now,
        updatedAt: now,
        lastLoginAt: null,
        refreshTokens: [],
        apiKeys: [],
        usage: {
          windowStartedAt: now,
          scans: 0
        }
      };

      state.users.unshift(user);

      state.auditEvents.unshift({
        id: `audit_${crypto.randomUUID()}`,
        userId: user.id,
        action: "auth.register",
        ipAddress: context.ipAddress || null,
        userAgent: safeText(context.userAgent, { fallback: "" }),
        metadata: {
          role: user.role
        },
        createdAt: now
      });

      return user;
    });

    const session = await this.createSession(result.id, {
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      action: "auth.register.session"
    });

    return {
      user: publicUser(result),
      ...session
    };
  }

  async checkUsernameAvailability(username) {
    const requested = safeText(username, { fallback: "", maxLength: 80 }).trim();
    if (requested.length < 2) {
      throw new HttpError(400, "Username must be at least 2 characters.", { code: "AUTH_USERNAME_INVALID" });
    }

    return this.store.read((state) => {
      const normalizedRequested = normalizeUsername(requested);
      const available = !state.users.some((candidate) => normalizeUsername(candidate.name) === normalizedRequested);

      return {
        username: requested,
        available,
        suggestions: available ? [] : buildUsernameSuggestions(requested, state.users)
      };
    });
  }

  async login({ email, password }, context = {}) {
    const normalizedEmail = normalizeEmail(email);

    if (this.config.authProvider === "supabase") {
      const payload = await this.#supabaseRequest("/auth/v1/token?grant_type=password", {
        method: "POST",
        body: {
          email: normalizedEmail,
          password
        }
      });

      return this.#createSupabaseSessionResponse(payload, {
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        action: "auth.supabase_login"
      });
    }

    const user = await this.store.read((state) => state.users.find((candidate) => candidate.email === normalizedEmail) || null);

    if (!user || user.status !== "active") {
      throw new HttpError(401, "Invalid email or password.", { code: "AUTH_INVALID_CREDENTIALS" });
    }

    if (!user.passwordHash) {
      throw new HttpError(401, "Invalid email or password.", { code: "AUTH_INVALID_CREDENTIALS" });
    }

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      throw new HttpError(401, "Invalid email or password.", { code: "AUTH_INVALID_CREDENTIALS" });
    }

    await this.store.write((state) => {
      const editableUser = state.users.find((candidate) => candidate.id === user.id);
      if (!editableUser) {
        return;
      }

      editableUser.lastLoginAt = new Date().toISOString();
      editableUser.updatedAt = editableUser.lastLoginAt;

      state.auditEvents.unshift({
        id: `audit_${crypto.randomUUID()}`,
        userId: editableUser.id,
        action: "auth.login",
        ipAddress: context.ipAddress || null,
        userAgent: safeText(context.userAgent, { fallback: "" }),
        metadata: {},
        createdAt: editableUser.lastLoginAt
      });
    });

    const session = await this.createSession(user.id, {
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      action: "auth.login.session"
    });

    return {
      user: publicUser(user),
      ...session
    };
  }

  async createSession(userId, context = {}) {
    if (this.config.authProvider === "supabase") {
      throw new HttpError(400, "Session creation is managed by Supabase Auth in this deployment.", {
        code: "AUTH_SESSION_MANAGED_EXTERNALLY"
      });
    }

    const now = new Date();
    const nowIso = now.toISOString();
    const refreshToken = `svr_${generateOpaqueToken(42)}`;
    const refreshTokenHash = hashSecret(refreshToken);
    const expiresAt = new Date(now.getTime() + this.config.refreshTokenTtlDays * 24 * 60 * 60 * 1000).toISOString();

    const user = await this.store.write((state) => {
      const editableUser = state.users.find((candidate) => candidate.id === userId);
      if (!editableUser || editableUser.status !== "active") {
        throw new HttpError(401, "Unauthorized.", { code: "AUTH_UNAUTHORIZED" });
      }

      editableUser.refreshTokens = editableUser.refreshTokens || [];
      editableUser.refreshTokens.unshift({
        id: `rt_${crypto.randomUUID()}`,
        tokenHash: refreshTokenHash,
        expiresAt,
        revokedAt: null,
        createdAt: nowIso
      });
      editableUser.refreshTokens = editableUser.refreshTokens.slice(0, 20);

      state.auditEvents.unshift({
        id: `audit_${crypto.randomUUID()}`,
        userId: editableUser.id,
        action: context.action || "auth.session.created",
        ipAddress: context.ipAddress || null,
        userAgent: safeText(context.userAgent, { fallback: "" }),
        metadata: {
          expiresAt
        },
        createdAt: nowIso
      });

      return editableUser;
    });

    return {
      accessToken: this.issueAccessToken(user),
      refreshToken,
      expiresInSeconds: this.config.accessTokenTtlMinutes * 60
    };
  }

  async refreshSession(refreshToken, context = {}) {
    if (this.config.authProvider === "supabase") {
      const payload = await this.#supabaseRequest("/auth/v1/token?grant_type=refresh_token", {
        method: "POST",
        body: {
          refresh_token: refreshToken
        }
      });

      return this.#createSupabaseSessionResponse(payload, {
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        action: "auth.supabase_refresh"
      });
    }

    const tokenHash = hashSecret(refreshToken);
    const nowIso = new Date().toISOString();

    const userId = await this.store.write((state) => {
      for (const user of state.users) {
        const token = (user.refreshTokens || []).find(
          (candidate) => candidate.tokenHash === tokenHash && !candidate.revokedAt && Date.parse(candidate.expiresAt) > Date.now()
        );

        if (!token) {
          continue;
        }

        token.revokedAt = nowIso;

        state.auditEvents.unshift({
          id: `audit_${crypto.randomUUID()}`,
          userId: user.id,
          action: "auth.refresh",
          ipAddress: context.ipAddress || null,
          userAgent: safeText(context.userAgent, { fallback: "" }),
          metadata: {},
          createdAt: nowIso
        });

        return user.id;
      }

      throw new HttpError(401, "Invalid refresh token.", { code: "AUTH_REFRESH_INVALID" });
    });

    const session = await this.createSession(userId, {
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      action: "auth.refresh.session"
    });

    const user = await this.getUserById(userId);

    return {
      user,
      ...session
    };
  }

  async logout(tokens = {}, context = {}) {
    if (this.config.authProvider === "supabase") {
      const refreshToken = String(tokens.refreshToken || "").trim();
      let accessToken = String(tokens.accessToken || "").trim();

      if (!accessToken && refreshToken) {
        try {
          const payload = await this.#supabaseRequest("/auth/v1/token?grant_type=refresh_token", {
            method: "POST",
            body: {
              refresh_token: refreshToken
            }
          });
          accessToken = String(payload?.access_token || "").trim();
        } catch {
          // If token refresh fails, we still allow local client logout to proceed.
        }
      }

      if (!accessToken) {
        return;
      }

      await this.#supabaseRequest("/auth/v1/logout", {
        method: "POST",
        accessToken
      }).catch((error) => {
        if (error instanceof HttpError && [400, 401, 403].includes(error.statusCode)) {
          return;
        }

        throw error;
      });
      return;
    }

    const refreshToken = String(tokens.refreshToken || "").trim();
    if (!refreshToken) {
      throw new HttpError(400, "refreshToken is required.", { code: "AUTH_REFRESH_REQUIRED" });
    }

    const tokenHash = hashSecret(refreshToken);

    await this.store.write((state) => {
      for (const user of state.users) {
        const token = (user.refreshTokens || []).find((candidate) => candidate.tokenHash === tokenHash && !candidate.revokedAt);

        if (!token) {
          continue;
        }

        token.revokedAt = new Date().toISOString();

        state.auditEvents.unshift({
          id: `audit_${crypto.randomUUID()}`,
          userId: user.id,
          action: "auth.logout",
          ipAddress: context.ipAddress || null,
          userAgent: safeText(context.userAgent, { fallback: "" }),
          metadata: {},
          createdAt: token.revokedAt
        });

        return;
      }
    });
  }

  async requestPasswordReset(email, context = {}) {
    const normalizedEmail = normalizeEmail(email);

    if (this.config.authProvider === "supabase") {
      const recoverPath = this.config.supabasePasswordResetRedirectUrl
        ? `/auth/v1/recover?redirect_to=${encodeURIComponent(this.config.supabasePasswordResetRedirectUrl)}`
        : "/auth/v1/recover";

      await this.#supabaseRequest(recoverPath, {
        method: "POST",
        body: {
          email: normalizedEmail
        }
      }).catch((error) => {
        if (error instanceof HttpError && [400, 404].includes(error.statusCode)) {
          return;
        }

        throw error;
      });
      return;
    }

    const now = Date.now();
    const nowIso = new Date(now).toISOString();

    await this.store.write((state) => {
      const user = state.users.find((candidate) => candidate.email === normalizedEmail);
      if (!user || user.status !== "active") {
        return;
      }

      const rawToken = `rst_${generateOpaqueToken(44)}`;
      const tokenHash = hashSecret(rawToken);
      const expiresAt = new Date(now + PASSWORD_RESET_TTL_MS).toISOString();

      user.passwordResetRequests = Array.isArray(user.passwordResetRequests) ? user.passwordResetRequests : [];
      user.passwordResetRequests.unshift({
        id: `pr_${crypto.randomUUID()}`,
        tokenHash,
        expiresAt,
        usedAt: null,
        createdAt: nowIso
      });
      user.passwordResetRequests = user.passwordResetRequests.slice(0, 5);

      state.auditEvents.unshift({
        id: `audit_${crypto.randomUUID()}`,
        userId: user.id,
        action: "auth.password_reset.requested",
        ipAddress: context.ipAddress || null,
        userAgent: safeText(context.userAgent, { fallback: "" }),
        metadata: {},
        createdAt: nowIso
      });

      if (!this.config.isProduction) {
        this.logger.info({ email: user.email, resetToken: rawToken, expiresAt }, "Local password reset token generated.");
      }
    });
  }

  async resetPassword({ password, accessToken, resetToken, email }, context = {}) {
    const normalizedEmail = normalizeEmail(email || "");

    if (this.config.authProvider === "supabase") {
      const recoveryAccessToken = String(accessToken || "").trim();
      if (!recoveryAccessToken) {
        throw new HttpError(400, "Password reset token is required.", { code: "AUTH_RESET_TOKEN_REQUIRED" });
      }

      const passwordError = passwordPolicyCheck(password, normalizedEmail);
      if (passwordError) {
        throw new HttpError(400, passwordError, { code: "AUTH_WEAK_PASSWORD" });
      }

      let payload;
      try {
        payload = await this.#supabaseRequest("/auth/v1/user", {
          method: "PUT",
          accessToken: recoveryAccessToken,
          body: {
            password
          }
        });
      } catch (error) {
        if (error instanceof HttpError && [400, 401, 403].includes(error.statusCode)) {
          throw new HttpError(401, "Reset link is invalid or has expired.", {
            code: "AUTH_RESET_TOKEN_INVALID"
          });
        }

        throw error;
      }

      await this.#upsertLocalUserFromSupabase(payload?.user || payload, {
        ipAddress: context.ipAddress,
        userAgent: context.userAgent,
        action: "auth.supabase_password_reset"
      }).catch(() => {
        // Password update already succeeded in Supabase; local upsert should not block response.
      });

      return {
        updated: true,
        message: "Password updated successfully. You can now sign in."
      };
    }

    const localResetToken = String(resetToken || "").trim();
    if (!localResetToken) {
      throw new HttpError(400, "Password reset token is required.", { code: "AUTH_RESET_TOKEN_REQUIRED" });
    }

    const resetTokenHash = hashSecret(localResetToken);
    const resetRequest = await this.store.read((state) => {
      for (const user of state.users) {
        if (user.status !== "active") {
          continue;
        }

        const token = (user.passwordResetRequests || []).find(
          (candidate) => candidate.tokenHash === resetTokenHash && !candidate.usedAt && Date.parse(candidate.expiresAt) > Date.now()
        );

        if (!token) {
          continue;
        }

        return {
          userId: user.id,
          email: user.email
        };
      }

      return null;
    });

    if (!resetRequest) {
      throw new HttpError(401, "Reset link is invalid or has expired.", { code: "AUTH_RESET_TOKEN_INVALID" });
    }

    const passwordError = passwordPolicyCheck(password, resetRequest.email);
    if (passwordError) {
      throw new HttpError(400, passwordError, { code: "AUTH_WEAK_PASSWORD" });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const nowIso = new Date().toISOString();

    await this.store.write((state) => {
      const user = state.users.find((candidate) => candidate.id === resetRequest.userId);
      if (!user || user.status !== "active") {
        throw new HttpError(401, "Reset link is invalid or has expired.", { code: "AUTH_RESET_TOKEN_INVALID" });
      }

      const token = (user.passwordResetRequests || []).find(
        (candidate) => candidate.tokenHash === resetTokenHash && !candidate.usedAt && Date.parse(candidate.expiresAt) > Date.now()
      );
      if (!token) {
        throw new HttpError(401, "Reset link is invalid or has expired.", { code: "AUTH_RESET_TOKEN_INVALID" });
      }

      user.passwordHash = passwordHash;
      user.updatedAt = nowIso;
      token.usedAt = nowIso;

      state.auditEvents.unshift({
        id: `audit_${crypto.randomUUID()}`,
        userId: user.id,
        action: "auth.password_reset.completed",
        ipAddress: context.ipAddress || null,
        userAgent: safeText(context.userAgent, { fallback: "" }),
        metadata: {},
        createdAt: nowIso
      });
    });

    return {
      updated: true,
      message: "Password updated successfully. You can now sign in."
    };
  }

  async getUserById(userId) {
    const user = await this.store.read((state) => state.users.find((candidate) => candidate.id === userId) || null);
    if (!user) {
      throw new HttpError(404, "User not found.", { code: "AUTH_USER_NOT_FOUND" });
    }

    return publicUser(user);
  }

  async createApiKey(userId, keyName, requestedScopes) {
    const name = safeText(keyName, { fallback: "Default API Key", maxLength: 40 });
    const scopes = normalizeApiKeyScopes(requestedScopes, { fallbackToAll: true });

    const result = await this.store.write((state) => {
      const user = state.users.find((candidate) => candidate.id === userId);

      if (!user || user.status !== "active") {
        throw new HttpError(404, "User not found.", { code: "AUTH_USER_NOT_FOUND" });
      }

      const activeKeys = (user.apiKeys || []).filter((key) => !key.revokedAt);
      if (activeKeys.length >= this.config.maxApiKeysPerUser) {
        throw new HttpError(400, "API key limit reached for this account.", { code: "AUTH_API_KEY_LIMIT" });
      }

      const prefix = `svk_${crypto.randomUUID().slice(0, 8)}`;
      const secret = generateOpaqueToken(30);
      const rawKey = `${prefix}.${secret}`;
      const key = {
        id: `key_${crypto.randomUUID()}`,
        name,
        keyPrefix: prefix,
        keyHash: hashSecret(rawKey),
        scopes: [...scopes],
        createdAt: new Date().toISOString(),
        lastUsedAt: null,
        revokedAt: null
      };

      user.apiKeys = user.apiKeys || [];
      user.apiKeys.unshift(key);

      state.auditEvents.unshift({
        id: `audit_${crypto.randomUUID()}`,
        userId,
        action: "auth.api_key.created",
        ipAddress: null,
        userAgent: "",
        metadata: {
          keyId: key.id,
          name: key.name,
          scopes: key.scopes
        },
        createdAt: key.createdAt
      });

      return {
        key,
        rawKey
      };
    });

    await this.notificationService?.create({
      userId,
      type: "api_key_created",
      tone: "info",
      title: "API key created",
      detail: `${result.key.name} is ready to copy and use.`,
      entityType: "api_key",
      entityId: result.key.id,
      dedupeKey: `api-key-created:${result.key.id}`
    });

    return {
      apiKey: result.rawKey,
      metadata: publicApiKey(result.key)
    };
  }

  async listApiKeys(userId) {
    const keys = await this.store.read((state) => {
      const user = state.users.find((candidate) => candidate.id === userId);
      if (!user) {
        throw new HttpError(404, "User not found.", { code: "AUTH_USER_NOT_FOUND" });
      }

      return (user.apiKeys || []).map(publicApiKey);
    });

    return keys;
  }

  async revokeApiKey(userId, keyId) {
    const revokedKey = await this.store.write((state) => {
      const user = state.users.find((candidate) => candidate.id === userId);
      if (!user) {
        throw new HttpError(404, "User not found.", { code: "AUTH_USER_NOT_FOUND" });
      }

      const key = (user.apiKeys || []).find((candidate) => candidate.id === keyId);
      if (!key || key.revokedAt) {
        throw new HttpError(404, "API key not found.", { code: "AUTH_API_KEY_NOT_FOUND" });
      }

      key.revokedAt = new Date().toISOString();

      state.auditEvents.unshift({
        id: `audit_${crypto.randomUUID()}`,
        userId,
        action: "auth.api_key.revoked",
        ipAddress: null,
        userAgent: "",
        metadata: {
          keyId
        },
        createdAt: key.revokedAt
      });

      return {
        id: key.id,
        name: key.name
      };
    });

    await this.notificationService?.create({
      userId,
      type: "api_key_revoked",
      tone: "warning",
      title: "API key revoked",
      detail: `${revokedKey.name} can no longer access the API.`,
      entityType: "api_key",
      entityId: revokedKey.id,
      dedupeKey: `api-key-revoked:${revokedKey.id}`
    });
  }

  async consumeDailyQuota(userId) {
    const quota = await this.store.write((state) => {
      const user = state.users.find((candidate) => candidate.id === userId);
      if (!user) {
        throw new HttpError(404, "User not found.", { code: "AUTH_USER_NOT_FOUND" });
      }

      if (user.role === "admin") {
        return {
          allowed: true,
          limit: null,
          used: 0,
          remaining: null
        };
      }

      const usage = buildUsageSnapshot(state, user, this.config.freeTierDailyScanLimit);

      if (usage.used >= this.config.freeTierDailyScanLimit) {
        return {
          allowed: false,
          limit: this.config.freeTierDailyScanLimit,
          used: usage.used,
          remaining: 0
        };
      }

      user.usage = {
        windowStartedAt: usage.windowStartedAt,
        scans: usage.used + 1
      };
      user.updatedAt = new Date().toISOString();

      return {
        allowed: true,
        limit: this.config.freeTierDailyScanLimit,
        used: usage.used + 1,
        remaining: Math.max(0, this.config.freeTierDailyScanLimit - (usage.used + 1)),
        windowStartedAt: usage.windowStartedAt
      };
    });

    await this.#notifyUsageThreshold(userId, quota, { requestedScans: 1 });
    return quota;
  }

  async consumeDailyQuotaBatch(userId, requestedScans) {
    const quota = await this.store.write((state) => {
      const user = state.users.find((candidate) => candidate.id === userId);
      if (!user) {
        throw new HttpError(404, "User not found.", { code: "AUTH_USER_NOT_FOUND" });
      }

      const batchSize = Math.max(1, Math.floor(Number(requestedScans) || 0));

      if (user.role === "admin") {
        return {
          allowed: true,
          accepted: batchSize,
          limit: null,
          used: 0,
          remaining: null
        };
      }

      const usage = buildUsageSnapshot(state, user, this.config.freeTierDailyScanLimit);
      const remaining = Math.max(0, this.config.freeTierDailyScanLimit - usage.used);
      if (remaining < batchSize) {
        return {
          allowed: false,
          accepted: 0,
          limit: this.config.freeTierDailyScanLimit,
          used: usage.used,
          remaining,
          windowStartedAt: usage.windowStartedAt
        };
      }

      user.usage = {
        windowStartedAt: usage.windowStartedAt,
        scans: usage.used + batchSize
      };
      user.updatedAt = new Date().toISOString();

      return {
        allowed: true,
        accepted: batchSize,
        limit: this.config.freeTierDailyScanLimit,
        used: usage.used + batchSize,
        remaining: Math.max(0, this.config.freeTierDailyScanLimit - (usage.used + batchSize)),
        windowStartedAt: usage.windowStartedAt
      };
    });

    await this.#notifyUsageThreshold(userId, quota, { requestedScans });
    return quota;
  }

  async listNotifications(userId, limit = 20, offset = 0) {
    if (!this.notificationService) {
      return {
        notifications: [],
        unreadCount: 0,
        totalCount: 0,
        limit,
        offset: Math.max(0, Number(offset) || 0),
        hasMore: false
      };
    }

    return this.notificationService.listForUser(userId, limit, offset);
  }

  async markNotificationsRead(userId, ids = []) {
    if (!this.notificationService) {
      return {
        updated: 0
      };
    }

    return this.notificationService.markRead(userId, ids);
  }

  async getUsage(userId) {
    return this.store.read((state) => {
      const user = state.users.find((candidate) => candidate.id === userId);
      if (!user) {
        throw new HttpError(404, "User not found.", { code: "AUTH_USER_NOT_FOUND" });
      }

      return buildUsageSnapshot(state, user, this.config.freeTierDailyScanLimit);
    });
  }

  async getAdminMetrics() {
    return this.store.read((state) => {
      const completedJobs = state.jobs.filter((job) => job.status === "completed").length;
      const failedJobs = state.jobs.filter((job) => job.status === "failed").length;

      return {
        users: state.users.length,
        reports: state.reports.length,
        jobs: {
          total: state.jobs.length,
          completed: completedJobs,
          failed: failedJobs,
          queued: state.jobs.filter((job) => job.status === "queued").length,
          processing: state.jobs.filter((job) => job.status === "processing").length
        },
        auditEvents: state.auditEvents.length
      };
    });
  }

  async listAuditEvents(limit = 100) {
    return this.store.read((state) => state.auditEvents.slice(0, Math.max(1, Math.min(500, Number(limit) || 100))));
  }
}

export { publicUser, publicApiKey };
