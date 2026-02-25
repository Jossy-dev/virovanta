import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { HttpError } from "../utils/httpError.js";
import { generateOpaqueToken, hashSecret, normalizeEmail, safeText, todayDateStamp } from "../utils/security.js";

const TOKEN_ALGORITHM = "HS256";

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

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
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
    createdAt: key.createdAt,
    lastUsedAt: key.lastUsedAt || null,
    revokedAt: key.revokedAt || null
  };
}

export class AuthService {
  constructor({ store, config, logger }) {
    this.store = store;
    this.config = config;
    this.logger = logger;
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
    try {
      const payload = jwt.verify(token, this.config.jwtAccessSecret, {
        algorithms: [TOKEN_ALGORITHM],
        issuer: this.config.jwtIssuer,
        audience: this.config.jwtAudience
      });

      const user = await this.store.read((state) => state.users.find((candidate) => candidate.id === payload.sub) || null);
      if (!user || user.status !== "active") {
        throw new HttpError(401, "Unauthorized.", { code: "AUTH_UNAUTHORIZED" });
      }

      return {
        user,
        authMethod: "bearer"
      };
    } catch (error) {
      if (error instanceof HttpError) {
        throw error;
      }

      throw new HttpError(401, "Invalid or expired token.", { code: "AUTH_TOKEN_INVALID" });
    }
  }

  async authenticateApiKey(rawKey) {
    const keyHash = hashSecret(rawKey);

    const match = await this.store.read((state) => {
      for (const user of state.users) {
        const key = (user.apiKeys || []).find((candidate) => candidate.keyHash === keyHash && !candidate.revokedAt);

        if (key) {
          return { user, keyId: key.id };
        }
      }

      return null;
    });

    if (!match || match.user.status !== "active") {
      throw new HttpError(401, "Invalid API key.", { code: "AUTH_API_KEY_INVALID" });
    }

    await this.store.write((state) => {
      const user = state.users.find((candidate) => candidate.id === match.user.id);
      if (!user) {
        return;
      }

      const key = (user.apiKeys || []).find((candidate) => candidate.id === match.keyId);
      if (key) {
        key.lastUsedAt = new Date().toISOString();
      }
    });

    return {
      user: match.user,
      authMethod: "api_key"
    };
  }

  async register({ email, password, name }, context = {}) {
    if (!this.config.allowOpenRegistration) {
      throw new HttpError(403, "Registration is disabled.", { code: "AUTH_REGISTRATION_DISABLED" });
    }

    const normalizedEmail = normalizeEmail(email);
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

      const user = {
        id: `usr_${crypto.randomUUID()}`,
        email: normalizedEmail,
        name: safeText(name, { fallback: normalizedEmail.split("@")[0], maxLength: 80 }),
        role: state.users.length === 0 ? "admin" : "user",
        status: "active",
        passwordHash,
        createdAt: now,
        updatedAt: now,
        lastLoginAt: null,
        refreshTokens: [],
        apiKeys: [],
        usage: {
          day: todayDateStamp(),
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

  async login({ email, password }, context = {}) {
    const normalizedEmail = normalizeEmail(email);

    const user = await this.store.read((state) => state.users.find((candidate) => candidate.email === normalizedEmail) || null);

    if (!user || user.status !== "active") {
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

  async logout(refreshToken, context = {}) {
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

  async getUserById(userId) {
    const user = await this.store.read((state) => state.users.find((candidate) => candidate.id === userId) || null);
    if (!user) {
      throw new HttpError(404, "User not found.", { code: "AUTH_USER_NOT_FOUND" });
    }

    return publicUser(user);
  }

  async createApiKey(userId, keyName) {
    const name = safeText(keyName, { fallback: "Default API Key", maxLength: 40 });

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
          name: key.name
        },
        createdAt: key.createdAt
      });

      return {
        key,
        rawKey
      };
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
    await this.store.write((state) => {
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
    });
  }

  async consumeDailyQuota(userId) {
    return this.store.write((state) => {
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

      user.usage = user.usage || {
        day: todayDateStamp(),
        scans: 0
      };

      if (user.usage.day !== todayDateStamp()) {
        user.usage.day = todayDateStamp();
        user.usage.scans = 0;
      }

      if (user.usage.scans >= this.config.freeTierDailyScanLimit) {
        return {
          allowed: false,
          limit: this.config.freeTierDailyScanLimit,
          used: user.usage.scans,
          remaining: 0
        };
      }

      user.usage.scans += 1;
      user.updatedAt = new Date().toISOString();

      return {
        allowed: true,
        limit: this.config.freeTierDailyScanLimit,
        used: user.usage.scans,
        remaining: Math.max(0, this.config.freeTierDailyScanLimit - user.usage.scans)
      };
    });
  }

  async getUsage(userId) {
    return this.store.read((state) => {
      const user = state.users.find((candidate) => candidate.id === userId);
      if (!user) {
        throw new HttpError(404, "User not found.", { code: "AUTH_USER_NOT_FOUND" });
      }

      const usage = user.usage || { day: todayDateStamp(), scans: 0 };

      if (user.role === "admin") {
        return {
          day: usage.day,
          used: usage.scans,
          remaining: null,
          limit: null
        };
      }

      return {
        day: usage.day,
        used: usage.scans,
        remaining: Math.max(0, this.config.freeTierDailyScanLimit - usage.scans),
        limit: this.config.freeTierDailyScanLimit
      };
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
