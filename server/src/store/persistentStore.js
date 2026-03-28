import fs from "fs";
import fsp from "fs/promises";
import path from "path";
import { Pool } from "pg";
import { applyStoreMigrations, buildStoreMigrations } from "./postgresMigrations.js";
import { hashSecret } from "../utils/security.js";

const POSTGRES_WRITE_MAX_ATTEMPTS = 4;
const POSTGRES_RETRY_BASE_DELAY_MS = 120;
const POSTGRES_RETRY_MAX_DELAY_MS = 1_000;

const DEFAULT_STATE = {
  version: 1,
  users: [],
  reports: [],
  jobs: [],
  notifications: [],
  auditEvents: []
};

const ANALYTICS_WINDOW_DAYS = 30;
const ANALYTICS_MONTH_BUCKETS = 6;

function cloneState(state) {
  return structuredClone(state);
}

function normalizeIdentifier(value, fallback) {
  const normalized = String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, "_")
    .replace(/^_+|_+$/g, "");

  return normalized || fallback;
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function toIsoOrNull(value) {
  if (!value) {
    return null;
  }

  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return null;
  }

  return date.toISOString();
}

function normalizeScopes(value) {
  return Array.isArray(value) ? value.map((entry) => String(entry || "")).filter(Boolean) : [];
}

function normalizeSourceType(value) {
  if (value === "url") {
    return "url";
  }

  if (value === "website") {
    return "website";
  }

  return "file";
}

function worstVerdictFromRank(rank) {
  if (rank >= 3) {
    return "malicious";
  }

  if (rank === 2) {
    return "suspicious";
  }

  return "clean";
}

function monthLabel(date) {
  return new Intl.DateTimeFormat("en-US", { month: "short" }).format(date);
}

function createMonthBuckets(count = ANALYTICS_MONTH_BUCKETS) {
  const now = new Date();
  const buckets = [];

  for (let index = count - 1; index >= 0; index -= 1) {
    const bucketDate = new Date(now.getFullYear(), now.getMonth() - index, 1);
    buckets.push({
      key: `${bucketDate.getFullYear()}-${bucketDate.getMonth()}`,
      month: monthLabel(bucketDate),
      reports: 0,
      flagged: 0,
      jobs: 0
    });
  }

  return buckets;
}

function mapUserRow(row) {
  if (!row) {
    return null;
  }

  return {
    id: row.id,
    email: row.email,
    name: row.name,
    role: row.role,
    status: row.status,
    passwordHash: row.password_hash,
    authSource: row.auth_source,
    createdAt: toIsoOrNull(row.created_at),
    updatedAt: toIsoOrNull(row.updated_at),
    lastLoginAt: toIsoOrNull(row.last_login_at),
    refreshTokens: [],
    apiKeys: [],
    passwordResetRequests: []
  };
}

function mapRefreshTokenRow(row) {
  return {
    id: row.id,
    tokenHash: row.token_hash,
    expiresAt: toIsoOrNull(row.expires_at),
    revokedAt: toIsoOrNull(row.revoked_at),
    createdAt: toIsoOrNull(row.created_at)
  };
}

function mapPasswordResetRow(row) {
  return {
    id: row.id,
    tokenHash: row.token_hash,
    expiresAt: toIsoOrNull(row.expires_at),
    usedAt: toIsoOrNull(row.used_at),
    createdAt: toIsoOrNull(row.created_at)
  };
}

function mapApiKeyRow(row) {
  return {
    id: row.id,
    name: row.name,
    keyPrefix: row.key_prefix,
    keyHash: row.key_hash,
    scopes: normalizeScopes(row.scopes),
    createdAt: toIsoOrNull(row.created_at),
    lastUsedAt: toIsoOrNull(row.last_used_at),
    revokedAt: toIsoOrNull(row.revoked_at)
  };
}

function mapJobRow(row) {
  if (!row) {
    return null;
  }

  return {
    id: row.id,
    userId: row.user_id,
    sourceType: normalizeSourceType(row.source_type),
    targetUrl: row.target_url || null,
    status: row.status,
    originalName: row.original_name,
    mimeType: row.mime_type,
    fileSize: Number(row.file_size) || 0,
    createdAt: toIsoOrNull(row.created_at),
    updatedAt: toIsoOrNull(row.updated_at),
    startedAt: toIsoOrNull(row.started_at),
    completedAt: toIsoOrNull(row.completed_at),
    reportId: row.report_id || null,
    errorMessage: row.error_message || null
  };
}

function mapNotificationRow(row) {
  return {
    id: row.id,
    userId: row.user_id,
    type: row.type,
    tone: row.tone,
    title: row.title,
    detail: row.detail,
    entityType: row.entity_type || null,
    entityId: row.entity_id || null,
    dedupeKey: row.dedupe_key || null,
    createdAt: toIsoOrNull(row.created_at),
    readAt: toIsoOrNull(row.read_at)
  };
}

function mapAuditEventRow(row) {
  return {
    id: row.id,
    userId: row.user_id || null,
    action: row.action,
    ipAddress: row.ip_address || null,
    userAgent: row.user_agent || "",
    metadata: row.metadata || {},
    createdAt: toIsoOrNull(row.created_at)
  };
}

function extractReportColumns(report) {
  const detectedFileType = String(report?.file?.detectedFileType || "").trim();
  const fileExtension = String(report?.file?.extension || "").trim();
  const sha256 = String(report?.file?.hashes?.sha256 || "").trim() || null;

  return {
    id: report.id,
    ownerUserId: report.ownerUserId,
    sourceType: normalizeSourceType(report.sourceType),
    queuedJobId: report.queuedJobId || null,
    createdAt: report.createdAt,
    completedAt: report.completedAt,
    verdict: report.verdict,
    riskScore: Number(report.riskScore) || 0,
    fileName: report?.file?.originalName || report?.url?.final || report?.url?.input || "Unknown target",
    fileSize: Number(report?.file?.size) || 0,
    fileSha256: sha256,
    detectedFileType,
    fileExtension,
    payload: report,
    deletedAt: report.deletedAt || null,
    deletedByUserId: report.deletedByUserId || null
  };
}

function mapReportPayloadRow(row) {
  if (!row) {
    return null;
  }

  return row.payload || null;
}

function normalizeLegacyState(input) {
  if (!input || typeof input !== "object") {
    return cloneState(DEFAULT_STATE);
  }

  return {
    version: Number(input.version) || 1,
    users: Array.isArray(input.users) ? input.users : [],
    reports: Array.isArray(input.reports) ? input.reports : [],
    jobs: Array.isArray(input.jobs) ? input.jobs : [],
    notifications: Array.isArray(input.notifications) ? input.notifications : [],
    auditEvents: Array.isArray(input.auditEvents) ? input.auditEvents : []
  };
}

export class PersistentStore {
  constructor({
    filePath,
    reportTtlMs,
    maxReports,
    driver = "file",
    databaseUrl = "",
    databaseSsl = false,
    databaseSslRejectUnauthorized = true,
    stateTable = "virovanta_state"
  }) {
    this.filePath = filePath;
    this.reportTtlMs = reportTtlMs;
    this.maxReports = maxReports;
    this.driver = driver;
    this.databaseUrl = databaseUrl;
    this.databaseSsl = databaseSsl;
    this.databaseSslRejectUnauthorized = databaseSslRejectUnauthorized;
    this.stateTable = normalizeIdentifier(stateTable, "virovanta_state");
    this.tableBase = this.stateTable.replace(/_state$/, "") || "virovanta";
    this.usersTable = `${this.tableBase}_users`;
    this.apiKeysTable = `${this.tableBase}_api_keys`;
    this.refreshTokensTable = `${this.tableBase}_refresh_tokens`;
    this.passwordResetTable = `${this.tableBase}_password_reset_tokens`;
    this.jobsTable = `${this.tableBase}_jobs`;
    this.reportsTable = `${this.tableBase}_reports`;
    this.notificationsTable = `${this.tableBase}_notifications`;
    this.auditEventsTable = `${this.tableBase}_audit_events`;
    this.migrationsTable = `${this.tableBase}_schema_migrations`;
    this.state = cloneState(DEFAULT_STATE);
    this.writeChain = Promise.resolve();
    this.pool = null;
  }

  async init() {
    if (this.driver === "postgres") {
      await this.#initPostgres();
      return;
    }

    await fsp.mkdir(path.dirname(this.filePath), { recursive: true });

    try {
      const raw = await fsp.readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw);
      this.state = normalizeLegacyState(parsed);
      this.#pruneState(this.state);
      await this.#persistFile(this.state);
    } catch (error) {
      if (error?.code !== "ENOENT") {
        throw error;
      }

      this.state = cloneState(DEFAULT_STATE);
      await this.#persistFile(this.state);
    }
  }

  async getOperationalStatus() {
    if (this.driver !== "postgres") {
      return {
        status: "ok",
        ready: true,
        driver: "file",
        tableBase: this.tableBase,
        migrationsTable: null,
        migrationCount: 0,
        latestMigration: null,
        latestMigrationAppliedAt: null,
        alerts: []
      };
    }

    const [probeResult, migrationsResult] = await Promise.all([
      this.pool.query("SELECT 1 AS ok"),
      this.pool.query(`SELECT name, applied_at FROM ${this.migrationsTable} ORDER BY name ASC`)
    ]);
    const latestMigration = migrationsResult.rows[migrationsResult.rows.length - 1] || null;

    return {
      status: probeResult.rowCount > 0 ? "ok" : "degraded",
      ready: probeResult.rowCount > 0,
      driver: "postgres",
      tableBase: this.tableBase,
      migrationsTable: this.migrationsTable,
      migrationCount: migrationsResult.rowCount,
      latestMigration: latestMigration?.name || null,
      latestMigrationAppliedAt: toIsoOrNull(latestMigration?.applied_at),
      alerts: []
    };
  }

  async read(selector) {
    if (this.driver === "postgres") {
      const current = await this.#materializePostgresState();
      return selector(current);
    }

    return selector(this.state);
  }

  async write(mutator) {
    const operation = async () => {
      if (this.driver === "postgres") {
        throw new Error("Generic store.write is not supported when DATA_STORE_DRIVER=postgres. Use row-level store methods.");
      }

      const nextState = cloneState(this.state);
      const result = await mutator(nextState);
      this.#pruneState(nextState);
      this.state = nextState;
      await this.#persistFile(nextState);
      return result;
    };

    this.writeChain = this.writeChain.then(operation, operation);
    return this.writeChain;
  }

  async close() {
    if (this.pool) {
      await this.pool.end();
      this.pool = null;
    }
  }

  async findUserById(userId) {
    if (this.driver !== "postgres") {
      return this.read((state) => state.users.find((candidate) => candidate.id === userId) || null);
    }

    const result = await this.pool.query(`SELECT * FROM ${this.usersTable} WHERE id = $1 LIMIT 1`, [userId]);
    return mapUserRow(result.rows[0]);
  }

  async findUserByEmail(email) {
    if (this.driver !== "postgres") {
      return this.read((state) => state.users.find((candidate) => candidate.email === email) || null);
    }

    const result = await this.pool.query(`SELECT * FROM ${this.usersTable} WHERE email_normalized = $1 LIMIT 1`, [email]);
    return mapUserRow(result.rows[0]);
  }

  async isUsernameTaken(username) {
    const normalized = String(username || "").trim().toLowerCase();

    if (this.driver !== "postgres") {
      return this.read((state) =>
        state.users.some((candidate) => String(candidate?.name || "").trim().toLowerCase() === normalized)
      );
    }

    const result = await this.pool.query(`SELECT 1 FROM ${this.usersTable} WHERE name_normalized = $1 LIMIT 1`, [normalized]);
    return result.rowCount > 0;
  }

  async upsertSupabaseUser({ userId, email, name, now, action, ipAddress = null, userAgent = "" }) {
    if (this.driver !== "postgres") {
      const existingUser = await this.read((state) =>
        state.users.find((candidate) => candidate.id === userId || candidate.email === email) || null
      );

      if (existingUser) {
        const nextUser = {
          ...existingUser,
          id: userId,
          email,
          name: existingUser.name || name,
          status: "active",
          authSource: "supabase",
          updatedAt: now,
          lastLoginAt: existingUser.lastLoginAt || now,
          refreshTokens: Array.isArray(existingUser.refreshTokens) ? existingUser.refreshTokens : [],
          apiKeys: Array.isArray(existingUser.apiKeys) ? existingUser.apiKeys : []
        };

        await this.write((state) => {
          const index = state.users.findIndex((candidate) => candidate.id === existingUser.id);
          if (index >= 0) {
            state.users[index] = nextUser;
          }
        }).catch(() => {});

        return nextUser;
      }

      return this.write((state) => {
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
          action,
          ipAddress,
          userAgent,
          metadata: {
            provider: "supabase"
          },
          createdAt: now
        });

        return nextUser;
      });
    }

    return this.#withTransaction(async (client) => {
      const byIdResult = await client.query(`SELECT * FROM ${this.usersTable} WHERE id = $1 LIMIT 1`, [userId]);
      if (byIdResult.rowCount > 0) {
        return mapUserRow(byIdResult.rows[0]);
      }

      const byEmailResult = await client.query(`SELECT * FROM ${this.usersTable} WHERE email_normalized = $1 LIMIT 1`, [email]);
      if (byEmailResult.rowCount > 0) {
        const existing = byEmailResult.rows[0];
        const updated = await client.query(
          `
            UPDATE ${this.usersTable}
            SET
              id = $2,
              email = $3,
              email_normalized = $4,
              name = COALESCE(NULLIF(name, ''), $5),
              name_normalized = COALESCE(NULLIF(name_normalized, ''), $6),
              status = 'active',
              auth_source = 'supabase',
              updated_at = $7
            WHERE id = $1
            RETURNING *
          `,
          [existing.id, userId, email, email, name, String(name || "").trim().toLowerCase(), now]
        );
        return mapUserRow(updated.rows[0]);
      }

      const inserted = await client.query(
        `
          INSERT INTO ${this.usersTable} (
            id,
            email,
            email_normalized,
            name,
            name_normalized,
            role,
            status,
            password_hash,
            auth_source,
            created_at,
            updated_at,
            last_login_at
          ) VALUES ($1, $2, $3, $4, $5, 'user', 'active', NULL, 'supabase', $6, $6, $6)
          RETURNING *
        `,
        [userId, email, email, name, String(name || "").trim().toLowerCase(), now]
      );

      await client.query(
        `
          INSERT INTO ${this.auditEventsTable} (
            id,
            user_id,
            action,
            ip_address,
            user_agent,
            metadata,
            created_at
          ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
        `,
        [
          `audit_${crypto.randomUUID()}`,
          userId,
          action,
          ipAddress,
          String(userAgent || ""),
          JSON.stringify({ provider: "supabase" }),
          now
        ]
      );

      return mapUserRow(inserted.rows[0]);
    });
  }

  async createLocalUser({ email, name, passwordHash, now, ipAddress = null, userAgent = "" }) {
    if (this.driver !== "postgres") {
      return this.write((state) => {
        const existing = state.users.find((candidate) => candidate.email === email);
        if (existing) {
          return null;
        }

        const user = {
          id: `usr_${crypto.randomUUID()}`,
          email,
          name,
          role: state.users.length === 0 ? "admin" : "user",
          status: "active",
          passwordHash,
          authSource: "local",
          createdAt: now,
          updatedAt: now,
          lastLoginAt: null,
          refreshTokens: [],
          apiKeys: [],
          passwordResetRequests: [],
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
          ipAddress,
          userAgent,
          metadata: {
            role: user.role
          },
          createdAt: now
        });

        return user;
      });
    }

    return this.#withTransaction(async (client) => {
      const existing = await client.query(`SELECT 1 FROM ${this.usersTable} WHERE email_normalized = $1 LIMIT 1`, [email]);
      if (existing.rowCount > 0) {
        return null;
      }

      const countResult = await client.query(`SELECT COUNT(*)::int AS count FROM ${this.usersTable}`);
      const role = Number(countResult.rows[0]?.count) === 0 ? "admin" : "user";
      const userId = `usr_${crypto.randomUUID()}`;

      const inserted = await client.query(
        `
          INSERT INTO ${this.usersTable} (
            id,
            email,
            email_normalized,
            name,
            name_normalized,
            role,
            status,
            password_hash,
            auth_source,
            created_at,
            updated_at,
            last_login_at
          ) VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, 'local', $8, $8, NULL)
          RETURNING *
        `,
        [userId, email, email, name, String(name || "").trim().toLowerCase(), role, passwordHash, now]
      );

      await client.query(
        `
          INSERT INTO ${this.auditEventsTable} (
            id,
            user_id,
            action,
            ip_address,
            user_agent,
            metadata,
            created_at
          ) VALUES ($1, $2, 'auth.register', $3, $4, $5::jsonb, $6)
        `,
        [
          `audit_${crypto.randomUUID()}`,
          userId,
          ipAddress,
          String(userAgent || ""),
          JSON.stringify({ role }),
          now
        ]
      );

      return mapUserRow(inserted.rows[0]);
    });
  }

  async recordLocalLogin({ userId, now, ipAddress = null, userAgent = "" }) {
    if (this.driver !== "postgres") {
      await this.write((state) => {
        const editableUser = state.users.find((candidate) => candidate.id === userId);
        if (!editableUser) {
          return;
        }

        editableUser.lastLoginAt = now;
        editableUser.updatedAt = now;
        state.auditEvents.unshift({
          id: `audit_${crypto.randomUUID()}`,
          userId,
          action: "auth.login",
          ipAddress,
          userAgent,
          metadata: {},
          createdAt: now
        });
      });
      return;
    }

    await this.#withTransaction(async (client) => {
      await client.query(
        `UPDATE ${this.usersTable} SET last_login_at = $2, updated_at = $2 WHERE id = $1`,
        [userId, now]
      );
      await client.query(
        `
          INSERT INTO ${this.auditEventsTable} (id, user_id, action, ip_address, user_agent, metadata, created_at)
          VALUES ($1, $2, 'auth.login', $3, $4, '{}'::jsonb, $5)
        `,
        [`audit_${crypto.randomUUID()}`, userId, ipAddress, String(userAgent || ""), now]
      );
    });
  }

  async createLocalSession({ userId, refreshTokenHash, expiresAt, createdAt, action, ipAddress = null, userAgent = "" }) {
    if (this.driver !== "postgres") {
      return this.write((state) => {
        const editableUser = state.users.find((candidate) => candidate.id === userId);
        if (!editableUser || editableUser.status !== "active") {
          return null;
        }

        editableUser.refreshTokens = editableUser.refreshTokens || [];
        editableUser.refreshTokens.unshift({
          id: `rt_${crypto.randomUUID()}`,
          tokenHash: refreshTokenHash,
          expiresAt,
          revokedAt: null,
          createdAt
        });
        editableUser.refreshTokens = editableUser.refreshTokens.slice(0, 20);

        state.auditEvents.unshift({
          id: `audit_${crypto.randomUUID()}`,
          userId,
          action,
          ipAddress,
          userAgent,
          metadata: {
            expiresAt
          },
          createdAt
        });

        return editableUser;
      });
    }

    return this.#withTransaction(async (client) => {
      const userResult = await client.query(
        `SELECT * FROM ${this.usersTable} WHERE id = $1 AND status = 'active' LIMIT 1`,
        [userId]
      );
      if (userResult.rowCount === 0) {
        return null;
      }

      const tokenId = `rt_${crypto.randomUUID()}`;
      await client.query(
        `
          INSERT INTO ${this.refreshTokensTable} (id, user_id, token_hash, expires_at, revoked_at, created_at)
          VALUES ($1, $2, $3, $4, NULL, $5)
        `,
        [tokenId, userId, refreshTokenHash, expiresAt, createdAt]
      );

      await client.query(
        `
          INSERT INTO ${this.auditEventsTable} (id, user_id, action, ip_address, user_agent, metadata, created_at)
          VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
        `,
        [
          `audit_${crypto.randomUUID()}`,
          userId,
          action,
          ipAddress,
          String(userAgent || ""),
          JSON.stringify({ expiresAt }),
          createdAt
        ]
      );

      return mapUserRow(userResult.rows[0]);
    });
  }

  async consumeLocalRefreshToken({ tokenHash, now, ipAddress = null, userAgent = "", action }) {
    if (this.driver !== "postgres") {
      return this.write((state) => {
        for (const user of state.users) {
          const token = (user.refreshTokens || []).find(
            (candidate) => candidate.tokenHash === tokenHash && !candidate.revokedAt && Date.parse(candidate.expiresAt) > Date.now()
          );
          if (!token) {
            continue;
          }

          token.revokedAt = now;
          state.auditEvents.unshift({
            id: `audit_${crypto.randomUUID()}`,
            userId: user.id,
            action,
            ipAddress,
            userAgent,
            metadata: {},
            createdAt: now
          });
          return user.id;
        }

        return null;
      });
    }

    return this.#withTransaction(async (client) => {
      const tokenResult = await client.query(
        `
          SELECT id, user_id
          FROM ${this.refreshTokensTable}
          WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()
          LIMIT 1
          FOR UPDATE
        `,
        [tokenHash]
      );
      if (tokenResult.rowCount === 0) {
        return null;
      }

      const token = tokenResult.rows[0];
      await client.query(`UPDATE ${this.refreshTokensTable} SET revoked_at = $2 WHERE id = $1`, [token.id, now]);
      await client.query(
        `
          INSERT INTO ${this.auditEventsTable} (id, user_id, action, ip_address, user_agent, metadata, created_at)
          VALUES ($1, $2, $3, $4, $5, '{}'::jsonb, $6)
        `,
        [`audit_${crypto.randomUUID()}`, token.user_id, action, ipAddress, String(userAgent || ""), now]
      );

      return token.user_id;
    });
  }

  async revokeLocalRefreshToken({ tokenHash, now, ipAddress = null, userAgent = "" }) {
    if (this.driver !== "postgres") {
      await this.write((state) => {
        for (const user of state.users) {
          const token = (user.refreshTokens || []).find((candidate) => candidate.tokenHash === tokenHash && !candidate.revokedAt);
          if (!token) {
            continue;
          }

          token.revokedAt = now;
          state.auditEvents.unshift({
            id: `audit_${crypto.randomUUID()}`,
            userId: user.id,
            action: "auth.logout",
            ipAddress,
            userAgent,
            metadata: {},
            createdAt: now
          });
          return;
        }
      });
      return;
    }

    await this.#withTransaction(async (client) => {
      const tokenResult = await client.query(
        `SELECT id, user_id FROM ${this.refreshTokensTable} WHERE token_hash = $1 AND revoked_at IS NULL LIMIT 1 FOR UPDATE`,
        [tokenHash]
      );
      if (tokenResult.rowCount === 0) {
        return;
      }

      const token = tokenResult.rows[0];
      await client.query(`UPDATE ${this.refreshTokensTable} SET revoked_at = $2 WHERE id = $1`, [token.id, now]);
      await client.query(
        `
          INSERT INTO ${this.auditEventsTable} (id, user_id, action, ip_address, user_agent, metadata, created_at)
          VALUES ($1, $2, 'auth.logout', $3, $4, '{}'::jsonb, $5)
        `,
        [`audit_${crypto.randomUUID()}`, token.user_id, ipAddress, String(userAgent || ""), now]
      );
    });
  }

  async createPasswordResetRequest({ email, now, ipAddress = null, userAgent = "" }) {
    const rawToken = `rst_${crypto.randomUUID().replace(/-/g, "")}${crypto.randomUUID().replace(/-/g, "")}`;
    const tokenHash = hashSecret(rawToken);
    const expiresAt = new Date(Date.parse(now) + 30 * 60 * 1000).toISOString();

    if (this.driver !== "postgres") {
      await this.write((state) => {
        const user = state.users.find((candidate) => candidate.email === email);
        if (!user || user.status !== "active") {
          return;
        }

        user.passwordResetRequests = Array.isArray(user.passwordResetRequests) ? user.passwordResetRequests : [];
        user.passwordResetRequests.unshift({
          id: `pr_${crypto.randomUUID()}`,
          tokenHash,
          expiresAt,
          usedAt: null,
          createdAt: now,
          rawToken
        });
        user.passwordResetRequests = user.passwordResetRequests.slice(0, 5);
        state.auditEvents.unshift({
          id: `audit_${crypto.randomUUID()}`,
          userId: user.id,
          action: "auth.password_reset.requested",
          ipAddress,
          userAgent,
          metadata: {},
          createdAt: now
        });
      });

      return {
        email,
        resetToken: rawToken,
        expiresAt
      };
    }

    return this.#withTransaction(async (client) => {
      const userResult = await client.query(
        `SELECT id, email FROM ${this.usersTable} WHERE email_normalized = $1 AND status = 'active' LIMIT 1`,
        [email]
      );
      if (userResult.rowCount === 0) {
        return null;
      }

      const user = userResult.rows[0];
      await client.query(
        `
          INSERT INTO ${this.passwordResetTable} (id, user_id, token_hash, expires_at, used_at, created_at)
          VALUES ($1, $2, $3, $4, NULL, $5)
        `,
        [
          `pr_${crypto.randomUUID()}`,
          user.id,
          tokenHash,
          expiresAt,
          now
        ]
      );
      await client.query(
        `
          INSERT INTO ${this.auditEventsTable} (id, user_id, action, ip_address, user_agent, metadata, created_at)
          VALUES ($1, $2, 'auth.password_reset.requested', $3, $4, '{}'::jsonb, $5)
        `,
        [`audit_${crypto.randomUUID()}`, user.id, ipAddress, String(userAgent || ""), now]
      );

      return {
        email: user.email,
        resetToken: rawToken,
        expiresAt
      };
    });
  }

  async findPasswordResetTarget(tokenHash) {
    if (this.driver !== "postgres") {
      return this.read((state) => {
        for (const user of state.users) {
          if (user.status !== "active") {
            continue;
          }

          const token = (user.passwordResetRequests || []).find(
            (candidate) => (candidate.rawToken || candidate.tokenHash) === tokenHash && !candidate.usedAt && Date.parse(candidate.expiresAt) > Date.now()
          );
          if (token) {
            return {
              userId: user.id,
              email: user.email
            };
          }
        }

        return null;
      });
    }

    const result = await this.pool.query(
      `
        SELECT u.id AS user_id, u.email
        FROM ${this.passwordResetTable} pr
        JOIN ${this.usersTable} u ON u.id = pr.user_id
        WHERE pr.token_hash = $1
          AND pr.used_at IS NULL
          AND pr.expires_at > NOW()
          AND u.status = 'active'
        LIMIT 1
      `,
      [tokenHash]
    );

    if (result.rowCount === 0) {
      return null;
    }

    return {
      userId: result.rows[0].user_id,
      email: result.rows[0].email
    };
  }

  async completePasswordReset({ tokenHash, passwordHash, now, ipAddress = null, userAgent = "" }) {
    if (this.driver !== "postgres") {
      await this.write((state) => {
        for (const user of state.users) {
          const token = (user.passwordResetRequests || []).find(
            (candidate) => (candidate.rawToken || candidate.tokenHash) === tokenHash && !candidate.usedAt && Date.parse(candidate.expiresAt) > Date.now()
          );
          if (!token || user.status !== "active") {
            continue;
          }

          user.passwordHash = passwordHash;
          user.updatedAt = now;
          token.usedAt = now;
          state.auditEvents.unshift({
            id: `audit_${crypto.randomUUID()}`,
            userId: user.id,
            action: "auth.password_reset.completed",
            ipAddress,
            userAgent,
            metadata: {},
            createdAt: now
          });
          return;
        }
      });
      return;
    }

    await this.#withTransaction(async (client) => {
      const tokenResult = await client.query(
        `
          SELECT pr.id, pr.user_id
          FROM ${this.passwordResetTable} pr
          JOIN ${this.usersTable} u ON u.id = pr.user_id
          WHERE pr.token_hash = $1
            AND pr.used_at IS NULL
            AND pr.expires_at > NOW()
            AND u.status = 'active'
          LIMIT 1
          FOR UPDATE
        `,
        [tokenHash]
      );
      if (tokenResult.rowCount === 0) {
        return;
      }

      const token = tokenResult.rows[0];
      await client.query(`UPDATE ${this.usersTable} SET password_hash = $2, updated_at = $3 WHERE id = $1`, [
        token.user_id,
        passwordHash,
        now
      ]);
      await client.query(`UPDATE ${this.passwordResetTable} SET used_at = $2 WHERE id = $1`, [token.id, now]);
      await client.query(
        `
          INSERT INTO ${this.auditEventsTable} (id, user_id, action, ip_address, user_agent, metadata, created_at)
          VALUES ($1, $2, 'auth.password_reset.completed', $3, $4, '{}'::jsonb, $5)
        `,
        [`audit_${crypto.randomUUID()}`, token.user_id, ipAddress, String(userAgent || ""), now]
      );
    });
  }

  async findUserByApiKeyHash(keyHash) {
    if (this.driver !== "postgres") {
      return this.read((state) => {
        for (const user of state.users) {
          const key = (user.apiKeys || []).find((candidate) => candidate.keyHash === keyHash && !candidate.revokedAt);
          if (key) {
            return { user, key };
          }
        }
        return null;
      });
    }

    const result = await this.pool.query(
      `
        SELECT
          u.*,
          k.id AS api_key_id,
          k.name AS api_key_name,
          k.key_prefix,
          k.key_hash,
          k.scopes,
          k.created_at AS api_key_created_at,
          k.last_used_at,
          k.revoked_at
        FROM ${this.apiKeysTable} k
        JOIN ${this.usersTable} u ON u.id = k.user_id
        WHERE k.key_hash = $1
          AND k.revoked_at IS NULL
          AND u.status = 'active'
        LIMIT 1
      `,
      [keyHash]
    );

    if (result.rowCount === 0) {
      return null;
    }

    const row = result.rows[0];
    return {
      user: mapUserRow(row),
      key: {
        id: row.api_key_id,
        name: row.api_key_name,
        keyPrefix: row.key_prefix,
        keyHash: row.key_hash,
        scopes: normalizeScopes(row.scopes),
        createdAt: toIsoOrNull(row.api_key_created_at),
        lastUsedAt: toIsoOrNull(row.last_used_at),
        revokedAt: toIsoOrNull(row.revoked_at)
      }
    };
  }

  async touchApiKeyLastUsed(keyId, lastUsedAt) {
    if (this.driver !== "postgres") {
      await this.write((state) => {
        for (const user of state.users) {
          const key = (user.apiKeys || []).find((candidate) => candidate.id === keyId);
          if (key) {
            key.lastUsedAt = lastUsedAt;
            return;
          }
        }
      });
      return;
    }

    await this.pool.query(`UPDATE ${this.apiKeysTable} SET last_used_at = $2 WHERE id = $1`, [keyId, lastUsedAt]);
  }

  async createApiKey({ userId, name, scopes, createdAt }) {
    if (this.driver !== "postgres") {
      return this.write((state) => {
        const user = state.users.find((candidate) => candidate.id === userId);
        if (!user || user.status !== "active") {
          return null;
        }

        const key = {
          id: `key_${crypto.randomUUID()}`,
          name,
          keyPrefix: `svk_${crypto.randomUUID().slice(0, 8)}`,
          keyHash: null,
          scopes: [...scopes],
          createdAt,
          lastUsedAt: null,
          revokedAt: null
        };

        return key;
      });
    }

    throw new Error("createApiKey requires key material to be generated in AuthService before persistence.");
  }

  async storeApiKey({ userId, name, keyPrefix, keyHash, scopes, createdAt }) {
    if (this.driver !== "postgres") {
      return this.write((state) => {
        const user = state.users.find((candidate) => candidate.id === userId);
        if (!user || user.status !== "active") {
          return null;
        }

        const key = {
          id: `key_${crypto.randomUUID()}`,
          name,
          keyPrefix,
          keyHash,
          scopes: [...scopes],
          createdAt,
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
          createdAt
        });
        return key;
      });
    }

    return this.#withTransaction(async (client) => {
      const countResult = await client.query(
        `SELECT COUNT(*)::int AS count FROM ${this.apiKeysTable} WHERE user_id = $1 AND revoked_at IS NULL`,
        [userId]
      );
      const userResult = await client.query(`SELECT id FROM ${this.usersTable} WHERE id = $1 AND status = 'active' LIMIT 1`, [userId]);
      if (userResult.rowCount === 0) {
        return null;
      }

      const key = {
        id: `key_${crypto.randomUUID()}`,
        name,
        keyPrefix,
        keyHash,
        scopes: [...scopes],
        createdAt,
        lastUsedAt: null,
        revokedAt: null
      };

      key.activeCount = Number(countResult.rows[0]?.count) || 0;

      await client.query(
        `
          INSERT INTO ${this.apiKeysTable} (id, user_id, name, key_prefix, key_hash, scopes, created_at, last_used_at, revoked_at)
          VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, NULL, NULL)
        `,
        [key.id, userId, key.name, key.keyPrefix, key.keyHash, JSON.stringify(key.scopes), createdAt]
      );
      await client.query(
        `
          INSERT INTO ${this.auditEventsTable} (id, user_id, action, ip_address, user_agent, metadata, created_at)
          VALUES ($1, $2, 'auth.api_key.created', NULL, '', $3::jsonb, $4)
        `,
        [
          `audit_${crypto.randomUUID()}`,
          userId,
          JSON.stringify({ keyId: key.id, name: key.name, scopes: key.scopes }),
          createdAt
        ]
      );

      return key;
    });
  }

  async countActiveApiKeys(userId) {
    if (this.driver !== "postgres") {
      return this.read((state) => {
        const user = state.users.find((candidate) => candidate.id === userId);
        if (!user) {
          return 0;
        }
        return (user.apiKeys || []).filter((candidate) => !candidate.revokedAt).length;
      });
    }

    const result = await this.pool.query(
      `SELECT COUNT(*)::int AS count FROM ${this.apiKeysTable} WHERE user_id = $1 AND revoked_at IS NULL`,
      [userId]
    );
    return Number(result.rows[0]?.count) || 0;
  }

  async listApiKeys(userId) {
    if (this.driver !== "postgres") {
      return this.read((state) => {
        const user = state.users.find((candidate) => candidate.id === userId);
        return user ? (user.apiKeys || []) : null;
      });
    }

    const userResult = await this.pool.query(`SELECT 1 FROM ${this.usersTable} WHERE id = $1 LIMIT 1`, [userId]);
    if (userResult.rowCount === 0) {
      return null;
    }

    const result = await this.pool.query(
      `SELECT * FROM ${this.apiKeysTable} WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId]
    );
    return result.rows.map(mapApiKeyRow);
  }

  async revokeApiKey({ userId, keyId, revokedAt }) {
    if (this.driver !== "postgres") {
      return this.write((state) => {
        const user = state.users.find((candidate) => candidate.id === userId);
        if (!user) {
          return null;
        }

        const key = (user.apiKeys || []).find((candidate) => candidate.id === keyId && !candidate.revokedAt);
        if (!key) {
          return null;
        }

        key.revokedAt = revokedAt;
        state.auditEvents.unshift({
          id: `audit_${crypto.randomUUID()}`,
          userId,
          action: "auth.api_key.revoked",
          ipAddress: null,
          userAgent: "",
          metadata: {
            keyId
          },
          createdAt: revokedAt
        });

        return {
          id: key.id,
          name: key.name
        };
      });
    }

    return this.#withTransaction(async (client) => {
      const keyResult = await client.query(
        `
          SELECT id, name
          FROM ${this.apiKeysTable}
          WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
          LIMIT 1
          FOR UPDATE
        `,
        [keyId, userId]
      );
      if (keyResult.rowCount === 0) {
        return null;
      }

      const key = keyResult.rows[0];
      await client.query(`UPDATE ${this.apiKeysTable} SET revoked_at = $2 WHERE id = $1`, [keyId, revokedAt]);
      await client.query(
        `
          INSERT INTO ${this.auditEventsTable} (id, user_id, action, ip_address, user_agent, metadata, created_at)
          VALUES ($1, $2, 'auth.api_key.revoked', NULL, '', $3::jsonb, $4)
        `,
        [`audit_${crypto.randomUUID()}`, userId, JSON.stringify({ keyId }), revokedAt]
      );

      return {
        id: key.id,
        name: key.name
      };
    });
  }

  async getUsageSnapshot({ userId, limit }) {
    if (this.driver !== "postgres") {
      return this.read((state) => {
        const user = state.users.find((candidate) => candidate.id === userId);
        if (!user) {
          return null;
        }

        const windowStartedAtTimestamp = Date.now() - 24 * 60 * 60 * 1000;
        const used = (state.jobs || []).reduce((count, job) => {
          if (job?.userId !== userId) {
            return count;
          }
          const createdAtTimestamp = Date.parse(job?.createdAt || "");
          return Number.isFinite(createdAtTimestamp) && createdAtTimestamp >= windowStartedAtTimestamp ? count + 1 : count;
        }, 0);
        const windowStartedAt = new Date(windowStartedAtTimestamp).toISOString();

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
      });
    }

    const userResult = await this.pool.query(`SELECT id, role FROM ${this.usersTable} WHERE id = $1 LIMIT 1`, [userId]);
    if (userResult.rowCount === 0) {
      return null;
    }

    const user = userResult.rows[0];
    const countResult = await this.pool.query(
      `SELECT COUNT(*)::int AS count FROM ${this.jobsTable} WHERE user_id = $1 AND created_at >= NOW() - INTERVAL '24 hours'`,
      [userId]
    );
    const used = Number(countResult.rows[0]?.count) || 0;
    const windowStartedAt = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

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

  async getAdminMetrics() {
    if (this.driver !== "postgres") {
      return this.read((state) => {
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

    const [usersResult, reportsResult, jobsResult, auditResult] = await Promise.all([
      this.pool.query(`SELECT COUNT(*)::int AS count FROM ${this.usersTable}`),
      this.pool.query(`SELECT COUNT(*)::int AS count FROM ${this.reportsTable}`),
      this.pool.query(
        `
          SELECT
            COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE status = 'completed')::int AS completed,
            COUNT(*) FILTER (WHERE status = 'failed')::int AS failed,
            COUNT(*) FILTER (WHERE status = 'queued')::int AS queued,
            COUNT(*) FILTER (WHERE status = 'processing')::int AS processing
          FROM ${this.jobsTable}
        `
      ),
      this.pool.query(`SELECT COUNT(*)::int AS count FROM ${this.auditEventsTable}`)
    ]);

    return {
      users: Number(usersResult.rows[0]?.count) || 0,
      reports: Number(reportsResult.rows[0]?.count) || 0,
      jobs: {
        total: Number(jobsResult.rows[0]?.total) || 0,
        completed: Number(jobsResult.rows[0]?.completed) || 0,
        failed: Number(jobsResult.rows[0]?.failed) || 0,
        queued: Number(jobsResult.rows[0]?.queued) || 0,
        processing: Number(jobsResult.rows[0]?.processing) || 0
      },
      auditEvents: Number(auditResult.rows[0]?.count) || 0
    };
  }

  async listAuditEvents(limit = 100) {
    const safeLimit = Math.max(1, Math.min(500, Number(limit) || 100));

    if (this.driver !== "postgres") {
      return this.read((state) => state.auditEvents.slice(0, safeLimit));
    }

    const result = await this.pool.query(
      `SELECT * FROM ${this.auditEventsTable} ORDER BY created_at DESC LIMIT $1`,
      [safeLimit]
    );
    return result.rows.map(mapAuditEventRow);
  }

  async createNotification({
    userId,
    type,
    tone,
    title,
    detail,
    entityType = null,
    entityId = null,
    dedupeKey = "",
    createdAt = new Date().toISOString()
  }) {
    if (!userId || !type || !tone || !title || !detail) {
      return null;
    }

    if (this.driver !== "postgres") {
      return this.write((state) => {
        const user = state.users.find((candidate) => candidate.id === userId);
        if (!user) {
          return null;
        }

        if (dedupeKey) {
          const existing = (state.notifications || []).find(
            (notification) => notification.userId === userId && notification.dedupeKey === dedupeKey
          );
          if (existing) {
            return existing;
          }
        }

        const notification = {
          id: `notification_${crypto.randomUUID()}`,
          userId,
          type,
          tone,
          title,
          detail,
          entityType,
          entityId,
          dedupeKey: dedupeKey || null,
          createdAt,
          readAt: null
        };

        state.notifications.unshift(notification);
        return notification;
      });
    }

    const userResult = await this.pool.query(`SELECT 1 FROM ${this.usersTable} WHERE id = $1 LIMIT 1`, [userId]);
    if (userResult.rowCount === 0) {
      return null;
    }

    const notificationId = `notification_${crypto.randomUUID()}`;
    const result = await this.pool.query(
      `
        INSERT INTO ${this.notificationsTable} (
          id,
          user_id,
          type,
          tone,
          title,
          detail,
          entity_type,
          entity_id,
          dedupe_key,
          created_at,
          read_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL)
        ON CONFLICT DO NOTHING
        RETURNING *
      `,
      [notificationId, userId, type, tone, title, detail, entityType, entityId, dedupeKey || null, createdAt]
    );

    if (result.rowCount > 0) {
      return mapNotificationRow(result.rows[0]);
    }

    if (!dedupeKey) {
      return null;
    }

    const existing = await this.pool.query(
      `SELECT * FROM ${this.notificationsTable} WHERE user_id = $1 AND dedupe_key = $2 LIMIT 1`,
      [userId, dedupeKey]
    );
    return mapNotificationRow(existing.rows[0]);
  }

  async listNotificationsForUser(userId, limit = 20, offset = 0) {
    const safeLimit = Math.max(1, Math.min(100, Number(limit) || 20));
    const safeOffset = Math.max(0, Number(offset) || 0);

    if (this.driver !== "postgres") {
      return this.read((state) => {
        const ownedNotifications = [...(state.notifications || [])]
          .filter((notification) => notification.userId === userId)
          .sort((left, right) => new Date(right.createdAt || 0).getTime() - new Date(left.createdAt || 0).getTime());
        const pagedNotifications = ownedNotifications.slice(safeOffset, safeOffset + safeLimit);
        const unreadCount = ownedNotifications.filter((notification) => !notification.readAt).length;
        const totalCount = ownedNotifications.length;

        return {
          notifications: pagedNotifications.map((notification) => ({
            id: notification.id,
            type: notification.type,
            tone: notification.tone,
            title: notification.title,
            detail: notification.detail,
            entityType: notification.entityType || null,
            entityId: notification.entityId || null,
            createdAt: notification.createdAt,
            readAt: notification.readAt || null
          })),
          unreadCount,
          totalCount,
          limit: safeLimit,
          offset: safeOffset,
          hasMore: safeOffset + safeLimit < totalCount
        };
      });
    }

    const [listResult, countResult, unreadResult] = await Promise.all([
      this.pool.query(
        `
          SELECT *
          FROM ${this.notificationsTable}
          WHERE user_id = $1
          ORDER BY created_at DESC
          LIMIT $2 OFFSET $3
        `,
        [userId, safeLimit, safeOffset]
      ),
      this.pool.query(`SELECT COUNT(*)::int AS count FROM ${this.notificationsTable} WHERE user_id = $1`, [userId]),
      this.pool.query(
        `SELECT COUNT(*)::int AS count FROM ${this.notificationsTable} WHERE user_id = $1 AND read_at IS NULL`,
        [userId]
      )
    ]);

    const totalCount = Number(countResult.rows[0]?.count) || 0;
    return {
      notifications: listResult.rows.map((notification) => {
        const mapped = mapNotificationRow(notification);
        return {
          id: mapped.id,
          type: mapped.type,
          tone: mapped.tone,
          title: mapped.title,
          detail: mapped.detail,
          entityType: mapped.entityType,
          entityId: mapped.entityId,
          createdAt: mapped.createdAt,
          readAt: mapped.readAt
        };
      }),
      unreadCount: Number(unreadResult.rows[0]?.count) || 0,
      totalCount,
      limit: safeLimit,
      offset: safeOffset,
      hasMore: safeOffset + safeLimit < totalCount
    };
  }

  async markNotificationsRead(userId, ids = []) {
    const requestedIds = new Set(Array.isArray(ids) ? ids.map((value) => String(value || "").trim()).filter(Boolean) : []);
    const readAll = requestedIds.size === 0;
    const readAt = new Date().toISOString();

    if (this.driver !== "postgres") {
      return this.write((state) => {
        let updated = 0;
        for (const notification of state.notifications || []) {
          if (notification.userId !== userId || notification.readAt) {
            continue;
          }
          if (!readAll && !requestedIds.has(notification.id)) {
            continue;
          }
          notification.readAt = readAt;
          updated += 1;
        }
        return { updated };
      });
    }

    let result;
    if (readAll) {
      result = await this.pool.query(
        `UPDATE ${this.notificationsTable} SET read_at = $2 WHERE user_id = $1 AND read_at IS NULL`,
        [userId, readAt]
      );
    } else {
      result = await this.pool.query(
        `UPDATE ${this.notificationsTable} SET read_at = $3 WHERE user_id = $1 AND id = ANY($2::text[]) AND read_at IS NULL`,
        [userId, Array.from(requestedIds), readAt]
      );
    }

    return {
      updated: result.rowCount || 0
    };
  }

  async markActiveJobsFailed(reason) {
    const now = new Date().toISOString();

    if (this.driver !== "postgres") {
      await this.write((state) => {
        for (const job of state.jobs) {
          if (job.status === "queued" || job.status === "processing") {
            job.status = "failed";
            job.completedAt = now;
            job.updatedAt = now;
            job.errorMessage = reason;
          }
        }
      });
      return;
    }

    await this.pool.query(
      `
        UPDATE ${this.jobsTable}
        SET status = 'failed', completed_at = $2, updated_at = $2, error_message = $3
        WHERE status IN ('queued', 'processing')
      `,
      [now, now, reason]
    );
  }

  async requeueProcessingJobs() {
    const now = new Date().toISOString();

    if (this.driver !== "postgres") {
      await this.write((state) => {
        for (const job of state.jobs) {
          if (job.status === "processing") {
            job.status = "queued";
            job.updatedAt = now;
            job.startedAt = null;
            job.errorMessage = null;
          }
        }
      });
      return;
    }

    await this.pool.query(
      `
        UPDATE ${this.jobsTable}
        SET status = 'queued', updated_at = $1, started_at = NULL, error_message = NULL
        WHERE status = 'processing'
      `,
      [now]
    );
  }

  async createQueuedJob({ userId, sourceType, originalName, mimeType, fileSize, targetUrl = null, createdAt }) {
    if (this.driver !== "postgres") {
      return this.write((state) => {
        const user = state.users.find((candidate) => candidate.id === userId);
        if (!user) {
          return null;
        }

        const nextJob = {
          id: `job_${crypto.randomUUID()}`,
          userId,
          sourceType,
          targetUrl: sourceType === "url" || sourceType === "website" ? targetUrl : null,
          status: "queued",
          originalName,
          mimeType,
          fileSize,
          createdAt,
          updatedAt: createdAt,
          startedAt: null,
          completedAt: null,
          reportId: null,
          errorMessage: null
        };

        state.jobs.unshift(nextJob);
        state.auditEvents.unshift({
          id: `audit_${crypto.randomUUID()}`,
          userId,
          action: "scan.job.queued",
          ipAddress: null,
          userAgent: "",
          metadata: {
            jobId: nextJob.id,
            sourceType: nextJob.sourceType,
            fileSize: nextJob.fileSize,
            originalName: nextJob.originalName,
            targetUrl: nextJob.targetUrl
          },
          createdAt
        });

        return nextJob;
      });
    }

    return this.#withTransaction(async (client) => {
      const userResult = await client.query(`SELECT id FROM ${this.usersTable} WHERE id = $1 LIMIT 1`, [userId]);
      if (userResult.rowCount === 0) {
        return null;
      }

      const nextJob = {
        id: `job_${crypto.randomUUID()}`,
        userId,
        sourceType: normalizeSourceType(sourceType),
        targetUrl: sourceType === "url" || sourceType === "website" ? targetUrl : null,
        status: "queued",
        originalName,
        mimeType,
        fileSize: Number(fileSize) || 0,
        createdAt,
        updatedAt: createdAt,
        startedAt: null,
        completedAt: null,
        reportId: null,
        errorMessage: null
      };

      await client.query(
        `
          INSERT INTO ${this.jobsTable} (
            id,
            user_id,
            source_type,
            target_url,
            status,
            original_name,
            mime_type,
            file_size,
            created_at,
            updated_at,
            started_at,
            completed_at,
            report_id,
            error_message
          ) VALUES ($1, $2, $3, $4, 'queued', $5, $6, $7, $8, $8, NULL, NULL, NULL, NULL)
        `,
        [
          nextJob.id,
          userId,
          nextJob.sourceType,
          nextJob.targetUrl,
          originalName,
          mimeType,
          nextJob.fileSize,
          createdAt
        ]
      );
      await client.query(
        `
          INSERT INTO ${this.auditEventsTable} (id, user_id, action, ip_address, user_agent, metadata, created_at)
          VALUES ($1, $2, 'scan.job.queued', NULL, '', $3::jsonb, $4)
        `,
        [
          `audit_${crypto.randomUUID()}`,
          userId,
          JSON.stringify({
            jobId: nextJob.id,
            sourceType: nextJob.sourceType,
            fileSize: nextJob.fileSize,
            originalName: nextJob.originalName,
            targetUrl: nextJob.targetUrl
          }),
          createdAt
        ]
      );

      return nextJob;
    });
  }

  async markJobFailed({ jobId, reason, failedAt }) {
    if (this.driver !== "postgres") {
      await this.write((state) => {
        const job = state.jobs.find((candidate) => candidate.id === jobId);
        if (!job) {
          return;
        }

        job.status = "failed";
        job.completedAt = failedAt;
        job.updatedAt = failedAt;
        job.errorMessage = reason;
      });
      return;
    }

    await this.pool.query(
      `UPDATE ${this.jobsTable} SET status = 'failed', completed_at = $2, updated_at = $2, error_message = $3 WHERE id = $1`,
      [jobId, failedAt, reason]
    );
  }

  async markJobProcessing({ jobId, startedAt }) {
    if (this.driver !== "postgres") {
      await this.write((state) => {
        const job = state.jobs.find((candidate) => candidate.id === jobId);
        if (!job) {
          return;
        }
        job.status = "processing";
        job.startedAt = startedAt;
        job.updatedAt = startedAt;
      });
      return;
    }

    await this.pool.query(
      `UPDATE ${this.jobsTable} SET status = 'processing', started_at = $2, updated_at = $2 WHERE id = $1`,
      [jobId, startedAt]
    );
  }

  async getHistoricalHashIntel(sha256) {
    const normalizedHash = String(sha256 || "").trim();
    if (!normalizedHash) {
      return {
        sha256: null,
        hashSeenBefore: false,
        previousMatches: 0,
        totalOccurrences: 1,
        firstSeenAt: null,
        lastSeenAt: null,
        knownWorstVerdict: "clean"
      };
    }

    if (this.driver !== "postgres") {
      return this.read((state) => {
        const previousMatches = (state.reports || []).filter(
          (item) => !item?.deletedAt && item?.file?.hashes?.sha256 === normalizedHash
        );
        const observedTimes = previousMatches
          .map((item) => Date.parse(item.completedAt || item.createdAt || ""))
          .filter((value) => Number.isFinite(value))
          .sort((left, right) => left - right);
        const ranks = previousMatches.map((item) => (item?.verdict === "malicious" ? 3 : item?.verdict === "suspicious" ? 2 : 1));

        return {
          sha256: normalizedHash,
          hashSeenBefore: previousMatches.length > 0,
          previousMatches: previousMatches.length,
          totalOccurrences: previousMatches.length + 1,
          firstSeenAt: Number.isFinite(observedTimes[0]) ? new Date(observedTimes[0]).toISOString() : null,
          lastSeenAt:
            observedTimes.length > 0 ? new Date(observedTimes[observedTimes.length - 1]).toISOString() : null,
          knownWorstVerdict: worstVerdictFromRank(Math.max(0, ...ranks))
        };
      });
    }

    const result = await this.pool.query(
      `
        SELECT
          COUNT(*)::int AS count,
          MIN(completed_at) AS first_seen_at,
          MAX(completed_at) AS last_seen_at,
          MAX(
            CASE verdict
              WHEN 'malicious' THEN 3
              WHEN 'suspicious' THEN 2
              ELSE 1
            END
          )::int AS worst_rank
        FROM ${this.reportsTable}
        WHERE file_sha256 = $1
          AND deleted_at IS NULL
      `,
      [normalizedHash]
    );

    const row = result.rows[0] || {};
    const count = Number(row.count) || 0;
    return {
      sha256: normalizedHash,
      hashSeenBefore: count > 0,
      previousMatches: count,
      totalOccurrences: count + 1,
      firstSeenAt: toIsoOrNull(row.first_seen_at),
      lastSeenAt: toIsoOrNull(row.last_seen_at),
      knownWorstVerdict: worstVerdictFromRank(Number(row.worst_rank) || 0)
    };
  }

  async completeJob({ jobId, userId, sourceType, targetUrl = null, report, completedAt }) {
    if (this.driver !== "postgres") {
      return this.write((state) => {
        const job = state.jobs.find((candidate) => candidate.id === jobId);
        if (!job) {
          return null;
        }

        state.reports.unshift(report);
        job.status = "completed";
        job.reportId = report.id;
        job.completedAt = completedAt;
        job.updatedAt = completedAt;
        job.errorMessage = null;
        job.sourceType = normalizeSourceType(sourceType);
        job.targetUrl = sourceType === "url" || sourceType === "website" ? targetUrl : null;

        state.auditEvents.unshift({
          id: `audit_${crypto.randomUUID()}`,
          userId,
          action: "scan.job.completed",
          ipAddress: null,
          userAgent: "",
          metadata: {
            jobId,
            reportId: report.id,
            sourceType,
            targetUrl: sourceType === "url" || sourceType === "website" ? targetUrl : null,
            verdict: report.verdict,
            riskScore: report.riskScore
          },
          createdAt: completedAt
        });

        return report;
      });
    }

    return this.#withTransaction(async (client) => {
      const jobResult = await client.query(`SELECT id FROM ${this.jobsTable} WHERE id = $1 LIMIT 1 FOR UPDATE`, [jobId]);
      if (jobResult.rowCount === 0) {
        return null;
      }

      const columns = extractReportColumns(report);
      await client.query(
        `
          INSERT INTO ${this.reportsTable} (
            id,
            owner_user_id,
            source_type,
            queued_job_id,
            created_at,
            completed_at,
            verdict,
            risk_score,
            file_name,
            file_size,
            file_sha256,
            detected_file_type,
            file_extension,
            payload,
            deleted_at,
            deleted_by_user_id
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb, $15, $16)
        `,
        [
          columns.id,
          columns.ownerUserId,
          columns.sourceType,
          columns.queuedJobId,
          columns.createdAt,
          columns.completedAt,
          columns.verdict,
          columns.riskScore,
          columns.fileName,
          columns.fileSize,
          columns.fileSha256,
          columns.detectedFileType,
          columns.fileExtension,
          JSON.stringify(columns.payload),
          columns.deletedAt,
          columns.deletedByUserId
        ]
      );

      await client.query(
        `
          UPDATE ${this.jobsTable}
          SET
            status = 'completed',
            report_id = $2,
            completed_at = $3,
            updated_at = $3,
            error_message = NULL,
            source_type = $4,
            target_url = $5
          WHERE id = $1
        `,
        [jobId, report.id, completedAt, normalizeSourceType(sourceType), sourceType === "url" || sourceType === "website" ? targetUrl : null]
      );

      await client.query(
        `
          INSERT INTO ${this.auditEventsTable} (id, user_id, action, ip_address, user_agent, metadata, created_at)
          VALUES ($1, $2, 'scan.job.completed', NULL, '', $3::jsonb, $4)
        `,
        [
          `audit_${crypto.randomUUID()}`,
          userId,
          JSON.stringify({
            jobId,
            reportId: report.id,
            sourceType: normalizeSourceType(sourceType),
            targetUrl: sourceType === "url" || sourceType === "website" ? targetUrl : null,
            verdict: report.verdict,
            riskScore: report.riskScore
          }),
          completedAt
        ]
      );

      return report;
    });
  }

  async attachReportArtifacts({ reportId, artifacts }) {
    if (this.driver !== "postgres") {
      await this.write((state) => {
        const report = state.reports.find((candidate) => candidate.id === reportId);
        if (report) {
          report.artifacts = artifacts;
        }
      });
      return;
    }

    await this.#withTransaction(async (client) => {
      const result = await client.query(`SELECT payload FROM ${this.reportsTable} WHERE id = $1 LIMIT 1 FOR UPDATE`, [reportId]);
      if (result.rowCount === 0) {
        return;
      }

      const payload = result.rows[0].payload || {};
      payload.artifacts = artifacts;
      await client.query(`UPDATE ${this.reportsTable} SET payload = $2::jsonb WHERE id = $1`, [reportId, JSON.stringify(payload)]);
    });
  }

  async replaceReport(report) {
    if (!report?.id) {
      return null;
    }

    if (this.driver !== "postgres") {
      return this.write((state) => {
        const index = state.reports.findIndex((candidate) => candidate.id === report.id);
        if (index === -1) {
          return null;
        }

        state.reports[index] = report;
        return report;
      });
    }

    const columns = extractReportColumns(report);
    const result = await this.pool.query(
      `
        UPDATE ${this.reportsTable}
        SET
          owner_user_id = $2,
          source_type = $3,
          queued_job_id = $4,
          created_at = $5,
          completed_at = $6,
          verdict = $7,
          risk_score = $8,
          file_name = $9,
          file_size = $10,
          file_sha256 = $11,
          detected_file_type = $12,
          file_extension = $13,
          payload = $14::jsonb,
          deleted_at = $15,
          deleted_by_user_id = $16
        WHERE id = $1
      `,
      [
        columns.id,
        columns.ownerUserId,
        columns.sourceType,
        columns.queuedJobId,
        columns.createdAt,
        columns.completedAt,
        columns.verdict,
        columns.riskScore,
        columns.fileName,
        columns.fileSize,
        columns.fileSha256,
        columns.detectedFileType,
        columns.fileExtension,
        JSON.stringify(columns.payload),
        columns.deletedAt,
        columns.deletedByUserId
      ]
    );

    if (result.rowCount === 0) {
      return null;
    }

    return report;
  }

  async failJob({ jobId, userId, sourceType, targetUrl = null, errorMessage, failedAt }) {
    if (this.driver !== "postgres") {
      await this.write((state) => {
        const job = state.jobs.find((candidate) => candidate.id === jobId);
        if (!job) {
          return;
        }

        job.status = "failed";
        job.completedAt = failedAt;
        job.updatedAt = failedAt;
        job.errorMessage = errorMessage;
        state.auditEvents.unshift({
          id: `audit_${crypto.randomUUID()}`,
          userId,
          action: "scan.job.failed",
          ipAddress: null,
          userAgent: "",
          metadata: {
            jobId,
            sourceType,
            targetUrl: sourceType === "url" || sourceType === "website" ? targetUrl : null,
            errorMessage
          },
          createdAt: failedAt
        });
      });
      return;
    }

    await this.#withTransaction(async (client) => {
      await client.query(
        `
          UPDATE ${this.jobsTable}
          SET status = 'failed', completed_at = $2, updated_at = $2, error_message = $3
          WHERE id = $1
        `,
        [jobId, failedAt, errorMessage]
      );
      await client.query(
        `
          INSERT INTO ${this.auditEventsTable} (id, user_id, action, ip_address, user_agent, metadata, created_at)
          VALUES ($1, $2, 'scan.job.failed', NULL, '', $3::jsonb, $4)
        `,
        [
          `audit_${crypto.randomUUID()}`,
          userId,
          JSON.stringify({
            jobId,
            sourceType: normalizeSourceType(sourceType),
            targetUrl: sourceType === "url" || sourceType === "website" ? targetUrl : null,
            errorMessage
          }),
          failedAt
        ]
      );
    });
  }

  async findJobById(jobId) {
    if (this.driver !== "postgres") {
      return this.read((state) => state.jobs.find((candidate) => candidate.id === jobId) || null);
    }

    const result = await this.pool.query(`SELECT * FROM ${this.jobsTable} WHERE id = $1 LIMIT 1`, [jobId]);
    return mapJobRow(result.rows[0]);
  }

  async listJobsForUser(user, limit = 20, sourceType = undefined) {
    const safeLimit = Math.max(1, Math.min(100, Number(limit) || 20));
    const normalizedSourceType = sourceType ? normalizeSourceType(sourceType) : null;

    if (this.driver !== "postgres") {
      return this.read((state) =>
        state.jobs
          .filter((job) => {
            if (user.role !== "admin" && job.userId !== user.id) {
              return false;
            }
            if (!normalizedSourceType) {
              return true;
            }
            return normalizeSourceType(job.sourceType) === normalizedSourceType;
          })
          .slice(0, safeLimit)
      );
    }

    const values = [];
    const clauses = [];
    let index = 1;

    if (user.role !== "admin") {
      clauses.push(`user_id = $${index}`);
      values.push(user.id);
      index += 1;
    }

    if (normalizedSourceType) {
      clauses.push(`source_type = $${index}`);
      values.push(normalizedSourceType);
      index += 1;
    }

    const whereClause = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
    values.push(safeLimit);

    const result = await this.pool.query(
      `SELECT * FROM ${this.jobsTable} ${whereClause} ORDER BY created_at DESC LIMIT $${index}`,
      values
    );
    return result.rows.map(mapJobRow);
  }

  async findReportById(reportId, { includeDeleted = false } = {}) {
    if (this.driver !== "postgres") {
      return this.read((state) => {
        const report = state.reports.find((candidate) => candidate.id === reportId) || null;
        if (!report) {
          return null;
        }
        if (!includeDeleted && report.deletedAt) {
          return null;
        }
        return report;
      });
    }

    const result = await this.pool.query(`SELECT * FROM ${this.reportsTable} WHERE id = $1 LIMIT 1`, [reportId]);
    if (result.rowCount === 0) {
      return null;
    }

    const row = result.rows[0];
    if (!includeDeleted && row.deleted_at) {
      return null;
    }
    return mapReportPayloadRow(row);
  }

  async listReportsForUser(user, limit = 20, sourceType = undefined) {
    const safeLimit = Math.max(1, Math.min(100, Number(limit) || 20));
    const normalizedSourceType = sourceType ? normalizeSourceType(sourceType) : null;

    if (this.driver !== "postgres") {
      return this.read((state) =>
        state.reports
          .filter((report) => {
            if (report.deletedAt) {
              return false;
            }
            if (user.role !== "admin" && report.ownerUserId !== user.id) {
              return false;
            }
            if (!normalizedSourceType) {
              return true;
            }
            return normalizeSourceType(report.sourceType) === normalizedSourceType;
          })
          .slice(0, safeLimit)
      );
    }

    const clauses = [`deleted_at IS NULL`];
    const values = [];
    let index = 1;

    if (user.role !== "admin") {
      clauses.push(`owner_user_id = $${index}`);
      values.push(user.id);
      index += 1;
    }

    if (normalizedSourceType) {
      clauses.push(`source_type = $${index}`);
      values.push(normalizedSourceType);
      index += 1;
    }

    values.push(safeLimit);
    const result = await this.pool.query(
      `SELECT payload FROM ${this.reportsTable} WHERE ${clauses.join(" AND ")} ORDER BY completed_at DESC NULLS LAST, created_at DESC LIMIT $${index}`,
      values
    );
    return result.rows.map((row) => row.payload);
  }

  async softDeleteReport({ reportId, actingUserId, deletedAt }) {
    if (this.driver !== "postgres") {
      return this.write((state) => {
        const report = state.reports.find((candidate) => candidate.id === reportId);
        if (!report) {
          return null;
        }

        if (report.deletedAt) {
          const expiresAt = Date.parse(report.completedAt || report.createdAt || "");
          return {
            id: report.id,
            deletedAt: report.deletedAt,
            retentionExpiresAt:
              Number.isFinite(expiresAt) && this.reportTtlMs > 0 ? new Date(expiresAt + this.reportTtlMs).toISOString() : null,
            alreadyDeleted: true
          };
        }

        report.deletedAt = deletedAt;
        report.deletedByUserId = actingUserId;
        state.auditEvents.unshift({
          id: `audit_${crypto.randomUUID()}`,
          userId: actingUserId,
          action: "scan.report.deleted",
          ipAddress: null,
          userAgent: "",
          metadata: {
            reportId: report.id,
            ownerUserId: report.ownerUserId,
            sourceType: report.sourceType || "file"
          },
          createdAt: deletedAt
        });

        const expiresAt = Date.parse(report.completedAt || report.createdAt || "");
        return {
          id: report.id,
          deletedAt,
          retentionExpiresAt:
            Number.isFinite(expiresAt) && this.reportTtlMs > 0 ? new Date(expiresAt + this.reportTtlMs).toISOString() : null,
          alreadyDeleted: false
        };
      });
    }

    return this.#withTransaction(async (client) => {
      const reportResult = await client.query(
        `SELECT payload, owner_user_id, completed_at, created_at, deleted_at FROM ${this.reportsTable} WHERE id = $1 LIMIT 1 FOR UPDATE`,
        [reportId]
      );
      if (reportResult.rowCount === 0) {
        return null;
      }

      const row = reportResult.rows[0];
      const payload = row.payload || {};
      const completedAt = toIsoOrNull(row.completed_at || row.created_at);
      if (row.deleted_at) {
        const expiresAt = Date.parse(completedAt || "");
        return {
          id: reportId,
          deletedAt: toIsoOrNull(row.deleted_at),
          retentionExpiresAt:
            Number.isFinite(expiresAt) && this.reportTtlMs > 0 ? new Date(expiresAt + this.reportTtlMs).toISOString() : null,
          alreadyDeleted: true
        };
      }

      payload.deletedAt = deletedAt;
      payload.deletedByUserId = actingUserId;
      await client.query(
        `
          UPDATE ${this.reportsTable}
          SET deleted_at = $2, deleted_by_user_id = $3, payload = $4::jsonb
          WHERE id = $1
        `,
        [reportId, deletedAt, actingUserId, JSON.stringify(payload)]
      );
      await client.query(
        `
          INSERT INTO ${this.auditEventsTable} (id, user_id, action, ip_address, user_agent, metadata, created_at)
          VALUES ($1, $2, 'scan.report.deleted', NULL, '', $3::jsonb, $4)
        `,
        [
          `audit_${crypto.randomUUID()}`,
          actingUserId,
          JSON.stringify({
            reportId,
            ownerUserId: row.owner_user_id,
            sourceType: normalizeSourceType(payload.sourceType)
          }),
          deletedAt
        ]
      );

      const expiresAt = Date.parse(completedAt || "");
      return {
        id: reportId,
        deletedAt,
        retentionExpiresAt:
          Number.isFinite(expiresAt) && this.reportTtlMs > 0 ? new Date(expiresAt + this.reportTtlMs).toISOString() : null,
        alreadyDeleted: false
      };
    });
  }

  async getAnalyticsSnapshotForUser(user) {
    if (this.driver !== "postgres") {
      return null;
    }

    const jobClauses = [];
    const reportClauses = [`deleted_at IS NULL`];
    const jobValues = [];
    const reportValues = [];
    let jobIndex = 1;
    let reportIndex = 1;

    if (user.role !== "admin") {
      jobClauses.push(`user_id = $${jobIndex}`);
      jobValues.push(user.id);
      reportClauses.push(`owner_user_id = $${reportIndex}`);
      reportValues.push(user.id);
      jobIndex += 1;
      reportIndex += 1;
    }

    const jobWhere = jobClauses.length > 0 ? `WHERE ${jobClauses.join(" AND ")}` : "";
    const reportWhere = reportClauses.length > 0 ? `WHERE ${reportClauses.join(" AND ")}` : "WHERE deleted_at IS NULL";

    const [jobSummaryResult, reportSummaryResult, riskResult, fileTypeResult, latestReportResult, highestRiskResult, reportMonthsResult, jobMonthsResult, currentReportsResult, previousReportsResult, currentJobsResult, previousJobsResult] = await Promise.all([
      this.pool.query(
        `
          SELECT
            COUNT(*)::int AS total_jobs,
            COUNT(*) FILTER (WHERE status = 'queued')::int AS queued_jobs,
            COUNT(*) FILTER (WHERE status = 'processing')::int AS processing_jobs,
            COUNT(*) FILTER (WHERE status = 'completed')::int AS completed_jobs,
            COUNT(*) FILTER (WHERE status = 'failed')::int AS failed_jobs
          FROM ${this.jobsTable}
          ${jobWhere}
        `,
        jobValues
      ),
      this.pool.query(
        `
          SELECT
            COUNT(*)::int AS total_reports,
            COUNT(*) FILTER (WHERE verdict = 'clean')::int AS clean_reports,
            COUNT(*) FILTER (WHERE verdict = 'suspicious')::int AS suspicious_reports,
            COUNT(*) FILTER (WHERE verdict = 'malicious')::int AS malicious_reports,
            AVG(risk_score)::float AS average_risk_score,
            MAX(risk_score)::int AS highest_risk_score
          FROM ${this.reportsTable}
          ${reportWhere}
        `,
        reportValues
      ),
      this.pool.query(
        `
          SELECT
            COUNT(*) FILTER (WHERE risk_score <= 24)::int AS low_count,
            COUNT(*) FILTER (WHERE risk_score BETWEEN 25 AND 49)::int AS medium_low_count,
            COUNT(*) FILTER (WHERE risk_score BETWEEN 50 AND 74)::int AS medium_high_count,
            COUNT(*) FILTER (WHERE risk_score >= 75)::int AS high_count
          FROM ${this.reportsTable}
          ${reportWhere}
        `,
        reportValues
      ),
      this.pool.query(
        `
          SELECT
            UPPER(COALESCE(NULLIF(detected_file_type, ''), NULLIF(file_extension, ''), 'Unknown')) AS label,
            COUNT(*)::int AS value
          FROM ${this.reportsTable}
          ${reportWhere}
          GROUP BY 1
          ORDER BY value DESC, label ASC
          LIMIT 5
        `,
        reportValues
      ),
      this.pool.query(
        `
          SELECT id, file_name, verdict, risk_score, completed_at, created_at
          FROM ${this.reportsTable}
          ${reportWhere}
          ORDER BY completed_at DESC NULLS LAST, created_at DESC
          LIMIT 1
        `,
        reportValues
      ),
      this.pool.query(
        `
          SELECT id, file_name, verdict, risk_score, completed_at, created_at
          FROM ${this.reportsTable}
          ${reportWhere}
          ORDER BY risk_score DESC, completed_at DESC NULLS LAST, created_at DESC
          LIMIT 1
        `,
        reportValues
      ),
      this.pool.query(
        `
          SELECT
            EXTRACT(YEAR FROM completed_at)::int AS year,
            EXTRACT(MONTH FROM completed_at)::int AS month,
            COUNT(*)::int AS reports,
            COUNT(*) FILTER (WHERE verdict IN ('suspicious', 'malicious'))::int AS flagged
          FROM ${this.reportsTable}
          ${reportWhere}
          AND completed_at >= date_trunc('month', NOW()) - INTERVAL '${ANALYTICS_MONTH_BUCKETS - 1} months'
          GROUP BY 1, 2
        `,
        reportValues
      ),
      this.pool.query(
        `
          SELECT
            EXTRACT(YEAR FROM created_at)::int AS year,
            EXTRACT(MONTH FROM created_at)::int AS month,
            COUNT(*)::int AS jobs
          FROM ${this.jobsTable}
          ${jobWhere ? `${jobWhere} AND` : 'WHERE'} created_at >= date_trunc('month', NOW()) - INTERVAL '${ANALYTICS_MONTH_BUCKETS - 1} months'
          GROUP BY 1, 2
        `,
        jobValues
      ),
      this.pool.query(
        `
          SELECT
            COUNT(*)::int AS reports,
            COUNT(*) FILTER (WHERE verdict IN ('suspicious', 'malicious'))::int AS flagged_reports,
            AVG(risk_score)::float AS average_risk_score
          FROM ${this.reportsTable}
          ${reportWhere}
          AND completed_at >= NOW() - INTERVAL '${ANALYTICS_WINDOW_DAYS} days'
        `,
        reportValues
      ),
      this.pool.query(
        `
          SELECT
            COUNT(*)::int AS reports,
            COUNT(*) FILTER (WHERE verdict IN ('suspicious', 'malicious'))::int AS flagged_reports,
            AVG(risk_score)::float AS average_risk_score
          FROM ${this.reportsTable}
          ${reportWhere}
          AND completed_at >= NOW() - INTERVAL '${ANALYTICS_WINDOW_DAYS * 2} days'
          AND completed_at < NOW() - INTERVAL '${ANALYTICS_WINDOW_DAYS} days'
        `,
        reportValues
      ),
      this.pool.query(
        `
          SELECT COUNT(*) FILTER (WHERE status = 'failed')::int AS failed_jobs
          FROM ${this.jobsTable}
          ${jobWhere ? `${jobWhere} AND` : 'WHERE'} created_at >= NOW() - INTERVAL '${ANALYTICS_WINDOW_DAYS} days'
        `,
        jobValues
      ),
      this.pool.query(
        `
          SELECT COUNT(*) FILTER (WHERE status = 'failed')::int AS failed_jobs
          FROM ${this.jobsTable}
          ${jobWhere ? `${jobWhere} AND` : 'WHERE'} created_at >= NOW() - INTERVAL '${ANALYTICS_WINDOW_DAYS * 2} days'
            AND created_at < NOW() - INTERVAL '${ANALYTICS_WINDOW_DAYS} days'
        `,
        jobValues
      )
    ]);

    const jobSummary = jobSummaryResult.rows[0] || {};
    const reportSummary = reportSummaryResult.rows[0] || {};
    const risk = riskResult.rows[0] || {};
    const currentReports = currentReportsResult.rows[0] || {};
    const previousReports = previousReportsResult.rows[0] || {};
    const currentJobs = currentJobsResult.rows[0] || {};
    const previousJobs = previousJobsResult.rows[0] || {};

    const buckets = createMonthBuckets();
    const bucketMap = new Map(buckets.map((bucket) => [bucket.key, bucket]));

    for (const row of reportMonthsResult.rows) {
      const key = `${row.year}-${Number(row.month) - 1}`;
      const bucket = bucketMap.get(key);
      if (bucket) {
        bucket.reports = Number(row.reports) || 0;
        bucket.flagged = Number(row.flagged) || 0;
      }
    }

    for (const row of jobMonthsResult.rows) {
      const key = `${row.year}-${Number(row.month) - 1}`;
      const bucket = bucketMap.get(key);
      if (bucket) {
        bucket.jobs = Number(row.jobs) || 0;
      }
    }

    const latestReport = latestReportResult.rows[0]
      ? {
          id: latestReportResult.rows[0].id,
          fileName: latestReportResult.rows[0].file_name || "Unknown file",
          verdict: latestReportResult.rows[0].verdict || "clean",
          riskScore: Number(latestReportResult.rows[0].risk_score) || 0,
          completedAt: toIsoOrNull(latestReportResult.rows[0].completed_at || latestReportResult.rows[0].created_at)
        }
      : null;

    const highestRiskReport = highestRiskResult.rows[0]
      ? {
          id: highestRiskResult.rows[0].id,
          fileName: highestRiskResult.rows[0].file_name || "Unknown file",
          verdict: highestRiskResult.rows[0].verdict || "clean",
          riskScore: Number(highestRiskResult.rows[0].risk_score) || 0,
          completedAt: toIsoOrNull(highestRiskResult.rows[0].completed_at || highestRiskResult.rows[0].created_at)
        }
      : null;

    const totalReports = Number(reportSummary.total_reports) || 0;
    const cleanReports = Number(reportSummary.clean_reports) || 0;
    const suspiciousReports = Number(reportSummary.suspicious_reports) || 0;
    const maliciousReports = Number(reportSummary.malicious_reports) || 0;
    const flaggedReports = suspiciousReports + maliciousReports;

    return {
      generatedAt: new Date().toISOString(),
      comparisonWindowDays: ANALYTICS_WINDOW_DAYS,
      summary: {
        totalJobs: Number(jobSummary.total_jobs) || 0,
        activeJobs: (Number(jobSummary.queued_jobs) || 0) + (Number(jobSummary.processing_jobs) || 0),
        queuedJobs: Number(jobSummary.queued_jobs) || 0,
        processingJobs: Number(jobSummary.processing_jobs) || 0,
        completedJobs: Number(jobSummary.completed_jobs) || 0,
        failedJobs: Number(jobSummary.failed_jobs) || 0,
        totalReports,
        cleanReports,
        suspiciousReports,
        maliciousReports,
        flaggedReports,
        cleanRate: totalReports > 0 ? (cleanReports / totalReports) * 100 : 0,
        averageRiskScore: Number(reportSummary.average_risk_score) || 0,
        highestRiskScore: Number(reportSummary.highest_risk_score) || 0
      },
      windows: {
        days: ANALYTICS_WINDOW_DAYS,
        current: {
          reports: Number(currentReports.reports) || 0,
          flaggedReports: Number(currentReports.flagged_reports) || 0,
          cleanRate:
            Number(currentReports.reports) > 0
              ? ((Number(currentReports.reports) || 0) - (Number(currentReports.flagged_reports) || 0)) /
                  (Number(currentReports.reports) || 1) *
                100
              : 0,
          averageRiskScore: Number(currentReports.average_risk_score) || 0,
          failedJobs: Number(currentJobs.failed_jobs) || 0
        },
        previous: {
          reports: Number(previousReports.reports) || 0,
          flaggedReports: Number(previousReports.flagged_reports) || 0,
          cleanRate:
            Number(previousReports.reports) > 0
              ? ((Number(previousReports.reports) || 0) - (Number(previousReports.flagged_reports) || 0)) /
                  (Number(previousReports.reports) || 1) *
                100
              : 0,
          averageRiskScore: Number(previousReports.average_risk_score) || 0,
          failedJobs: Number(previousJobs.failed_jobs) || 0
        }
      },
      timeSeries: buckets,
      postureBreakdown: [
        { label: 'Clean', value: cleanReports },
        { label: 'Suspicious', value: suspiciousReports },
        { label: 'Malicious', value: maliciousReports }
      ],
      queueBreakdown: [
        { label: 'Queued', value: Number(jobSummary.queued_jobs) || 0 },
        { label: 'Processing', value: Number(jobSummary.processing_jobs) || 0 },
        { label: 'Completed', value: Number(jobSummary.completed_jobs) || 0 },
        { label: 'Failed', value: Number(jobSummary.failed_jobs) || 0 }
      ],
      riskDistribution: [
        { label: '0-24', value: Number(risk.low_count) || 0 },
        { label: '25-49', value: Number(risk.medium_low_count) || 0 },
        { label: '50-74', value: Number(risk.medium_high_count) || 0 },
        { label: '75-100', value: Number(risk.high_count) || 0 }
      ],
      fileTypeBreakdown: fileTypeResult.rows.map((row) => ({ label: row.label, value: Number(row.value) || 0 })),
      latestReport,
      highestRiskReport
    };
  }

  async #materializePostgresState() {
    const [usersResult, apiKeysResult, refreshTokensResult, resetTokensResult, jobsResult, reportsResult, notificationsResult, auditResult] =
      await Promise.all([
        this.pool.query(`SELECT * FROM ${this.usersTable} ORDER BY created_at DESC`),
        this.pool.query(`SELECT * FROM ${this.apiKeysTable} ORDER BY created_at DESC`),
        this.pool.query(`SELECT * FROM ${this.refreshTokensTable} ORDER BY created_at DESC`),
        this.pool.query(`SELECT * FROM ${this.passwordResetTable} ORDER BY created_at DESC`),
        this.pool.query(`SELECT * FROM ${this.jobsTable} ORDER BY created_at DESC`),
        this.pool.query(`SELECT * FROM ${this.reportsTable} ORDER BY completed_at DESC NULLS LAST, created_at DESC`),
        this.pool.query(`SELECT * FROM ${this.notificationsTable} ORDER BY created_at DESC`),
        this.pool.query(`SELECT * FROM ${this.auditEventsTable} ORDER BY created_at DESC LIMIT 20000`)
      ]);

    const users = usersResult.rows.map(mapUserRow);
    const usersById = new Map(users.map((user) => [user.id, user]));

    for (const row of apiKeysResult.rows) {
      const user = usersById.get(row.user_id);
      if (user) {
        user.apiKeys.push(mapApiKeyRow(row));
      }
    }

    for (const row of refreshTokensResult.rows) {
      const user = usersById.get(row.user_id);
      if (user) {
        user.refreshTokens.push(mapRefreshTokenRow(row));
      }
    }

    for (const row of resetTokensResult.rows) {
      const user = usersById.get(row.user_id);
      if (user) {
        user.passwordResetRequests.push(mapPasswordResetRow(row));
      }
    }

    return {
      version: 2,
      users,
      jobs: jobsResult.rows.map(mapJobRow),
      reports: reportsResult.rows.map(mapReportPayloadRow),
      notifications: notificationsResult.rows.map(mapNotificationRow),
      auditEvents: auditResult.rows.map(mapAuditEventRow)
    };
  }

  async #initPostgres() {
    if (!this.databaseUrl) {
      throw new Error("DATABASE_URL is required when store driver is postgres.");
    }

    this.pool = new Pool({
      connectionString: this.databaseUrl,
      ssl: this.databaseSsl
        ? {
            rejectUnauthorized: this.databaseSslRejectUnauthorized,
            ca: fs.readFileSync("./certs/prod-ca-2021.crt", "utf8")
          }
        : false
    });

    await this.#createPostgresSchema();
  }

  async #createPostgresSchema() {
    return applyStoreMigrations({
      pool: this.pool,
      migrationsTable: this.migrationsTable,
      migrations: buildStoreMigrations({
        usersTable: this.usersTable,
        jobsTable: this.jobsTable,
        reportsTable: this.reportsTable,
        apiKeysTable: this.apiKeysTable,
        refreshTokensTable: this.refreshTokensTable,
        passwordResetTable: this.passwordResetTable,
        notificationsTable: this.notificationsTable,
        auditEventsTable: this.auditEventsTable
      })
    });
  }

  async #withTransaction(work) {
    return this.#withRetry(async () => {
      const client = await this.pool.connect();
      try {
        await client.query("BEGIN");
        const result = await work(client);
        await client.query("COMMIT");
        return result;
      } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        throw error;
      } finally {
        client.release();
      }
    });
  }

  async #withRetry(operation, { maxAttempts = POSTGRES_WRITE_MAX_ATTEMPTS } = {}) {
    let attempt = 0;
    let lastError = null;

    while (attempt < maxAttempts) {
      attempt += 1;
      try {
        return await operation();
      } catch (error) {
        lastError = error;
        const code = String(error?.code || "").toUpperCase();
        if (!["55P03", "40P01", "40001", "57014"].includes(code) || attempt >= maxAttempts) {
          throw error;
        }
        const delayMs = Math.min(POSTGRES_RETRY_MAX_DELAY_MS, POSTGRES_RETRY_BASE_DELAY_MS * attempt);
        await wait(delayMs);
      }
    }

    throw lastError;
  }

  #pruneState(state) {
    const now = Date.now();

    state.reports = state.reports
      .filter((report) => {
        const createdAt = Date.parse(report.createdAt || report.completedAt || "");
        if (!Number.isFinite(createdAt)) {
          return false;
        }
        return now - createdAt <= this.reportTtlMs;
      })
      .slice(0, this.maxReports);

    const validReportIds = new Set(state.reports.map((report) => report.id));

    state.jobs = state.jobs
      .map((job) => {
        if (job.reportId && !validReportIds.has(job.reportId)) {
          return {
            ...job,
            reportId: null
          };
        }
        return job;
      })
      .slice(0, this.maxReports * 2);

    state.notifications = state.notifications
      .filter((notification) => Boolean(notification?.id && notification?.userId && notification?.createdAt))
      .slice(0, Math.max(500, this.maxReports * 20));

    state.auditEvents = state.auditEvents.slice(0, 20_000);

    state.users = state.users.map((user) => ({
      ...user,
      refreshTokens: Array.isArray(user.refreshTokens)
        ? user.refreshTokens.filter((token) => !token.revokedAt && Date.parse(token.expiresAt) > now)
        : [],
      apiKeys: Array.isArray(user.apiKeys) ? user.apiKeys : [],
      passwordResetRequests: Array.isArray(user.passwordResetRequests) ? user.passwordResetRequests : []
    }));
  }

  async #persistFile(state) {
    const tmpPath = `${this.filePath}.tmp`;
    const payload = JSON.stringify(state, null, 2);
    await fsp.writeFile(tmpPath, payload, "utf8");
    await fsp.rename(tmpPath, this.filePath);
  }
}

export { DEFAULT_STATE };
