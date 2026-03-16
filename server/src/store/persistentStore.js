import fs from "fs";
import fsp from "fs/promises";
import path from "path";
import { Pool } from "pg";

const DEFAULT_STATE = {
  version: 1,
  users: [],
  reports: [],
  jobs: [],
  notifications: [],
  auditEvents: []
};

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
    this.stateRowId = "main";
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
      this.state = this.#normalizeState(parsed);
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

  async read(selector) {
    if (this.driver === "postgres") {
      const current = await this.#readPostgresState();
      return selector(current);
    }

    const current = this.state;
    return selector(current);
  }

  async write(mutator) {
    if (this.driver === "postgres") {
      return this.#writePostgres(mutator);
    }

    const operation = async () => {
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

    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS ${this.stateTable} (
        id TEXT PRIMARY KEY,
        state JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await this.pool.query(
      `INSERT INTO ${this.stateTable} (id, state) VALUES ($1, $2::jsonb) ON CONFLICT (id) DO NOTHING`,
      [this.stateRowId, JSON.stringify(cloneState(DEFAULT_STATE))]
    );

    await this.#writePostgres((state) => state);
  }

  async #readPostgresState() {
    const result = await this.pool.query(`SELECT state FROM ${this.stateTable} WHERE id = $1`, [this.stateRowId]);
    const parsed = result.rows[0]?.state || cloneState(DEFAULT_STATE);
    return this.#normalizeState(parsed);
  }

  async #writePostgres(mutator) {
    const client = await this.pool.connect();

    try {
      await client.query("BEGIN");

      const queryResult = await client.query(`SELECT state FROM ${this.stateTable} WHERE id = $1 FOR UPDATE`, [this.stateRowId]);
      const nextState = this.#normalizeState(queryResult.rows[0]?.state || cloneState(DEFAULT_STATE));

      const result = await mutator(nextState);
      this.#pruneState(nextState);

      await client.query(`UPDATE ${this.stateTable} SET state = $2::jsonb, updated_at = NOW() WHERE id = $1`, [
        this.stateRowId,
        JSON.stringify(nextState)
      ]);

      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  #normalizeState(input) {
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

  #pruneState(state) {
    const now = Date.now();

    state.reports = state.reports
      .filter((report) => {
        const createdAt = Date.parse(report.createdAt || report.completedAt || "");

        if (!Number.isFinite(createdAt)) {
          return false;
        }

        return now - createdAt <= this.reportTtlMs;
      });

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
      apiKeys: Array.isArray(user.apiKeys) ? user.apiKeys : []
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
