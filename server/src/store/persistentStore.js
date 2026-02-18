import fs from "fs/promises";
import path from "path";

const DEFAULT_STATE = {
  version: 1,
  users: [],
  reports: [],
  jobs: [],
  auditEvents: []
};

function cloneState(state) {
  return structuredClone(state);
}

export class PersistentStore {
  constructor({ filePath, reportTtlMs, maxReports }) {
    this.filePath = filePath;
    this.reportTtlMs = reportTtlMs;
    this.maxReports = maxReports;
    this.state = cloneState(DEFAULT_STATE);
    this.writeChain = Promise.resolve();
  }

  async init() {
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });

    try {
      const raw = await fs.readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw);
      this.state = this.#normalizeState(parsed);
      this.#pruneState(this.state);
      await this.#persist(this.state);
    } catch (error) {
      if (error?.code !== "ENOENT") {
        throw error;
      }

      this.state = cloneState(DEFAULT_STATE);
      await this.#persist(this.state);
    }
  }

  async read(selector) {
    const current = this.state;
    return selector(current);
  }

  async write(mutator) {
    const operation = async () => {
      const nextState = cloneState(this.state);
      const result = await mutator(nextState);
      this.#pruneState(nextState);
      this.state = nextState;
      await this.#persist(nextState);
      return result;
    };

    this.writeChain = this.writeChain.then(operation, operation);
    return this.writeChain;
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

    state.auditEvents = state.auditEvents.slice(0, 20_000);

    state.users = state.users.map((user) => ({
      ...user,
      refreshTokens: Array.isArray(user.refreshTokens)
        ? user.refreshTokens.filter((token) => !token.revokedAt && Date.parse(token.expiresAt) > now)
        : [],
      apiKeys: Array.isArray(user.apiKeys) ? user.apiKeys : []
    }));
  }

  async #persist(state) {
    const tmpPath = `${this.filePath}.tmp`;
    const payload = JSON.stringify(state, null, 2);
    await fs.writeFile(tmpPath, payload, "utf8");
    await fs.rename(tmpPath, this.filePath);
  }
}

export { DEFAULT_STATE };
