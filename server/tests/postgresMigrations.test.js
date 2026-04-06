import { describe, expect, it } from "vitest";
import { applyStoreMigrations, buildStoreMigrations } from "../src/store/postgresMigrations.js";

function createFakePool() {
  const state = {
    applied: [],
    createdMigrationTable: false,
    clients: []
  };

  const pool = {
    async query(sql) {
      if (sql.includes("CREATE TABLE IF NOT EXISTS virovanta_schema_migrations")) {
        state.createdMigrationTable = true;
        return { rowCount: 0, rows: [] };
      }

      if (sql.includes("SELECT name, checksum FROM virovanta_schema_migrations")) {
        return {
          rowCount: state.applied.length,
          rows: state.applied.map((entry) => ({ name: entry.name, checksum: entry.checksum }))
        };
      }

      throw new Error(`Unexpected pool query: ${sql}`);
    },
    async connect() {
      const clientState = {
        ranSql: []
      };
      state.clients.push(clientState);

      return {
        async query(sql, params = []) {
          if (sql === "BEGIN" || sql === "COMMIT" || sql === "ROLLBACK") {
            clientState.ranSql.push(sql);
            return { rowCount: 0, rows: [] };
          }

          if (sql.startsWith("INSERT INTO virovanta_schema_migrations")) {
            state.applied.push({
              name: params[0],
              checksum: params[1]
            });
            clientState.ranSql.push("INSERT_MIGRATION");
            return { rowCount: 1, rows: [] };
          }

          clientState.ranSql.push(sql);
          return { rowCount: 0, rows: [] };
        },
        release() {}
      };
    }
  };

  return { pool, state };
}

describe("postgres migration runner", () => {
  it("applies pending migrations in order and records them", async () => {
    const migrations = buildStoreMigrations({
      usersTable: "virovanta_users",
      jobsTable: "virovanta_jobs",
      reportsTable: "virovanta_reports",
      apiKeysTable: "virovanta_api_keys",
      refreshTokensTable: "virovanta_refresh_tokens",
      passwordResetTable: "virovanta_password_reset_tokens",
      notificationsTable: "virovanta_notifications",
      auditEventsTable: "virovanta_audit_events"
    });
    const { pool, state } = createFakePool();

    const result = await applyStoreMigrations({
      pool,
      migrationsTable: "virovanta_schema_migrations",
      migrations
    });

    expect(state.createdMigrationTable).toBe(true);
    expect(result.totalMigrations).toBe(3);
    expect(result.appliedMigrations).toEqual([
      "001_initial_schema",
      "002_scale_hardening",
      "003_commercial_workspace_foundations"
    ]);
    expect(state.applied).toHaveLength(3);
  });

  it("rejects checksum drift for an already recorded migration", async () => {
    const migrations = buildStoreMigrations({
      usersTable: "virovanta_users",
      jobsTable: "virovanta_jobs",
      reportsTable: "virovanta_reports",
      apiKeysTable: "virovanta_api_keys",
      refreshTokensTable: "virovanta_refresh_tokens",
      passwordResetTable: "virovanta_password_reset_tokens",
      notificationsTable: "virovanta_notifications",
      auditEventsTable: "virovanta_audit_events"
    });
    const { pool, state } = createFakePool();

    state.applied.push({
      name: "001_initial_schema",
      checksum: "unexpected"
    });

    await expect(
      applyStoreMigrations({
        pool,
        migrationsTable: "virovanta_schema_migrations",
        migrations
      })
    ).rejects.toThrow("Migration checksum mismatch for 001_initial_schema.");
  });
});
