import crypto from "crypto";

function checksum(sql) {
  return crypto.createHash("sha256").update(sql).digest("hex");
}

function buildInitialSchemaSql({
  usersTable,
  jobsTable,
  reportsTable,
  apiKeysTable,
  refreshTokensTable,
  passwordResetTable,
  notificationsTable,
  auditEventsTable
}) {
  return `
    CREATE TABLE IF NOT EXISTS ${usersTable} (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL,
      email_normalized TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      name_normalized TEXT NOT NULL UNIQUE,
      role TEXT NOT NULL,
      status TEXT NOT NULL,
      password_hash TEXT NULL,
      auth_source TEXT NOT NULL DEFAULT 'local',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_login_at TIMESTAMPTZ NULL
    );

    CREATE TABLE IF NOT EXISTS ${jobsTable} (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES ${usersTable}(id) ON DELETE CASCADE ON UPDATE CASCADE,
      source_type TEXT NOT NULL,
      target_url TEXT NULL,
      status TEXT NOT NULL,
      original_name TEXT NOT NULL,
      mime_type TEXT NULL,
      file_size BIGINT NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      started_at TIMESTAMPTZ NULL,
      completed_at TIMESTAMPTZ NULL,
      report_id TEXT NULL,
      error_message TEXT NULL
    );

    CREATE TABLE IF NOT EXISTS ${reportsTable} (
      id TEXT PRIMARY KEY,
      owner_user_id TEXT NOT NULL REFERENCES ${usersTable}(id) ON DELETE CASCADE ON UPDATE CASCADE,
      source_type TEXT NOT NULL,
      queued_job_id TEXT NULL UNIQUE REFERENCES ${jobsTable}(id) ON DELETE SET NULL ON UPDATE CASCADE,
      created_at TIMESTAMPTZ NOT NULL,
      completed_at TIMESTAMPTZ NOT NULL,
      verdict TEXT NOT NULL,
      risk_score INTEGER NOT NULL DEFAULT 0,
      file_name TEXT NOT NULL,
      file_size BIGINT NOT NULL DEFAULT 0,
      file_sha256 TEXT NULL,
      detected_file_type TEXT NULL,
      file_extension TEXT NULL,
      payload JSONB NOT NULL,
      deleted_at TIMESTAMPTZ NULL,
      deleted_by_user_id TEXT NULL REFERENCES ${usersTable}(id) ON DELETE SET NULL ON UPDATE CASCADE
    );

    CREATE TABLE IF NOT EXISTS ${apiKeysTable} (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES ${usersTable}(id) ON DELETE CASCADE ON UPDATE CASCADE,
      name TEXT NOT NULL,
      key_prefix TEXT NOT NULL,
      key_hash TEXT NOT NULL UNIQUE,
      scopes JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_used_at TIMESTAMPTZ NULL,
      revoked_at TIMESTAMPTZ NULL
    );

    CREATE TABLE IF NOT EXISTS ${refreshTokensTable} (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES ${usersTable}(id) ON DELETE CASCADE ON UPDATE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      revoked_at TIMESTAMPTZ NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ${passwordResetTable} (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES ${usersTable}(id) ON DELETE CASCADE ON UPDATE CASCADE,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ${notificationsTable} (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES ${usersTable}(id) ON DELETE CASCADE ON UPDATE CASCADE,
      type TEXT NOT NULL,
      tone TEXT NOT NULL,
      title TEXT NOT NULL,
      detail TEXT NOT NULL,
      entity_type TEXT NULL,
      entity_id TEXT NULL,
      dedupe_key TEXT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      read_at TIMESTAMPTZ NULL
    );

    CREATE TABLE IF NOT EXISTS ${auditEventsTable} (
      id TEXT PRIMARY KEY,
      user_id TEXT NULL REFERENCES ${usersTable}(id) ON DELETE SET NULL ON UPDATE CASCADE,
      action TEXT NOT NULL,
      ip_address TEXT NULL,
      user_agent TEXT NOT NULL DEFAULT '',
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS ${jobsTable}_user_created_idx ON ${jobsTable}(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS ${jobsTable}_status_created_idx ON ${jobsTable}(status, created_at DESC);
    CREATE INDEX IF NOT EXISTS ${jobsTable}_source_created_idx ON ${jobsTable}(source_type, created_at DESC);
    CREATE INDEX IF NOT EXISTS ${reportsTable}_owner_completed_idx ON ${reportsTable}(owner_user_id, completed_at DESC);
    CREATE INDEX IF NOT EXISTS ${reportsTable}_hash_idx ON ${reportsTable}(file_sha256);
    CREATE INDEX IF NOT EXISTS ${reportsTable}_visible_idx ON ${reportsTable}(deleted_at, completed_at DESC);
    CREATE INDEX IF NOT EXISTS ${apiKeysTable}_user_active_idx ON ${apiKeysTable}(user_id, revoked_at, created_at DESC);
    CREATE INDEX IF NOT EXISTS ${refreshTokensTable}_user_active_idx ON ${refreshTokensTable}(user_id, revoked_at, expires_at DESC);
    CREATE INDEX IF NOT EXISTS ${passwordResetTable}_user_active_idx ON ${passwordResetTable}(user_id, used_at, expires_at DESC);
    CREATE INDEX IF NOT EXISTS ${notificationsTable}_user_created_idx ON ${notificationsTable}(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS ${notificationsTable}_user_unread_idx ON ${notificationsTable}(user_id, read_at, created_at DESC);
    CREATE UNIQUE INDEX IF NOT EXISTS ${notificationsTable}_dedupe_idx ON ${notificationsTable}(user_id, dedupe_key) WHERE dedupe_key IS NOT NULL;
    CREATE INDEX IF NOT EXISTS ${auditEventsTable}_created_idx ON ${auditEventsTable}(created_at DESC);
    CREATE INDEX IF NOT EXISTS ${auditEventsTable}_user_created_idx ON ${auditEventsTable}(user_id, created_at DESC);
  `;
}

function buildScaleHardeningSql({
  usersTable,
  jobsTable,
  reportsTable,
  notificationsTable
}) {
  return `
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${usersTable}_role_check') THEN
        EXECUTE 'ALTER TABLE ${usersTable} ADD CONSTRAINT ${usersTable}_role_check CHECK (role IN (''user'', ''admin''))';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${usersTable}_status_check') THEN
        EXECUTE 'ALTER TABLE ${usersTable} ADD CONSTRAINT ${usersTable}_status_check CHECK (status IN (''active'', ''disabled''))';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${usersTable}_auth_source_check') THEN
        EXECUTE 'ALTER TABLE ${usersTable} ADD CONSTRAINT ${usersTable}_auth_source_check CHECK (auth_source IN (''local'', ''supabase''))';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${jobsTable}_source_type_check') THEN
        EXECUTE 'ALTER TABLE ${jobsTable} ADD CONSTRAINT ${jobsTable}_source_type_check CHECK (source_type IN (''file'', ''url'', ''website''))';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${jobsTable}_status_check') THEN
        EXECUTE 'ALTER TABLE ${jobsTable} ADD CONSTRAINT ${jobsTable}_status_check CHECK (status IN (''queued'', ''processing'', ''completed'', ''failed''))';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${jobsTable}_target_url_check') THEN
        EXECUTE 'ALTER TABLE ${jobsTable} ADD CONSTRAINT ${jobsTable}_target_url_check CHECK ((source_type = ''file'' AND target_url IS NULL) OR (source_type IN (''url'', ''website'') AND target_url IS NOT NULL))';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${reportsTable}_source_type_check') THEN
        EXECUTE 'ALTER TABLE ${reportsTable} ADD CONSTRAINT ${reportsTable}_source_type_check CHECK (source_type IN (''file'', ''url'', ''website''))';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${reportsTable}_verdict_check') THEN
        EXECUTE 'ALTER TABLE ${reportsTable} ADD CONSTRAINT ${reportsTable}_verdict_check CHECK (verdict IN (''clean'', ''suspicious'', ''malicious''))';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${notificationsTable}_tone_check') THEN
        EXECUTE 'ALTER TABLE ${notificationsTable} ADD CONSTRAINT ${notificationsTable}_tone_check CHECK (tone IN (''info'', ''success'', ''warning'', ''danger''))';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${jobsTable}_report_fk') THEN
        EXECUTE 'ALTER TABLE ${jobsTable} ADD CONSTRAINT ${jobsTable}_report_fk FOREIGN KEY (report_id) REFERENCES ${reportsTable}(id) ON DELETE SET NULL ON UPDATE CASCADE';
      END IF;
    END $$;

    CREATE INDEX IF NOT EXISTS ${jobsTable}_user_source_created_idx ON ${jobsTable}(user_id, source_type, created_at DESC);
    CREATE UNIQUE INDEX IF NOT EXISTS ${jobsTable}_report_unique_idx ON ${jobsTable}(report_id) WHERE report_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS ${reportsTable}_owner_source_completed_visible_idx
      ON ${reportsTable}(owner_user_id, source_type, completed_at DESC, created_at DESC)
      WHERE deleted_at IS NULL;
    CREATE INDEX IF NOT EXISTS ${reportsTable}_completed_visible_idx
      ON ${reportsTable}(completed_at DESC, created_at DESC)
      WHERE deleted_at IS NULL;
    CREATE INDEX IF NOT EXISTS ${notificationsTable}_entity_created_idx
      ON ${notificationsTable}(entity_type, entity_id, created_at DESC);
  `;
}

export function buildStoreMigrations(context) {
  const migrations = [
    {
      name: "001_initial_schema",
      sql: buildInitialSchemaSql(context)
    },
    {
      name: "002_scale_hardening",
      sql: buildScaleHardeningSql(context)
    }
  ];

  return migrations.map((migration) => ({
    ...migration,
    checksum: checksum(migration.sql)
  }));
}

export async function applyStoreMigrations({ pool, migrationsTable, migrations }) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ${migrationsTable} (
      name TEXT PRIMARY KEY,
      checksum TEXT NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  const appliedResult = await pool.query(`SELECT name, checksum FROM ${migrationsTable} ORDER BY name ASC`);
  const appliedByName = new Map(appliedResult.rows.map((row) => [row.name, row.checksum]));
  const appliedMigrations = [];

  for (const migration of migrations) {
    const existingChecksum = appliedByName.get(migration.name);

    if (existingChecksum) {
      if (existingChecksum !== migration.checksum) {
        throw new Error(`Migration checksum mismatch for ${migration.name}.`);
      }
      continue;
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(migration.sql);
      await client.query(`INSERT INTO ${migrationsTable} (name, checksum) VALUES ($1, $2)`, [
        migration.name,
        migration.checksum
      ]);
      await client.query("COMMIT");
      appliedMigrations.push(migration.name);
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  return {
    totalMigrations: migrations.length,
    appliedMigrations
  };
}
