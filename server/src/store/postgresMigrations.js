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

function buildCommercialWorkspaceSql({
  usersTable,
  reportsTable,
  apiKeysTable,
  workspaceProfilesTable,
  reportSharesTable,
  reportWorkflowsTable,
  reportCommentsTable,
  webhooksTable,
  webhookDeliveriesTable,
  monitorsTable
}) {
  return `
    CREATE TABLE IF NOT EXISTS ${workspaceProfilesTable} (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL UNIQUE REFERENCES ${usersTable}(id) ON DELETE CASCADE ON UPDATE CASCADE,
      plan_id TEXT NOT NULL DEFAULT 'free',
      trial_plan_id TEXT NOT NULL DEFAULT 'pro',
      trial_status TEXT NOT NULL DEFAULT 'available',
      trial_started_at TIMESTAMPTZ NULL,
      trial_ends_at TIMESTAMPTZ NULL,
      trial_days INTEGER NOT NULL DEFAULT 14,
      retention_days_override INTEGER NULL,
      monitor_limit_override INTEGER NULL,
      webhook_limit_override INTEGER NULL,
      api_key_limit_override INTEGER NULL,
      billing_provider TEXT NULL,
      billing_customer_id TEXT NULL,
      billing_subscription_id TEXT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ${reportSharesTable} (
      id TEXT PRIMARY KEY,
      report_id TEXT NOT NULL REFERENCES ${reportsTable}(id) ON DELETE CASCADE ON UPDATE CASCADE,
      owner_user_id TEXT NOT NULL REFERENCES ${usersTable}(id) ON DELETE CASCADE ON UPDATE CASCADE,
      label TEXT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      revoked_at TIMESTAMPTZ NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_accessed_at TIMESTAMPTZ NULL,
      access_count INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS ${reportWorkflowsTable} (
      id TEXT PRIMARY KEY,
      report_id TEXT NOT NULL UNIQUE REFERENCES ${reportsTable}(id) ON DELETE CASCADE ON UPDATE CASCADE,
      owner_user_id TEXT NOT NULL REFERENCES ${usersTable}(id) ON DELETE CASCADE ON UPDATE CASCADE,
      case_status TEXT NOT NULL DEFAULT 'new',
      severity TEXT NOT NULL DEFAULT 'medium',
      assignee_label TEXT NULL,
      client_label TEXT NULL,
      recommended_action TEXT NULL,
      notes_summary TEXT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_commented_at TIMESTAMPTZ NULL
    );

    CREATE TABLE IF NOT EXISTS ${reportCommentsTable} (
      id TEXT PRIMARY KEY,
      report_id TEXT NOT NULL REFERENCES ${reportsTable}(id) ON DELETE CASCADE ON UPDATE CASCADE,
      owner_user_id TEXT NOT NULL REFERENCES ${usersTable}(id) ON DELETE CASCADE ON UPDATE CASCADE,
      author_user_id TEXT NULL REFERENCES ${usersTable}(id) ON DELETE SET NULL ON UPDATE CASCADE,
      author_name TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ${webhooksTable} (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES ${usersTable}(id) ON DELETE CASCADE ON UPDATE CASCADE,
      name TEXT NOT NULL,
      target_url TEXT NOT NULL,
      events JSONB NOT NULL DEFAULT '[]'::jsonb,
      secret TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      deleted_at TIMESTAMPTZ NULL
    );

    CREATE TABLE IF NOT EXISTS ${webhookDeliveriesTable} (
      id TEXT PRIMARY KEY,
      webhook_id TEXT NOT NULL REFERENCES ${webhooksTable}(id) ON DELETE CASCADE ON UPDATE CASCADE,
      user_id TEXT NOT NULL REFERENCES ${usersTable}(id) ON DELETE CASCADE ON UPDATE CASCADE,
      event_type TEXT NOT NULL,
      request_body JSONB NOT NULL,
      response_status INTEGER NULL,
      response_body JSONB NULL,
      error_message TEXT NULL,
      delivered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ${monitorsTable} (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES ${usersTable}(id) ON DELETE CASCADE ON UPDATE CASCADE,
      name TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target TEXT NOT NULL,
      normalized_target TEXT NOT NULL,
      cadence_hours INTEGER NOT NULL DEFAULT 24,
      notes TEXT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      last_checked_at TIMESTAMPTZ NULL,
      next_check_at TIMESTAMPTZ NULL,
      last_report_id TEXT NULL REFERENCES ${reportsTable}(id) ON DELETE SET NULL ON UPDATE CASCADE,
      last_verdict TEXT NULL,
      last_risk_score INTEGER NULL,
      last_change_summary JSONB NULL,
      last_snapshot JSONB NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      deleted_at TIMESTAMPTZ NULL
    );

    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${workspaceProfilesTable}_plan_check') THEN
        EXECUTE 'ALTER TABLE ${workspaceProfilesTable} ADD CONSTRAINT ${workspaceProfilesTable}_plan_check CHECK (plan_id IN (''free'', ''pro'', ''team'', ''business''))';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${workspaceProfilesTable}_trial_plan_check') THEN
        EXECUTE 'ALTER TABLE ${workspaceProfilesTable} ADD CONSTRAINT ${workspaceProfilesTable}_trial_plan_check CHECK (trial_plan_id IN (''free'', ''pro'', ''team'', ''business''))';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${workspaceProfilesTable}_trial_status_check') THEN
        EXECUTE 'ALTER TABLE ${workspaceProfilesTable} ADD CONSTRAINT ${workspaceProfilesTable}_trial_status_check CHECK (trial_status IN (''available'', ''active'', ''expired'', ''converted''))';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${reportWorkflowsTable}_status_check') THEN
        EXECUTE 'ALTER TABLE ${reportWorkflowsTable} ADD CONSTRAINT ${reportWorkflowsTable}_status_check CHECK (case_status IN (''new'', ''triage'', ''investigating'', ''closed''))';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${reportWorkflowsTable}_severity_check') THEN
        EXECUTE 'ALTER TABLE ${reportWorkflowsTable} ADD CONSTRAINT ${reportWorkflowsTable}_severity_check CHECK (severity IN (''low'', ''medium'', ''high'', ''critical''))';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${monitorsTable}_target_type_check') THEN
        EXECUTE 'ALTER TABLE ${monitorsTable} ADD CONSTRAINT ${monitorsTable}_target_type_check CHECK (target_type IN (''url'', ''website''))';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${monitorsTable}_status_check') THEN
        EXECUTE 'ALTER TABLE ${monitorsTable} ADD CONSTRAINT ${monitorsTable}_status_check CHECK (status IN (''active'', ''paused'', ''deleted''))';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${monitorsTable}_verdict_check') THEN
        EXECUTE 'ALTER TABLE ${monitorsTable} ADD CONSTRAINT ${monitorsTable}_verdict_check CHECK (last_verdict IS NULL OR last_verdict IN (''clean'', ''suspicious'', ''malicious''))';
      END IF;
    END $$;

    CREATE INDEX IF NOT EXISTS ${workspaceProfilesTable}_plan_idx ON ${workspaceProfilesTable}(plan_id, trial_status, updated_at DESC);
    CREATE INDEX IF NOT EXISTS ${reportSharesTable}_report_created_idx ON ${reportSharesTable}(report_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS ${reportSharesTable}_owner_active_idx ON ${reportSharesTable}(owner_user_id, revoked_at, expires_at DESC);
    CREATE INDEX IF NOT EXISTS ${reportWorkflowsTable}_owner_status_idx ON ${reportWorkflowsTable}(owner_user_id, case_status, severity, updated_at DESC);
    CREATE INDEX IF NOT EXISTS ${reportCommentsTable}_report_created_idx ON ${reportCommentsTable}(report_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS ${webhooksTable}_user_active_idx ON ${webhooksTable}(user_id, deleted_at, created_at DESC);
    CREATE INDEX IF NOT EXISTS ${webhookDeliveriesTable}_webhook_delivered_idx ON ${webhookDeliveriesTable}(webhook_id, delivered_at DESC);
    CREATE INDEX IF NOT EXISTS ${webhookDeliveriesTable}_user_delivered_idx ON ${webhookDeliveriesTable}(user_id, delivered_at DESC);
    CREATE INDEX IF NOT EXISTS ${monitorsTable}_user_active_idx ON ${monitorsTable}(user_id, deleted_at, status, next_check_at ASC);
    CREATE INDEX IF NOT EXISTS ${monitorsTable}_target_lookup_idx ON ${monitorsTable}(user_id, normalized_target, deleted_at);
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
    },
    {
      name: "003_commercial_workspace_foundations",
      sql: buildCommercialWorkspaceSql(context)
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
