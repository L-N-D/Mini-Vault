import { createHash } from "node:crypto";
import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";

export type Db = Database.Database;

export function openDatabase(databasePath: string): Db {
  fs.mkdirSync(path.dirname(databasePath), { recursive: true });
  const db = new Database(databasePath);
  db.pragma("foreign_keys = ON");
  db.pragma("busy_timeout = 5000");
  db.pragma("secure_delete = ON");
  db.pragma("journal_mode = WAL");
  migrate(db);
  return db;
}

function tableExists(db: Db, name: string): boolean {
  const row = db
    .prepare(
      `SELECT 1 AS ok FROM sqlite_master WHERE type = 'table' AND name = ?`,
    )
    .get(name) as { ok: number } | undefined;
  return row !== undefined;
}

function columnExists(db: Db, table: string, column: string): boolean {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{
    name: string;
  }>;
  return rows.some((r) => r.name === column);
}

function ensureColumn(
  db: Db,
  table: string,
  column: string,
  ddlType: string,
): void {
  if (!tableExists(db, table)) return;
  if (columnExists(db, table, column)) return;
  db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${ddlType}`);
}

export function migrate(db: Db): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS vault_metadata (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      kdf_name TEXT NOT NULL,
      kdf_salt_b64 TEXT NOT NULL,
      kdf_params_json TEXT NOT NULL,
      dek_nonce_b64 TEXT NOT NULL,
      encrypted_dek_b64 TEXT NOT NULL,
      dek_tag_b64 TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      email TEXT PRIMARY KEY,
      password_hash TEXT NOT NULL,
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      token_hash TEXT NOT NULL UNIQUE,
      user_email TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      revoked_at TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_email) REFERENCES users(email)
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_user_email ON sessions(user_email);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

    CREATE TABLE IF NOT EXISTS kv_entries (
      path TEXT PRIMARY KEY,
      owner_email TEXT NOT NULL,
      nonce_b64 TEXT NOT NULL,
      ciphertext_b64 TEXT NOT NULL,
      tag_b64 TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      FOREIGN KEY (owner_email) REFERENCES users(email)
    );

    CREATE TABLE IF NOT EXISTS transit_keys (
      id TEXT PRIMARY KEY,
      owner_email TEXT NOT NULL,
      key_name TEXT NOT NULL UNIQUE,
      key_usage TEXT NOT NULL
        CHECK (key_usage IN ('ENCRYPT_DECRYPT', 'SIGN_VERIFY')),
      signing_algorithm TEXT,
      material_nonce_b64 TEXT NOT NULL,
      encrypted_key_material_b64 TEXT NOT NULL,
      material_tag_b64 TEXT NOT NULL,
      public_key_b64 TEXT,
      created_at TEXT NOT NULL,
      FOREIGN KEY (owner_email) REFERENCES users(email),
      CHECK (
        (
          key_usage = 'ENCRYPT_DECRYPT'
          AND signing_algorithm IS NULL
          AND public_key_b64 IS NULL
        )
        OR
        (
          key_usage = 'SIGN_VERIFY'
          AND signing_algorithm = 'ED25519'
          AND public_key_b64 IS NOT NULL
        )
      )
    );

    CREATE INDEX IF NOT EXISTS idx_transit_keys_owner ON transit_keys(owner_email);

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT NOT NULL,
      requester_email TEXT,
      target_type TEXT,
      target_value TEXT,
      result TEXT NOT NULL,
      metadata_json TEXT,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
  `);

  ensureColumn(
    db,
    "vault_metadata",
    "unlock_mode",
    `TEXT NOT NULL DEFAULT 'passphrase'`,
  );
  ensureColumn(db, "vault_metadata", "shamir_n", "INTEGER");
  ensureColumn(db, "vault_metadata", "shamir_k", "INTEGER");

  ensureColumn(db, "users", "totp_enabled", "INTEGER NOT NULL DEFAULT 0");
  ensureColumn(db, "users", "totp_salt_b64", "TEXT");
  ensureColumn(db, "users", "totp_secret_nonce_b64", "TEXT");
  ensureColumn(db, "users", "totp_secret_ct_b64", "TEXT");
  ensureColumn(db, "users", "totp_secret_tag_b64", "TEXT");
  ensureColumn(db, "users", "totp_pending_secret_b64", "TEXT");

  ensureColumn(db, "kv_entries", "version", "INTEGER NOT NULL DEFAULT 1");

  ensureColumn(
    db,
    "transit_keys",
    "current_version",
    "INTEGER NOT NULL DEFAULT 1",
  );
  ensureColumn(
    db,
    "transit_keys",
    "allow_public_verify",
    "INTEGER NOT NULL DEFAULT 0",
  );

  ensureColumn(db, "audit_logs", "prev_hash_hex", "TEXT");
  ensureColumn(db, "audit_logs", "entry_hash_hex", "TEXT");

  db.exec(`
    CREATE TABLE IF NOT EXISTS mfa_challenges (
      token_hash TEXT PRIMARY KEY,
      user_email TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_email) REFERENCES users(email)
    );

    CREATE TABLE IF NOT EXISTS kv_versions (
      path TEXT NOT NULL,
      version INTEGER NOT NULL,
      owner_email TEXT NOT NULL,
      nonce_b64 TEXT NOT NULL,
      ciphertext_b64 TEXT NOT NULL,
      tag_b64 TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (path, version),
      FOREIGN KEY (owner_email) REFERENCES users(email)
    );

    CREATE INDEX IF NOT EXISTS idx_kv_versions_path ON kv_versions(path);

    CREATE TABLE IF NOT EXISTS transit_key_versions (
      key_id TEXT NOT NULL,
      version INTEGER NOT NULL,
      material_nonce_b64 TEXT NOT NULL,
      encrypted_key_material_b64 TEXT NOT NULL,
      material_tag_b64 TEXT NOT NULL,
      public_key_b64 TEXT,
      created_at TEXT NOT NULL,
      PRIMARY KEY (key_id, version),
      FOREIGN KEY (key_id) REFERENCES transit_keys(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS access_grants (
      id TEXT PRIMARY KEY,
      resource_type TEXT NOT NULL CHECK (resource_type IN ('kv', 'transit')),
      resource_id TEXT NOT NULL,
      grantee_email TEXT NOT NULL,
      permissions TEXT NOT NULL,
      granted_by TEXT NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE(resource_type, resource_id, grantee_email),
      FOREIGN KEY (grantee_email) REFERENCES users(email),
      FOREIGN KEY (granted_by) REFERENCES users(email)
    );

    CREATE INDEX IF NOT EXISTS idx_access_grants_grantee
      ON access_grants(grantee_email);
    CREATE INDEX IF NOT EXISTS idx_access_grants_resource
      ON access_grants(resource_type, resource_id);
  `);

  backfillAuditHashes(db);

  db.exec(`
    INSERT OR IGNORE INTO transit_key_versions
      (key_id, version, material_nonce_b64, encrypted_key_material_b64,
       material_tag_b64, public_key_b64, created_at)
    SELECT id, 1, material_nonce_b64, encrypted_key_material_b64,
           material_tag_b64, public_key_b64, created_at
    FROM transit_keys
  `);
}

const GENESIS_HASH = "0".repeat(64);

function backfillAuditHashes(db: Db): void {
  const unhashed = db
    .prepare(
      `SELECT id FROM audit_logs WHERE entry_hash_hex IS NULL ORDER BY id ASC`,
    )
    .all() as Array<{ id: number }>;
  if (unhashed.length === 0) return;

  let prev = GENESIS_HASH;
  const lastHashed = db
    .prepare(
      `SELECT entry_hash_hex FROM audit_logs
       WHERE entry_hash_hex IS NOT NULL ORDER BY id DESC LIMIT 1`,
    )
    .get() as { entry_hash_hex: string } | undefined;
  if (lastHashed) prev = lastHashed.entry_hash_hex;

  const select = db.prepare(
    `SELECT id, event_type, requester_email, target_type, target_value,
            result, metadata_json, created_at
     FROM audit_logs WHERE id = ?`,
  );
  const update = db.prepare(
    `UPDATE audit_logs SET prev_hash_hex = ?, entry_hash_hex = ? WHERE id = ?`,
  );

  const tx = db.transaction(() => {
    for (const { id } of unhashed) {
      const row = select.get(id) as {
        event_type: string;
        requester_email: string | null;
        target_type: string | null;
        target_value: string | null;
        result: string;
        metadata_json: string | null;
        created_at: string;
      };
      const canonical = [
        prev,
        row.event_type,
        row.requester_email ?? "",
        row.target_type ?? "",
        row.target_value ?? "",
        row.result,
        row.metadata_json ?? "",
        row.created_at,
      ].join("|");
      const entryHash = createHash("sha256")
        .update(canonical, "utf8")
        .digest("hex");
      update.run(prev, entryHash, id);
      prev = entryHash;
    }
  });
  tx();
}

export { GENESIS_HASH };
