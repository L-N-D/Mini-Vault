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
}
