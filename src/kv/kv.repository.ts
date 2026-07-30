import type { Db } from "../storage/database.js";

export interface KvEntryRow {
  path: string;
  owner_email: string;
  nonce_b64: string;
  ciphertext_b64: string;
  tag_b64: string;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface KvVersionRow {
  path: string;
  version: number;
  owner_email: string;
  nonce_b64: string;
  ciphertext_b64: string;
  tag_b64: string;
  created_at: string;
}

export class KvRepository {
  constructor(private readonly db: Db) {}

  get(path: string): KvEntryRow | null {
    return (
      (this.db
        .prepare(
          `SELECT path, owner_email, nonce_b64, ciphertext_b64, tag_b64,
                  version, created_at, updated_at
           FROM kv_entries WHERE path = ?`,
        )
        .get(path) as KvEntryRow | undefined) ?? null
    );
  }

  upsert(entry: KvEntryRow): void {
    this.db
      .prepare(
        `INSERT INTO kv_entries
         (path, owner_email, nonce_b64, ciphertext_b64, tag_b64,
          version, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(path) DO UPDATE SET
           owner_email = excluded.owner_email,
           nonce_b64 = excluded.nonce_b64,
           ciphertext_b64 = excluded.ciphertext_b64,
           tag_b64 = excluded.tag_b64,
           version = excluded.version,
           updated_at = excluded.updated_at`,
      )
      .run(
        entry.path,
        entry.owner_email,
        entry.nonce_b64,
        entry.ciphertext_b64,
        entry.tag_b64,
        entry.version,
        entry.created_at,
        entry.updated_at,
      );
  }

  delete(path: string): boolean {
    const run = this.db.transaction(() => {
      this.db.prepare(`DELETE FROM kv_versions WHERE path = ?`).run(path);
      return this.db.prepare(`DELETE FROM kv_entries WHERE path = ?`).run(path);
    });
    return run().changes > 0;
  }

  insertVersion(row: KvVersionRow): void {
    this.db
      .prepare(
        `INSERT INTO kv_versions
         (path, version, owner_email, nonce_b64, ciphertext_b64, tag_b64, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        row.path,
        row.version,
        row.owner_email,
        row.nonce_b64,
        row.ciphertext_b64,
        row.tag_b64,
        row.created_at,
      );
  }

  getVersion(path: string, version: number): KvVersionRow | null {
    return (
      (this.db
        .prepare(
          `SELECT path, version, owner_email, nonce_b64, ciphertext_b64, tag_b64, created_at
           FROM kv_versions WHERE path = ? AND version = ?`,
        )
        .get(path, version) as KvVersionRow | undefined) ?? null
    );
  }

  listVersions(path: string): Array<{ version: number; created_at: string }> {
    return this.db
      .prepare(
        `SELECT version, created_at FROM kv_versions
         WHERE path = ? ORDER BY version ASC`,
      )
      .all(path) as Array<{ version: number; created_at: string }>;
  }
}
