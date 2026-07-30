import type { Db } from "../storage/database.js";

export type VaultUnlockMode = "passphrase" | "shamir";

export interface VaultMetadataRow {
  kdf_name: string;
  kdf_salt_b64: string;
  kdf_params_json: string;
  dek_nonce_b64: string;
  encrypted_dek_b64: string;
  dek_tag_b64: string;
  created_at: string;
  unlock_mode: VaultUnlockMode;
  shamir_n: number | null;
  shamir_k: number | null;
}

export class VaultRepository {
  constructor(private readonly db: Db) {}

  exists(): boolean {
    const row = this.db
      .prepare(`SELECT 1 AS ok FROM vault_metadata WHERE id = 1`)
      .get() as { ok: number } | undefined;
    return row !== undefined;
  }

  get(): VaultMetadataRow | null {
    return (
      (this.db
        .prepare(
          `SELECT kdf_name, kdf_salt_b64, kdf_params_json, dek_nonce_b64,
                  encrypted_dek_b64, dek_tag_b64, created_at,
                  unlock_mode, shamir_n, shamir_k
           FROM vault_metadata WHERE id = 1`,
        )
        .get() as VaultMetadataRow | undefined) ?? null
    );
  }

  /** Insert inside caller-opened IMMEDIATE transaction after re-check. */
  insert(row: VaultMetadataRow): void {
    this.db
      .prepare(
        `INSERT INTO vault_metadata
         (id, kdf_name, kdf_salt_b64, kdf_params_json, dek_nonce_b64,
          encrypted_dek_b64, dek_tag_b64, created_at,
          unlock_mode, shamir_n, shamir_k)
         VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        row.kdf_name,
        row.kdf_salt_b64,
        row.kdf_params_json,
        row.dek_nonce_b64,
        row.encrypted_dek_b64,
        row.dek_tag_b64,
        row.created_at,
        row.unlock_mode,
        row.shamir_n,
        row.shamir_k,
      );
  }

  withImmediateTransaction<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.db.exec("COMMIT");
      return result;
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }
}
