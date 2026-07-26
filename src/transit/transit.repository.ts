import type { Db } from "../storage/database.js";
import type { AuthorizedKeyMetadata } from "./access/transit-authorization.port.js";

export interface EncryptedMaterial {
  nonceB64: string;
  ciphertextB64: string;
  tagB64: string;
  publicKeyB64: string | null;
}

export interface TransitKeyInsert {
  id: string;
  ownerEmail: string;
  keyName: string;
  keyUsage: "ENCRYPT_DECRYPT" | "SIGN_VERIFY";
  signingAlgorithm: "ED25519" | null;
  materialNonceB64: string;
  encryptedKeyMaterialB64: string;
  materialTagB64: string;
  publicKeyB64: string | null;
  createdAt: string;
}

export class TransitRepository {
  constructor(private readonly db: Db) {}

  getKeyMetadata(keyName: string): AuthorizedKeyMetadata | null {
    const row = this.db
      .prepare(
        `SELECT id, key_name, owner_email, key_usage, signing_algorithm
         FROM transit_keys WHERE key_name = ?`,
      )
      .get(keyName) as
      | {
          id: string;
          key_name: string;
          owner_email: string;
          key_usage: "ENCRYPT_DECRYPT" | "SIGN_VERIFY";
          signing_algorithm: string | null;
        }
      | undefined;

    if (!row) return null;
    return {
      id: row.id,
      keyName: row.key_name,
      ownerEmail: row.owner_email,
      keyUsage: row.key_usage,
      signingAlgorithm:
        row.signing_algorithm === "ED25519" ? "ED25519" : null,
    };
  }

  getEncryptedKeyMaterial(keyId: string): EncryptedMaterial | null {
    const row = this.db
      .prepare(
        `SELECT material_nonce_b64, encrypted_key_material_b64, material_tag_b64, public_key_b64
         FROM transit_keys WHERE id = ?`,
      )
      .get(keyId) as
      | {
          material_nonce_b64: string;
          encrypted_key_material_b64: string;
          material_tag_b64: string;
          public_key_b64: string | null;
        }
      | undefined;

    if (!row) return null;
    return {
      nonceB64: row.material_nonce_b64,
      ciphertextB64: row.encrypted_key_material_b64,
      tagB64: row.material_tag_b64,
      publicKeyB64: row.public_key_b64,
    };
  }

  listMetadataByOwner(ownerEmail: string): AuthorizedKeyMetadata[] {
    const rows = this.db
      .prepare(
        `SELECT id, key_name, owner_email, key_usage, signing_algorithm
         FROM transit_keys WHERE owner_email = ? ORDER BY key_name`,
      )
      .all(ownerEmail) as Array<{
      id: string;
      key_name: string;
      owner_email: string;
      key_usage: "ENCRYPT_DECRYPT" | "SIGN_VERIFY";
      signing_algorithm: string | null;
    }>;

    return rows.map((row) => ({
      id: row.id,
      keyName: row.key_name,
      ownerEmail: row.owner_email,
      keyUsage: row.key_usage,
      signingAlgorithm:
        row.signing_algorithm === "ED25519" ? "ED25519" : null,
    }));
  }

  insertKey(row: TransitKeyInsert): void {
    this.db
      .prepare(
        `INSERT INTO transit_keys
         (id, owner_email, key_name, key_usage, signing_algorithm,
          material_nonce_b64, encrypted_key_material_b64, material_tag_b64,
          public_key_b64, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        row.id,
        row.ownerEmail,
        row.keyName,
        row.keyUsage,
        row.signingAlgorithm,
        row.materialNonceB64,
        row.encryptedKeyMaterialB64,
        row.materialTagB64,
        row.publicKeyB64,
        row.createdAt,
      );
  }

  keyNameExists(keyName: string): boolean {
    const row = this.db
      .prepare(`SELECT 1 AS ok FROM transit_keys WHERE key_name = ?`)
      .get(keyName) as { ok: number } | undefined;
    return row !== undefined;
  }

  deleteKeyById(id: string): boolean {
    const result = this.db
      .prepare(`DELETE FROM transit_keys WHERE id = ?`)
      .run(id);
    return result.changes > 0;
  }
}
