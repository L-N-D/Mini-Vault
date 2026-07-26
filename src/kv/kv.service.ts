import { AppError } from "../common/errors.js";
import type { Clock } from "../common/clock.js";
import { validateAndReturnCanonicalSecretPath } from "../common/kv-path.js";
import { aesGcmEncrypt, aesGcmDecrypt } from "../crypto/aes-gcm.js";
import type { VaultState } from "../core/vault-state.js";
import type { KvAuthorizationPort } from "./access/kv-authorization.port.js";
import type { KvRepository } from "./kv.repository.js";

export class KvService {
  constructor(
    private readonly repo: KvRepository,
    private readonly vaultState: VaultState,
    private readonly authorization: KvAuthorizationPort,
    private readonly clock: Clock,
  ) {}

  private requireUnlocked(): void {
    if (!this.vaultState.isUnlocked()) {
      throw new AppError("VAULT_LOCKED");
    }
  }

  async write(
    actorEmail: string,
    pathRaw: string,
    data: unknown,
  ): Promise<{ path: string; created_at: string; updated_at: string }> {
    const canonicalPath = validateAndReturnCanonicalSecretPath(pathRaw);
    this.requireUnlocked();
    await this.authorization.assertAllowed({
      actorEmail,
      action: "write",
      path: canonicalPath,
    });

    const plaintext = Buffer.from(JSON.stringify(data), "utf8");
    if (plaintext.length > 1024 * 1024) {
      throw new AppError("REQUEST_TOO_LARGE");
    }

    const aad = `kv:${actorEmail}:${canonicalPath}:v1`;
    const sealed = this.vaultState.withDek((dek) =>
      aesGcmEncrypt(dek, plaintext, aad),
    );

    const existing = this.repo.get(canonicalPath);
    const now = this.clock.now().toISOString();
    const createdAt = existing?.created_at ?? now;

    this.repo.upsert({
      path: canonicalPath,
      owner_email: actorEmail,
      nonce_b64: sealed.nonceB64,
      ciphertext_b64: sealed.ciphertextB64,
      tag_b64: sealed.tagB64,
      created_at: createdAt,
      updated_at: now,
    });

    return { path: canonicalPath, created_at: createdAt, updated_at: now };
  }

  async read(
    actorEmail: string,
    pathRaw: string,
  ): Promise<{ path: string; data: unknown }> {
    const canonicalPath = validateAndReturnCanonicalSecretPath(pathRaw);
    this.requireUnlocked();
    await this.authorization.assertAllowed({
      actorEmail,
      action: "read",
      path: canonicalPath,
    });

    const row = this.repo.get(canonicalPath);
    if (!row) {
      throw new AppError("NOT_FOUND");
    }

    const aad = `kv:${actorEmail}:${canonicalPath}:v1`;
    const plaintext = this.vaultState.withDek((dek) =>
      aesGcmDecrypt(
        dek,
        {
          nonceB64: row.nonce_b64,
          ciphertextB64: row.ciphertext_b64,
          tagB64: row.tag_b64,
        },
        aad,
      ),
    );

    return {
      path: canonicalPath,
      data: JSON.parse(plaintext.toString("utf8")) as unknown,
    };
  }

  async delete(
    actorEmail: string,
    pathRaw: string,
  ): Promise<{ deleted: true; path: string }> {
    const canonicalPath = validateAndReturnCanonicalSecretPath(pathRaw);
    this.requireUnlocked();
    await this.authorization.assertAllowed({
      actorEmail,
      action: "delete",
      path: canonicalPath,
    });

    const ok = this.repo.delete(canonicalPath);
    if (!ok) {
      throw new AppError("NOT_FOUND");
    }
    return { deleted: true, path: canonicalPath };
  }
}
