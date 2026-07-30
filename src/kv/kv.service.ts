import { AppError } from "../common/errors.js";
import type { Clock } from "../common/clock.js";
import {
  emailFromSecretPath,
  validateAndReturnCanonicalSecretPath,
} from "../common/kv-path.js";
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
  ): Promise<{
    path: string;
    version: number;
    created_at: string;
    updated_at: string;
  }> {
    const canonicalPath = validateAndReturnCanonicalSecretPath(pathRaw);
    this.requireUnlocked();
    await this.authorization.assertAllowed({
      actorEmail,
      action: "write",
      path: canonicalPath,
    });

    const ownerEmail = emailFromSecretPath(canonicalPath);
    const plaintext = Buffer.from(JSON.stringify(data), "utf8");
    if (plaintext.length > 1024 * 1024) {
      throw new AppError("REQUEST_TOO_LARGE");
    }

    const existing = this.repo.get(canonicalPath);
    const version = existing ? existing.version + 1 : 1;
    const aad = `kv:${ownerEmail}:${canonicalPath}:v${version}`;
    const sealed = this.vaultState.withDek((dek) =>
      aesGcmEncrypt(dek, plaintext, aad),
    );

    const now = this.clock.now().toISOString();
    const createdAt = existing?.created_at ?? now;

    if (existing) {
      this.repo.insertVersion({
        path: existing.path,
        version: existing.version,
        owner_email: existing.owner_email,
        nonce_b64: existing.nonce_b64,
        ciphertext_b64: existing.ciphertext_b64,
        tag_b64: existing.tag_b64,
        created_at: existing.updated_at,
      });
    }

    this.repo.upsert({
      path: canonicalPath,
      owner_email: ownerEmail,
      nonce_b64: sealed.nonceB64,
      ciphertext_b64: sealed.ciphertextB64,
      tag_b64: sealed.tagB64,
      version,
      created_at: createdAt,
      updated_at: now,
    });

    return {
      path: canonicalPath,
      version,
      created_at: createdAt,
      updated_at: now,
    };
  }

  async read(
    actorEmail: string,
    pathRaw: string,
    version?: number,
  ): Promise<{ path: string; version: number; data: unknown }> {
    const canonicalPath = validateAndReturnCanonicalSecretPath(pathRaw);
    this.requireUnlocked();
    await this.authorization.assertAllowed({
      actorEmail,
      action: "read",
      path: canonicalPath,
    });

    const ownerEmail = emailFromSecretPath(canonicalPath);
    const current = this.repo.get(canonicalPath);

    let nonceB64: string;
    let ciphertextB64: string;
    let tagB64: string;
    let resolvedVersion: number;

    if (version === undefined) {
      if (!current) {
        throw new AppError("NOT_FOUND");
      }
      resolvedVersion = current.version;
      nonceB64 = current.nonce_b64;
      ciphertextB64 = current.ciphertext_b64;
      tagB64 = current.tag_b64;
    } else if (current && current.version === version) {
      resolvedVersion = current.version;
      nonceB64 = current.nonce_b64;
      ciphertextB64 = current.ciphertext_b64;
      tagB64 = current.tag_b64;
    } else {
      const archived = this.repo.getVersion(canonicalPath, version);
      if (!archived) {
        throw new AppError("VERSION_NOT_FOUND");
      }
      resolvedVersion = archived.version;
      nonceB64 = archived.nonce_b64;
      ciphertextB64 = archived.ciphertext_b64;
      tagB64 = archived.tag_b64;
    }

    const aad = `kv:${ownerEmail}:${canonicalPath}:v${resolvedVersion}`;
    const plaintext = this.vaultState.withDek((dek) =>
      aesGcmDecrypt(
        dek,
        {
          nonceB64,
          ciphertextB64,
          tagB64,
        },
        aad,
      ),
    );

    return {
      path: canonicalPath,
      version: resolvedVersion,
      data: JSON.parse(plaintext.toString("utf8")) as unknown,
    };
  }

  async listVersions(
    actorEmail: string,
    pathRaw: string,
  ): Promise<{
    path: string;
    versions: Array<{ version: number; created_at: string }>;
  }> {
    const canonicalPath = validateAndReturnCanonicalSecretPath(pathRaw);
    this.requireUnlocked();
    await this.authorization.assertAllowed({
      actorEmail,
      action: "read",
      path: canonicalPath,
    });

    const current = this.repo.get(canonicalPath);
    if (!current) {
      throw new AppError("NOT_FOUND");
    }

    const archived = this.repo.listVersions(canonicalPath);
    const versions = [
      ...archived,
      { version: current.version, created_at: current.updated_at },
    ].sort((a, b) => a.version - b.version);

    return { path: canonicalPath, versions };
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
