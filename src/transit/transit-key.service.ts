import { randomUUID } from "node:crypto";
import { AppError } from "../common/errors.js";
import type { Clock } from "../common/clock.js";
import { toBase64 } from "../common/base64.js";
import { aesGcmEncrypt } from "../crypto/aes-gcm.js";
import { randomBytesSecure } from "../crypto/random.js";
import {
  generateEd25519KeyPair,
  SIGNING_ALGORITHM,
} from "../crypto/signing.js";
import { zeroize } from "../crypto/zeroize.js";
import type { VaultState } from "../core/vault-state.js";
import type { TransitAuthorizationPort } from "./access/transit-authorization.port.js";
import type { TransitRepository } from "./transit.repository.js";

const KEY_NAME_RE = /^[A-Za-z0-9._-]{1,64}$/;

export function assertKeyName(keyName: string): void {
  if (!KEY_NAME_RE.test(keyName)) {
    throw new AppError("INVALID_INPUT", "Invalid key_name");
  }
}

export class TransitKeyService {
  constructor(
    private readonly repo: TransitRepository,
    private readonly vaultState: VaultState,
    private readonly authorization: TransitAuthorizationPort,
    private readonly clock: Clock,
  ) {}

  private requireUnlocked(): void {
    if (!this.vaultState.isUnlocked()) {
      throw new AppError("VAULT_LOCKED");
    }
  }

  createEncryptionKey(actorEmail: string, keyName: string): {
    key_name: string;
    key_usage: string;
  } {
    assertKeyName(keyName);
    this.requireUnlocked();

    if (this.repo.keyNameExists(keyName)) {
      throw new AppError("KEY_NAME_UNAVAILABLE");
    }

    let aesKey: Buffer | null = randomBytesSecure(32);
    try {
      const aad = `transit-key:${actorEmail}:${keyName}:ENCRYPT_DECRYPT:kv1`;
      const sealed = this.vaultState.withDek((dek) =>
        aesGcmEncrypt(dek, aesKey!, aad),
      );
      this.repo.insertKey({
        id: randomUUID(),
        ownerEmail: actorEmail,
        keyName,
        keyUsage: "ENCRYPT_DECRYPT",
        signingAlgorithm: null,
        materialNonceB64: sealed.nonceB64,
        encryptedKeyMaterialB64: sealed.ciphertextB64,
        materialTagB64: sealed.tagB64,
        publicKeyB64: null,
        allowPublicVerify: false,
        createdAt: this.clock.now().toISOString(),
      });
      return { key_name: keyName, key_usage: "ENCRYPT_DECRYPT" };
    } catch (err) {
      if (
        err &&
        typeof err === "object" &&
        "code" in err &&
        (err as { code: string }).code === "SQLITE_CONSTRAINT_UNIQUE"
      ) {
        throw new AppError("KEY_NAME_UNAVAILABLE");
      }
      throw err;
    } finally {
      zeroize(aesKey);
      aesKey = null;
    }
  }

  createSigningKey(
    actorEmail: string,
    keyName: string,
    opts?: { allowPublicVerify?: boolean },
  ): {
    key_name: string;
    key_usage: string;
    signing_algorithm: string;
    allow_public_verify: boolean;
  } {
    assertKeyName(keyName);
    this.requireUnlocked();

    if (this.repo.keyNameExists(keyName)) {
      throw new AppError("KEY_NAME_UNAVAILABLE");
    }

    const allowPublicVerify = opts?.allowPublicVerify === true;
    const pair = generateEd25519KeyPair();
    try {
      const aad = `transit-key:${actorEmail}:${keyName}:SIGN_VERIFY:kv1`;
      const sealed = this.vaultState.withDek((dek) =>
        aesGcmEncrypt(dek, pair.privateKeyDer, aad),
      );
      this.repo.insertKey({
        id: randomUUID(),
        ownerEmail: actorEmail,
        keyName,
        keyUsage: "SIGN_VERIFY",
        signingAlgorithm: SIGNING_ALGORITHM,
        materialNonceB64: sealed.nonceB64,
        encryptedKeyMaterialB64: sealed.ciphertextB64,
        materialTagB64: sealed.tagB64,
        publicKeyB64: toBase64(pair.publicKeyDer),
        allowPublicVerify,
        createdAt: this.clock.now().toISOString(),
      });
      return {
        key_name: keyName,
        key_usage: "SIGN_VERIFY",
        signing_algorithm: SIGNING_ALGORITHM,
        allow_public_verify: allowPublicVerify,
      };
    } catch (err) {
      if (
        err &&
        typeof err === "object" &&
        "code" in err &&
        (err as { code: string }).code === "SQLITE_CONSTRAINT_UNIQUE"
      ) {
        throw new AppError("KEY_NAME_UNAVAILABLE");
      }
      throw err;
    } finally {
      zeroize(pair.privateKeyDer);
    }
  }

  listKeys(actorEmail: string): Array<{
    key_name: string;
    key_usage: string;
    signing_algorithm: string | null;
    current_version: number;
    allow_public_verify: boolean;
  }> {
    this.requireUnlocked();
    return this.repo.listMetadataByOwner(actorEmail).map((k) => ({
      key_name: k.keyName,
      key_usage: k.keyUsage,
      signing_algorithm: k.signingAlgorithm,
      current_version: k.currentVersion,
      allow_public_verify: k.allowPublicVerify,
    }));
  }

  async rotateKey(
    actorEmail: string,
    keyName: string,
  ): Promise<{ key_name: string; current_version: number }> {
    assertKeyName(keyName);
    this.requireUnlocked();

    const authorizedKey = await this.authorization.authorizeKey({
      actorEmail,
      action: "rotate",
      keyName,
    });

    const nextVersion = authorizedKey.currentVersion + 1;
    const createdAt = this.clock.now().toISOString();
    const owner = authorizedKey.ownerEmail;

    switch (authorizedKey.keyUsage) {
      case "ENCRYPT_DECRYPT": {
        let aesKey: Buffer | null = randomBytesSecure(32);
        try {
          const aad = `transit-key:${owner}:${keyName}:ENCRYPT_DECRYPT:kv${nextVersion}`;
          const sealed = this.vaultState.withDek((dek) =>
            aesGcmEncrypt(dek, aesKey!, aad),
          );
          this.repo.insertKeyVersion({
            keyId: authorizedKey.id,
            version: nextVersion,
            materialNonceB64: sealed.nonceB64,
            encryptedKeyMaterialB64: sealed.ciphertextB64,
            materialTagB64: sealed.tagB64,
            publicKeyB64: null,
            createdAt,
          });
          this.repo.updateCurrentVersion(authorizedKey.id, nextVersion, {
            materialNonceB64: sealed.nonceB64,
            encryptedKeyMaterialB64: sealed.ciphertextB64,
            materialTagB64: sealed.tagB64,
            publicKeyB64: null,
          });
        } finally {
          zeroize(aesKey);
          aesKey = null;
        }
        break;
      }
      case "SIGN_VERIFY": {
        const pair = generateEd25519KeyPair();
        try {
          const aad = `transit-key:${owner}:${keyName}:SIGN_VERIFY:kv${nextVersion}`;
          const sealed = this.vaultState.withDek((dek) =>
            aesGcmEncrypt(dek, pair.privateKeyDer, aad),
          );
          const publicKeyB64 = toBase64(pair.publicKeyDer);
          this.repo.insertKeyVersion({
            keyId: authorizedKey.id,
            version: nextVersion,
            materialNonceB64: sealed.nonceB64,
            encryptedKeyMaterialB64: sealed.ciphertextB64,
            materialTagB64: sealed.tagB64,
            publicKeyB64,
            createdAt,
          });
          this.repo.updateCurrentVersion(authorizedKey.id, nextVersion, {
            materialNonceB64: sealed.nonceB64,
            encryptedKeyMaterialB64: sealed.ciphertextB64,
            materialTagB64: sealed.tagB64,
            publicKeyB64,
          });
        } finally {
          zeroize(pair.privateKeyDer);
        }
        break;
      }
      default: {
        const _exhaustive: never = authorizedKey.keyUsage;
        return _exhaustive;
      }
    }

    return { key_name: keyName, current_version: nextVersion };
  }

  async revokeKey(
    actorEmail: string,
    keyName: string,
  ): Promise<{ revoked: true }> {
    assertKeyName(keyName);
    this.requireUnlocked();

    const authorizedKey = await this.authorization.authorizeKey({
      actorEmail,
      action: "revoke",
      keyName,
    });

    const deleted = this.repo.deleteKeyById(authorizedKey.id);
    if (!deleted) {
      throw new AppError("KEY_NOT_FOUND");
    }
    return { revoked: true };
  }
}
