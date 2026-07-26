import { AppError } from "../common/errors.js";
import { fromBase64, toBase64, toBase64Url, fromBase64Url } from "../common/base64.js";
import { aesGcmEncrypt, aesGcmDecrypt } from "../crypto/aes-gcm.js";
import { zeroize } from "../crypto/zeroize.js";
import type { VaultState } from "../core/vault-state.js";
import type { TransitAuthorizationPort } from "./access/transit-authorization.port.js";
import type { TransitRepository } from "./transit.repository.js";
import { assertKeyName } from "./transit-key.service.js";

const ENVELOPE_RE = /^vault:([A-Za-z0-9._-]{1,64}):([A-Za-z0-9_-]+)$/;

export class TransitCryptoService {
  constructor(
    private readonly repo: TransitRepository,
    private readonly vaultState: VaultState,
    private readonly authorization: TransitAuthorizationPort,
  ) {}

  private requireUnlocked(): void {
    if (!this.vaultState.isUnlocked()) {
      throw new AppError("VAULT_LOCKED");
    }
  }

  async encrypt(
    actorEmail: string,
    keyName: string,
    plaintextB64: string,
  ): Promise<{ ciphertext: string }> {
    assertKeyName(keyName);
    this.requireUnlocked();

    const authorizedKey = await this.authorization.authorizeKey({
      actorEmail,
      action: "encrypt",
      keyName,
    });

    if (authorizedKey.keyUsage !== "ENCRYPT_DECRYPT") {
      throw new AppError("INVALID_KEY_USAGE");
    }

    const material = this.repo.getEncryptedKeyMaterial(authorizedKey.id);
    if (!material) {
      throw new AppError("KEY_NOT_FOUND");
    }

    const plaintext = fromBase64(plaintextB64, "plaintext_b64");
    if (plaintext.length > 1024 * 1024) {
      throw new AppError("REQUEST_TOO_LARGE");
    }

    let namedKey: Buffer | null = null;
    try {
      const wrapAad = `transit-key:${authorizedKey.ownerEmail}:${authorizedKey.keyName}:ENCRYPT_DECRYPT:v1`;
      namedKey = this.vaultState.withDek((dek) =>
        aesGcmDecrypt(
          dek,
          {
            nonceB64: material.nonceB64,
            ciphertextB64: material.ciphertextB64,
            tagB64: material.tagB64,
          },
          wrapAad,
        ),
      );

      const dataAad = `transit-data:${authorizedKey.ownerEmail}:${authorizedKey.keyName}:v1`;
      const sealed = aesGcmEncrypt(namedKey, plaintext, dataAad);
      const packed = Buffer.concat([
        fromBase64(sealed.nonceB64),
        fromBase64(sealed.ciphertextB64),
        fromBase64(sealed.tagB64),
      ]);
      return {
        ciphertext: `vault:${keyName}:${toBase64Url(packed)}`,
      };
    } finally {
      zeroize(namedKey);
    }
  }

  async decrypt(
    actorEmail: string,
    ciphertext: string,
  ): Promise<{ plaintext_b64: string }> {
    this.requireUnlocked();

    const match = ENVELOPE_RE.exec(ciphertext);
    if (!match) {
      throw new AppError("INVALID_CIPHERTEXT");
    }
    const keyName = match[1]!;
    const packedB64 = match[2]!;

    const authorizedKey = await this.authorization.authorizeKey({
      actorEmail,
      action: "decrypt",
      keyName,
    });

    if (authorizedKey.keyUsage !== "ENCRYPT_DECRYPT") {
      throw new AppError("INVALID_KEY_USAGE");
    }

    const material = this.repo.getEncryptedKeyMaterial(authorizedKey.id);
    if (!material) {
      throw new AppError("KEY_NOT_FOUND");
    }

    let packed: Buffer;
    try {
      packed = fromBase64Url(packedB64, "envelope");
    } catch {
      throw new AppError("INVALID_CIPHERTEXT");
    }
    if (packed.length < 12 + 16) {
      throw new AppError("INVALID_CIPHERTEXT");
    }

    const nonce = packed.subarray(0, 12);
    const tag = packed.subarray(packed.length - 16);
    const ct = packed.subarray(12, packed.length - 16);

    let namedKey: Buffer | null = null;
    try {
      const wrapAad = `transit-key:${authorizedKey.ownerEmail}:${authorizedKey.keyName}:ENCRYPT_DECRYPT:v1`;
      namedKey = this.vaultState.withDek((dek) =>
        aesGcmDecrypt(
          dek,
          {
            nonceB64: material.nonceB64,
            ciphertextB64: material.ciphertextB64,
            tagB64: material.tagB64,
          },
          wrapAad,
        ),
      );

      const dataAad = `transit-data:${authorizedKey.ownerEmail}:${authorizedKey.keyName}:v1`;
      const plaintext = aesGcmDecrypt(
        namedKey,
        {
          nonceB64: toBase64(nonce),
          ciphertextB64: toBase64(ct),
          tagB64: toBase64(tag),
        },
        dataAad,
      );
      return { plaintext_b64: toBase64(plaintext) };
    } finally {
      zeroize(namedKey);
    }
  }
}
