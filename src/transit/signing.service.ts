import { AppError } from "../common/errors.js";
import { fromBase64, toBase64 } from "../common/base64.js";
import {
  ed25519Sign,
  ed25519Verify,
  resolveDigest,
  SIGNING_ALGORITHM,
  type MessageType,
} from "../crypto/signing.js";
import { zeroize } from "../crypto/zeroize.js";
import type { VaultState } from "../core/vault-state.js";
import type { TransitAuthorizationPort } from "./access/transit-authorization.port.js";
import type { TransitRepository } from "./transit.repository.js";
import { assertKeyName } from "./transit-key.service.js";
import { unwrapNamedKeyMaterial } from "./unwrap-named-key.js";

export class SigningService {
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

  private checkAlgorithm(
    provided: string | undefined,
    expected: string | null,
  ): void {
    if (provided !== undefined && provided !== expected) {
      throw new AppError("INVALID_SIGNING_ALGORITHM");
    }
  }

  async sign(
    actorEmail: string,
    keyName: string,
    messageB64: string,
    messageType: MessageType,
    signingAlgorithm?: string,
  ): Promise<{
    signature_b64: string;
    key_name: string;
    key_version: number;
    signing_algorithm: string;
  }> {
    assertKeyName(keyName);
    this.requireUnlocked();
    if (messageType !== "RAW" && messageType !== "DIGEST") {
      throw new AppError("INVALID_MESSAGE_TYPE");
    }

    const authorizedKey = await this.authorization.authorizeKey({
      actorEmail,
      action: "sign",
      keyName,
    });

    if (authorizedKey.keyUsage !== "SIGN_VERIFY") {
      throw new AppError("INVALID_KEY_USAGE");
    }
    this.checkAlgorithm(signingAlgorithm, authorizedKey.signingAlgorithm);

    const version = authorizedKey.currentVersion;
    const material = this.repo.getEncryptedKeyMaterial(
      authorizedKey.id,
      version,
    );
    if (!material) {
      throw new AppError("KEY_NOT_FOUND");
    }

    const message = fromBase64(messageB64, "message_b64");
    if (message.length > 1024 * 1024) {
      throw new AppError("REQUEST_TOO_LARGE");
    }
    const digest = resolveDigest(message, messageType);

    let privateKeyDer: Buffer | null = null;
    try {
      privateKeyDer = unwrapNamedKeyMaterial(
        this.vaultState,
        material,
        authorizedKey.ownerEmail,
        authorizedKey.keyName,
        "SIGN_VERIFY",
        version,
      );
      const signature = ed25519Sign(privateKeyDer, digest);
      return {
        signature_b64: toBase64(signature),
        key_name: keyName,
        key_version: version,
        signing_algorithm: SIGNING_ALGORITHM,
      };
    } finally {
      zeroize(privateKeyDer);
    }
  }

  async verify(
    actorEmail: string,
    keyName: string,
    messageB64: string,
    messageType: MessageType,
    signatureB64: string,
    signingAlgorithm?: string,
    keyVersion?: number,
  ): Promise<{
    key_name: string;
    key_version: number;
    signature_valid: boolean;
    signing_algorithm: string;
  }> {
    assertKeyName(keyName);
    this.requireUnlocked();
    if (messageType !== "RAW" && messageType !== "DIGEST") {
      throw new AppError("INVALID_MESSAGE_TYPE");
    }

    const authorizedKey = await this.authorization.authorizeKey({
      actorEmail,
      action: "verify",
      keyName,
    });

    if (authorizedKey.keyUsage !== "SIGN_VERIFY") {
      throw new AppError("INVALID_KEY_USAGE");
    }
    this.checkAlgorithm(signingAlgorithm, authorizedKey.signingAlgorithm);

    const version = keyVersion ?? authorizedKey.currentVersion;
    const material = this.repo.getEncryptedKeyMaterial(
      authorizedKey.id,
      version,
    );
    if (!material || !material.publicKeyB64) {
      throw new AppError(
        keyVersion !== undefined ? "VERSION_NOT_FOUND" : "KEY_NOT_FOUND",
      );
    }

    let message: Buffer;
    let signature: Buffer;
    try {
      message = fromBase64(messageB64, "message_b64");
      signature = fromBase64(signatureB64, "signature_b64");
    } catch (err) {
      if (err instanceof AppError) throw err;
      throw new AppError("INVALID_BASE64");
    }

    if (message.length > 1024 * 1024 || signature.length > 1024) {
      throw new AppError("INVALID_INPUT");
    }

    let digest: Buffer;
    try {
      digest = resolveDigest(message, messageType);
    } catch (err) {
      throw err;
    }

    const publicKeyDer = fromBase64(material.publicKeyB64, "public_key");
    const valid = ed25519Verify(publicKeyDer, digest, signature);

    return {
      key_name: keyName,
      key_version: version,
      signature_valid: valid,
      signing_algorithm: SIGNING_ALGORITHM,
    };
  }
}
