import { AppError } from "../common/errors.js";
import { toBase64 } from "../common/base64.js";
import type { Clock } from "../common/clock.js";
import {
  deriveKek,
  kdfParamsJson,
  encodeSalt,
  decodeSalt,
} from "../crypto/argon2.js";
import { aesGcmEncrypt, aesGcmDecrypt } from "../crypto/aes-gcm.js";
import { randomBytesSecure } from "../crypto/random.js";
import { zeroize } from "../crypto/zeroize.js";
import {
  split as shamirSplit,
  combine as shamirCombine,
  encodeShare,
  decodeShare,
} from "../crypto/shamir.js";
import type { VaultRepository, VaultUnlockMode } from "./vault.repository.js";
import type { VaultState } from "./vault-state.js";
import type { MasterPassphraseProvider } from "./master-passphrase-provider.js";
import type { ShareProvider } from "./share-provider.js";
import type { AuditService } from "../audit/audit.service.js";

const DEK_AAD = "mini-vault:dek:v1";
const MIN_PASSPHRASE = 12;
const MAX_PASSPHRASE = 256;

function validateMasterPassphrase(passphrase: string): void {
  if (
    typeof passphrase !== "string" ||
    passphrase.length < MIN_PASSPHRASE ||
    passphrase.length > MAX_PASSPHRASE ||
    passphrase.trim().length === 0
  ) {
    throw new AppError("INVALID_INPUT", "Master Passphrase does not meet policy");
  }
}

export class VaultService {
  constructor(
    private readonly repo: VaultRepository,
    private readonly state: VaultState,
    private readonly clock: Clock,
    private readonly audit: AuditService,
  ) {}

  diskStatus(): "NOT_INITIALIZED" | "LOCKED" {
    return this.repo.exists() ? "LOCKED" : "NOT_INITIALIZED";
  }

  runtimeStatus(): "LOCKED" | "UNLOCKED" {
    return this.state.status;
  }

  getUnlockMode(): VaultUnlockMode {
    const meta = this.repo.get();
    if (!meta) {
      throw new AppError("VAULT_NOT_INITIALIZED");
    }
    return meta.unlock_mode === "shamir" ? "shamir" : "passphrase";
  }

  async init(passphrase: string): Promise<void> {
    validateMasterPassphrase(passphrase);

    if (this.repo.exists()) {
      throw new AppError("VAULT_ALREADY_INITIALIZED");
    }

    const salt = randomBytesSecure(16);
    let kek: Buffer | null = null;
    let dek: Buffer | null = null;

    try {
      kek = await deriveKek(passphrase, salt);
      dek = randomBytesSecure(32);
      const sealed = aesGcmEncrypt(kek, dek, DEK_AAD);
      const row = {
        kdf_name: "argon2id",
        kdf_salt_b64: encodeSalt(salt),
        kdf_params_json: kdfParamsJson(),
        dek_nonce_b64: sealed.nonceB64,
        encrypted_dek_b64: sealed.ciphertextB64,
        dek_tag_b64: sealed.tagB64,
        created_at: this.clock.now().toISOString(),
        unlock_mode: "passphrase" as const,
        shamir_n: null,
        shamir_k: null,
      };

      this.repo.withImmediateTransaction(() => {
        if (this.repo.exists()) {
          throw new AppError("VAULT_ALREADY_INITIALIZED");
        }
        this.repo.insert(row);
      });

      this.audit.log({
        eventType: "VAULT_INIT",
        result: "SUCCESS",
      });
    } catch (err) {
      this.audit.log({
        eventType: "VAULT_INIT",
        result: "FAILURE",
        safeReasonCode: err instanceof AppError ? err.code : "ERROR",
      });
      throw err;
    } finally {
      zeroize(kek);
      zeroize(dek);
      zeroize(salt);
    }
  }

  async initShamir(n = 5, k = 3): Promise<string[]> {
    if (this.repo.exists()) {
      throw new AppError("VAULT_ALREADY_INITIALIZED");
    }

    const salt = randomBytesSecure(16);
    let rootKek: Buffer | null = null;
    let dek: Buffer | null = null;

    try {
      rootKek = randomBytesSecure(32);
      dek = randomBytesSecure(32);
      const sealed = aesGcmEncrypt(rootKek, dek, DEK_AAD);
      const shares = shamirSplit(rootKek, n, k);
      const encoded = shares.map(encodeShare);

      const row = {
        kdf_name: "shamir",
        kdf_salt_b64: toBase64(salt),
        kdf_params_json: JSON.stringify({ n, k }),
        dek_nonce_b64: sealed.nonceB64,
        encrypted_dek_b64: sealed.ciphertextB64,
        dek_tag_b64: sealed.tagB64,
        created_at: this.clock.now().toISOString(),
        unlock_mode: "shamir" as const,
        shamir_n: n,
        shamir_k: k,
      };

      this.repo.withImmediateTransaction(() => {
        if (this.repo.exists()) {
          throw new AppError("VAULT_ALREADY_INITIALIZED");
        }
        this.repo.insert(row);
      });

      this.audit.log({
        eventType: "VAULT_INIT",
        result: "SUCCESS",
      });

      return encoded;
    } catch (err) {
      this.audit.log({
        eventType: "VAULT_INIT",
        result: "FAILURE",
        safeReasonCode: err instanceof AppError ? err.code : "ERROR",
      });
      throw err;
    } finally {
      zeroize(rootKek);
      zeroize(dek);
      zeroize(salt);
    }
  }

  async unlock(passphrase: string): Promise<void> {
    validateMasterPassphrase(passphrase);
    const meta = this.repo.get();
    if (!meta) {
      throw new AppError("VAULT_NOT_INITIALIZED");
    }
    if (meta.unlock_mode === "shamir") {
      throw new AppError(
        "INVALID_INPUT",
        "Vault requires Shamir shares to unlock",
      );
    }

    const salt = decodeSalt(meta.kdf_salt_b64);
    let kek: Buffer | null = null;
    let dek: Buffer | null = null;

    try {
      kek = await deriveKek(passphrase, salt);
      dek = aesGcmDecrypt(
        kek,
        {
          nonceB64: meta.dek_nonce_b64,
          ciphertextB64: meta.encrypted_dek_b64,
          tagB64: meta.dek_tag_b64,
        },
        DEK_AAD,
      );
      this.state.setDek(dek);
      dek = null; // ownership transferred to state
      this.audit.log({
        eventType: "VAULT_UNLOCK",
        result: "SUCCESS",
      });
    } catch {
      this.audit.log({
        eventType: "VAULT_UNLOCK",
        result: "FAILURE",
        safeReasonCode: "INVALID_MASTER_PASSPHRASE",
      });
      throw new AppError("INVALID_MASTER_PASSPHRASE");
    } finally {
      zeroize(kek);
      zeroize(dek);
      zeroize(salt);
    }
  }

  async unlockWithShares(shareStrings: string[]): Promise<void> {
    const meta = this.repo.get();
    if (!meta) {
      throw new AppError("VAULT_NOT_INITIALIZED");
    }
    if (meta.unlock_mode !== "shamir") {
      throw new AppError(
        "INVALID_INPUT",
        "Vault requires Master Passphrase to unlock",
      );
    }

    let rootKek: Buffer | null = null;
    let dek: Buffer | null = null;

    try {
      if (!Array.isArray(shareStrings) || shareStrings.length < 2) {
        throw new AppError("INVALID_SHARE");
      }
      const shares = shareStrings.map((s) => decodeShare(s));
      rootKek = shamirCombine(shares);
      dek = aesGcmDecrypt(
        rootKek,
        {
          nonceB64: meta.dek_nonce_b64,
          ciphertextB64: meta.encrypted_dek_b64,
          tagB64: meta.dek_tag_b64,
        },
        DEK_AAD,
      );
      this.state.setDek(dek);
      dek = null;
      this.audit.log({
        eventType: "VAULT_UNLOCK",
        result: "SUCCESS",
      });
    } catch {
      this.audit.log({
        eventType: "VAULT_UNLOCK",
        result: "FAILURE",
        safeReasonCode: "INVALID_SHARE",
      });
      throw new AppError("INVALID_SHARE");
    } finally {
      zeroize(rootKek);
      zeroize(dek);
    }
  }

  async unlockLoop(
    provider: MasterPassphraseProvider,
    options?: { maxAttempts?: number; delayMs?: number },
  ): Promise<void> {
    const meta = this.repo.get();
    if (!meta) {
      throw new AppError("VAULT_NOT_INITIALIZED");
    }
    if (meta.unlock_mode === "shamir") {
      throw new AppError(
        "INVALID_INPUT",
        "Vault requires Shamir shares to unlock",
      );
    }

    const maxAttempts = options?.maxAttempts ?? Number.POSITIVE_INFINITY;
    const delayMs = options?.delayMs ?? 1000;
    let attempts = 0;

    while (attempts < maxAttempts && !this.state.isUnlocked()) {
      attempts += 1;
      try {
        const passphrase = await provider.requestPassphrase("Master Passphrase: ");
        await this.unlock(passphrase);
        return;
      } catch (err) {
        if (err instanceof AppError && err.code === "INVALID_MASTER_PASSPHRASE") {
          process.stderr.write("Invalid Master Passphrase. Try again.\n");
          await sleep(delayMs);
          continue;
        }
        throw err;
      }
    }
  }

  async unlockLoopShamir(
    shareProvider: ShareProvider,
    options?: { maxAttempts?: number; delayMs?: number },
  ): Promise<void> {
    const meta = this.repo.get();
    if (!meta) {
      throw new AppError("VAULT_NOT_INITIALIZED");
    }
    if (meta.unlock_mode !== "shamir" || meta.shamir_k == null) {
      throw new AppError(
        "INVALID_INPUT",
        "Vault is not in Shamir unlock mode",
      );
    }

    const k = meta.shamir_k;
    const maxAttempts = options?.maxAttempts ?? Number.POSITIVE_INFINITY;
    const delayMs = options?.delayMs ?? 1000;
    let attempts = 0;

    while (attempts < maxAttempts && !this.state.isUnlocked()) {
      attempts += 1;
      try {
        const shares = await shareProvider.requestShares(k);
        await this.unlockWithShares(shares);
        return;
      } catch (err) {
        if (err instanceof AppError && err.code === "INVALID_SHARE") {
          process.stderr.write("Invalid shares. Try again.\n");
          await sleep(delayMs);
          continue;
        }
        throw err;
      }
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
