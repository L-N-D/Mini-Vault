import { AppError } from "../common/errors.js";
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
import type { VaultRepository } from "./vault.repository.js";
import type { VaultState } from "./vault-state.js";
import type { MasterPassphraseProvider } from "./master-passphrase-provider.js";
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

  async unlock(passphrase: string): Promise<void> {
    validateMasterPassphrase(passphrase);
    const meta = this.repo.get();
    if (!meta) {
      throw new AppError("VAULT_NOT_INITIALIZED");
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

  async unlockLoop(
    provider: MasterPassphraseProvider,
    options?: { maxAttempts?: number; delayMs?: number },
  ): Promise<void> {
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
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
