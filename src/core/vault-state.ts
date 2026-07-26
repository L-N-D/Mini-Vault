import { zeroize } from "../crypto/zeroize.js";

export type VaultRuntimeStatus = "LOCKED" | "UNLOCKED";

export class VaultState {
  private dek: Buffer | null = null;

  get status(): VaultRuntimeStatus {
    return this.dek ? "UNLOCKED" : "LOCKED";
  }

  isUnlocked(): boolean {
    return this.dek !== null;
  }

  /** Caller must not retain the returned buffer beyond the operation. Prefer withDek. */
  getDekOrThrow(): Buffer {
    if (!this.dek) {
      throw new Error("VAULT_LOCKED");
    }
    return this.dek;
  }

  withDek<T>(fn: (dek: Buffer) => T): T {
    if (!this.dek) {
      throw new Error("VAULT_LOCKED");
    }
    return fn(this.dek);
  }

  setDek(dek: Buffer): void {
    if (this.dek) {
      zeroize(this.dek);
    }
    this.dek = dek;
  }

  clear(): void {
    zeroize(this.dek);
    this.dek = null;
  }
}
