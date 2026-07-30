import { aesGcmDecrypt } from "../crypto/aes-gcm.js";
import type { VaultState } from "../core/vault-state.js";
import type { EncryptedMaterial } from "./transit.repository.js";

export function unwrapNamedKeyMaterial(
  vaultState: VaultState,
  material: EncryptedMaterial,
  ownerEmail: string,
  keyName: string,
  keyUsage: "ENCRYPT_DECRYPT" | "SIGN_VERIFY",
  version: number,
): Buffer {
  const sealed = {
    nonceB64: material.nonceB64,
    ciphertextB64: material.ciphertextB64,
    tagB64: material.tagB64,
  };

  const candidates = [
    `transit-key:${ownerEmail}:${keyName}:${keyUsage}:kv${version}`,
  ];
  if (version === 1) {
    candidates.push(
      `transit-key:${ownerEmail}:${keyName}:${keyUsage}:v1`,
    );
  }

  let lastError: unknown;
  for (const aad of candidates) {
    try {
      return vaultState.withDek((dek) => aesGcmDecrypt(dek, sealed, aad));
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError;
}
