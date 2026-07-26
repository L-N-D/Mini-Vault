import { createCipheriv, createDecipheriv } from "node:crypto";
import { AppError } from "../common/errors.js";
import { toBase64, fromBase64 } from "../common/base64.js";
import { randomBytesSecure } from "./random.js";

const NONCE_LEN = 12;
const TAG_LEN = 16;

export interface AesGcmSealed {
  nonceB64: string;
  ciphertextB64: string;
  tagB64: string;
}

export function aesGcmEncrypt(
  key: Buffer,
  plaintext: Buffer,
  aad: string | Buffer,
): AesGcmSealed {
  if (key.length !== 32) {
    throw new AppError("INVALID_INPUT", "AES key must be 32 bytes");
  }
  const nonce = randomBytesSecure(NONCE_LEN);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const aadBuf = typeof aad === "string" ? Buffer.from(aad, "utf8") : aad;
  cipher.setAAD(aadBuf);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    nonceB64: toBase64(nonce),
    ciphertextB64: toBase64(ciphertext),
    tagB64: toBase64(tag),
  };
}

export function aesGcmDecrypt(
  key: Buffer,
  sealed: AesGcmSealed,
  aad: string | Buffer,
): Buffer {
  if (key.length !== 32) {
    throw new AppError("INVALID_INPUT", "AES key must be 32 bytes");
  }
  try {
    const nonce = fromBase64(sealed.nonceB64, "nonce");
    const ciphertext = fromBase64(sealed.ciphertextB64, "ciphertext");
    const tag = fromBase64(sealed.tagB64, "tag");
    if (nonce.length !== NONCE_LEN || tag.length !== TAG_LEN) {
      throw new AppError("INTEGRITY_CHECK_FAILED");
    }
    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    const aadBuf = typeof aad === "string" ? Buffer.from(aad, "utf8") : aad;
    decipher.setAAD(aadBuf);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    if (err instanceof AppError) throw err;
    throw new AppError("INTEGRITY_CHECK_FAILED", "Ciphertext authentication failed");
  }
}
