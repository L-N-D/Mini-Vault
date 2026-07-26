import * as argon2 from "argon2";
import { toBase64, fromBase64 } from "../common/base64.js";
import { randomBytesSecure } from "./random.js";
import { zeroize } from "./zeroize.js";

export const ARGON2_PARAMS = {
  type: argon2.argon2id,
  memoryCost: 65536, // 64 MiB
  timeCost: 3,
  parallelism: 1,
  hashLength: 32,
} as const;

export async function deriveKek(
  passphrase: string,
  salt: Buffer,
): Promise<Buffer> {
  const hash = await argon2.hash(passphrase, {
    ...ARGON2_PARAMS,
    salt,
    raw: true,
  });
  return Buffer.from(hash);
}

export async function hashPassword(passphrase: string): Promise<string> {
  return argon2.hash(passphrase, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 1,
  });
}

export async function verifyPassword(
  hash: string,
  passphrase: string,
): Promise<boolean> {
  try {
    return await argon2.verify(hash, passphrase);
  } catch {
    return false;
  }
}

/** Dummy verify to reduce timing difference for unknown emails. */
export async function dummyPasswordVerify(passphrase: string): Promise<void> {
  const salt = randomBytesSecure(16);
  let kek: Buffer | null = null;
  try {
    kek = await deriveKek(passphrase, salt);
  } finally {
    zeroize(kek);
    zeroize(salt);
  }
}

export function encodeSalt(salt: Buffer): string {
  return toBase64(salt);
}

export function decodeSalt(saltB64: string): Buffer {
  return fromBase64(saltB64, "kdf_salt");
}

export function kdfParamsJson(): string {
  return JSON.stringify({
    memoryCost: ARGON2_PARAMS.memoryCost,
    timeCost: ARGON2_PARAMS.timeCost,
    parallelism: ARGON2_PARAMS.parallelism,
    hashLength: ARGON2_PARAMS.hashLength,
    type: "argon2id",
  });
}
