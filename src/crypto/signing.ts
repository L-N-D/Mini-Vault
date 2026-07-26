import {
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  createPrivateKey,
  createPublicKey,
} from "node:crypto";
import { AppError } from "../common/errors.js";
import { sha256 } from "./hashing.js";
import { zeroize } from "./zeroize.js";

export const SIGNING_ALGORITHM = "ED25519" as const;
export type SigningAlgorithm = typeof SIGNING_ALGORITHM;

export interface Ed25519KeyPair {
  privateKeyDer: Buffer;
  publicKeyDer: Buffer;
}

export function generateEd25519KeyPair(): Ed25519KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKeyDer: Buffer.from(privateKey.export({ type: "pkcs8", format: "der" })),
    publicKeyDer: Buffer.from(publicKey.export({ type: "spki", format: "der" })),
  };
}

export type MessageType = "RAW" | "DIGEST";

export function resolveDigest(
  message: Buffer,
  messageType: MessageType,
): Buffer {
  if (messageType === "RAW") {
    return sha256(message);
  }
  if (messageType === "DIGEST") {
    if (message.length !== 32) {
      throw new AppError(
        "INVALID_DIGEST_LENGTH",
        "DIGEST message_type requires exactly 32 bytes",
      );
    }
    return message;
  }
  const _exhaustive: never = messageType;
  return _exhaustive;
}

export function ed25519Sign(privateKeyDer: Buffer, digest32: Buffer): Buffer {
  if (digest32.length !== 32) {
    throw new AppError("INVALID_DIGEST_LENGTH");
  }
  const keyObject = createPrivateKey({
    key: privateKeyDer,
    format: "der",
    type: "pkcs8",
  });
  try {
    return cryptoSign(null, digest32, keyObject);
  } finally {
    // KeyObject cannot be zeroized; caller zeroizes DER buffer.
  }
}

export function ed25519Verify(
  publicKeyDer: Buffer,
  digest32: Buffer,
  signature: Buffer,
): boolean {
  if (digest32.length !== 32) {
    throw new AppError("INVALID_DIGEST_LENGTH");
  }
  try {
    const keyObject = createPublicKey({
      key: publicKeyDer,
      format: "der",
      type: "spki",
    });
    return cryptoVerify(null, digest32, keyObject, signature);
  } catch {
    return false;
  }
}

export function withPrivateKeyDer<T>(
  der: Buffer,
  fn: (der: Buffer) => T,
): T {
  try {
    return fn(der);
  } finally {
    zeroize(der);
  }
}
