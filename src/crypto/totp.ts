import { createHmac, timingSafeEqual } from "node:crypto";
import { randomBytesSecure } from "./random.js";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEP_SECONDS = 30;
const DIGITS = 6;
const SECRET_BYTES = 20;

export function encodeBase32(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31]!;
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31]!;
  }
  return output;
}

export function decodeBase32(input: string): Buffer {
  const cleaned = input.replace(/=+$/, "").toUpperCase().replace(/\s+/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx < 0) {
      throw new Error("Invalid base32");
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function hotp(secret: Buffer, counter: number): string {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac("sha1", secret).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const code =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff);
  const otp = (code % 10 ** DIGITS).toString().padStart(DIGITS, "0");
  return otp;
}

export function generateTotpSecret(): {
  secretBytes: Buffer;
  secretBase32: string;
  otpauthUrl: (email: string, issuer: string) => string;
} {
  const secretBytes = randomBytesSecure(SECRET_BYTES);
  const secretBase32 = encodeBase32(secretBytes);
  return {
    secretBytes,
    secretBase32,
    otpauthUrl(email: string, issuer: string): string {
      const label = encodeURIComponent(`${issuer}:${email}`);
      const iss = encodeURIComponent(issuer);
      return `otpauth://totp/${label}?secret=${secretBase32}&issuer=${iss}&algorithm=SHA1&digits=${DIGITS}&period=${STEP_SECONDS}`;
    },
  };
}

export function generateTotpCode(secretBytes: Buffer): string {
  const counter = Math.floor(Date.now() / 1000 / STEP_SECONDS);
  return hotp(secretBytes, counter);
}

export function verifyTotpCode(
  secretBytes: Buffer,
  code: string,
  window = 1,
): boolean {
  if (typeof code !== "string" || !/^\d{6}$/.test(code)) {
    return false;
  }
  const counter = Math.floor(Date.now() / 1000 / STEP_SECONDS);
  const expected = Buffer.from(code, "utf8");
  for (let w = -window; w <= window; w++) {
    const candidate = Buffer.from(hotp(secretBytes, counter + w), "utf8");
    if (
      candidate.length === expected.length &&
      timingSafeEqual(candidate, expected)
    ) {
      return true;
    }
  }
  return false;
}

export function decodeTotpSecretBase32(secretBase32: string): Buffer {
  return decodeBase32(secretBase32);
}
