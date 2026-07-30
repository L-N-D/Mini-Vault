import { AppError } from "../common/errors.js";
import { toBase64Url, fromBase64Url } from "../common/base64.js";
import { randomBytesSecure } from "./random.js";

/**
 * AES GF(256) multiply (poly 0x11b).
 * Russian-peasant / xtime form — no log tables.
 */
function gfMul(a: number, b: number): number {
  let p = 0;
  let aa = a & 0xff;
  let bb = b & 0xff;
  for (let i = 0; i < 8; i++) {
    if (bb & 1) p ^= aa;
    const hi = aa & 0x80;
    aa = (aa << 1) & 0xff;
    if (hi) aa ^= 0x1b;
    bb >>= 1;
  }
  return p;
}

/** Modular inverse via a^(254) since a^255 = 1 for a ≠ 0. */
function gfInv(a: number): number {
  if (a === 0) {
    throw new AppError("INVALID_SHARE", "GF inversion of zero");
  }
  // a^2, a^4, ... square-and-multiply for a^254 = a^(11111110_2)
  let b = a & 0xff;
  let result = 1;
  for (let i = 0; i < 7; i++) {
    b = gfMul(b, b);
    result = gfMul(result, b);
  }
  return result;
}

function gfDiv(a: number, b: number): number {
  if (b === 0) {
    throw new AppError("INVALID_SHARE", "GF division by zero");
  }
  if (a === 0) return 0;
  return gfMul(a, gfInv(b));
}

function evalPoly(coeffs: number[], x: number): number {
  let y = 0;
  for (let i = coeffs.length - 1; i >= 0; i--) {
    y = gfMul(y, x) ^ coeffs[i]!;
  }
  return y;
}

/** Lagrange interpolate f(0) given points (xs[i], ys[i]) over GF(256). */
function interpolateAtZero(xs: number[], ys: number[]): number {
  let secret = 0;
  for (let j = 0; j < xs.length; j++) {
    let num = 1;
    let den = 1;
    for (let m = 0; m < xs.length; m++) {
      if (m === j) continue;
      // (0 - x_m) = x_m under XOR
      num = gfMul(num, xs[m]!);
      den = gfMul(den, xs[j]! ^ xs[m]!);
    }
    secret ^= gfMul(ys[j]!, gfDiv(num, den));
  }
  return secret;
}

export interface ShamirShare {
  index: number;
  share: Buffer;
}

export function split(secret: Buffer, n: number, k: number): ShamirShare[] {
  if (!Buffer.isBuffer(secret) || secret.length === 0) {
    throw new AppError("INVALID_INPUT", "Secret must be a non-empty Buffer");
  }
  if (!Number.isInteger(n) || !Number.isInteger(k) || k < 2 || n < k || n > 255) {
    throw new AppError("INVALID_INPUT", "Invalid Shamir parameters n/k");
  }

  const out: ShamirShare[] = [];
  for (let i = 1; i <= n; i++) {
    out.push({ index: i, share: Buffer.alloc(secret.length) });
  }

  for (let byteIdx = 0; byteIdx < secret.length; byteIdx++) {
    const coeffs = new Array<number>(k);
    coeffs[0] = secret[byteIdx]!;
    const random = randomBytesSecure(k - 1);
    for (let c = 1; c < k; c++) {
      // Leading / higher coeffs must be non-zero for full degree when possible
      let v = random[c - 1]!;
      if (c === k - 1 && v === 0) {
        v = 1;
      }
      coeffs[c] = v;
    }
    for (let i = 0; i < n; i++) {
      const x = i + 1;
      out[i]!.share[byteIdx] = evalPoly(coeffs, x);
    }
  }

  return out;
}

export function combine(shares: ShamirShare[]): Buffer {
  if (!Array.isArray(shares) || shares.length < 2) {
    throw new AppError("INSUFFICIENT_SHARES");
  }

  const seen = new Set<number>();
  let shareLen = -1;
  for (const s of shares) {
    if (
      !s ||
      !Number.isInteger(s.index) ||
      s.index < 1 ||
      s.index > 255 ||
      !Buffer.isBuffer(s.share) ||
      s.share.length === 0
    ) {
      throw new AppError("INVALID_SHARE");
    }
    if (seen.has(s.index)) {
      throw new AppError("INVALID_SHARE", "Duplicate share index");
    }
    seen.add(s.index);
    if (shareLen < 0) {
      shareLen = s.share.length;
    } else if (s.share.length !== shareLen) {
      throw new AppError("INVALID_SHARE", "Mismatched share lengths");
    }
  }

  const xs = shares.map((s) => s.index);
  const secret = Buffer.alloc(shareLen);
  for (let byteIdx = 0; byteIdx < shareLen; byteIdx++) {
    const ys = shares.map((s) => s.share[byteIdx]!);
    secret[byteIdx] = interpolateAtZero(xs, ys);
  }
  return secret;
}

/** CLI display form: base64url(indexByte || shareBytes). */
export function encodeShare(share: ShamirShare): string {
  if (
    !Number.isInteger(share.index) ||
    share.index < 1 ||
    share.index > 255 ||
    !Buffer.isBuffer(share.share) ||
    share.share.length === 0
  ) {
    throw new AppError("INVALID_SHARE");
  }
  const packed = Buffer.alloc(1 + share.share.length);
  packed[0] = share.index;
  share.share.copy(packed, 1);
  return toBase64Url(packed);
}

export function decodeShare(encoded: string): ShamirShare {
  let packed: Buffer;
  try {
    packed = fromBase64Url(encoded, "share");
  } catch {
    throw new AppError("INVALID_SHARE");
  }
  if (packed.length < 2) {
    throw new AppError("INVALID_SHARE");
  }
  const index = packed[0]!;
  if (index < 1) {
    throw new AppError("INVALID_SHARE");
  }
  return { index, share: Buffer.from(packed.subarray(1)) };
}
