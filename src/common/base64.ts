import { AppError } from "./errors.js";

const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;
const BASE64URL_RE = /^[A-Za-z0-9_-]*$/;

export function toBase64(buf: Buffer): string {
  return buf.toString("base64");
}

export function toBase64Url(buf: Buffer): string {
  return buf.toString("base64url");
}

export function fromBase64(value: string, label = "value"): Buffer {
  if (typeof value !== "string" || value.length === 0 || !BASE64_RE.test(value)) {
    throw new AppError("INVALID_BASE64", `Invalid base64: ${label}`);
  }
  if (value.length % 4 !== 0) {
    throw new AppError("INVALID_BASE64", `Invalid base64 padding: ${label}`);
  }
  const buf = Buffer.from(value, "base64");
  if (toBase64(buf) !== value) {
    throw new AppError("INVALID_BASE64", `Non-canonical base64: ${label}`);
  }
  return buf;
}

export function fromBase64Url(value: string, label = "value"): Buffer {
  if (typeof value !== "string" || value.length === 0 || !BASE64URL_RE.test(value)) {
    throw new AppError("INVALID_BASE64", `Invalid base64url: ${label}`);
  }
  const buf = Buffer.from(value, "base64url");
  if (toBase64Url(buf) !== value) {
    throw new AppError("INVALID_BASE64", `Non-canonical base64url: ${label}`);
  }
  return buf;
}
