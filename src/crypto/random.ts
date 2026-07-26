import { randomBytes } from "node:crypto";

export function randomBytesSecure(size: number): Buffer {
  return randomBytes(size);
}
