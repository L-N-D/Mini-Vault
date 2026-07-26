import { AppError } from "./errors.js";

const MAX_PATH_LENGTH = 512;

/**
 * Validates a logical KV path. Does NOT rewrite input.
 * Returns the same string if already canonical; otherwise throws INVALID_INPUT.
 */
export function validateAndReturnCanonicalSecretPath(
  path: string,
  expectedEmail?: string,
): string {
  if (typeof path !== "string") {
    throw new AppError("INVALID_INPUT", "Path must be a string");
  }
  if (path.length === 0 || path.length > MAX_PATH_LENGTH) {
    throw new AppError("INVALID_INPUT", "Path length invalid");
  }
  if (path.includes("\0") || path.includes("\\")) {
    throw new AppError("INVALID_INPUT", "Path contains forbidden characters");
  }
  if (!path.startsWith("secret/")) {
    throw new AppError("INVALID_INPUT", "Path must start with secret/");
  }
  if (path.includes("//")) {
    throw new AppError("INVALID_INPUT", "Path must not contain empty segments");
  }

  const parts = path.split("/");
  // secret / email / ...segments
  if (parts.length < 3) {
    throw new AppError("INVALID_INPUT", "Path must include email and at least one segment");
  }
  if (parts[0] !== "secret") {
    throw new AppError("INVALID_INPUT", "Path must start with secret/");
  }

  const email = parts[1]!;
  if (email.length === 0 || email !== email.toLowerCase()) {
    throw new AppError("INVALID_INPUT", "Path email must be lowercase");
  }
  if (!email.includes("@")) {
    throw new AppError("INVALID_INPUT", "Path email invalid");
  }

  const segments = parts.slice(2);
  if (segments.length === 0) {
    throw new AppError("INVALID_INPUT", "Path needs at least one segment after email");
  }
  for (const seg of segments) {
    if (seg.length === 0 || seg === "." || seg === "..") {
      throw new AppError("INVALID_INPUT", "Path segment invalid");
    }
  }

  if (expectedEmail !== undefined && email !== expectedEmail.toLowerCase()) {
    // Structural check only when expectedEmail provided at validation layer;
    // ownership ACL still enforced separately via authorization port.
    throw new AppError("INVALID_INPUT", "Path email must match session email format rules");
  }

  // Return exact input — no rewriting
  return path;
}

export function emailFromSecretPath(path: string): string {
  const canonical = validateAndReturnCanonicalSecretPath(path);
  return canonical.split("/")[1]!;
}
