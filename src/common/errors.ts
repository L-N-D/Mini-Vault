export type ErrorCode =
  | "VAULT_NOT_INITIALIZED"
  | "VAULT_ALREADY_INITIALIZED"
  | "VAULT_LOCKED"
  | "INVALID_MASTER_PASSPHRASE"
  | "EMAIL_ALREADY_EXISTS"
  | "INVALID_CREDENTIALS"
  | "ACCOUNT_LOCKED"
  | "UNAUTHENTICATED"
  | "SESSION_EXPIRED"
  | "NOT_FOUND"
  | "PERMISSION_DENIED"
  | "AUTHORIZATION_NOT_IMPLEMENTED"
  | "KEY_NAME_UNAVAILABLE"
  | "KEY_NOT_FOUND"
  | "INVALID_KEY_USAGE"
  | "INVALID_SIGNING_ALGORITHM"
  | "INVALID_CIPHERTEXT"
  | "INTEGRITY_CHECK_FAILED"
  | "INVALID_MESSAGE_TYPE"
  | "INVALID_DIGEST_LENGTH"
  | "INVALID_BASE64"
  | "REQUEST_TOO_LARGE"
  | "INVALID_INPUT";

export class AppError extends Error {
  readonly code: ErrorCode;
  readonly httpStatus: number;

  constructor(code: ErrorCode, message?: string, httpStatus?: number) {
    super(message ?? code);
    this.name = "AppError";
    this.code = code;
    this.httpStatus = httpStatus ?? defaultStatus(code);
  }
}

function defaultStatus(code: ErrorCode): number {
  switch (code) {
    case "UNAUTHENTICATED":
    case "SESSION_EXPIRED":
    case "INVALID_CREDENTIALS":
    case "INVALID_MASTER_PASSPHRASE":
      return 401;
    case "PERMISSION_DENIED":
    case "ACCOUNT_LOCKED":
    case "AUTHORIZATION_NOT_IMPLEMENTED":
      return 403;
    case "NOT_FOUND":
    case "KEY_NOT_FOUND":
      return 404;
    case "VAULT_LOCKED":
    case "VAULT_NOT_INITIALIZED":
    case "VAULT_ALREADY_INITIALIZED":
    case "EMAIL_ALREADY_EXISTS":
    case "KEY_NAME_UNAVAILABLE":
    case "INVALID_KEY_USAGE":
    case "INVALID_SIGNING_ALGORITHM":
    case "INVALID_CIPHERTEXT":
    case "INTEGRITY_CHECK_FAILED":
    case "INVALID_MESSAGE_TYPE":
    case "INVALID_DIGEST_LENGTH":
    case "INVALID_BASE64":
    case "INVALID_INPUT":
      return 400;
    case "REQUEST_TOO_LARGE":
      return 413;
    default: {
      const _exhaustive: never = code;
      return _exhaustive;
    }
  }
}
