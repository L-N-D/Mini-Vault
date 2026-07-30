import type { Db } from "../storage/database.js";

export interface UserRow {
  email: string;
  password_hash: string;
  failed_attempts: number;
  locked_until: string | null;
  created_at: string;
  updated_at: string;
  totp_enabled: number;
  totp_salt_b64: string | null;
  totp_secret_nonce_b64: string | null;
  totp_secret_ct_b64: string | null;
  totp_secret_tag_b64: string | null;
  totp_pending_secret_b64: string | null;
}

export interface SessionRow {
  id: string;
  token_hash: string;
  user_email: string;
  expires_at: string;
  revoked_at: string | null;
  created_at: string;
}

export interface MfaChallengeRow {
  token_hash: string;
  user_email: string;
  expires_at: string;
  created_at: string;
}

const USER_SELECT = `email, password_hash, failed_attempts, locked_until, created_at, updated_at,
           totp_enabled, totp_salt_b64, totp_secret_nonce_b64, totp_secret_ct_b64,
           totp_secret_tag_b64, totp_pending_secret_b64`;

export class AuthRepository {
  constructor(private readonly db: Db) {}

  findUser(email: string): UserRow | null {
    return (
      (this.db
        .prepare(
          `SELECT ${USER_SELECT}
           FROM users WHERE email = ?`,
        )
        .get(email) as UserRow | undefined) ?? null
    );
  }

  createUser(email: string, passwordHash: string, nowIso: string): void {
    this.db
      .prepare(
        `INSERT INTO users (email, password_hash, failed_attempts, locked_until, created_at, updated_at)
         VALUES (?, ?, 0, NULL, ?, ?)`,
      )
      .run(email, passwordHash, nowIso, nowIso);
  }

  withTransaction<T>(fn: () => T): T {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = fn();
      this.db.exec("COMMIT");
      return result;
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  updateLoginFailure(
    email: string,
    failedAttempts: number,
    lockedUntil: string | null,
    nowIso: string,
  ): void {
    this.db
      .prepare(
        `UPDATE users SET failed_attempts = ?, locked_until = ?, updated_at = ? WHERE email = ?`,
      )
      .run(failedAttempts, lockedUntil, nowIso, email);
  }

  resetLoginSuccess(email: string, nowIso: string): void {
    this.db
      .prepare(
        `UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE email = ?`,
      )
      .run(nowIso, email);
  }

  setTotpPending(email: string, pendingSecretB64: string, nowIso: string): void {
    this.db
      .prepare(
        `UPDATE users SET totp_pending_secret_b64 = ?, updated_at = ? WHERE email = ?`,
      )
      .run(pendingSecretB64, nowIso, email);
  }

  clearTotpPending(email: string, nowIso: string): void {
    this.db
      .prepare(
        `UPDATE users SET totp_pending_secret_b64 = NULL, updated_at = ? WHERE email = ?`,
      )
      .run(nowIso, email);
  }

  enableTotp(
    email: string,
    sealed: {
      saltB64: string;
      nonceB64: string;
      ciphertextB64: string;
      tagB64: string;
    },
    nowIso: string,
  ): void {
    this.db
      .prepare(
        `UPDATE users SET
           totp_enabled = 1,
           totp_salt_b64 = ?,
           totp_secret_nonce_b64 = ?,
           totp_secret_ct_b64 = ?,
           totp_secret_tag_b64 = ?,
           totp_pending_secret_b64 = NULL,
           updated_at = ?
         WHERE email = ?`,
      )
      .run(
        sealed.saltB64,
        sealed.nonceB64,
        sealed.ciphertextB64,
        sealed.tagB64,
        nowIso,
        email,
      );
  }

  disableTotp(email: string, nowIso: string): void {
    this.db
      .prepare(
        `UPDATE users SET
           totp_enabled = 0,
           totp_salt_b64 = NULL,
           totp_secret_nonce_b64 = NULL,
           totp_secret_ct_b64 = NULL,
           totp_secret_tag_b64 = NULL,
           totp_pending_secret_b64 = NULL,
           updated_at = ?
         WHERE email = ?`,
      )
      .run(nowIso, email);
  }

  createMfaChallenge(row: MfaChallengeRow): void {
    this.db
      .prepare(
        `INSERT INTO mfa_challenges (token_hash, user_email, expires_at, created_at)
         VALUES (?, ?, ?, ?)`,
      )
      .run(row.token_hash, row.user_email, row.expires_at, row.created_at);
  }

  findMfaChallenge(tokenHash: string): MfaChallengeRow | null {
    return (
      (this.db
        .prepare(
          `SELECT token_hash, user_email, expires_at, created_at
           FROM mfa_challenges WHERE token_hash = ?`,
        )
        .get(tokenHash) as MfaChallengeRow | undefined) ?? null
    );
  }

  deleteMfaChallenge(tokenHash: string): void {
    this.db
      .prepare(`DELETE FROM mfa_challenges WHERE token_hash = ?`)
      .run(tokenHash);
  }

  createSession(row: SessionRow): void {
    this.db
      .prepare(
        `INSERT INTO sessions (id, token_hash, user_email, expires_at, revoked_at, created_at)
         VALUES (?, ?, ?, ?, NULL, ?)`,
      )
      .run(row.id, row.token_hash, row.user_email, row.expires_at, row.created_at);
  }

  findSessionByTokenHash(tokenHash: string): SessionRow | null {
    return (
      (this.db
        .prepare(
          `SELECT id, token_hash, user_email, expires_at, revoked_at, created_at
           FROM sessions WHERE token_hash = ?`,
        )
        .get(tokenHash) as SessionRow | undefined) ?? null
    );
  }

  revokeSession(id: string, nowIso: string): void {
    this.db
      .prepare(`UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`)
      .run(nowIso, id);
  }
}
