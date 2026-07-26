import type { Db } from "../storage/database.js";

export interface UserRow {
  email: string;
  password_hash: string;
  failed_attempts: number;
  locked_until: string | null;
  created_at: string;
  updated_at: string;
}

export interface SessionRow {
  id: string;
  token_hash: string;
  user_email: string;
  expires_at: string;
  revoked_at: string | null;
  created_at: string;
}

export class AuthRepository {
  constructor(private readonly db: Db) {}

  findUser(email: string): UserRow | null {
    return (
      (this.db
        .prepare(
          `SELECT email, password_hash, failed_attempts, locked_until, created_at, updated_at
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
