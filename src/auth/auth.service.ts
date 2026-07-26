import { randomUUID } from "node:crypto";
import { AppError } from "../common/errors.js";
import type { Clock } from "../common/clock.js";
import {
  hashPassword,
  verifyPassword,
  dummyPasswordVerify,
} from "../crypto/argon2.js";
import { sha256 } from "../crypto/hashing.js";
import { randomBytesSecure } from "../crypto/random.js";
import { toBase64Url } from "../common/base64.js";
import type { AuthRepository } from "./auth.repository.js";
import type { AuditService } from "../audit/audit.service.js";

const SESSION_TTL_MS = 30 * 60 * 1000;
const LOCKOUT_MS = 5 * 60 * 1000;
const MAX_FAILED = 5;
const MIN_PASS = 12;
const MAX_PASS = 256;

export interface SessionInfo {
  sessionId: string;
  email: string;
  token: string;
  expiresAt: string;
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function validatePassphrase(passphrase: string, confirm?: string): void {
  if (
    typeof passphrase !== "string" ||
    passphrase.length < MIN_PASS ||
    passphrase.length > MAX_PASS ||
    passphrase.trim().length === 0
  ) {
    throw new AppError("INVALID_INPUT", "Passphrase does not meet policy");
  }
  if (confirm !== undefined && passphrase !== confirm) {
    throw new AppError("INVALID_INPUT", "Passphrase confirmation does not match");
  }
}

export class AuthService {
  constructor(
    private readonly repo: AuthRepository,
    private readonly clock: Clock,
    private readonly audit: AuditService,
  ) {}

  async register(
    emailRaw: string,
    passphrase: string,
    confirm: string,
  ): Promise<{ email: string }> {
    const email = normalizeEmail(emailRaw);
    if (!email.includes("@") || email.length > 254) {
      throw new AppError("INVALID_INPUT", "Invalid email");
    }
    validatePassphrase(passphrase, confirm);

    if (this.repo.findUser(email)) {
      throw new AppError("EMAIL_ALREADY_EXISTS");
    }

    const passwordHash = await hashPassword(passphrase);
    const now = this.clock.now().toISOString();
    try {
      this.repo.createUser(email, passwordHash, now);
    } catch {
      throw new AppError("EMAIL_ALREADY_EXISTS");
    }
    return { email };
  }

  async login(emailRaw: string, passphrase: string): Promise<SessionInfo> {
    const email = normalizeEmail(emailRaw);
    validatePassphrase(passphrase);

    const user = this.repo.findUser(email);
    const now = this.clock.now();

    if (!user) {
      await dummyPasswordVerify(passphrase);
      this.audit.log({
        eventType: "LOGIN",
        requesterEmail: email,
        result: "FAILURE",
        safeReasonCode: "INVALID_CREDENTIALS",
      });
      throw new AppError("INVALID_CREDENTIALS");
    }

    if (user.locked_until) {
      const lockedUntil = new Date(user.locked_until);
      if (lockedUntil.getTime() > now.getTime()) {
        throw new AppError("ACCOUNT_LOCKED");
      }
    }

    const ok = await verifyPassword(user.password_hash, passphrase);

    return this.repo.withTransaction(() => {
      const fresh = this.repo.findUser(email);
      if (!fresh) {
        throw new AppError("INVALID_CREDENTIALS");
      }
      const t = this.clock.now();
      const tIso = t.toISOString();

      if (fresh.locked_until && new Date(fresh.locked_until).getTime() > t.getTime()) {
        throw new AppError("ACCOUNT_LOCKED");
      }

      if (!ok) {
        const attempts = fresh.failed_attempts + 1;
        const lockedUntil =
          attempts >= MAX_FAILED
            ? new Date(t.getTime() + LOCKOUT_MS).toISOString()
            : null;
        this.repo.updateLoginFailure(email, attempts, lockedUntil, tIso);
        this.audit.log({
          eventType: "LOGIN",
          requesterEmail: email,
          result: "FAILURE",
          safeReasonCode: "INVALID_CREDENTIALS",
        });
        throw new AppError("INVALID_CREDENTIALS");
      }

      this.repo.resetLoginSuccess(email, tIso);
      const tokenBuf = randomBytesSecure(32);
      const token = toBase64Url(tokenBuf);
      const tokenHash = sha256(token).toString("hex");
      const sessionId = randomUUID();
      const expiresAt = new Date(t.getTime() + SESSION_TTL_MS).toISOString();
      this.repo.createSession({
        id: sessionId,
        token_hash: tokenHash,
        user_email: email,
        expires_at: expiresAt,
        revoked_at: null,
        created_at: tIso,
      });
      this.audit.log({
        eventType: "LOGIN",
        requesterEmail: email,
        result: "SUCCESS",
      });
      return {
        sessionId,
        email,
        token,
        expiresAt,
      };
    });
  }

  authenticate(bearerToken: string | undefined): { email: string; sessionId: string } {
    if (!bearerToken) {
      throw new AppError("UNAUTHENTICATED");
    }
    const tokenHash = sha256(bearerToken).toString("hex");
    const session = this.repo.findSessionByTokenHash(tokenHash);
    if (!session) {
      throw new AppError("UNAUTHENTICATED");
    }
    if (session.revoked_at) {
      throw new AppError("UNAUTHENTICATED");
    }
    if (new Date(session.expires_at).getTime() <= this.clock.now().getTime()) {
      throw new AppError("SESSION_EXPIRED");
    }
    return { email: session.user_email, sessionId: session.id };
  }

  logout(bearerToken: string | undefined): void {
    const { sessionId, email } = this.authenticate(bearerToken);
    this.repo.revokeSession(sessionId, this.clock.now().toISOString());
    this.audit.log({
      eventType: "LOGOUT",
      requesterEmail: email,
      result: "SUCCESS",
    });
  }
}
