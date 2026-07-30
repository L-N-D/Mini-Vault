import { randomUUID } from "node:crypto";
import { AppError } from "../common/errors.js";
import type { Clock } from "../common/clock.js";
import {
  hashPassword,
  verifyPassword,
  dummyPasswordVerify,
  deriveKek,
  encodeSalt,
  decodeSalt,
} from "../crypto/argon2.js";
import { aesGcmEncrypt, aesGcmDecrypt } from "../crypto/aes-gcm.js";
import { sha256 } from "../crypto/hashing.js";
import { randomBytesSecure } from "../crypto/random.js";
import { generateTotpSecret, verifyTotpCode } from "../crypto/totp.js";
import { zeroize } from "../crypto/zeroize.js";
import { toBase64, toBase64Url, fromBase64 } from "../common/base64.js";
import type { AuthRepository } from "./auth.repository.js";
import type { AuditService } from "../audit/audit.service.js";

const SESSION_TTL_MS = 30 * 60 * 1000;
const MFA_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const LOCKOUT_MS = 5 * 60 * 1000;
const MAX_FAILED = 5;
const MIN_PASS = 12;
const MAX_PASS = 256;
const TOTP_AAD = "totp-secret:v1";
const TOTP_ISSUER = "Mini Vault";

export interface SessionInfo {
  sessionId: string;
  email: string;
  token: string;
  expiresAt: string;
}

export interface MfaRequiredResult {
  mfa_required: true;
  mfa_token: string;
  email: string;
}

export type LoginResult = SessionInfo | MfaRequiredResult;

export function isMfaRequiredResult(
  result: LoginResult,
): result is MfaRequiredResult {
  return "mfa_required" in result && result.mfa_required === true;
}

export function requireSessionInfo(result: LoginResult): SessionInfo {
  if (isMfaRequiredResult(result)) {
    throw new AppError("MFA_REQUIRED");
  }
  return result;
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

function validateTotpCode(code: string): void {
  if (typeof code !== "string" || !/^\d{6}$/.test(code)) {
    throw new AppError("INVALID_MFA_CODE");
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

  async login(emailRaw: string, passphrase: string): Promise<LoginResult> {
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

    // Failure path must NOT throw inside a transaction — that rolled back lockout.
    if (!ok) {
      const fresh = this.repo.findUser(email);
      if (!fresh) {
        throw new AppError("INVALID_CREDENTIALS");
      }
      const t = this.clock.now();
      const tIso = t.toISOString();
      if (fresh.locked_until && new Date(fresh.locked_until).getTime() > t.getTime()) {
        throw new AppError("ACCOUNT_LOCKED");
      }
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

      this.repo.resetLoginSuccess(email, tIso);

      if (fresh.totp_enabled === 1) {
        const tokenBuf = randomBytesSecure(32);
        const mfaToken = toBase64Url(tokenBuf);
        const tokenHash = sha256(mfaToken).toString("hex");
        const expiresAt = new Date(
          t.getTime() + MFA_CHALLENGE_TTL_MS,
        ).toISOString();
        this.repo.createMfaChallenge({
          token_hash: tokenHash,
          user_email: email,
          expires_at: expiresAt,
          created_at: tIso,
        });
        this.audit.log({
          eventType: "LOGIN",
          requesterEmail: email,
          result: "FAILURE",
          safeReasonCode: "MFA_REQUIRED",
        });
        return {
          mfa_required: true as const,
          mfa_token: mfaToken,
          email,
        };
      }

      return this.createSession(email, tIso, t.getTime());
    });
  }

  mfaSetup(emailRaw: string): {
    otpauth_url: string;
    secret_base32: string;
  } {
    const email = normalizeEmail(emailRaw);
    const user = this.repo.findUser(email);
    if (!user) {
      throw new AppError("NOT_FOUND");
    }
    if (user.totp_enabled === 1) {
      throw new AppError("INVALID_INPUT", "MFA already enabled");
    }

    const generated = generateTotpSecret();
    const pendingB64 = toBase64(generated.secretBytes);
    const nowIso = this.clock.now().toISOString();
    this.repo.setTotpPending(email, pendingB64, nowIso);

    return {
      otpauth_url: generated.otpauthUrl(email, TOTP_ISSUER),
      secret_base32: generated.secretBase32,
    };
  }

  async mfaEnable(
    emailRaw: string,
    passphrase: string,
    code: string,
  ): Promise<void> {
    const email = normalizeEmail(emailRaw);
    validatePassphrase(passphrase);
    validateTotpCode(code);

    const user = this.repo.findUser(email);
    if (!user) {
      throw new AppError("NOT_FOUND");
    }
    if (user.totp_enabled === 1) {
      throw new AppError("INVALID_INPUT", "MFA already enabled");
    }
    if (!user.totp_pending_secret_b64) {
      throw new AppError("INVALID_INPUT", "MFA setup required first");
    }

    const ok = await verifyPassword(user.password_hash, passphrase);
    if (!ok) {
      throw new AppError("INVALID_CREDENTIALS");
    }

    let secretBytes: Buffer | null = null;
    let kek: Buffer | null = null;
    let salt: Buffer | null = null;
    try {
      secretBytes = fromBase64(user.totp_pending_secret_b64, "totp_pending");
      if (!verifyTotpCode(secretBytes, code)) {
        throw new AppError("INVALID_MFA_CODE");
      }

      salt = randomBytesSecure(16);
      kek = await deriveKek(passphrase, salt);
      const sealed = aesGcmEncrypt(kek, secretBytes, TOTP_AAD);
      this.repo.enableTotp(
        email,
        {
          saltB64: encodeSalt(salt),
          nonceB64: sealed.nonceB64,
          ciphertextB64: sealed.ciphertextB64,
          tagB64: sealed.tagB64,
        },
        this.clock.now().toISOString(),
      );
    } finally {
      zeroize(secretBytes);
      zeroize(kek);
      zeroize(salt);
    }
  }

  async mfaDisable(
    emailRaw: string,
    passphrase: string,
    code: string,
  ): Promise<void> {
    const email = normalizeEmail(emailRaw);
    validatePassphrase(passphrase);
    validateTotpCode(code);

    const user = this.repo.findUser(email);
    if (!user || user.totp_enabled !== 1) {
      throw new AppError("INVALID_INPUT", "MFA is not enabled");
    }

    const ok = await verifyPassword(user.password_hash, passphrase);
    if (!ok) {
      throw new AppError("INVALID_CREDENTIALS");
    }

    await this.verifyUserTotp(user, passphrase, code);
    this.repo.disableTotp(email, this.clock.now().toISOString());
  }

  async mfaVerify(
    mfaToken: string,
    passphrase: string,
    code: string,
  ): Promise<SessionInfo> {
    if (typeof mfaToken !== "string" || mfaToken.length === 0) {
      throw new AppError("INVALID_INPUT", "mfa_token required");
    }
    validatePassphrase(passphrase);
    validateTotpCode(code);

    const tokenHash = sha256(mfaToken).toString("hex");
    const challenge = this.repo.findMfaChallenge(tokenHash);
    if (!challenge) {
      throw new AppError("MFA_TOKEN_EXPIRED");
    }

    const now = this.clock.now();
    if (new Date(challenge.expires_at).getTime() <= now.getTime()) {
      this.repo.deleteMfaChallenge(tokenHash);
      throw new AppError("MFA_TOKEN_EXPIRED");
    }

    const email = challenge.user_email;
    const user = this.repo.findUser(email);
    if (!user || user.totp_enabled !== 1) {
      this.repo.deleteMfaChallenge(tokenHash);
      throw new AppError("INVALID_MFA_CODE");
    }

    if (user.locked_until) {
      const lockedUntil = new Date(user.locked_until);
      if (lockedUntil.getTime() > now.getTime()) {
        throw new AppError("ACCOUNT_LOCKED");
      }
    }

    const ok = await verifyPassword(user.password_hash, passphrase);
    if (!ok) {
      throw new AppError("INVALID_CREDENTIALS");
    }

    await this.verifyUserTotp(user, passphrase, code);

    return this.repo.withTransaction(() => {
      this.repo.deleteMfaChallenge(tokenHash);
      const t = this.clock.now();
      const tIso = t.toISOString();
      this.repo.resetLoginSuccess(email, tIso);
      const session = this.createSession(email, tIso, t.getTime());
      return session;
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

  private createSession(
    email: string,
    tIso: string,
    nowMs: number,
  ): SessionInfo {
    const tokenBuf = randomBytesSecure(32);
    const token = toBase64Url(tokenBuf);
    const tokenHash = sha256(token).toString("hex");
    const sessionId = randomUUID();
    const expiresAt = new Date(nowMs + SESSION_TTL_MS).toISOString();
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
  }

  private async verifyUserTotp(
    user: {
      email: string;
      totp_salt_b64: string | null;
      totp_secret_nonce_b64: string | null;
      totp_secret_ct_b64: string | null;
      totp_secret_tag_b64: string | null;
    },
    passphrase: string,
    code: string,
  ): Promise<void> {
    if (
      !user.totp_salt_b64 ||
      !user.totp_secret_nonce_b64 ||
      !user.totp_secret_ct_b64 ||
      !user.totp_secret_tag_b64
    ) {
      throw new AppError("INVALID_MFA_CODE");
    }

    let kek: Buffer | null = null;
    let secretBytes: Buffer | null = null;
    try {
      const salt = decodeSalt(user.totp_salt_b64);
      kek = await deriveKek(passphrase, salt);
      secretBytes = aesGcmDecrypt(
        kek,
        {
          nonceB64: user.totp_secret_nonce_b64,
          ciphertextB64: user.totp_secret_ct_b64,
          tagB64: user.totp_secret_tag_b64,
        },
        TOTP_AAD,
      );
      if (!verifyTotpCode(secretBytes, code)) {
        throw new AppError("INVALID_MFA_CODE");
      }
    } catch (err) {
      if (err instanceof AppError) throw err;
      throw new AppError("INVALID_MFA_CODE");
    } finally {
      zeroize(kek);
      zeroize(secretBytes);
    }
  }
}
