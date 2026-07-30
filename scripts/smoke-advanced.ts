/**
 * Advanced smoke test: npm run test:advanced
 * Covers all 7 bonus features on temp DBs via buildApp.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import assert from "node:assert/strict";
import { FakeClock } from "../src/common/clock.js";
import { buildApp } from "../src/bootstrap.js";
import { AppError } from "../src/common/errors.js";
import { toBase64 } from "../src/common/base64.js";
import {
  isMfaRequiredResult,
  requireSessionInfo,
} from "../src/auth/auth.service.js";
import {
  decodeTotpSecretBase32,
  generateTotpCode,
} from "../src/crypto/totp.js";

function cleanupDb(dbPath: string): void {
  for (const suffix of ["", "-wal", "-shm"]) {
    try {
      fs.unlinkSync(dbPath + suffix);
    } catch {
      /* ignore */
    }
  }
}

async function phasePassphraseFeatures(): Promise<void> {
  const dbPath = path.join(
    os.tmpdir(),
    `mini-vault-adv-${Date.now()}.db`,
  );
  const clock = new FakeClock();
  const boot = await buildApp({
    databasePath: dbPath,
    authzMode: "ownership",
    clock,
  });

  try {
    const master = "master-passphrase-ok";
    await boot.vaultService.init(master);
    await boot.app.listen({ port: 0, host: "127.0.0.1" });

    const addr = boot.app.server.address();
    assert.ok(addr && typeof addr !== "string");

    // 1) Register alice + bob while LOCKED
    await boot.services.auth.register(
      "alice@example.com",
      "user-passphrase1",
      "user-passphrase1",
    );
    await boot.services.auth.register(
      "bob@example.com",
      "user-passphrase2",
      "user-passphrase2",
    );

    // 2) Login while LOCKED works
    const aliceLogin1 = requireSessionInfo(
      await boot.services.auth.login(
        "alice@example.com",
        "user-passphrase1",
      ),
    );
    assert.equal(aliceLogin1.email, "alice@example.com");
    assert.ok(aliceLogin1.token.length > 0);

    // MFA setup / enable / two-step login while still LOCKED
    const setup = boot.services.auth.mfaSetup("alice@example.com");
    assert.ok(setup.secret_base32);
    assert.ok(setup.otpauth_url.includes("otpauth://totp/"));

    const secretBytes = decodeTotpSecretBase32(setup.secret_base32);
    const enableCode = generateTotpCode(secretBytes);
    await boot.services.auth.mfaEnable(
      "alice@example.com",
      "user-passphrase1",
      enableCode,
    );

    boot.services.auth.logout(aliceLogin1.token);

    const mfaChallenge = await boot.services.auth.login(
      "alice@example.com",
      "user-passphrase1",
    );
    assert.ok(isMfaRequiredResult(mfaChallenge));
    assert.equal(mfaChallenge.mfa_required, true);

    const mfaCode = generateTotpCode(secretBytes);
    const aliceSession = await boot.services.auth.mfaVerify(
      mfaChallenge.mfa_token,
      "user-passphrase1",
      mfaCode,
    );
    assert.equal(aliceSession.email, "alice@example.com");

    const statusLocked = boot.services.vault.runtimeStatus();
    assert.equal(statusLocked, "LOCKED");

    // 3) Unlock; audit verify ok
    await boot.vaultService.unlock(master);
    assert.equal(boot.services.vault.runtimeStatus(), "UNLOCKED");
    const auditOk = boot.services.audit.verifyChain();
    assert.equal(auditOk.ok, true);
    assert.ok(auditOk.checked >= 1);

    // 4) KV write v1, write v2, listVersions, read version 1
    const kvPath = "secret/alice@example.com/db";
    await boot.services.kv.write("alice@example.com", kvPath, { v: 1 });
    await boot.services.kv.write("alice@example.com", kvPath, { v: 2 });
    const versions = await boot.services.kv.listVersions(
      "alice@example.com",
      kvPath,
    );
    assert.ok(versions.versions.some((x) => x.version === 1));
    assert.ok(versions.versions.some((x) => x.version === 2));
    const v1 = await boot.services.kv.read(
      "alice@example.com",
      kvPath,
      1,
    );
    assert.deepEqual(v1.data, { v: 1 });
    assert.equal(v1.version, 1);

    // 5) Transit encrypt, rotate, decrypt old ciphertext
    boot.services.transitKeys.createEncryptionKey(
      "alice@example.com",
      "enc1",
    );
    const enc = await boot.services.transitCrypto.encrypt(
      "alice@example.com",
      "enc1",
      toBase64(Buffer.from("hello-old")),
    );
    await boot.services.transitKeys.rotateKey("alice@example.com", "enc1");
    const dec = await boot.services.transitCrypto.decrypt(
      "alice@example.com",
      enc.ciphertext,
    );
    assert.equal(
      Buffer.from(dec.plaintext_b64, "base64").toString(),
      "hello-old",
    );

    // 6) ACL grant bob read; bob reads; revoke; bob denied
    const bobLogin = requireSessionInfo(
      await boot.services.auth.login(
        "bob@example.com",
        "user-passphrase2",
      ),
    );
    void bobLogin;

    await assert.rejects(
      () => boot.services.kv.read("bob@example.com", kvPath),
      (err: unknown) =>
        err instanceof AppError && err.code === "PERMISSION_DENIED",
    );

    boot.services.acl.grant(
      "alice@example.com",
      "kv",
      kvPath,
      "bob@example.com",
      ["read"],
    );
    const bobRead = await boot.services.kv.read("bob@example.com", kvPath);
    assert.deepEqual(bobRead.data, { v: 2 });

    boot.services.acl.revoke(
      "alice@example.com",
      "kv",
      kvPath,
      "bob@example.com",
    );
    await assert.rejects(
      () => boot.services.kv.read("bob@example.com", kvPath),
      (err: unknown) =>
        err instanceof AppError && err.code === "PERMISSION_DENIED",
    );

    // 7) Signing key with allow_public_verify; bob verifies (not owner)
    boot.services.transitKeys.createSigningKey(
      "alice@example.com",
      "sig-pub",
      { allowPublicVerify: true },
    );
    const msg = toBase64(Buffer.from("public-msg"));
    const signed = await boot.services.signing.sign(
      "alice@example.com",
      "sig-pub",
      msg,
      "RAW",
    );
    const bobVerify = await boot.services.signing.verify(
      "bob@example.com",
      "sig-pub",
      msg,
      "RAW",
      signed.signature_b64,
    );
    assert.equal(bobVerify.signature_valid, true);
  } finally {
    await boot.app.close();
    boot.db.close();
    cleanupDb(dbPath);
  }
}

async function phaseShamir(): Promise<void> {
  const dbPath = path.join(
    os.tmpdir(),
    `mini-vault-shamir-${Date.now()}.db`,
  );
  const clock = new FakeClock();
  const boot = await buildApp({
    databasePath: dbPath,
    authzMode: "ownership",
    clock,
  });

  try {
    const shares = await boot.vaultService.initShamir(5, 3);
    assert.equal(shares.length, 5);

    await boot.vaultService.unlockWithShares(shares.slice(0, 3));
    assert.equal(boot.services.vault.runtimeStatus(), "UNLOCKED");

    await boot.services.auth.register(
      "carol@example.com",
      "user-passphrase3",
      "user-passphrase3",
    );
    await boot.services.kv.write(
      "carol@example.com",
      "secret/carol@example.com/shamir",
      { unlocked: true },
    );
    const read = await boot.services.kv.read(
      "carol@example.com",
      "secret/carol@example.com/shamir",
    );
    assert.deepEqual(read.data, { unlocked: true });
  } finally {
    await boot.app.close();
    boot.db.close();
    cleanupDb(dbPath);
  }
}

async function main(): Promise<void> {
  await phasePassphraseFeatures();
  await phaseShamir();
  console.log("OK");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
