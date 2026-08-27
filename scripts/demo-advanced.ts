/**
 * Advanced features console demo (programmatic, no running server required).
 *
 * Usage: npm run demo:advanced
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { FakeClock } from "../src/common/clock.js";
import { buildApp } from "../src/bootstrap.js";
import { toBase64 } from "../src/common/base64.js";
import { requireSessionInfo } from "../src/auth/auth.service.js";
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

function section(title: string): void {
  console.log(`\n=== ${title} ===`);
}

function action(description: string): void {
  console.log(`ACTION: ${description}`);
}

function expected(description: string): void {
  console.log(`EXPECTED: ${description}`);
}

function evidence(label: string, value: unknown): void {
  console.log(`${label}:`, value);
}

function verify(condition: boolean, message: string): void {
  if (!condition) {
    console.log(`RESULT: FAIL — ${message}`);
    throw new Error(`Advanced demo verification failed: ${message}`);
  }

  console.log(`RESULT: PASS — ${message}`);
}

function hasNumberPropertyN(
  value: unknown,
): value is { n: number } {
  return (
    typeof value === "object" &&
    value !== null &&
    "n" in value &&
    typeof (value as { n?: unknown }).n === "number"
  );
}

async function expectDenied(
  operation: () => Promise<unknown> | unknown,
): Promise<{ denied: boolean; errorCode: string | null }> {
  try {
    await operation();
    return {
      denied: false,
      errorCode: null,
    };
  } catch (error) {
    const candidate = error as {
      code?: unknown;
      message?: unknown;
    };

    const errorCode =
      typeof candidate.code === "string"
        ? candidate.code
        : typeof candidate.message === "string"
          ? candidate.message
          : "UNKNOWN_ERROR";

    return {
      denied: true,
      errorCode,
    };
  }
}



async function main(): Promise<void> {
  const dbPath = path.join(
    os.tmpdir(),
    `mini-vault-demo-adv-${Date.now()}.db`,
  );
  const clock = new FakeClock();
  const boot = await buildApp({
    databasePath: dbPath,
    authzMode: "ownership",
    clock,
  });

  try {
    section("ADVANCED 1 — MFA/TOTP AUTHENTICATION");

    action("Enable TOTP MFA for Alice while the Vault remains locked");
    expected(
      "MFA setup and enable succeed; Vault remains LOCKED; password login no longer returns a session directly",
    );

    await boot.vaultService.init("master-passphrase-ok");

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

    const vaultStatusBeforeMfa = boot.services.vault.runtimeStatus();

    const initialLogin = requireSessionInfo(
      await boot.services.auth.login(
        "alice@example.com",
        "user-passphrase1",
      ),
    );

    const setup = boot.services.auth.mfaSetup("alice@example.com");
    const secret = decodeTotpSecretBase32(setup.secret_base32);

    await boot.services.auth.mfaEnable(
      "alice@example.com",
      "user-passphrase1",
      generateTotpCode(secret),
    );

    boot.services.auth.logout(initialLogin.token);

    const loginAfterMfa = await boot.services.auth.login(
      "alice@example.com",
      "user-passphrase1",
    );

    let sessionIssuedBeforeTotp = true;

    try {
      requireSessionInfo(loginAfterMfa);
    } catch {
      sessionIssuedBeforeTotp = false;
    }

    const vaultStatusAfterMfa = boot.services.vault.runtimeStatus();

    const mfaEvidence = {
      vault_status_before: vaultStatusBeforeMfa,
      mfa_setup_returned_secret: Boolean(setup.secret_base32),
      mfa_enable_completed: true,
      session_issued_before_totp: sessionIssuedBeforeTotp,
      login_response_fields:
        typeof loginAfterMfa === "object" && loginAfterMfa !== null
          ? Object.keys(loginAfterMfa)
          : [],
      vault_status_after: vaultStatusAfterMfa,
    };

    evidence("EVIDENCE", mfaEvidence);

    verify(
      vaultStatusBeforeMfa === "LOCKED" &&
      Boolean(setup.secret_base32) &&
      !sessionIssuedBeforeTotp &&
      vaultStatusAfterMfa === "LOCKED",
      "MFA was enabled while the Vault remained locked, and password login did not directly issue a session",
    );

    section("ADVANCED 2 — TAMPER-EVIDENT AUDIT LOG");

    action("Unlock the Vault and verify the audit hash chain");
    expected(
      "Vault becomes UNLOCKED and all existing audit entries form a valid hash chain",
    );

    await boot.vaultService.unlock("master-passphrase-ok");

    const vaultStatus = boot.services.vault.runtimeStatus();
    const auditResult = boot.services.audit.verifyChain();

    evidence("EVIDENCE", {
      vault_status: vaultStatus,
      chain_valid: auditResult.ok,
      entries_checked: auditResult.checked,
    });

    verify(
      vaultStatus === "UNLOCKED" &&
      auditResult.ok === true &&
      auditResult.checked > 0,
      "The Vault was unlocked and the audit hash chain was valid",
    );

    section("ADVANCED 3 — KV VERSIONING");

    action("Write two versions of a secret and read Version 1");
    expected(
      "Versions 1 and 2 are listed; Version 1 remains readable after Version 2 is written",
    );

    const p = "secret/alice@example.com/demo";

    await boot.services.kv.write(
      "alice@example.com",
      p,
      { n: 1 },
    );

    await boot.services.kv.write(
      "alice@example.com",
      p,
      { n: 2 },
    );

    const versionsResult = await boot.services.kv.listVersions(
      "alice@example.com",
      p,
    );

    const versionOne = await boot.services.kv.read(
      "alice@example.com",
      p,
      1,
    );

    const currentVersion = await boot.services.kv.read(
      "alice@example.com",
      p,
    );

    const listedVersionNumbers = versionsResult.versions.map(
      (item) => item.version,
    );

    evidence("EVIDENCE", {
      path: p,
      listed_versions: listedVersionNumbers,
      version_1_data: versionOne.data,
      current_version: currentVersion.version,
      current_data: currentVersion.data,
    });

    verify(
      listedVersionNumbers.includes(1) &&
      listedVersionNumbers.includes(2) &&
      versionOne.version === 1 &&
      hasNumberPropertyN(versionOne.data) &&
      versionOne.data.n === 1 &&
      currentVersion.version === 2 &&
      hasNumberPropertyN(currentVersion.data) &&
      currentVersion.data.n === 2,
      "Two KV versions were stored and Version 1 remained readable",
    );

    section("ADVANCED 4 — TRANSIT KEY ROTATION");

    action(
      "Encrypt plaintext, rotate the named key, then decrypt the old ciphertext",
    );
    expected(
      'The ciphertext created before rotation still decrypts to "rotate-me"',
    );

    const createdKey =
      boot.services.transitKeys.createEncryptionKey(
        "alice@example.com",
        "k",
      );

    const enc = await boot.services.transitCrypto.encrypt(
      "alice@example.com",
      "k",
      toBase64(Buffer.from("rotate-me")),
    );

    const rotatedKey =
      await boot.services.transitKeys.rotateKey(
        "alice@example.com",
        "k",
      );

    const dec = await boot.services.transitCrypto.decrypt(
      "alice@example.com",
      enc.ciphertext,
    );

    const recoveredPlaintext = Buffer.from(
      dec.plaintext_b64,
      "base64",
    ).toString();

    evidence("EVIDENCE", {
      key_before_rotation: createdKey,
      key_after_rotation: rotatedKey,
      old_ciphertext_prefix: enc.ciphertext.slice(0, 30),
      recovered_plaintext: recoveredPlaintext,
      old_ciphertext_decrypts: recoveredPlaintext === "rotate-me",
    });

    verify(
      recoveredPlaintext === "rotate-me",
      "The old ciphertext remained decryptable after Transit key rotation",
    );

    section("ADVANCED 5 — ACL GRANT AND REVOKE");

    action(
      "Test Bob before grant, grant read permission, then revoke the permission",
    );
    expected(
      "Bob is denied before grant, can read after grant, and is denied again after revoke",
    );

    const beforeGrant = await expectDenied(() =>
      boot.services.kv.read("bob@example.com", p),
    );

    boot.services.acl.grant(
      "alice@example.com",
      "kv",
      p,
      "bob@example.com",
      ["read"],
    );

    const readAfterGrant = await boot.services.kv.read(
      "bob@example.com",
      p,
    );

    boot.services.acl.revoke(
      "alice@example.com",
      "kv",
      p,
      "bob@example.com",
    );

    const afterRevoke = await expectDenied(() =>
      boot.services.kv.read("bob@example.com", p),
    );

    evidence("EVIDENCE", {
      denied_before_grant: beforeGrant.denied,
      error_before_grant: beforeGrant.errorCode,
      read_after_grant: true,
      data_after_grant: readAfterGrant.data,
      revoke_completed: true,
      denied_after_revoke: afterRevoke.denied,
      error_after_revoke: afterRevoke.errorCode,
    });

    verify(
      beforeGrant.denied &&
      hasNumberPropertyN(readAfterGrant.data) &&
      readAfterGrant.data.n === 2 &&
      afterRevoke.denied,
      "ACL grant allowed Bob to read, and revoke removed the permission",
    );

    section("ADVANCED 6 — SHARED SIGNATURE VERIFICATION");

    action(
      "Alice signs a message; Bob verifies it and attempts to sign with Alice's key",
    );
    expected(
      "Bob can verify the signature but cannot sign with Alice's private key",
    );

    boot.services.transitKeys.createSigningKey(
      "alice@example.com",
      "sig",
      {
        allowPublicVerify: true,
      },
    );

    const msg = toBase64(Buffer.from("hello"));

    const signed = await boot.services.signing.sign(
      "alice@example.com",
      "sig",
      msg,
      "RAW",
    );

    const verified = await boot.services.signing.verify(
      "bob@example.com",
      "sig",
      msg,
      "RAW",
      signed.signature_b64,
    );

    const bobSignAttempt = await expectDenied(() =>
      boot.services.signing.sign(
        "bob@example.com",
        "sig",
        msg,
        "RAW",
      ),
    );

    evidence("EVIDENCE", {
      verifier: "bob@example.com",
      signature_valid: verified.signature_valid,
      signing_algorithm: verified.signing_algorithm,
      bob_sign_denied: bobSignAttempt.denied,
      bob_sign_error: bobSignAttempt.errorCode,
    });

    verify(
      verified.signature_valid === true &&
      bobSignAttempt.denied,
      "Bob could verify Alice's signature but could not sign with Alice's key",
    );

    section("ADVANCED 7 — SHAMIR SECRET SHARING");

    action(
      "Attempt to unlock with 2 of 5 shares, then unlock with the required 3 shares",
    );
    expected(
      "Two shares are insufficient; three shares unlock the Vault",
    );

    const shamirPath = path.join(
      os.tmpdir(),
      `mini-vault-demo-shamir-${Date.now()}.db`,
    );

    const shamirBoot = await buildApp({
      databasePath: shamirPath,
      authzMode: "ownership",
      clock: new FakeClock(),
    });

    try {
      const shares = await shamirBoot.vaultService.initShamir(5, 3);

      const insufficientShares = await expectDenied(() =>
        shamirBoot.vaultService.unlockWithShares(
          shares.slice(0, 2),
        ),
      );

      const statusAfterTwoShares =
        shamirBoot.services.vault.runtimeStatus();

      await shamirBoot.vaultService.unlockWithShares(
        shares.slice(0, 3),
      );

      const statusAfterThreeShares =
        shamirBoot.services.vault.runtimeStatus();

      evidence("EVIDENCE", {
        total_shares: 5,
        required_shares: 3,
        unlock_with_2_shares_denied:
          insufficientShares.denied,
        status_after_2_shares: statusAfterTwoShares,
        status_after_3_shares: statusAfterThreeShares,
      });

      verify(
        insufficientShares.denied &&
        statusAfterTwoShares === "LOCKED" &&
        statusAfterThreeShares === "UNLOCKED",
        "The Vault rejected 2 shares and unlocked successfully with 3 of 5 shares",
      );
    } finally {
      await shamirBoot.app.close();
      shamirBoot.db.close();
      cleanupDb(shamirPath);
    }

    console.log("\n============================================================",);
    console.log("ALL DEMONSTRATED ADVANCED FEATURE CHECKS PASSED",);
    console.log("============================================================",);
  } finally {
    await boot.app.close();
    boot.db.close();
    cleanupDb(dbPath);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
