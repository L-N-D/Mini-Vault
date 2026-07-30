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
    section("Init + MFA while LOCKED");
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

    const login = requireSessionInfo(
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
    console.log("MFA enabled for alice (vault still LOCKED)");
    boot.services.auth.logout(login.token);

    section("Unlock + audit verify");
    await boot.vaultService.unlock("master-passphrase-ok");
    console.log("status:", boot.services.vault.runtimeStatus());
    console.log("audit:", boot.services.audit.verifyChain());

    section("KV versions");
    const p = "secret/alice@example.com/demo";
    await boot.services.kv.write("alice@example.com", p, { n: 1 });
    await boot.services.kv.write("alice@example.com", p, { n: 2 });
    console.log(
      "versions:",
      await boot.services.kv.listVersions("alice@example.com", p),
    );
    console.log(
      "v1:",
      await boot.services.kv.read("alice@example.com", p, 1),
    );

    section("Transit rotate + decrypt old");
    boot.services.transitKeys.createEncryptionKey("alice@example.com", "k");
    const enc = await boot.services.transitCrypto.encrypt(
      "alice@example.com",
      "k",
      toBase64(Buffer.from("rotate-me")),
    );
    await boot.services.transitKeys.rotateKey("alice@example.com", "k");
    const dec = await boot.services.transitCrypto.decrypt(
      "alice@example.com",
      enc.ciphertext,
    );
    console.log(
      "decrypted after rotate:",
      Buffer.from(dec.plaintext_b64, "base64").toString(),
    );

    section("ACL grant / revoke");
    boot.services.acl.grant(
      "alice@example.com",
      "kv",
      p,
      "bob@example.com",
      ["read"],
    );
    console.log(
      "bob read after grant:",
      await boot.services.kv.read("bob@example.com", p),
    );
    boot.services.acl.revoke(
      "alice@example.com",
      "kv",
      p,
      "bob@example.com",
    );
    console.log("ACL revoked");

    section("allow_public_verify");
    boot.services.transitKeys.createSigningKey("alice@example.com", "sig", {
      allowPublicVerify: true,
    });
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
    console.log("bob verify:", verified);

    section("Shamir (separate temp DB)");
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
      await shamirBoot.vaultService.unlockWithShares(shares.slice(0, 3));
      console.log(
        "shamir unlocked with 3/5 shares:",
        shamirBoot.services.vault.runtimeStatus(),
      );
    } finally {
      await shamirBoot.app.close();
      shamirBoot.db.close();
      cleanupDb(shamirPath);
    }

    console.log("\nDEMO ADVANCED OK");
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
