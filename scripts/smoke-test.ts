/**
 * Smoke test runnable with: npx tsx scripts/smoke-test.ts
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import assert from "node:assert/strict";
import { FakeClock } from "../src/common/clock.js";
import { buildApp } from "../src/bootstrap.js";
import { validateAndReturnCanonicalSecretPath } from "../src/common/kv-path.js";
import { AppError } from "../src/common/errors.js";
import { toBase64 } from "../src/common/base64.js";

function assertThrowsInvalidPath(p: string): void {
  try {
    validateAndReturnCanonicalSecretPath(p);
    throw new Error(`expected invalid: ${p}`);
  } catch (err) {
    assert.ok(err instanceof AppError);
    assert.equal(err.code, "INVALID_INPUT");
  }
}

async function main(): Promise<void> {
  const okPath = "secret/alice@example.com/database/prod";
  assert.equal(validateAndReturnCanonicalSecretPath(okPath), okPath);
  for (const p of [
    "Secret/alice@example.com/db",
    "secret/Alice@example.com/db",
    "secret/alice@example.com/../bob",
    "secret/alice@example.com//db",
  ]) {
    assertThrowsInvalidPath(p);
  }

  const dbPath = path.join(
    os.tmpdir(),
    `mini-vault-smoke-${Date.now()}.db`,
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
    const base = `http://127.0.0.1:${addr.port}`;

    let res = await fetch(`${base}/v1/vault/status`);
    assert.deepEqual(await res.json(), { status: "LOCKED" });

    await boot.services.auth.register(
      "alice@example.com",
      "user-passphrase1",
      "user-passphrase1",
    );
    const login = await boot.services.auth.login(
      "alice@example.com",
      "user-passphrase1",
    );

    res = await fetch(`${base}/v1/kv/write`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${login.token}`,
      },
      body: JSON.stringify({
        path: "secret/alice@example.com/db",
        data: { x: 1 },
      }),
    });
    assert.equal(res.status, 400);
    assert.equal(
      ((await res.json()) as { error: { code: string } }).error.code,
      "VAULT_LOCKED",
    );

    await boot.vaultService.unlock(master);
    res = await fetch(`${base}/v1/vault/status`);
    assert.deepEqual(await res.json(), { status: "UNLOCKED" });

    await boot.services.kv.write("alice@example.com", "secret/alice@example.com/db", {
      password: "secret",
    });
    const read = await boot.services.kv.read(
      "alice@example.com",
      "secret/alice@example.com/db",
    );
    assert.deepEqual(read.data, { password: "secret" });

    await assert.rejects(
      () =>
        boot.services.kv.read("bob@example.com", "secret/alice@example.com/db"),
      (err: unknown) =>
        err instanceof AppError && err.code === "PERMISSION_DENIED",
    );

    boot.services.transitKeys.createEncryptionKey("alice@example.com", "k1");
    const enc = await boot.services.transitCrypto.encrypt(
      "alice@example.com",
      "k1",
      toBase64(Buffer.from("hello")),
    );
    const dec = await boot.services.transitCrypto.decrypt(
      "alice@example.com",
      enc.ciphertext,
    );
    assert.equal(Buffer.from(dec.plaintext_b64, "base64").toString(), "hello");

    boot.services.transitKeys.createSigningKey("alice@example.com", "s1");
    const msg = toBase64(Buffer.from("msg"));
    const signed = await boot.services.signing.sign(
      "alice@example.com",
      "s1",
      msg,
      "RAW",
    );
    const ok = await boot.services.signing.verify(
      "alice@example.com",
      "s1",
      msg,
      "RAW",
      signed.signature_b64,
    );
    assert.equal(ok.signature_valid, true);

    console.log("SMOKE OK");
  } finally {
    await boot.app.close();
    boot.db.close();
    for (const suffix of ["", "-wal", "-shm"]) {
      try {
        fs.unlinkSync(dbPath + suffix);
      } catch {
        /* ignore */
      }
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
