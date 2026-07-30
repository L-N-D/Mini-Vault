import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { FakeClock } from "../../src/common/clock.js";
import { buildApp } from "../../src/bootstrap.js";
import { FakePassphraseProvider } from "../../src/core/fake-passphrase-provider.js";
import { validateAndReturnCanonicalSecretPath } from "../../src/common/kv-path.js";
import { AppError } from "../../src/common/errors.js";
import { toBase64 } from "../../src/common/base64.js";

describe("kv path validation", () => {
  it("accepts canonical path", () => {
    const p = "secret/alice@example.com/database/prod";
    expect(validateAndReturnCanonicalSecretPath(p)).toBe(p);
  });

  it("rejects dangerous paths without rewriting", () => {
    const bad = [
      "Secret/alice@example.com/db",
      "secret/Alice@example.com/db",
      "secret/alice@example.com/../bob",
      "secret/alice@example.com//db",
      "secret\\alice@example.com\\db",
    ];
    for (const p of bad) {
      expect(() => validateAndReturnCanonicalSecretPath(p)).toThrow(AppError);
    }
  });
});

describe("mini-vault integration", () => {
  let dbPath: string;
  let close: () => void;

  beforeEach(() => {
    dbPath = path.join(
      os.tmpdir(),
      `mini-vault-test-${Date.now()}-${Math.random().toString(16).slice(2)}.db`,
    );
  });

  afterEach(() => {
    close?.();
    for (const suffix of ["", "-wal", "-shm"]) {
      try {
        fs.unlinkSync(dbPath + suffix);
      } catch {
        /* ignore */
      }
    }
  });

  it("init, listen locked, unlock, kv round-trip, transit, sign", async () => {
    const clock = new FakeClock();
    const boot = await buildApp({
      databasePath: dbPath,
      authzMode: "ownership",
      clock,
    });
    close = () => {
      void boot.app.close();
      boot.db.close();
    };

    const master = "master-passphrase-ok";
    await boot.vaultService.init(master);

    await boot.app.listen({ port: 0, host: "127.0.0.1" });
    const addr = boot.app.server.address();
    if (!addr || typeof addr === "string") throw new Error("no address");
    const base = `http://127.0.0.1:${addr.port}`;

    let res = await fetch(`${base}/v1/vault/status`);
    expect(await res.json()).toEqual({ status: "LOCKED" });

    // Feature while locked
    await boot.services.auth.register(
      "alice@example.com",
      "user-passphrase1",
      "user-passphrase1",
    );
    const login = await boot.services.auth.login("alice@example.com", "user-passphrase1");
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
    expect(res.status).toBe(400);
    expect((await res.json() as { error: { code: string } }).error.code).toBe(
      "VAULT_LOCKED",
    );

    await boot.vaultService.unlock(master);
    res = await fetch(`${base}/v1/vault/status`);
    expect(await res.json()).toEqual({ status: "UNLOCKED" });

    const write = await boot.services.kv.write(
      "alice@example.com",
      "secret/alice@example.com/db",
      { password: "secret" },
    );
    expect(write.path).toBe("secret/alice@example.com/db");

    const read = await boot.services.kv.read(
      "alice@example.com",
      "secret/alice@example.com/db",
    );
    expect(read.data).toEqual({ password: "secret" });

    await expect(
      boot.services.kv.read("bob@example.com", "secret/alice@example.com/db"),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });

    boot.services.transitKeys.createEncryptionKey(
      "alice@example.com",
      "k1",
    );
    const enc = await boot.services.transitCrypto.encrypt(
      "alice@example.com",
      "k1",
      toBase64(Buffer.from("hello")),
    );
    const dec = await boot.services.transitCrypto.decrypt(
      "alice@example.com",
      enc.ciphertext,
    );
    expect(Buffer.from(dec.plaintext_b64, "base64").toString()).toBe("hello");

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
    expect(ok.signature_valid).toBe(true);

    const bad = await boot.services.signing.verify(
      "alice@example.com",
      "s1",
      toBase64(Buffer.from("msG")),
      "RAW",
      signed.signature_b64,
    );
    expect(bad.signature_valid).toBe(false);

    // Fake provider smoke
    const fake = new FakePassphraseProvider(["wrong-pass-word1", master]);
    // already unlocked — just ensure provider API works
    expect(await fake.requestPassphrase()).toBe("wrong-pass-word1");
  });
});
