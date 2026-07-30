import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, afterEach } from "vitest";
import { FakeClock } from "../../src/common/clock.js";
import { openDatabase } from "../../src/storage/database.js";
import { createServices } from "../../src/bootstrap.js";
import { AppError } from "../../src/common/errors.js";
import { isMfaRequiredResult } from "../../src/auth/auth.service.js";

describe("login lockout (0.2)", () => {
  let dbPath = "";

  afterEach(() => {
    if (!dbPath) return;
    for (const suffix of ["", "-wal", "-shm"]) {
      try {
        fs.unlinkSync(dbPath + suffix);
      } catch {
        /* ignore */
      }
    }
    dbPath = "";
  });

  it("locks account after 5 consecutive wrong passwords", async () => {
    dbPath = path.join(os.tmpdir(), `mini-vault-lockout-${Date.now()}.db`);
    const clock = new FakeClock();
    const db = openDatabase(dbPath);
    const services = createServices(db, clock, "ownership");

    await services.vaultService.init("master-passphrase-ok");
    await services.auth.register(
      "alice@example.com",
      "user-passphrase1",
      "user-passphrase1",
    );

    for (let i = 0; i < 5; i++) {
      await expect(
        services.auth.login("alice@example.com", "wrong-passphrase"),
      ).rejects.toMatchObject({ code: "INVALID_CREDENTIALS" });
    }

    await expect(
      services.auth.login("alice@example.com", "user-passphrase1"),
    ).rejects.toBeInstanceOf(AppError);
    await expect(
      services.auth.login("alice@example.com", "user-passphrase1"),
    ).rejects.toMatchObject({ code: "ACCOUNT_LOCKED" });

    // After lockout window, correct password succeeds again.
    clock.advanceMs(5 * 60 * 1000 + 1);
    const result = await services.auth.login(
      "alice@example.com",
      "user-passphrase1",
    );
    expect(isMfaRequiredResult(result)).toBe(false);
    if (!isMfaRequiredResult(result)) {
      expect(result.email).toBe("alice@example.com");
      expect(result.token.length).toBeGreaterThan(10);
    }

    db.close();
  });
});
