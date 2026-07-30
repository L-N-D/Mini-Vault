import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { AuditService } from "../../src/audit/audit.service.js";
import { FakeClock } from "../../src/common/clock.js";
import { openDatabase, type Db } from "../../src/storage/database.js";

describe("AuditService chain", () => {
  let dbPath: string;
  let db: Db;

  afterEach(() => {
    db?.close();
    for (const suffix of ["", "-wal", "-shm"]) {
      try {
        fs.unlinkSync(dbPath + suffix);
      } catch {
        /* ignore */
      }
    }
  });

  it("verifyChain succeeds for an intact hash chain", () => {
    dbPath = path.join(os.tmpdir(), `mini-vault-audit-${Date.now()}.db`);
    db = openDatabase(dbPath);
    const clock = new FakeClock();
    const audit = new AuditService(db, clock);

    audit.log({
      eventType: "VAULT_INIT",
      result: "SUCCESS",
    });
    clock.advanceMs(1000);
    audit.log({
      eventType: "LOGIN",
      requesterEmail: "alice@example.com",
      result: "SUCCESS",
    });
    clock.advanceMs(1000);
    audit.log({
      eventType: "VAULT_UNLOCK",
      result: "SUCCESS",
    });

    const result = audit.verifyChain();
    expect(result.ok).toBe(true);
    expect(result.checked).toBe(3);
    expect(result.brokenAtId).toBeUndefined();
  });

  it("verifyChain fails when an entry_hash_hex is mutated", () => {
    dbPath = path.join(os.tmpdir(), `mini-vault-audit-broken-${Date.now()}.db`);
    db = openDatabase(dbPath);
    const clock = new FakeClock();
    const audit = new AuditService(db, clock);

    audit.log({
      eventType: "VAULT_INIT",
      result: "SUCCESS",
    });
    audit.log({
      eventType: "LOGIN",
      requesterEmail: "alice@example.com",
      result: "SUCCESS",
    });

    const row = db
      .prepare(
        `SELECT id, entry_hash_hex FROM audit_logs ORDER BY id DESC LIMIT 1`,
      )
      .get() as { id: number; entry_hash_hex: string };

    const mutated = row.entry_hash_hex.replace(/0/g, "1").replace(/a/g, "b");
    const newHash =
      mutated === row.entry_hash_hex
        ? "f".repeat(64)
        : mutated.padEnd(64, "0").slice(0, 64);

    db.prepare(`UPDATE audit_logs SET entry_hash_hex = ? WHERE id = ?`).run(
      newHash,
      row.id,
    );

    const result = audit.verifyChain();
    expect(result.ok).toBe(false);
    expect(result.brokenAtId).toBe(row.id);
  });
});
