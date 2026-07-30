import { SystemClock } from "../common/clock.js";
import { loadEnv, ensureDataDir } from "../config/env.js";
import { openDatabase } from "../storage/database.js";
import { AuditService } from "./audit.service.js";

function main(): void {
  const env = loadEnv();
  ensureDataDir(env.databasePath);
  const db = openDatabase(env.databasePath);
  try {
    const clock = new SystemClock();
    const audit = new AuditService(db, clock);
    const result = audit.verifyChain();
    if (result.ok) {
      process.stdout.write("OK\n");
      return;
    }
    process.stdout.write(`brokenAtId=${result.brokenAtId}\n`);
    process.exitCode = 1;
  } finally {
    db.close();
  }
}

main();
