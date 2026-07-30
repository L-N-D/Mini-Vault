import { SystemClock } from "../common/clock.js";
import { loadEnv, ensureDataDir } from "../config/env.js";
import { openDatabase } from "../storage/database.js";
import { AuditService } from "../audit/audit.service.js";
import { VaultRepository } from "./vault.repository.js";
import { VaultState } from "./vault-state.js";
import { VaultService } from "./vault.service.js";
import { AppError } from "../common/errors.js";

async function main(): Promise<void> {
  const env = loadEnv();
  ensureDataDir(env.databasePath);
  const db = openDatabase(env.databasePath);
  const clock = new SystemClock();
  const audit = new AuditService(db, clock);
  const repo = new VaultRepository(db);
  const state = new VaultState();
  const vault = new VaultService(repo, state, clock, audit);

  const n = Number(process.argv[2] ?? 5);
  const k = Number(process.argv[3] ?? 3);

  try {
    if (vault.diskStatus() === "LOCKED") {
      throw new AppError("VAULT_ALREADY_INITIALIZED");
    }
    if (!Number.isInteger(n) || !Number.isInteger(k)) {
      throw new AppError("INVALID_INPUT", "n and k must be integers");
    }

    const shares = await vault.initShamir(n, k);
    process.stdout.write(
      "WARNING: These Shamir shares are shown once. Store them securely and do not lose them.\n",
    );
    process.stdout.write(
      `Vault initialized with Shamir unlock (n=${n}, k=${k}).\n\n`,
    );
    for (let i = 0; i < shares.length; i++) {
      process.stdout.write(`Share ${i + 1}/${shares.length}: ${shares[i]}\n`);
    }
  } catch (err) {
    if (err instanceof AppError) {
      process.stderr.write(`${err.code}: ${err.message}\n`);
      process.exit(1);
    }
    throw err;
  } finally {
    db.close();
  }
}

main();
