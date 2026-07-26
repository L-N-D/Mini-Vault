import { SystemClock } from "../common/clock.js";
import { loadEnv, ensureDataDir } from "../config/env.js";
import { openDatabase } from "../storage/database.js";
import { AuditService } from "../audit/audit.service.js";
import { VaultRepository } from "./vault.repository.js";
import { VaultState } from "./vault-state.js";
import { VaultService } from "./vault.service.js";
import { HiddenStdinPassphraseProvider } from "./hidden-stdin-passphrase-provider.js";
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

  try {
    if (vault.diskStatus() === "LOCKED") {
      throw new AppError("VAULT_ALREADY_INITIALIZED");
    }
    const provider = new HiddenStdinPassphraseProvider();
    const passphrase = await provider.requestPassphrase("Master Passphrase: ");
    const confirm = await provider.requestPassphrase("Confirm Master Passphrase: ");
    if (passphrase !== confirm) {
      process.stderr.write("Passphrases did not match.\n");
      process.exit(1);
    }
    await vault.init(passphrase);
    process.stdout.write("Vault initialized successfully.\n");
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
