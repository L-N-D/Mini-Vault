import { loadEnv, ensureDataDir } from "../config/env.js";
import { openDatabase } from "../storage/database.js";
import { VaultRepository } from "./vault.repository.js";

function main(): void {
  const env = loadEnv();
  ensureDataDir(env.databasePath);
  const db = openDatabase(env.databasePath);
  try {
    const repo = new VaultRepository(db);
    const status = repo.exists() ? "LOCKED" : "NOT_INITIALIZED";
    process.stdout.write(`${status}\n`);
  } finally {
    db.close();
  }
}

main();
