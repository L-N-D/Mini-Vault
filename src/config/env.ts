import path from "node:path";
import fs from "node:fs";

export interface EnvConfig {
  port: number;
  host: string;
  databasePath: string;
  authzMode: "ownership" | "placeholder";
}

export function loadEnv(): EnvConfig {
  const authz = (process.env.AUTHZ_MODE ?? "ownership").toLowerCase();
  return {
    port: Number(process.env.PORT ?? 3000),
    host: process.env.HOST ?? "127.0.0.1",
    databasePath: path.resolve(
      process.env.DATABASE_PATH ?? path.join(process.cwd(), "data", "vault.db"),
    ),
    authzMode: authz === "placeholder" ? "placeholder" : "ownership",
  };
}

export function ensureDataDir(databasePath: string): void {
  fs.mkdirSync(path.dirname(databasePath), { recursive: true });
}
