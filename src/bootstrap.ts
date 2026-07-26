import Fastify from "fastify";
import { SystemClock } from "./common/clock.js";
import { loadEnv, ensureDataDir } from "./config/env.js";
import { openDatabase } from "./storage/database.js";
import { AuditService } from "./audit/audit.service.js";
import { VaultRepository } from "./core/vault.repository.js";
import { VaultState } from "./core/vault-state.js";
import { VaultService } from "./core/vault.service.js";
import { AuthRepository } from "./auth/auth.repository.js";
import { AuthService } from "./auth/auth.service.js";
import { KvRepository } from "./kv/kv.repository.js";
import { KvService } from "./kv/kv.service.js";
import { KvAuthorizationPlaceholder } from "./kv/access/kv-authorization.placeholder.js";
import { OwnershipKvAuthorization } from "./kv/access/ownership-kv-authorization.js";
import { TransitRepository } from "./transit/transit.repository.js";
import { TransitKeyService } from "./transit/transit-key.service.js";
import { TransitCryptoService } from "./transit/transit-crypto.service.js";
import { SigningService } from "./transit/signing.service.js";
import { TransitAuthorizationPlaceholder } from "./transit/access/transit-authorization.placeholder.js";
import { OwnershipTransitAuthorization } from "./transit/access/ownership-transit-authorization.js";
import { registerRoutes, type AppServices } from "./app.js";
import type { Clock } from "./common/clock.js";
import type { Db } from "./storage/database.js";
import type { MasterPassphraseProvider } from "./core/master-passphrase-provider.js";

export interface BootstrapResult {
  app: ReturnType<typeof Fastify>;
  services: AppServices;
  db: Db;
  env: ReturnType<typeof loadEnv>;
  vaultService: VaultService;
}

export function createServices(
  db: Db,
  clock: Clock,
  authzMode: "ownership" | "placeholder",
): AppServices & { vaultService: VaultService; audit: AuditService } {
  const audit = new AuditService(db, clock);
  const vaultRepo = new VaultRepository(db);
  const vaultState = new VaultState();
  const vaultService = new VaultService(vaultRepo, vaultState, clock, audit);
  const authRepo = new AuthRepository(db);
  const auth = new AuthService(authRepo, clock, audit);
  const kvRepo = new KvRepository(db);
  const transitRepo = new TransitRepository(db);

  const kvAuthz =
    authzMode === "placeholder"
      ? new KvAuthorizationPlaceholder()
      : new OwnershipKvAuthorization(audit);
  const transitAuthz =
    authzMode === "placeholder"
      ? new TransitAuthorizationPlaceholder()
      : new OwnershipTransitAuthorization(transitRepo, audit);

  const kv = new KvService(kvRepo, vaultState, kvAuthz, clock);
  const transitKeys = new TransitKeyService(
    transitRepo,
    vaultState,
    transitAuthz,
    clock,
  );
  const transitCrypto = new TransitCryptoService(
    transitRepo,
    vaultState,
    transitAuthz,
  );
  const signing = new SigningService(transitRepo, vaultState, transitAuthz);

  return {
    auth,
    vault: vaultService,
    vaultState,
    kv,
    transitKeys,
    transitCrypto,
    signing,
    vaultService,
    audit,
  };
}

export async function buildApp(options?: {
  databasePath?: string;
  authzMode?: "ownership" | "placeholder";
  clock?: Clock;
}): Promise<BootstrapResult> {
  const env = loadEnv();
  const databasePath = options?.databasePath ?? env.databasePath;
  const authzMode = options?.authzMode ?? env.authzMode;
  const clock = options?.clock ?? new SystemClock();

  ensureDataDir(databasePath);
  const db = openDatabase(databasePath);
  const created = createServices(db, clock, authzMode);

  const app = Fastify({
    logger: false,
    bodyLimit: 2 * 1024 * 1024,
  });

  const services: AppServices = {
    auth: created.auth,
    vault: created.vault,
    vaultState: created.vaultState,
    kv: created.kv,
    transitKeys: created.transitKeys,
    transitCrypto: created.transitCrypto,
    signing: created.signing,
  };

  await registerRoutes(app, services);

  return {
    app,
    services,
    db,
    env: { ...env, databasePath, authzMode },
    vaultService: created.vaultService,
  };
}

export async function startUnlockLoop(
  vaultService: VaultService,
  provider: MasterPassphraseProvider,
): Promise<void> {
  // Non-blocking: run in background so listen happens first
  void vaultService.unlockLoop(provider).catch((err) => {
    process.stderr.write(`Unlock loop error: ${String(err)}\n`);
  });
}
