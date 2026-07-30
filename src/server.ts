import { buildApp, startUnlockLoop, startShamirUnlockLoop } from "./bootstrap.js";
import { HiddenStdinPassphraseProvider } from "./core/hidden-stdin-passphrase-provider.js";
import { HiddenStdinShareProvider } from "./core/hidden-stdin-share-provider.js";
import { AppError } from "./common/errors.js";

async function main(): Promise<void> {
  const { app, env, vaultService, db } = await buildApp();

  if (vaultService.diskStatus() === "NOT_INITIALIZED") {
    process.stderr.write(
      "Vault is NOT_INITIALIZED. Run: npm run vault:init  or  npm run vault:init:shamir\n",
    );
    db.close();
    process.exit(1);
  }

  try {
    await app.listen({ port: env.port, host: env.host });
    process.stdout.write(
      `Mini Vault listening on http://${env.host}:${env.port} (LOCKED until unlock)\n`,
    );
    process.stdout.write(`GET /v1/vault/status  (no auth)\n`);

    const unlockMode = vaultService.getUnlockMode();
    if (unlockMode === "shamir") {
      process.stdout.write("Unlock mode: Shamir shares\n");
      await startShamirUnlockLoop(vaultService, new HiddenStdinShareProvider());
    } else {
      process.stdout.write("Unlock mode: Master Passphrase\n");
      await startUnlockLoop(vaultService, new HiddenStdinPassphraseProvider());
    }
  } catch (err) {
    if (err instanceof AppError) {
      process.stderr.write(`${err.code}: ${err.message}\n`);
    } else {
      process.stderr.write(String(err) + "\n");
    }
    db.close();
    process.exit(1);
  }
}

main();
