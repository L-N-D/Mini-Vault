import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { buildApp } from "../../src/bootstrap.js";
import { FakeClock } from "../../src/common/clock.js";
import { toBase64 } from "../../src/common/base64.js";

describe("Transit named-key ownership access control", () => {
    let dbPath: string;
    let closeApp: (() => Promise<void>) | undefined;

    beforeEach(() => {
        dbPath = path.join(
            os.tmpdir(),
            `mini-vault-transit-ownership-${Date.now()}-${Math.random()
                .toString(16)
                .slice(2)}.db`,
        );
    });

    afterEach(async () => {
        await closeApp?.();

        for (const suffix of ["", "-wal", "-shm"]) {
            try {
                fs.unlinkSync(dbPath + suffix);
            } catch {
                // The file may not exist.
            }
        }
    });

    it("allows the owner to encrypt and decrypt with their own named key", async () => {
        const clock = new FakeClock();

        const boot = await buildApp({
            databasePath: dbPath,
            authzMode: "ownership",
            clock,
        });

        closeApp = async () => {
            await boot.app.close();
            boot.db.close();
        };

        const masterPassphrase = "master-passphrase-ok";

        await boot.vaultService.init(masterPassphrase);
        await boot.vaultService.unlock(masterPassphrase);

        await boot.services.auth.register(
            "alice@example.com",
            "user-passphrase1",
            "user-passphrase1",
        );

        boot.services.transitKeys.createEncryptionKey(
            "alice@example.com",
            "alice-key",
        );

        const plaintext = Buffer.from("hello from alice");

        const encrypted = await boot.services.transitCrypto.encrypt(
            "alice@example.com",
            "alice-key",
            toBase64(plaintext),
        );

        expect(encrypted.ciphertext).toMatch(/^vault:alice-key:/);

        const decrypted = await boot.services.transitCrypto.decrypt(
            "alice@example.com",
            encrypted.ciphertext,
        );

        expect(
            Buffer.from(decrypted.plaintext_b64, "base64").toString("utf8"),
        ).toBe("hello from alice");
    });

    it("denies a user from encrypting with another user's named key", async () => {
        const clock = new FakeClock();

        const boot = await buildApp({
            databasePath: dbPath,
            authzMode: "ownership",
            clock,
        });

        closeApp = async () => {
            await boot.app.close();
            boot.db.close();
        };

        const masterPassphrase = "master-passphrase-ok";

        await boot.vaultService.init(masterPassphrase);
        await boot.vaultService.unlock(masterPassphrase);

        await boot.services.auth.register(
            "alice@example.com",
            "user-passphrase1",
            "user-passphrase1",
        );

        await boot.services.auth.register(
            "bob@example.com",
            "user-passphrase2",
            "user-passphrase2",
        );

        boot.services.transitKeys.createEncryptionKey(
            "alice@example.com",
            "alice-key",
        );

        await expect(
            boot.services.transitCrypto.encrypt(
                "bob@example.com",
                "alice-key",
                toBase64(Buffer.from("bob should not encrypt")),
            ),
        ).rejects.toMatchObject({
            code: "PERMISSION_DENIED",
        });
    });

    it("denies a user from decrypting ciphertext created with another user's named key", async () => {
        const clock = new FakeClock();

        const boot = await buildApp({
            databasePath: dbPath,
            authzMode: "ownership",
            clock,
        });

        closeApp = async () => {
            await boot.app.close();
            boot.db.close();
        };

        const masterPassphrase = "master-passphrase-ok";

        await boot.vaultService.init(masterPassphrase);
        await boot.vaultService.unlock(masterPassphrase);

        await boot.services.auth.register(
            "alice@example.com",
            "user-passphrase1",
            "user-passphrase1",
        );

        await boot.services.auth.register(
            "bob@example.com",
            "user-passphrase2",
            "user-passphrase2",
        );

        boot.services.transitKeys.createEncryptionKey(
            "alice@example.com",
            "alice-key",
        );

        const encrypted = await boot.services.transitCrypto.encrypt(
            "alice@example.com",
            "alice-key",
            toBase64(Buffer.from("alice private data")),
        );

        await expect(
            boot.services.transitCrypto.decrypt(
                "bob@example.com",
                encrypted.ciphertext,
            ),
        ).rejects.toMatchObject({
            code: "PERMISSION_DENIED",
        });
    });

    it("does not reveal whether another user's named key exists", async () => {
        const clock = new FakeClock();

        const boot = await buildApp({
            databasePath: dbPath,
            authzMode: "ownership",
            clock,
        });

        closeApp = async () => {
            await boot.app.close();
            boot.db.close();
        };

        const masterPassphrase = "master-passphrase-ok";

        await boot.vaultService.init(masterPassphrase);
        await boot.vaultService.unlock(masterPassphrase);

        await boot.services.auth.register(
            "alice@example.com",
            "user-passphrase1",
            "user-passphrase1",
        );

        await boot.services.auth.register(
            "bob@example.com",
            "user-passphrase2",
            "user-passphrase2",
        );

        boot.services.transitKeys.createEncryptionKey(
            "alice@example.com",
            "alice-key",
        );

        const plaintextB64 = toBase64(Buffer.from("test data"));

        let existingKeyError: unknown;

        try {
            await boot.services.transitCrypto.encrypt(
                "bob@example.com",
                "alice-key",
                plaintextB64,
            );
        } catch (error) {
            existingKeyError = error;
        }

        let missingKeyError: unknown;

        try {
            await boot.services.transitCrypto.encrypt(
                "bob@example.com",
                "missing-key",
                plaintextB64,
            );
        } catch (error) {
            missingKeyError = error;
        }

        expect(existingKeyError).toMatchObject({
            code: "PERMISSION_DENIED",
        });

        expect(missingKeyError).toMatchObject({
            code: "PERMISSION_DENIED",
        });
    });

    it("logs denied attempts to use another user's named key", async () => {
        const clock = new FakeClock();

        const boot = await buildApp({
            databasePath: dbPath,
            authzMode: "ownership",
            clock,
        });

        closeApp = async () => {
            await boot.app.close();
            boot.db.close();
        };

        const masterPassphrase = "master-passphrase-ok";

        await boot.vaultService.init(masterPassphrase);
        await boot.vaultService.unlock(masterPassphrase);

        await boot.services.auth.register(
            "alice@example.com",
            "user-passphrase1",
            "user-passphrase1",
        );

        await boot.services.auth.register(
            "bob@example.com",
            "user-passphrase2",
            "user-passphrase2",
        );

        boot.services.transitKeys.createEncryptionKey(
            "alice@example.com",
            "alice-key",
        );

        await expect(
            boot.services.transitCrypto.encrypt(
                "bob@example.com",
                "alice-key",
                toBase64(Buffer.from("unauthorized data")),
            ),
        ).rejects.toMatchObject({
            code: "PERMISSION_DENIED",
        });

        const row = boot.db
            .prepare(
                `SELECT
                    event_type,
                    requester_email,
                    target_type,
                    target_value,
                    result,
                    metadata_json
                FROM audit_logs
                WHERE event_type = ?
                ORDER BY id DESC
                LIMIT 1`,
            )
            .get("ACCESS_DENIED") as
            | {
                event_type: string;
                requester_email: string | null;
                target_type: string | null;
                target_value: string | null;
                result: string;
                metadata_json: string;
            }
            | undefined;

        expect(row).toBeDefined();

        expect(row).toMatchObject({
            event_type: "ACCESS_DENIED",
            requester_email: "bob@example.com",
            target_type: "transit_key",
            target_value: "alice-key",
            result: "DENIED",
        });

        expect(JSON.parse(row!.metadata_json)).toEqual({
            safe_reason_code: "PERMISSION_DENIED",
        });
    });

    it("denies cross-user encryption through the authenticated HTTP API", async () => {
        const clock = new FakeClock();

        const boot = await buildApp({
            databasePath: dbPath,
            authzMode: "ownership",
            clock,
        });

        closeApp = async () => {
            await boot.app.close();
            boot.db.close();
        };

        const masterPassphrase = "master-passphrase-ok";

        await boot.vaultService.init(masterPassphrase);
        await boot.vaultService.unlock(masterPassphrase);

        await boot.services.auth.register(
            "alice@example.com",
            "user-passphrase1",
            "user-passphrase1",
        );

        await boot.services.auth.register(
            "bob@example.com",
            "user-passphrase2",
            "user-passphrase2",
        );

        const aliceLogin = await boot.services.auth.login(
            "alice@example.com",
            "user-passphrase1",
        );

        const bobLogin = await boot.services.auth.login(
            "bob@example.com",
            "user-passphrase2",
        );

        await boot.app.listen({
            port: 0,
            host: "127.0.0.1",
        });

        const address = boot.app.server.address();

        if (!address || typeof address === "string") {
            throw new Error("Unable to determine test server address");
        }

        const baseUrl = `http://127.0.0.1:${address.port}`;

        const createKeyResponse = await fetch(
            `${baseUrl}/v1/transit/keys/encryption`,
            {
                method: "POST",
                headers: {
                    "content-type": "application/json",
                    authorization: `Bearer ${aliceLogin.token}`,
                },
                body: JSON.stringify({
                    key_name: "alice-key",
                }),
            },
        );

        expect(createKeyResponse.status).toBe(200);

        const bobEncryptResponse = await fetch(
            `${baseUrl}/v1/transit/encrypt/alice-key`,
            {
                method: "POST",
                headers: {
                    "content-type": "application/json",
                    authorization: `Bearer ${bobLogin.token}`,
                },
                body: JSON.stringify({
                    plaintext_b64: toBase64(
                        Buffer.from("bob must not use this key"),
                    ),
                }),
            },
        );

        expect(bobEncryptResponse.status).toBe(403);

        const responseBody = (await bobEncryptResponse.json()) as {
            error: {
                code: string;
            };
        };

        expect(responseBody.error.code).toBe("PERMISSION_DENIED");
    });

    it("denies cross-user decryption through the authenticated HTTP API", async () => {
        const clock = new FakeClock();

        const boot = await buildApp({
            databasePath: dbPath,
            authzMode: "ownership",
            clock,
        });

        closeApp = async () => {
            await boot.app.close();
            boot.db.close();
        };

        const masterPassphrase = "master-passphrase-ok";

        await boot.vaultService.init(masterPassphrase);
        await boot.vaultService.unlock(masterPassphrase);

        await boot.services.auth.register(
            "alice@example.com",
            "user-passphrase1",
            "user-passphrase1",
        );

        await boot.services.auth.register(
            "bob@example.com",
            "user-passphrase2",
            "user-passphrase2",
        );

        const aliceLogin = await boot.services.auth.login(
            "alice@example.com",
            "user-passphrase1",
        );

        const bobLogin = await boot.services.auth.login(
            "bob@example.com",
            "user-passphrase2",
        );

        await boot.app.listen({
            port: 0,
            host: "127.0.0.1",
        });

        const address = boot.app.server.address();

        if (!address || typeof address === "string") {
            throw new Error("Unable to determine test server address");
        }

        const baseUrl = `http://127.0.0.1:${address.port}`;

        const createKeyResponse = await fetch(
            `${baseUrl}/v1/transit/keys/encryption`,
            {
                method: "POST",
                headers: {
                    "content-type": "application/json",
                    authorization: `Bearer ${aliceLogin.token}`,
                },
                body: JSON.stringify({
                    key_name: "alice-key",
                }),
            },
        );

        expect(createKeyResponse.status).toBe(200);

        const aliceEncryptResponse = await fetch(
            `${baseUrl}/v1/transit/encrypt/alice-key`,
            {
                method: "POST",
                headers: {
                    "content-type": "application/json",
                    authorization: `Bearer ${aliceLogin.token}`,
                },
                body: JSON.stringify({
                    plaintext_b64: toBase64(
                        Buffer.from("alice private transit data"),
                    ),
                }),
            },
        );

        expect(aliceEncryptResponse.status).toBe(200);

        const aliceEncryptBody = (await aliceEncryptResponse.json()) as {
            ciphertext: string;
        };

        expect(aliceEncryptBody.ciphertext).toMatch(/^vault:alice-key:/);

        const bobDecryptResponse = await fetch(
            `${baseUrl}/v1/transit/decrypt`,
            {
                method: "POST",
                headers: {
                    "content-type": "application/json",
                    authorization: `Bearer ${bobLogin.token}`,
                },
                body: JSON.stringify({
                    ciphertext: aliceEncryptBody.ciphertext,
                }),
            },
        );

        expect(bobDecryptResponse.status).toBe(403);

        const bobDecryptBody = (await bobDecryptResponse.json()) as {
            error: {
                code: string;
            };
        };

        expect(bobDecryptBody.error.code).toBe("PERMISSION_DENIED");
    });
});