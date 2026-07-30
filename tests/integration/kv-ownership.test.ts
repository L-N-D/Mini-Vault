import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { buildApp } from "../../src/bootstrap.js";
import { FakeClock } from "../../src/common/clock.js";
import { requireSessionInfo } from "../../src/auth/auth.service.js";

describe("KV ownership access control", () => {
    let dbPath: string;
    let closeApp: (() => Promise<void>) | undefined;

    beforeEach(() => {
        dbPath = path.join(
            os.tmpdir(),
            `mini-vault-kv-ownership-${Date.now()}-${Math.random()
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

    it("allows the owner to write and read their own secret", async () => {
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

        const aliceLogin = requireSessionInfo(await boot.services.auth.login(
            "alice@example.com",
            "user-passphrase1",
        ));

        await boot.app.listen({
            port: 0,
            host: "127.0.0.1",
        });

        const address = boot.app.server.address();

        if (!address || typeof address === "string") {
            throw new Error("Unable to determine test server address");
        }

        const baseUrl = `http://127.0.0.1:${address.port}`;
        const secretPath = "secret/alice@example.com/database";

        const writeResponse = await fetch(`${baseUrl}/v1/kv/write`, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: `Bearer ${aliceLogin.token}`,
            },
            body: JSON.stringify({
                path: secretPath,
                data: {
                    username: "alice",
                    password: "alice-database-password",
                },
            }),
        });

        expect(writeResponse.status).toBe(200);

        const writeBody = (await writeResponse.json()) as {
            path: string;
            created_at?: string;
            updated_at?: string;
        };

        expect(writeBody.path).toBe(secretPath);

        const readResponse = await fetch(`${baseUrl}/v1/kv/read`, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: `Bearer ${aliceLogin.token}`,
            },
            body: JSON.stringify({
                path: secretPath,
            }),
        });

        expect(readResponse.status).toBe(200);

        const readBody = (await readResponse.json()) as {
            path: string;
            data: {
                username: string;
                password: string;
            };
        };

        expect(readBody.path).toBe(secretPath);

        expect(readBody.data).toEqual({
            username: "alice",
            password: "alice-database-password",
        });
    });

    it("denies a user from reading another user's secret", async () => {
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

        const aliceLogin = requireSessionInfo(await boot.services.auth.login(
            "alice@example.com",
            "user-passphrase1",
        ));

        const bobLogin = requireSessionInfo(await boot.services.auth.login(
            "bob@example.com",
            "user-passphrase2",
        ));

        await boot.app.listen({
            port: 0,
            host: "127.0.0.1",
        });

        const address = boot.app.server.address();

        if (!address || typeof address === "string") {
            throw new Error("Unable to determine test server address");
        }

        const baseUrl = `http://127.0.0.1:${address.port}`;
        const secretPath = "secret/alice@example.com/database";

        const writeResponse = await fetch(`${baseUrl}/v1/kv/write`, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: `Bearer ${aliceLogin.token}`,
            },
            body: JSON.stringify({
                path: secretPath,
                data: {
                    password: "alice-secret",
                },
            }),
        });

        expect(writeResponse.status).toBe(200);

        const bobReadResponse = await fetch(`${baseUrl}/v1/kv/read`, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: `Bearer ${bobLogin.token}`,
            },
            body: JSON.stringify({
                path: secretPath,
            }),
        });

        expect(bobReadResponse.status).toBe(403);

        const responseBody = (await bobReadResponse.json()) as {
            error: {
                code: string;
            };
        };

        expect(responseBody.error.code).toBe("PERMISSION_DENIED");
    });

    it("does not allow another user to overwrite the owner's secret", async () => {
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

        const aliceLogin = requireSessionInfo(await boot.services.auth.login(
            "alice@example.com",
            "user-passphrase1",
        ));

        const bobLogin = requireSessionInfo(await boot.services.auth.login(
            "bob@example.com",
            "user-passphrase2",
        ));

        await boot.app.listen({
            port: 0,
            host: "127.0.0.1",
        });

        const address = boot.app.server.address();

        if (!address || typeof address === "string") {
            throw new Error("Unable to determine test server address");
        }

        const baseUrl = `http://127.0.0.1:${address.port}`;
        const secretPath = "secret/alice@example.com/database";

        const aliceWriteResponse = await fetch(`${baseUrl}/v1/kv/write`, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: `Bearer ${aliceLogin.token}`,
            },
            body: JSON.stringify({
                path: secretPath,
                data: {
                    password: "original-secret",
                },
            }),
        });

        expect(aliceWriteResponse.status).toBe(200);

        const bobWriteResponse = await fetch(`${baseUrl}/v1/kv/write`, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: `Bearer ${bobLogin.token}`,
            },
            body: JSON.stringify({
                path: secretPath,
                data: {
                    password: "overwritten-secret",
                },
            }),
        });

        expect(bobWriteResponse.status).toBe(403);

        const bobWriteBody = (await bobWriteResponse.json()) as {
            error: {
                code: string;
            };
        };

        expect(bobWriteBody.error.code).toBe("PERMISSION_DENIED");

        const aliceReadResponse = await fetch(`${baseUrl}/v1/kv/read`, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: `Bearer ${aliceLogin.token}`,
            },
            body: JSON.stringify({
                path: secretPath,
            }),
        });

        expect(aliceReadResponse.status).toBe(200);

        const aliceReadBody = (await aliceReadResponse.json()) as {
            data: {
                password: string;
            };
        };

        expect(aliceReadBody.data).toEqual({
            password: "original-secret",
        });
    });

    it("does not allow another user to delete the owner's secret", async () => {
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

        const aliceLogin = requireSessionInfo(await boot.services.auth.login(
            "alice@example.com",
            "user-passphrase1",
        ));

        const bobLogin = requireSessionInfo(await boot.services.auth.login(
            "bob@example.com",
            "user-passphrase2",
        ));

        await boot.app.listen({
            port: 0,
            host: "127.0.0.1",
        });

        const address = boot.app.server.address();

        if (!address || typeof address === "string") {
            throw new Error("Unable to determine test server address");
        }

        const baseUrl = `http://127.0.0.1:${address.port}`;
        const secretPath = "secret/alice@example.com/database";

        const aliceWriteResponse = await fetch(`${baseUrl}/v1/kv/write`, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: `Bearer ${aliceLogin.token}`,
            },
            body: JSON.stringify({
                path: secretPath,
                data: {
                    password: "must-remain",
                },
            }),
        });

        expect(aliceWriteResponse.status).toBe(200);

        const bobDeleteResponse = await fetch(`${baseUrl}/v1/kv/delete`, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: `Bearer ${bobLogin.token}`,
            },
            body: JSON.stringify({
                path: secretPath,
            }),
        });

        expect(bobDeleteResponse.status).toBe(403);

        const bobDeleteBody = (await bobDeleteResponse.json()) as {
            error: {
                code: string;
            };
        };

        expect(bobDeleteBody.error.code).toBe("PERMISSION_DENIED");

        const aliceReadResponse = await fetch(`${baseUrl}/v1/kv/read`, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: `Bearer ${aliceLogin.token}`,
            },
            body: JSON.stringify({
                path: secretPath,
            }),
        });

        expect(aliceReadResponse.status).toBe(200);

        const aliceReadBody = (await aliceReadResponse.json()) as {
            data: {
                password: string;
            };
        };

        expect(aliceReadBody.data).toEqual({
            password: "must-remain",
        });
    });

    it("does not reveal whether another user's path exists", async () => {
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

        const aliceLogin = requireSessionInfo(await boot.services.auth.login(
            "alice@example.com",
            "user-passphrase1",
        ));

        const bobLogin = requireSessionInfo(await boot.services.auth.login(
            "bob@example.com",
            "user-passphrase2",
        ));

        await boot.app.listen({
            port: 0,
            host: "127.0.0.1",
        });

        const address = boot.app.server.address();

        if (!address || typeof address === "string") {
            throw new Error("Unable to determine test server address");
        }

        const baseUrl = `http://127.0.0.1:${address.port}`;

        const existingPath =
            "secret/alice@example.com/existing-secret";

        const missingPath =
            "secret/alice@example.com/missing-secret";

        const aliceWriteResponse = await fetch(`${baseUrl}/v1/kv/write`, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: `Bearer ${aliceLogin.token}`,
            },
            body: JSON.stringify({
                path: existingPath,
                data: {
                    value: "this-secret-exists",
                },
            }),
        });

        expect(aliceWriteResponse.status).toBe(200);

        const existingPathResponse = await fetch(`${baseUrl}/v1/kv/read`, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: `Bearer ${bobLogin.token}`,
            },
            body: JSON.stringify({
                path: existingPath,
            }),
        });

        const missingPathResponse = await fetch(`${baseUrl}/v1/kv/read`, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: `Bearer ${bobLogin.token}`,
            },
            body: JSON.stringify({
                path: missingPath,
            }),
        });

        expect(existingPathResponse.status).toBe(403);
        expect(missingPathResponse.status).toBe(403);

        const existingPathBody = (await existingPathResponse.json()) as {
            error: {
                code: string;
            };
        };

        const missingPathBody = (await missingPathResponse.json()) as {
            error: {
                code: string;
            };
        };

        expect(existingPathBody.error.code).toBe("PERMISSION_DENIED");
        expect(missingPathBody.error.code).toBe("PERMISSION_DENIED");
    });

    it("rejects a request without a token before ownership evaluation", async () => {
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

        await boot.app.listen({
            port: 0,
            host: "127.0.0.1",
        });

        const address = boot.app.server.address();

        if (!address || typeof address === "string") {
            throw new Error("Unable to determine test server address");
        }

        const baseUrl = `http://127.0.0.1:${address.port}`;

        const response = await fetch(`${baseUrl}/v1/kv/read`, {
            method: "POST",
            headers: {
                "content-type": "application/json",
            },
            body: JSON.stringify({
                path: "secret/alice@example.com/database",
            }),
        });

        expect(response.status).toBe(401);

        const responseBody = (await response.json()) as {
            error: {
                code: string;
            };
        };

        expect(responseBody.error.code).toBe("UNAUTHENTICATED");
    });

    it("rejects an invalid token before ownership evaluation", async () => {
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

        await boot.app.listen({
            port: 0,
            host: "127.0.0.1",
        });

        const address = boot.app.server.address();

        if (!address || typeof address === "string") {
            throw new Error("Unable to determine test server address");
        }

        const baseUrl = `http://127.0.0.1:${address.port}`;

        const response = await fetch(`${baseUrl}/v1/kv/read`, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: "Bearer completely-invalid-token",
            },
            body: JSON.stringify({
                path: "secret/alice@example.com/database",
            }),
        });

        expect(response.status).toBe(401);

        const responseBody = (await response.json()) as {
            error: {
                code: string;
            };
        };

        expect(responseBody.error.code).toBe("UNAUTHENTICATED");
    });

    it("logs every denied cross-user access attempt", async () => {
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

        const bobLogin = requireSessionInfo(await boot.services.auth.login(
            "bob@example.com",
            "user-passphrase2",
        ));

        await boot.app.listen({
            port: 0,
            host: "127.0.0.1",
        });

        const address = boot.app.server.address();

        if (!address || typeof address === "string") {
            throw new Error("Unable to determine test server address");
        }

        const baseUrl = `http://127.0.0.1:${address.port}`;
        const deniedPath = "secret/alice@example.com/database";

        const response = await fetch(`${baseUrl}/v1/kv/read`, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                authorization: `Bearer ${bobLogin.token}`,
            },
            body: JSON.stringify({
                path: deniedPath,
            }),
        });

        expect(response.status).toBe(403);

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
            target_type: "kv_path",
            target_value: deniedPath,
            result: "DENIED",
        });

        expect(JSON.parse(row!.metadata_json)).toEqual({
            safe_reason_code: "PERMISSION_DENIED",
        });
    });
});