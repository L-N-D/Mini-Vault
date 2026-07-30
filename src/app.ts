import type { FastifyInstance, FastifyRequest } from "fastify";
import { AppError } from "./common/errors.js";
import {
  isMfaRequiredResult,
  type AuthService,
} from "./auth/auth.service.js";
import type { VaultService } from "./core/vault.service.js";
import type { VaultState } from "./core/vault-state.js";
import type { KvService } from "./kv/kv.service.js";
import type { TransitKeyService } from "./transit/transit-key.service.js";
import type { TransitCryptoService } from "./transit/transit-crypto.service.js";
import type { SigningService } from "./transit/signing.service.js";
import type { AclService } from "./acl/acl.service.js";
import type { AuditService } from "./audit/audit.service.js";

export interface AppServices {
  auth: AuthService;
  vault: VaultService;
  vaultState: VaultState;
  kv: KvService;
  transitKeys: TransitKeyService;
  transitCrypto: TransitCryptoService;
  signing: SigningService;
  acl: AclService;
  audit: AuditService;
}

function bearer(req: FastifyRequest): string | undefined {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) return undefined;
  return header.slice("Bearer ".length).trim();
}

function requireAuth(
  services: AppServices,
  req: FastifyRequest,
): { email: string } {
  return services.auth.authenticate(bearer(req));
}

export async function registerRoutes(
  app: FastifyInstance,
  services: AppServices,
): Promise<void> {
  app.setErrorHandler((err, _req, reply) => {
    if (err instanceof AppError) {
      return reply.status(err.httpStatus).send({
        error: { code: err.code, message: err.message },
      });
    }
    if (err && typeof err === "object" && "validation" in err) {
      return reply.status(400).send({
        error: { code: "INVALID_INPUT", message: "Request validation failed" },
      });
    }
    if (err && typeof err === "object" && "statusCode" in err) {
      const status = (err as { statusCode?: number }).statusCode ?? 500;
      if (status === 413) {
        return reply.status(413).send({
          error: { code: "REQUEST_TOO_LARGE", message: "Request too large" },
        });
      }
    }
    app.log.error(err);
    return reply.status(500).send({
      error: { code: "INVALID_INPUT", message: "Internal error" },
    });
  });

  app.addContentTypeParser(
    "application/json",
    { parseAs: "buffer", bodyLimit: 2 * 1024 * 1024 },
    (_req, body, done) => {
      try {
        const json = JSON.parse(body.toString("utf8")) as unknown;
        done(null, json);
      } catch {
        done(new AppError("INVALID_INPUT", "Invalid JSON"), undefined);
      }
    },
  );

  app.get("/v1/vault/status", async () => ({
    status: services.vault.runtimeStatus(),
  }));

  app.post<{
    Body: { email: string; passphrase: string; confirm_passphrase: string };
  }>(
    "/v1/auth/register",
    {
      schema: {
        body: {
          type: "object",
          required: ["email", "passphrase", "confirm_passphrase"],
          properties: {
            email: { type: "string", maxLength: 254 },
            passphrase: { type: "string", minLength: 12, maxLength: 256 },
            confirm_passphrase: {
              type: "string",
              minLength: 12,
              maxLength: 256,
            },
          },
        },
      },
    },
    async (req) => {
      return services.auth.register(
        req.body.email,
        req.body.passphrase,
        req.body.confirm_passphrase,
      );
    },
  );

  app.post<{
    Body: { email: string; passphrase: string };
  }>(
    "/v1/auth/login",
    {
      schema: {
        body: {
          type: "object",
          required: ["email", "passphrase"],
          properties: {
            email: { type: "string", maxLength: 254 },
            passphrase: { type: "string", minLength: 12, maxLength: 256 },
          },
        },
      },
    },
    async (req) => {
      const result = await services.auth.login(
        req.body.email,
        req.body.passphrase,
      );
      if (isMfaRequiredResult(result)) {
        return {
          mfa_required: true,
          mfa_token: result.mfa_token,
          email: result.email,
        };
      }
      return {
        token: result.token,
        expires_at: result.expiresAt,
        email: result.email,
      };
    },
  );

  app.post<{
    Body: { mfa_token: string; passphrase: string; code: string };
  }>(
    "/v1/auth/mfa/verify",
    {
      schema: {
        body: {
          type: "object",
          required: ["mfa_token", "passphrase", "code"],
          properties: {
            mfa_token: { type: "string" },
            passphrase: { type: "string", minLength: 12, maxLength: 256 },
            code: { type: "string", minLength: 6, maxLength: 6 },
          },
        },
      },
    },
    async (req) => {
      const session = await services.auth.mfaVerify(
        req.body.mfa_token,
        req.body.passphrase,
        req.body.code,
      );
      return {
        token: session.token,
        expires_at: session.expiresAt,
        email: session.email,
      };
    },
  );

  app.post("/v1/auth/mfa/setup", async (req) => {
    const { email } = requireAuth(services, req);
    return services.auth.mfaSetup(email);
  });

  app.post<{ Body: { passphrase: string; code: string } }>(
    "/v1/auth/mfa/enable",
    {
      schema: {
        body: {
          type: "object",
          required: ["passphrase", "code"],
          properties: {
            passphrase: { type: "string", minLength: 12, maxLength: 256 },
            code: { type: "string", minLength: 6, maxLength: 6 },
          },
        },
      },
    },
    async (req) => {
      const { email } = requireAuth(services, req);
      await services.auth.mfaEnable(
        email,
        req.body.passphrase,
        req.body.code,
      );
      return { ok: true, totp_enabled: true };
    },
  );

  app.post<{ Body: { passphrase: string; code: string } }>(
    "/v1/auth/mfa/disable",
    {
      schema: {
        body: {
          type: "object",
          required: ["passphrase", "code"],
          properties: {
            passphrase: { type: "string", minLength: 12, maxLength: 256 },
            code: { type: "string", minLength: 6, maxLength: 6 },
          },
        },
      },
    },
    async (req) => {
      const { email } = requireAuth(services, req);
      await services.auth.mfaDisable(
        email,
        req.body.passphrase,
        req.body.code,
      );
      return { ok: true, totp_enabled: false };
    },
  );

  app.post("/v1/auth/logout", async (req) => {
    services.auth.logout(bearer(req));
    return { ok: true };
  });

  app.get("/v1/audit/verify", async (req) => {
    requireAuth(services, req);
    return services.audit.verifyChain();
  });

  // KV
  app.post<{ Body: { path: string; data: unknown } }>(
    "/v1/kv/write",
    {
      schema: {
        body: {
          type: "object",
          required: ["path", "data"],
          properties: {
            path: { type: "string", maxLength: 512 },
            data: {},
          },
        },
      },
    },
    async (req) => {
      const { email } = requireAuth(services, req);
      return services.kv.write(email, req.body.path, req.body.data);
    },
  );

  app.post<{ Body: { path: string; version?: number } }>(
    "/v1/kv/read",
    {
      schema: {
        body: {
          type: "object",
          required: ["path"],
          properties: {
            path: { type: "string", maxLength: 512 },
            version: { type: "integer", minimum: 1 },
          },
        },
      },
    },
    async (req) => {
      const { email } = requireAuth(services, req);
      return services.kv.read(email, req.body.path, req.body.version);
    },
  );

  app.post<{ Body: { path: string } }>(
    "/v1/kv/versions",
    {
      schema: {
        body: {
          type: "object",
          required: ["path"],
          properties: { path: { type: "string", maxLength: 512 } },
        },
      },
    },
    async (req) => {
      const { email } = requireAuth(services, req);
      return services.kv.listVersions(email, req.body.path);
    },
  );

  app.post<{ Body: { path: string; version: number } }>(
    "/v1/kv/read-version",
    {
      schema: {
        body: {
          type: "object",
          required: ["path", "version"],
          properties: {
            path: { type: "string", maxLength: 512 },
            version: { type: "integer", minimum: 1 },
          },
        },
      },
    },
    async (req) => {
      const { email } = requireAuth(services, req);
      return services.kv.read(email, req.body.path, req.body.version);
    },
  );

  app.post<{ Body: { path: string } }>(
    "/v1/kv/delete",
    {
      schema: {
        body: {
          type: "object",
          required: ["path"],
          properties: { path: { type: "string", maxLength: 512 } },
        },
      },
    },
    async (req) => {
      const { email } = requireAuth(services, req);
      return services.kv.delete(email, req.body.path);
    },
  );

  // Transit keys
  app.post<{ Body: { key_name: string } }>(
    "/v1/transit/keys/encryption",
    {
      schema: {
        body: {
          type: "object",
          required: ["key_name"],
          properties: { key_name: { type: "string", maxLength: 64 } },
        },
      },
    },
    async (req) => {
      const { email } = requireAuth(services, req);
      return services.transitKeys.createEncryptionKey(email, req.body.key_name);
    },
  );

  app.post<{
    Body: { key_name: string; allow_public_verify?: boolean };
  }>(
    "/v1/transit/keys/signing",
    {
      schema: {
        body: {
          type: "object",
          required: ["key_name"],
          properties: {
            key_name: { type: "string", maxLength: 64 },
            allow_public_verify: { type: "boolean" },
          },
        },
      },
    },
    async (req) => {
      const { email } = requireAuth(services, req);
      return services.transitKeys.createSigningKey(email, req.body.key_name, {
        allowPublicVerify: req.body.allow_public_verify === true,
      });
    },
  );

  app.get("/v1/transit/keys", async (req) => {
    const { email } = requireAuth(services, req);
    return { keys: services.transitKeys.listKeys(email) };
  });

  app.delete<{ Params: { keyName: string } }>(
    "/v1/transit/keys/:keyName",
    async (req) => {
      const { email } = requireAuth(services, req);
      return services.transitKeys.revokeKey(email, req.params.keyName);
    },
  );

  app.post<{ Params: { keyName: string } }>(
    "/v1/transit/keys/:keyName/rotate",
    async (req) => {
      const { email } = requireAuth(services, req);
      return services.transitKeys.rotateKey(email, req.params.keyName);
    },
  );

  app.post<{
    Params: { keyName: string };
    Body: { plaintext_b64: string };
  }>(
    "/v1/transit/encrypt/:keyName",
    {
      schema: {
        body: {
          type: "object",
          required: ["plaintext_b64"],
          properties: { plaintext_b64: { type: "string" } },
        },
      },
    },
    async (req) => {
      const { email } = requireAuth(services, req);
      return services.transitCrypto.encrypt(
        email,
        req.params.keyName,
        req.body.plaintext_b64,
      );
    },
  );

  app.post<{ Body: { ciphertext: string } }>(
    "/v1/transit/decrypt",
    {
      schema: {
        body: {
          type: "object",
          required: ["ciphertext"],
          properties: { ciphertext: { type: "string" } },
        },
      },
    },
    async (req) => {
      const { email } = requireAuth(services, req);
      return services.transitCrypto.decrypt(email, req.body.ciphertext);
    },
  );

  app.post<{
    Params: { keyName: string };
    Body: {
      message_b64: string;
      message_type: "RAW" | "DIGEST";
      signing_algorithm?: string;
    };
  }>(
    "/v1/transit/sign/:keyName",
    {
      schema: {
        body: {
          type: "object",
          required: ["message_b64", "message_type"],
          properties: {
            message_b64: { type: "string" },
            message_type: { type: "string", enum: ["RAW", "DIGEST"] },
            signing_algorithm: { type: "string" },
          },
        },
      },
    },
    async (req) => {
      const { email } = requireAuth(services, req);
      return services.signing.sign(
        email,
        req.params.keyName,
        req.body.message_b64,
        req.body.message_type,
        req.body.signing_algorithm,
      );
    },
  );

  app.post<{
    Params: { keyName: string };
    Body: {
      message_b64: string;
      message_type: "RAW" | "DIGEST";
      signature_b64: string;
      signing_algorithm?: string;
      key_version?: number;
    };
  }>(
    "/v1/transit/verify/:keyName",
    {
      schema: {
        body: {
          type: "object",
          required: ["message_b64", "message_type", "signature_b64"],
          properties: {
            message_b64: { type: "string" },
            message_type: { type: "string", enum: ["RAW", "DIGEST"] },
            signature_b64: { type: "string" },
            signing_algorithm: { type: "string" },
            key_version: { type: "integer", minimum: 1 },
          },
        },
      },
    },
    async (req) => {
      const { email } = requireAuth(services, req);
      return services.signing.verify(
        email,
        req.params.keyName,
        req.body.message_b64,
        req.body.message_type,
        req.body.signature_b64,
        req.body.signing_algorithm,
        req.body.key_version,
      );
    },
  );

  // ACL
  app.post<{
    Body: {
      resource_type: "kv" | "transit";
      resource_id: string;
      grantee_email: string;
      permissions: string[];
    };
  }>(
    "/v1/acl/grant",
    {
      schema: {
        body: {
          type: "object",
          required: [
            "resource_type",
            "resource_id",
            "grantee_email",
            "permissions",
          ],
          properties: {
            resource_type: { type: "string", enum: ["kv", "transit"] },
            resource_id: { type: "string", maxLength: 512 },
            grantee_email: { type: "string", maxLength: 254 },
            permissions: {
              type: "array",
              items: { type: "string" },
              minItems: 1,
            },
          },
        },
      },
    },
    async (req) => {
      const { email } = requireAuth(services, req);
      const row = services.acl.grant(
        email,
        req.body.resource_type,
        req.body.resource_id,
        req.body.grantee_email,
        req.body.permissions,
      );
      return {
        id: row.id,
        resource_type: row.resource_type,
        resource_id: row.resource_id,
        grantee_email: row.grantee_email,
        permissions: row.permissions.split(","),
        granted_by: row.granted_by,
        created_at: row.created_at,
      };
    },
  );

  app.post<{
    Body: {
      resource_type: "kv" | "transit";
      resource_id: string;
      grantee_email: string;
    };
  }>(
    "/v1/acl/revoke",
    {
      schema: {
        body: {
          type: "object",
          required: ["resource_type", "resource_id", "grantee_email"],
          properties: {
            resource_type: { type: "string", enum: ["kv", "transit"] },
            resource_id: { type: "string", maxLength: 512 },
            grantee_email: { type: "string", maxLength: 254 },
          },
        },
      },
    },
    async (req) => {
      const { email } = requireAuth(services, req);
      services.acl.revoke(
        email,
        req.body.resource_type,
        req.body.resource_id,
        req.body.grantee_email,
      );
      return { revoked: true };
    },
  );

  app.get<{
    Querystring: { resource_type: "kv" | "transit"; resource_id: string };
  }>(
    "/v1/acl/list",
    {
      schema: {
        querystring: {
          type: "object",
          required: ["resource_type", "resource_id"],
          properties: {
            resource_type: { type: "string", enum: ["kv", "transit"] },
            resource_id: { type: "string", maxLength: 512 },
          },
        },
      },
    },
    async (req) => {
      const { email } = requireAuth(services, req);
      const rows = services.acl.list(
        email,
        req.query.resource_type,
        req.query.resource_id,
      );
      return {
        grants: rows.map((row) => ({
          id: row.id,
          resource_type: row.resource_type,
          resource_id: row.resource_id,
          grantee_email: row.grantee_email,
          permissions: row.permissions.split(","),
          granted_by: row.granted_by,
          created_at: row.created_at,
        })),
      };
    },
  );
}
