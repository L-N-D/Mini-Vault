import type { FastifyInstance, FastifyRequest } from "fastify";
import { AppError } from "./common/errors.js";
import type { AuthService } from "./auth/auth.service.js";
import type { VaultService } from "./core/vault.service.js";
import type { VaultState } from "./core/vault-state.js";
import type { KvService } from "./kv/kv.service.js";
import type { TransitKeyService } from "./transit/transit-key.service.js";
import type { TransitCryptoService } from "./transit/transit-crypto.service.js";
import type { SigningService } from "./transit/signing.service.js";

export interface AppServices {
  auth: AuthService;
  vault: VaultService;
  vaultState: VaultState;
  kv: KvService;
  transitKeys: TransitKeyService;
  transitCrypto: TransitCryptoService;
  signing: SigningService;
}

function bearer(req: FastifyRequest): string | undefined {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) return undefined;
  return header.slice("Bearer ".length).trim();
}

function requireAuth(services: AppServices, req: FastifyRequest): { email: string } {
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

  // Public vault status — no session
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
            confirm_passphrase: { type: "string", minLength: 12, maxLength: 256 },
          },
        },
      },
    },
    async (req) => {
      const result = await services.auth.register(
        req.body.email,
        req.body.passphrase,
        req.body.confirm_passphrase,
      );
      return result;
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
      const session = await services.auth.login(req.body.email, req.body.passphrase);
      return {
        token: session.token,
        expires_at: session.expiresAt,
        email: session.email,
      };
    },
  );

  app.post("/v1/auth/logout", async (req) => {
    services.auth.logout(bearer(req));
    return { ok: true };
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

  app.post<{ Body: { path: string } }>(
    "/v1/kv/read",
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
      return services.kv.read(email, req.body.path);
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

  app.post<{ Body: { key_name: string } }>(
    "/v1/transit/keys/signing",
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
      return services.transitKeys.createSigningKey(email, req.body.key_name);
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
      );
    },
  );
}
