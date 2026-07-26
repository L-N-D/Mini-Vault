/**
 * Demo client script. Requires server already running and unlocked.
 *
 * Usage:
 *   npm run vault:init
 *   npm run start   # unlock in that terminal
 *   npm run demo    # in another terminal
 */
const BASE = process.env.VAULT_URL ?? "http://127.0.0.1:3000";

async function api(
  method: string,
  path: string,
  body?: unknown,
  token?: string,
): Promise<{ status: number; json: unknown }> {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = (await res.json()) as unknown;
  return { status: res.status, json };
}

async function main(): Promise<void> {
  const status = await api("GET", "/v1/vault/status");
  console.log("status:", status.json);

  const aliceEmail = "alice@example.com";
  const bobEmail = "bob@example.com";
  const pass = "correct-horse-battery";

  await api("POST", "/v1/auth/register", {
    email: aliceEmail,
    passphrase: pass,
    confirm_passphrase: pass,
  });
  await api("POST", "/v1/auth/register", {
    email: bobEmail,
    passphrase: pass,
    confirm_passphrase: pass,
  });

  const aliceLogin = await api("POST", "/v1/auth/login", {
    email: aliceEmail,
    passphrase: pass,
  });
  const bobLogin = await api("POST", "/v1/auth/login", {
    email: bobEmail,
    passphrase: pass,
  });
  const aliceToken = (aliceLogin.json as { token: string }).token;
  const bobToken = (bobLogin.json as { token: string }).token;

  const path = `secret/${aliceEmail}/database`;
  const write = await api(
    "POST",
    "/v1/kv/write",
    { path, data: { password: "PLAINTEXT_SENTINEL_f728bb8e993841adb98fc530" } },
    aliceToken,
  );
  console.log("write:", write.status, write.json);

  const read = await api("POST", "/v1/kv/read", { path }, aliceToken);
  console.log("read:", read.status, read.json);

  const cross = await api("POST", "/v1/kv/read", { path }, bobToken);
  console.log("cross-user read (expect deny):", cross.status, cross.json);

  const key = await api(
    "POST",
    "/v1/transit/keys/encryption",
    { key_name: "alice-aes" },
    aliceToken,
  );
  console.log("create key:", key.status, key.json);

  const plaintext_b64 = Buffer.from("hello-vault", "utf8").toString("base64");
  const enc = await api(
    "POST",
    "/v1/transit/encrypt/alice-aes",
    { plaintext_b64 },
    aliceToken,
  );
  console.log("encrypt:", enc.status, enc.json);

  const ciphertext = (enc.json as { ciphertext: string }).ciphertext;
  const dec = await api("POST", "/v1/transit/decrypt", { ciphertext }, aliceToken);
  console.log("decrypt:", dec.status, dec.json);

  const crossKey = await api(
    "POST",
    "/v1/transit/encrypt/alice-aes",
    { plaintext_b64 },
    bobToken,
  );
  console.log("cross-key encrypt (expect deny):", crossKey.status, crossKey.json);

  const sk = await api(
    "POST",
    "/v1/transit/keys/signing",
    { key_name: "alice-sign" },
    aliceToken,
  );
  console.log("signing key:", sk.status, sk.json);

  const message_b64 = Buffer.from("important message", "utf8").toString("base64");
  const signed = await api(
    "POST",
    "/v1/transit/sign/alice-sign",
    { message_b64, message_type: "RAW" },
    aliceToken,
  );
  console.log("sign:", signed.status, signed.json);

  const signature_b64 = (signed.json as { signature_b64: string }).signature_b64;
  const verifyOk = await api(
    "POST",
    "/v1/transit/verify/alice-sign",
    { message_b64, message_type: "RAW", signature_b64 },
    aliceToken,
  );
  console.log("verify ok:", verifyOk.status, verifyOk.json);

  const tampered = Buffer.from("important messagE", "utf8").toString("base64");
  const verifyBad = await api(
    "POST",
    "/v1/transit/verify/alice-sign",
    { message_b64: tampered, message_type: "RAW", signature_b64 },
    aliceToken,
  );
  console.log("verify tampered:", verifyBad.status, verifyBad.json);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
