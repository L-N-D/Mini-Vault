# Mini Vault

Secure Storage (KV Engine) & Encryption / Signing as a Service (Transit Engine)

**Team:** 23127177, 23127200  
**Course:** Computer Security — Assignment 1

## Stack

- Node.js LTS + TypeScript
- Fastify + SQLite (`better-sqlite3`)
- Argon2id (`argon2`)
- AES-256-GCM / Ed25519 (`node:crypto`)

## Setup

```bash
cd 23127177_23127200
npm install
```

## Run

```bash
# 1) Initialize vault (enter Master Passphrase twice; not via env/argv)
npm run vault:init

# 2) Disk status (NOT_INITIALIZED | LOCKED only)
npm run vault:status

# 3) Start server — listens while LOCKED, then unlock via hidden stdin
npm run start
```

After unlock in the server terminal:

```bash
# another terminal
npm run demo
```

Default URL: `http://127.0.0.1:3000`

## API (summary)

| Method | Path | Auth |
|--------|------|------|
| GET | `/v1/vault/status` | No — `{ status: "LOCKED"\|"UNLOCKED" }` |
| POST | `/v1/auth/register` | No |
| POST | `/v1/auth/login` | No |
| POST | `/v1/auth/logout` | Bearer |
| POST | `/v1/kv/write\|read\|delete` | Bearer + unlocked |
| POST | `/v1/transit/keys/encryption\|signing` | Bearer + unlocked |
| GET | `/v1/transit/keys` | Bearer + unlocked |
| DELETE | `/v1/transit/keys/:keyName` | Bearer + unlocked |
| POST | `/v1/transit/encrypt/:keyName` | Bearer + unlocked |
| POST | `/v1/transit/decrypt` | Bearer + unlocked |
| POST | `/v1/transit/sign\|verify/:keyName` | Bearer + unlocked |

Pipeline for Feature 1/2: **Auth → session → Vault unlocked → Authorization → crypto**.

## Authorization (1.2 / 2.3)

Ports + placeholders are available. Default `AUTHZ_MODE=ownership` wires:

- `OwnershipKvAuthorization` — path must be `secret/<session-email>/...`
- `OwnershipTransitAuthorization` — `authorizeKey` returns metadata; deny is generic `PERMISSION_DENIED`

Set `AUTHZ_MODE=placeholder` to use fail-closed holders (for contract testing of placeholders).

## Tests

```bash
npm test
```

Runs an end-to-end smoke test (init → locked HTTP `VAULT_LOCKED` → unlock → KV/Transit/Sign).
## Security notes

- Master Passphrase: stdin only (never env/argv/`.env`)
- DEK only in Fastify process RAM after unlock
- Restart → always LOCKED
- Audit logs use allowlist fields only
- Do not commit `data/vault.db` (see `.gitignore`)

## Project docs

See `../docs/FINAL_PLAN.md` for the full design plan.
