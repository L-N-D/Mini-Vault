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
cd 23127177_23127200/Mini-Vault/
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
npm test                 # core smoke (init → LOCKED HTTP → unlock → KV/Transit/Sign)
npm run test:vitest      # unit + integration (Vitest)
npm run test:advanced    # all 7 bonus features on temp DBs
npm run demo:advanced    # shorter console demo of advanced features
```

## Advanced features (extra credit)

The following advanced features have been implemented and tested:

| # | Feature | Notes |
|---|---------|--------|
| 1 | Tamper-evident audit hash chain | Each audit row links `prev_hash_hex` → `entry_hash_hex` (SHA-256) |
| 2 | MFA / TOTP | Setup → enable → two-step login (`mfa_token` + code) |
| 3 | KV secret versions | Write creates versions; list + read historical version |
| 4 | Transit key rotation | Rotate encryption key; old ciphertext still decrypts |
| 5 | ACL grants | Owner grants/revokes `read`/`write`/… on KV paths or transit keys |
| 6 | `allow_public_verify` | Non-owners can verify signatures when the flag is set |
| 7 | Shamir unlock | `initShamir(n,k)` + unlock with any `k` shares |

### New APIs / CLI

| Method / command | Path / script | Notes |
|------------------|---------------|--------|
| GET | `/v1/audit/verify` | Bearer — `{ ok, checked, brokenAtId? }` |
| POST | `/v1/auth/mfa/setup` | Bearer — `{ otpauth_url, secret_base32 }` |
| POST | `/v1/auth/mfa/enable` | Bearer — `{ passphrase, code }` |
| POST | `/v1/auth/mfa/disable` | Bearer — `{ passphrase, code }` |
| POST | `/v1/auth/mfa/verify` | `{ mfa_token, passphrase, code }` → session |
| POST | `/v1/kv/versions` | Bearer — list versions for a path |
| POST | `/v1/kv/read` | optional `version` |
| POST | `/v1/kv/read-version` | `{ path, version }` |
| POST | `/v1/transit/keys/:keyName/rotate` | Bearer + owner |
| POST | `/v1/transit/keys/signing` | optional `allow_public_verify` |
| POST | `/v1/acl/grant` \| `/revoke` | Bearer + owner |
| GET | `/v1/acl/list` | query `resource_type`, `resource_id` |
| CLI | `npm run audit:verify` | Verify audit chain on disk DB |
| CLI | `npm run vault:init:shamir` | Init with Shamir shares (prints shares once) |

`POST /v1/auth/login` may return `{ mfa_required: true, mfa_token, email }` when TOTP is enabled.

### Reset DB for schema upgrades

SQLite migrations are additive (`ALTER TABLE` / new tables). If you hit schema errors after pulling upgrades, delete the local DB and re-init:

```bash
# stop the server first
rm -f data/vault.db data/vault.db-wal data/vault.db-shm   # Unix
# or on Windows: del data\vault.db*
npm run vault:init
```

## Security notes

- Master Passphrase: stdin only (never env/argv/`.env`)
- DEK only in Fastify process RAM after unlock
- Restart → always LOCKED
- Audit logs use allowlist fields only
- Do not commit `data/vault.db` (see `.gitignore`)

## Project docs

See `../docs/report/23127177_23127200_report.pdf` for the report.
