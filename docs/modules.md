# Modules và file

## Cây thư mục (rút gọn)

```text
23127177_23127200/
├── README.md
├── package.json
├── docs/                 # Tài liệu hướng dẫn (bộ này)
├── src/
│   ├── server.ts         # Entry HTTP: listen LOCKED + unlock loop
│   ├── bootstrap.ts      # DI: tạo services + AuthZ
│   ├── app.ts            # Đăng ký routes Fastify
│   ├── config/env.ts
│   ├── storage/database.ts
│   ├── common/           # errors, clock, base64, kv-path
│   ├── crypto/           # aes-gcm, argon2, signing, totp, shamir, …
│   ├── core/             # Vault init/unlock/state/CLI
│   ├── auth/             # Register/login/session/MFA
│   ├── kv/               # KV engine + ownership ACL
│   ├── transit/          # Named keys, encrypt, sign
│   ├── acl/              # Grants share (bonus)
│   └── audit/            # Hash-chained audit + CLI verify
├── scripts/              # demo, smoke, smoke-advanced
├── tests/                # Vitest unit + integration
└── data/                 # vault.db (gitignore)
```

---

## Entry & wiring

| File | Vai trò | Phụ thuộc / liên kết |
|------|---------|----------------------|
| [`src/server.ts`](../src/server.ts) | `buildApp` → listen → chọn unlock passphrase hoặc Shamir | `bootstrap`, providers stdin |
| [`src/bootstrap.ts`](../src/bootstrap.ts) | Tạo DB, services, AuthZ, gắn vào `AppServices` | Mọi service |
| [`src/app.ts`](../src/app.ts) | Routes + error handler `{ error: { code, message } }` | `AppServices` |
| [`src/config/env.ts`](../src/config/env.ts) | PORT, HOST, DATABASE_PATH, AUTHZ_MODE | Không chứa passphrase |

---

## `src/storage/`

| File | Vai trò |
|------|---------|
| [`database.ts`](../src/storage/database.ts) | Mở SQLite, pragma (FK, WAL, secure_delete), `migrate()` tạo/ALTER bảng: vault, users, sessions, kv, transit, audit, MFA, grants, versions |

---

## `src/common/`

| File | Vai trò |
|------|---------|
| [`errors.ts`](../src/common/errors.ts) | `ErrorCode` + `AppError` + HTTP status (exhaustive switch) |
| [`clock.ts`](../src/common/clock.ts) | `Clock` / `FakeClock` — test khóa thời gian (lockout, session) |
| [`base64.ts`](../src/common/base64.ts) | Base64 / Base64URL encode-decode an toàn |
| [`kv-path.ts`](../src/common/kv-path.ts) | Validate path `secret/<email>/...` (không rewrite); `emailFromSecretPath` |

---

## `src/crypto/`

| File | Vai trò |
|------|---------|
| [`argon2.ts`](../src/crypto/argon2.ts) | deriveKek, hashPassword, verifyPassword, dummy verify |
| [`aes-gcm.ts`](../src/crypto/aes-gcm.ts) | AES-256-GCM encrypt/decrypt + AAD |
| [`signing.ts`](../src/crypto/signing.ts) | Ed25519 keygen/sign/verify; RAW→SHA-256; DIGEST 32 bytes |
| [`hashing.ts`](../src/crypto/hashing.ts) | SHA-256 (session token hash, audit chain) |
| [`random.ts`](../src/crypto/random.ts) | `randomBytesSecure` |
| [`zeroize.ts`](../src/crypto/zeroize.ts) | Best-effort xóa Buffer nhạy cảm |
| [`totp.ts`](../src/crypto/totp.ts) | TOTP RFC 6238 (HMAC-SHA1, 30s, 6 digits) — không phụ thuộc DEK |
| [`shamir.ts`](../src/crypto/shamir.ts) | Shamir SSS trên GF(256); encode/decode share |

---

## `src/core/` — Vault (0.1 + Shamir)

| File | Vai trò |
|------|---------|
| [`vault-state.ts`](../src/core/vault-state.ts) | DEK trong RAM; `LOCKED` / `UNLOCKED`; `withDek(fn)` |
| [`vault.repository.ts`](../src/core/vault.repository.ts) | Đọc/ghi `vault_metadata` (kdf, encrypted DEK, unlock_mode, shamir n/k) |
| [`vault.service.ts`](../src/core/vault.service.ts) | `init`, `initShamir`, `unlock`, `unlockWithShares`, unlock loops |
| [`master-passphrase-provider.ts`](../src/core/master-passphrase-provider.ts) | Interface nhập passphrase |
| [`hidden-stdin-passphrase-provider.ts`](../src/core/hidden-stdin-passphrase-provider.ts) | Stdin ẩn (production) |
| [`fake-passphrase-provider.ts`](../src/core/fake-passphrase-provider.ts) | Test |
| [`share-provider.ts`](../src/core/share-provider.ts) | Interface nhập K shares |
| [`hidden-stdin-share-provider.ts`](../src/core/hidden-stdin-share-provider.ts) | Stdin shares |
| [`fake-share-provider.ts`](../src/core/fake-share-provider.ts) | Test Shamir |
| [`vault.cli-init.ts`](../src/core/vault.cli-init.ts) | `npm run vault:init` |
| [`vault.cli-init-shamir.ts`](../src/core/vault.cli-init-shamir.ts) | `npm run vault:init:shamir` — in shares **một lần** |
| [`vault.cli-status.ts`](../src/core/vault.cli-status.ts) | `NOT_INITIALIZED` \| `LOCKED` |

---

## `src/auth/` — Identity (0.2 + MFA)

| File | Vai trò |
|------|---------|
| [`auth.repository.ts`](../src/auth/auth.repository.ts) | users, sessions, MFA pending/wrapped secret, mfa_challenges |
| [`auth.service.ts`](../src/auth/auth.service.ts) | register, login (+ lockout), logout, authenticate; MFA setup/enable/disable/verify |

**Liên kết:** Login có thể trả session ngay hoặc `{ mfa_required, mfa_token }`. TOTP secret bọc bằng KEK từ password (Argon2id) — **không cần Vault unlock**.

---

## `src/kv/` — Secure Storage

| File | Vai trò |
|------|---------|
| [`kv.repository.ts`](../src/kv/kv.repository.ts) | `kv_entries` + `kv_versions` |
| [`kv.service.ts`](../src/kv/kv.service.ts) | write/read/delete/listVersions; AAD `kv:<owner>:<path>:v<N>` |
| [`access/kv-authorization.port.ts`](../src/kv/access/kv-authorization.port.ts) | Port `assertAllowed(read\|write\|delete)` |
| [`access/ownership-kv-authorization.ts`](../src/kv/access/ownership-kv-authorization.ts) | Owner path **hoặc** ACL grant |
| [`access/kv-authorization.placeholder.ts`](../src/kv/access/kv-authorization.placeholder.ts) | Fail-closed (`AUTHZ_MODE=placeholder`) |
| [`access/kv-authorization.test-allow.ts`](../src/kv/access/kv-authorization.test-allow.ts) | Helper test |

---

## `src/transit/` — Encrypt & Sign as a Service

| File | Vai trò |
|------|---------|
| [`transit.repository.ts`](../src/transit/transit.repository.ts) | Metadata + `transit_key_versions` |
| [`transit-key.service.ts`](../src/transit/transit-key.service.ts) | create encryption/signing, list, revoke, **rotate** |
| [`transit-crypto.service.ts`](../src/transit/transit-crypto.service.ts) | encrypt/decrypt envelope |
| [`signing.service.ts`](../src/transit/signing.service.ts) | sign/verify; optional `key_version` |
| [`unwrap-named-key.ts`](../src/transit/unwrap-named-key.ts) | Giải bọc material (`:kvN` hoặc legacy `:v1`) |
| [`access/transit-authorization.port.ts`](../src/transit/access/transit-authorization.port.ts) | `authorizeKey` → metadata (version, allowPublicVerify) |
| [`access/ownership-transit-authorization.ts`](../src/transit/access/ownership-transit-authorization.ts) | Owner / grant / `allow_public_verify` (verify) |
| Placeholder + test-allow | Giống KV |

---

## `src/acl/` — Policy share (bonus)

| File | Vai trò |
|------|---------|
| [`acl.repository.ts`](../src/acl/acl.repository.ts) | Bảng `access_grants` |
| [`acl.service.ts`](../src/acl/acl.service.ts) | grant/revoke/list — **chỉ owner** resource |

Permissions KV: `read`, `write`, `delete`.  
Transit: `encrypt`, `decrypt`, `sign`, `verify`, `revoke` (`rotate` **không** grant — chỉ owner).

---

## `src/audit/`

| File | Vai trò |
|------|---------|
| [`audit.service.ts`](../src/audit/audit.service.ts) | `log` / `denied` + hash-chain; `verifyChain()` |
| [`audit.cli-verify.ts`](../src/audit/audit.cli-verify.ts) | `npm run audit:verify` |

---

## `scripts/` và `tests/`

| Path | Vai trò |
|------|---------|
| [`scripts/demo.ts`](../scripts/demo.ts) | Demo mandatory (server thật) |
| [`scripts/demo-advanced.ts`](../scripts/demo-advanced.ts) | Demo bonus ngắn |
| [`scripts/smoke-test.ts`](../scripts/smoke-test.ts) | Smoke bắt buộc (`npm test`) |
| [`scripts/smoke-advanced.ts`](../scripts/smoke-advanced.ts) | Smoke 7 bonus (`npm run test:advanced`) |
| `tests/unit/*` | AuthZ, audit-chain, totp, shamir, … |
| `tests/integration/*` | Vault, KV/Transit ownership, lockout |

---

## Cách các phần “nói chuyện”

1. **HTTP** vào `app.ts` → gọi service tương ứng.
2. Service **KV/Transit** hỏi **AuthZ port** trước khi đụng crypto/DB material.
3. AuthZ ownership có thể hỏi **AclRepository** nếu không phải owner.
4. Crypto cần **VaultState** (DEK) hoặc (với MFA) chỉ password của user.
5. Mọi deny / vault event quan trọng đi qua **AuditService** → SQLite hash-chain.
