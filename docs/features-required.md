# Feature bắt buộc (PDF §III)

Mỗi mục: **Mục tiêu → Luồng → File chính → Liên kết → Lỗi thường gặp**.

---

## 0.1 — Init & Unlock (Master Passphrase)

**Mục tiêu:** Khởi tạo vault một lần; mỗi lần start phải unlock mới dùng được Feature 1/2. DEK plaintext không lên đĩa.

**Luồng init**

1. `npm run vault:init` → nhập passphrase + confirm (stdin ẩn).
2. Sinh salt + Argon2id → KEK; sinh DEK 32B; AES-GCM wrap DEK (AAD `mini-vault:dek:v1`).
3. Ghi `vault_metadata` (salt, params, nonce/ct/tag DEK). Process CLI kết thúc — **không** giữ DEK.

**Luồng unlock (runtime)**

1. `npm run start` — nếu chưa init → thoát; nếu đã init → listen HTTP **LOCKED**.
2. Stdin Master Passphrase → derive KEK → unwrap DEK → `VaultState.setDek`.
3. `GET /v1/vault/status` → `UNLOCKED`.

**File chính:** `vault.service.ts`, `vault.repository.ts`, `vault-state.ts`, `vault.cli-init.ts`, `server.ts`, `hidden-stdin-passphrase-provider.ts`.

**Liên kết:** Mọi KV/Transit phụ thuộc `VaultState.isUnlocked()`.

**Lỗi:** `VAULT_ALREADY_INITIALIZED`, `VAULT_NOT_INITIALIZED`, `INVALID_MASTER_PASSPHRASE`, `VAULT_LOCKED`.

---

## 0.2 — Register / Login / Session

**Mục tiêu:** Định danh user trước khi đụng secret/key; session token opaque; lockout 5 lần / 5 phút.

**Luồng**

1. Register: email + passphrase + confirm → Argon2id hash → `users`.
2. Login: verify password → (nếu MFA off) tạo session 30 phút; lưu **SHA-256(token)** thôi.
3. Sai mật khẩu: tăng `failed_attempts`; đủ 5 → `locked_until` +5 phút (**commit ngoài transaction throw**).
4. Email không tồn tại: dummy Argon2 + `INVALID_CREDENTIALS` (anti-enumeration).
5. Feature 1/2: `Authorization: Bearer <token>` → `authenticate`.

**File chính:** `auth.service.ts`, `auth.repository.ts`, routes trong `app.ts`.

**Liên kết:** MFA (bonus) xen vào sau password đúng; lockout test: `tests/integration/auth-lockout.test.ts`.

**Lỗi:** `EMAIL_ALREADY_EXISTS`, `INVALID_CREDENTIALS`, `ACCOUNT_LOCKED`, `UNAUTHENTICATED`, `SESSION_EXPIRED`.

---

## 1.1 — KV Encrypted-at-Rest

**Mục tiêu:** Secret trên đĩa luôn ciphertext; tamper tag → từ chối decrypt.

**Luồng write**

1. Validate path canonical.
2. AuthZ write → serialize JSON → AES-GCM(DEK, AAD `kv:<owner>:<path>:v<N>`).
3. Lưu nonce/ct/tag (+ version; overwrite đẩy bản cũ vào `kv_versions` nếu bonus bật).

**Luồng read / delete:** AuthZ → load → decrypt/verify tag hoặc xóa.

**File chính:** `kv.service.ts`, `kv.repository.ts`, `aes-gcm.ts`, `kv-path.ts`.

**Liên kết:** Owner lấy từ path (`emailFromSecretPath`), **không** dùng actor trong AAD (để grant đọc được).

**Lỗi:** `VAULT_LOCKED`, `NOT_FOUND`, `INTEGRITY_CHECK_FAILED`, `REQUEST_TOO_LARGE`, `INVALID_INPUT`.

---

## 1.2 — KV Ownership ACL

**Mục tiêu:** User A không đọc/ghi/xóa namespace B; deny generic (không lộ path tồn tại).

**Luồng:** So khớp `session.email` với email trong `secret/<email>/...`. Sai → audit `ACCESS_DENIED` + `PERMISSION_DENIED` **trước** crypto.

**File chính:** `ownership-kv-authorization.ts`, `kv-authorization.port.ts`.

**Liên kết:** Bonus ACL mở rộng cùng port (grant `read`/`write`/`delete`).

**Acceptance:** Cross-user deny 100%; token invalid không tới bước path-check (`UNAUTHENTICATED` trước).

---

## 2.1 — Named Key Management

**Mục tiêu:** Tạo/list/revoke named key; API **không** trả AES/private key.

**Luồng**

1. `create` ENCRYPT_DECRYPT: random AES-256 → wrap bằng DEK (AAD `transit-key:…:kv1`) → DB.
2. `create` SIGN_VERIFY: Ed25519 → private wrap DEK; public lưu riêng (không trả client tạo key).
3. `list_keys`: tên + usage (+ version metadata).
4. `revoke`: AuthZ revoke → xóa key (+ cascade versions).

**File chính:** `transit-key.service.ts`, `transit.repository.ts`.

**Lỗi:** `KEY_NAME_UNAVAILABLE`, `VAULT_LOCKED`, `KEY_NOT_FOUND` (sau authz hiếm).

---

## 2.2 — Encrypt / Decrypt as a Service

**Mục tiêu:** Client gửi plaintext_b64 → nhận envelope tự mô tả; decrypt ngược lại; tamper → fail.

**Luồng encrypt**

1. AuthZ `encrypt` → unwrap named key bằng DEK → AES-GCM data (AAD `transit-data:…`).
2. Envelope:
   - Version 1: `vault:<key_name>:<base64url(nonce||ct||tag)>` (**đúng tinh thần PDF**)
   - Sau rotate: `vault:<key_name>:v<N>:<base64url(…)>`

**Luồng decrypt:** Parse envelope (legacy hoặc versioned) → AuthZ → load đúng version material → decrypt.

**File chính:** `transit-crypto.service.ts`, `unwrap-named-key.ts`.

**Lỗi:** `INVALID_CIPHERTEXT`, `INVALID_KEY_USAGE`, `INTEGRITY_CHECK_FAILED`, `PERMISSION_DENIED`.

---

## 2.3 — Named-Key Access Control

**Mục tiêu:** Không dùng được key của người khác; missing/foreign cùng `PERMISSION_DENIED`.

**Luồng:** `OwnershipTransitAuthorization.authorizeKey` — so `ownerEmail`; audit deny; **không** load material trước khi allow.

**File chính:** `ownership-transit-authorization.ts`, port `AuthorizedKeyMetadata`.

**Liên kết:** Bonus grant + `allow_public_verify` chỉ nới **verify** (và các action được grant), không nới mặc định encrypt/sign.

---

## 2.4 — Sign & Verify

**Mục tiêu:** Private key không rời server; verify trả `{ key_name, signature_valid, signing_algorithm }`.

**Luồng**

1. `sign(RAW|DIGEST)`: AuthZ → unwrap private → Ed25519; RAW hash SHA-256 trước.
2. `verify`: AuthZ → dùng public → `signature_valid` true/false (message/signature lệch → false).

**File chính:** `signing.service.ts`, `crypto/signing.ts`.

**Lỗi:** `INVALID_MESSAGE_TYPE`, `INVALID_DIGEST_LENGTH`, `INVALID_KEY_USAGE`, `INVALID_SIGNING_ALGORITHM`.

**Mandatory scope:** Chỉ owner verify (trừ khi bật bonus open verify / grant).

---

## Ma trận nhanh file ↔ feature

| Feature | Service chính | AuthZ | Storage |
|---------|---------------|-------|---------|
| 0.1 | VaultService | — | vault_metadata |
| 0.2 | AuthService | — | users, sessions |
| 1.1 | KvService | sau 1.2 | kv_entries |
| 1.2 | OwnershipKv | port | — |
| 2.1 | TransitKeyService | create/list owner filter | transit_keys |
| 2.2 | TransitCryptoService | encrypt/decrypt | key versions |
| 2.3 | OwnershipTransit | port | — |
| 2.4 | SigningService | sign/verify | public + wrapped private |
