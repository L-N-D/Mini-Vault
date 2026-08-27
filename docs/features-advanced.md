# Feature mở rộng — Extra credit (PDF §IV)

Rubric gợi ý tổng ≈ 2.4 điểm nhưng **trần +1.0**. Đã triển khai đủ 7 mục. Mỗi mục: **Mục tiêu → Vì sao chọn cách này → Luồng → File/API → Ràng buộc**.

---

## 1. Tamper-evident audit log (+0.3)

**Mục tiêu:** Phát hiện sửa/xóa/chen dòng audit (hash-chain).

**Vì sao:** Hash-chain SHA-256 đủ “tamper-evident”; không ký bằng DEK → verify được cả khi vault LOCKED.

**Luồng:** Mỗi `AuditService.log` đọc `entry_hash` dòng cuối trong transaction → `prev_hash` → `entry_hash = SHA256(canonical)`. `verifyChain()` duyệt lại.

**API/CLI:** `GET /v1/audit/verify` (Bearer), `npm run audit:verify`.

**File:** `audit.service.ts`, cột `prev_hash_hex` / `entry_hash_hex`, test `tests/unit/audit-chain.test.ts`.

---

## 2. MFA TOTP (+0.2)

**Mục tiêu:** Login thêm bước OTP.

**Vì sao không bọc TOTP bằng DEK:** Server listen LOCKED; login phải chạy khi chưa unlock → secret bọc bằng **Argon2id(password) + AES-GCM** (`totp-secret:v1`).

**Luồng**

1. User đã login thường → `POST /v1/auth/mfa/setup` → `otpauth_url` + secret (một lần).
2. `enable` với passphrase + code → lưu secret đã wrap.
3. Login sau đó: password đúng → `{ mfa_required, mfa_token }` (5 phút).
4. `POST /v1/auth/mfa/verify` với `{ mfa_token, passphrase, code }` → session thật.

**File:** `auth.service.ts`, `crypto/totp.ts`, routes MFA trong `app.ts`.

---

## 3. Shamir Secret Sharing (+0.5)

**Mục tiêu:** Thay Master Passphrase bằng N shares, cần K để unlock.

**Vì sao:** Mode tách `passphrase` | `shamir` — giữ regression mandatory. Shamir: RootKEK random → wrap DEK → split; shares in stdout **một lần**, không lưu đủ N trên đĩa.

**Luồng:** `npm run vault:init:shamir` (mặc định n=5, k=3) → `start` prompt K shares → `combine` → unwrap DEK.

**File:** `crypto/shamir.ts`, `vault.service.ts` (`initShamir`, `unlockWithShares`), share providers, `vault.cli-init-shamir.ts`, nhánh trong `server.ts`.

---

## 4. Transit key rotation (+0.4)

**Mục tiêu:** Đổi material named key; ciphertext cũ vẫn decrypt được.

**Luồng:** `POST .../keys/:keyName/rotate` (owner) → version++ → material mới AAD `:kv<N>`. Encrypt luôn dùng `current_version`. Decrypt đọc version từ envelope (hoặc legacy = v1).

**Envelope:** v1 không có `:vN:`; sau rotate có `v2`, `v3`, …

**File:** `transit-key.service.ts` (`rotateKey`), `transit-crypto.service.ts`, `transit_key_versions`.

---

## 5. KV versioning (+0.3)

**Mục tiêu:** Giữ lịch sử overwrite.

**Luồng write:** Archive bản hiện tại vào `kv_versions` → version++ → encrypt với AAD có version.  
**Read:** mặc định latest; optional `version` / `POST /v1/kv/read-version`.  
**List:** `POST /v1/kv/versions` (metadata, không plaintext).

**File:** `kv.service.ts`, `kv.repository.ts`.

---

## 6. Policy / ACL share (+0.4)

**Mục tiêu:** Share secret/key cho user khác thay vì chỉ ownership cứng.

**Vì sao:** Mở rộng `Ownership*` + bảng `access_grants` — không viết AuthZ engine mới.

**Luồng:** Owner `POST /v1/acl/grant` → grantee có permission khớp action. Revoke / list tương ứng.

**File:** `acl.service.ts`, `acl.repository.ts`, inject vào Ownership trong `bootstrap.ts`.

---

## 7. Open verify (+0.3)

**Mục tiêu:** User đã authenticate (không nhất thiết owner) được `verify()`.

**Cách bật**

- Tạo signing key với `allow_public_verify: true`, **hoặc**
- Grant permission `verify` cho email cụ thể.

Sign / encrypt / decrypt **không** public. Vẫn cần Bearer + vault unlocked (verify dùng public key đã lưu; pipeline thống nhất).

**File:** `ownership-transit-authorization.ts`, `createSigningKey(..., { allowPublicVerify })`.

---

## Kiểm thử bonus

```bash
npm run test:advanced    # smoke đủ 7 mục
npm run demo:advanced
npm run test:vitest      # gồm audit-chain, totp, shamir
```

Xem thêm [api-flows.md](./api-flows.md) và [runbook.md](./runbook.md).
