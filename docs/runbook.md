# Runbook — chạy, test, xử lý sự cố

## 1. Cài đặt

```bash
cd 23127177_23127200
npm install
```

Yêu cầu: **Node.js ≥ 20**.

## 2. Init vault (passphrase — mặc định)

```bash
npm run vault:init
```

- Nhập Master Passphrase **hai lần** (stdin ẩn).
- Policy: độ dài **12–256**, không chỉ khoảng trắng.
- Chỉ chạy được khi chưa init.

Kiểm tra đĩa:

```bash
npm run vault:status
# NOT_INITIALIZED | LOCKED
```

## 3. Init vault (Shamir — bonus)

```bash
npm run vault:init:shamir
# tùy chọn: npm run vault:init:shamir -- 5 3
```

- In ra N shares **một lần** — sao lưu offline ngay.
- Mất dưới K shares → **mất vault** (phải xóa DB và init lại).

Không init passphrase rồi “đổi” sang Shamir trên cùng DB — chọn **một** mode lúc init.

## 4. Start server

```bash
npm run start
```

1. Process listen `http://127.0.0.1:3000` (hoặc `HOST`/`PORT`).
2. Status HTTP: `LOCKED`.
3. Terminal server: nhập passphrase **hoặc** K shares (tùy `unlock_mode`).
4. Sau unlock: `GET /v1/vault/status` → `UNLOCKED`.

Restart process → luôn về LOCKED (DEK chỉ RAM).

## 5. Demo

Terminal khác (server đã unlock):

```bash
npm run demo              # bắt buộc
npm run demo:advanced     # bonus
```

## 6. Test

```bash
npm test                  # smoke mandatory
npm run test:vitest       # unit + integration
npm run test:advanced     # 7 bonus trên DB tạm
npm run build             # tsc
```

## 7. Reset database

Dừng server trước. Schema breaking / quên passphrase / mất shares:

**Windows (PowerShell):**

```powershell
Remove-Item -Force data\vault.db, data\vault.db-wal, data\vault.db-shm -ErrorAction SilentlyContinue
npm run vault:init
```

**Unix:**

```bash
rm -f data/vault.db data/vault.db-wal data/vault.db-shm
npm run vault:init
```

## 8. Biến môi trường an toàn

| Biến | Ví dụ | Ghi chú |
|------|--------|---------|
| `PORT` | `3000` | |
| `HOST` | `127.0.0.1` | |
| `DATABASE_PATH` | đường dẫn khác | |
| `AUTHZ_MODE` | `ownership` / `placeholder` | Chỉ test placeholder |

**Không** đặt Master Passphrase / shares vào env.

## 9. Troubleshooting

| Triệu chứng | Nguyên nhân thường gặp | Cách xử |
|-------------|------------------------|---------|
| `VAULT_NOT_INITIALIZED` khi start | Chưa `vault:init` | Chạy init |
| `VAULT_LOCKED` trên KV/Transit | Chưa unlock stdin | Nhập passphrase/shares đúng terminal server |
| `INVALID_MASTER_PASSPHRASE` | Sai passphrase | Thử lại; không có recovery nếu quên |
| `ACCOUNT_LOCKED` | 5 lần login sai | Đợi 5 phút |
| `PERMISSION_DENIED` | Sai namespace / chưa grant | Path `secret/<email>/...` hoặc ACL |
| `INVALID_CIPHERTEXT` | Envelope lệch / sai key | Kiểm tra format `vault:name:…` |
| Schema / cột thiếu sau pull | DB cũ | Reset `data/vault.db*` |
| `INVALID_SHARE` / thiếu share | Sai share hoặc &lt; K | Nhập đúng K shares |
| MFA không login được | Sai code / hết `mfa_token` | Setup lại; cửa sổ TOTP ±1 step |

## 10. Checklist demo trước GV (gợi ý)

1. `vault:status` → LOCKED (đã init).
2. `start` → status HTTP LOCKED → login vẫn được → KV bị `VAULT_LOCKED`.
3. Unlock → write/read secret.
4. User khác đọc path Alice → `PERMISSION_DENIED`.
5. Tạo key → encrypt/decrypt → sign/verify → message tamper → `signature_valid: false`.
6. (Bonus) rotate + decrypt cũ; grant Bob; audit:verify; MFA; (tuỳ chọn) Shamir trên DB test.

## 11. Tài liệu liên quan

- Tổng quan: [index.md](./index.md)
- Kiến trúc: [architecture.md](./architecture.md)
- Module/file: [modules.md](./modules.md)
- Feature: [features-required.md](./features-required.md), [features-advanced.md](./features-advanced.md)
- API: [api-flows.md](./api-flows.md)
