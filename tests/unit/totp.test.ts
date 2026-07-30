import { describe, expect, it } from "vitest";

import {
  generateTotpCode,
  generateTotpSecret,
  verifyTotpCode,
} from "../../src/crypto/totp.js";

describe("TOTP", () => {
  it("generates a secret and verifies the current code window", () => {
    const { secretBytes } = generateTotpSecret();
    const code = generateTotpCode(secretBytes);

    expect(code).toMatch(/^\d{6}$/);
    expect(verifyTotpCode(secretBytes, code)).toBe(true);
    expect(verifyTotpCode(secretBytes, "000000")).toBe(false);
  });
});
