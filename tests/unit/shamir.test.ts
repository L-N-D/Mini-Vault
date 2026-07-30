import { describe, expect, it } from "vitest";

import { AppError } from "../../src/common/errors.js";
import {
  combine,
  decodeShare,
  encodeShare,
  split,
} from "../../src/crypto/shamir.js";

describe("Shamir secret sharing", () => {
  it("round-trips split/combine with any k shares", () => {
    const secret = Buffer.from("mini-vault-root-kek-32-bytes!!");
    const shares = split(secret, 5, 3);
    expect(shares).toHaveLength(5);

    const recovered = combine(shares.slice(0, 3));
    expect(Buffer.compare(recovered, secret)).toBe(0);

    const recoveredAlt = combine([shares[1]!, shares[3]!, shares[4]!]);
    expect(Buffer.compare(recoveredAlt, secret)).toBe(0);
  });

  it("fails to recover the secret with only k-1 shares", () => {
    const secret = Buffer.from("mini-vault-root-kek-32-bytes!!");
    const shares = split(secret, 5, 3);
    const partial = combine(shares.slice(0, 2));
    expect(Buffer.compare(partial, secret)).not.toBe(0);
  });

  it("fails to recover the secret when a share is wrong", () => {
    const secret = Buffer.from("mini-vault-root-kek-32-bytes!!");
    const shares = split(secret, 5, 3);
    const bad = {
      index: shares[0]!.index,
      share: Buffer.from(shares[0]!.share),
    };
    bad.share[0] = (bad.share[0]! + 1) % 256;

    const recovered = combine([bad, shares[1]!, shares[2]!]);
    expect(Buffer.compare(recovered, secret)).not.toBe(0);
  });

  it("encode/decode preserves share bytes", () => {
    const secret = Buffer.from("abc");
    const [share] = split(secret, 3, 2);
    const encoded = encodeShare(share!);
    const decoded = decodeShare(encoded);
    expect(decoded.index).toBe(share!.index);
    expect(Buffer.compare(decoded.share, share!.share)).toBe(0);
  });

  it("rejects fewer than two shares", () => {
    const secret = Buffer.from("x");
    const shares = split(secret, 3, 2);
    expect(() => combine([shares[0]!])).toThrow(AppError);
  });
});
