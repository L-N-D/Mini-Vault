import { beforeEach, describe, expect, it, vi } from "vitest";

import { AppError } from "../../src/common/errors.js";
import { toBase64Url } from "../../src/common/base64.js";
import { VaultState } from "../../src/core/vault-state.js";
import type { TransitAuthorizationPort } from "../../src/transit/access/transit-authorization.port.js";
import type { TransitRepository } from "../../src/transit/transit.repository.js";
import { TransitCryptoService } from "../../src/transit/transit-crypto.service.js";

describe("TransitCryptoService authorization boundary", () => {
  let getEncryptedKeyMaterialMock: ReturnType<typeof vi.fn>;
  let authorizeKeyMock: ReturnType<typeof vi.fn>;

  let repository: TransitRepository;
  let authorization: TransitAuthorizationPort;
  let vaultState: VaultState;
  let service: TransitCryptoService;

  beforeEach(() => {
    getEncryptedKeyMaterialMock = vi.fn();

    repository = {
      getEncryptedKeyMaterial: getEncryptedKeyMaterialMock,
    } as unknown as TransitRepository;

    authorizeKeyMock = vi
      .fn()
      .mockRejectedValue(new AppError("PERMISSION_DENIED"));

    authorization = {
      authorizeKey: authorizeKeyMock,
    };

    vaultState = new VaultState();
    vaultState.setDek(Buffer.alloc(32, 1));

    service = new TransitCryptoService(
      repository,
      vaultState,
      authorization,
    );
  });

  it("does not read key material when authorization denies encrypt", async () => {
    await expect(
      service.encrypt(
        "bob@example.com",
        "alice-key",
        Buffer.from("hello").toString("base64"),
      ),
    ).rejects.toMatchObject({
      code: "PERMISSION_DENIED",
    });

    expect(authorizeKeyMock).toHaveBeenCalledTimes(1);

    expect(authorizeKeyMock).toHaveBeenCalledWith({
      actorEmail: "bob@example.com",
      action: "encrypt",
      keyName: "alice-key",
    });

    expect(getEncryptedKeyMaterialMock).not.toHaveBeenCalled();
  });

  it("does not read key material when authorization denies decrypt", async () => {
    const packed = Buffer.alloc(12 + 1 + 16, 1);
    const ciphertext = `vault:alice-key:${toBase64Url(packed)}`;

    await expect(
      service.decrypt(
        "bob@example.com",
        ciphertext,
      ),
    ).rejects.toMatchObject({
      code: "PERMISSION_DENIED",
    });

    expect(authorizeKeyMock).toHaveBeenCalledTimes(1);

    expect(authorizeKeyMock).toHaveBeenCalledWith({
      actorEmail: "bob@example.com",
      action: "decrypt",
      keyName: "alice-key",
    });

    expect(getEncryptedKeyMaterialMock).not.toHaveBeenCalled();
  });
});