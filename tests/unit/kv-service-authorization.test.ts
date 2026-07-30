import { beforeEach, describe, expect, it, vi } from "vitest";

import { FakeClock } from "../../src/common/clock.js";
import { AppError } from "../../src/common/errors.js";
import { VaultState } from "../../src/core/vault-state.js";
import type { KvAuthorizationPort } from "../../src/kv/access/kv-authorization.port.js";
import type { KvRepository } from "../../src/kv/kv.repository.js";
import { KvService } from "../../src/kv/kv.service.js";

describe("KvService authorization boundary", () => {
  let repoGetMock: ReturnType<typeof vi.fn>;
  let repoUpsertMock: ReturnType<typeof vi.fn>;
  let repoDeleteMock: ReturnType<typeof vi.fn>;
  let assertAllowedMock: ReturnType<typeof vi.fn>;

  let repository: KvRepository;
  let authorization: KvAuthorizationPort;
  let vaultState: VaultState;
  let service: KvService;

  beforeEach(() => {
    repoGetMock = vi.fn();
    repoUpsertMock = vi.fn();
    repoDeleteMock = vi.fn();

    repository = {
      get: repoGetMock,
      upsert: repoUpsertMock,
      delete: repoDeleteMock,
    } as unknown as KvRepository;

    assertAllowedMock = vi
      .fn()
      .mockRejectedValue(new AppError("PERMISSION_DENIED"));

    authorization = {
      assertAllowed: assertAllowedMock,
    };

    vaultState = new VaultState();
    vaultState.setDek(Buffer.alloc(32, 1));

    service = new KvService(
      repository,
      vaultState,
      authorization,
      new FakeClock(),
    );
  });

  it("does not read from the repository when authorization denies read", async () => {
    await expect(
      service.read(
        "bob@example.com",
        "secret/alice@example.com/database",
      ),
    ).rejects.toMatchObject({
      code: "PERMISSION_DENIED",
    });

    expect(assertAllowedMock).toHaveBeenCalledTimes(1);

    expect(assertAllowedMock).toHaveBeenCalledWith({
      actorEmail: "bob@example.com",
      action: "read",
      path: "secret/alice@example.com/database",
    });

    expect(repoGetMock).not.toHaveBeenCalled();
  });

  it("does not read or write repository data when authorization denies write", async () => {
    await expect(
      service.write(
        "bob@example.com",
        "secret/alice@example.com/database",
        {
          password: "attempted-overwrite",
        },
      ),
    ).rejects.toMatchObject({
      code: "PERMISSION_DENIED",
    });

    expect(assertAllowedMock).toHaveBeenCalledTimes(1);

    expect(assertAllowedMock).toHaveBeenCalledWith({
      actorEmail: "bob@example.com",
      action: "write",
      path: "secret/alice@example.com/database",
    });

    expect(repoGetMock).not.toHaveBeenCalled();
    expect(repoUpsertMock).not.toHaveBeenCalled();
  });

  it("does not delete repository data when authorization denies delete", async () => {
    await expect(
      service.delete(
        "bob@example.com",
        "secret/alice@example.com/database",
      ),
    ).rejects.toMatchObject({
      code: "PERMISSION_DENIED",
    });

    expect(assertAllowedMock).toHaveBeenCalledTimes(1);

    expect(assertAllowedMock).toHaveBeenCalledWith({
      actorEmail: "bob@example.com",
      action: "delete",
      path: "secret/alice@example.com/database",
    });

    expect(repoDeleteMock).not.toHaveBeenCalled();
  });

  it("checks authorization before reading from the repository", async () => {
    const callOrder: string[] = [];

    assertAllowedMock.mockImplementation(async () => {
      callOrder.push("authorization");
    });

    repoGetMock.mockImplementation(() => {
      callOrder.push("repository");
      return null;
    });

    await expect(
      service.read(
        "alice@example.com",
        "secret/alice@example.com/database",
      ),
    ).rejects.toMatchObject({
      code: "NOT_FOUND",
    });

    expect(callOrder).toEqual([
      "authorization",
      "repository",
    ]);
  });
});