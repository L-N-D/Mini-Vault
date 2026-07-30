import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AuditService } from "../../src/audit/audit.service.js";
import type { TransitRepository } from "../../src/transit/transit.repository.js";
import { OwnershipTransitAuthorization } from "../../src/transit/access/ownership-transit-authorization.js";

describe("OwnershipTransitAuthorization", () => {
  let getKeyMetadataMock: ReturnType<typeof vi.fn>;
  let deniedMock: ReturnType<typeof vi.fn>;

  let repository: TransitRepository;
  let audit: AuditService;
  let authorization: OwnershipTransitAuthorization;

  beforeEach(() => {
    getKeyMetadataMock = vi.fn();
    deniedMock = vi.fn();

    repository = {
      getKeyMetadata: getKeyMetadataMock,
    } as unknown as TransitRepository;

    audit = {
      denied: deniedMock,
    } as unknown as AuditService;

    authorization = new OwnershipTransitAuthorization(repository, audit);
  });

  it("allows the owner to use their own named key", async () => {
    const metadata = {
      id: 1,
      keyName: "alice-key",
      ownerEmail: "alice@example.com",
      keyUsage: "ENCRYPT_DECRYPT",
      signingAlgorithm: null,
    } as const;

    getKeyMetadataMock.mockReturnValue(metadata);

    await expect(
      authorization.authorizeKey({
        actorEmail: "alice@example.com",
        action: "encrypt",
        keyName: "alice-key",
      }),
    ).resolves.toEqual(metadata);

    expect(getKeyMetadataMock).toHaveBeenCalledWith("alice-key");
    expect(deniedMock).not.toHaveBeenCalled();
  });

  it("denies a user from using another user's named key", async () => {
    getKeyMetadataMock.mockReturnValue({
      id: 1,
      keyName: "alice-key",
      ownerEmail: "alice@example.com",
      keyUsage: "ENCRYPT_DECRYPT",
      signingAlgorithm: null,
    });

    await expect(
      authorization.authorizeKey({
        actorEmail: "bob@example.com",
        action: "encrypt",
        keyName: "alice-key",
      }),
    ).rejects.toMatchObject({
      code: "PERMISSION_DENIED",
    });

    expect(deniedMock).toHaveBeenCalledTimes(1);

    expect(deniedMock).toHaveBeenCalledWith({
      requesterEmail: "bob@example.com",
      targetType: "transit_key",
      targetValue: "alice-key",
      safeReasonCode: "PERMISSION_DENIED",
    });
  });

  it("returns the same permission error when the named key does not exist", async () => {
    getKeyMetadataMock.mockReturnValue(undefined);

    await expect(
      authorization.authorizeKey({
        actorEmail: "bob@example.com",
        action: "encrypt",
        keyName: "missing-key",
      }),
    ).rejects.toMatchObject({
      code: "PERMISSION_DENIED",
    });

    expect(deniedMock).toHaveBeenCalledTimes(1);

    expect(deniedMock).toHaveBeenCalledWith({
      requesterEmail: "bob@example.com",
      targetType: "transit_key",
      targetValue: "missing-key",
      safeReasonCode: "PERMISSION_DENIED",
    });
  });
});