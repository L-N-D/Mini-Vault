import { beforeEach, describe, expect, it, vi } from "vitest";

import type { AuditService } from "../../src/audit/audit.service.js";
import { OwnershipKvAuthorization } from "../../src/kv/access/ownership-kv-authorization.js";

describe("OwnershipKvAuthorization", () => {
  let deniedMock: ReturnType<typeof vi.fn>;
  let audit: AuditService;
  let authorization: OwnershipKvAuthorization;

  beforeEach(() => {
    deniedMock = vi.fn();

    audit = {
      denied: deniedMock,
    } as unknown as AuditService;

    authorization = new OwnershipKvAuthorization(audit);
  });

  it("allows a user to access a path in their own namespace", async () => {
    await expect(
      authorization.assertAllowed({
        actorEmail: "alice@example.com",
        action: "read",
        path: "secret/alice@example.com/database",
      }),
    ).resolves.toBeUndefined();

    expect(deniedMock).not.toHaveBeenCalled();
  });

  it("denies access to a path owned by another user", async () => {
    await expect(
      authorization.assertAllowed({
        actorEmail: "bob@example.com",
        action: "read",
        path: "secret/alice@example.com/database",
      }),
    ).rejects.toMatchObject({
      code: "PERMISSION_DENIED",
    });

    expect(deniedMock).toHaveBeenCalledTimes(1);

    expect(deniedMock).toHaveBeenCalledWith({
      requesterEmail: "bob@example.com",
      targetType: "kv_path",
      targetValue: "secret/alice@example.com/database",
      safeReasonCode: "PERMISSION_DENIED",
    });
  });

  it.each(["write", "delete"] as const)(
    "denies cross-user %s access",
    async (action) => {
      await expect(
        authorization.assertAllowed({
          actorEmail: "bob@example.com",
          action,
          path: "secret/alice@example.com/database",
        }),
      ).rejects.toMatchObject({
        code: "PERMISSION_DENIED",
      });

      expect(deniedMock).toHaveBeenCalledTimes(1);
    },
  );

  it("does not authorize by partial or substring email matching", async () => {
    await expect(
      authorization.assertAllowed({
        actorEmail: "alice@example.com",
        action: "read",
        path: "secret/alice@example.com.attacker/database",
      }),
    ).rejects.toMatchObject({
      code: "PERMISSION_DENIED",
    });

    expect(deniedMock).toHaveBeenCalledTimes(1);
  });

  it("fails closed when the secret path is malformed", async () => {
    const malformedPath = "invalid/alice@example.com/database";

    await expect(
      authorization.assertAllowed({
        actorEmail: "alice@example.com",
        action: "read",
        path: malformedPath,
      }),
    ).rejects.toMatchObject({
      code: "PERMISSION_DENIED",
    });

    expect(deniedMock).toHaveBeenCalledTimes(1);

    expect(deniedMock).toHaveBeenCalledWith({
      requesterEmail: "alice@example.com",
      targetType: "kv_path",
      targetValue: malformedPath,
      safeReasonCode: "PERMISSION_DENIED",
    });
  });
});