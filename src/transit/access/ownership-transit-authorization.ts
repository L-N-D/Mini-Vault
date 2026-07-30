import { AppError } from "../../common/errors.js";
import type { AclRepository } from "../../acl/acl.repository.js";
import type { AuditService } from "../../audit/audit.service.js";
import type { TransitRepository } from "../transit.repository.js";
import type {
  AuthorizedKeyMetadata,
  TransitAuthorizationContext,
  TransitAuthorizationPort,
} from "./transit-authorization.port.js";

export class OwnershipTransitAuthorization implements TransitAuthorizationPort {
  constructor(
    private readonly repo: TransitRepository,
    private readonly audit: AuditService,
    private readonly aclRepo?: AclRepository,
  ) {}

  async authorizeKey(
    context: TransitAuthorizationContext,
  ): Promise<AuthorizedKeyMetadata> {
    const meta = this.repo.getKeyMetadata(context.keyName);

    if (!meta) {
      this.deny(context);
    }

    if (meta.ownerEmail === context.actorEmail) {
      return meta;
    }

    if (context.action === "verify" && meta.allowPublicVerify) {
      return meta;
    }

    // rotate is owner-only; never grant via ACL
    if (
      context.action !== "rotate" &&
      this.aclRepo?.hasPermission(
        "transit",
        context.keyName,
        context.actorEmail,
        context.action,
      )
    ) {
      return meta;
    }

    this.deny(context);
  }

  private deny(context: TransitAuthorizationContext): never {
    this.audit.denied({
      requesterEmail: context.actorEmail,
      targetType: "transit_key",
      targetValue: context.keyName,
      safeReasonCode: "PERMISSION_DENIED",
    });

    throw new AppError("PERMISSION_DENIED");
  }
}
