import { AppError } from "../../common/errors.js";
import { emailFromSecretPath } from "../../common/kv-path.js";
import type { AclRepository } from "../../acl/acl.repository.js";
import type { AuditService } from "../../audit/audit.service.js";
import type {
  KvAuthorizationContext,
  KvAuthorizationPort,
} from "./kv-authorization.port.js";

/**
 * Ownership-based ACL (section 1.2), optionally extended by access_grants.
 * Path must be secret/<ownerEmail>/...
 */
export class OwnershipKvAuthorization implements KvAuthorizationPort {
  constructor(
    private readonly audit: AuditService,
    private readonly aclRepo?: AclRepository,
  ) {}

  async assertAllowed(context: KvAuthorizationContext): Promise<void> {
    let ownerEmail: string;
    try {
      ownerEmail = emailFromSecretPath(context.path);
    } catch {
      this.deny(context);
    }

    if (ownerEmail === context.actorEmail) {
      return;
    }

    if (
      this.aclRepo?.hasPermission(
        "kv",
        context.path,
        context.actorEmail,
        context.action,
      )
    ) {
      return;
    }

    this.deny(context);
  }

  private deny(context: KvAuthorizationContext): never {
    this.audit.denied({
      requesterEmail: context.actorEmail,
      targetType: "kv_path",
      targetValue: context.path,
      safeReasonCode: "PERMISSION_DENIED",
    });

    throw new AppError("PERMISSION_DENIED");
  }
}
