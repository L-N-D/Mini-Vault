import { AppError } from "../../common/errors.js";
import { emailFromSecretPath } from "../../common/kv-path.js";
import type { AuditService } from "../../audit/audit.service.js";
import type {
  KvAuthorizationContext,
  KvAuthorizationPort,
} from "./kv-authorization.port.js";

/**
 * Ownership-based ACL (section 1.2).
 * Path must be secret/<actorEmail>/...
 */
export class OwnershipKvAuthorization implements KvAuthorizationPort {
  constructor(private readonly audit: AuditService) {}

  async assertAllowed(context: KvAuthorizationContext): Promise<void> {
    let pathEmail: string;
    try {
      pathEmail = emailFromSecretPath(context.path);
    } catch {
      this.audit.denied({
        requesterEmail: context.actorEmail,
        targetType: "kv_path",
        targetValue: context.path,
        safeReasonCode: "PERMISSION_DENIED",
      });
      throw new AppError("PERMISSION_DENIED");
    }

    if (pathEmail !== context.actorEmail) {
      this.audit.denied({
        requesterEmail: context.actorEmail,
        targetType: "kv_path",
        targetValue: context.path,
        safeReasonCode: "PERMISSION_DENIED",
      });
      throw new AppError("PERMISSION_DENIED");
    }
  }
}
