import { AppError } from "../../common/errors.js";
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
  ) {}

  async authorizeKey(
    context: TransitAuthorizationContext,
  ): Promise<AuthorizedKeyMetadata> {
    const meta = this.repo.getKeyMetadata(context.keyName);

    if (!meta || meta.ownerEmail !== context.actorEmail) {
      this.deny(context);
    }

    return meta;
  }

  private deny(context: TransitAuthorizationContext) : never {
    this.audit.denied({
      requesterEmail: context.actorEmail,
      targetType: "transit_key",
      targetValue: context.keyName,
      safeReasonCode: "PERMISSION_DENIED",
    });

    throw new AppError("PERMISSION_DENIED");
  }
}
