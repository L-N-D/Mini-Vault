import { AppError } from "../../common/errors.js";
import type { KvAuthorizationPort } from "./kv-authorization.port.js";

export class KvAuthorizationPlaceholder implements KvAuthorizationPort {
  async assertAllowed(): Promise<void> {
    throw new AppError("AUTHORIZATION_NOT_IMPLEMENTED");
  }
}
