import { AppError } from "../../common/errors.js";
import type { TransitAuthorizationPort } from "./transit-authorization.port.js";

export class TransitAuthorizationPlaceholder implements TransitAuthorizationPort {
  async authorizeKey(): Promise<never> {
    throw new AppError("AUTHORIZATION_NOT_IMPLEMENTED");
  }
}
