import type {
  AuthorizedKeyMetadata,
  TransitAuthorizationPort,
} from "./transit-authorization.port.js";

/** Test-only adapter. Do not use in production/demo. */
export class TestAllowTransitAuthorization implements TransitAuthorizationPort {
  constructor(private readonly metadata: AuthorizedKeyMetadata) {}

  async authorizeKey(): Promise<AuthorizedKeyMetadata> {
    return this.metadata;
  }
}
