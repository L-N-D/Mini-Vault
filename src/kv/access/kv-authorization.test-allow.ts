import type { KvAuthorizationPort } from "./kv-authorization.port.js";

/** Test-only adapter. Do not use in production/demo. */
export class TestAllowKvAuthorization implements KvAuthorizationPort {
  async assertAllowed(): Promise<void> {
    return;
  }
}
