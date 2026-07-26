export type KvAction = "read" | "write" | "delete";

export interface KvAuthorizationContext {
  actorEmail: string;
  action: KvAction;
  path: string;
}

export interface KvAuthorizationPort {
  assertAllowed(context: KvAuthorizationContext): Promise<void>;
}
