export type TransitProtectedAction =
  | "encrypt"
  | "decrypt"
  | "sign"
  | "verify"
  | "revoke";

export interface TransitAuthorizationContext {
  actorEmail: string;
  action: TransitProtectedAction;
  keyName: string;
}

export interface AuthorizedKeyMetadata {
  id: string;
  keyName: string;
  ownerEmail: string;
  keyUsage: "ENCRYPT_DECRYPT" | "SIGN_VERIFY";
  signingAlgorithm: "ED25519" | null;
}

export interface TransitAuthorizationPort {
  authorizeKey(
    context: TransitAuthorizationContext,
  ): Promise<AuthorizedKeyMetadata>;
}
