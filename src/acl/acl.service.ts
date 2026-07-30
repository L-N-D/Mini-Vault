import { randomUUID } from "node:crypto";
import { AppError } from "../common/errors.js";
import {
  emailFromSecretPath,
  validateAndReturnCanonicalSecretPath,
} from "../common/kv-path.js";
import type { Clock } from "../common/clock.js";
import type { TransitRepository } from "../transit/transit.repository.js";
import type { AccessGrantRow, AclRepository, ResourceType } from "./acl.repository.js";

const KV_PERMISSIONS = new Set(["read", "write", "delete"]);
const TRANSIT_PERMISSIONS = new Set([
  "encrypt",
  "decrypt",
  "sign",
  "verify",
  "revoke",
]);

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function validatePermissions(
  resourceType: ResourceType,
  permissions: string[],
): string {
  if (!Array.isArray(permissions) || permissions.length === 0) {
    throw new AppError("INVALID_INPUT", "permissions must be a non-empty array");
  }
  const allowed =
    resourceType === "kv" ? KV_PERMISSIONS : TRANSIT_PERMISSIONS;
  const normalized: string[] = [];
  const seen = new Set<string>();
  for (const raw of permissions) {
    if (typeof raw !== "string" || raw.trim().length === 0) {
      throw new AppError("INVALID_INPUT", "Invalid permission value");
    }
    const perm = raw.trim();
    if (!allowed.has(perm)) {
      throw new AppError("INVALID_INPUT", `Permission not allowed: ${perm}`);
    }
    if (!seen.has(perm)) {
      seen.add(perm);
      normalized.push(perm);
    }
  }
  return normalized.join(",");
}

export class AclService {
  constructor(
    private readonly repo: AclRepository,
    private readonly transitRepo: TransitRepository,
    private readonly clock: Clock,
  ) {}

  grant(
    actorEmailRaw: string,
    resourceType: ResourceType,
    resourceIdRaw: string,
    granteeEmailRaw: string,
    permissions: string[],
  ): AccessGrantRow {
    const actorEmail = normalizeEmail(actorEmailRaw);
    const granteeEmail = normalizeEmail(granteeEmailRaw);
    if (!granteeEmail.includes("@") || granteeEmail.length > 254) {
      throw new AppError("INVALID_INPUT", "Invalid grantee email");
    }

    const resourceId = this.assertOwnerAndCanonicalize(
      actorEmail,
      resourceType,
      resourceIdRaw,
    );
    const permissionsCsv = validatePermissions(resourceType, permissions);
    const nowIso = this.clock.now().toISOString();
    const existing = this.repo.findGrant(resourceType, resourceId, granteeEmail);
    const row: AccessGrantRow = {
      id: existing?.id ?? randomUUID(),
      resource_type: resourceType,
      resource_id: resourceId,
      grantee_email: granteeEmail,
      permissions: permissionsCsv,
      granted_by: actorEmail,
      created_at: nowIso,
    };
    this.repo.upsertGrant(row);
    return row;
  }

  revoke(
    actorEmailRaw: string,
    resourceType: ResourceType,
    resourceIdRaw: string,
    granteeEmailRaw: string,
  ): void {
    const actorEmail = normalizeEmail(actorEmailRaw);
    const granteeEmail = normalizeEmail(granteeEmailRaw);
    const resourceId = this.assertOwnerAndCanonicalize(
      actorEmail,
      resourceType,
      resourceIdRaw,
    );
    const ok = this.repo.revokeGrant(resourceType, resourceId, granteeEmail);
    if (!ok) {
      throw new AppError("GRANT_NOT_FOUND");
    }
  }

  list(
    actorEmailRaw: string,
    resourceType: ResourceType,
    resourceIdRaw: string,
  ): AccessGrantRow[] {
    const actorEmail = normalizeEmail(actorEmailRaw);
    const resourceId = this.assertOwnerAndCanonicalize(
      actorEmail,
      resourceType,
      resourceIdRaw,
    );
    return this.repo.listByResource(resourceType, resourceId);
  }

  private assertOwnerAndCanonicalize(
    actorEmail: string,
    resourceType: ResourceType,
    resourceIdRaw: string,
  ): string {
    if (resourceType === "kv") {
      let path: string;
      try {
        path = validateAndReturnCanonicalSecretPath(resourceIdRaw);
      } catch (err) {
        if (err instanceof AppError) throw err;
        throw new AppError("INVALID_INPUT", "Invalid resource path");
      }
      const owner = emailFromSecretPath(path);
      if (owner !== actorEmail) {
        throw new AppError("PERMISSION_DENIED");
      }
      return path;
    }

    if (resourceType === "transit") {
      if (typeof resourceIdRaw !== "string" || resourceIdRaw.length === 0) {
        throw new AppError("INVALID_INPUT", "Invalid key name");
      }
      const meta = this.transitRepo.getKeyMetadata(resourceIdRaw);
      if (!meta) {
        throw new AppError("NOT_FOUND");
      }
      if (meta.ownerEmail !== actorEmail) {
        throw new AppError("PERMISSION_DENIED");
      }
      return meta.keyName;
    }

    const _exhaustive: never = resourceType;
    throw new AppError("INVALID_INPUT", `Unknown resource type: ${_exhaustive}`);
  }
}
