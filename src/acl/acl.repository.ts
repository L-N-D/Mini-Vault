import type { Db } from "../storage/database.js";

export type ResourceType = "kv" | "transit";

export interface AccessGrantRow {
  id: string;
  resource_type: ResourceType;
  resource_id: string;
  grantee_email: string;
  permissions: string;
  granted_by: string;
  created_at: string;
}

export class AclRepository {
  constructor(private readonly db: Db) {}

  upsertGrant(row: AccessGrantRow): void {
    this.db
      .prepare(
        `INSERT INTO access_grants
           (id, resource_type, resource_id, grantee_email, permissions, granted_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(resource_type, resource_id, grantee_email)
         DO UPDATE SET
           permissions = excluded.permissions,
           granted_by = excluded.granted_by,
           created_at = excluded.created_at`,
      )
      .run(
        row.id,
        row.resource_type,
        row.resource_id,
        row.grantee_email,
        row.permissions,
        row.granted_by,
        row.created_at,
      );
  }

  revokeGrant(
    resourceType: ResourceType,
    resourceId: string,
    granteeEmail: string,
  ): boolean {
    const result = this.db
      .prepare(
        `DELETE FROM access_grants
         WHERE resource_type = ? AND resource_id = ? AND grantee_email = ?`,
      )
      .run(resourceType, resourceId, granteeEmail);
    return result.changes > 0;
  }

  listByResource(
    resourceType: ResourceType,
    resourceId: string,
  ): AccessGrantRow[] {
    return this.db
      .prepare(
        `SELECT id, resource_type, resource_id, grantee_email, permissions,
                granted_by, created_at
         FROM access_grants
         WHERE resource_type = ? AND resource_id = ?
         ORDER BY grantee_email`,
      )
      .all(resourceType, resourceId) as AccessGrantRow[];
  }

  findGrant(
    resourceType: ResourceType,
    resourceId: string,
    granteeEmail: string,
  ): AccessGrantRow | null {
    return (
      (this.db
        .prepare(
          `SELECT id, resource_type, resource_id, grantee_email, permissions,
                  granted_by, created_at
           FROM access_grants
           WHERE resource_type = ? AND resource_id = ? AND grantee_email = ?`,
        )
        .get(resourceType, resourceId, granteeEmail) as
        | AccessGrantRow
        | undefined) ?? null
    );
  }

  hasPermission(
    resourceType: ResourceType,
    resourceId: string,
    granteeEmail: string,
    action: string,
  ): boolean {
    const grant = this.findGrant(resourceType, resourceId, granteeEmail);
    if (!grant) return false;
    const perms = grant.permissions
      .split(",")
      .map((p) => p.trim())
      .filter((p) => p.length > 0);
    return perms.includes(action);
  }
}
