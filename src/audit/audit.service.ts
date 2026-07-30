import { createHash } from "node:crypto";
import type { Db } from "../storage/database.js";
import { GENESIS_HASH } from "../storage/database.js";
import type { Clock } from "../common/clock.js";

export interface AuditEvent {
  eventType: string;
  requesterEmail?: string | null;
  targetType?: string | null;
  targetValue?: string | null;
  result: string;
  safeReasonCode?: string | null;
}

export interface AuditChainVerifyResult {
  ok: boolean;
  checked: number;
  brokenAtId?: number;
}

function buildCanonical(parts: {
  prevHash: string;
  eventType: string;
  requesterEmail: string | null;
  targetType: string | null;
  targetValue: string | null;
  result: string;
  metadataJson: string | null;
  createdAt: string;
}): string {
  return [
    parts.prevHash,
    parts.eventType,
    parts.requesterEmail ?? "",
    parts.targetType ?? "",
    parts.targetValue ?? "",
    parts.result,
    parts.metadataJson ?? "",
    parts.createdAt,
  ].join("|");
}

export function hashAuditEntry(canonical: string): string {
  return createHash("sha256").update(canonical, "utf8").digest("hex");
}

export class AuditService {
  constructor(
    private readonly db: Db,
    private readonly clock: Clock,
  ) {}

  log(event: AuditEvent): void {
    const metadata = {
      safe_reason_code: event.safeReasonCode ?? null,
    };
    const metadataJson = JSON.stringify(metadata);
    const createdAt = this.clock.now().toISOString();

    const insert = this.db.transaction(() => {
      const last = this.db
        .prepare(
          `SELECT entry_hash_hex FROM audit_logs
           WHERE entry_hash_hex IS NOT NULL
           ORDER BY id DESC LIMIT 1`,
        )
        .get() as { entry_hash_hex: string } | undefined;
      const prevHash = last?.entry_hash_hex ?? GENESIS_HASH;
      const canonical = buildCanonical({
        prevHash,
        eventType: event.eventType,
        requesterEmail: event.requesterEmail ?? null,
        targetType: event.targetType ?? null,
        targetValue: event.targetValue ?? null,
        result: event.result,
        metadataJson,
        createdAt,
      });
      const entryHash = hashAuditEntry(canonical);
      this.db
        .prepare(
          `INSERT INTO audit_logs
           (event_type, requester_email, target_type, target_value, result,
            metadata_json, created_at, prev_hash_hex, entry_hash_hex)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          event.eventType,
          event.requesterEmail ?? null,
          event.targetType ?? null,
          event.targetValue ?? null,
          event.result,
          metadataJson,
          createdAt,
          prevHash,
          entryHash,
        );
    });
    insert();
  }

  denied(params: {
    requesterEmail: string;
    targetType: string;
    targetValue: string;
    safeReasonCode?: string;
  }): void {
    this.log({
      eventType: "ACCESS_DENIED",
      requesterEmail: params.requesterEmail,
      targetType: params.targetType,
      targetValue: params.targetValue,
      result: "DENIED",
      safeReasonCode: params.safeReasonCode ?? "PERMISSION_DENIED",
    });
  }

  verifyChain(): AuditChainVerifyResult {
    const rows = this.db
      .prepare(
        `SELECT id, event_type, requester_email, target_type, target_value,
                result, metadata_json, created_at, prev_hash_hex, entry_hash_hex
         FROM audit_logs ORDER BY id ASC`,
      )
      .all() as Array<{
      id: number;
      event_type: string;
      requester_email: string | null;
      target_type: string | null;
      target_value: string | null;
      result: string;
      metadata_json: string | null;
      created_at: string;
      prev_hash_hex: string | null;
      entry_hash_hex: string | null;
    }>;

    let expectedPrev = GENESIS_HASH;
    let checked = 0;
    for (const row of rows) {
      checked += 1;
      if (!row.prev_hash_hex || !row.entry_hash_hex) {
        return { ok: false, checked, brokenAtId: row.id };
      }
      if (row.prev_hash_hex !== expectedPrev) {
        return { ok: false, checked, brokenAtId: row.id };
      }
      const canonical = buildCanonical({
        prevHash: row.prev_hash_hex,
        eventType: row.event_type,
        requesterEmail: row.requester_email,
        targetType: row.target_type,
        targetValue: row.target_value,
        result: row.result,
        metadataJson: row.metadata_json,
        createdAt: row.created_at,
      });
      const expectedHash = hashAuditEntry(canonical);
      if (expectedHash !== row.entry_hash_hex) {
        return { ok: false, checked, brokenAtId: row.id };
      }
      expectedPrev = row.entry_hash_hex;
    }
    return { ok: true, checked };
  }
}
