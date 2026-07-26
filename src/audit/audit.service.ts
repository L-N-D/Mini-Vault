import type { Db } from "../storage/database.js";
import type { Clock } from "../common/clock.js";

export interface AuditEvent {
  eventType: string;
  requesterEmail?: string | null;
  targetType?: string | null;
  targetValue?: string | null;
  result: string;
  safeReasonCode?: string | null;
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
    this.db
      .prepare(
        `INSERT INTO audit_logs
         (event_type, requester_email, target_type, target_value, result, metadata_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        event.eventType,
        event.requesterEmail ?? null,
        event.targetType ?? null,
        event.targetValue ?? null,
        event.result,
        JSON.stringify(metadata),
        this.clock.now().toISOString(),
      );
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
}
