import { createAuditLogRepository } from "../db/repositories";

interface AuditEvent {
  actor?: string;
  action: string;
  details?: string | Record<string, unknown>;
  userId?: string;
  ipAddress?: string;
}

export const logAuditEvent = async (event: AuditEvent) => {
  const payload = {
    ...event,
    actor: event.actor || "system",
    details: event.details,
  };

  try {
    await createAuditLogRepository().createAuditLog(payload);
  } catch (err) {
    // Audit should never block core API flow.
    console.warn("Failed to persist audit event", err);
  }

  console.log("[AUDIT]", payload);
};
