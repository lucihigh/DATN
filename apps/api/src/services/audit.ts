interface AuditEvent {
  actor: string;
  action: string;
  details?: string;
  timestamp?: string;
}

export const logAuditEvent = (event: AuditEvent) => {
  const payload = { ...event, timestamp: event.timestamp || new Date().toISOString() };
  // TODO: persist to DB AuditLog table
  console.log('[AUDIT]', payload);
};
