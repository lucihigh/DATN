// Simplified hand-authored OpenAPI types. Regenerate with `pnpm contract:gen` when pnpm is available.

export interface components {
  schemas: {
    RegisterRequest: { email: string; password: string; role: "USER" | "ADMIN" };
    LoginRequest: { email: string; password: string };
    AuthResponse: { token?: string; user?: components["schemas"]["User"] };
    User: { id: string; email: string; role: "USER" | "ADMIN" };
    Wallet: { id: string; balance: number; currency: string };
    DepositRequest: { amount: number };
    TransferRequest: { toUserId: string; amount: number };
    TransferResult: { status?: string; transaction?: components["schemas"]["Transaction"] };
    Transaction: { id: string; amount: number; type: string; description?: string; createdAt: string };
    LoginEvent: { userId: string; ipAddress: string; userAgent?: string; timestamp: string };
    AnomalyScore: { score?: number; reasons?: string[] };
    SecurityAlert: { id?: string; type?: string; message?: string; createdAt?: string };
    AuditLog: { id?: string; action?: string; actor?: string; details?: string; createdAt?: string };
    SecurityPolicy: { id?: string; maxLoginAttempts?: number; lockoutMinutes?: number; rateLimitPerMin?: number };
  };
}

// Paths are intentionally left minimal; add typed routes as needed.
export interface paths {}
