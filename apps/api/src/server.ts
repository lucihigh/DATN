import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import dotenv from "dotenv";
import fetch from "node-fetch";
import { loginSchema, registerSchema } from "@secure-wallet/shared";
import type { components } from "@secure-wallet/shared/api-client/types";
import { logAuditEvent } from "./services/audit";
import { applySecurityHeaders } from "./middleware/secureHeaders";
import { rateLimitPlaceholder } from "./middleware/rateLimit";
import { lockoutPlaceholder } from "./middleware/lockout";
import { connectMongo } from "./db/mongo";

dotenv.config();

const app = express();
app.use(cors());
app.use(helmet());
app.use(morgan("dev"));
app.use(express.json());
app.use(applySecurityHeaders);
app.use(rateLimitPlaceholder);
app.use(lockoutPlaceholder);

const PORT = process.env.PORT_API || 4000;
const AI_URL = process.env.AI_SERVICE_URL || "http://localhost:8000";

app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "api", timestamp: new Date().toISOString() });
});

app.post("/auth/register", (req, res) => {
  type RegisterReq = components["schemas"]["RegisterRequest"];
  const parsed = registerSchema.safeParse(req.body as RegisterReq);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }
  const user = {
    id: "user_" + Date.now(),
    email: parsed.data.email,
    role: parsed.data.role,
  };
  logAuditEvent({ actor: user.email, action: "REGISTER", details: "stubbed register" });
  res.status(201).json({ token: "jwt-placeholder", user });
});

app.post("/auth/login", async (req, res) => {
  type LoginReq = components["schemas"]["LoginRequest"];
  const parsed = loginSchema.safeParse(req.body as LoginReq);
  if (!parsed.success) {
    return res.status(400).json({ error: parsed.error.flatten() });
  }

  const loginEvent = {
    userId: "user_stub",
    ipAddress: req.ip,
    userAgent: req.headers["user-agent"] || "unknown",
    timestamp: new Date().toISOString(),
  };

  let aiResult: any = { score: 0.1, reasons: ["stubbed"] };
  try {
    const resp = await fetch(`${AI_URL}/ai/score`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(loginEvent),
    });
    aiResult = await resp.json();
  } catch (err) {
    console.warn("AI service not reachable, using default", err);
  }

  logAuditEvent({ actor: parsed.data.email, action: "LOGIN", details: `anomaly=${aiResult.score}` });

  const token = "jwt-placeholder";
  const user: components["schemas"]["User"] = {
    id: "user_stub",
    email: parsed.data.email,
    role: "USER",
  };
  res.json({ token, user, anomaly: aiResult });
});

app.post("/auth/logout", (_req, res) => {
  res.status(204).send();
});

// Contract placeholders below
app.get("/wallet/me", (_req, res) => {
  const wallet: components["schemas"]["Wallet"] = { id: "wallet1", balance: 0, currency: "USD" };
  res.json(wallet);
});

app.post("/wallet/deposit", (_req, res) => {
  res.json({ id: "wallet1", balance: 100, currency: "USD" });
});

app.post("/transfer", (_req, res) => {
  res.json({ status: "ok", transaction: { id: "txn1", amount: 10, type: "TRANSFER", createdAt: new Date().toISOString() } });
});

app.get("/transactions", (_req, res) => {
  res.json([]);
});

app.post("/security/login-events", (_req, res) => {
  res.json({ score: 0.1, reasons: ["stub"], received: _req.body });
});

app.get("/security/alerts", (_req, res) => {
  res.json([]);
});

app.get("/admin/users", (_req, res) => {
  res.json([]);
});

app.get("/admin/alerts", (_req, res) => {
  res.json([]);
});

app.get("/admin/audit-logs", (_req, res) => {
  res.json([]);
});

app.get("/admin/policies", (_req, res) => {
  res.json([]);
});

app.post("/admin/policies", (_req, res) => {
  res.json({ status: "updated" });
});

app.use((err: any, _req: any, res: any, _next: any) => {
  console.error(err);
  res.status(500).json({ error: "Internal error" });
});

const start = async () => {
  try {
    await connectMongo();
    app.listen(PORT, () => {
      console.log(`API listening on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error("Failed to start API (MongoDB connection)", err);
    process.exit(1);
  }
};

start();
