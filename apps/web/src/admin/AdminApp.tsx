import React, { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";

import { useAuth } from "../context/AuthContext";
import { API_BASE } from "../lib/apiBase";

import "../index.css";

type KpiCard = {
  title: string;
  value: string;
  delta: string;
  items: { label: string; value: string; color: string }[];
};

const MONTH_LABELS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

type AdminUser = {
  id: string;
  name: string;
  email: string;
  role: "Admin" | "User";
  title: string;
  phone: string;
  birthday: string;
  address: string;
  avatar: string;
  status: "Active" | "Locked";
  lastLogin: string;
};

type Transaction = {
  id: string;
  userId: string;
  date: string;
  type: "Payment" | "Transfer" | "Refund";
  amount: string;
  status: "Completed" | "Pending" | "Failed";
  reference: string;
};

type AdminUserApi = {
  id: string;
  email: string;
  role: "USER" | "ADMIN";
  status?: "ACTIVE" | "DISABLED" | "PENDING";
  fullName?: string;
  phone?: string;
  address?: string;
  createdAt?: string;
  lastLoginAt?: string;
};

type AdminTransactionApi = {
  id: string;
  amount: number;
  type: string;
  status: string;
  description?: string;
  createdAt: string;
  fromUserId?: string;
  toUserId?: string;
};

type AuditLogDoc = {
  _id: string;
  userId: string | null;
  actor?: string | null;
  action: string;
  details?: string | Record<string, unknown> | null;
  ipAddress?: string | null;
  metadata?: Record<string, unknown> | null;
  createdAt: string;
};

type AuditLogView = {
  id: string;
  ts: string;
  admin: string;
  category: string;
  categoryClass: "um" | "tx" | "acc" | "login" | "sec";
  detail: string;
  ip: string;
  status: "Success" | "Pending" | "Failed";
  statusClass: "ok" | "pending" | "fail";
  userAgent?: string;
  requestId?: string;
  location?: string;
};

type AlertSignal = {
  label: string;
  value: string;
  tone: "neutral" | "warn" | "info";
};

type AdminAlertStatus =
  | "pending_review"
  | "confirmed_risk"
  | "false_positive"
  | "escalated";

type AdminAlertApi = {
  id: string;
  type: "login" | "transaction";
  sourceAction: string;
  actor: string;
  userId: string | null;
  createdAt: string;
  ipAddress: string | null;
  riskLevel: "low" | "medium" | "high";
  anomalyScore: number;
  reasons: string[];
  summary: string;
  explanation: string;
  keySignals: AlertSignal[];
  adminStatus: AdminAlertStatus;
  adminNote?: string | null;
  reviewedAt?: string | null;
  reviewedBy?: string | null;
  monitoringOnly: boolean;
  aiDecision?: string | null;
  modelVersion?: string | null;
  modelSource?: string | null;
  eventId?: string | null;
  transactionId?: string | null;
  amount?: number | null;
  currency?: string | null;
  location?: string | null;
  paymentMethod?: string | null;
  merchantCategory?: string | null;
};

const AUDIT_ACTION_LABELS: Record<string, string> = {
  LOGIN_TRUSTED_IP: "Trusted Login",
  SESSION_REPLACED: "Session Replaced",
  FUNDS_FLOW_EVENT: "Funds Flow",
  TRANSFER_FLOW_STARTED: "Transfer Started",
  TRANSFER_FLOW_CANCELLED: "Transfer Cancelled",
  TRANSFER_ADVISORY_PRESENTED: "Transfer Warning",
  TRANSFER_ADVISORY_ACKNOWLEDGED: "Warning Accepted",
  TRANSFER_ADVISORY_DISMISSED: "Warning Dismissed",
  TRANSFER_SAFETY_BLOCKED: "Transfer Blocked",
  TRANSFER_OTP_SENT: "OTP Sent",
  TRANSFER_OTP_PREVERIFIED: "OTP Checked",
  TRANSFER_OTP_VERIFIED: "Transfer Confirmed",
  AI_TRANSACTION_ALERT: "AI Risk Alert",
  AI_TRANSACTION_SCORE: "AI Risk Check",
  AI_LOGIN_ALERT: "AI Login Alert",
  AI_LOGIN_SCORE: "AI Login Check",
};

const prettyAction = (action: string) =>
  AUDIT_ACTION_LABELS[action] ||
  action
    .toLowerCase()
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");

const formatUsdAmount = (amount?: number | null, currency?: string | null) => {
  if (amount == null || !Number.isFinite(amount)) return "Unknown";
  const suffix = currency?.trim() || "USD";
  return `${Number(amount).toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })} ${suffix}`;
};

const inferAuditCategoryClass = (
  action: string,
): AuditLogView["categoryClass"] => {
  const a = action.toUpperCase();
  if (a.includes("LOGIN") || a.includes("MFA")) return "login";
  if (
    a.includes("TRANSFER") ||
    a.includes("TRANSACTION") ||
    a.includes("WITHDRAW") ||
    a.includes("DEPOSIT") ||
    a.includes("PAYMENT") ||
    a.includes("REFUND")
  ) {
    return "tx";
  }
  if (a.includes("USER") || a.includes("ROLE")) return "um";
  if (
    a.includes("PROFILE") ||
    a.includes("PASSWORD") ||
    a.includes("ACCOUNT")
  ) {
    return "acc";
  }
  return "sec";
};

const inferAuditStatusClass = (
  action: string,
  details?: AuditLogDoc["details"],
): AuditLogView["statusClass"] => {
  const a = action.toUpperCase();
  const d =
    typeof details === "string"
      ? details.toUpperCase()
      : JSON.stringify(details ?? {}).toUpperCase();
  if (
    a.includes("FAIL") ||
    a.includes("BLOCK") ||
    a.includes("DENY") ||
    a.includes("ALERT") ||
    d.includes("FAIL") ||
    d.includes("BLOCK")
  ) {
    return "fail";
  }
  if (
    a.includes("PENDING") ||
    a.includes("REVIEW") ||
    d.includes("PENDING") ||
    d.includes("REVIEW")
  ) {
    return "pending";
  }
  return "ok";
};

const asTrimmedString = (value: unknown): string | undefined =>
  typeof value === "string" && value.trim() ? value.trim() : undefined;

const pickAuditString = (...values: Array<unknown>): string | undefined => {
  for (const value of values) {
    const normalized = asTrimmedString(value);
    if (normalized) return normalized;
  }
  return undefined;
};

const buildAuditLocationLabel = (
  source?: Record<string, unknown>,
  ipAddress?: string | null,
) => {
  const location =
    pickAuditString(
      source?.location,
      source?.city,
      [source?.city, source?.region, source?.country]
        .filter((part) => typeof part === "string" && part.trim())
        .join(", "),
      source?.country,
    ) ?? "";

  if (location) return location;
  const ip = asTrimmedString(ipAddress);
  if (!ip) return "";
  if (ip === "127.0.0.1") return "Local device";
  if (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
    ip === "::1"
  ) {
    return "Private network";
  }
  return `IP ${ip}`;
};

const formatAuditLocation = (value?: string) => {
  const normalized = asTrimmedString(value);
  if (!normalized) return "-";
  if (normalized === "Local device") return "Current device";
  if (normalized === "Private network") return "Private network";
  if (normalized.startsWith("IP ")) {
    return `IP: ${normalized.slice(3)}`;
  }
  return normalized;
};

const formatAlertOrigin = (
  location?: string | null,
  ipAddress?: string | null,
) => {
  const normalizedLocation = asTrimmedString(location);
  if (normalizedLocation) return normalizedLocation;

  const ip = asTrimmedString(ipAddress);
  if (!ip) return "Source unavailable";
  if (ip === "127.0.0.1" || ip === "::1") return "Local testing";
  if (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)
  ) {
    return "Private network";
  }
  return `IP ${ip}`;
};

const summarizeAuditUserAgent = (value?: string) => {
  const userAgent = asTrimmedString(value);
  if (!userAgent) return "-";

  const browser = userAgent.match(/Edg\/(\d+)/)?.[1]
    ? `Edge ${userAgent.match(/Edg\/(\d+)/)?.[1]}`
    : userAgent.match(/Chrome\/(\d+)/)?.[1]
      ? `Chrome ${userAgent.match(/Chrome\/(\d+)/)?.[1]}`
      : userAgent.match(/Firefox\/(\d+)/)?.[1]
        ? `Firefox ${userAgent.match(/Firefox\/(\d+)/)?.[1]}`
        : userAgent.match(/Version\/(\d+).+Safari\//)?.[1]
          ? `Safari ${userAgent.match(/Version\/(\d+).+Safari\//)?.[1]}`
          : "";

  const device = /Windows/i.test(userAgent)
    ? "Windows PC"
    : /Mac OS X/i.test(userAgent)
      ? "Mac"
      : /Android/i.test(userAgent)
        ? "Android"
        : /\biPhone\b|\biPad\b|\biOS\b/i.test(userAgent)
          ? "iPhone/iPad"
          : /Linux/i.test(userAgent)
            ? "Linux"
            : "Device";

  return [device, browser].filter(Boolean).join(" - ") || userAgent;
};

const formatAuditRequestId = (value?: string) => {
  const requestId = asTrimmedString(value);
  if (!requestId) return "-";
  if (requestId.length <= 18) return requestId;
  return `${requestId.slice(0, 8)}...${requestId.slice(-6)}`;
};

const mapAuditDocToView = (doc: AuditLogDoc): AuditLogView => {
  const detailsObj =
    doc.details && typeof doc.details === "object" ? doc.details : undefined;
  const metadataObj =
    doc.metadata && typeof doc.metadata === "object" ? doc.metadata : undefined;
  const detail =
    typeof doc.details === "string"
      ? doc.details
      : (typeof detailsObj?.message === "string" && detailsObj.message) ||
        (typeof detailsObj?.reason === "string" && detailsObj.reason) ||
        (typeof detailsObj?.detail === "string" && detailsObj.detail) ||
        (typeof detailsObj?.description === "string" &&
          detailsObj.description) ||
        (typeof metadataObj?.message === "string" && metadataObj.message) ||
        (typeof metadataObj?.reason === "string" && metadataObj.reason) ||
        prettyAction(doc.action);
  const categoryClass = inferAuditCategoryClass(doc.action);
  const statusClass = inferAuditStatusClass(doc.action, doc.details);
  const status =
    statusClass === "ok"
      ? "Success"
      : statusClass === "pending"
        ? "Pending"
        : "Failed";
  return {
    id: doc._id,
    ts: doc.createdAt,
    admin: doc.actor || "system",
    category: prettyAction(doc.action),
    categoryClass,
    detail,
    ip: doc.ipAddress || "unknown",
    status,
    statusClass,
    userAgent:
      pickAuditString(
        detailsObj?.userAgent,
        detailsObj?.currentUserAgent,
        detailsObj?.previousUserAgent,
        detailsObj?.device,
        metadataObj?.userAgent,
        metadataObj?.currentUserAgent,
        metadataObj?.previousUserAgent,
      ) ?? "",
    requestId:
      pickAuditString(
        detailsObj?.requestId,
        detailsObj?.eventId,
        detailsObj?.sessionId,
        detailsObj?.loginEventId,
        detailsObj?.transactionEventId,
        metadataObj?.requestId,
        metadataObj?.eventId,
        metadataObj?.sessionId,
        metadataObj?.loginEventId,
        metadataObj?.transactionEventId,
        doc._id,
      ) ?? "",
    location:
      buildAuditLocationLabel(detailsObj, doc.ipAddress) ||
      buildAuditLocationLabel(metadataObj, doc.ipAddress) ||
      "",
  };
};

const formatRiskLabel = (value: string) =>
  value ? `${value.charAt(0).toUpperCase()}${value.slice(1)} risk` : "Low risk";

const formatAlertStatusLabel = (value: AdminAlertStatus) => {
  switch (value) {
    case "confirmed_risk":
      return "Confirmed risk";
    case "false_positive":
      return "False positive";
    case "escalated":
      return "Escalated";
    default:
      return "Pending review";
  }
};

const formatAlertTypeLabel = (value: AdminAlertApi["type"]) =>
  value === "transaction" ? "Transaction" : "Login";

const parseCurrencyAmount = (value: string): number => {
  const parsed = Number(value.replace(/[^0-9.-]/g, ""));
  return Number.isFinite(parsed) ? parsed : 0;
};

const parseDateLoose = (value: string): Date | null => {
  const date = new Date(value);
  if (!Number.isNaN(date.getTime())) return date;
  const fallback = new Date(value.replace(" ", "T"));
  return Number.isNaN(fallback.getTime()) ? null : fallback;
};

const startOfDay = (date: Date) =>
  new Date(date.getFullYear(), date.getMonth(), date.getDate());

const endOfDay = (date: Date) =>
  new Date(
    date.getFullYear(),
    date.getMonth(),
    date.getDate(),
    23,
    59,
    59,
    999,
  );

const addDays = (date: Date, amount: number) => {
  const next = new Date(date);
  next.setDate(next.getDate() + amount);
  return next;
};

const addMonths = (date: Date, amount: number) =>
  new Date(date.getFullYear(), date.getMonth() + amount, date.getDate());

const addYears = (date: Date, amount: number) =>
  new Date(date.getFullYear() + amount, date.getMonth(), date.getDate());

const getWeekStart = (date: Date) => {
  const normalized = startOfDay(date);
  const day = normalized.getDay();
  const diff = day === 0 ? -6 : 1 - day;
  return addDays(normalized, diff);
};

const isWithinRange = (date: Date | null, start: Date, end: Date) =>
  Boolean(
    date &&
    date.getTime() >= start.getTime() &&
    date.getTime() <= end.getTime(),
  );

const formatMoneyCompact = (amount: number) =>
  `$${amount.toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;

const styles = `
  .ana-page {
    background: #f6f7fb;
    min-height: 100vh;
    padding: 28px 32px 40px;
    color: #1f2937;
    font-family: "Inter", "Segoe UI", sans-serif;
  }
  .ana-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 14px;
  }
  .ana-status-banner {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
    padding: 14px 16px;
    border-radius: 14px;
    margin-bottom: 16px;
    border: 1px solid transparent;
  }
  .ana-status-banner strong {
    display: block;
    margin-bottom: 4px;
    font-size: 14px;
  }
  .ana-status-banner p {
    margin: 0;
    font-size: 13px;
    line-height: 1.5;
  }
  .ana-status-banner.error {
    background: rgba(127, 29, 29, 0.2);
    border-color: rgba(248, 113, 113, 0.35);
    color: #fecaca;
  }
  .ana-status-banner.loading {
    background: rgba(37, 99, 235, 0.12);
    border-color: rgba(96, 165, 250, 0.35);
    color: #bfdbfe;
  }
  .ana-title h1 { margin: 0; font-size: 26px; }
  .ana-title p { margin: 2px 0 0; color: #6b7280; }
  .ana-actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .ana-segmented {
    display: inline-flex;
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
    background: var(--panel);
    box-shadow: 0 10px 28px rgba(15,23,42,0.16);
  }
  .ana-segmented button {
    border: none;
    background: transparent;
    padding: 8px 16px;
    font-weight: 700;
    color: var(--muted);
    cursor: pointer;
  }
  .ana-segmented button.active {
    background: linear-gradient(135deg, #e0e7ff, #ede9fe);
    color: #5b21b6;
  }
  .ana-pill {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 10px 12px;
    border-radius: 12px;
    border: 1px solid var(--border);
    background: var(--panel);
    color: var(--text);
    box-shadow: 0 10px 28px rgba(15,23,42,0.16);
  }
  .ana-date {
    border: none;
    background: transparent;
    outline: none;
    color: var(--text);
    font-weight: 600;
    font-size: 14px;
    min-width: 180px;
    cursor: pointer;
  }
  .ana-icon-btn {
    width: 38px; height: 38px;
    border-radius: 12px;
    border: 1px solid #e2e8f0;
    background: #fff;
    display: grid; place-items: center;
    cursor: pointer;
    box-shadow: 0 6px 16px rgba(0,0,0,0.04);
  }

  .ana-kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; margin-bottom: 18px; }
  .ana-card {
    background: #fff;
    border-radius: 16px;
    box-shadow: 0 10px 28px rgba(15, 23, 42, 0.08);
    padding: 16px 18px;
  }
  .ana-card h4 { margin: 0 0 10px; color: #9ca3af; letter-spacing: 0.2px; font-size: 13px; text-transform: uppercase; }
  .ana-kpi-head { display:flex; align-items:center; justify-content: space-between; color:#6b7280; font-size:13px; margin-bottom:6px; }
  .ana-kpi-value { margin:0 0 6px; font-size:28px; font-weight:800; color:#111827; }
  .ana-kpi-list { list-style:none; padding:0; margin:0; display:grid; gap:6px; }
  .ana-kpi-list li { display:flex; align-items:center; gap:8px; color:#4b5563; font-size:14px; }
  .ana-kpi-list strong { margin-left:auto; color:#111827; }
  .ana-dot { width:10px; height:10px; border-radius:50%; display:inline-block; }
  .ana-delta.up { color:#10b981; font-weight:700; }
  .ana-delta.down { color:#ef4444; font-weight:700; }

  .ana-grid-main { display:grid; grid-template-columns: 2.1fr 0.9fr; gap:16px; margin-bottom:16px; }
  .ana-bar-chart { display:grid; grid-template-columns: repeat(12, 1fr); gap:12px; align-items:end; height:260px; }
  .ana-bar-item {
    height:100%;
    display:flex;
    flex-direction:column;
    justify-content:flex-end;
    text-align:center;
    min-height:0;
  }
  .ana-bar {
    width:100%;
    background:#5b21b6;
    border-radius:10px 10px 6px 6px;
    min-height:0;
  }
  .ana-bar-label { margin-top:6px; font-size:12px; color:#6b7280; }
  .ana-chart-empty {
    height:100%;
    display:grid;
    place-items:center;
    color:#6b7280;
    font-size:14px;
  }
  .ana-chart-head {
    display:flex; align-items:center; justify-content:space-between;
    margin-bottom:8px; color:#9ca3af; font-weight:700; letter-spacing:0.2px;
    gap:12px; flex-wrap: nowrap;
  }
  .ana-chart-head > span:first-child { white-space: nowrap; }

  .ana-pie-wrap { display:flex; flex-direction:column; align-items:center; gap:12px; }
  .ana-pie {
    position:relative; width:180px; height:180px;
    background: conic-gradient(#5b21b6 0 33%, #7c3aed 33% 62%, #a78bfa 62% 77%, #c4b5fd 77% 87%, #e0e7ff 87% 100%);
    border-radius:50%; box-shadow: inset 0 0 0 14px #fff;
  }
  .ana-pie-center {
    position:absolute; inset:50% auto auto 50%; transform:translate(-50%,-50%);
    background:#fff; width:90px; height:90px; border-radius:50%;
    display:grid; place-items:center; font-weight:700; color:#4b5563;
    box-shadow:0 4px 14px rgba(0,0,0,0.06);
  }
  .ana-legend { list-style:none; padding:0; margin:0; display:grid; gap:10px; width:100%; }
  .ana-legend li { display:grid; grid-template-columns:auto 1fr auto; gap:8px; align-items:center; font-size:14px; color:#374151; }
  .ana-legend .value { font-weight:700; }
  .ana-muted { color:#6b7280; font-size:13px; margin:0; }

  .ana-bottom-grid { display:grid; grid-template-columns: 1.2fr 0.8fr; gap:14px; }
  .ana-hbar-list { display:grid; gap:14px; }
  .ana-hbar-row { display:grid; grid-template-columns:110px 1fr; gap:10px; align-items:center; color:#4b5563; font-size:14px; }
  .ana-hbar-row .label { font-weight:600; }
  .ana-hbar-track { position:relative; height:12px; background:#eef2ff; border-radius:8px; }
  .ana-hbar-prev { position:absolute; inset:0; background:#c7d2fe; border-radius:8px; }
  .ana-hbar-now { position:absolute; inset:0; background:#5b21b6; border-radius:8px; }

  .ana-dual-chart { display:grid; grid-template-columns: repeat(8, 1fr); gap:12px; align-items:end; height:180px; }
  .ana-dual-bars { display:grid; grid-template-columns: repeat(2, 1fr); gap:6px; align-items:end; height:120px; }
  .ana-dual-now { background:#5b21b6; border-radius:8px 8px 6px 6px; }
  .ana-dual-prev { background:#c7d2fe; border-radius:8px 8px 6px 6px; }
  .ana-dual-label { margin-top:6px; font-size:12px; color:#6b7280; text-align:center; }

  /* Lighten admin shell */
  .mf-main {
    background: #f6f7fb;
    margin-left: 260px;
    width: calc(100% - 260px);
    min-height: 100vh;
  }
  .mf-main.no-scroll {
    overflow: hidden;
    height: 100dvh;
  }
  .mf-main.audit-view {
    display: flex;
    flex-direction: column;
  }
  .mf-main.users-view {
    display: flex;
    flex-direction: column;
  }
  .ana-page.no-scroll { padding: 0; }
  .mf-sidebar {
    position: fixed;
    top: 0;
    left: 0;
    bottom: 0;
    z-index: 20;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    background: #ffffff;
    border-right: 1px solid #e5e7eb;
    color: #111827;
  }
  .mf-menu {
    display: flex;
    flex-direction: column;
    flex: 1;
  }
  .mf-menu li:last-child { margin-top: auto; }

  /* Sidebar icons */
  .mf-menu button {
    width: 100%; display: flex; align-items: center; gap: 14px; padding: 14px 16px;
    background: transparent; border: none; color: #111827; text-align: left;
    border-radius: 12px; cursor: pointer; transition: all 0.2s; font-size: 16px; font-weight: 700;
  }
  .mf-menu button:hover, .mf-menu button.active { background: #e8edfb; color: #111827; }
  .mf-ico {
    width: 32px; height: 32px;
    border-radius: 50%;
    display: grid; place-items: center;
    font-size: 16px;
    background: #e8edfb;
    color: #1f2937;
    flex-shrink: 0;
  }
  .mf-ico.users, .mf-ico.audit, .mf-ico.profile, .mf-ico.setting, .mf-ico.logout {
    background: #e8edfb;
    color: #1f2937;
  }
  .mf-menu button.active .mf-ico {
    background: #2563eb;
    color: #ffffff;
  }
  .mf-logo { color: #111827; }

  /* User management */
  .user-card {
    background:#fff;
    border-radius:16px;
    padding:20px;
    box-shadow:0 10px 28px rgba(0,0,0,0.08);
    display:flex;
    flex:1;
    flex-direction:column;
    min-height:calc(100vh - 56px);
  }
  .user-head { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:18px; }
  .user-actions { display:flex; gap:10px; align-items:center; }
  .user-search { padding:10px 12px; border:1px solid #e5e7eb; border-radius:10px; min-width:220px; }
  .user-table-wrap { overflow:auto; flex:1; min-height:0; }
  .user-table { width:100%; border-collapse:collapse; }
  .user-table th, .user-table td { padding:10px 10px; text-align:left; border-bottom:1px solid #eceff5; font-size:14px; vertical-align:middle; }
  .user-table td { line-height:1.25; }
  .user-person { display:flex; gap:12px; align-items:center; min-height:42px; }
  .user-contact { display:grid; gap:4px; }
  .user-action-group { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  .user-badge { padding:4px 10px; border-radius:12px; font-weight:700; font-size:12px; display:inline-block; }
  .user-badge.active { background:#d1fae5; color:#0f5132; border:1px solid #a7f3d0; }
  .user-badge.locked { background:#ffe4e6; color:#b91c1c; border:1px solid #fecdd3; }
  .user-btn { padding:8px 12px; border-radius:10px; border:1px solid #d8ddee; background:#f8fafc; cursor:pointer; font-weight:600; }
  .user-btn.primary { background:#1f6bff; color:white; border-color:#1f6bff; }
  .user-btn.text { border:none; background:transparent; color:#1f6bff; padding:6px 8px; }
  .user-btn.danger { border-color:#fda4af; color:#b91c1c; background:#fff1f2; }
  .user-btn:hover { filter:brightness(0.97); }
  .user-btn.text:hover { text-decoration:underline; filter:none; }
  .user-btn.danger:hover { filter:brightness(0.95); }
  .user-row { background:#fff; }
  .user-avatar { width:48px; height:48px; border-radius:50%; object-fit:cover; }
  .user-name { font-weight:700; }
  .user-title { color:#6b7280; font-size:13px; }
  .user-tabs { display:flex; gap:10px; margin:16px 0 4px; }
  .user-tab { padding:10px 16px; border-radius:10px; border:1px solid #e5e7eb; background:#f8fafc; cursor:pointer; font-weight:700; color:#4b5563; }
  .user-tab.active { background:#e8edfb; color:#1f6bff; border-color:#d0dafc; }
  .user-filter-btn { padding:10px 14px; border-radius:12px; border:1px solid #e5e7eb; background:#fff; display:flex; gap:8px; align-items:center; cursor:pointer; }
  .user-filter-pop { position:relative; }
  .user-filter-panel {
    position:absolute; top:calc(100% + 8px); right:0; z-index:20;
    min-width:260px; background:#fff; border:1px solid #e5e7eb; border-radius:12px;
    box-shadow:0 14px 30px rgba(15,23,42,0.12); padding:12px; display:grid; gap:10px;
  }
  .user-filter-panel label { display:grid; gap:6px; font-size:12px; color:#6b7280; font-weight:700; }
  .user-filter-panel select { padding:8px 10px; border:1px solid #e5e7eb; border-radius:10px; background:#fff; color:#0f172a; }
  .user-filter-actions { display:flex; justify-content:flex-end; }
  .user-filter-actions button { padding:6px 10px; border-radius:8px; border:1px solid #d8ddee; background:#f8fafc; cursor:pointer; }
  .theme-dark .user-filter-btn { background:#0f1934; border:1px solid #1b2748; color:#e7ecff; }
  .theme-dark .user-filter-panel { background:#0f162e; border:1px solid #1b2748; box-shadow:0 16px 32px rgba(0,0,0,0.35); }
  .theme-dark .user-filter-panel label { color:#a3b1d6; }
  .theme-dark .user-filter-panel select { background:#0f1934; border:1px solid #1b2748; color:#e7ecff; }
  .theme-dark .user-filter-actions button { background:#162143; border:1px solid #1b2748; color:#e7ecff; }
  .user-footer { padding:12px 0 6px; color:#6b7280; font-size:13px; display:flex; justify-content:space-between; align-items:center; margin-top:auto; }
  .pager { display:flex; gap:8px; }
  .pager button { width:34px; height:34px; border-radius:8px; border:1px solid #e5e7eb; background:#fff; cursor:pointer; }
  .pager button.active { background:#1f6bff; color:#fff; border-color:#1f6bff; }

  /* Profile */
  .prof-page { padding: 16px; display:flex; justify-content:center; }
  .no-scroll .prof-page {
    height: 100%;
    overflow: hidden;
    align-items: center;
  }
  .prof-card {
    background: #ffffff;
    color: #0f172a;
    border-radius: 18px;
    padding: 16px;
    box-shadow: 0 18px 46px rgba(15,23,42,0.08);
    border: 1px solid #e5e7eb;
    width: min(840px, 100%);
  }
  .no-scroll .prof-card {
    max-height: calc(100dvh - 32px);
    overflow: hidden;
  }
  .prof-header { display:flex; flex-direction:column; align-items:center; gap:6px; margin-bottom:10px; color:#0f172a; }
  .prof-avatar-wrap { position:relative; width:84px; height:84px; }
  .prof-avatar { width:84px; height:84px; border-radius:50%; object-fit:cover; border:3px solid #182449; cursor:pointer; }
  .prof-avatar-btn {
    position:absolute; right:6px; bottom:6px;
    width:34px; height:34px; border-radius:50%;
    background:#1f6bff; border:none; color:white;
    display:grid; place-items:center; cursor:pointer;
    box-shadow:0 10px 20px rgba(31,107,255,0.4);
  }
  .prof-name { font-size:16px; margin:2px 0 0; font-weight:700; color:#0f172a; }
  .prof-email { margin:0; color:#475569; }
  .prof-grid {
    display:grid;
    grid-template-columns: repeat(2, minmax(280px, 1fr));
    gap:10px 12px;
    margin-bottom:10px;
  }
  .prof-field { display:flex; flex-direction:column; gap:6px; }
  .prof-field label { color:#6b7280; font-size:12px; }
  .prof-field input {
    background:#f8fafc;
    border:1px solid #dfe3ea;
    color:#0f172a;
    padding:8px 10px;
    border-radius:12px;
    font-size:13px;
  }
  .prof-actions { display:flex; justify-content:flex-end; margin-top:6px; }
  .prof-save {
    background:#2563eb;
    color:white;
    border:none;
    border-radius:12px;
    padding:12px 18px;
    font-weight:700;
    cursor:pointer;
    box-shadow:0 10px 24px rgba(37,99,235,0.28);
  }

  /* Admin theme helpers */
  .theme-light { background: #f6f7fb; color: #0f172a; }
  .theme-dark { background: #0b1224; color: #e7ecff; }
  body.admin-profile-no-scroll { overflow: hidden; }
  .theme-light h1, .theme-light h2, .theme-light h3, .theme-light h4, .theme-light h5, .theme-light h6,
  .theme-light p, .theme-light span, .theme-light label, .theme-light td, .theme-light th, .theme-light li, .theme-light strong { color:#0f172a; }
  .theme-dark h1, .theme-dark h2, .theme-dark h3, .theme-dark h4, .theme-dark h5, .theme-dark h6,
  .theme-dark p, .theme-dark span, .theme-dark label, .theme-dark td, .theme-dark th, .theme-dark li, .theme-dark strong { color:#e7ecff; }
  .theme-dark .mf-main { background: #0b1224; }
  .theme-dark .mf-sidebar {
    background: linear-gradient(180deg, #0f172d 0%, #0c1327 100%);
    border-right: 1px solid #101a35;
    color: #e7ecff;
  }
  .theme-dark .mf-menu button { color: #e7ecff; }
  .theme-dark .mf-menu button:hover,
  .theme-dark .mf-menu button.active { background: #162143; color: #e7ecff; }
  .theme-dark .mf-ico { background: #111c35; color: #9cbcf9; }
  .theme-dark .mf-menu button.active .mf-ico { background: #1f6bff; color: #e7ecff; }
  .theme-dark .mf-logo { color: #e7ecff; }
  .theme-dark .prof-card {
    background: linear-gradient(180deg, #0f172d 0%, #0b1224 100%);
    color: #e7ecff;
    border: 1px solid #101a35;
    box-shadow: 0 20px 46px rgba(0,0,0,0.38);
  }
  .theme-dark .prof-email { color: #a3b1d6; }
  .theme-dark .prof-field label { color: #a3b1d6; }
  .theme-dark .prof-field input {
    background:#0f162e;
    border:1px solid #1b2748;
    color:#e7ecff;
  }
  .theme-dark .set-card { background:#0f162e; border:1px solid #1b2748; box-shadow:0 16px 32px rgba(0,0,0,0.35); color:#e7ecff; }
  .theme-dark .set-row { border-color:#1b2748; }
  .theme-dark .set-row p { color:#7f8bad; }
  .theme-dark .set-toggle { background:#2a3550; }
  .theme-dark .set-toggle.on { background:#5b21b6; }
  .theme-dark .user-card,
  .theme-dark .audit-card { background:#0f162e; border:1px solid #1b2748; box-shadow:0 16px 32px rgba(0,0,0,0.35); }
  .theme-dark .user-tab { background:#0f1934; border-color:#1b2748; color:#ffffff; }
  .theme-dark .user-tab.active { background:#1f6bff; border-color:#1f6bff; color:#ffffff; }
  .theme-dark .user-btn { background:#162143; border:1px solid #1b2748; color:#ffffff; }
  .theme-dark .user-btn.primary { background:#1f6bff; border-color:#1f6bff; color:#ffffff; }
  .theme-dark .user-btn.text { background:#0f1934; border:none; color:#8fb7ff; }
  .theme-dark .pager button { background:#162143; border:1px solid #1b2748; color:#ffffff; }
  .theme-dark .pager button.active { background:#1f6bff; border-color:#1f6bff; color:#ffffff; }
  .theme-dark .user-card h2,
  .theme-dark .user-head h2,
  .theme-dark .user-head h1 { color:#ffffff; }
  .theme-dark .user-search { background:#0f1934; border:1px solid #1b2748; color:#e7ecff; }
  .theme-dark .user-btn { background:#0f1934; border:1px solid #1b2748; color:#e7ecff; }
  .theme-dark .user-btn.primary { background:#1f6bff; border-color:#1f6bff; color:#fff; }
  .theme-dark .user-head h2 { color:#e7ecff; }
  .theme-dark .user-name { color:#e7ecff; }
  .theme-dark .user-title { color:#a3b1d6; }
  .theme-dark .user-footer { color:#a3b1d6; }
  .theme-dark .user-table th,
  .theme-dark .audit-table th,
  .theme-dark .tx-table th { background:#0f1934; color:#a3b1d6; border-color:#1b2748; }
  .theme-dark .user-table td,
  .theme-dark .audit-table td,
  .theme-dark .tx-table td { background:#0b1224; color:#e7ecff; border-color:#1b2748; }
  .theme-dark .user-row { background:#0b1224; }
  .theme-dark .tx-modal { background:#0f162e; border:1px solid #1b2748; box-shadow:0 20px 46px rgba(0,0,0,0.38); }
  .theme-dark .tx-head { border-color:#1b2748; }
  .theme-dark .tx-chip.completed { background:#12351c; border-color:#1f5c2d; color:#c8fdd7; }
  .theme-dark .tx-chip.pending { background:#3c2a14; border-color:#5a381c; color:#ffd7a3; }
  .theme-dark .tx-chip.failed { background:#3a1c1c; border-color:#5a2a2a; color:#f8c2c2; }

  /* Light inputs stay white with dark text */
  .theme-light input,
  .theme-light .user-search { background:#ffffff; color:#0f172a; border:1px solid #dfe3ea; }

  /* Dark dashboard panels */
  .theme-dark .ana-page { background:#0b1224; color:#e7ecff; }
  .theme-dark .ana-card,
  .theme-dark .ana-panel,
  .theme-dark .ana-section,
  .theme-dark .ana-block {
    background:#0f162e;
    border:1px solid #1b2748;
    box-shadow:0 16px 32px rgba(0,0,0,0.35);
    color:#e7ecff;
  }
  .theme-dark .ana-kpi-head,
  .theme-dark .ana-kpi-list li,
  .theme-dark .ana-chart-head,
  .theme-dark .ana-muted,
  .theme-dark .ana-hbar-row,
  .theme-dark .ana-legend li,
  .theme-dark .ana-legend .value { color:#a3b1d6; }
  .theme-dark .ana-hbar-track { background:#162143; }
  .theme-dark .ana-hbar-prev { background:#20305a; }
  .theme-dark .ana-hbar-now { background:#5b21b6; }
  .theme-dark .ana-pie { box-shadow: inset 0 0 0 14px #0f162e; }
  .theme-dark .ana-segmented { border-color:#1b2748; background:#0f162e; box-shadow:0 12px 26px rgba(0,0,0,0.38); }
  .theme-dark .ana-segmented button { color:#a3b1d6; }
  .theme-dark .ana-segmented button.active { background: linear-gradient(135deg,#1f293a,#162143); color:#8fb7ff; }

  /* Setting */
  .set-card { background:#fff; border-radius:16px; padding:20px; box-shadow:0 10px 28px rgba(0,0,0,0.08); }
  .set-row { display:flex; align-items:center; justify-content:space-between; padding:12px 0; border-bottom:1px solid #e5e7eb; }
  .set-row:last-child { border-bottom:none; }
  .set-row h4 { margin:0; font-size:15px; }
  .set-row p { margin:4px 0 0; color:#6b7280; font-size:13px; }
  .set-toggle { width:44px; height:24px; border-radius:12px; background:#e5e7eb; border:none; position:relative; cursor:pointer; }
  .set-toggle::after {
    content:"";
    position:absolute; top:3px; left:4px; width:18px; height:18px; border-radius:50%; background:white; box-shadow:0 1px 4px rgba(0,0,0,0.3);
    transition:transform 0.15s;
  }
  .set-toggle.on { background:#5b21b6; }
  .set-toggle.on::after { transform: translateX(18px); }

  /* Transactions modal */
  .tx-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(15, 23, 42, 0.36);
    display: grid;
    place-items: center;
    z-index: 50;
    padding: 16px;
  }
  .tx-modal {
    background: #fff;
    border-radius: 16px;
    box-shadow: 0 24px 64px rgba(0, 0, 0, 0.22);
    max-width: 820px;
    width: min(100%, 820px);
    max-height: min(80vh, 900px);
    overflow: auto;
  }
  .tx-head {
    display:flex; justify-content:space-between; align-items:center;
    padding: 18px 22px; border-bottom:1px solid #e5e7eb;
  }
  .tx-head h3 { margin:0; font-size:20px; }
  .tx-close { border:none; background:transparent; font-size:18px; cursor:pointer; color:#6b7280; }
  .tx-table { width:100%; border-collapse:collapse; font-size:14px; }
  .tx-table th, .tx-table td { padding:12px 16px; border-bottom:1px solid #f1f5f9; text-align:left; }
  .tx-table th { background:#f8fafc; color:#475569; }
  .tx-chip {
    display:inline-flex; align-items:center; gap:6px;
    padding:6px 10px; border-radius:10px; font-weight:700; font-size:12px;
  }
  .tx-chip.completed { background:#ecfdf3; color:#166534; border:1px solid #bbf7d0; }
  .tx-chip.pending { background:#fff7ed; color:#c2410c; border:1px solid #fed7aa; }
  .tx-chip.failed { background:#fef2f2; color:#b91c1c; border:1px solid #fecdd3; }

  /* Audit log */
  .audit-card {
    background: radial-gradient(circle at 8% -30%, rgba(36, 113, 255, 0.25), transparent 35%), #061527;
    border: 1px solid #1a3351;
    border-radius: 16px;
    box-shadow: 0 22px 40px rgba(4, 11, 24, 0.45);
    padding: 18px;
    color: #d6e6ff;
    display: flex;
    flex: 1;
    flex-direction: column;
    min-height: calc(100dvh - 56px);
  }
  .audit-tabs { display:flex; align-items:center; gap:18px; border-bottom:1px solid #1d3552; padding-bottom:10px; margin-bottom:16px; }
  .audit-tab {
    border:none;
    background:transparent;
    color:#7a95b8;
    font-size:16px;
    font-weight:700;
    padding:4px 0 10px;
    cursor:pointer;
    position:relative;
  }
  .audit-tab.active { color:#1e90ff; }
  .audit-tab.active::after {
    content:"";
    position:absolute;
    left:0;
    right:0;
    bottom:-11px;
    height:2px;
    background:#1e90ff;
    border-radius:2px;
  }
  .audit-head { display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap; margin-bottom:16px; }
  .audit-filters { display:flex; gap:10px; flex-wrap:wrap; }
  .audit-select {
    appearance:none;
    min-width:170px;
    padding:10px 34px 10px 12px;
    border:1px solid #2a4767;
    border-radius:10px;
    background:#0f243d;
    color:#e8f1ff;
    font-weight:600;
    font-size:14px;
    cursor:pointer;
  }
  .audit-input {
    min-width:220px;
    padding-right:12px;
  }
  .audit-count { color:#7089a9; font-size:13px; letter-spacing:0.4px; text-transform:uppercase; font-weight:700; }
  .audit-table-wrap {
    border:1px solid #1f3857;
    border-radius:14px;
    overflow:hidden;
    background:#0a1a2f;
    flex:1;
  }
  .audit-table { width:100%; border-collapse:collapse; }
  .audit-table th, .audit-table td { padding:14px 12px; text-align:left; vertical-align:middle; border-bottom:1px solid #1a3350; }
  .audit-table th { background:#0d2139; color:#87a7cd; font-size:14px; letter-spacing:0.2px; text-transform:none; }
  .audit-table td { color:#d8e7ff; font-size:14px; }
  .audit-row.main { transition:background 0.15s; }
  .audit-row.main:hover { background:#102947; }
  .audit-time { display:grid; gap:2px; }
  .audit-date-label { font-weight:700; color:#edf4ff; }
  .audit-time-label { font-size:13px; color:#7992b3; }
  .audit-type { display:inline-flex; align-items:center; gap:8px; font-weight:700; }
  .audit-type-ico { width:20px; color:#41a6ff; text-align:center; }
  .audit-admin { display:grid; gap:3px; }
  .audit-admin-name { font-weight:700; color:#e7f1ff; }
  .audit-admin-sub { font-size:13px; color:#7992b3; }
  .audit-status { display:inline-flex; align-items:center; gap:8px; padding:6px 12px; border-radius:999px; font-weight:700; font-size:12px; border:1px solid transparent; }
  .audit-status::before { content:""; width:7px; height:7px; border-radius:50%; background:currentColor; }
  .audit-status.ok { background:#103a2d; border-color:#1a644b; color:#2bd27f; }
  .audit-status.pending { background:#3c3218; border-color:#665422; color:#f3c742; }
  .audit-status.fail { background:#41202a; border-color:#6b2d3b; color:#ff7a95; }
  .audit-detail-btn { border:none; background:transparent; color:#2c9bff; font-weight:700; cursor:pointer; }
  .audit-expand { background:#0c2240; }
  .audit-meta {
    padding:2px 0;
    display:grid;
    grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));
    gap:12px;
    color:#9cb5d6;
    font-size:13px;
  }
  .audit-meta > div { min-width: 0; }
  .audit-meta span { word-break: break-word; overflow-wrap: anywhere; }
  .audit-meta strong { display:block; color:#d7e7ff; font-size:12px; margin-bottom:4px; }
  .audit-pagination {
    display:flex;
    justify-content:flex-end;
    align-items:center;
    gap:10px;
    margin-top:14px;
    color:#6e89ad;
  }
  .audit-page-meta { font-size:13px; color:#7089a9; }
  .pager-ellipsis {
    min-width:34px;
    text-align:center;
    color:#7089a9;
    font-weight:700;
  }

  /* Light theme overrides for audit log */
  .theme-light .audit-card {
    background: radial-gradient(circle at 8% -30%, rgba(59, 130, 246, 0.12), transparent 35%), #ffffff;
    border: 1px solid #dbe5f3;
    box-shadow: 0 16px 32px rgba(15, 23, 42, 0.08);
    color: #0f172a;
  }
  .theme-light .audit-tabs { border-bottom-color: #dbe5f3; }
  .theme-light .audit-tab { color: #64748b; }
  .theme-light .audit-tab.active { color: #2563eb; }
  .theme-light .audit-tab.active::after { background: #2563eb; }
  .theme-light .audit-select {
    border-color: #cbd5e1;
    background: #ffffff;
    color: #0f172a;
  }
  .theme-light .audit-count { color: #64748b; }
  .theme-light .audit-table-wrap { border-color: #dbe5f3; background: #ffffff; }
  .theme-light .audit-table th,
  .theme-light .audit-table td { border-bottom-color: #e7edf7; }
  .theme-light .audit-table th { background: #f8fbff; color: #475569; }
  .theme-light .audit-table td { color: #0f172a; }
  .theme-light .audit-row.main:hover { background: #f4f8ff; }
  .theme-light .audit-date-label { color: #0f172a; }
  .theme-light .audit-time-label { color: #64748b; }
  .theme-light .audit-type-ico { color: #2563eb; }
  .theme-light .audit-admin-name { color: #0f172a; }
  .theme-light .audit-admin-sub { color: #64748b; }
  .theme-light .audit-status.ok { background: #ecfdf3; border-color: #bbf7d0; color: #15803d; }
  .theme-light .audit-status.pending { background: #fff7ed; border-color: #fed7aa; color: #c2410c; }
  .theme-light .audit-status.fail { background: #fef2f2; border-color: #fecdd3; color: #b91c1c; }
  .theme-light .audit-detail-btn { color: #2563eb; }
  .theme-light .audit-expand { background: #f8fbff; }
  .theme-light .audit-meta { color: #475569; }
  .theme-light .audit-meta strong { color: #0f172a; }
  .theme-light .audit-pagination { color: #64748b; }

  /* AI alerts */
  .alerts-card {
    background: linear-gradient(180deg, #08192d 0%, #091425 100%);
    border: 1px solid #1a3351;
    border-radius: 18px;
    box-shadow: 0 22px 40px rgba(4, 11, 24, 0.45);
    padding: 18px;
    color: #d6e6ff;
  }
  .alerts-head {
    display:flex;
    justify-content:space-between;
    align-items:flex-end;
    gap:14px;
    flex-wrap:wrap;
    margin-bottom:18px;
  }
  .alerts-head h2 { margin:0 0 4px; font-size:28px; color:#eef4ff; }
  .alerts-head p { margin:0; color:#89a3c8; }
  .alerts-summary-bar {
    display:grid;
    grid-template-columns:repeat(4, minmax(140px, 1fr));
    gap:10px;
    margin:0 0 18px;
  }
  .alerts-stat {
    border:1px solid #1d3a5b;
    border-radius:14px;
    background:#0b1a2f;
    padding:12px 14px;
  }
  .alerts-stat strong {
    display:block;
    color:#eef4ff;
    font-size:20px;
    margin-bottom:4px;
  }
  .alerts-stat span {
    color:#89a3c8;
    font-size:12px;
    text-transform:uppercase;
    letter-spacing:0.3px;
    font-weight:700;
  }
  .alerts-filters { display:flex; gap:10px; flex-wrap:wrap; }
  .alerts-filter,
  .alerts-search {
    min-width:160px;
    padding:10px 12px;
    border:1px solid #284564;
    border-radius:12px;
    background:#10233c;
    color:#e7f1ff;
    font-weight:600;
  }
  .alerts-search { min-width:240px; }
  .alerts-list { display:grid; gap:14px; }
  .alerts-item {
    border:1px solid #1f3857;
    border-radius:16px;
    background:#0d1f35;
    padding:16px;
  }
  .alerts-item[data-risk="high"] { border-color:#6b2d3b; box-shadow: inset 0 0 0 1px rgba(255,122,149,0.16); }
  .alerts-item[data-risk="medium"] { border-color:#665422; box-shadow: inset 0 0 0 1px rgba(243,199,66,0.12); }
  .alerts-top {
    display:flex;
    justify-content:space-between;
    gap:14px;
    flex-wrap:wrap;
    margin-bottom:10px;
  }
  .alerts-summary { display:grid; gap:6px; }
  .alerts-summary h3 { margin:0; color:#eef4ff; font-size:19px; }
  .alerts-one-line {
    margin:0;
    color:#dbe8ff;
    font-size:14px;
    line-height:1.5;
    display:-webkit-box;
    -webkit-line-clamp:1;
    -webkit-box-orient:vertical;
    overflow:hidden;
  }
  .alerts-body {
    display:grid;
    gap:12px;
  }
  .alerts-core-grid {
    display:grid;
    grid-template-columns:minmax(0, 1.4fr) minmax(320px, 0.9fr);
    gap:14px;
    align-items:start;
  }
  .alerts-primary {
    display:grid;
    gap:10px;
    min-width:0;
  }
  .alerts-explanation.compact {
    margin:0;
    color:#dbe8ff;
    line-height:1.55;
  }
  .alerts-compact-reasons {
    display:flex;
    gap:8px;
    flex-wrap:wrap;
  }
  .alerts-meta-line {
    display:flex;
    gap:8px;
    align-items:center;
    flex-wrap:wrap;
    color:#89a3c8;
    font-size:13px;
  }
  .alerts-badge,
  .alerts-status-pill,
  .alerts-tone-pill {
    display:inline-flex;
    align-items:center;
    gap:6px;
    padding:6px 10px;
    border-radius:999px;
    font-size:12px;
    font-weight:800;
    border:1px solid transparent;
  }
  .alerts-badge.low { background:#103a2d; border-color:#1a644b; color:#7ff0b4; }
  .alerts-badge.medium { background:#3c3218; border-color:#665422; color:#f3c742; }
  .alerts-badge.high { background:#41202a; border-color:#6b2d3b; color:#ff9aae; }
  .alerts-status-pill.pending_review { background:#20324d; border-color:#2f4a72; color:#9fc1f7; }
  .alerts-status-pill.confirmed_risk { background:#41202a; border-color:#6b2d3b; color:#ff9aae; }
  .alerts-status-pill.false_positive { background:#103a2d; border-color:#1a644b; color:#7ff0b4; }
  .alerts-status-pill.escalated { background:#3c3218; border-color:#665422; color:#f3c742; }
  .alerts-tone-pill { background:#132742; border-color:#27456b; color:#9fc1f7; }
  .alerts-explanation {
    margin: 0 0 12px;
    color:#dbe8ff;
    line-height:1.6;
  }
  .alerts-reasons {
    display:flex;
    gap:8px;
    flex-wrap:wrap;
    margin:0 0 14px;
  }
  .alerts-reason {
    padding:6px 10px;
    border-radius:999px;
    background:#142b49;
    border:1px solid #25476f;
    color:#d7e7ff;
    font-size:12px;
    font-weight:700;
  }
  .alerts-signals {
    display:grid;
    grid-template-columns:repeat(2, minmax(0, 1fr));
    gap:10px;
    margin:0;
  }
  .alerts-signal {
    border:1px solid #1d3a5b;
    border-radius:12px;
    padding:10px 12px;
    background:#0b1a2f;
  }
  .alerts-signal strong {
    display:block;
    color:#89a3c8;
    font-size:12px;
    margin-bottom:4px;
  }
  .alerts-signal span { color:#eef4ff; font-weight:700; }
  .alerts-signal[data-tone="warn"] { border-color:#6b2d3b; }
  .alerts-signal[data-tone="info"] { border-color:#2f4a72; }
  .alerts-actions {
    display:flex;
    justify-content:space-between;
    gap:12px;
    flex-wrap:wrap;
    align-items:center;
  }
  .alerts-buttons {
    display:flex;
    gap:8px;
    flex-wrap:wrap;
  }
  .alerts-btn {
    border:1px solid #284564;
    background:#10233c;
    color:#e7f1ff;
    border-radius:10px;
    padding:9px 12px;
    cursor:pointer;
    font-weight:700;
  }
  .alerts-btn.primary { background:#1f6bff; border-color:#1f6bff; }
  .alerts-btn.warn { background:#3c3218; border-color:#665422; color:#f8dc84; }
  .alerts-btn.safe { background:#103a2d; border-color:#1a644b; color:#7ff0b4; }
  .alerts-btn:disabled { opacity:0.65; cursor:not-allowed; }
  .alerts-extra {
    margin-top:12px;
    border-top:1px solid #1a3350;
    padding-top:12px;
    display:grid;
    grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));
    gap:10px;
    color:#99b2d5;
    font-size:13px;
  }
  .alerts-extra strong { display:block; color:#d9e8ff; margin-bottom:4px; font-size:12px; }
  .alerts-empty {
    border:1px dashed #2b4768;
    border-radius:16px;
    padding:26px;
    text-align:center;
    color:#89a3c8;
  }
  .theme-light .alerts-card {
    background:#ffffff;
    border-color:#dbe5f3;
    box-shadow: 0 16px 32px rgba(15, 23, 42, 0.08);
    color:#0f172a;
  }
  .theme-light .alerts-head h2,
  .theme-light .alerts-summary h3,
  .theme-light .alerts-signal span,
  .theme-light .alerts-extra strong { color:#0f172a; }
  .theme-light .alerts-stat { background:#ffffff; border-color:#dbe5f3; }
  .theme-light .alerts-stat strong { color:#0f172a; }
  .theme-light .alerts-stat span { color:#64748b; }
  .theme-light .alerts-head p,
  .theme-light .alerts-meta-line,
  .theme-light .alerts-extra { color:#64748b; }
  .theme-light .alerts-filter,
  .theme-light .alerts-search,
  .theme-light .alerts-btn,
  .theme-light .alerts-item,
  .theme-light .alerts-signal {
    background:#ffffff;
    color:#0f172a;
    border-color:#dbe5f3;
  }
  .theme-light .alerts-reason { background:#f8fbff; border-color:#dbe5f3; color:#0f172a; }
  .theme-light .alerts-explanation { color:#334155; }
  .theme-light .alerts-tone-pill { background:#eff6ff; border-color:#bfdbfe; color:#1d4ed8; }

  /* Compact desktop layout for 16:9 screens */
  @media (min-width: 1280px) and (min-aspect-ratio: 16/9) {
    .mf-sidebar { width: 220px; padding: 20px 14px; gap: 14px; }
    .mf-main { margin-left: 220px; width: calc(100% - 220px); }
    .mf-logo { font-size: 20px; margin-bottom: 20px; }
    .mf-menu button { gap: 10px; padding: 10px 12px; font-size: 14px; border-radius: 10px; }
    .mf-ico { width: 28px; height: 28px; font-size: 14px; border-radius: 10px; }

    .ana-page { padding: 18px 20px 24px; }
    .ana-title h1 { font-size: 22px; }
    .ana-kpi-grid { gap: 10px; margin-bottom: 12px; }
    .ana-grid-main, .ana-bottom-grid { gap: 12px; margin-bottom: 12px; }
    .ana-card, .user-card, .set-card, .audit-card { border-radius: 12px; padding: 14px; }
    .ana-kpi-value { font-size: 24px; }
    .ana-bar-chart { height: 210px; gap: 8px; }
    .ana-dual-chart { height: 160px; gap: 10px; }
    .ana-dual-bars { height: 106px; }
    .ana-pie { width: 160px; height: 160px; }
    .ana-pie-center { width: 78px; height: 78px; font-size: 13px; }

    .user-table th, .user-table td { padding: 10px 8px; font-size: 13px; }
    .user-search { padding: 8px 10px; min-width: 200px; }
    .user-avatar { width: 42px; height: 42px; }
    .user-tab { padding: 8px 12px; }

    .prof-page { padding: 16px; }
    .prof-card { max-width: 980px; padding: 24px; gap: 20px; }
    .prof-avatar-wrap, .prof-avatar { width: 104px; height: 104px; }
    .prof-name { font-size: 20px; }
    .prof-field input { padding: 10px 12px; }

    .audit-table th, .audit-table td { padding: 10px 8px; }
    .audit-select { min-width: 150px; }
  }
  @media (max-width: 900px) {
    .alerts-summary-bar { grid-template-columns:repeat(2, minmax(140px, 1fr)); }
    .alerts-core-grid { grid-template-columns:1fr; }
    .audit-filters { width: 100%; }
    .audit-select { flex: 1 1 170px; min-width: 0; }
    .audit-input { flex: 1 1 220px; min-width: 0; }
    .audit-table-wrap { overflow-x: auto; }
    .audit-table { min-width: 780px; }
    .audit-pagination { justify-content: center; }
    .alerts-filters { width:100%; }
    .alerts-filter, .alerts-search { flex:1 1 180px; min-width:0; }
  }
`;

function KpiCard({ card }: { card: KpiCard }) {
  return (
    <div className="ana-card">
      <div className="ana-kpi-head">
        <span>{card.title}</span>
        <span
          className={`ana-delta ${card.delta.startsWith("-") ? "down" : "up"}`}
        >
          {card.delta}
        </span>
      </div>
      <p className="ana-kpi-value">{card.value}</p>
      <ul className="ana-kpi-list">
        {card.items.map((item) => (
          <li key={item.label}>
            <span className="ana-dot" style={{ background: item.color }} />
            <span>{item.label}</span>
            <strong>{item.value}</strong>
          </li>
        ))}
      </ul>
    </div>
  );
}

function AdminApp() {
  const { user, token, logout } = useAuth();
  const theme: "dark" = "dark";
  const getAuditPageSize = () => {
    if (typeof window === "undefined") return 10;
    const availableHeight = window.innerHeight - 320;
    return Math.max(8, Math.min(14, Math.floor(availableHeight / 60)));
  };
  const [period, setPeriod] = useState<"year" | "month" | "week">("year");
  const [selectedDate, setSelectedDate] = useState(() => {
    // default to current date for realistic demo
    const now = new Date();
    return now.toISOString().slice(0, 10);
  });
  const [active, setActive] = useState<
    "dashboard" | "alerts" | "users" | "audit" | "profile" | "setting"
  >("dashboard");
  useEffect(() => {
    if (typeof document !== "undefined") {
      document.body.classList.remove("theme-light", "theme-dark");
      document.body.classList.add(`theme-${theme}`);
    }
    if (typeof localStorage !== "undefined") {
      localStorage.setItem("admin-theme", theme);
    }
  }, [theme]);

  useEffect(() => {
    if (typeof document === "undefined") return;
    if (active === "profile") {
      document.body.classList.add("admin-profile-no-scroll");
    } else {
      document.body.classList.remove("admin-profile-no-scroll");
    }
    return () => {
      document.body.classList.remove("admin-profile-no-scroll");
    };
  }, [active]);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [alerts, setAlerts] = useState<AdminAlertApi[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogView[]>([]);
  const [auditTotalCount, setAuditTotalCount] = useState(0);
  const [adminDataLoading, setAdminDataLoading] = useState(false);
  const [adminDataError, setAdminDataError] = useState("");
  const [auditPageSize, setAuditPageSize] = useState(getAuditPageSize);

  useEffect(() => {
    if (typeof window === "undefined") return;

    const updateAuditPageSize = () => {
      setAuditPageSize(getAuditPageSize());
    };

    updateAuditPageSize();
    window.addEventListener("resize", updateAuditPageSize);
    return () => {
      window.removeEventListener("resize", updateAuditPageSize);
    };
  }, []);

  const mapAdminTxnToView = (t: AdminTransactionApi): Transaction => ({
    id: t.id,
    userId:
      t.type === "DEPOSIT"
        ? t.toUserId || t.fromUserId || ""
        : t.fromUserId || t.toUserId || "",
    date: new Date(t.createdAt).toLocaleString("en-US"),
    type:
      t.type === "REFUND"
        ? "Refund"
        : t.type === "TRANSFER"
          ? "Transfer"
          : "Payment",
    amount: `$${Number(t.amount || 0).toLocaleString("en-US", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    })}`,
    status:
      t.status === "FAILED"
        ? "Failed"
        : t.status === "PENDING"
          ? "Pending"
          : "Completed",
    reference: t.description || t.id,
  });

  useEffect(() => {
    if (!token || user?.role !== "ADMIN") return;

    const headers = { Authorization: `Bearer ${token}` };

    const mapUser = (u: AdminUserApi): AdminUser => ({
      id: u.id,
      name: u.fullName?.trim() || u.email.split("@")[0] || "User",
      email: u.email,
      role: u.role === "ADMIN" ? "Admin" : "User",
      title: u.role === "ADMIN" ? "System Admin" : "Customer",
      phone: u.phone || "-",
      birthday: u.createdAt
        ? new Date(u.createdAt).toISOString().slice(0, 10)
        : "",
      address: u.address || "-",
      avatar: `https://i.pravatar.cc/80?u=${encodeURIComponent(u.email)}`,
      status: u.status === "ACTIVE" ? "Active" : "Locked",
      lastLogin: u.lastLoginAt || u.createdAt || new Date().toISOString(),
    });

    const load = async () => {
      setAdminDataLoading(true);
      setAdminDataError("");

      try {
        const [usersResp, txResp, alertsResp] = await Promise.all([
          fetch(`${API_BASE}/admin/users`, { headers }),
          fetch(`${API_BASE}/admin/transactions`, { headers }),
          fetch(`${API_BASE}/admin/alerts`, { headers }),
        ]);

        const usersData = (await usersResp
          .json()
          .catch(() => [])) as AdminUserApi[];
        const txData = (await txResp
          .json()
          .catch(() => [])) as AdminTransactionApi[];
        const alertsData = (await alertsResp
          .json()
          .catch(() => [])) as AdminAlertApi[];

        if (usersResp.ok) setUsers(usersData.map(mapUser));
        else setUsers([]);
        if (txResp.ok) setTransactions(txData.map(mapAdminTxnToView));
        else setTransactions([]);
        if (alertsResp.ok) setAlerts(alertsData);
        else setAlerts([]);

        const responseErrors = [
          !usersResp.ok ? `/admin/users: ${usersResp.status}` : null,
          !txResp.ok ? `/admin/transactions: ${txResp.status}` : null,
          !alertsResp.ok ? `/admin/alerts: ${alertsResp.status}` : null,
        ].filter(Boolean);

        if (responseErrors.length > 0) {
          setAdminDataError(
            `Admin data could not be loaded from the API. ${responseErrors.join(", ")}`,
          );
        }
      } catch (err) {
        setUsers([]);
        setTransactions([]);
        setAlerts([]);
        setAdminDataError(
          err instanceof Error
            ? `Admin API is unavailable: ${err.message}. Check that the API server is running and can reach the database.`
            : "Admin API is unavailable. Check that the API server is running and can reach the database.",
        );
      } finally {
        setAdminDataLoading(false);
      }
    };

    void load();
  }, [token, user?.role]);

  const [settings, setSettings] = useState({
    notifications: true,
    twofa: false,
    weekly: true,
  });
  const [profile, setProfile] = useState({
    name: user?.name ?? "Vanh",
    username: "vanh123",
    phone: "0123 456 789",
    email: user?.email ?? "vanh@example.com",
    dob: "2005-10-01",
    present: "123",
    permanent: "Ha Noi, VietNam",
    postal: "000001",
    password: "password",
    avatar: user?.avatar ?? "https://i.pravatar.cc/200?img=11",
  });
  const avatarInputRef = useRef<HTMLInputElement | null>(null);
  const [userSearch, setUserSearch] = useState("");
  const [userTab, setUserTab] = useState<"all" | "active" | "locked">("all");
  const [showUserFilters, setShowUserFilters] = useState(false);
  const [userRoleFilter, setUserRoleFilter] = useState<
    "all" | "Admin" | "User"
  >("all");
  const [userSort, setUserSort] = useState<"latest" | "oldest">("latest");
  const [userPage, setUserPage] = useState(1);
  const userPageSize = 10;
  const [txUser, setTxUser] = useState<AdminUser | null>(null);
  const [expandedAlert, setExpandedAlert] = useState<string | null>(null);
  const [alertStatusFilter, setAlertStatusFilter] = useState<
    "all" | AdminAlertStatus
  >("all");
  const [alertRiskFilter, setAlertRiskFilter] = useState<
    "all" | "low" | "medium" | "high"
  >("all");
  const [alertTypeFilter, setAlertTypeFilter] = useState<
    "all" | "login" | "transaction"
  >("all");
  const [alertSearch, setAlertSearch] = useState("");
  const [alertPage, setAlertPage] = useState(1);
  const [alertActionBusyId, setAlertActionBusyId] = useState<string | null>(
    null,
  );
  const [expandedAudit, setExpandedAudit] = useState<string | null>(null);
  const [auditRange, setAuditRange] = useState<"7" | "30" | "90">("7");
  const [auditActivity, setAuditActivity] = useState<
    "all" | "um" | "tx" | "acc" | "login" | "sec"
  >("all");
  const [auditStatus, setAuditStatus] = useState<
    "all" | "ok" | "pending" | "fail"
  >("all");
  const [auditSource, setAuditSource] = useState<"human" | "ai" | "all">(
    "human",
  );
  const [auditAccountQuery, setAuditAccountQuery] = useState("");
  const [auditPage, setAuditPage] = useState(1);
  const alertPageSize = 4;

  useEffect(() => {
    if (expandedAudit && !auditLogs.some((item) => item.id === expandedAudit)) {
      setExpandedAudit(null);
    }
  }, [expandedAudit, auditLogs]);

  const openAvatarPicker = () => {
    avatarInputRef.current?.click();
  };

  const handleAvatarChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith("image/")) {
      alert("Please choose an image file.");
      e.target.value = "";
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const avatarData = reader.result;
      if (typeof avatarData === "string") {
        setProfile((prev) => ({ ...prev, avatar: avatarData }));
      }
    };
    reader.readAsDataURL(file);
    e.target.value = "";
  };

  const filteredUsers = useMemo(() => {
    const search = userSearch.trim().toLowerCase();
    const list = users.filter(
      (u) =>
        (!search ||
          u.name.toLowerCase().includes(search) ||
          u.email.toLowerCase().includes(search)) &&
        (userTab === "all" ||
          (userTab === "active" && u.status === "Active") ||
          (userTab === "locked" && u.status === "Locked")) &&
        (userRoleFilter === "all" ||
          (userRoleFilter === "Admin" && u.role === "Admin") ||
          (userRoleFilter === "User" && u.role === "User")),
    );

    return list.sort((a, b) => {
      const timeA = new Date(a.lastLogin.replace(" ", "T")).getTime();
      const timeB = new Date(b.lastLogin.replace(" ", "T")).getTime();
      return userSort === "latest" ? timeB - timeA : timeA - timeB;
    });
  }, [users, userSearch, userTab, userRoleFilter, userSort]);

  useEffect(() => {
    setUserPage(1);
  }, [userSearch, userTab, userRoleFilter, userSort]);

  const totalUserPages = Math.max(
    1,
    Math.ceil(filteredUsers.length / userPageSize),
  );
  const currentUserPage = Math.min(userPage, totalUserPages);
  const paginatedUsers = useMemo(() => {
    const start = (currentUserPage - 1) * userPageSize;
    return filteredUsers.slice(start, start + userPageSize);
  }, [filteredUsers, currentUserPage]);

  const userTransactions = useMemo(
    () => (txUser ? transactions.filter((t) => t.userId === txUser.id) : []),
    [transactions, txUser],
  );

  useEffect(() => {
    setAlertPage(1);
  }, [alertStatusFilter, alertRiskFilter, alertTypeFilter, alertSearch]);

  const filteredAlerts = useMemo(() => {
    const query = alertSearch.trim().toLowerCase();
    const list = alerts.filter((alert) => {
      if (
        alertStatusFilter !== "all" &&
        alert.adminStatus !== alertStatusFilter
      )
        return false;
      if (alertRiskFilter !== "all" && alert.riskLevel !== alertRiskFilter)
        return false;
      if (alertTypeFilter !== "all" && alert.type !== alertTypeFilter)
        return false;
      if (!query) return true;

      const haystack = [
        alert.summary,
        alert.explanation,
        alert.actor,
        alert.ipAddress,
        alert.location,
        alert.transactionId,
        alert.eventId,
        ...(alert.reasons || []),
        ...(alert.keySignals || []).map(
          (signal) => `${signal.label} ${signal.value}`,
        ),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return haystack.includes(query);
    });

    if (expandedAlert && !list.some((item) => item.id === expandedAlert)) {
      setExpandedAlert(null);
    }

    return list;
  }, [
    alerts,
    alertStatusFilter,
    alertRiskFilter,
    alertTypeFilter,
    alertSearch,
    expandedAlert,
  ]);

  const totalAlertPages = Math.max(
    1,
    Math.ceil(filteredAlerts.length / alertPageSize),
  );
  const alertSummary = useMemo(
    () => ({
      total: filteredAlerts.length,
      pending: filteredAlerts.filter(
        (item) => item.adminStatus === "pending_review",
      ).length,
      high: filteredAlerts.filter((item) => item.riskLevel === "high").length,
      transaction: filteredAlerts.filter((item) => item.type === "transaction")
        .length,
    }),
    [filteredAlerts],
  );
  const currentAlertPage = Math.min(alertPage, totalAlertPages);
  const paginatedAlerts = useMemo(() => {
    const start = (currentAlertPage - 1) * alertPageSize;
    return filteredAlerts.slice(start, start + alertPageSize);
  }, [filteredAlerts, currentAlertPage]);

  const handleAlertReview = async (
    alertId: string,
    status: AdminAlertStatus,
  ) => {
    if (!token) return;

    const notePrompt =
      status === "false_positive"
        ? "Why is this a false positive?"
        : status === "escalated"
          ? "What should the team investigate next?"
          : "Add an optional admin note";
    const note = window.prompt(notePrompt, "") ?? "";

    try {
      setAlertActionBusyId(alertId);
      const resp = await fetch(`${API_BASE}/admin/alerts/${alertId}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ status, note }),
      });
      const payload = (await resp.json().catch(() => null)) as
        | AdminAlertApi
        | { error?: string }
        | null;
      const nextAlert =
        payload && !("error" in payload) ? (payload as AdminAlertApi) : null;
      if (!resp.ok || !nextAlert) {
        window.alert(
          (payload && "error" in payload && payload.error) ||
            "Could not update alert status.",
        );
        return;
      }

      setAlerts((list) =>
        list.map((item) => (item.id === alertId ? nextAlert : item)),
      );
    } finally {
      setAlertActionBusyId(null);
    }
  };

  useEffect(() => {
    setAuditPage(1);
  }, [auditRange, auditActivity, auditStatus, auditAccountQuery, auditSource]);

  useEffect(() => {
    if (!token || user?.role !== "ADMIN") return;

    const headers = { Authorization: `Bearer ${token}` };
    const params = new URLSearchParams({
      page: String(auditPage),
      pageSize: String(auditPageSize),
      rangeDays: auditRange,
      activity: auditActivity,
      status: auditStatus,
      source: auditSource,
    });
    if (auditAccountQuery.trim()) {
      params.set("accountQuery", auditAccountQuery.trim());
    }

    const loadAuditLogs = async () => {
      try {
        const auditResp = await fetch(
          `${API_BASE}/admin/audit-logs?${params.toString()}`,
          { headers },
        );
        const payload = (await auditResp.json().catch(() => null)) as {
          logs?: Array<{
            id: string;
            actor?: string;
            action?: string;
            details?: string | Record<string, unknown>;
            ipAddress?: string;
            metadata?: Record<string, unknown>;
            createdAt?: string;
          }>;
          totalCount?: number;
          totalPages?: number;
          page?: number;
          error?: string;
        } | null;

        if (!auditResp.ok) {
          setAuditLogs([]);
          setAuditTotalCount(0);
          return;
        }

        const mapped = (payload?.logs || []).map((d) =>
          mapAuditDocToView({
            _id: d.id,
            userId: null,
            actor: d.actor,
            action: d.action || "UNKNOWN",
            details: d.details,
            ipAddress: d.ipAddress,
            metadata: d.metadata,
            createdAt: d.createdAt || new Date().toISOString(),
          }),
        );
        setAuditLogs(mapped);
        setAuditTotalCount(
          typeof payload?.totalCount === "number"
            ? payload.totalCount
            : mapped.length,
        );
        if (typeof payload?.page === "number" && payload.page !== auditPage) {
          setAuditPage(payload.page);
        }
      } catch {
        setAuditLogs([]);
        setAuditTotalCount(0);
      }
    };

    void loadAuditLogs();
  }, [
    token,
    user?.role,
    auditPage,
    auditPageSize,
    auditRange,
    auditActivity,
    auditStatus,
    auditSource,
    auditAccountQuery,
  ]);

  const totalAuditPages = Math.max(
    1,
    Math.ceil(auditTotalCount / auditPageSize),
  );
  const currentAuditPage = Math.min(auditPage, totalAuditPages);
  const visibleAuditPages = useMemo(() => {
    if (totalAuditPages <= 7) {
      return Array.from({ length: totalAuditPages }, (_, i) => i + 1);
    }

    if (currentAuditPage <= 4) {
      return [1, 2, 3, 4, 5, "...", totalAuditPages] as const;
    }

    if (currentAuditPage >= totalAuditPages - 3) {
      return [
        1,
        "...",
        totalAuditPages - 4,
        totalAuditPages - 3,
        totalAuditPages - 2,
        totalAuditPages - 1,
        totalAuditPages,
      ] as const;
    }

    return [
      1,
      "...",
      currentAuditPage - 1,
      currentAuditPage,
      currentAuditPage + 1,
      "...",
      totalAuditPages,
    ] as const;
  }, [currentAuditPage, totalAuditPages]);
  const paginatedAuditLogs = auditLogs;

  const handleExportCsv = () => {
    const header = [
      "Timestamp",
      "Admin",
      "Category",
      "Detail",
      "IP",
      "Status",
      "UserAgent",
      "RequestID",
      "Location",
    ];
    const rows = auditLogs.map((l) =>
      [
        l.ts,
        l.admin,
        l.category,
        l.detail,
        l.ip,
        l.status,
        l.userAgent ?? "",
        l.requestId ?? "",
        l.location ?? "",
      ].map((v) => `"${String(v).replace(/"/g, '""')}"`),
    );
    const csv = [
      header.map((h) => `"${h}"`).join(","),
      ...rows.map((r) => r.join(",")),
    ].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "audit-log.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  const analytics = useMemo(() => {
    const anchorDate = (() => {
      const parsed = new Date(selectedDate);
      return Number.isNaN(parsed.getTime()) ? new Date() : parsed;
    })();
    const selectedMonth = anchorDate.getMonth();
    const selectedYear = anchorDate.getFullYear();

    const currentRange =
      period === "year"
        ? {
            start: new Date(selectedYear, 0, 1),
            end: new Date(selectedYear, 11, 31, 23, 59, 59, 999),
          }
        : period === "month"
          ? {
              start: new Date(selectedYear, selectedMonth, 1),
              end: new Date(
                selectedYear,
                selectedMonth + 1,
                0,
                23,
                59,
                59,
                999,
              ),
            }
          : {
              start: getWeekStart(anchorDate),
              end: endOfDay(addDays(getWeekStart(anchorDate), 6)),
            };

    const previousRange =
      period === "year"
        ? {
            start: addYears(currentRange.start, -1),
            end: addYears(currentRange.end, -1),
          }
        : period === "month"
          ? {
              start: new Date(selectedYear, selectedMonth - 1, 1),
              end: new Date(selectedYear, selectedMonth, 0, 23, 59, 59, 999),
            }
          : {
              start: addDays(currentRange.start, -7),
              end: endOfDay(addDays(currentRange.start, -1)),
            };

    const txRows = transactions.map((t) => {
      const amountNum = parseCurrencyAmount(t.amount);
      const dateObj = parseDateLoose(t.date);
      return { ...t, amountNum, dateObj };
    });

    const currentTx = txRows.filter((t) =>
      isWithinRange(t.dateObj, currentRange.start, currentRange.end),
    );
    const previousTx = txRows.filter((t) =>
      isWithinRange(t.dateObj, previousRange.start, previousRange.end),
    );
    const completedCurrentTx = currentTx.filter(
      (t) => t.status === "Completed",
    );
    const completedPreviousTx = previousTx.filter(
      (t) => t.status === "Completed",
    );

    const totalUsers = users.length;
    const activeUsers = users.filter((u) => u.status === "Active").length;
    const lockedUsers = users.filter((u) => u.status === "Locked").length;
    const adminUsers = users.filter((u) => u.role === "Admin").length;
    const userUsers = users.filter((u) => u.role === "User").length;

    const successCount = currentTx.filter(
      (t) => t.status === "Completed",
    ).length;
    const pendingCount = currentTx.filter((t) => t.status === "Pending").length;
    const failedCount = currentTx.filter((t) => t.status === "Failed").length;
    const totalTx = currentTx.length;
    const successRate = totalTx > 0 ? (successCount / totalTx) * 100 : 0;

    const profileCompleted = users.filter(
      (u) => u.phone !== "-" && u.address !== "-",
    ).length;
    const profileCompletionRate =
      totalUsers > 0 ? (profileCompleted / totalUsers) * 100 : 0;

    const currentPeriodGmv = completedCurrentTx.reduce(
      (sum, tx) => sum + tx.amountNum,
      0,
    );
    const previousPeriodGmv = completedPreviousTx.reduce(
      (sum, tx) => sum + tx.amountNum,
      0,
    );
    const gmvDelta =
      previousPeriodGmv > 0
        ? ((currentPeriodGmv - previousPeriodGmv) / previousPeriodGmv) * 100
        : currentPeriodGmv > 0
          ? 100
          : 0;

    const currentTypeMap = new Map<string, { count: number; amount: number }>();
    for (const tx of completedCurrentTx) {
      const current = currentTypeMap.get(tx.type) ?? { count: 0, amount: 0 };
      current.count += 1;
      current.amount += tx.amountNum;
      currentTypeMap.set(tx.type, current);
    }
    const totalTypeCount = Array.from(currentTypeMap.values()).reduce(
      (sum, item) => sum + item.count,
      0,
    );
    const categories = Array.from(currentTypeMap.entries())
      .map(([name, info]) => ({
        name,
        count: info.count,
        amount: info.amount,
        value:
          totalTypeCount > 0
            ? Math.round((info.count / totalTypeCount) * 100)
            : 0,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    const currentAudit = auditLogs.filter((log) =>
      isWithinRange(
        parseDateLoose(log.ts),
        currentRange.start,
        currentRange.end,
      ),
    );
    const previousAudit = auditLogs.filter((log) =>
      isWithinRange(
        parseDateLoose(log.ts),
        previousRange.start,
        previousRange.end,
      ),
    );

    const engagementChannels = [
      {
        name: "Active users",
        now: activeUsers,
        prev: Math.max(totalUsers - activeUsers, 0),
      },
      {
        name: "Transactions",
        now: currentTx.length,
        prev: previousTx.length,
      },
      {
        name: "Login events",
        now: currentAudit.filter((l) => l.categoryClass === "login").length,
        prev: previousAudit.filter((l) => l.categoryClass === "login").length,
      },
      {
        name: "Security alerts",
        now: currentAudit.filter((l) => l.statusClass === "fail").length,
        prev: previousAudit.filter((l) => l.statusClass === "fail").length,
      },
    ];

    const gmvChart =
      period === "year"
        ? {
            title: "GMV by Month",
            labels: MONTH_LABELS,
            data: MONTH_LABELS.map((_, monthIndex) =>
              txRows
                .filter(
                  (tx) =>
                    tx.status === "Completed" &&
                    tx.dateObj?.getFullYear() === selectedYear &&
                    tx.dateObj.getMonth() === monthIndex,
                )
                .reduce((sum, tx) => sum + tx.amountNum, 0),
            ),
          }
        : period === "month"
          ? (() => {
              const daysInMonth = new Date(
                selectedYear,
                selectedMonth + 1,
                0,
              ).getDate();
              const bucketCount = Math.ceil(daysInMonth / 7);
              const labels = Array.from(
                { length: bucketCount },
                (_, index) => `W${index + 1}`,
              );
              const data = Array.from({ length: bucketCount }, () => 0);
              for (const tx of completedCurrentTx) {
                if (!tx.dateObj) continue;
                const bucketIndex = Math.floor((tx.dateObj.getDate() - 1) / 7);
                data[bucketIndex] += tx.amountNum;
              }
              return { title: "GMV by Week", labels, data };
            })()
          : (() => {
              const labels = Array.from({ length: 7 }, (_, index) =>
                addDays(currentRange.start, index).toLocaleDateString("en-US", {
                  weekday: "short",
                }),
              );
              const data = Array.from({ length: 7 }, () => 0);
              for (const tx of completedCurrentTx) {
                if (!tx.dateObj) continue;
                const bucketIndex = Math.floor(
                  (startOfDay(tx.dateObj).getTime() -
                    currentRange.start.getTime()) /
                    (24 * 60 * 60 * 1000),
                );
                if (bucketIndex >= 0 && bucketIndex < 7) {
                  data[bucketIndex] += tx.amountNum;
                }
              }
              return { title: "GMV by Day", labels, data };
            })();

    const revenueTrend =
      period === "year"
        ? MONTH_LABELS.map((label, monthIndex) => {
            const nowTx = txRows.filter(
              (tx) =>
                tx.status === "Completed" &&
                tx.dateObj?.getFullYear() === selectedYear &&
                tx.dateObj.getMonth() === monthIndex,
            );
            const prevTx = txRows.filter(
              (tx) =>
                tx.status === "Completed" &&
                tx.dateObj?.getFullYear() === selectedYear - 1 &&
                tx.dateObj.getMonth() === monthIndex,
            );
            const nowAmount = nowTx.reduce((sum, tx) => sum + tx.amountNum, 0);
            const prevAmount = prevTx.reduce(
              (sum, tx) => sum + tx.amountNum,
              0,
            );
            return {
              month: label,
              now: nowTx.length ? nowAmount / nowTx.length : 0,
              prev: prevTx.length ? prevAmount / prevTx.length : 0,
            };
          })
        : period === "month"
          ? gmvChart.labels.map((label, index) => {
              const nowTx = completedCurrentTx.filter((tx) => {
                if (!tx.dateObj) return false;
                return Math.floor((tx.dateObj.getDate() - 1) / 7) === index;
              });
              const prevTx = completedPreviousTx.filter((tx) => {
                if (!tx.dateObj) return false;
                return Math.floor((tx.dateObj.getDate() - 1) / 7) === index;
              });
              const nowAmount = nowTx.reduce(
                (sum, tx) => sum + tx.amountNum,
                0,
              );
              const prevAmount = prevTx.reduce(
                (sum, tx) => sum + tx.amountNum,
                0,
              );
              return {
                month: label,
                now: nowTx.length ? nowAmount / nowTx.length : 0,
                prev: prevTx.length ? prevAmount / prevTx.length : 0,
              };
            })
          : gmvChart.labels.map((label, index) => {
              const currentDay = startOfDay(addDays(currentRange.start, index));
              const previousDay = startOfDay(
                addDays(previousRange.start, index),
              );
              const nowTx = completedCurrentTx.filter(
                (tx) =>
                  tx.dateObj &&
                  startOfDay(tx.dateObj).getTime() === currentDay.getTime(),
              );
              const prevTx = completedPreviousTx.filter(
                (tx) =>
                  tx.dateObj &&
                  startOfDay(tx.dateObj).getTime() === previousDay.getTime(),
              );
              const nowAmount = nowTx.reduce(
                (sum, tx) => sum + tx.amountNum,
                0,
              );
              const prevAmount = prevTx.reduce(
                (sum, tx) => sum + tx.amountNum,
                0,
              );
              return {
                month: label,
                now: nowTx.length ? nowAmount / nowTx.length : 0,
                prev: prevTx.length ? prevAmount / prevTx.length : 0,
              };
            });

    const periodTitle =
      period === "year"
        ? "Yearly GMV"
        : period === "month"
          ? "Monthly GMV"
          : "Weekly GMV";

    const kpiCards: KpiCard[] = [
      {
        title: "Active users",
        value: activeUsers.toLocaleString("en-US"),
        delta: `${totalUsers > 0 ? ((activeUsers / totalUsers) * 100).toFixed(1) : "0.0"}%`,
        items: [
          {
            label: "Total users",
            value: totalUsers.toLocaleString("en-US"),
            color: "#5b21b6",
          },
          {
            label: "Admin",
            value: adminUsers.toLocaleString("en-US"),
            color: "#2563eb",
          },
          {
            label: "Customer",
            value: userUsers.toLocaleString("en-US"),
            color: "#f59e0b",
          },
        ],
      },
      {
        title: "Transaction success rate",
        value: `${successRate.toFixed(1)}%`,
        delta: `${totalTx.toLocaleString("en-US")} tx`,
        items: [
          {
            label: "Completed",
            value: successCount.toLocaleString("en-US"),
            color: "#5b21b6",
          },
          {
            label: "Pending",
            value: pendingCount.toLocaleString("en-US"),
            color: "#6366f1",
          },
          {
            label: "Failed",
            value: failedCount.toLocaleString("en-US"),
            color: "#f59e0b",
          },
        ],
      },
      {
        title: "Profile completion",
        value: `${profileCompletionRate.toFixed(1)}%`,
        delta: `${lockedUsers.toLocaleString("en-US")} locked`,
        items: [
          {
            label: "Completed profile",
            value: profileCompleted.toLocaleString("en-US"),
            color: "#5b21b6",
          },
          {
            label: "Incomplete",
            value: Math.max(totalUsers - profileCompleted, 0).toLocaleString(
              "en-US",
            ),
            color: "#6366f1",
          },
          {
            label: "Locked",
            value: lockedUsers.toLocaleString("en-US"),
            color: "#f59e0b",
          },
        ],
      },
      {
        title: periodTitle,
        value: formatMoneyCompact(currentPeriodGmv),
        delta: `${gmvDelta >= 0 ? "+" : ""}${gmvDelta.toFixed(1)}%`,
        items: [
          {
            label: "Transfer",
            value: formatMoneyCompact(
              currentTypeMap.get("Transfer")?.amount ?? 0,
            ),
            color: "#5b21b6",
          },
          {
            label: "Payment",
            value: formatMoneyCompact(
              currentTypeMap.get("Payment")?.amount ?? 0,
            ),
            color: "#6366f1",
          },
          {
            label: "Refund",
            value: formatMoneyCompact(
              currentTypeMap.get("Refund")?.amount ?? 0,
            ),
            color: "#f59e0b",
          },
        ],
      },
    ];

    return {
      kpiCards,
      categories,
      engagementChannels,
      revenueTrend,
      selectedMonth,
      gmvChart,
      periodTitle,
    };
  }, [transactions, users, auditLogs, selectedDate, period]);

  const maxMonthly = useMemo(
    () => Math.max(1, ...analytics.gmvChart.data),
    [analytics.gmvChart],
  );

  const maxChannel = useMemo(
    () =>
      Math.max(
        1,
        ...analytics.engagementChannels.map((c) => Math.max(c.now, c.prev)),
      ),
    [analytics.engagementChannels],
  );

  const maxRevenue = useMemo(
    () =>
      Math.max(
        1,
        ...analytics.revenueTrend.map((r) => Math.max(r.now, r.prev)),
      ),
    [analytics.revenueTrend],
  );

  return (
    <div className={`mf-shell theme-${theme}`}>
      <style>{styles}</style>

      <aside className="mf-sidebar">
        <div className="mf-logo">FPIPay Admin</div>
        <ul className="mf-menu">
          <li>
            <button
              className={active === "dashboard" ? "active" : ""}
              onClick={() => setActive("dashboard")}
            >
              <span className="mf-ico palette">🎨</span>
              Dashboard
            </button>
          </li>
          <li>
            <button
              className={active === "alerts" ? "active" : ""}
              onClick={() => setActive("alerts")}
            >
              <span className="mf-ico audit">AI</span>
              Alerts
            </button>
          </li>
          <li>
            <button
              className={active === "users" ? "active" : ""}
              onClick={() => setActive("users")}
            >
              <span className="mf-ico users">👥</span>
              User Management
            </button>
          </li>
          <li>
            <button
              className={active === "audit" ? "active" : ""}
              onClick={() => setActive("audit")}
            >
              <span className="mf-ico audit">📄</span>
              Audit Log
            </button>
          </li>
          <li>
            <button
              className={active === "profile" ? "active" : ""}
              onClick={() => setActive("profile")}
            >
              <span className="mf-ico profile">👤</span>
              Profile
            </button>
          </li>
          <li>
            <button
              className={active === "setting" ? "active" : ""}
              onClick={() => setActive("setting")}
            >
              <span className="mf-ico setting">⚙️</span>
              Setting
            </button>
          </li>
          <li>
            <button
              onClick={() => {
                logout();
                window.location.href = "/";
              }}
            >
              <span className="mf-ico logout">🚪</span>
              Logout
            </button>
          </li>
        </ul>
      </aside>

      <div
        className={`mf-main ana-page ${active === "profile" ? "no-scroll" : ""} ${active === "audit" ? "audit-view" : ""} ${active === "users" ? "users-view" : ""}`}
      >
        {adminDataError ? (
          <div className="ana-status-banner error">
            <div>
              <strong>Admin data is unavailable</strong>
              <p>{adminDataError}</p>
            </div>
          </div>
        ) : null}
        {adminDataLoading && !adminDataError ? (
          <div className="ana-status-banner loading">
            <div>
              <strong>Loading admin data</strong>
              <p>
                Fetching users, AI alerts, transactions, and audit logs from the
                API.
              </p>
            </div>
          </div>
        ) : null}
        {active === "dashboard" && (
          <>
            <header className="ana-header">
              <div className="ana-title">
                <h1>Dashboard</h1>
              </div>
              <div className="ana-actions">
                <div className="ana-segmented">
                  {(["year", "month", "week"] as const).map((p) => (
                    <button
                      key={p}
                      className={period === p ? "active" : ""}
                      onClick={() => setPeriod(p)}
                    >
                      {p === "year" ? "Year" : p === "month" ? "Month" : "Week"}
                    </button>
                  ))}
                </div>
                <div className="ana-pill">
                  <span role="img" aria-label="calendar">
                    📅
                  </span>
                  <input
                    className="ana-date"
                    type="date"
                    value={selectedDate}
                    onChange={(e) => setSelectedDate(e.target.value)}
                  />
                </div>
              </div>
            </header>

            <section className="ana-kpi-grid">
              {analytics.kpiCards.map((card) => (
                <KpiCard key={card.title} card={card} />
              ))}
            </section>

            <section className="ana-grid-main">
              <div className="ana-card">
                <div className="ana-chart-head">
                  <span>{analytics.gmvChart.title}</span>
                  <span className="ana-muted" aria-hidden="true"></span>
                </div>
                {analytics.gmvChart.data.every((value) => value <= 0) ? (
                  <div className="ana-chart-empty">
                    No GMV data for the selected period.
                  </div>
                ) : (
                  <div
                    className="ana-bar-chart"
                    style={{
                      gridTemplateColumns: `repeat(${analytics.gmvChart.data.length}, minmax(0, 1fr))`,
                    }}
                  >
                    {analytics.gmvChart.data.map((v, i) => (
                      <div
                        key={analytics.gmvChart.labels[i]}
                        className="ana-bar-item"
                      >
                        <div
                          className="ana-bar"
                          style={{
                            height: `${(v / maxMonthly) * 100}%`,
                            minHeight: v > 0 ? 10 : 0,
                          }}
                        />
                        <div className="ana-bar-label">
                          {analytics.gmvChart.labels[i]}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="ana-card">
                <h4>Top services by volume</h4>
                <div className="ana-pie-wrap">
                  <div
                    className="ana-pie"
                    style={{
                      background:
                        analytics.categories.length > 0
                          ? `conic-gradient(${analytics.categories
                              .map((category, index, list) => {
                                const start = list
                                  .slice(0, index)
                                  .reduce((sum, item) => sum + item.value, 0);
                                const end = start + category.value;
                                const colors = [
                                  "#5b21b6",
                                  "#7c3aed",
                                  "#8b5cf6",
                                  "#a78bfa",
                                  "#c4b5fd",
                                ];
                                return `${colors[index % colors.length]} ${start}% ${end}%`;
                              })
                              .join(", ")})`
                          : undefined,
                    }}
                  >
                    <div className="ana-pie-center">
                      {analytics.categories[0]?.name || "No data"}
                    </div>
                  </div>
                  <ul className="ana-legend">
                    {analytics.categories.map((c, i) => (
                      <li key={c.name}>
                        <span
                          className="ana-dot"
                          style={{
                            background: i % 2 === 0 ? "#5b21b6" : "#6366f1",
                          }}
                        />
                        <div>
                          <strong>{c.name}</strong>
                          <p className="ana-muted">{c.count} transactions</p>
                        </div>
                        <span className="value">{c.value}%</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </section>

            <section className="ana-bottom-grid">
              <div className="ana-card">
                <div className="ana-chart-head">
                  <span>Channel performance</span>
                  <div
                    className="ana-legend inline"
                    style={{ display: "flex", gap: 10, alignItems: "center" }}
                  >
                    <span
                      className="ana-dot"
                      style={{ background: "#5b21b6" }}
                    />{" "}
                    Now
                    <span
                      className="ana-dot"
                      style={{ background: "#c7d2fe" }}
                    />{" "}
                    Previous
                  </div>
                </div>
                <div className="ana-hbar-list">
                  {analytics.engagementChannels.map((c) => (
                    <div key={c.name} className="ana-hbar-row">
                      <span className="label">{c.name}</span>
                      <div className="ana-hbar-track">
                        <span
                          className="ana-hbar-prev"
                          style={{ width: `${(c.prev / maxChannel) * 100}%` }}
                        />
                        <span
                          className="ana-hbar-now"
                          style={{ width: `${(c.now / maxChannel) * 100}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="ana-card">
                <div className="ana-chart-head">
                  <span>Average transaction value</span>
                  <div
                    className="ana-legend inline"
                    style={{ display: "flex", gap: 10, alignItems: "center" }}
                  >
                    <span
                      className="ana-dot"
                      style={{ background: "#5b21b6" }}
                    />{" "}
                    Now
                    <span
                      className="ana-dot"
                      style={{ background: "#c7d2fe" }}
                    />{" "}
                    Previous
                  </div>
                </div>
                <div className="ana-dual-chart">
                  {analytics.revenueTrend.map((r) => (
                    <div key={r.month} className="ana-bar-item">
                      <div className="ana-dual-bars">
                        <div
                          className="ana-dual-now"
                          style={{ height: `${(r.now / maxRevenue) * 100}%` }}
                        />
                        <div
                          className="ana-dual-prev"
                          style={{ height: `${(r.prev / maxRevenue) * 100}%` }}
                        />
                      </div>
                      <div className="ana-dual-label">{r.month}</div>
                    </div>
                  ))}
                </div>
              </div>
            </section>
          </>
        )}

        {active === "alerts" && (
          <div className="alerts-card">
            <div className="alerts-head">
              <div>
                <h2>AI Alerts</h2>
                <p>
                  Review flagged cases, decide quickly, and open details only
                  when you need them.
                </p>
              </div>
              <div className="alerts-filters">
                <select
                  className="alerts-filter"
                  value={alertStatusFilter}
                  onChange={(e) =>
                    setAlertStatusFilter(
                      e.target.value as typeof alertStatusFilter,
                    )
                  }
                >
                  <option value="all">All statuses</option>
                  <option value="pending_review">Pending review</option>
                  <option value="confirmed_risk">Confirmed risk</option>
                  <option value="false_positive">False positive</option>
                  <option value="escalated">Escalated</option>
                </select>
                <select
                  className="alerts-filter"
                  value={alertRiskFilter}
                  onChange={(e) =>
                    setAlertRiskFilter(e.target.value as typeof alertRiskFilter)
                  }
                >
                  <option value="all">All risk levels</option>
                  <option value="high">High risk</option>
                  <option value="medium">Medium risk</option>
                  <option value="low">Low risk</option>
                </select>
                <select
                  className="alerts-filter"
                  value={alertTypeFilter}
                  onChange={(e) =>
                    setAlertTypeFilter(e.target.value as typeof alertTypeFilter)
                  }
                >
                  <option value="all">All alert types</option>
                  <option value="login">Login</option>
                  <option value="transaction">Transaction</option>
                </select>
                <input
                  className="alerts-search"
                  type="search"
                  value={alertSearch}
                  onChange={(e) => setAlertSearch(e.target.value)}
                  placeholder="Search reason, IP, location, event..."
                />
              </div>
            </div>

            <div className="alerts-summary-bar">
              <div className="alerts-stat">
                <strong>{alertSummary.total}</strong>
                <span>Matching alerts</span>
              </div>
              <div className="alerts-stat">
                <strong>{alertSummary.pending}</strong>
                <span>Pending review</span>
              </div>
              <div className="alerts-stat">
                <strong>{alertSummary.high}</strong>
                <span>High risk</span>
              </div>
              <div className="alerts-stat">
                <strong>{alertSummary.transaction}</strong>
                <span>Transaction alerts</span>
              </div>
            </div>

            {filteredAlerts.length === 0 ? (
              <div className="alerts-empty">
                No alerts match the current filters.
              </div>
            ) : (
              <>
                <div className="alerts-list">
                  {paginatedAlerts.map((alert) => {
                    const createdAt = new Date(alert.createdAt);
                    const reviewedAt = alert.reviewedAt
                      ? new Date(alert.reviewedAt)
                      : null;
                    const isExpanded = expandedAlert === alert.id;
                    return (
                      <article
                        key={alert.id}
                        className="alerts-item"
                        data-risk={alert.riskLevel}
                      >
                        <div className="alerts-top">
                          <div className="alerts-summary">
                            <div className="alerts-meta-line">
                              <span
                                className={`alerts-badge ${alert.riskLevel}`}
                              >
                                {formatRiskLabel(alert.riskLevel)}
                              </span>
                              <span
                                className={`alerts-status-pill ${alert.adminStatus}`}
                              >
                                {formatAlertStatusLabel(alert.adminStatus)}
                              </span>
                              <span className="alerts-tone-pill">
                                {formatAlertTypeLabel(alert.type)}
                              </span>
                            </div>
                            <h3>{alert.summary}</h3>
                            <div className="alerts-meta-line">
                              <span>
                                {Number.isNaN(createdAt.getTime())
                                  ? alert.createdAt
                                  : createdAt.toLocaleString("en-US")}
                              </span>
                              <span>|</span>
                              <span>
                                {formatAlertOrigin(
                                  alert.location,
                                  alert.ipAddress,
                                )}
                              </span>
                            </div>
                          </div>
                          <button
                            className="alerts-btn"
                            type="button"
                            onClick={() =>
                              setExpandedAlert((prev) =>
                                prev === alert.id ? null : alert.id,
                              )
                            }
                          >
                            {isExpanded ? "Hide details" : "Open details"}
                          </button>
                        </div>

                        <p className="alerts-one-line">
                          {alert.reasons[0] ||
                            alert.explanation ||
                            "Open details to review this alert."}
                        </p>

                        {isExpanded ? (
                          <>
                            <div className="alerts-body">
                              <div className="alerts-core-grid">
                                <div className="alerts-primary">
                                  <p className="alerts-explanation compact">
                                    {alert.explanation}
                                  </p>
                                  <div className="alerts-compact-reasons">
                                    {alert.reasons.map((reason) => (
                                      <span
                                        key={`${alert.id}-${reason}`}
                                        className="alerts-reason"
                                      >
                                        {reason}
                                      </span>
                                    ))}
                                  </div>
                                </div>
                                <div className="alerts-signals">
                                  <div
                                    className="alerts-signal"
                                    data-tone="warn"
                                  >
                                    <strong>Risk level</strong>
                                    <span>
                                      {formatRiskLabel(alert.riskLevel)}
                                    </span>
                                  </div>
                                  <div
                                    className="alerts-signal"
                                    data-tone="info"
                                  >
                                    <strong>Anomaly score</strong>
                                    <span>
                                      {typeof alert.anomalyScore === "number"
                                        ? `${Math.round(alert.anomalyScore)}%`
                                        : "N/A"}
                                    </span>
                                  </div>
                                  <div
                                    className="alerts-signal"
                                    data-tone="warn"
                                  >
                                    <strong>Amount</strong>
                                    <span>
                                      {alert.amount != null
                                        ? formatUsdAmount(
                                            alert.amount,
                                            alert.currency,
                                          )
                                        : "Unknown"}
                                    </span>
                                  </div>
                                  <div
                                    className="alerts-signal"
                                    data-tone="info"
                                  >
                                    <strong>Origin</strong>
                                    <span>
                                      {formatAlertOrigin(
                                        alert.location,
                                        alert.ipAddress,
                                      )}
                                    </span>
                                  </div>
                                </div>
                              </div>

                              <div className="alerts-actions">
                                <div className="alerts-buttons">
                                  <button
                                    type="button"
                                    className="alerts-btn primary"
                                    onClick={() =>
                                      handleAlertReview(
                                        alert.id,
                                        "confirmed_risk",
                                      )
                                    }
                                  >
                                    Confirm risk
                                  </button>
                                  <button
                                    type="button"
                                    className="alerts-btn safe"
                                    onClick={() =>
                                      handleAlertReview(
                                        alert.id,
                                        "false_positive",
                                      )
                                    }
                                  >
                                    False positive
                                  </button>
                                  <button
                                    type="button"
                                    className="alerts-btn warn"
                                    onClick={() =>
                                      handleAlertReview(alert.id, "escalated")
                                    }
                                  >
                                    Escalate
                                  </button>
                                  <button
                                    type="button"
                                    className="alerts-btn"
                                    onClick={() =>
                                      handleAlertReview(
                                        alert.id,
                                        "pending_review",
                                      )
                                    }
                                  >
                                    Reset
                                  </button>
                                </div>
                              </div>
                            </div>

                            <div className="alerts-extra">
                              <div>
                                <strong>Full explanation</strong>
                                <span>{alert.explanation}</span>
                              </div>
                              <div>
                                <strong>AI action</strong>
                                <span>
                                  {alert.aiDecision || "Monitoring only"}
                                </span>
                              </div>
                              <div>
                                <strong>Model</strong>
                                <span>
                                  {alert.modelVersion || "unknown"}
                                  {alert.modelSource
                                    ? ` - ${alert.modelSource}`
                                    : ""}
                                </span>
                              </div>
                              <div>
                                <strong>Event reference</strong>
                                <span>
                                  {alert.transactionId ||
                                    alert.eventId ||
                                    "Unavailable"}
                                </span>
                              </div>
                              <div>
                                <strong>Reviewed by</strong>
                                <span>
                                  {alert.reviewedBy || "-"}
                                  {reviewedAt &&
                                  !Number.isNaN(reviewedAt.getTime())
                                    ? ` - ${reviewedAt.toLocaleString("en-US")}`
                                    : ""}
                                </span>
                              </div>
                              <div>
                                <strong>Admin note</strong>
                                <span>{alert.adminNote || "No note"}</span>
                              </div>
                              <div>
                                <strong>Source</strong>
                                <span>{alert.sourceAction}</span>
                              </div>
                            </div>
                          </>
                        ) : null}
                      </article>
                    );
                  })}
                </div>

                <div className="audit-pagination">
                  <div className="pager">
                    <button
                      disabled={currentAlertPage === 1}
                      onClick={() => setAlertPage((p) => Math.max(1, p - 1))}
                    >
                      {"<"}
                    </button>
                    {Array.from(
                      { length: Math.min(totalAlertPages, 5) },
                      (_, i) => i + 1,
                    ).map((n) => (
                      <button
                        key={n}
                        className={n === currentAlertPage ? "active" : ""}
                        onClick={() => setAlertPage(n)}
                      >
                        {n}
                      </button>
                    ))}
                    <button
                      disabled={
                        currentAlertPage === totalAlertPages ||
                        totalAlertPages === 0
                      }
                      onClick={() =>
                        setAlertPage((p) => Math.min(totalAlertPages, p + 1))
                      }
                    >
                      {">"}
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {active === "profile" && (
          <div className="prof-page">
            <div className="prof-card">
              <div className="prof-header">
                <div className="prof-avatar-wrap">
                  <img
                    className="prof-avatar"
                    src={profile.avatar}
                    alt="avatar"
                    role="button"
                    tabIndex={0}
                    onClick={openAvatarPicker}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ")
                        openAvatarPicker();
                    }}
                  />
                  <button
                    type="button"
                    className="prof-avatar-btn"
                    aria-label="Upload photo"
                    onClick={openAvatarPicker}
                  >
                    📷
                  </button>
                  <input
                    ref={avatarInputRef}
                    type="file"
                    accept="image/*"
                    onChange={handleAvatarChange}
                    style={{ display: "none" }}
                  />
                </div>
                <div className="prof-name">{profile.name}</div>
                <p className="prof-email">{profile.email}</p>
              </div>

              <div className="prof-grid">
                <div className="prof-field">
                  <label>Full Name</label>
                  <input
                    value={profile.name}
                    onChange={(e) =>
                      setProfile({ ...profile, name: e.target.value })
                    }
                  />
                </div>
                <div className="prof-field">
                  <label>User Name</label>
                  <input
                    value={profile.username}
                    onChange={(e) =>
                      setProfile({ ...profile, username: e.target.value })
                    }
                  />
                </div>
                <div className="prof-field">
                  <label>Email</label>
                  <input
                    value={profile.email}
                    onChange={(e) =>
                      setProfile({ ...profile, email: e.target.value })
                    }
                  />
                </div>
                <div className="prof-field">
                  <label>Phone</label>
                  <input
                    value={profile.phone}
                    onChange={(e) =>
                      setProfile({ ...profile, phone: e.target.value })
                    }
                  />
                </div>
                <div className="prof-field">
                  <label>Password</label>
                  <input
                    type="password"
                    value={profile.password}
                    onChange={(e) =>
                      setProfile({ ...profile, password: e.target.value })
                    }
                  />
                </div>
                <div className="prof-field">
                  <label>Date of Birth</label>
                  <input
                    type="date"
                    value={profile.dob}
                    onChange={(e) =>
                      setProfile({ ...profile, dob: e.target.value })
                    }
                  />
                </div>
                <div className="prof-field">
                  <label>Present Address</label>
                  <input
                    value={profile.present}
                    onChange={(e) =>
                      setProfile({ ...profile, present: e.target.value })
                    }
                  />
                </div>
                <div className="prof-field">
                  <label>Permanent Address</label>
                  <input
                    value={profile.permanent}
                    onChange={(e) =>
                      setProfile({ ...profile, permanent: e.target.value })
                    }
                  />
                </div>
                <div className="prof-field">
                  <label>Postal Code</label>
                  <input
                    value={profile.postal}
                    onChange={(e) =>
                      setProfile({ ...profile, postal: e.target.value })
                    }
                  />
                </div>
              </div>

              <div className="prof-actions">
                <button
                  className="prof-save"
                  onClick={() => alert("Profile saved (demo only).")}
                >
                  Save Changes
                </button>
              </div>
            </div>
          </div>
        )}

        {active === "setting" && (
          <div className="set-card">
            <h2 style={{ marginTop: 0, marginBottom: 10 }}>Settings</h2>
            <div className="set-row">
              <div>
                <h4>Theme</h4>
                <p>Dark mode is fixed for admin.</p>
              </div>
              <button
                className={`set-toggle ${theme === "dark" ? "on" : ""}`}
                onClick={() => {}}
                aria-label="Toggle theme"
              />
            </div>
            <div className="set-row">
              <div>
                <h4>Notifications</h4>
                <p>Send important updates to your email.</p>
              </div>
              <button
                className={`set-toggle ${settings.notifications ? "on" : ""}`}
                onClick={() =>
                  setSettings((s) => ({
                    ...s,
                    notifications: !s.notifications,
                  }))
                }
              />
            </div>
            <div className="set-row">
              <div>
                <h4>Two-factor authentication</h4>
                <p>Add an extra layer of security to sign in.</p>
              </div>
              <button
                className={`set-toggle ${settings.twofa ? "on" : ""}`}
                onClick={() => setSettings((s) => ({ ...s, twofa: !s.twofa }))}
              />
            </div>
            <div className="set-row">
              <div>
                <h4>Weekly summary</h4>
                <p>Receive performance summary every Monday.</p>
              </div>
              <button
                className={`set-toggle ${settings.weekly ? "on" : ""}`}
                onClick={() =>
                  setSettings((s) => ({ ...s, weekly: !s.weekly }))
                }
              />
            </div>
          </div>
        )}

        {active === "users" && (
          <>
            <div className="user-card">
              <div className="user-head">
                <div>
                  <h2 style={{ margin: 0, fontSize: 28, color: "var(--text)" }}>
                    User Management
                  </h2>
                </div>
                <div className="user-actions" style={{ gap: 12 }}>
                  <input
                    className="user-search"
                    type="search"
                    placeholder="Search name or email..."
                    value={userSearch}
                    onChange={(e) => setUserSearch(e.target.value)}
                  />
                  <div className="user-filter-pop">
                    <button
                      className="user-filter-btn"
                      type="button"
                      aria-expanded={showUserFilters}
                      onClick={() => setShowUserFilters((v) => !v)}
                    >
                      <span aria-hidden="true">☰</span> More Filters
                    </button>
                    {showUserFilters && (
                      <div className="user-filter-panel">
                        <label>
                          Role
                          <select
                            value={userRoleFilter}
                            onChange={(e) =>
                              setUserRoleFilter(
                                e.target.value as typeof userRoleFilter,
                              )
                            }
                          >
                            <option value="all">All roles</option>
                            <option value="Admin">Admin</option>
                            <option value="User">User</option>
                          </select>
                        </label>
                        <label>
                          Last login
                          <select
                            value={userSort}
                            onChange={(e) =>
                              setUserSort(e.target.value as typeof userSort)
                            }
                          >
                            <option value="latest">Newest first</option>
                            <option value="oldest">Oldest first</option>
                          </select>
                        </label>
                        <div className="user-filter-actions">
                          <button
                            type="button"
                            onClick={() => {
                              setUserRoleFilter("all");
                              setUserSort("latest");
                            }}
                          >
                            Reset
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              <div className="user-tabs">
                {[
                  { id: "all", label: "All Users" },
                  { id: "active", label: "Active" },
                  { id: "locked", label: "Locked" },
                ].map((t) => (
                  <button
                    key={t.id}
                    className={`user-tab ${userTab === t.id ? "active" : ""}`}
                    onClick={() => setUserTab(t.id as typeof userTab)}
                  >
                    {t.label}
                  </button>
                ))}
              </div>

              <div className="user-table-wrap">
                <table className="user-table">
                  <thead>
                    <tr>
                      <th>Full name</th>
                      <th>Contact details</th>
                      <th>Role</th>
                      <th>Birthday</th>
                      <th>Address</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedUsers.map((u) => (
                      <tr key={u.id} className="user-row">
                        <td>
                          <div className="user-person">
                            <img
                              className="user-avatar"
                              src={u.avatar}
                              alt={u.name}
                            />
                            <div>
                              <div className="user-name">{u.name}</div>
                              <div className="user-title">{u.title}</div>
                            </div>
                          </div>
                        </td>
                        <td style={{ color: "var(--text)" }}>
                          <div className="user-contact">
                            <div>{u.email}</div>
                            <div className="user-title">{u.phone}</div>
                          </div>
                        </td>
                        <td style={{ color: "var(--text)" }}>{u.role}</td>
                        <td style={{ color: "var(--text)" }}>
                          {u.birthday
                            ? new Date(u.birthday).toLocaleDateString("en-US", {
                                month: "short",
                                day: "2-digit",
                                year: "numeric",
                              })
                            : "-"}
                        </td>
                        <td style={{ color: "var(--text)" }}>{u.address}</td>
                        <td>
                          <span
                            className={`user-badge ${u.status === "Active" ? "active" : "locked"}`}
                          >
                            {u.status}
                          </span>
                        </td>
                        <td>
                          <div className="user-action-group">
                            <button
                              className="user-btn primary"
                              onClick={async () => {
                                if (!token) return;
                                const value = window.prompt(
                                  `Enter amount to top up for ${u.email}`,
                                  "100",
                                );
                                if (value === null) return;
                                const amount = Number(value);
                                if (!Number.isFinite(amount) || amount <= 0) {
                                  window.alert(
                                    "Amount must be a positive number.",
                                  );
                                  return;
                                }

                                const resp = await fetch(
                                  `${API_BASE}/admin/users/${u.id}/deposit`,
                                  {
                                    method: "POST",
                                    headers: {
                                      "Content-Type": "application/json",
                                      Authorization: `Bearer ${token}`,
                                    },
                                    body: JSON.stringify({ amount }),
                                  },
                                );
                                const payload = (await resp
                                  .json()
                                  .catch(() => null)) as {
                                  error?: string;
                                  transaction?: AdminTransactionApi;
                                } | null;
                                if (!resp.ok || !payload?.transaction) {
                                  window.alert(
                                    payload?.error || "Top up failed.",
                                  );
                                  return;
                                }

                                setTransactions((list) => [
                                  mapAdminTxnToView(payload.transaction!),
                                  ...list,
                                ]);
                                window.alert(
                                  `Added $${amount.toLocaleString("en-US", {
                                    minimumFractionDigits: 2,
                                    maximumFractionDigits: 2,
                                  })} to ${u.email}`,
                                );
                              }}
                            >
                              Add Money
                            </button>
                            <button
                              className="user-btn danger"
                              onClick={async () => {
                                if (!token) return;
                                const targetStatus =
                                  u.status === "Locked" ? "ACTIVE" : "DISABLED";
                                const resp = await fetch(
                                  `${API_BASE}/admin/users/${u.id}/status`,
                                  {
                                    method: "PATCH",
                                    headers: {
                                      "Content-Type": "application/json",
                                      Authorization: `Bearer ${token}`,
                                    },
                                    body: JSON.stringify({
                                      status: targetStatus,
                                      reason: "manual update from admin panel",
                                    }),
                                  },
                                );
                                if (!resp.ok) return;
                                setUsers((list) =>
                                  list.map((x) =>
                                    x.id === u.id
                                      ? {
                                          ...x,
                                          status:
                                            targetStatus === "ACTIVE"
                                              ? "Active"
                                              : "Locked",
                                        }
                                      : x,
                                  ),
                                );
                              }}
                            >
                              {u.status === "Locked" ? "Unlock" : "Lock"}
                            </button>
                            <button
                              className="user-btn text"
                              onClick={() => setTxUser(u)}
                            >
                              Transactions
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="user-footer">
                <span>
                  Showing{" "}
                  {filteredUsers.length
                    ? (currentUserPage - 1) * userPageSize + 1
                    : 0}{" "}
                  to{" "}
                  {Math.min(
                    currentUserPage * userPageSize,
                    filteredUsers.length,
                  )}{" "}
                  of {filteredUsers.length} users
                </span>
                <div className="pager">
                  <button
                    disabled={currentUserPage === 1}
                    onClick={() => setUserPage((p) => Math.max(1, p - 1))}
                  >
                    {"<"}
                  </button>
                  {Array.from(
                    { length: Math.min(totalUserPages, 5) },
                    (_, i) => i + 1,
                  ).map((n) => (
                    <button
                      key={n}
                      className={n === currentUserPage ? "active" : ""}
                      onClick={() => setUserPage(n)}
                    >
                      {n}
                    </button>
                  ))}
                  <button
                    disabled={
                      currentUserPage === totalUserPages ||
                      filteredUsers.length === 0
                    }
                    onClick={() =>
                      setUserPage((p) => Math.min(totalUserPages, p + 1))
                    }
                  >
                    {">"}
                  </button>
                </div>
              </div>
            </div>

            {txUser && typeof document !== "undefined"
              ? createPortal(
                  <div
                    className="tx-backdrop"
                    role="dialog"
                    aria-modal="true"
                    onClick={() => setTxUser(null)}
                  >
                    <div
                      className="tx-modal"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <div className="tx-head">
                        <h3>Transactions · {txUser.name}</h3>
                        <button
                          className="tx-close"
                          aria-label="Close"
                          onClick={() => setTxUser(null)}
                        >
                          X
                        </button>
                      </div>
                      <table className="tx-table">
                        <thead>
                          <tr>
                            <th>Date</th>
                            <th>Type</th>
                            <th>Amount</th>
                            <th>Status</th>
                            <th>Reference</th>
                          </tr>
                        </thead>
                        <tbody>
                          {userTransactions.length ? (
                            userTransactions.map((t) => (
                              <tr key={t.id}>
                                <td>{t.date}</td>
                                <td>{t.type}</td>
                                <td>{t.amount}</td>
                                <td>
                                  <span
                                    className={`tx-chip ${t.status.toLowerCase()}`}
                                  >
                                    {t.status}
                                  </span>
                                </td>
                                <td>{t.reference}</td>
                              </tr>
                            ))
                          ) : (
                            <tr>
                              <td
                                colSpan={5}
                                style={{ textAlign: "center", padding: 18 }}
                              >
                                No transactions recorded.
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>,
                  document.body,
                )
              : null}
          </>
        )}

        {active === "audit" && (
          <div className="audit-card">
            <div className="audit-tabs">
              <button className="audit-tab active" type="button">
                Audit Logs
              </button>
            </div>

            <div className="audit-head">
              <div className="audit-filters">
                <select
                  className="audit-select"
                  value={auditRange}
                  onChange={(e) =>
                    setAuditRange(e.target.value as typeof auditRange)
                  }
                >
                  <option value="7">Last 7 Days</option>
                  <option value="30">Last 30 Days</option>
                  <option value="90">Last 90 Days</option>
                </select>
                <input
                  className="audit-select audit-input"
                  type="text"
                  value={auditAccountQuery}
                  onChange={(e) => setAuditAccountQuery(e.target.value)}
                  placeholder="Account name"
                  aria-label="Filter by account name"
                />
                <select
                  className="audit-select"
                  value={auditActivity}
                  onChange={(e) =>
                    setAuditActivity(e.target.value as typeof auditActivity)
                  }
                >
                  <option value="all">All Types</option>
                  <option value="um">User Management</option>
                  <option value="tx">Transaction</option>
                  <option value="acc">Account Edit</option>
                  <option value="login">Login</option>
                  <option value="sec">Security</option>
                </select>
                <select
                  className="audit-select"
                  value={auditStatus}
                  onChange={(e) =>
                    setAuditStatus(e.target.value as typeof auditStatus)
                  }
                >
                  <option value="all">Status: All</option>
                  <option value="ok">Success</option>
                  <option value="pending">Pending</option>
                  <option value="fail">Failed</option>
                </select>
                <select
                  className="audit-select"
                  value={auditSource}
                  onChange={(e) =>
                    setAuditSource(e.target.value as typeof auditSource)
                  }
                >
                  <option value="human">User Activity</option>
                  <option value="all">All Sources</option>
                  <option value="ai">AI / System</option>
                </select>
              </div>
              <span className="audit-count">
                Showing {auditTotalCount} logs
              </span>
            </div>

            <div className="audit-table-wrap">
              <table className="audit-table">
                <thead>
                  <tr>
                    <th>Date & Time</th>
                    <th>Type</th>
                    <th>Admin / Source</th>
                    <th>Details</th>
                    <th>Status</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedAuditLogs.map((log) => {
                    const dt = new Date(log.ts.replace(" ", "T"));
                    const isDateValid = !Number.isNaN(dt.getTime());
                    const dateLabel = isDateValid
                      ? dt.toLocaleDateString("en-US", {
                          month: "short",
                          day: "2-digit",
                          year: "numeric",
                        })
                      : log.ts;
                    const timeLabel = isDateValid
                      ? dt.toLocaleTimeString("en-US", {
                          hour: "2-digit",
                          minute: "2-digit",
                          second: "2-digit",
                        })
                      : "--:--:--";
                    return (
                      <React.Fragment key={log.id}>
                        <tr className="audit-row main">
                          <td>
                            <div className="audit-time">
                              <span className="audit-date-label">
                                {dateLabel}
                              </span>
                              <span className="audit-time-label">
                                {timeLabel}
                              </span>
                            </div>
                          </td>
                          <td>
                            <span className="audit-type">{log.category}</span>
                          </td>
                          <td>
                            <div className="audit-admin">
                              <span className="audit-admin-name">
                                {log.admin}
                              </span>
                              <span className="audit-admin-sub">{log.ip}</span>
                            </div>
                          </td>
                          <td>{log.detail}</td>
                          <td>
                            <span className={`audit-status ${log.statusClass}`}>
                              {log.status}
                            </span>
                          </td>
                          <td>
                            <button
                              className="audit-detail-btn"
                              type="button"
                              onClick={() =>
                                setExpandedAudit((prev) =>
                                  prev === log.id ? null : log.id,
                                )
                              }
                            >
                              {expandedAudit === log.id ? "Hide" : "Details"}
                            </button>
                          </td>
                        </tr>
                        {expandedAudit === log.id && (
                          <tr className="audit-row audit-expand">
                            <td colSpan={6}>
                              <div className="audit-meta">
                                <div>
                                  <strong>Log ID</strong>
                                  <span title={log.requestId || "-"}>
                                    {formatAuditRequestId(log.requestId)}
                                  </span>
                                </div>
                                <div>
                                  <strong>Where</strong>
                                  <span>
                                    {formatAuditLocation(log.location)}
                                  </span>
                                </div>
                                <div>
                                  <strong>Device</strong>
                                  <span title={log.userAgent || "-"}>
                                    {summarizeAuditUserAgent(log.userAgent)}
                                  </span>
                                </div>
                                <div>
                                  <strong>Export</strong>
                                  <button
                                    type="button"
                                    className="audit-detail-btn"
                                    onClick={handleExportCsv}
                                  >
                                    Export CSV
                                  </button>
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>

            <div className="audit-pagination">
              <span className="audit-page-meta">
                Page {currentAuditPage} / {totalAuditPages}
              </span>
              <div className="pager">
                <button
                  disabled={currentAuditPage === 1}
                  onClick={() => setAuditPage((p) => Math.max(1, p - 1))}
                >
                  {"<"}
                </button>
                {visibleAuditPages.map((item, index) =>
                  item === "..." ? (
                    <span key={`ellipsis-${index}`} className="pager-ellipsis">
                      ...
                    </span>
                  ) : (
                    <button
                      key={item}
                      className={item === currentAuditPage ? "active" : ""}
                      onClick={() => setAuditPage(item)}
                    >
                      {item}
                    </button>
                  ),
                )}
                <button
                  disabled={
                    currentAuditPage === totalAuditPages ||
                    totalAuditPages === 0
                  }
                  onClick={() =>
                    setAuditPage((p) => Math.min(totalAuditPages, p + 1))
                  }
                >
                  {">"}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default AdminApp;
