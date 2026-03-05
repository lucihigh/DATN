import React, { useEffect, useMemo, useRef, useState } from "react";

import { useAuth } from "../context/AuthContext";

import "../index.css";

type KpiCard = {
  title: string;
  value: string;
  delta: string;
  items: { label: string; value: string; color: string }[];
};

const kpiCards: KpiCard[] = [
  {
    title: "Active users",
    value: "68,200",
    delta: "+8.2%",
    items: [
      { label: "App MAU", value: "52,400", color: "#5b21b6" },
      { label: "Web MAU", value: "9,860", color: "#6366f1" },
      { label: "New signups (7d)", value: "5,940", color: "#f59e0b" },
    ],
  },
  {
    title: "Top-up success rate",
    value: "97.6%",
    delta: "+1.4%",
    items: [
      { label: "Bank transfer", value: "99%", color: "#5b21b6" },
      { label: "Cards", value: "96%", color: "#6366f1" },
      { label: "Wallet/mini-app partners", value: "95%", color: "#f59e0b" },
    ],
  },
  {
    title: "KYC completion",
    value: "91.3%",
    delta: "-0.8%",
    items: [
      { label: "Tier 1 verified", value: "55%", color: "#5b21b6" },
      { label: "Tier 2 verified", value: "29%", color: "#6366f1" },
      { label: "Pending review", value: "16%", color: "#f59e0b" },
    ],
  },
  {
    title: "Monthly GMV",
    value: "$12,450,320",
    delta: "+18.3%",
    items: [
      { label: "P2P transfers", value: "$5,980,000", color: "#5b21b6" },
      { label: "Bill payments", value: "$3,210,000", color: "#6366f1" },
      { label: "Offline QR", value: "$2,180,000", color: "#f59e0b" },
    ],
  },
];

// Monthly GMV (k USD)
const monthlyKpi = [
  920, 1140, 1280, 1360, 1520, 1480, 1210, 1600, 1710, 1820, 1760, 1940,
];
const monthlyLabels = [
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

const engagementChannels = [
  { name: "Mobile app", now: 32000, prev: 28800 },
  { name: "Web portal", now: 14800, prev: 13100 },
  { name: "Partner mini app", now: 17200, prev: 15400 },
  { name: "Agent network", now: 9200, prev: 8100 },
];

// Average ticket size (VND thousand)
const revenueTrend = [
  { month: "Jan", now: 182, prev: 169 },
  { month: "Feb", now: 188, prev: 174 },
  { month: "Mar", now: 194, prev: 176 },
  { month: "Apr", now: 201, prev: 182 },
  { month: "May", now: 214, prev: 190 },
  { month: "Jun", now: 208, prev: 193 },
  { month: "Jul", now: 202, prev: 195 },
  { month: "Aug", now: 225, prev: 204 },
];

const categories = [
  { name: "P2P transfers", value: 34, count: 1_280_000 },
  { name: "Bill payments", value: 26, count: 620_000 },
  { name: "Offline QR", value: 18, count: 410_000 },
  { name: "Mobile data top-up", value: 12, count: 290_000 },
  { name: "Gaming vouchers", value: 6, count: 140_000 },
  { name: "Ride-hailing", value: 4, count: 95_000 },
];

type AdminUser = {
  id: string;
  name: string;
  email: string;
  role: "Admin" | "Support" | "Viewer";
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

type AuditLogDoc = {
  _id: string;
  userId: string | null;
  actor?: string | null;
  action: string;
  details?: string | Record<string, unknown> | null;
  ipAddress?: string | null;
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

const prettyAction = (action: string) =>
  action
    .toLowerCase()
    .split("_")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");

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

const mapAuditDocToView = (doc: AuditLogDoc): AuditLogView => {
  const detailsObj =
    doc.details && typeof doc.details === "object" ? doc.details : undefined;
  const detail =
    typeof doc.details === "string"
      ? doc.details
      : (typeof detailsObj?.message === "string" && detailsObj.message) ||
        (typeof detailsObj?.reason === "string" && detailsObj.reason) ||
        (typeof detailsObj?.description === "string" &&
          detailsObj.description) ||
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
      typeof detailsObj?.userAgent === "string" ? detailsObj.userAgent : "",
    requestId:
      typeof detailsObj?.requestId === "string" ? detailsObj.requestId : "",
    location:
      typeof detailsObj?.location === "string" ? detailsObj.location : "",
  };
};

const USERS_STORE_KEY = "ewallet_admin_users";

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
  .ana-bar-item { text-align:center; }
  .ana-bar { width:100%; background:#5b21b6; border-radius:10px 10px 6px 6px; }
  .ana-bar-label { margin-top:6px; font-size:12px; color:#6b7280; }
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
  .mf-main { background: #f6f7fb; }
  .mf-sidebar {
    background: #ffffff;
    border-right: 1px solid #e5e7eb;
    color: #111827;
  }

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
  .user-card { background:#fff; border-radius:16px; padding:20px; box-shadow:0 10px 28px rgba(0,0,0,0.08); }
  .user-head { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:18px; }
  .user-actions { display:flex; gap:10px; align-items:center; }
  .user-search { padding:10px 12px; border:1px solid #e5e7eb; border-radius:10px; min-width:220px; }
  .user-table-wrap { overflow-x:auto; }
  .user-table { width:100%; border-collapse:collapse; }
  .user-table th, .user-table td { padding:14px 10px; text-align:left; border-bottom:1px solid #eceff5; font-size:14px; }
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
  .user-footer { padding:12px 0 6px; color:#6b7280; font-size:13px; display:flex; justify-content:space-between; align-items:center; }
  .pager { display:flex; gap:8px; }
  .pager button { width:34px; height:34px; border-radius:8px; border:1px solid #e5e7eb; background:#fff; cursor:pointer; }
  .pager button.active { background:#1f6bff; color:#fff; border-color:#1f6bff; }

  /* Profile */
  .prof-page { padding: 24px; display:flex; justify-content:center; }
  .prof-card {
    background: #ffffff;
    color: #0f172a;
    border-radius: 18px;
    padding: 36px;
    box-shadow: 0 18px 46px rgba(15,23,42,0.08);
    border: 1px solid #e5e7eb;
    width: min(1100px, 100%);
  }
  .prof-header { display:flex; flex-direction:column; align-items:center; gap:10px; margin-bottom:24px; color:#0f172a; }
  .prof-avatar-wrap { position:relative; width:120px; height:120px; }
  .prof-avatar { width:120px; height:120px; border-radius:50%; object-fit:cover; border:4px solid #182449; cursor:pointer; }
  .prof-avatar-btn {
    position:absolute; right:6px; bottom:6px;
    width:34px; height:34px; border-radius:50%;
    background:#1f6bff; border:none; color:white;
    display:grid; place-items:center; cursor:pointer;
    box-shadow:0 10px 20px rgba(31,107,255,0.4);
  }
  .prof-name { font-size:22px; margin:4px 0 0; font-weight:700; color:#0f172a; }
  .prof-email { margin:0; color:#475569; }
  .prof-grid {
    display:grid;
    grid-template-columns: repeat(2, minmax(280px, 1fr));
    gap:18px 20px;
    margin-bottom:22px;
  }
  .prof-field { display:flex; flex-direction:column; gap:6px; }
  .prof-field label { color:#6b7280; font-size:13px; }
  .prof-field input {
    background:#f8fafc;
    border:1px solid #dfe3ea;
    color:#0f172a;
    padding:12px 14px;
    border-radius:12px;
    font-size:14px;
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
    overflow: hidden;
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
  }
  .audit-tabs { display:flex; align-items:center; gap:18px; border-bottom:1px solid #1d3552; padding-bottom:10px; margin-bottom:16px; }
  .audit-tab {
    border:none;
    background:transparent;
    color:#7a95b8;
    font-size:18px;
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
    cursor:pointer;
  }
  .audit-count { color:#7089a9; font-size:12px; letter-spacing:1.2px; text-transform:uppercase; font-weight:700; }
  .audit-table-wrap { border:1px solid #1f3857; border-radius:14px; overflow:hidden; background:#0a1a2f; }
  .audit-table { width:100%; border-collapse:collapse; }
  .audit-table th, .audit-table td { padding:14px 12px; text-align:left; vertical-align:middle; border-bottom:1px solid #1a3350; }
  .audit-table th { background:#0d2139; color:#87a7cd; font-size:12px; letter-spacing:0.8px; text-transform:uppercase; }
  .audit-table td { color:#d8e7ff; }
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
  .audit-meta strong { display:block; color:#d7e7ff; font-size:12px; margin-bottom:4px; }
  .audit-pagination {
    display:grid;
    grid-template-columns:1fr auto 1fr;
    align-items:center;
    margin-top:14px;
    color:#6e89ad;
    gap:8px;
  }
  .audit-page-nav {
    border:none;
    background:transparent;
    color:#2c9bff;
    font-weight:700;
    cursor:pointer;
    justify-self:start;
  }
  .audit-page-nav.next { justify-self:end; }
  .audit-page-nav:disabled { color:#4c607c; cursor:not-allowed; }
  .audit-pager { display:flex; justify-content:center; gap:8px; }
  .audit-pager button {
    min-width:32px;
    height:32px;
    border:1px solid #274667;
    border-radius:8px;
    background:#0f243d;
    color:#a8c1e2;
    cursor:pointer;
    font-weight:700;
  }
  .audit-pager button.active { background:#1f8fff; border-color:#1f8fff; color:#fff; }

  /* Compact desktop layout for 16:9 screens */
  @media (min-width: 1280px) and (min-aspect-ratio: 16/9) {
    .mf-sidebar { width: 220px; padding: 20px 14px; gap: 14px; }
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
    .audit-filters { width: 100%; }
    .audit-select { flex: 1 1 170px; min-width: 0; }
    .audit-table-wrap { overflow-x: auto; }
    .audit-table { min-width: 780px; }
    .audit-pagination { grid-template-columns: 1fr; }
    .audit-page-nav, .audit-page-nav.next { justify-self: center; }
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
  const { user, logout } = useAuth();
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    if (typeof window === "undefined") return "light";
    return (localStorage.getItem("admin-theme") as "light" | "dark") || "light";
  });
  const [period, setPeriod] = useState<"year" | "month" | "week">("year");
  const [selectedDate, setSelectedDate] = useState(() => {
    // default to current date for realistic demo
    const now = new Date();
    return now.toISOString().slice(0, 10);
  });
  const [active, setActive] = useState<
    "dashboard" | "users" | "audit" | "profile" | "setting"
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
  const defaultUsers: AdminUser[] = [
    {
      id: "u001",
      name: "Jenny Wilson",
      email: "jenny@example.com",
      role: "Admin",
      title: "Product Manager",
      phone: "+1 (415) 555-0101",
      birthday: "1990-05-12",
      address: "123 Tech Avenue, San Francisco, CA",
      avatar: "https://i.pravatar.cc/80?img=32",
      status: "Active",
      lastLogin: "2026-02-23 21:40",
    },
    {
      id: "u002",
      name: "Devon Lane",
      email: "devon@example.com",
      role: "Support",
      title: "Security Lead",
      phone: "+1 (510) 555-2345",
      birthday: "1988-11-22",
      address: "456 Data Drive, New York, NY",
      avatar: "https://i.pravatar.cc/80?img=48",
      status: "Active",
      lastLogin: "2026-02-22 18:12",
    },
    {
      id: "u003",
      name: "Courtney Henry",
      email: "courtney@example.com",
      role: "Viewer",
      title: "Former Engineer",
      phone: "+1 (303) 555-9876",
      birthday: "1992-03-10",
      address: "789 Cloud St, Austin, TX",
      avatar: "https://i.pravatar.cc/80?img=15",
      status: "Locked",
      lastLogin: "2026-02-24 08:05",
    },
    {
      id: "u004",
      name: "Eleanor Pena",
      email: "eleanor@example.com",
      role: "Support",
      title: "UX Researcher",
      phone: "+1 (206) 555-4567",
      birthday: "1995-07-01",
      address: "101 Logic Ave, Seattle, WA",
      avatar: "https://i.pravatar.cc/80?img=67",
      status: "Active",
      lastLogin: "2026-02-23 10:18",
    },
  ];

  const transactions: Transaction[] = [
    {
      id: "tx-1001",
      userId: "u001",
      date: "2026-02-24 09:15",
      type: "Payment",
      amount: "$120.50",
      status: "Completed",
      reference: "INV-42015",
    },
    {
      id: "tx-1002",
      userId: "u001",
      date: "2026-02-23 21:05",
      type: "Transfer",
      amount: "$980.00",
      status: "Completed",
      reference: "TRF-88421",
    },
    {
      id: "tx-1003",
      userId: "u002",
      date: "2026-02-22 14:44",
      type: "Refund",
      amount: "$35.20",
      status: "Pending",
      reference: "RF-33812",
    },
    {
      id: "tx-1004",
      userId: "u003",
      date: "2026-02-21 18:07",
      type: "Payment",
      amount: "$260.00",
      status: "Failed",
      reference: "INV-42001",
    },
    {
      id: "tx-1005",
      userId: "u004",
      date: "2026-02-20 11:32",
      type: "Transfer",
      amount: "$1,240.00",
      status: "Completed",
      reference: "TRF-88310",
    },
    {
      id: "tx-1006",
      userId: "u002",
      date: "2026-02-24 07:55",
      type: "Payment",
      amount: "$72.15",
      status: "Completed",
      reference: "INV-42050",
    },
  ];

  const auditLogDocs: AuditLogDoc[] = [
    {
      _id: "699f98aa1ae0d9039da45276",
      userId: null,
      actor: "ai-service",
      action: "AI_LOGIN_ALERT",
      details: {
        message: "Impossible travel pattern detected.",
        requestId: "req_ai_45276",
        userAgent: "risk-engine/1.8",
        location: "Singapore",
      },
      ipAddress: "88.88.88.88",
      createdAt: "2026-02-26T00:49:46.897Z",
    },
    {
      _id: "699f98aa1ae0d9039da45277",
      userId: "65f8fb0a8d7bb2218a12ab10",
      actor: "alex.rivera@company.com",
      action: "USER_LOCKED",
      details: {
        message: "Locked user account after repeated fraud signals.",
        requestId: "req_admin_1001",
        userAgent: "Mozilla/5.0",
        location: "San Francisco, USA",
      },
      ipAddress: "192.168.1.45",
      createdAt: "2026-02-25T14:32:01.000Z",
    },
    {
      _id: "699f98aa1ae0d9039da45278",
      userId: "65f8fb0a8d7bb2218a12ab11",
      actor: "sarah.chen@company.com",
      action: "TRANSACTION_REFUND_APPROVED",
      details: {
        message: "Refund approved for trx #TRX-990",
        requestId: "req_tx_990",
        userAgent: "Mozilla/5.0",
        location: "New York, USA",
      },
      ipAddress: "203.0.113.12",
      createdAt: "2026-02-25T13:15:22.000Z",
    },
    {
      _id: "699f98aa1ae0d9039da45279",
      userId: "65f8fb0a8d7bb2218a12ab12",
      actor: "michael.scott@company.com",
      action: "ACCOUNT_ROLE_UPDATED",
      details: "Changed role from Viewer to Support",
      ipAddress: "172.16.254.1",
      createdAt: "2026-02-25T11:05:40.000Z",
    },
    {
      _id: "699f98aa1ae0d9039da45280",
      userId: null,
      actor: "ai-service",
      action: "AI_LOGIN_REVIEW_PENDING",
      details: {
        message: "Login flagged and queued for manual review.",
        requestId: "req_ai_review_042",
        userAgent: "risk-engine/1.8",
        location: "Tokyo, Japan",
      },
      ipAddress: "45.76.11.20",
      createdAt: "2026-02-25T09:45:12.000Z",
    },
    {
      _id: "699f98aa1ae0d9039da45281",
      userId: "65f8fb0a8d7bb2218a12ab13",
      actor: "sarah.chen@company.com",
      action: "SECURITY_POLICY_UPDATED",
      details: {
        message: "Updated lockout policy and rate limit.",
        requestId: "req_sec_778",
        userAgent: "Mozilla/5.0",
        location: "Los Angeles, USA",
      },
      ipAddress: "203.0.113.12",
      createdAt: "2026-02-24T08:20:05.000Z",
    },
    {
      _id: "699f98aa1ae0d9039da45282",
      userId: null,
      actor: "alex.rivera@company.com",
      action: "LOGIN_FAILED",
      details: {
        message: "Failed login attempt from unknown browser.",
        requestId: "req_login_fail_11",
        userAgent: "Mozilla/5.0 Firefox/123.0",
        location: "New York, USA",
      },
      ipAddress: "203.0.113.12",
      createdAt: "2026-02-24T07:12:54.000Z",
    },
    {
      _id: "699f98aa1ae0d9039da45283",
      userId: "65f8fb0a8d7bb2218a12ab14",
      actor: "alex.rivera@company.com",
      action: "TRANSFER_HIGH_VALUE_APPROVED",
      details: {
        message: "Approved payout over threshold: $25,000",
        requestId: "req_tx_high_25000",
        userAgent: "Mozilla/5.0",
        location: "San Francisco, USA",
      },
      ipAddress: "192.168.1.45",
      createdAt: "2026-02-23T16:44:10.000Z",
    },
  ];

  const auditLogs = auditLogDocs.map(mapAuditDocToView);

  const [users, setUsers] = useState<AdminUser[]>(() => {
    try {
      const raw = localStorage.getItem(USERS_STORE_KEY);
      if (raw) return JSON.parse(raw) as AdminUser[];
    } catch {
      /* ignore */
    }
    return defaultUsers;
  });
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
  const [txUser, setTxUser] = useState<AdminUser | null>(null);
  const [expandedAudit, setExpandedAudit] = useState<string | null>(null);
  const [auditRange, setAuditRange] = useState<"7" | "30" | "90">("7");
  const [auditActivity, setAuditActivity] = useState<
    "all" | "um" | "tx" | "acc" | "login" | "sec"
  >("all");
  const [auditStatus, setAuditStatus] = useState<
    "all" | "ok" | "pending" | "fail"
  >("all");
  const [auditPage, setAuditPage] = useState(1);
  const auditPageSize = 5;

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
          (userRoleFilter === "User" && u.role !== "Admin")),
    );

    return list.sort((a, b) => {
      const timeA = new Date(a.lastLogin.replace(" ", "T")).getTime();
      const timeB = new Date(b.lastLogin.replace(" ", "T")).getTime();
      return userSort === "latest" ? timeB - timeA : timeA - timeB;
    });
  }, [users, userSearch, userTab, userRoleFilter, userSort]);

  const userTransactions = useMemo(
    () => (txUser ? transactions.filter((t) => t.userId === txUser.id) : []),
    [transactions, txUser],
  );

  useEffect(() => {
    setAuditPage(1);
  }, [auditRange, auditActivity, auditStatus]);

  const filteredAuditLogs = useMemo(() => {
    const maxAgeDays = Number(auditRange);
    const now = new Date();
    const list = auditLogs.filter((log) => {
      const logDate = new Date(log.ts.replace(" ", "T"));
      if (!Number.isNaN(maxAgeDays)) {
        const diff =
          (now.getTime() -
            (Number.isNaN(logDate.getTime())
              ? now.getTime()
              : logDate.getTime())) /
          (1000 * 60 * 60 * 24);
        if (diff > maxAgeDays) return false;
      }
      if (auditActivity !== "all" && log.categoryClass !== auditActivity)
        return false;
      if (auditStatus !== "all" && log.statusClass !== auditStatus)
        return false;
      return true;
    });
    if (expandedAudit && !list.some((l) => l.id === expandedAudit)) {
      setExpandedAudit(null);
    }
    return list;
  }, [auditLogs, auditRange, auditActivity, auditStatus, expandedAudit]);

  const totalAuditPages = Math.max(
    1,
    Math.ceil(filteredAuditLogs.length / auditPageSize),
  );
  const currentAuditPage = Math.min(auditPage, totalAuditPages);
  const paginatedAuditLogs = useMemo(() => {
    const start = (currentAuditPage - 1) * auditPageSize;
    return filteredAuditLogs.slice(start, start + auditPageSize);
  }, [filteredAuditLogs, currentAuditPage]);

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
    const rows = filteredAuditLogs.map((l) =>
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

  const filteredBars = useMemo(() => {
    if (period === "year") return { data: monthlyKpi, labels: monthlyLabels };
    if (period === "month") {
      return {
        data: monthlyKpi.slice(-6),
        labels: monthlyLabels.slice(-6),
      };
    }
    // week -> last 4 points
    return {
      data: monthlyKpi.slice(-4),
      labels: monthlyLabels.slice(-4),
    };
  }, [period]);

  const maxMonthly = useMemo(
    () => Math.max(...filteredBars.data),
    [filteredBars],
  );

  const maxChannel = useMemo(
    () => Math.max(...engagementChannels.map((c) => Math.max(c.now, c.prev))),
    [],
  );

  const maxRevenue = useMemo(
    () => Math.max(...revenueTrend.map((r) => Math.max(r.now, r.prev))),
    [],
  );

  useEffect(() => {
    try {
      localStorage.setItem(USERS_STORE_KEY, JSON.stringify(users));
    } catch {
      /* ignore storage failures */
    }
  }, [users]);

  return (
    <div className={`mf-shell theme-${theme}`}>
      <style>{styles}</style>

      <aside className="mf-sidebar">
        <div className="mf-logo">E-Wallet Admin</div>
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

      <div className="mf-main ana-page">
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
              {kpiCards.map((card) => (
                <KpiCard key={card.title} card={card} />
              ))}
            </section>

            <section className="ana-grid-main">
              <div className="ana-card">
                <div className="ana-chart-head">
                  <span>Monthly GMV</span>
                  <span className="ana-muted" aria-hidden="true"></span>
                </div>
                <div className="ana-bar-chart">
                  {filteredBars.data.map((v, i) => (
                    <div key={filteredBars.labels[i]} className="ana-bar-item">
                      <div
                        className="ana-bar"
                        style={{ height: `${(v / maxMonthly) * 100}%` }}
                      />
                      <div className="ana-bar-label">
                        {filteredBars.labels[i]}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="ana-card">
                <h4>Top services by volume</h4>
                <div className="ana-pie-wrap">
                  <div className="ana-pie">
                    <div className="ana-pie-center">Sales</div>
                  </div>
                  <ul className="ana-legend">
                    {categories.map((c, i) => (
                      <li key={c.name}>
                        <span
                          className="ana-dot"
                          style={{
                            background: i % 2 === 0 ? "#5b21b6" : "#6366f1",
                          }}
                        />
                        <div>
                          <strong>{c.name}</strong>
                          <p className="ana-muted">{c.count} products</p>
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
                  {engagementChannels.map((c) => (
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
                  {revenueTrend.map((r) => (
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
                <p>Switch between light and dark mode.</p>
              </div>
              <button
                className={`set-toggle ${theme === "dark" ? "on" : ""}`}
                onClick={() =>
                  setTheme((t) => (t === "dark" ? "light" : "dark"))
                }
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
                      <th>Birthday</th>
                      <th>Address</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredUsers.map((u) => (
                      <tr key={u.id} className="user-row">
                        <td>
                          <div
                            style={{
                              display: "flex",
                              gap: 12,
                              alignItems: "center",
                            }}
                          >
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
                          <div>{u.email}</div>
                          <div className="user-title">{u.phone}</div>
                        </td>
                        <td style={{ color: "var(--text)" }}>
                          {new Date(u.birthday).toLocaleDateString("en-US", {
                            month: "short",
                            day: "2-digit",
                            year: "numeric",
                          })}
                        </td>
                        <td style={{ color: "var(--text)" }}>{u.address}</td>
                        <td>
                          <span
                            className={`user-badge ${u.status === "Active" ? "active" : "locked"}`}
                          >
                            {u.status}
                          </span>
                        </td>
                        <td
                          style={{
                            display: "flex",
                            gap: 8,
                            flexWrap: "wrap",
                            alignItems: "center",
                          }}
                        >
                          <button
                            className="user-btn danger"
                            onClick={() =>
                              setUsers((list) =>
                                list.map((x) =>
                                  x.id === u.id
                                    ? {
                                        ...x,
                                        status:
                                          x.status === "Locked"
                                            ? "Active"
                                            : "Locked",
                                      }
                                    : x,
                                ),
                              )
                            }
                          >
                            {u.status === "Locked" ? "Unlock" : "Lock"}
                          </button>
                          <button
                            className="user-btn text"
                            onClick={() => setTxUser(u)}
                          >
                            Transactions
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="user-footer">
                <span>
                  Showing {filteredUsers.length ? 1 : 0} to{" "}
                  {filteredUsers.length} of {filteredUsers.length} users
                </span>
                <div className="pager" aria-hidden="true">
                  <button disabled>{"<"}</button>
                  <button className="active">1</button>
                  <button disabled>2</button>
                  <button disabled>3</button>
                  <button disabled>{">"}</button>
                </div>
              </div>
            </div>

            {txUser && (
              <div className="tx-backdrop" role="dialog" aria-modal="true">
                <div className="tx-modal">
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
              </div>
            )}
          </>
        )}

        {active === "audit" && (
          <div className="audit-card">
            <div className="audit-tabs">
              <button className="audit-tab active" type="button">
                Audit History
              </button>
              <button className="audit-tab" type="button" aria-disabled="true">
                Security Logs
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
              </div>
              <span className="audit-count">
                Showing {filteredAuditLogs.length} logs
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
                    const typeIcon =
                      log.categoryClass === "tx"
                        ? "⇄"
                        : log.categoryClass === "um"
                          ? "👤"
                          : log.categoryClass === "acc"
                            ? "✎"
                            : log.categoryClass === "login"
                              ? "🔐"
                              : "🛡";
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
                            <span className="audit-type">
                              <span
                                className="audit-type-ico"
                                aria-hidden="true"
                              >
                                {typeIcon}
                              </span>
                              {log.category}
                            </span>
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
                                  <strong>Request ID</strong>
                                  <span>{log.requestId ?? "-"}</span>
                                </div>
                                <div>
                                  <strong>Location</strong>
                                  <span>{log.location ?? "-"}</span>
                                </div>
                                <div>
                                  <strong>User Agent</strong>
                                  <span>{log.userAgent ?? "-"}</span>
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
              <button
                className="audit-page-nav"
                disabled={currentAuditPage === 1}
                onClick={() => setAuditPage((p) => Math.max(1, p - 1))}
              >
                Previous
              </button>
              <div className="audit-pager">
                {Array.from(
                  { length: Math.min(totalAuditPages, 5) },
                  (_, i) => i + 1,
                ).map((n) => (
                  <button
                    key={n}
                    className={n === currentAuditPage ? "active" : ""}
                    onClick={() => setAuditPage(n)}
                  >
                    {n}
                  </button>
                ))}
              </div>
              <button
                className="audit-page-nav next"
                disabled={
                  currentAuditPage === totalAuditPages || totalAuditPages === 0
                }
                onClick={() =>
                  setAuditPage((p) => Math.min(totalAuditPages, p + 1))
                }
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default AdminApp;
