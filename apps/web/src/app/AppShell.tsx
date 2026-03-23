import {
  Suspense,
  lazy,
  startTransition,
  useEffect,
  useCallback,
  useDeferredValue,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
} from "react";
import { createPortal } from "react-dom";
import jsQR from "jsqr";

import {
  useAuth,
  type AuthCompletionResult,
  type LoginResult,
  type LoginMonitoring,
  type SessionReplacementAlert,
} from "../context/AuthContext";
import { FaceIdCapture, type FaceIdProof } from "../components/FaceIdCapture";
import {
  SliderCaptcha,
  type SliderCaptchaValue,
} from "../components/SliderCaptcha";
import { useToast } from "../context/ToastContext";
import { useTheme } from "../context/ThemeContext";
import { useActivityNotifications } from "./hooks/useActivityNotifications";
import "../index.css";

const LazyInvoiceListView = lazy(() => import("./views/InvoiceListView"));
const LazyCreateInvoicesView = lazy(() => import("./views/CreateInvoicesView"));
const LazyKnowledgeBaseView = lazy(() => import("./views/KnowledgeBaseView"));
const LazyNotificationsView = lazy(() => import("./views/NotificationsView"));
const LazyKycView = lazy(() => import("./views/KycView"));

const API_BASE =
  (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, "") ||
  "http://localhost:4000";
const SESSION_REPLACEMENT_ALERT_STORAGE_KEY =
  "fpipay_session_replacement_alert";
const NOTIFICATION_READ_STORAGE_PREFIX = "fpipay_notification_reads";
const COPILOT_REQUEST_TIMEOUT_MS = 90000;
const PROFESSIONAL_PASSWORD_MIN_LENGTH = 12;
const TRANSFER_FACE_ID_THRESHOLD = 10000;

type PasswordStrengthCheck = {
  id: "length" | "uppercase" | "lowercase" | "number" | "special" | "no_spaces";
  label: string;
  shortLabel: string;
  met: boolean;
};

const getPasswordStrength = (password: string) => {
  const value = password || "";
  const checks: PasswordStrengthCheck[] = [
    {
      id: "length",
      label: `At least ${PROFESSIONAL_PASSWORD_MIN_LENGTH} characters`,
      shortLabel: `${PROFESSIONAL_PASSWORD_MIN_LENGTH}+ chars`,
      met: value.length >= PROFESSIONAL_PASSWORD_MIN_LENGTH,
    },
    {
      id: "uppercase",
      label: "At least 1 uppercase letter",
      shortLabel: "Uppercase",
      met: /[A-Z]/.test(value),
    },
    {
      id: "lowercase",
      label: "At least 1 lowercase letter",
      shortLabel: "Lowercase",
      met: /[a-z]/.test(value),
    },
    {
      id: "number",
      label: "At least 1 number",
      shortLabel: "Number",
      met: /\d/.test(value),
    },
    {
      id: "special",
      label: "At least 1 special character",
      shortLabel: "Special",
      met: /[^A-Za-z0-9\s]/.test(value),
    },
    {
      id: "no_spaces",
      label: "No spaces",
      shortLabel: "No spaces",
      met: !/\s/.test(value),
    },
  ];
  const passedChecks = checks.filter((check) => check.met).length;
  const meetsPolicy = checks.every((check) => check.met);

  if (!value) {
    return {
      checks,
      passedChecks,
      totalChecks: checks.length,
      meetsPolicy: false,
      level: "empty" as const,
      label: "No password yet",
      message: "Use a strong password to protect your account.",
    };
  }
  if (meetsPolicy) {
    return {
      checks,
      passedChecks,
      totalChecks: checks.length,
      meetsPolicy: true,
      level: "strong" as const,
      label: "Strong",
      message: "Professional password standard met.",
    };
  }
  if (passedChecks >= 5) {
    return {
      checks,
      passedChecks,
      totalChecks: checks.length,
      meetsPolicy: false,
      level: "good" as const,
      label: "Good",
      message: "Almost there. Add the missing requirement to meet the policy.",
    };
  }
  if (passedChecks >= 3) {
    return {
      checks,
      passedChecks,
      totalChecks: checks.length,
      meetsPolicy: false,
      level: "fair" as const,
      label: "Fair",
      message: "Improve this password before using it for a real account.",
    };
  }

  return {
    checks,
    passedChecks,
    totalChecks: checks.length,
    meetsPolicy: false,
    level: "weak" as const,
    label: "Weak",
    message: "This password is too easy to guess.",
  };
};

const sanitizeDownloadFileName = (value?: string) => {
  const cleaned = (value || "User")
    .replace(/[<>:"/\\|?*\u0000-\u001f]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return cleaned || "User";
};

const parseUsdLikeNumber = (value?: string) => {
  const normalized = (value || "").replace(/[^0-9.-]/g, "");
  const amount = Number(normalized);
  return Number.isFinite(amount) ? amount : 0;
};

const loadImageFromBlob = (blob: Blob) =>
  new Promise<HTMLImageElement>((resolve, reject) => {
    const objectUrl = URL.createObjectURL(blob);
    const image = new Image();
    image.onload = () => {
      URL.revokeObjectURL(objectUrl);
      resolve(image);
    };
    image.onerror = () => {
      URL.revokeObjectURL(objectUrl);
      reject(new Error("image-load-failed"));
    };
    image.src = objectUrl;
  });

const drawCenteredWrappedText = (
  ctx: CanvasRenderingContext2D,
  text: string,
  centerX: number,
  startY: number,
  maxWidth: number,
  lineHeight: number,
) => {
  const words = text.trim().split(/\s+/).filter(Boolean);
  const lines: string[] = [];
  let currentLine = "";

  for (const word of words) {
    const nextLine = currentLine ? `${currentLine} ${word}` : word;
    if (ctx.measureText(nextLine).width <= maxWidth || !currentLine) {
      currentLine = nextLine;
    } else {
      lines.push(currentLine);
      currentLine = word;
    }
  }

  if (currentLine) {
    lines.push(currentLine);
  }

  const renderedLines = lines.length ? lines : ["User"];
  renderedLines.forEach((line, index) => {
    ctx.fillText(line, centerX, startY + index * lineHeight);
  });

  return startY + (renderedLines.length - 1) * lineHeight;
};

const NAV_ITEMS: {
  id: string;
  label: string;
  children?: { id: string; label: string }[];
}[] = [
  { id: "Dashboard", label: "Dashboard" },
  { id: "Card Center", label: "Card Center" },
  {
    id: "Support",
    label: "Support",
    children: [
      { id: "Knowledge base", label: "Knowledge base" },
      { id: "KYC Verification", label: "KYC Verification" },
    ],
  },
];

const dashboardQuickActions = [
  {
    id: "deposit",
    title: "AI Deposit Agent",
    detail: "Plan and fund with AI guidance",
    icon: "DEP",
  },
  {
    id: "copilot",
    title: "AI Copilot",
    detail: "Ask about budget, savings, and market context",
    icon: "AI",
  },
  {
    id: "transfer",
    title: "Internal Transfer",
    detail: "Move funds between accounts",
    icon: "GO",
  },
];

const dashboardSecurityAlerts: SecurityAlertItem[] = [];

const accountsRecentTransactions = [
  {
    id: "596380",
    name: "Charlotte",
    date: "February 19, 2021, 10:50 AM",
    amount: "$590",
    card: "Mastercard",
    status: "Pending",
    statusType: "pending",
    img: 11,
  },
  {
    id: "596381",
    name: "Alexander",
    date: "February 18, 2021, 03:25 PM",
    amount: "$1250",
    card: "Mastercard",
    status: "Pending",
    statusType: "pending",
    img: 12,
  },
  {
    id: "596382",
    name: "Christopher",
    date: "February 18, 2021, 10:12 AM",
    amount: "$5600",
    card: "Paypal",
    status: "Completed",
    statusType: "completed",
    img: 13,
  },
];

type RecentTransaction = {
  amount: number;
  type: string;
  description?: string;
  createdAt: string;
  direction: "credit" | "debit";
};

type TransactionReceipt = {
  txId: string;
  executedAt: string;
  fromAccount: string;
  toAccount: string;
  amountUsd: string;
  feeUsd: string;
  note: string;
  status: string;
};

type TransactionHistoryItem = {
  id: string;
  entity: string;
  date: string;
  status: string;
  amount: string;
  amountTone: "positive" | "negative";
  receipt: TransactionReceipt;
};

type SecurityAlertTone = "safe" | "info" | "warn";

type SecurityAlertItem = {
  id: string;
  title: string;
  location: string;
  detail: string;
  time: string;
  tone: SecurityAlertTone;
};

type SecurityRecentLoginItem = {
  id: string;
  location: string;
  ipAddress?: string;
  userAgent: string;
  deviceTitle?: string;
  deviceDetail?: string;
  success: boolean;
  anomaly: number;
  riskUnavailable?: boolean;
  createdAt: string;
  trustedIp: boolean;
};

type SecurityTrustedDeviceItem = {
  id: string;
  ipAddress: string;
  location: string;
  userAgent: string;
  firstSeenAt: string;
  lastSeenAt: string;
  lastVerifiedAt: string;
  current: boolean;
};

type SecurityOverviewAlert = {
  id?: string;
  title?: string;
  location?: string;
  detail?: string;
  tone?: SecurityAlertTone;
  occurredAt?: string;
};

type SecurityOverviewResponse = {
  alerts: SecurityOverviewAlert[];
  recentLogins: SecurityRecentLoginItem[];
  trustedDevices: SecurityTrustedDeviceItem[];
};

type TransferSafetyAdvisory = {
  requestKey?: string | null;
  severity: "caution" | "warning" | "blocked";
  title: string;
  message: string;
  confirmationLabel: string;
  reasons: string[];
  requiresAcknowledgement: boolean;
  transferRatio: number;
  remainingBalance: number;
  remainingBalanceRatio: number;
  amount: number;
  currency: string;
  blockedUntil?: string | null;
};

type ActivityNotificationType = "transactions" | "security";

type ActivityNotification = {
  id: string;
  type: ActivityNotificationType;
  title: string;
  message: string;
  meta?: string;
  createdAt: string;
  timeLabel: string;
  amountText?: string;
  amountTone?: "positive" | "negative";
};

type CopilotMessage = {
  role: "user" | "assistant";
  content: string;
};

type CopilotContentBlock =
  | { kind: "paragraph"; text: string }
  | { kind: "list"; items: string[] }
  | { kind: "table"; headers: string[]; rows: string[][] };

type CopilotInsight = {
  topic: string;
  suggestedActions: string[];
  suggestedDepositAmount?: number | null;
  riskLevel: string;
  confidence: number;
  followUpQuestion?: string | null;
};

const IPV4_ADDRESS_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

const normalizeNotificationCopy = (value?: string) =>
  (value || "").replace(/\s+/g, " ").trim();

const truncateNotificationCopy = (value: string, maxLength: number) =>
  value.length <= maxLength
    ? value
    : `${value.slice(0, maxLength - 3).trimEnd()}...`;

const summarizeUserAgent = (value?: string) => {
  const userAgent = normalizeNotificationCopy(value);
  if (!userAgent) return "";

  const browser = userAgent.match(/Edg\/(\d+)/)?.[1]
    ? `Edge ${userAgent.match(/Edg\/(\d+)/)?.[1]}`
    : userAgent.match(/Chrome\/(\d+)/)?.[1]
      ? `Chrome ${userAgent.match(/Chrome\/(\d+)/)?.[1]}`
      : userAgent.match(/Firefox\/(\d+)/)?.[1]
        ? `Firefox ${userAgent.match(/Firefox\/(\d+)/)?.[1]}`
        : userAgent.match(/Version\/(\d+).+Safari\//)?.[1]
          ? `Safari ${userAgent.match(/Version\/(\d+).+Safari\//)?.[1]}`
          : "";

  const os = /Windows NT 10\.0/i.test(userAgent)
    ? "Windows 10"
    : /Windows/i.test(userAgent)
      ? "Windows"
      : /Android/i.test(userAgent)
        ? "Android"
        : /\biPhone\b|\biPad\b|\biOS\b/i.test(userAgent)
          ? "iOS"
          : /Mac OS X/i.test(userAgent)
            ? "macOS"
            : /Linux/i.test(userAgent)
              ? "Linux"
              : "";

  if (browser && os) return `${browser} on ${os}`;
  if (browser || os) return browser || os;
  return truncateNotificationCopy(userAgent, 48);
};

const formatSecurityNotification = (alert: SecurityOverviewAlert) => {
  const detail = normalizeNotificationCopy(alert.detail);
  const location = normalizeNotificationCopy(alert.location);
  const deviceMatch = detail.match(/^Device:\s*(.+?)\.\s*(.+)$/i);
  const device = summarizeUserAgent(deviceMatch?.[1]);
  const detailBody = normalizeNotificationCopy(deviceMatch?.[2] || detail);
  const ipAddress =
    detailBody.match(IPV4_ADDRESS_PATTERN)?.[0] ||
    detail.match(IPV4_ADDRESS_PATTERN)?.[0] ||
    "";

  let message = detailBody || "Security activity was recorded on this account.";
  if (/saved for future sign-ins|now trusted/i.test(detailBody)) {
    message = "Trusted for future sign-ins.";
  } else if (
    /matched the saved IP|matched the saved device/i.test(detailBody)
  ) {
    message = "Matched a trusted device and IP.";
  }

  message = truncateNotificationCopy(normalizeNotificationCopy(message), 84);

  const meta = [device, ipAddress, location].filter(
    (part, index, items) =>
      part &&
      items.findIndex(
        (candidate) => candidate.toLowerCase() === part.toLowerCase(),
      ) === index,
  );

  return {
    title: alert.title || "Security activity detected",
    message,
    meta: meta.length ? meta.join(" / ") : undefined,
  };
};

type AiMonitoringSummary = {
  score: number;
  riskLevel: string;
  reasons: string[];
  monitoringOnly: boolean;
  action?: string;
  modelSource?: string | null;
  modelVersion?: string | null;
  requestKey?: string | null;
};

function Ring({ value }: { value: number }) {
  const r = 36;
  const circ = 2 * Math.PI * r;
  const offset = circ * (1 - value / 100);
  return (
    <svg viewBox="0 0 84 84" className="ring">
      <circle className="ring-bg" cx="42" cy="42" r={r} />
      <circle
        className="ring-fg"
        cx="42"
        cy="42"
        r={r}
        strokeDasharray={`${circ} ${circ}`}
        strokeDashoffset={offset}
      />
      <text x="50%" y="52%" textAnchor="middle" className="ring-text">
        {value}%
      </text>
    </svg>
  );
}

const parseCopilotTableRow = (line: string) =>
  line
    .trim()
    .replace(/^\|/, "")
    .replace(/\|$/, "")
    .split("|")
    .map((cell) => cell.trim().replace(/\\\|/g, "|"));

const isCopilotTableSeparator = (line: string) => {
  const cells = parseCopilotTableRow(line);
  return cells.length > 0 && cells.every((cell) => /^:?-{3,}:?$/.test(cell));
};

const isCopilotListLine = (line: string) =>
  /^\s*(?:[-*]\s+|\d+\.\s+)/.test(line);

const parseCopilotMessageBlocks = (content: string): CopilotContentBlock[] => {
  const lines = content.replace(/\r/g, "").split("\n");
  const blocks: CopilotContentBlock[] = [];
  let index = 0;

  while (index < lines.length) {
    const rawLine = lines[index];
    const line = rawLine.trim();
    if (!line) {
      index += 1;
      continue;
    }

    if (
      line.startsWith("|") &&
      index + 1 < lines.length &&
      isCopilotTableSeparator(lines[index + 1])
    ) {
      const headers = parseCopilotTableRow(lines[index]);
      index += 2;
      const rows: string[][] = [];
      while (index < lines.length && lines[index].trim().startsWith("|")) {
        rows.push(parseCopilotTableRow(lines[index]));
        index += 1;
      }
      blocks.push({ kind: "table", headers, rows });
      continue;
    }

    if (isCopilotListLine(rawLine)) {
      const items: string[] = [];
      while (index < lines.length && isCopilotListLine(lines[index])) {
        items.push(lines[index].replace(/^\s*(?:[-*]\s+|\d+\.\s+)/, "").trim());
        index += 1;
      }
      blocks.push({ kind: "list", items });
      continue;
    }

    const paragraphLines: string[] = [];
    while (index < lines.length) {
      const nextLine = lines[index].trim();
      if (!nextLine) break;
      if (
        nextLine.startsWith("|") &&
        index + 1 < lines.length &&
        isCopilotTableSeparator(lines[index + 1])
      ) {
        break;
      }
      if (isCopilotListLine(lines[index])) break;
      paragraphLines.push(nextLine);
      index += 1;
    }
    blocks.push({ kind: "paragraph", text: paragraphLines.join(" ") });
  }

  return blocks;
};

const renderCopilotMessageContent = (content: string) => {
  const blocks = parseCopilotMessageBlocks(content);

  return (
    <div className="ai-copilot-message-content">
      {blocks.map((block, index) => {
        if (block.kind === "table") {
          return (
            <div key={`table-${index}`} className="ai-copilot-table-wrap">
              <table className="ai-copilot-table">
                <thead>
                  <tr>
                    {block.headers.map((header, headerIndex) => (
                      <th key={`h-${headerIndex}`}>{header}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {block.rows.map((row, rowIndex) => (
                    <tr key={`r-${rowIndex}`}>
                      {block.headers.map((_, cellIndex) => (
                        <td key={`c-${rowIndex}-${cellIndex}`}>
                          {row[cellIndex] || ""}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          );
        }

        if (block.kind === "list") {
          return (
            <ul key={`list-${index}`} className="ai-copilot-message-list">
              {block.items.map((item, itemIndex) => (
                <li key={`item-${itemIndex}`}>{item}</li>
              ))}
            </ul>
          );
        }

        return (
          <p key={`p-${index}`} className="ai-copilot-message-paragraph">
            {block.text}
          </p>
        );
      })}
    </div>
  );
};

function DonutChart({
  percent,
  segments,
}: {
  percent: number;
  segments: { label: string; color: string }[];
}) {
  const r = 42;
  const circ = 2 * Math.PI * r;
  const filled = (percent / 100) * circ;
  return (
    <div className="donut-wrap">
      <svg viewBox="0 0 100 100" className="donut-chart">
        <circle className="donut-bg" cx="50" cy="50" r={r} />
        <circle
          className="donut-fg"
          cx="50"
          cy="50"
          r={r}
          strokeDasharray={`${filled} ${circ - filled}`}
        />
        <text x="50" y="55" textAnchor="middle" className="donut-text">
          {percent}%
        </text>
      </svg>
      <div className="donut-legend">
        {segments.map((s) => (
          <div key={s.label} className="donut-legend-item">
            <span className="dot" style={{ background: s.color }} /> {s.label}
          </div>
        ))}
      </div>
    </div>
  );
}

function BarChart({
  labels,
  data,
}: {
  labels: string[];
  data: { debit: number; credit: number }[];
}) {
  const max = Math.max(...data.flatMap((d) => [d.debit, d.credit]));
  return (
    <div className="bar-chart">
      <div className="bar-chart-bars">
        {data.map((d, i) => (
          <div key={i} className="bar-chart-group">
            <div className="bar-wrap">
              <div
                className="bar bar-debit"
                style={{ height: `${(d.debit / max) * 100}%` }}
              />
              <div
                className="bar bar-credit"
                style={{ height: `${(d.credit / max) * 100}%` }}
              />
            </div>
            <span className="bar-label">{labels[i]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function DashboardView() {
  const { user, token, sessionSecurity } = useAuth();
  const { toast } = useToast();
  const transferQrVideoRef = useRef<HTMLVideoElement>(null);
  const transferQrStreamRef = useRef<MediaStream | null>(null);
  const transferQrScanTimerRef = useRef<number | null>(null);
  const copilotThreadRef = useRef<HTMLDivElement>(null);
  const walletRefreshInFlightRef = useRef(false);
  const [wallet, setWallet] = useState<{
    id: string;
    balance: number;
    currency: string;
    accountNumber?: string;
    qrPayload?: string;
    qrImageUrl?: string;
  } | null>(null);
  const [showWalletId, setShowWalletId] = useState(false);
  const [detailsModalOpen, setDetailsModalOpen] = useState(false);
  const [detailsStep, setDetailsStep] = useState<"otp" | "details">("otp");
  const [otpCode, setOtpCode] = useState("");
  const [otpInput, setOtpInput] = useState("");
  const [otpError, setOtpError] = useState("");
  const [otpAttempts, setOtpAttempts] = useState(0);
  const [transferOpen, setTransferOpen] = useState(false);
  const [copilotOpen, setCopilotOpen] = useState(false);
  const [copilotBusy, setCopilotBusy] = useState(false);
  const [copilotInput, setCopilotInput] = useState("");
  const [copilotMessages, setCopilotMessages] = useState<CopilotMessage[]>([
    {
      role: "assistant",
      content:
        "I can help with budget, spending, savings targets, and live FX, gold, crypto, and stock quotes. Ask me what you want to improve.",
    },
  ]);
  const [copilotInsight, setCopilotInsight] = useState<CopilotInsight>({
    topic: "",
    suggestedActions: [],
    suggestedDepositAmount: null,
    riskLevel: "low",
    confidence: 0,
    followUpQuestion: null,
  });
  const [transferStep, setTransferStep] = useState<1 | 2 | 3 | 4>(1);
  const [transferStepDirection, setTransferStepDirection] = useState<
    "forward" | "backward"
  >("forward");
  const [transferMethod, setTransferMethod] = useState<"account" | "qr">(
    "account",
  );
  const [transferAccount, setTransferAccount] = useState("");
  const [transferRecipientUserId, setTransferRecipientUserId] = useState("");
  const [transferReceiverName, setTransferReceiverName] = useState("");
  const [transferAmount, setTransferAmount] = useState("");
  const [transferContent, setTransferContent] = useState("");
  const [transferQrFile, setTransferQrFile] = useState("");
  const [transferQrCameraOn, setTransferQrCameraOn] = useState(false);
  const [transferQrCameraError, setTransferQrCameraError] = useState("");
  const [transferQrCameraPanelOpen, setTransferQrCameraPanelOpen] =
    useState(false);
  const [transferQrFacingMode, setTransferQrFacingMode] = useState<
    "environment" | "user"
  >("environment");
  const [transferQrDevices, setTransferQrDevices] = useState<MediaDeviceInfo[]>(
    [],
  );
  const [transferQrDeviceId, setTransferQrDeviceId] = useState("");
  const [transferShowMyQr, setTransferShowMyQr] = useState(false);
  const [transferQrDownloadBusy, setTransferQrDownloadBusy] = useState(false);
  const [transferOtpInput, setTransferOtpInput] = useState("");
  const [transferOtpError, setTransferOtpError] = useState("");
  const [transferOtpChallengeId, setTransferOtpChallengeId] = useState("");
  const [transferOtpDestination, setTransferOtpDestination] = useState("");
  const [transferOtpExpiresAt, setTransferOtpExpiresAt] = useState("");
  const [transferFaceProof, setTransferFaceProof] =
    useState<FaceIdProof | null>(null);
  const [transferFaceResetKey, setTransferFaceResetKey] = useState(0);
  const [transferFaceVerifyOpen, setTransferFaceVerifyOpen] = useState(false);
  const [transferFaceVerifyBusy, setTransferFaceVerifyBusy] = useState(false);
  const [transferFaceIdEnabled, setTransferFaceIdEnabled] = useState(false);
  const [transferServerFaceIdRequired, setTransferServerFaceIdRequired] =
    useState(false);
  const [transferServerFaceIdReason, setTransferServerFaceIdReason] =
    useState("");
  const [transferRollingOutflowAmount, setTransferRollingOutflowAmount] =
    useState<number | null>(null);
  const [transferOtpResendAt, setTransferOtpResendAt] = useState(0);
  const [transferOtpClock, setTransferOtpClock] = useState(Date.now());
  const [transferMonitoring, setTransferMonitoring] =
    useState<AiMonitoringSummary | null>(null);
  const [transferOtpBusy, setTransferOtpBusy] = useState(false);
  const [transferOtpVerifyBusy, setTransferOtpVerifyBusy] = useState(false);
  const [transferAdvisory, setTransferAdvisory] =
    useState<TransferSafetyAdvisory | null>(null);
  const [transferAdvisoryAcknowledged, setTransferAdvisoryAcknowledged] =
    useState(false);
  const [recentTransactions, setRecentTransactions] = useState<
    RecentTransaction[]
  >([]);
  const [transactionHistory, setTransactionHistory] = useState<
    TransactionHistoryItem[]
  >([]);
  const [securityAlerts, setSecurityAlerts] = useState<SecurityAlertItem[]>(
    dashboardSecurityAlerts,
  );
  const [securityRecentLogins, setSecurityRecentLogins] = useState<
    SecurityRecentLoginItem[]
  >([]);
  const [securityTrustedDevices, setSecurityTrustedDevices] = useState<
    SecurityTrustedDeviceItem[]
  >([]);
  const [securityAlertsBusy, setSecurityAlertsBusy] = useState(false);
  const [securityAlertsError, setSecurityAlertsError] = useState("");
  const [securityAlertsModalOpen, setSecurityAlertsModalOpen] = useState(false);
  const [historyModalOpen, setHistoryModalOpen] = useState(false);
  const [transferReceipt, setTransferReceipt] =
    useState<TransactionReceipt | null>(null);
  const [selectedTransactionReceipt, setSelectedTransactionReceipt] =
    useState<TransactionReceipt | null>(null);

  const cardProfile = {
    holder: "Alex Thompson",
    number: "1234 5678 9012 5678",
    type: "Visa Signature",
    expiry: "09/29",
    cvv: "***",
    status: "Active",
    issuedAt: "San Francisco Main Branch",
    linkedAccount: "Checking **** 8841",
    dailyLimit: "$10,000.00",
    contactless: "Enabled",
    onlinePayment: "Enabled",
    lastActivity: "Mar 05, 2026 / 09:42 AM",
  };

  const walletRaw = wallet?.accountNumber || wallet?.id || "";
  const walletDigits = walletRaw.replace(/\D/g, "").slice(0, 19);
  const maskedDigits =
    showWalletId || walletDigits.length <= 4
      ? walletDigits
      : `${"*".repeat(walletDigits.length - 4)}${walletDigits.slice(-4)}`;
  const walletGroups = maskedDigits.match(/.{1,4}/g) ?? [];
  const defaultTransferContent = `${user?.name ?? "User"} transfer`;
  const transferAmountNumber = Number(transferAmount.replace(/,/g, ""));
  const isTransferFaceIdRequired =
    transferAmount.trim().length > 0 &&
    Number.isFinite(transferAmountNumber) &&
    transferAmountNumber > TRANSFER_FACE_ID_THRESHOLD;
  const isInsufficientBalance =
    wallet !== null &&
    transferAmount.trim().length > 0 &&
    Number.isFinite(transferAmountNumber) &&
    transferAmountNumber > Number(wallet.balance);
  const restrictedTransferLimit =
    sessionSecurity.restrictLargeTransfers &&
    typeof sessionSecurity.maxTransferAmount === "number"
      ? sessionSecurity.maxTransferAmount
      : null;
  const exceedsRestrictedTransferLimit =
    restrictedTransferLimit !== null &&
    transferAmount.trim().length > 0 &&
    Number.isFinite(transferAmountNumber) &&
    transferAmountNumber > restrictedTransferLimit;
  const canContinueTransferAmount =
    wallet !== null &&
    transferAmount.trim().length > 0 &&
    Number.isFinite(transferAmountNumber) &&
    transferAmountNumber > 0 &&
    !isInsufficientBalance &&
    !exceedsRestrictedTransferLimit;
  const isTransferHardBlocked = transferAdvisory?.severity === "blocked";
  const isTransferPreOtpWarning =
    transferAdvisory?.severity === "blocked" ||
    transferAdvisory?.requiresAcknowledgement === true;
  const transferContinueLabel = transferOtpBusy
    ? isTransferPreOtpWarning && !transferAdvisoryAcknowledged
      ? "Reviewing transfer..."
      : "Sending OTP..."
    : isTransferHardBlocked
      ? "Blocked for safety review"
      : isTransferPreOtpWarning && !transferAdvisoryAcknowledged
        ? transferAdvisory.confirmationLabel
        : "Continue to OTP";
  const ownQrPayload =
    wallet?.qrPayload ||
    (wallet?.accountNumber
      ? `EWALLET|ACC:${wallet.accountNumber}|BANK:SECURE-WALLET`
      : "");
  const ownQrImageUrl =
    wallet?.qrImageUrl ||
    (ownQrPayload
      ? `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(ownQrPayload)}`
      : "");
  const ownQrDisplayName = user?.name?.trim() || "User";
  const ownQrDownloadName = `${sanitizeDownloadFileName(ownQrDisplayName)}.png`;
  const transferOtpCooldownSeconds = Math.max(
    0,
    Math.ceil((transferOtpResendAt - transferOtpClock) / 1000),
  );
  const monthlyIncomeValue = 0;
  const monthlyExpensesValue = 0;
  const copilotSuggestedPrompts = [
    "What is the USD/VND exchange rate today?",
    "What is the gold price today?",
    "How much is Bitcoin today?",
    "What is AAPL stock price today?",
  ];
  const copilotHasInsight = Boolean(
    copilotInsight.topic ||
    copilotInsight.suggestedActions.length ||
    copilotInsight.suggestedDepositAmount ||
    copilotInsight.followUpQuestion,
  );
  const copilotRiskTone =
    copilotInsight.riskLevel === "high" || copilotInsight.riskLevel === "medium"
      ? copilotInsight.riskLevel
      : "low";

  const buildTransactionReceipt = useCallback(
    (tx: {
      id: string;
      amount: number;
      type: string;
      status?: string;
      description?: string;
      createdAt: string;
      metadata?: {
        entry?: "DEBIT" | "CREDIT";
        fromAccount?: string;
        toAccount?: string;
        source?: string;
      };
    }) => {
      const currentAccount = wallet?.accountNumber || "Primary Checking";
      const isCredit = tx.type === "DEPOSIT" || tx.metadata?.entry === "CREDIT";
      const fallbackFromAccount = isCredit
        ? tx.metadata?.source === "ADMIN_TOPUP"
          ? "Admin funding"
          : currentAccount
        : currentAccount;
      const fallbackToAccount = isCredit ? currentAccount : "Unknown account";

      return {
        txId: tx.id,
        executedAt: new Date(tx.createdAt).toLocaleString("en-US", {
          month: "short",
          day: "2-digit",
          year: "numeric",
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: true,
        }),
        fromAccount: tx.metadata?.fromAccount || fallbackFromAccount,
        toAccount: tx.metadata?.toAccount || fallbackToAccount,
        amountUsd: Number(tx.amount || 0).toLocaleString("en-US", {
          minimumFractionDigits: 2,
          maximumFractionDigits: 2,
        }),
        feeUsd: "0.00",
        note: tx.description || tx.type,
        status: tx.status || "Completed",
      };
    },
    [wallet?.accountNumber],
  );

  const formatSecurityAlertTime = useCallback((value: string) => {
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return "Just now";

    const diffMinutes = Math.max(
      0,
      Math.round((Date.now() - parsed.getTime()) / 60000),
    );
    if (diffMinutes < 1) return "Just now";
    if (diffMinutes < 60) {
      return `${diffMinutes} minute${diffMinutes === 1 ? "" : "s"} ago`;
    }
    if (diffMinutes < 24 * 60) {
      const diffHours = Math.round(diffMinutes / 60);
      return `${diffHours} hour${diffHours === 1 ? "" : "s"} ago`;
    }

    return parsed.toLocaleString("en-US", {
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  }, []);

  const formatSecurityTimestamp = useCallback((value: string) => {
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return "Unknown";
    return parsed.toLocaleString("en-US", {
      month: "short",
      day: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  }, []);

  const parseUserAgentSummary = useCallback((value?: string) => {
    if (!value?.trim()) {
      return {
        title: "Unknown device",
        detail: "Browser and device details unavailable",
      };
    }

    const userAgent = value.trim();
    const browserMatchers: Array<[RegExp, string]> = [
      [/Edg\/(\d+)/, "Edge"],
      [/Chrome\/(\d+)/, "Chrome"],
      [/Firefox\/(\d+)/, "Firefox"],
      [/Version\/(\d+).+Safari\//, "Safari"],
    ];

    let browserLabel = "";
    for (const [pattern, label] of browserMatchers) {
      const match = userAgent.match(pattern);
      if (match) {
        browserLabel = `${label}${match[1] ? ` ${match[1]}` : ""}`;
        break;
      }
    }

    let osLabel = "";
    let deviceTitle = "Unknown device";
    if (
      /Windows NT 10\.0/.test(userAgent) ||
      /Windows NT 11\.0/.test(userAgent)
    ) {
      osLabel = "Windows";
      deviceTitle = "Windows PC";
    } else if (/Windows NT 6\.3/.test(userAgent)) {
      osLabel = "Windows";
      deviceTitle = "Windows PC";
    } else if (/Mac OS X [\d_]+/.test(userAgent)) {
      osLabel = "macOS";
      deviceTitle = "Mac device";
    } else if (/iPhone/.test(userAgent)) {
      osLabel = "iOS";
      deviceTitle = "iPhone";
    } else if (/iPad/.test(userAgent)) {
      osLabel = "iPadOS";
      deviceTitle = "iPad";
    } else if (/iPod/.test(userAgent)) {
      osLabel = "iOS";
      deviceTitle = "iPod";
    } else if (/Android/.test(userAgent) && /Mobile/i.test(userAgent)) {
      osLabel = "Android";
      deviceTitle = "Android phone";
    } else if (/Android/.test(userAgent)) {
      osLabel = "Android";
      deviceTitle = "Android tablet";
    } else if (/Linux/.test(userAgent)) {
      osLabel = "Linux";
      deviceTitle = "Linux device";
    }

    const detailParts = [browserLabel, osLabel].filter(Boolean);
    return {
      title: deviceTitle,
      detail:
        detailParts.join(" / ") ||
        (userAgent.length > 64 ? `${userAgent.slice(0, 64)}...` : userAgent),
    };
  }, []);

  const renderSecurityRecentLoginList = useCallback(
    (
      items: SecurityRecentLoginItem[],
      options?: {
        limit?: number;
        keyPrefix?: string;
        className?: string;
      },
    ) => {
      const visibleItems =
        typeof options?.limit === "number"
          ? items.slice(0, options.limit)
          : items;

      if (!visibleItems.length) {
        return (
          <div className="dashboard-inline-note">
            No recent sign-in activity is available for this account yet.
          </div>
        );
      }

      return (
        <div
          className={
            options?.className
              ? `security-record-list ${options.className}`
              : "security-record-list"
          }
        >
          {visibleItems.map((login) => (
            <article
              className="security-record-card"
              key={
                options?.keyPrefix
                  ? `${options.keyPrefix}-${login.id}`
                  : login.id
              }
            >
              {(() => {
                const deviceSummary = parseUserAgentSummary(login.userAgent);
                return (
                  <>
                    <div className="security-record-head">
                      <div className="security-record-summary">
                        <strong title={login.userAgent}>
                          {login.deviceTitle || deviceSummary.title}
                        </strong>
                        <p>{login.location}</p>
                        <p
                          className="security-record-agent"
                          title={login.userAgent}
                        >
                          {login.deviceDetail || deviceSummary.detail}
                        </p>
                      </div>
                      <span
                        className={`security-record-pill ${login.success ? "success" : "warn"}`}
                      >
                        {login.success
                          ? login.trustedIp
                            ? "Trusted sign-in"
                            : "Verified sign-in"
                          : "Blocked"}
                      </span>
                    </div>
                    <dl className="security-record-meta">
                      <div>
                        <dt>IP</dt>
                        <dd>{login.ipAddress || "Unavailable"}</dd>
                      </div>
                      <div>
                        <dt>Time</dt>
                        <dd>{formatSecurityTimestamp(login.createdAt)}</dd>
                      </div>
                      <div>
                        <dt>Risk</dt>
                        <dd>
                          {login.riskUnavailable
                            ? "N/A"
                            : `${Math.round(login.anomaly * 100)}%`}
                        </dd>
                      </div>
                      <div>
                        <dt>Status</dt>
                        <dd>{login.success ? "Successful" : "Blocked"}</dd>
                      </div>
                    </dl>
                  </>
                );
              })()}
            </article>
          ))}
        </div>
      );
    },
    [formatSecurityTimestamp, parseUserAgentSummary],
  );

  const parseAiMonitoringSummary = useCallback(
    (value: unknown): AiMonitoringSummary | null => {
      if (!value || typeof value !== "object") return null;
      const data = value as Record<string, unknown>;
      const score =
        typeof data.score === "number"
          ? data.score
          : typeof data.anomaly_score === "number"
            ? data.anomaly_score
            : 0;
      return {
        score,
        riskLevel:
          typeof data.riskLevel === "string"
            ? data.riskLevel
            : typeof data.risk_level === "string"
              ? data.risk_level
              : "low",
        reasons: Array.isArray(data.reasons)
          ? data.reasons.filter(
              (item): item is string => typeof item === "string",
            )
          : [],
        monitoringOnly: Boolean(
          data.monitoringOnly ?? data.monitoring_only ?? true,
        ),
        action: typeof data.action === "string" ? data.action : undefined,
        modelSource:
          typeof data.modelSource === "string"
            ? data.modelSource
            : typeof data.model_source === "string"
              ? data.model_source
              : null,
        modelVersion:
          typeof data.modelVersion === "string"
            ? data.modelVersion
            : typeof data.model_version === "string"
              ? data.model_version
              : null,
        requestKey:
          typeof data.requestKey === "string"
            ? data.requestKey
            : typeof data.request_key === "string"
              ? data.request_key
              : null,
      };
    },
    [],
  );

  const parseTransferSafetyAdvisory = useCallback(
    (value: unknown): TransferSafetyAdvisory | null => {
      if (!value || typeof value !== "object") return null;
      const data = value as Record<string, unknown>;
      const severity =
        data.severity === "warning" ||
        data.severity === "caution" ||
        data.severity === "blocked"
          ? data.severity
          : null;
      if (
        (data.requestKey !== null && typeof data.requestKey !== "string") ||
        !severity ||
        typeof data.title !== "string" ||
        typeof data.message !== "string" ||
        typeof data.confirmationLabel !== "string" ||
        typeof data.requiresAcknowledgement !== "boolean" ||
        typeof data.transferRatio !== "number" ||
        typeof data.remainingBalance !== "number" ||
        typeof data.remainingBalanceRatio !== "number" ||
        typeof data.amount !== "number" ||
        typeof data.currency !== "string" ||
        (data.blockedUntil !== undefined &&
          data.blockedUntil !== null &&
          typeof data.blockedUntil !== "string")
      ) {
        return null;
      }

      return {
        requestKey:
          typeof data.requestKey === "string" ? data.requestKey : null,
        severity,
        title: data.title,
        message: data.message,
        confirmationLabel: data.confirmationLabel,
        reasons: Array.isArray(data.reasons)
          ? data.reasons.filter(
              (item): item is string => typeof item === "string",
            )
          : [],
        requiresAcknowledgement: data.requiresAcknowledgement,
        transferRatio: data.transferRatio,
        remainingBalance: data.remainingBalance,
        remainingBalanceRatio: data.remainingBalanceRatio,
        amount: data.amount,
        currency: data.currency,
        blockedUntil:
          typeof data.blockedUntil === "string" ? data.blockedUntil : null,
      };
    },
    [],
  );

  const formatTransferAdvisoryAmount = useCallback(
    (amount: number, currency: string) =>
      `${currency} ${amount.toLocaleString("en-US", {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2,
      })}`,
    [],
  );

  const renderTransferAdvisoryPanel = useCallback(
    (
      advisory: TransferSafetyAdvisory | null,
      options?: { acknowledged?: boolean; compact?: boolean },
    ) => {
      if (!advisory) return null;
      const acknowledged = Boolean(options?.acknowledged);
      const compact = Boolean(options?.compact);
      return (
        <div
          className={`transfer-advisory-card ${advisory.severity} ${
            compact ? "compact" : ""
          }`}
        >
          <div className="transfer-advisory-head">
            <strong>{advisory.title}</strong>
            <span className={`transfer-advisory-pill ${advisory.severity}`}>
              {advisory.severity === "blocked"
                ? "Blocked"
                : advisory.severity === "warning"
                  ? "Warning"
                  : "Advisory"}
            </span>
          </div>
          <p>{advisory.message}</p>
          {advisory.blockedUntil && !compact ? (
            <small className="transfer-advisory-note">
              Temporary hold until{" "}
              {new Date(advisory.blockedUntil).toLocaleString("en-US")}.
            </small>
          ) : null}
          <dl className="transfer-advisory-metrics">
            <div>
              <dt>Transfer</dt>
              <dd>
                {formatTransferAdvisoryAmount(
                  advisory.amount,
                  advisory.currency,
                )}
              </dd>
            </div>
            <div>
              <dt>Balance used</dt>
              <dd>{Math.round(advisory.transferRatio * 100)}%</dd>
            </div>
            <div>
              <dt>After transfer</dt>
              <dd>
                {formatTransferAdvisoryAmount(
                  advisory.remainingBalance,
                  advisory.currency,
                )}
              </dd>
            </div>
          </dl>
          {advisory.reasons.length > 0 && (
            <ul>
              {advisory.reasons.slice(0, compact ? 2 : 4).map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
          )}
          {acknowledged && advisory.severity !== "blocked" && !compact ? (
            <small className="transfer-advisory-note">
              You reviewed this warning and chose to continue.
            </small>
          ) : null}
        </div>
      );
    },
    [formatTransferAdvisoryAmount],
  );

  const renderTransferAmountAiPanel = useCallback(
    (
      advisory: TransferSafetyAdvisory | null,
      monitoring: AiMonitoringSummary | null,
      options?: { external?: boolean },
    ) => {
      if (!advisory && !monitoring) return null;
      const external = Boolean(options?.external);
      const amount =
        Number(transferAmount.replace(/,/g, "")) || advisory?.amount || 0;
      const isHighValueTransfer = amount >= TRANSFER_FACE_ID_THRESHOLD;

      const tone =
        advisory?.severity === "blocked"
          ? "blocked"
          : !isHighValueTransfer
            ? "safe"
            : advisory?.severity === "warning" ||
                monitoring?.riskLevel.toLowerCase() === "high"
              ? "warning"
              : "caution";
      const balanceUsed =
        advisory?.transferRatio ??
        (wallet?.balance ? amount / Math.max(Number(wallet.balance), 1) : 0);
      const afterTransfer =
        advisory?.remainingBalance ??
        Math.max((Number(wallet?.balance) || 0) - amount, 0);
      const recipientLabel =
        transferReceiverName.trim() ||
        (transferAccount
          ? `account ending ${transferAccount.slice(-4)}`
          : "this recipient");
      const previousOutgoingTransfers = transactionHistory
        .filter((item) => item.amountTone === "negative")
        .map((item) => {
          const fromReceipt = parseUsdLikeNumber(item.receipt?.amountUsd);
          return fromReceipt > 0
            ? fromReceipt
            : Math.abs(parseUsdLikeNumber(item.amount));
        })
        .filter((value) => value > 0);
      const largestPreviousTransfer = previousOutgoingTransfers.length
        ? Math.max(...previousOutgoingTransfers)
        : 0;
      const averagePreviousTransfer = previousOutgoingTransfers.length
        ? previousOutgoingTransfers.reduce((sum, value) => sum + value, 0) /
          previousOutgoingTransfers.length
        : 0;
      const amountVsAverage =
        averagePreviousTransfer > 0 ? amount / averagePreviousTransfer : null;
      const previousTransfersToRecipient = transactionHistory.filter((item) => {
        const receiptAccount = item.receipt?.toAccount || "";
        const receiptLabel = item.entity.toLowerCase();
        return (
          (transferAccount && receiptAccount === transferAccount) ||
          (transferReceiverName &&
            receiptLabel.includes(transferReceiverName.toLowerCase()))
        );
      }).length;
      const isNewRecipient = previousTransfersToRecipient === 0;
      const noteIsGeneric =
        transferContent.trim().length < 8 ||
        /^(transfer|payment|banking|send money|test|gift|invoice)$/i.test(
          transferContent.trim(),
        );
      const aiReasons: string[] = [];
      if (isNewRecipient) {
        aiReasons.push(
          `${recipientLabel} does not appear in your recent completed transfer history.`,
        );
      }
      if (amountVsAverage && amountVsAverage >= 3) {
        aiReasons.push(
          `This amount is about ${amountVsAverage.toFixed(1)}x higher than your usual outgoing transfer size.`,
        );
      } else if (
        largestPreviousTransfer > 0 &&
        amount > largestPreviousTransfer
      ) {
        aiReasons.push(
          `This amount is larger than your biggest recent completed transfer.`,
        );
      } else if (amount >= TRANSFER_FACE_ID_THRESHOLD) {
        aiReasons.push(
          `This is a high-value transfer that automatically triggers stronger review.`,
        );
      }
      if (noteIsGeneric && amount >= TRANSFER_FACE_ID_THRESHOLD) {
        aiReasons.push(
          `The transfer note is quite generic for a high-value payment, so recipient confirmation matters more.`,
        );
      }
      for (const rawReason of [
        ...(advisory?.reasons || []),
        ...(monitoring?.reasons || []),
      ]) {
        const cleaned = rawReason.replace(/\s+/g, " ").trim();
        if (
          cleaned &&
          !aiReasons.some(
            (reason) => reason.toLowerCase() === cleaned.toLowerCase(),
          )
        ) {
          aiReasons.push(cleaned);
        }
        if (aiReasons.length >= 3) break;
      }

      let title = advisory?.title || "AI transfer review";
      if (!isHighValueTransfer && tone !== "blocked") {
        title = "AI review: low-risk transfer check";
      }
      if (tone === "blocked") {
        title = `AI paused transfer to ${recipientLabel}`;
      } else if (
        isHighValueTransfer &&
        isNewRecipient &&
        (amountVsAverage
          ? amountVsAverage >= 2
          : amount >= TRANSFER_FACE_ID_THRESHOLD)
      ) {
        title = `New recipient with an unusually large amount`;
      } else if (
        isHighValueTransfer &&
        amountVsAverage &&
        amountVsAverage >= 3
      ) {
        title = `Amount is far above your recent transfer pattern`;
      } else if (isHighValueTransfer && isNewRecipient) {
        title = `First transfer to this recipient`;
      } else if (
        isHighValueTransfer &&
        noteIsGeneric &&
        amount >= TRANSFER_FACE_ID_THRESHOLD
      ) {
        title = `High-value transfer needs clearer recipient verification`;
      }

      const narrativeParts = [
        `You are sending ${formatTransferAdvisoryAmount(amount, "USD")} to ${recipientLabel}.`,
      ];
      if (!isHighValueTransfer) {
        narrativeParts.push(
          isNewRecipient
            ? `AI sees this as a small transfer to a newer recipient and is only showing a light advisory check.`
            : `This amount stays below the high-risk threshold, so AI is only giving a light review.`,
        );
      } else if (isNewRecipient) {
        narrativeParts.push(
          `This receiver looks new for this wallet, so AI recommends an out-of-band confirmation before you continue.`,
        );
      } else if (amountVsAverage && amountVsAverage >= 3) {
        narrativeParts.push(
          `The amount is much higher than your recent transfer pattern, which increases fraud review sensitivity.`,
        );
      } else if (
        largestPreviousTransfer > 0 &&
        amount > largestPreviousTransfer
      ) {
        narrativeParts.push(
          `It is larger than your previous completed transfers, so confirm the purpose and beneficiary carefully.`,
        );
      } else if (noteIsGeneric && amount >= TRANSFER_FACE_ID_THRESHOLD) {
        narrativeParts.push(
          `The payment note is generic, so AI is asking for a clearer recipient check before OTP is sent.`,
        );
      } else if (monitoring?.riskLevel.toLowerCase() === "high") {
        narrativeParts.push(
          `AI sees multiple scam-like signals around this payment and wants a stronger review first.`,
        );
      } else {
        narrativeParts.push(
          `AI wants you to verify the receiver and amount through a trusted channel before continuing.`,
        );
      }
      const message = narrativeParts.join(" ");
      const reasons = aiReasons.slice(0, 3);

      return (
        <aside
          className={`transfer-ai-amount-panel transfer-ai-amount-panel-${tone} ${
            external ? "external" : ""
          }`}
        >
          <div className="transfer-ai-amount-arrow" aria-hidden="true" />
          <div className="transfer-ai-amount-head">
            <span className="transfer-ai-amount-badge">AI Monitor</span>
            <span className={`transfer-advisory-pill ${tone}`}>
              {tone === "blocked"
                ? "Blocked"
                : tone === "warning"
                  ? "Warning"
                  : tone === "safe"
                    ? "Light check"
                    : "Review"}
            </span>
          </div>
          <strong>{title}</strong>
          <p>{message}</p>
          <dl className="transfer-ai-amount-metrics">
            <div>
              <dt>Amount</dt>
              <dd>{formatTransferAdvisoryAmount(amount, "USD")}</dd>
            </div>
            <div>
              <dt>Balance used</dt>
              <dd>{Math.max(0, Math.round(balanceUsed * 100))}%</dd>
            </div>
            <div>
              <dt>After</dt>
              <dd>{formatTransferAdvisoryAmount(afterTransfer, "USD")}</dd>
            </div>
          </dl>
          {reasons.length > 0 ? (
            <ul>
              {reasons.map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
          ) : null}
        </aside>
      );
    },
    [
      formatTransferAdvisoryAmount,
      transactionHistory,
      transferAccount,
      transferAmount,
      transferContent,
      transferReceiverName,
      wallet?.balance,
    ],
  );

  const visibleTransferMonitoring = useMemo(() => {
    if (!transferMonitoring) return null;
    const riskLevel = transferMonitoring.riskLevel.toLowerCase();
    const filteredReasons = transferMonitoring.reasons.filter(
      (reason) => reason !== "AI monitoring unavailable",
    );
    if (riskLevel === "low" && filteredReasons.length === 0) {
      return null;
    }
    return {
      ...transferMonitoring,
      reasons: filteredReasons,
    };
  }, [transferMonitoring]);
  const deferredTransferAdvisory = useDeferredValue(transferAdvisory);
  const deferredTransferMonitoring = useDeferredValue(
    visibleTransferMonitoring,
  );

  const renderAiMonitoringPanel = useCallback(
    (monitoring: AiMonitoringSummary | null, title: string) => {
      if (!monitoring) return null;
      const riskLevel = monitoring.riskLevel.toLowerCase();
      const tone =
        riskLevel === "high" || riskLevel === "medium" ? riskLevel : "low";
      return (
        <div className={`transfer-ai-card ${tone}`} data-risk={tone}>
          <div className="transfer-ai-head">
            <strong>{title}</strong>
            <span className={`transfer-ai-pill ${tone}`}>
              {tone.toUpperCase()} / {Math.round(monitoring.score * 100)}%
            </span>
          </div>
          <p>
            {monitoring.monitoringOnly
              ? "This action is being monitored by the anomaly model."
              : "This action is being evaluated by the anomaly model."}
          </p>
          {monitoring.reasons.length > 0 && (
            <ul>
              {monitoring.reasons.slice(0, 3).map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
          )}
        </div>
      );
    },
    [],
  );

  const renderTransferTrustPanel = useCallback(
    (
      monitoring: AiMonitoringSummary | null,
      options?: {
        forceTone?: "low" | "medium" | "high";
        compact?: boolean;
      },
    ) => {
      if (!monitoring) return null;
      const riskLevel = monitoring.riskLevel.toLowerCase();
      const derivedTone =
        riskLevel === "high" || riskLevel === "medium" ? riskLevel : "low";
      const tone = options?.forceTone || derivedTone;
      const trustLabel =
        tone === "high"
          ? "Low trust"
          : tone === "medium"
            ? "Moderate trust"
            : "High trust";
      const trustPercent = Math.max(
        1,
        Math.min(99, Math.round((1 - monitoring.score) * 100)),
      );

      return (
        <div className={`transfer-ai-card ${tone}`} data-risk={tone}>
          <div className="transfer-ai-head">
            <strong>Transfer Trust Check</strong>
            <span className={`transfer-ai-pill ${tone}`}>
              {trustLabel} | {trustPercent}%
            </span>
          </div>
          <p>
            {tone === "low"
              ? "This transfer looks normal. OTP was sent and you can continue."
              : tone === "medium"
                ? "This transfer is less typical than usual. Review the signals before entering OTP."
                : "This transfer has strong risk signals. Review carefully before entering OTP."}
          </p>
          {!options?.compact && monitoring.reasons.length > 0 && (
            <ul>
              {monitoring.reasons.slice(0, 3).map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
          )}
        </div>
      );
    },
    [],
  );

  const refreshSecurityAlerts = useCallback(
    async (options?: { silent?: boolean }) => {
      if (!token) {
        setSecurityAlerts(dashboardSecurityAlerts);
        setSecurityRecentLogins([]);
        setSecurityTrustedDevices([]);
        setSecurityAlertsError("");
        setSecurityAlertsBusy(false);
        return;
      }

      if (!options?.silent) {
        setSecurityAlertsBusy(true);
      }
      setSecurityAlertsError("");

      try {
        const resp = await fetch(`${API_BASE}/security/overview`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = (await resp.json().catch(() => null)) as
          | SecurityOverviewResponse
          | { error?: string }
          | null;

        if (
          !resp.ok ||
          !data ||
          !("alerts" in data) ||
          !Array.isArray(data.alerts) ||
          !Array.isArray(data.recentLogins) ||
          !Array.isArray(data.trustedDevices)
        ) {
          throw new Error(
            (data &&
              "error" in data &&
              typeof data.error === "string" &&
              data.error) ||
              "Cannot load security alerts",
          );
        }

        const overview = data;

        setSecurityAlerts(
          overview.alerts.length
            ? overview.alerts.map((alert, index) => ({
                id: alert.id || `alert-${index}`,
                title: alert.title || "Security Activity",
                location: alert.location || "Unknown location",
                detail:
                  alert.detail ||
                  "Security activity was recorded for your account.",
                tone: alert.tone || "info",
                time: formatSecurityAlertTime(
                  alert.occurredAt || new Date().toISOString(),
                ),
              }))
            : [
                {
                  id: "no-alerts",
                  title: "No Recent Alerts",
                  location: "Current Account",
                  detail:
                    "No unusual sign-in activity was detected for this account in the current review window.",
                  time: "Up to date",
                  tone: "safe",
                },
              ],
        );
        setSecurityRecentLogins(overview.recentLogins);
        setSecurityTrustedDevices(overview.trustedDevices);
      } catch (err) {
        setSecurityAlertsError(
          err instanceof Error ? err.message : "Cannot load security alerts",
        );
      } finally {
        setSecurityAlertsBusy(false);
      }
    },
    [formatSecurityAlertTime, token],
  );

  const refreshWalletSnapshot = useCallback(
    async (options?: { resetOnFailure?: boolean; force?: boolean }) => {
      if (!token) {
        if (options?.resetOnFailure) {
          setWallet(null);
          setRecentTransactions([]);
          setTransactionHistory([]);
        }
        return;
      }
      if (walletRefreshInFlightRef.current && !options?.force) return;

      walletRefreshInFlightRef.current = true;
      const headers = { Authorization: `Bearer ${token}` };

      try {
        const [walletResp, txResp] = await Promise.all([
          fetch(`${API_BASE}/wallet/me`, { headers }),
          fetch(`${API_BASE}/transactions`, { headers }),
        ]);

        if (walletResp.ok) {
          const w = (await walletResp.json()) as {
            id: string;
            balance: number;
            currency: string;
            accountNumber?: string;
            qrPayload?: string;
            qrImageUrl?: string;
          };
          setWallet(w);
        }

        if (txResp.ok) {
          const txs = (await txResp.json()) as Array<{
            id: string;
            amount: number;
            type: string;
            status?: string;
            description?: string;
            createdAt: string;
            metadata?: {
              entry?: "DEBIT" | "CREDIT";
              fromAccount?: string;
              toAccount?: string;
            };
          }>;
          setRecentTransactions(
            txs.slice(0, 12).map((tx) => ({
              amount: Number(tx.amount || 0),
              type: tx.type,
              description: tx.description,
              createdAt: tx.createdAt,
              direction:
                tx.type === "DEPOSIT" || tx.metadata?.entry === "CREDIT"
                  ? "credit"
                  : "debit",
            })),
          );
          setTransactionHistory(
            txs.map((tx) => {
              const isCredit =
                tx.type === "DEPOSIT" || tx.metadata?.entry === "CREDIT";
              const receipt = buildTransactionReceipt(tx);
              return {
                id: tx.id,
                entity: tx.description || tx.type,
                date: new Date(tx.createdAt).toLocaleString("en-US"),
                status: (tx.status || "Completed").toUpperCase(),
                amount: `${isCredit ? "+" : "-"}$${Math.abs(
                  Number(tx.amount || 0),
                ).toLocaleString("en-US", {
                  minimumFractionDigits: 2,
                  maximumFractionDigits: 2,
                })}`,
                amountTone: isCredit ? "positive" : "negative",
                receipt,
              };
            }),
          );
        }
      } catch {
        if (options?.resetOnFailure) {
          setWallet(null);
          setRecentTransactions([]);
          setTransactionHistory([]);
        }
      } finally {
        walletRefreshInFlightRef.current = false;
      }
    },
    [buildTransactionReceipt, token],
  );

  const handleDownloadOwnQr = useCallback(async () => {
    if (!ownQrImageUrl || !wallet?.accountNumber) {
      toast("Wallet QR is not available yet.", "error");
      return;
    }

    setTransferQrDownloadBusy(true);
    try {
      const resp = await fetch(ownQrImageUrl);
      if (!resp.ok) {
        throw new Error(`download-failed-${resp.status}`);
      }

      const qrBlob = await resp.blob();
      const qrImage = await loadImageFromBlob(qrBlob);
      const canvas = document.createElement("canvas");
      canvas.width = 1080;
      canvas.height = 1400;
      const ctx = canvas.getContext("2d");

      if (!ctx) {
        throw new Error("canvas-context-unavailable");
      }

      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.fillStyle = "#0f172a";
      ctx.textAlign = "center";
      ctx.textBaseline = "top";
      ctx.font = '700 66px "DM Sans", "Segoe UI", sans-serif';
      const nameBottomY = drawCenteredWrappedText(
        ctx,
        ownQrDisplayName,
        canvas.width / 2,
        96,
        canvas.width - 160,
        80,
      );

      ctx.fillStyle = "#475569";
      ctx.font = '500 28px "DM Sans", "Segoe UI", sans-serif';
      ctx.fillText("Account Number", canvas.width / 2, nameBottomY + 54);

      ctx.fillStyle = "#0f172a";
      ctx.font = '600 44px "DM Sans", "Segoe UI", sans-serif';
      ctx.fillText(wallet.accountNumber, canvas.width / 2, nameBottomY + 98);

      const qrCardX = 170;
      const qrCardY = nameBottomY + 220;
      const qrCardSize = 740;
      ctx.fillStyle = "#f8fafc";
      ctx.fillRect(qrCardX, qrCardY, qrCardSize, qrCardSize);
      ctx.strokeStyle = "#dbe4f0";
      ctx.lineWidth = 4;
      ctx.strokeRect(qrCardX, qrCardY, qrCardSize, qrCardSize);

      const qrSize = 620;
      const qrX = (canvas.width - qrSize) / 2;
      const qrY = qrCardY + (qrCardSize - qrSize) / 2;
      ctx.drawImage(qrImage, qrX, qrY, qrSize, qrSize);

      const composedBlob = await new Promise<Blob>((resolve, reject) => {
        canvas.toBlob((blob) => {
          if (blob) {
            resolve(blob);
            return;
          }
          reject(new Error("canvas-export-failed"));
        }, "image/png");
      });

      const objectUrl = URL.createObjectURL(composedBlob);
      const link = document.createElement("a");
      link.href = objectUrl;
      link.download = ownQrDownloadName;
      link.click();
      URL.revokeObjectURL(objectUrl);
      toast("QR image downloaded successfully.");
    } catch (err) {
      console.error("Failed to download wallet QR", err);
      toast("Failed to download QR image.", "error");
    } finally {
      setTransferQrDownloadBusy(false);
    }
  }, [
    ownQrDisplayName,
    ownQrDownloadName,
    ownQrImageUrl,
    toast,
    wallet?.accountNumber,
  ]);

  const sendCopilotMessage = async (promptOverride?: string) => {
    const content = (promptOverride ?? copilotInput).trim();
    if (!token) {
      toast("Session expired. Please login again.", "error");
      return;
    }
    if (!content || copilotBusy) {
      return;
    }

    const nextMessages: CopilotMessage[] = [
      ...copilotMessages,
      { role: "user", content },
    ];
    setCopilotMessages(nextMessages);
    setCopilotInput("");
    setCopilotBusy(true);

    const controller = new AbortController();
    const timeout = window.setTimeout(() => {
      controller.abort();
    }, COPILOT_REQUEST_TIMEOUT_MS);

    try {
      const resp = await fetch(`${API_BASE}/ai/copilot-chat`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        signal: controller.signal,
        body: JSON.stringify({
          currency: wallet?.currency || "USD",
          currentBalance: Number(wallet?.balance || 0),
          monthlyIncome: Number.isFinite(monthlyIncomeValue)
            ? monthlyIncomeValue
            : 0,
          monthlyExpenses: Number.isFinite(monthlyExpensesValue)
            ? monthlyExpensesValue
            : 0,
          recentTransactions,
          messages: nextMessages,
        }),
      });
      const data = (await resp.json().catch(() => null)) as {
        error?: string;
        reply?: string;
        topic?: string;
        suggestedActions?: string[];
        suggestedDepositAmount?: number | null;
        riskLevel?: string;
        confidence?: number;
        followUpQuestion?: string | null;
      } | null;
      if (!resp.ok || !data?.reply) {
        toast(data?.error || "AI copilot is unavailable", "error");
        setCopilotMessages(nextMessages);
        return;
      }

      const assistantMessage = data.followUpQuestion
        ? `${data.reply}\n\n${data.followUpQuestion}`
        : data.reply;
      setCopilotMessages([
        ...nextMessages,
        { role: "assistant", content: assistantMessage },
      ]);
      setCopilotInsight({
        topic: data.topic || "general",
        suggestedActions: Array.isArray(data.suggestedActions)
          ? data.suggestedActions
          : [],
        suggestedDepositAmount:
          typeof data.suggestedDepositAmount === "number"
            ? data.suggestedDepositAmount
            : null,
        riskLevel: data.riskLevel || "medium",
        confidence: Number(data.confidence || 0.7),
        followUpQuestion: data.followUpQuestion || null,
      });
    } catch (error) {
      const isTimeout =
        error instanceof DOMException && error.name === "AbortError";
      toast(
        isTimeout
          ? "AI copilot took too long to respond. Local 7B replies can take up to a minute."
          : "Cannot reach AI copilot right now.",
        "error",
      );
      setCopilotMessages(nextMessages);
    } finally {
      window.clearTimeout(timeout);
      setCopilotBusy(false);
    }
  };

  useEffect(() => {
    if (!copilotOpen) return;
    const thread = copilotThreadRef.current;
    if (!thread) return;
    thread.scrollTo({
      top: thread.scrollHeight,
      behavior: "smooth",
    });
  }, [copilotMessages, copilotBusy, copilotOpen]);

  const extractAccountFromQrPayload = (payload: string) =>
    payload.match(/ACC:(\d{8,19})/i)?.[1] ||
    payload.replace(/\D/g, "").slice(0, 19);

  const decodeQrFromCanvasArea = (
    source: HTMLCanvasElement,
    area?: { x: number; y: number; size: number },
  ) => {
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    if (!ctx) return "";

    const srcX = area?.x ?? 0;
    const srcY = area?.y ?? 0;
    const srcW = area?.size ?? source.width;
    const srcH = area?.size ?? source.height;
    canvas.width = srcW;
    canvas.height = srcH;
    ctx.drawImage(source, srcX, srcY, srcW, srcH, 0, 0, srcW, srcH);
    const imageData = ctx.getImageData(0, 0, srcW, srcH);
    const decoded = jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: "attemptBoth",
    });
    return decoded?.data?.trim() || "";
  };

  const stopTransferQrCameraScan = (hidePanel = false) => {
    if (transferQrScanTimerRef.current !== null) {
      window.clearInterval(transferQrScanTimerRef.current);
      transferQrScanTimerRef.current = null;
    }

    const stream = transferQrStreamRef.current;
    if (stream) {
      for (const track of stream.getTracks()) {
        track.stop();
      }
      transferQrStreamRef.current = null;
    }

    if (transferQrVideoRef.current) {
      transferQrVideoRef.current.srcObject = null;
    }
    setTransferQrCameraOn(false);
    if (hidePanel) {
      setTransferQrCameraPanelOpen(false);
    }
  };

  const loadTransferQrDevices = async () => {
    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      const cameras = devices.filter((d) => d.kind === "videoinput");
      setTransferQrDevices(cameras);
      if (cameras.length > 0) {
        setTransferQrDeviceId((prev) =>
          prev && cameras.some((d) => d.deviceId === prev)
            ? prev
            : cameras[0].deviceId,
        );
      } else {
        setTransferQrDeviceId("");
      }
    } catch {
      setTransferQrDevices([]);
      setTransferQrDeviceId("");
    }
  };

  const resolveTransferRecipient = async (accountNumber: string) => {
    if (!token) {
      toast("Session expired. Please login again.", "error");
      return null;
    }
    try {
      const resp = await fetch(
        `${API_BASE}/wallet/resolve/${encodeURIComponent(accountNumber)}`,
        {
          headers: { Authorization: `Bearer ${token}` },
        },
      );
      const data = (await resp.json().catch(() => null)) as {
        error?: string;
        holderName?: string;
        accountNumber?: string;
        userId?: string;
      } | null;
      if (!resp.ok || !data?.accountNumber) {
        toast(data?.error || "Recipient account not found", "error");
        return null;
      }
      setTransferAccount(data.accountNumber);
      setTransferRecipientUserId(data.userId || "");
      setTransferReceiverName(
        data.holderName || `Account ${data.accountNumber.slice(-4)}`,
      );
      return {
        accountNumber: data.accountNumber,
        holderName:
          data.holderName || `Account ${data.accountNumber.slice(-4)}`,
        userId: data.userId || "",
      };
    } catch {
      toast("Cannot verify account with server", "error");
      return null;
    }
  };
  const handleTransferQrPayloadDetected = async (payload: string) => {
    const extracted = extractAccountFromQrPayload(payload);
    if (!/^\d{8,19}$/.test(extracted)) {
      toast("Cannot detect a valid account number from QR.", "error");
      return;
    }
    const resolved = await resolveTransferRecipient(extracted);
    if (!resolved) return;
    await logTransferFlowEvent("STARTED");
    toast("QR scanned successfully.");
    goToTransferStep(2);
  };
  const startTransferQrCameraScan = async (
    preferredFacingMode: "environment" | "user" = transferQrFacingMode,
  ) => {
    const BarcodeDetectorCtor = (
      window as Window & {
        BarcodeDetector?: new (opts?: { formats?: string[] }) => {
          detect: (
            source: ImageBitmapSource,
          ) => Promise<Array<{ rawValue?: string }>>;
        };
      }
    ).BarcodeDetector;

    stopTransferQrCameraScan();
    setTransferQrCameraPanelOpen(true);
    await new Promise<void>((resolve) => {
      window.requestAnimationFrame(() => resolve());
    });

    const constraintsList: MediaStreamConstraints[] = [
      { video: true },
      ...(transferQrDeviceId
        ? [
            {
              video: {
                deviceId: { exact: transferQrDeviceId },
              },
            } as MediaStreamConstraints,
          ]
        : []),
      ...(transferQrDeviceId
        ? [
            {
              video: {
                deviceId: transferQrDeviceId,
              },
            } as MediaStreamConstraints,
          ]
        : []),
      {
        video: {
          facingMode: { ideal: preferredFacingMode },
        },
      },
      {
        video: {
          facingMode: {
            ideal:
              preferredFacingMode === "environment" ? "user" : "environment",
          },
        },
      },
    ];
    for (const cam of transferQrDevices) {
      if (!cam.deviceId || cam.deviceId === transferQrDeviceId) continue;
      constraintsList.push({
        video: {
          deviceId: { exact: cam.deviceId },
        },
      });
    }

    try {
      if (!navigator.mediaDevices?.getUserMedia) {
        setTransferQrCameraError(
          "This browser does not support camera API (getUserMedia). Please use Chrome/Edge/Firefox latest.",
        );
        return;
      }

      setTransferQrCameraError("Opening camera...");
      let activeStream: MediaStream | null = null;
      const attemptErrors: string[] = [];
      for (const constraints of constraintsList) {
        try {
          const stream = await navigator.mediaDevices.getUserMedia(constraints);
          const video = transferQrVideoRef.current;
          if (!video) {
            stream.getTracks().forEach((track) => track.stop());
            continue;
          }
          video.srcObject = stream;
          video.muted = true;
          video.playsInline = true;
          video.setAttribute("playsinline", "true");
          await video.play().catch(() => {
            // Some environments may block autoplay preview but stream is still usable.
          });
          activeStream = stream;
          const activeTrack = stream.getVideoTracks()[0];
          const activeDeviceId = activeTrack?.getSettings().deviceId;
          if (activeDeviceId) {
            setTransferQrDeviceId(activeDeviceId);
          }
          setTransferQrCameraError("");
          break;
        } catch (openErr) {
          const n =
            openErr && typeof openErr === "object" && "name" in openErr
              ? String((openErr as { name?: unknown }).name || "Error")
              : "Error";
          const m =
            openErr && typeof openErr === "object" && "message" in openErr
              ? String((openErr as { message?: unknown }).message || "")
              : "";
          const shortConstraints =
            typeof constraints.video === "boolean"
              ? "video:true"
              : constraints.video &&
                  typeof constraints.video === "object" &&
                  "deviceId" in constraints.video &&
                  constraints.video.deviceId
                ? "deviceId"
                : constraints.video &&
                    typeof constraints.video === "object" &&
                    "facingMode" in constraints.video
                  ? "facingMode"
                  : "video";
          attemptErrors.push(`${shortConstraints}:${n}${m ? `(${m})` : ""}`);
        }
      }
      if (!activeStream) {
        setTransferQrCameraError(
          attemptErrors.length > 0
            ? `Cannot open camera. Attempts failed: ${attemptErrors.join(" | ")}`
            : "Cannot open camera. Browser returned no device stream.",
        );
        return;
      }
      transferQrStreamRef.current = activeStream;

      const detector = BarcodeDetectorCtor
        ? new BarcodeDetectorCtor({ formats: ["qr_code"] })
        : null;
      const frameCanvas = document.createElement("canvas");
      const frameCtx = frameCanvas.getContext("2d");
      const activeTrack = activeStream.getVideoTracks()[0] ?? null;
      const ImageCaptureCtor = (window as Window & { ImageCapture?: unknown })
        .ImageCapture as
        | (new (track: MediaStreamTrack) => {
            grabFrame: () => Promise<ImageBitmap>;
          })
        | undefined;
      setTransferQrCameraOn(true);
      transferQrScanTimerRef.current = window.setInterval(async () => {
        const video = transferQrVideoRef.current;
        if (!video) return;
        try {
          let raw = "";

          if (detector && video.readyState >= 2 && video.videoWidth > 0) {
            const results = await detector.detect(video);
            raw = results[0]?.rawValue?.trim() || "";
          }

          if (!raw && frameCtx && video.readyState >= 2) {
            const vw = video.videoWidth || video.clientWidth;
            const vh = video.videoHeight || video.clientHeight;
            if (vw > 0 && vh > 0) {
              frameCanvas.width = vw;
              frameCanvas.height = vh;
              frameCtx.drawImage(video, 0, 0, vw, vh);
              const squareSize = Math.floor(Math.min(vw, vh) * 0.72);
              const centerSquare = {
                x: Math.max(0, Math.floor((vw - squareSize) / 2)),
                y: Math.max(0, Math.floor((vh - squareSize) / 2)),
                size: squareSize,
              };
              raw =
                decodeQrFromCanvasArea(frameCanvas, centerSquare) ||
                decodeQrFromCanvasArea(frameCanvas);
            }
          }

          if (
            !raw &&
            activeTrack &&
            ImageCaptureCtor &&
            activeTrack.readyState === "live"
          ) {
            const imageCapture = new ImageCaptureCtor(activeTrack);
            const bitmap = await imageCapture.grabFrame();
            try {
              if (detector) {
                const results = await detector.detect(bitmap);
                raw = results[0]?.rawValue?.trim() || "";
              }
              if (!raw && frameCtx) {
                frameCanvas.width = bitmap.width;
                frameCanvas.height = bitmap.height;
                frameCtx.drawImage(bitmap, 0, 0, bitmap.width, bitmap.height);
                const squareSize = Math.floor(
                  Math.min(bitmap.width, bitmap.height) * 0.72,
                );
                const centerSquare = {
                  x: Math.max(0, Math.floor((bitmap.width - squareSize) / 2)),
                  y: Math.max(0, Math.floor((bitmap.height - squareSize) / 2)),
                  size: squareSize,
                };
                raw =
                  decodeQrFromCanvasArea(frameCanvas, centerSquare) ||
                  decodeQrFromCanvasArea(frameCanvas);
              }
            } finally {
              bitmap.close();
            }
          }

          if (!raw) return;
          stopTransferQrCameraScan(true);
          await handleTransferQrPayloadDetected(raw);
        } catch {
          // keep scanning
        }
      }, 500);
    } catch (err) {
      stopTransferQrCameraScan();
      const name =
        err && typeof err === "object" && "name" in err
          ? String((err as { name?: unknown }).name || "")
          : "";
      const message =
        err && typeof err === "object" && "message" in err
          ? String((err as { message?: unknown }).message || "")
          : "";
      if (name === "NotAllowedError") {
        setTransferQrCameraError(
          "Camera permission denied. Please allow camera access.",
        );
      } else if (name === "NotFoundError") {
        setTransferQrCameraError("No camera device found on this machine.");
      } else if (name === "NotReadableError") {
        setTransferQrCameraError(
          "Camera is in use by another app (Zoom/Meet/Zalo/OBS). Close it and try again.",
        );
      } else if (name === "OverconstrainedError") {
        setTransferQrCameraError(
          "Camera constraints are not supported on this device. Press Reload cameras and try again.",
        );
      } else if (name === "SecurityError") {
        setTransferQrCameraError(
          "Browser blocked camera due to security policy. Open from localhost only and allow camera.",
        );
      } else if (name === "AbortError") {
        setTransferQrCameraError(
          "Camera start was interrupted. Please try Scan QR by camera again.",
        );
      } else {
        setTransferQrCameraError(
          `Cannot open camera on this browser/device.${name ? ` [${name}]` : ""}${message ? ` ${message}` : ""}`,
        );
      }
    }
  };

  const detectQrFromImageFile = async (file: File) => {
    const BarcodeDetectorCtor = (
      window as Window & {
        BarcodeDetector?: new (opts?: { formats?: string[] }) => {
          detect: (
            source: ImageBitmapSource,
          ) => Promise<Array<{ rawValue?: string }>>;
        };
      }
    ).BarcodeDetector;

    let bitmap: ImageBitmap | null = null;
    try {
      if (BarcodeDetectorCtor) {
        const detector = new BarcodeDetectorCtor({ formats: ["qr_code"] });
        bitmap = await createImageBitmap(file);
        const results = await detector.detect(bitmap);
        const raw = results[0]?.rawValue?.trim();
        if (raw) {
          await handleTransferQrPayloadDetected(raw);
          return;
        }
      }

      const objectUrl = URL.createObjectURL(file);
      try {
        const img = await new Promise<HTMLImageElement>((resolve, reject) => {
          const image = new Image();
          image.onload = () => resolve(image);
          image.onerror = () => reject(new Error("load-failed"));
          image.src = objectUrl;
        });
        const canvas = document.createElement("canvas");
        canvas.width = img.naturalWidth || img.width;
        canvas.height = img.naturalHeight || img.height;
        const ctx = canvas.getContext("2d");
        if (!ctx) throw new Error("canvas-context-failed");
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        const rotateCanvas = (
          sourceCanvas: HTMLCanvasElement,
          angle: 0 | 90 | 180 | 270,
        ) => {
          if (angle === 0) return sourceCanvas;
          const out = document.createElement("canvas");
          const srcW = sourceCanvas.width;
          const srcH = sourceCanvas.height;
          out.width = angle === 90 || angle === 270 ? srcH : srcW;
          out.height = angle === 90 || angle === 270 ? srcW : srcH;
          const outCtx = out.getContext("2d");
          if (!outCtx) return sourceCanvas;
          outCtx.translate(out.width / 2, out.height / 2);
          outCtx.rotate((angle * Math.PI) / 180);
          outCtx.drawImage(sourceCanvas, -srcW / 2, -srcH / 2);
          return out;
        };
        const decodeCanvasRegion = (
          sourceCanvas: HTMLCanvasElement,
          region?: { x: number; y: number; w: number; h: number },
          scale = 1,
        ) => {
          const srcX = region?.x ?? 0;
          const srcY = region?.y ?? 0;
          const srcW = region?.w ?? sourceCanvas.width;
          const srcH = region?.h ?? sourceCanvas.height;
          if (srcW <= 0 || srcH <= 0) return "";

          const work = document.createElement("canvas");
          work.width = Math.max(1, Math.floor(srcW * scale));
          work.height = Math.max(1, Math.floor(srcH * scale));
          const workCtx = work.getContext("2d");
          if (!workCtx) return "";
          workCtx.imageSmoothingEnabled = false;
          workCtx.drawImage(
            sourceCanvas,
            srcX,
            srcY,
            srcW,
            srcH,
            0,
            0,
            work.width,
            work.height,
          );
          const imageData = workCtx.getImageData(0, 0, work.width, work.height);
          const decoded = jsQR(
            imageData.data,
            imageData.width,
            imageData.height,
            {
              inversionAttempts: "attemptBoth",
            },
          );
          return decoded?.data?.trim() || "";
        };

        const buildScanRegions = (sourceCanvas: HTMLCanvasElement) => {
          const cw = sourceCanvas.width;
          const ch = sourceCanvas.height;
          const regions: Array<
            | undefined
            | {
                x: number;
                y: number;
                w: number;
                h: number;
              }
          > = [undefined];

          const ratioWindows = [0.9, 0.75, 0.6, 0.45, 0.35];
          const anchors = [0, 0.25, 0.5, 0.75, 1];

          for (const ratio of ratioWindows) {
            const w = Math.max(96, Math.floor(cw * ratio));
            const h = Math.max(96, Math.floor(ch * ratio));
            const maxX = Math.max(0, cw - w);
            const maxY = Math.max(0, ch - h);
            for (const fx of anchors) {
              for (const fy of anchors) {
                const x = Math.floor(maxX * fx);
                const y = Math.floor(maxY * fy);
                regions.push({ x, y, w, h });
              }
            }
          }

          return regions;
        };

        const scales = [1, 1.5, 2, 3];
        let raw = "";
        const rotations: Array<0 | 90 | 180 | 270> = [0, 90, 180, 270];
        for (const angle of rotations) {
          const rotated = rotateCanvas(canvas, angle);
          const regions = buildScanRegions(rotated);
          for (const region of regions) {
            for (const scale of scales) {
              raw = decodeCanvasRegion(rotated, region, scale);
              if (raw) break;
            }
            if (raw) break;
          }
          if (raw) break;
        }

        if (!raw) {
          toast(
            "Cannot detect QR from this image. Please try another image angle or higher resolution.",
            "error",
          );
          return;
        }
        await handleTransferQrPayloadDetected(raw);
      } finally {
        URL.revokeObjectURL(objectUrl);
      }
    } catch {
      toast("Failed to decode QR image.", "error");
    } finally {
      bitmap?.close();
    }
  };

  useEffect(() => {
    void refreshWalletSnapshot({ resetOnFailure: true, force: true });
  }, [refreshWalletSnapshot]);

  useEffect(() => {
    void refreshSecurityAlerts({ silent: true });
  }, [refreshSecurityAlerts]);

  useEffect(() => {
    if (!user || !token) {
      setTransferFaceIdEnabled(false);
      return;
    }

    let cancelled = false;
    const loadTransferFaceFlag = async () => {
      try {
        const resp = await fetch(`${API_BASE}/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = (await resp.json().catch(() => null)) as {
          metadata?: Record<string, unknown>;
        } | null;
        if (!resp.ok || !data || cancelled) return;
        setTransferFaceIdEnabled(data.metadata?.faceIdEnabled === true);
      } catch {
        if (!cancelled) {
          setTransferFaceIdEnabled(false);
        }
      }
    };

    void loadTransferFaceFlag();
    return () => {
      cancelled = true;
    };
  }, [token, user?.id]);

  useEffect(() => {
    if (!token) return;

    const refreshIfVisible = () => {
      if (document.visibilityState === "hidden") return;
      void refreshWalletSnapshot();
      void refreshSecurityAlerts({ silent: true });
    };

    const interval = window.setInterval(refreshIfVisible, 5000);
    window.addEventListener("focus", refreshIfVisible);
    document.addEventListener("visibilitychange", refreshIfVisible);

    return () => {
      window.clearInterval(interval);
      window.removeEventListener("focus", refreshIfVisible);
      document.removeEventListener("visibilitychange", refreshIfVisible);
    };
  }, [refreshSecurityAlerts, refreshWalletSnapshot, token]);

  const generateOtp = () => {
    const next = String(Math.floor(100000 + Math.random() * 900000));
    setOtpCode(next);
    setOtpInput("");
    setOtpError("");
    setOtpAttempts(0);
    toast(`OTP sent to +1 *** **67 (demo OTP: ${next})`, "info");
  };

  const openDetailsModal = () => {
    setDetailsModalOpen(true);
    setDetailsStep("otp");
    generateOtp();
  };

  const closeDetailsModal = () => {
    setDetailsModalOpen(false);
    setOtpInput("");
    setOtpError("");
    setOtpAttempts(0);
    setDetailsStep("otp");
  };

  const verifyOtpAndShowDetails = () => {
    if (!/^\d{6}$/.test(otpInput)) {
      setOtpError("OTP must be exactly 6 digits.");
      return;
    }
    if (otpInput !== otpCode) {
      const nextAttempts = otpAttempts + 1;
      setOtpAttempts(nextAttempts);
      setOtpError("Incorrect OTP. Please try again.");
      if (nextAttempts >= 3) {
        generateOtp();
        setOtpError("Too many failed attempts. A new OTP has been sent.");
      }
      return;
    }
    setOtpError("");
    setDetailsStep("details");
    toast("OTP verified successfully");
  };

  const resetTransferFlow = () => {
    stopTransferQrCameraScan(true);
    setTransferStepDirection("backward");
    startTransition(() => {
      setTransferStep(1);
    });
    setTransferMethod("account");
    setTransferAccount("");
    setTransferRecipientUserId("");
    setTransferReceiverName("");
    setTransferAmount("");
    setTransferContent(defaultTransferContent);
    setTransferQrFile("");
    setTransferQrCameraError("");
    setTransferQrFacingMode("environment");
    setTransferShowMyQr(false);
    setTransferOtpInput("");
    setTransferOtpError("");
    setTransferOtpChallengeId("");
    setTransferOtpDestination("");
    setTransferOtpExpiresAt("");
    setTransferFaceProof(null);
    setTransferFaceResetKey((value) => value + 1);
    setTransferFaceVerifyOpen(false);
    setTransferFaceVerifyBusy(false);
    setTransferServerFaceIdRequired(false);
    setTransferServerFaceIdReason("");
    setTransferRollingOutflowAmount(null);
    setTransferOtpResendAt(0);
    setTransferOtpBusy(false);
    setTransferOtpVerifyBusy(false);
    setTransferMonitoring(null);
    setTransferAdvisory(null);
    setTransferAdvisoryAcknowledged(false);
    setTransferReceipt(null);
  };

  const goToTransferStep = useCallback(
    (nextStep: 1 | 2 | 3 | 4) => {
      setTransferStepDirection(
        nextStep >= transferStep ? "forward" : "backward",
      );
      startTransition(() => {
        setTransferStep(nextStep);
      });
    },
    [transferStep],
  );

  const openTransferModal = () => {
    setTransferOpen(true);
    resetTransferFlow();
  };

  const closeTransferModal = () => {
    const shouldLogCancelled =
      transferStep < 4 &&
      Boolean(
        transferAccount ||
        transferRecipientUserId ||
        transferAmount ||
        transferOtpChallengeId ||
        transferAdvisory ||
        transferMonitoring,
      );
    if (shouldLogCancelled) {
      void logTransferFlowEvent("CANCELLED", {
        reason: "USER_CLOSED_TRANSFER_MODAL",
      });
    }
    void dismissTransferAdvisory();
    setTransferOpen(false);
    resetTransferFlow();
  };

  useEffect(() => {
    return () => {
      stopTransferQrCameraScan(true);
    };
  }, []);

  useEffect(() => {
    if (!transferOpen || transferStep !== 1 || transferMethod !== "qr") return;
    void loadTransferQrDevices();
  }, [transferOpen, transferStep, transferMethod]);

  useEffect(() => {
    if (
      transferOtpResendAt <= Date.now() ||
      (!transferFaceVerifyOpen && (!transferOpen || transferStep !== 3))
    ) {
      return;
    }
    const timer = window.setInterval(
      () => setTransferOtpClock(Date.now()),
      1000,
    );
    return () => window.clearInterval(timer);
  }, [transferFaceVerifyOpen, transferOpen, transferOtpResendAt, transferStep]);

  useEffect(() => {
    if (typeof document === "undefined") return;
    document.body.classList.toggle(
      "transfer-faceid-screen-open",
      transferFaceVerifyOpen,
    );
    document.documentElement.classList.toggle(
      "transfer-faceid-screen-open",
      transferFaceVerifyOpen,
    );

    return () => {
      document.body.classList.remove("transfer-faceid-screen-open");
      document.documentElement.classList.remove("transfer-faceid-screen-open");
    };
  }, [transferFaceVerifyOpen]);

  const generateTransferOtp = async (options?: {
    advisoryAcknowledged?: boolean;
  }) => {
    if (!token) {
      toast("Session expired. Please login again.", "error");
      return false;
    }
    setTransferOtpBusy(true);
    try {
      const amount = Number(transferAmount.replace(/,/g, "")) || 0;
      const resp = await fetch(`${API_BASE}/transfer/otp/send`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          toAccount: transferAccount,
          amount,
          note: transferContent || defaultTransferContent,
          advisoryAcknowledged:
            options?.advisoryAcknowledged === true ||
            transferAdvisoryAcknowledged,
          advisoryRequestKey:
            transferAdvisory?.requestKey ||
            transferMonitoring?.requestKey ||
            null,
        }),
      });
      const data = (await resp.json().catch(() => null)) as {
        error?: string;
        challengeId?: string;
        destination?: string;
        expiresAt?: string;
        retryAfterSeconds?: number;
        anomaly?: unknown;
        transferAdvisory?: unknown;
        faceIdRequired?: boolean;
        faceIdReason?: string;
        rollingOutflowAmount?: number;
      } | null;
      const monitoring = parseAiMonitoringSummary(data?.anomaly);
      const advisory = parseTransferSafetyAdvisory(data?.transferAdvisory);
      const visibleMonitoring = (() => {
        if (!monitoring) return null;
        const riskLevel = monitoring.riskLevel.toLowerCase();
        const filteredReasons = monitoring.reasons.filter(
          (reason) => reason !== "AI monitoring unavailable",
        );
        if (riskLevel === "low" && filteredReasons.length === 0) {
          return null;
        }
        return {
          ...monitoring,
          reasons: filteredReasons,
        };
      })();
      if (monitoring) {
        setTransferMonitoring(monitoring);
      } else if (resp.ok || resp.status === 409 || resp.status === 423) {
        setTransferMonitoring(null);
      }
      if (advisory) {
        setTransferAdvisory(advisory);
      } else if (resp.ok || resp.status === 423 || resp.status === 403) {
        setTransferAdvisory(null);
      }

      if ((resp.status === 409 || resp.status === 423) && advisory) {
        setTransferAdvisoryAcknowledged(false);
        toast(
          data?.error ||
            (resp.status === 423
              ? "This transfer is blocked for safety review."
              : "Please review this transfer warning."),
          resp.status === 423 ? "error" : "info",
        );
        return false;
      }

      if (!resp.ok || !data?.challengeId) {
        toast(data?.error || "Failed to send OTP email", "error");
        return false;
      }
      setTransferAdvisoryAcknowledged(
        options?.advisoryAcknowledged === true ||
          transferAdvisoryAcknowledged ||
          Boolean(advisory),
      );
      setTransferOtpChallengeId(data.challengeId);
      setTransferOtpDestination(data.destination || "");
      setTransferOtpExpiresAt(data.expiresAt || "");
      setTransferServerFaceIdRequired(data.faceIdRequired === true);
      setTransferServerFaceIdReason(data.faceIdReason || "");
      setTransferRollingOutflowAmount(
        typeof data.rollingOutflowAmount === "number"
          ? data.rollingOutflowAmount
          : null,
      );
      setTransferOtpResendAt(
        Date.now() + Number(data.retryAfterSeconds || 60) * 1000,
      );
      setTransferOtpInput("");
      setTransferOtpError("");
      toast(
        data.destination
          ? `OTP sent to ${data.destination}`
          : "OTP sent to your email",
        "info",
      );
      if (
        visibleMonitoring &&
        visibleMonitoring.riskLevel.toLowerCase() !== "low"
      ) {
        toast(
          `AI transfer monitoring flagged ${visibleMonitoring.riskLevel.toLowerCase()} risk (${Math.round(
            visibleMonitoring.score * 100,
          )}%).`,
          "info",
        );
      }
      return true;
    } finally {
      setTransferOtpBusy(false);
    }
  };
  const dismissTransferAdvisory = useCallback(async () => {
    if (
      !token ||
      !transferAdvisory ||
      transferAdvisoryAcknowledged ||
      (!transferAdvisory.requestKey && !transferMonitoring?.requestKey)
    ) {
      return;
    }

    try {
      await fetch(`${API_BASE}/transfer/advisory/dismiss`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          requestKey:
            transferAdvisory.requestKey ||
            transferMonitoring?.requestKey ||
            null,
          advisory: transferAdvisory,
          toAccount: transferAccount,
          amount:
            Number(transferAmount.replace(/,/g, "")) || transferAdvisory.amount,
        }),
      });
    } catch {
      // Best-effort telemetry only.
    }
  }, [
    token,
    transferAdvisory,
    transferAdvisoryAcknowledged,
    transferMonitoring?.requestKey,
    transferAccount,
    transferAmount,
  ]);
  const logTransferFlowEvent = useCallback(
    async (
      eventType: "STARTED" | "CANCELLED",
      options?: {
        amount?: number | null;
        reason?: string;
      },
    ) => {
      if (!token) return;

      try {
        await fetch(`${API_BASE}/transfer/flow-event`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            eventType,
            toAccount: transferAccount || null,
            toUserId: transferRecipientUserId || null,
            amount:
              typeof options?.amount === "number"
                ? options.amount
                : Number(transferAmount.replace(/,/g, "")) || null,
            note: transferContent.trim() || null,
            requestKey:
              transferMonitoring?.requestKey ||
              transferAdvisory?.requestKey ||
              null,
            step: transferStep,
            reason: options?.reason || null,
          }),
        });
      } catch {
        // Best-effort telemetry only.
      }
    },
    [
      token,
      transferAccount,
      transferRecipientUserId,
      transferAmount,
      transferContent,
      transferMonitoring?.requestKey,
      transferAdvisory?.requestKey,
      transferStep,
    ],
  );
  const continueTransferRecipient = async () => {
    if (transferMethod === "account") {
      if (!/^\d{8,19}$/.test(transferAccount)) {
        toast("Please enter a valid account number (8-19 digits).", "error");
        return;
      }
    } else if (!transferAccount) {
      toast("Please scan QR by camera or upload a QR image first.", "error");
      return;
    }
    const resolved = await resolveTransferRecipient(transferAccount);
    if (!resolved) return;
    await logTransferFlowEvent("STARTED");
    goToTransferStep(2);
  };
  const continueTransferAmount = async () => {
    const amount = Number(transferAmount.replace(/,/g, ""));
    if (!transferAmount || Number.isNaN(amount) || amount <= 0) {
      toast("Please enter a valid transfer amount.", "error");
      return;
    }
    if (exceedsRestrictedTransferLimit && restrictedTransferLimit !== null) {
      toast(
        `Large transfers above $${restrictedTransferLimit.toLocaleString("en-US")} are temporarily restricted for this sign-in.`,
        "error",
      );
      return;
    }
    if (!canContinueTransferAmount) {
      return;
    }
    if (amount > TRANSFER_FACE_ID_THRESHOLD && !transferFaceIdEnabled) {
      toast(
        `Transfers above $${TRANSFER_FACE_ID_THRESHOLD.toLocaleString(
          "en-US",
        )} require FaceID enrollment on this account.`,
        "error",
      );
      return;
    }
    if (!transferContent.trim()) {
      setTransferContent(defaultTransferContent);
    }
    const sent = await generateTransferOtp({
      advisoryAcknowledged: Boolean(transferAdvisory),
    });
    if (sent) {
      goToTransferStep(3);
    }
  };

  const closeTransferFaceVerification = useCallback(() => {
    setTransferFaceVerifyOpen(false);
    setTransferOpen(true);
    goToTransferStep(3);
    setTransferFaceProof(null);
    setTransferFaceResetKey((value) => value + 1);
    setTransferFaceVerifyBusy(false);
  }, []);

  const verifyTransferOtpGate = useCallback(async () => {
    if (!token) {
      toast("Session expired. Please login again.", "error");
      return false;
    }

    setTransferOtpVerifyBusy(true);
    try {
      let resp: Response;
      try {
        resp = await fetch(`${API_BASE}/transfer/otp/verify`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            challengeId: transferOtpChallengeId,
            otp: transferOtpInput,
          }),
        });
      } catch {
        setTransferOtpError("Cannot connect to API server.");
        return false;
      }

      const data = (await resp.json().catch(() => null)) as {
        error?: string;
        faceIdRequired?: boolean;
        faceIdReason?: string;
        rollingOutflowAmount?: number;
      } | null;
      if (!resp.ok) {
        setTransferOtpError(data?.error || "OTP verification failed");
        return false;
      }

      setTransferServerFaceIdRequired(data?.faceIdRequired === true);
      setTransferServerFaceIdReason(data?.faceIdReason || "");
      setTransferRollingOutflowAmount(
        typeof data?.rollingOutflowAmount === "number"
          ? data.rollingOutflowAmount
          : null,
      );
      setTransferOtpError("");
      return true;
    } finally {
      setTransferOtpVerifyBusy(false);
    }
  }, [token, toast, transferOtpChallengeId, transferOtpInput]);

  const submitTransferConfirmation = useCallback(
    async (faceProof?: FaceIdProof | null) => {
      const now = new Date();
      const txId = `TXN-${now
        .toISOString()
        .replace(/[-:.TZ]/g, "")
        .slice(0, 14)}-${Math.floor(1000 + Math.random() * 9000)}`;
      const executedAt = now.toLocaleString("en-US", {
        month: "short",
        day: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: true,
      });
      const amount = Number(transferAmount.replace(/,/g, "")) || 0;
      if (!token) {
        toast("Session expired. Please login again.", "error");
        return false;
      }
      let transferResp: Response;
      try {
        transferResp = await fetch(`${API_BASE}/transfer/confirm`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            challengeId: transferOtpChallengeId,
            otp: transferOtpInput,
            faceIdEnrollment: transferServerFaceIdRequired
              ? faceProof
              : undefined,
          }),
        });
      } catch {
        setTransferOtpError("Cannot connect to API server.");
        return false;
      }
      if (!transferResp.ok) {
        const err = (await transferResp.json().catch(() => null)) as {
          error?: string;
        } | null;
        setTransferOtpError(err?.error || "OTP verification failed");
        return false;
      }

      const transferPayload = (await transferResp.json().catch(() => null)) as {
        reconciliationId?: string;
        anomaly?: unknown;
        transaction?: {
          id: string;
          toAccount?: string;
        };
      } | null;
      const confirmedMonitoring = parseAiMonitoringSummary(
        transferPayload?.anomaly,
      );
      if (confirmedMonitoring) {
        setTransferMonitoring(confirmedMonitoring);
      }
      const targetAccount =
        transferPayload?.transaction?.toAccount || transferAccount;
      setTransferReceipt({
        txId: transferPayload?.transaction?.id || txId,
        executedAt,
        fromAccount: wallet?.accountNumber || "Primary Checking",
        toAccount: targetAccount,
        amountUsd: amount.toLocaleString("en-US", {
          minimumFractionDigits: 2,
          maximumFractionDigits: 2,
        }),
        feeUsd: "0.00",
        note: transferContent || defaultTransferContent,
        status: "Completed",
      });
      setTransactionHistory((prev) => [
        {
          entity: `Transfer to **** ${targetAccount.slice(-4)}`,
          date: executedAt,
          id: transferPayload?.transaction?.id || txId,
          status: "COMPLETED",
          amount: `-$${amount.toLocaleString("en-US", {
            minimumFractionDigits: 2,
            maximumFractionDigits: 2,
          })}`,
          amountTone: "negative",
          receipt: {
            txId: transferPayload?.transaction?.id || txId,
            executedAt,
            fromAccount: wallet?.accountNumber || "Primary Checking",
            toAccount: targetAccount,
            amountUsd: amount.toLocaleString("en-US", {
              minimumFractionDigits: 2,
              maximumFractionDigits: 2,
            }),
            feeUsd: "0.00",
            note: transferContent || defaultTransferContent,
            status: "Completed",
          },
        },
        ...prev,
      ]);
      closeTransferFaceVerification();
      await refreshWalletSnapshot({ force: true });
      goToTransferStep(4);
      toast("Transfer completed successfully");
      return true;
    },
    [
      closeTransferFaceVerification,
      defaultTransferContent,
      refreshWalletSnapshot,
      toast,
      token,
      transferServerFaceIdRequired,
      transferAccount,
      transferAmount,
      transferContent,
      transferOtpChallengeId,
      transferOtpInput,
      wallet?.accountNumber,
    ],
  );

  const verifyTransferOtpAndSubmit = async () => {
    if (!/^\d{6}$/.test(transferOtpInput)) {
      setTransferOtpError("OTP must be exactly 6 digits.");
      return;
    }
    if (!transferOtpChallengeId) {
      setTransferOtpError("OTP session is missing. Please resend OTP.");
      return;
    }
    setTransferOtpError("");
    if (transferServerFaceIdRequired) {
      const otpVerified = await verifyTransferOtpGate();
      if (!otpVerified) {
        return;
      }
      setTransferFaceProof(null);
      setTransferFaceResetKey((value) => value + 1);
      setTransferOpen(false);
      setTransferFaceVerifyOpen(true);
      return;
    }
    await submitTransferConfirmation(null);
  };

  const handleTransferFaceConfirm = useCallback(async () => {
    if (!transferFaceProof) {
      setTransferOtpError("Complete the live FaceID scan first.");
      return;
    }
    setTransferOtpError("");
    setTransferFaceVerifyBusy(true);
    try {
      await submitTransferConfirmation(transferFaceProof);
    } finally {
      setTransferFaceVerifyBusy(false);
    }
  }, [submitTransferConfirmation, transferFaceProof]);

  return (
    <section className="dashboard-v2">
      <div className="dashboard-v2-top">
        <article className="dashboard-wallet-card">
          <div className="dashboard-wallet-head">
            <div>
              <div className="dashboard-wallet-label">Total Wallet Balance</div>
              <h2>
                {wallet
                  ? `${wallet.currency} ${Number(wallet.balance).toLocaleString(
                      "en-US",
                      { minimumFractionDigits: 2, maximumFractionDigits: 2 },
                    )}`
                  : "USD 0.00"}
              </h2>
            </div>
          </div>
          <div className="dashboard-wallet-foot">
            <div>
              <div className="dashboard-wallet-id-label">Account Number</div>
              <div className="dashboard-wallet-id-row">
                <div className="dashboard-wallet-id">
                  {walletGroups.map((group, idx) => (
                    <span key={idx} className="dashboard-wallet-id-group">
                      {group}
                    </span>
                  ))}
                </div>
                <button
                  type="button"
                  className="dashboard-wallet-toggle-btn"
                  onClick={() => setShowWalletId((v) => !v)}
                  aria-label={
                    showWalletId ? "Hide account number" : "Show account number"
                  }
                  title={
                    showWalletId ? "Hide account number" : "Show account number"
                  }
                >
                  {showWalletId ? "Hide" : "Show"}
                </button>
              </div>
            </div>
            <button
              type="button"
              className="dashboard-wallet-detail-btn"
              onClick={openDetailsModal}
            >
              View Details
            </button>
          </div>
        </article>

        <aside className="dashboard-actions-card">
          <h3>Quick Actions</h3>
          <div className="dashboard-actions-list">
            {dashboardQuickActions
              .filter((action) => action.id !== "deposit")
              .map((action) => (
                <button
                  type="button"
                  className="dashboard-action-item"
                  key={action.title}
                  onClick={() => {
                    if (action.id === "transfer") {
                      openTransferModal();
                    } else if (action.id === "copilot") {
                      setCopilotOpen(true);
                    }
                  }}
                >
                  <span className="dashboard-action-icon">{action.icon}</span>
                  <span className="dashboard-action-text">
                    <strong>{action.title}</strong>
                    <small>{action.detail}</small>
                  </span>
                  <span className="dashboard-action-arrow">{">"}</span>
                </button>
              ))}
          </div>
          <button
            type="button"
            className="dashboard-all-actions"
            onClick={() => {
              setCopilotOpen(true);
            }}
          >
            Open AI workspace
          </button>
        </aside>
      </div>

      <section className="dashboard-block">
        <div className="dashboard-block-head">
          <h3>Security Alerts</h3>
          <span className="dashboard-tag">{securityRecentLogins.length}</span>
          <button
            type="button"
            className="dashboard-link"
            onClick={() => {
              setSecurityAlertsModalOpen(true);
              void refreshSecurityAlerts();
            }}
          >
            {securityAlertsBusy ? "Loading..." : "View Sign-In Activity"}
          </button>
        </div>
        {renderSecurityRecentLoginList(securityRecentLogins, {
          limit: 3,
          keyPrefix: "preview",
          className: "security-alerts-preview-list",
        })}
        {securityAlertsError ? (
          <div className="dashboard-inline-note">{securityAlertsError}</div>
        ) : null}
      </section>

      <section className="dashboard-block">
        <div className="dashboard-block-head">
          <h3>Transaction History</h3>
          <button
            type="button"
            className="dashboard-link"
            onClick={() => setHistoryModalOpen(true)}
          >
            View All Transactions
          </button>
        </div>
        <div className="dashboard-tx-wrap">
          <table className="dashboard-tx-table">
            <thead>
              <tr>
                <th>Entity</th>
                <th>Date</th>
                <th>Status</th>
                <th>Amount</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {transactionHistory.slice(0, 3).map((tx) => (
                <tr key={tx.id}>
                  <td>{tx.entity}</td>
                  <td>{tx.date}</td>
                  <td>
                    <span className="dashboard-status-pill">{tx.status}</span>
                  </td>
                  <td
                    className={
                      tx.amountTone === "positive"
                        ? "amount-positive"
                        : "amount-negative"
                    }
                  >
                    {tx.amount}
                  </td>
                  <td>
                    <button
                      type="button"
                      className="tx-detail-btn"
                      onClick={() => setSelectedTransactionReceipt(tx.receipt)}
                    >
                      Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {securityAlertsModalOpen && (
        <div
          className="modal-overlay"
          onClick={() => setSecurityAlertsModalOpen(false)}
        >
          <div
            className="modal-card security-alerts-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="card-details-head">
              <h3>Sign-In Activity</h3>
              <button
                type="button"
                className="card-details-close"
                onClick={() => setSecurityAlertsModalOpen(false)}
              >
                x
              </button>
            </div>
            <div className="security-alerts-toolbar">
              <span className="dashboard-tag">LIVE</span>
              <button
                type="button"
                className="pill"
                disabled={securityAlertsBusy}
                onClick={() => void refreshSecurityAlerts()}
              >
                {securityAlertsBusy ? "Refreshing..." : "Refresh"}
              </button>
            </div>
            {securityAlertsError ? (
              <div className="dashboard-inline-note">{securityAlertsError}</div>
            ) : null}
            <div className="security-activity-grid">
              <section className="security-activity-section">
                <div className="security-activity-head">
                  <h4>Recent Sign-Ins</h4>
                  <span className="dashboard-tag">
                    {securityRecentLogins.length}
                  </span>
                </div>
                {renderSecurityRecentLoginList(securityRecentLogins, {
                  keyPrefix: "modal",
                })}
              </section>
            </div>
          </div>
        </div>
      )}

      {historyModalOpen && (
        <div
          className="modal-overlay"
          onClick={() => setHistoryModalOpen(false)}
        >
          <div
            className="modal-card tx-history-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="card-details-head">
              <h3>Full Transaction History</h3>
              <button
                type="button"
                className="card-details-close"
                onClick={() => setHistoryModalOpen(false)}
              >
                x
              </button>
            </div>
            <div className="dashboard-tx-wrap">
              <table className="dashboard-tx-table">
                <thead>
                  <tr>
                    <th>Entity</th>
                    <th>Date</th>
                    <th>Status</th>
                    <th>Amount</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {transactionHistory.map((tx) => (
                    <tr key={`modal-${tx.id}`}>
                      <td>{tx.entity}</td>
                      <td>{tx.date}</td>
                      <td>
                        <span className="dashboard-status-pill">
                          {tx.status}
                        </span>
                      </td>
                      <td
                        className={
                          tx.amountTone === "positive"
                            ? "amount-positive"
                            : "amount-negative"
                        }
                      >
                        {tx.amount}
                      </td>
                      <td>
                        <button
                          type="button"
                          className="tx-detail-btn"
                          onClick={() =>
                            setSelectedTransactionReceipt(tx.receipt)
                          }
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="transfer-actions" style={{ marginTop: 12 }}>
              <button
                type="button"
                className="btn-primary"
                onClick={() => setHistoryModalOpen(false)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {detailsModalOpen && (
        <div className="modal-overlay" onClick={closeDetailsModal}>
          <div
            className="modal-card card-details-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="card-details-head">
              <h3>Card Security Verification</h3>
              <button
                type="button"
                className="card-details-close"
                onClick={closeDetailsModal}
              >
                x
              </button>
            </div>

            {detailsStep === "otp" ? (
              <div className="card-otp-step">
                <p className="muted">
                  To view full card details, enter the 6-digit OTP sent to your
                  registered phone number.
                </p>
                <label className="form-group">
                  <span>Enter OTP</span>
                  <input
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    value={otpInput}
                    onChange={(e) =>
                      setOtpInput(e.target.value.replace(/\D/g, "").slice(0, 6))
                    }
                    placeholder="6-digit OTP"
                  />
                </label>
                {otpError && <div className="card-otp-error">{otpError}</div>}
                <div className="card-otp-actions">
                  <button type="button" className="pill" onClick={generateOtp}>
                    Resend OTP
                  </button>
                  <button
                    type="button"
                    className="btn-primary"
                    onClick={verifyOtpAndShowDetails}
                  >
                    Verify & Continue
                  </button>
                </div>
              </div>
            ) : (
              <div className="card-details-content">
                <p className="muted">
                  Verified session. Full card information is shown below.
                </p>
                <div className="card-details-grid">
                  <div className="card-details-item">
                    <span>Card Holder</span>
                    <strong>{cardProfile.holder}</strong>
                  </div>
                  <div className="card-details-item">
                    <span>Card Type</span>
                    <strong>{cardProfile.type}</strong>
                  </div>
                  <div className="card-details-item span-2">
                    <span>Card Number</span>
                    <strong>{cardProfile.number}</strong>
                  </div>
                  <div className="card-details-item">
                    <span>Expiry Date</span>
                    <strong>{cardProfile.expiry}</strong>
                  </div>
                  <div className="card-details-item">
                    <span>CVV</span>
                    <strong>{cardProfile.cvv}</strong>
                  </div>
                  <div className="card-details-item">
                    <span>Status</span>
                    <strong>{cardProfile.status}</strong>
                  </div>
                  <div className="card-details-item">
                    <span>Issued At</span>
                    <strong>{cardProfile.issuedAt}</strong>
                  </div>
                  <div className="card-details-item">
                    <span>Linked Account</span>
                    <strong>
                      {wallet?.accountNumber
                        ? `Wallet ${wallet.accountNumber}`
                        : cardProfile.linkedAccount}
                    </strong>
                  </div>
                  <div className="card-details-item">
                    <span>Daily Limit</span>
                    <strong>{cardProfile.dailyLimit}</strong>
                  </div>
                  <div className="card-details-item">
                    <span>Contactless</span>
                    <strong>{cardProfile.contactless}</strong>
                  </div>
                  <div className="card-details-item">
                    <span>Online Payment</span>
                    <strong>{cardProfile.onlinePayment}</strong>
                  </div>
                  <div className="card-details-item span-2">
                    <span>Last Activity</span>
                    <strong>{cardProfile.lastActivity}</strong>
                  </div>
                  <div className="card-details-item span-2">
                    <span>Transfer QR (fixed by account)</span>
                    {wallet?.qrImageUrl ? (
                      <img
                        src={wallet.qrImageUrl}
                        alt={`QR ${wallet.accountNumber ?? "account"}`}
                        style={{
                          width: 132,
                          height: 132,
                          borderRadius: 10,
                          border: "1px solid rgba(255,255,255,0.18)",
                        }}
                      />
                    ) : (
                      <strong>No QR yet</strong>
                    )}
                    {wallet?.qrPayload && (
                      <small className="muted" style={{ marginTop: 6 }}>
                        {wallet.qrPayload}
                      </small>
                    )}
                  </div>
                </div>
                <div className="card-details-actions">
                  <button
                    type="button"
                    className="btn-primary"
                    onClick={closeDetailsModal}
                  >
                    Done
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {transferOpen && (
        <div className="modal-overlay transfer-modal-overlay">
          <div className="transfer-modal-frame">
            <div
              className="modal-card transfer-modal"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="transfer-head">
                <h3>FPIPay Transfer</h3>
                <button
                  type="button"
                  className="card-details-close"
                  onClick={closeTransferModal}
                >
                  x
                </button>
              </div>
              <div className="transfer-steps" aria-label="Transfer progress">
                {["Recipient", "Amount", "OTP", "Done"].map((label, index) => {
                  const stepNumber = index + 1;
                  const state =
                    transferStep > stepNumber
                      ? "done"
                      : transferStep === stepNumber
                        ? "current"
                        : "upcoming";
                  return (
                    <div
                      key={label}
                      className={`transfer-step transfer-step-${state}`}
                    >
                      <span className="transfer-step-dot">{stepNumber}</span>
                      <span className="transfer-step-label">{label}</span>
                    </div>
                  );
                })}
              </div>

              <div
                key={`transfer-step-${transferStep}`}
                className={`transfer-stage transfer-stage-${transferStepDirection}`}
              >
                {transferStep === 1 && (
                  <div className="transfer-body">
                    <div className="transfer-method-tabs">
                      <button
                        type="button"
                        className={transferMethod === "account" ? "active" : ""}
                        onClick={() => {
                          setTransferMethod("account");
                          stopTransferQrCameraScan(true);
                        }}
                      >
                        Account Number
                      </button>
                      <button
                        type="button"
                        className={transferMethod === "qr" ? "active" : ""}
                        onClick={() => setTransferMethod("qr")}
                      >
                        Scan QR
                      </button>
                    </div>

                    {transferMethod === "account" ? (
                      <label className="form-group">
                        <span>Recipient Account Number</span>
                        <input
                          type="text"
                          inputMode="numeric"
                          placeholder="Enter bank account number"
                          value={transferAccount}
                          onChange={(e) => {
                            void dismissTransferAdvisory();
                            setTransferAccount(
                              e.target.value.replace(/\D/g, "").slice(0, 19),
                            );
                            setTransferMonitoring(null);
                            setTransferAdvisory(null);
                            setTransferAdvisoryAcknowledged(false);
                          }}
                        />
                      </label>
                    ) : (
                      <div className="transfer-qr-zone">
                        <div className="transfer-qr-actions">
                          <label className="transfer-qr-upload">
                            <input
                              type="file"
                              accept="image/*"
                              onChange={(e) => {
                                const file = e.target.files?.[0];
                                if (!file) return;
                                setTransferQrFile(file.name);
                                void detectQrFromImageFile(file);
                                e.currentTarget.value = "";
                              }}
                            />
                            <span>Upload transfer QR image</span>
                          </label>
                          {!transferQrCameraOn ? (
                            <button
                              type="button"
                              className="pill"
                              onClick={() => {
                                setTransferShowMyQr(false);
                                void startTransferQrCameraScan();
                              }}
                            >
                              Scan QR by camera
                            </button>
                          ) : (
                            <>
                              <button
                                type="button"
                                className="pill"
                                onClick={() => stopTransferQrCameraScan()}
                              >
                                Stop camera
                              </button>
                              <button
                                type="button"
                                className="pill"
                                onClick={() => {
                                  const nextMode =
                                    transferQrFacingMode === "environment"
                                      ? "user"
                                      : "environment";
                                  setTransferQrFacingMode(nextMode);
                                  void startTransferQrCameraScan(nextMode);
                                }}
                              >
                                Switch camera
                              </button>
                            </>
                          )}
                          <button
                            type="button"
                            className="pill"
                            onClick={() =>
                              setTransferShowMyQr((v) => {
                                const next = !v;
                                if (next) {
                                  stopTransferQrCameraScan(true);
                                }
                                return next;
                              })
                            }
                          >
                            {transferShowMyQr ? "Hide my QR" : "Show my QR"}
                          </button>
                        </div>
                        <div className="muted">
                          {transferQrFile
                            ? `QR file: ${transferQrFile}`
                            : "No QR file selected yet."}
                        </div>
                        {transferQrCameraError && (
                          <small className="transfer-input-error">
                            {transferQrCameraError}
                          </small>
                        )}
                        {transferQrCameraPanelOpen && (
                          <>
                            <div className="transfer-qr-device-row">
                              <label className="transfer-qr-device-label">
                                Camera
                                <select
                                  value={transferQrDeviceId}
                                  onChange={(e) =>
                                    setTransferQrDeviceId(e.target.value)
                                  }
                                  disabled={transferQrDevices.length === 0}
                                >
                                  {transferQrDevices.length === 0 ? (
                                    <option value="">No camera found</option>
                                  ) : (
                                    transferQrDevices.map((cam, idx) => (
                                      <option
                                        key={cam.deviceId || String(idx)}
                                        value={cam.deviceId}
                                      >
                                        {cam.label || `Camera ${idx + 1}`}
                                      </option>
                                    ))
                                  )}
                                </select>
                              </label>
                              <button
                                type="button"
                                className="pill"
                                onClick={() => void loadTransferQrDevices()}
                              >
                                Reload cameras
                              </button>
                            </div>
                            <div
                              className={`transfer-qr-camera ${transferQrCameraOn ? "active" : ""}`}
                            >
                              <div className="transfer-qr-preview">
                                <video
                                  ref={transferQrVideoRef}
                                  className="transfer-qr-video"
                                  autoPlay
                                  playsInline
                                  muted
                                />
                                <div
                                  className="transfer-qr-target"
                                  aria-hidden="true"
                                />
                              </div>
                              <small className="muted">
                                {transferQrCameraOn
                                  ? `Place the QR inside the square frame to auto-detect. Current camera: ${
                                      transferQrFacingMode === "environment"
                                        ? "Back"
                                        : "Front"
                                    }.`
                                  : "Camera preview will appear here after you start scanning."}
                              </small>
                            </div>
                          </>
                        )}
                        {transferShowMyQr && (
                          <div className="transfer-my-qr-card">
                            <span>My account QR</span>
                            {ownQrImageUrl ? (
                              <img
                                src={ownQrImageUrl}
                                alt={`My QR ${wallet?.accountNumber ?? ""}`}
                                className="transfer-my-qr-image"
                              />
                            ) : (
                              <small className="muted">
                                Wallet QR is not available yet.
                              </small>
                            )}
                            {wallet?.accountNumber && (
                              <strong>Account: {wallet.accountNumber}</strong>
                            )}
                            {ownQrImageUrl && (
                              <button
                                type="button"
                                className="btn-primary transfer-my-qr-download"
                                onClick={handleDownloadOwnQr}
                                disabled={transferQrDownloadBusy}
                              >
                                {transferQrDownloadBusy
                                  ? "Downloading..."
                                  : "Download QR"}
                              </button>
                            )}
                            {ownQrPayload && (
                              <small className="muted transfer-my-qr-payload">
                                {ownQrPayload}
                              </small>
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    <div className="transfer-actions">
                      <button
                        type="button"
                        className="btn-primary"
                        onClick={continueTransferRecipient}
                      >
                        Continue
                      </button>
                    </div>
                  </div>
                )}

                {transferStep === 2 && (
                  <div className="transfer-body">
                    <div className="transfer-summary">
                      <span>To Account</span>
                      <strong>{transferAccount}</strong>
                      <small>{transferReceiverName}</small>
                    </div>
                    <label className="form-group transfer-amount-field">
                      <span>Amount (USD)</span>
                      <input
                        type="text"
                        inputMode="decimal"
                        placeholder="Enter transfer amount"
                        value={transferAmount}
                        onChange={(e) => {
                          void dismissTransferAdvisory();
                          setTransferAmount(
                            e.target.value.replace(/[^0-9.]/g, ""),
                          );
                          setTransferFaceProof(null);
                          setTransferFaceResetKey((value) => value + 1);
                          setTransferMonitoring(null);
                          setTransferAdvisory(null);
                          setTransferAdvisoryAcknowledged(false);
                        }}
                      />
                      {isInsufficientBalance && (
                        <small className="transfer-input-error">
                          Insufficient balance
                        </small>
                      )}
                      {exceedsRestrictedTransferLimit &&
                        restrictedTransferLimit !== null && (
                          <small className="transfer-input-error">
                            This sign-in can only transfer up to $
                            {restrictedTransferLimit.toLocaleString("en-US")}.
                          </small>
                        )}
                      {isTransferFaceIdRequired && !transferFaceIdEnabled && (
                        <small className="transfer-input-error">
                          Transfers above $
                          {TRANSFER_FACE_ID_THRESHOLD.toLocaleString("en-US")}{" "}
                          require FaceID enrollment on this account.
                        </small>
                      )}
                    </label>
                    <label className="form-group">
                      <span>Transfer Content</span>
                      <input
                        type="text"
                        value={transferContent}
                        onChange={(e) => {
                          void dismissTransferAdvisory();
                          setTransferContent(e.target.value);
                          setTransferMonitoring(null);
                          setTransferAdvisory(null);
                          setTransferAdvisoryAcknowledged(false);
                        }}
                      />
                    </label>
                    <div className="transfer-actions">
                      <button
                        type="button"
                        className="pill"
                        onClick={() => {
                          void dismissTransferAdvisory();
                          goToTransferStep(1);
                          setTransferMonitoring(null);
                          setTransferAdvisory(null);
                          setTransferAdvisoryAcknowledged(false);
                        }}
                      >
                        Back
                      </button>
                      <button
                        type="button"
                        className="btn-primary"
                        onClick={continueTransferAmount}
                        disabled={
                          !canContinueTransferAmount ||
                          transferOtpBusy ||
                          isTransferHardBlocked
                        }
                      >
                        {transferContinueLabel}
                      </button>
                    </div>
                  </div>
                )}

                {transferStep === 3 && (
                  <div className="transfer-body">
                    <div className="transfer-confirm-card">
                      <div>
                        <span>Recipient</span>
                        <strong>{transferAccount}</strong>
                      </div>
                      <div>
                        <span>Amount</span>
                        <strong>${transferAmount}</strong>
                      </div>
                      <div>
                        <span>Content</span>
                        <strong>
                          {transferContent || defaultTransferContent}
                        </strong>
                      </div>
                    </div>
                    {transferOtpDestination && (
                      <div className="transfer-summary">
                        <span>OTP delivery</span>
                        <strong>{transferOtpDestination}</strong>
                        <small>
                          {transferOtpExpiresAt
                            ? `Expires at ${new Date(
                                transferOtpExpiresAt,
                              ).toLocaleTimeString("en-US", {
                                hour: "2-digit",
                                minute: "2-digit",
                              })}`
                            : "Check your inbox for the 6-digit code."}
                        </small>
                      </div>
                    )}
                    <label className="form-group">
                      <span>Enter OTP</span>
                      <input
                        type="text"
                        inputMode="numeric"
                        maxLength={6}
                        disabled={transferOtpVerifyBusy}
                        value={transferOtpInput}
                        onChange={(e) =>
                          setTransferOtpInput(
                            e.target.value.replace(/\D/g, "").slice(0, 6),
                          )
                        }
                        placeholder="6-digit OTP"
                      />
                    </label>
                    {transferOtpError && (
                      <div className="card-otp-error">{transferOtpError}</div>
                    )}
                    <div className="transfer-actions">
                      <button
                        type="button"
                        className="pill"
                        disabled={
                          transferOtpCooldownSeconds > 0 ||
                          transferOtpBusy ||
                          transferOtpVerifyBusy
                        }
                        onClick={() =>
                          void generateTransferOtp({
                            advisoryAcknowledged: Boolean(transferAdvisory),
                          })
                        }
                      >
                        {transferOtpBusy
                          ? "Sending..."
                          : transferOtpCooldownSeconds > 0
                            ? `Resend in ${transferOtpCooldownSeconds}s`
                            : "Resend OTP"}
                      </button>
                      <button
                        type="button"
                        className="btn-primary"
                        onClick={verifyTransferOtpAndSubmit}
                        disabled={transferOtpBusy || transferOtpVerifyBusy}
                      >
                        {transferOtpVerifyBusy
                          ? "Verifying OTP..."
                          : "Confirm Transfer"}
                      </button>
                    </div>
                  </div>
                )}

                {transferStep === 4 && (
                  <div className="transfer-body transfer-success">
                    <div className="transfer-success-icon">OK</div>
                    <h4>Transfer Successful</h4>
                    {transferReceipt && (
                      <TransactionReceiptCard receipt={transferReceipt} />
                    )}
                    <div className="transfer-actions">
                      <button
                        type="button"
                        className="btn-primary"
                        onClick={closeTransferModal}
                      >
                        Finish
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
            {transferStep === 2 &&
              (deferredTransferAdvisory || deferredTransferMonitoring) &&
              renderTransferAmountAiPanel(
                deferredTransferAdvisory,
                deferredTransferMonitoring,
                {
                  external: true,
                },
              )}
          </div>
        </div>
      )}

      {transferFaceVerifyOpen && typeof document !== "undefined"
        ? createPortal(
            <div
              className="faceid-modal-overlay transfer-faceid-overlay"
              onClick={closeTransferFaceVerification}
            >
              <div
                className="faceid-modal transfer-faceid-modal"
                onClick={(event) => event.stopPropagation()}
              >
                <div className="faceid-modal-head">
                  <div>
                    <h3>Transfer FaceID Verification</h3>
                    <p>
                      {transferServerFaceIdReason ||
                        `OTP is ready. Complete FaceID now to approve this transfer above $${TRANSFER_FACE_ID_THRESHOLD.toLocaleString(
                          "en-US",
                        )}.`}
                    </p>
                  </div>
                  <button
                    type="button"
                    className="faceid-modal-close"
                    onClick={closeTransferFaceVerification}
                  >
                    x
                  </button>
                </div>

                <div className="transfer-faceid-summary-card">
                  <small className="transfer-faceid-summary-copy">
                    {transferServerFaceIdReason
                      ? `OTP was verified. ${transferServerFaceIdReason}`
                      : `OTP was entered successfully. FaceID is required to release this transfer above $${TRANSFER_FACE_ID_THRESHOLD.toLocaleString(
                          "en-US",
                        )}.`}
                  </small>
                  <div className="transfer-faceid-summary-grid">
                    <div>
                      <span>Recipient</span>
                      <strong>{transferAccount}</strong>
                    </div>
                    <div>
                      <span>Amount</span>
                      <strong>${transferAmount}</strong>
                    </div>
                    <div>
                      <span>OTP</span>
                      <strong>{transferOtpInput || "******"}</strong>
                    </div>
                    {transferRollingOutflowAmount !== null ? (
                      <div>
                        <span>24h outgoing</span>
                        <strong>
                          $
                          {transferRollingOutflowAmount.toLocaleString(
                            "en-US",
                            {
                              minimumFractionDigits: 2,
                              maximumFractionDigits: 2,
                            },
                          )}
                        </strong>
                      </div>
                    ) : null}
                  </div>
                </div>

                <FaceIdCapture
                  apiBase={API_BASE}
                  resetKey={transferFaceResetKey}
                  disabled={transferFaceVerifyBusy}
                  mode="verify"
                  onChange={setTransferFaceProof}
                />

                {transferOtpError ? (
                  <div className="card-otp-error transfer-faceid-error">
                    {transferOtpError}
                  </div>
                ) : null}

                <div className="faceid-modal-actions transfer-faceid-actions">
                  <button
                    type="button"
                    className="pill"
                    onClick={closeTransferFaceVerification}
                    disabled={transferFaceVerifyBusy}
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    className="btn-primary"
                    disabled={!transferFaceProof || transferFaceVerifyBusy}
                    onClick={() => void handleTransferFaceConfirm()}
                  >
                    {transferFaceVerifyBusy
                      ? "Verifying Transfer..."
                      : "Verify FaceID & Transfer"}
                  </button>
                </div>
              </div>
            </div>,
            document.body,
          )
        : null}

      {selectedTransactionReceipt && (
        <div
          className="modal-overlay"
          onClick={() => setSelectedTransactionReceipt(null)}
        >
          <div
            className="modal-card transfer-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="card-details-head">
              <h3>Transaction Details</h3>
              <button
                type="button"
                className="card-details-close"
                onClick={() => setSelectedTransactionReceipt(null)}
              >
                x
              </button>
            </div>
            <div className="transfer-body transfer-success">
              <div className="transfer-success-icon">OK</div>
              <h4>Transaction Detail</h4>
              <TransactionReceiptCard receipt={selectedTransactionReceipt} />
              <div className="transfer-actions">
                <button
                  type="button"
                  className="btn-primary"
                  onClick={() => setSelectedTransactionReceipt(null)}
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {copilotOpen && (
        <div
          className="modal-overlay"
          onClick={() => {
            if (copilotBusy) return;
            setCopilotOpen(false);
          }}
        >
          <div
            className="modal-card ai-copilot-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="ai-copilot-head">
              <div className="ai-copilot-head-copy">
                <div className="ai-copilot-kicker">FPIPay Copilot</div>
                <h3>Financial Assistant</h3>
                <div className="ai-agent-copy">
                  Wallet-aware chat for spending, savings, transfers, and live
                  market context.
                </div>
              </div>
              <div className="ai-copilot-head-actions">
                <div className="ai-copilot-status">
                  <span className="ai-copilot-status-dot" />
                  {copilotBusy ? "Thinking" : "Ready"}
                </div>
              </div>
              <button
                type="button"
                className="card-details-close ai-copilot-close"
                onClick={() => setCopilotOpen(false)}
                aria-label="Close AI Copilot"
              >
                x
              </button>
            </div>

            <div className="ai-copilot-body">
              <div className="ai-copilot-thread-wrap">
                <div className="ai-copilot-thread" ref={copilotThreadRef}>
                  {copilotMessages.map((message, index) => (
                    <div
                      key={`${message.role}-${index}-${message.content.slice(0, 24)}`}
                      className={`ai-copilot-message-row ai-copilot-message-row-${message.role}`}
                    >
                      {message.role === "assistant" ? (
                        <div className="ai-copilot-avatar">AI</div>
                      ) : null}
                      <div
                        className={`ai-copilot-message-card ai-copilot-message-card-${message.role}`}
                      >
                        <span className="ai-copilot-message-label">
                          {message.role === "assistant"
                            ? "FPIPay Copilot"
                            : "You"}
                        </span>
                        {renderCopilotMessageContent(message.content)}
                      </div>
                    </div>
                  ))}
                  {copilotBusy && (
                    <div className="ai-copilot-message-row ai-copilot-message-row-assistant">
                      <div className="ai-copilot-avatar">AI</div>
                      <div className="ai-copilot-message-card ai-copilot-message-card-assistant ai-copilot-bubble-thinking">
                        <span className="ai-copilot-message-label">
                          FPIPay Copilot
                        </span>
                        <div className="ai-copilot-typing" aria-hidden="true">
                          <span />
                          <span />
                          <span />
                        </div>
                        <p>Thinking...</p>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {copilotHasInsight ? (
                <div className="ai-copilot-insight ai-copilot-insight-live">
                  <div className="ai-copilot-insight-head">
                    <div>
                      <strong>
                        {copilotInsight.topic || "Wallet guidance"}
                      </strong>
                    </div>
                    <div className="ai-copilot-insight-metrics">
                      <span
                        className={`ai-copilot-risk-pill ${copilotRiskTone}`}
                      >
                        {copilotInsight.riskLevel} risk
                      </span>
                      <span>
                        {Math.round(copilotInsight.confidence * 100)}%
                        confidence
                      </span>
                    </div>
                    <span>
                      Risk {copilotInsight.riskLevel} /{" "}
                      {Math.round(copilotInsight.confidence * 100)}% confidence
                    </span>
                  </div>
                  {copilotInsight.suggestedDepositAmount ? (
                    <div className="ai-copilot-deposit-tip">
                      Suggested deposit: $
                      {copilotInsight.suggestedDepositAmount.toLocaleString(
                        "en-US",
                      )}
                    </div>
                  ) : null}
                  {copilotInsight.followUpQuestion ? (
                    <p className="ai-copilot-followup">
                      {copilotInsight.followUpQuestion}
                    </p>
                  ) : null}
                  <div className="ai-copilot-actions">
                    {copilotInsight.suggestedActions.map((action) => (
                      <p key={action}>{action}</p>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="ai-copilot-insight ai-copilot-insight-empty">
                  <strong>Ask anything about your money</strong>
                  <p>
                    Try live quotes, spending review, cash-flow analysis, or a
                    transfer safety check.
                  </p>
                </div>
              )}

              <div className="ai-copilot-prompt-block">
                <div className="ai-copilot-prompts">
                  {copilotSuggestedPrompts.map((prompt) => (
                    <button
                      key={prompt}
                      type="button"
                      className="pill ai-copilot-prompt"
                      disabled={copilotBusy}
                      onClick={() => void sendCopilotMessage(prompt)}
                    >
                      {prompt}
                    </button>
                  ))}
                </div>
              </div>

              <div className="ai-copilot-compose">
                <textarea
                  value={copilotInput}
                  onChange={(e) => setCopilotInput(e.target.value)}
                  placeholder="Message FPIPay Copilot..."
                  rows={3}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && !e.shiftKey) {
                      e.preventDefault();
                      void sendCopilotMessage();
                    }
                  }}
                />
                <div className="ai-copilot-compose-hint">
                  Enter to send. Shift+Enter for a new line.
                </div>
                <div className="ai-copilot-compose-actions">
                  <button
                    type="button"
                    className="btn-primary ai-copilot-primary"
                    disabled={copilotBusy || !copilotInput.trim()}
                    onClick={() => void sendCopilotMessage()}
                  >
                    {copilotBusy ? "Thinking..." : "Send Message"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

function TransactionReceiptCard({ receipt }: { receipt: TransactionReceipt }) {
  return (
    <div className="transfer-receipt">
      <div className="transfer-receipt-row">
        <span>Transaction ID</span>
        <strong>{receipt.txId}</strong>
      </div>
      <div className="transfer-receipt-row">
        <span>Execution Time</span>
        <strong>{receipt.executedAt}</strong>
      </div>
      <div className="transfer-receipt-row">
        <span>From Account</span>
        <strong>{receipt.fromAccount}</strong>
      </div>
      <div className="transfer-receipt-row">
        <span>To Account</span>
        <strong>{receipt.toAccount}</strong>
      </div>
      <div className="transfer-receipt-row">
        <span>Amount</span>
        <strong>${receipt.amountUsd}</strong>
      </div>
      <div className="transfer-receipt-row">
        <span>Transfer Fee</span>
        <strong>${receipt.feeUsd}</strong>
      </div>
      <div className="transfer-receipt-row">
        <span>Content</span>
        <strong>{receipt.note}</strong>
      </div>
      <div className="transfer-receipt-row">
        <span>Status</span>
        <strong className="transfer-receipt-status">{receipt.status}</strong>
      </div>
    </div>
  );
}

const initialCardList = [
  {
    id: 1,
    type: "Mastercard",
    status: "Primary",
    bank: "DBL Bank",
    number: "3778 4545 9685****",
    holder: "William",
    img: 1,
  },
  {
    id: 2,
    type: "Skrill",
    status: "",
    bank: "Skrill Inc.",
    number: "3778 4545 9685****",
    holder: "William",
    img: 2,
  },
];
const recentTransfers = [
  {
    name: "Randi Press",
    date: "February 20, 2021",
    amount: "-$490",
    positive: false,
    img: 1,
  },
  {
    name: "David Bekam",
    date: "February 19, 2021",
    amount: "+$250",
    positive: true,
    img: 2,
  },
  {
    name: "Spotify",
    date: "February 19, 2021",
    amount: "-$15",
    positive: false,
    img: 3,
  },
];

function LegacyCardCenterView() {
  const { user } = useAuth();
  const { toast } = useToast();
  const [cardList, setCardList] = useState(initialCardList);
  const [addCardOpen, setAddCardOpen] = useState(false);
  const [newCard, setNewCard] = useState({
    type: "Mastercard",
    bank: "",
    number: "",
    holder: user?.name ?? "John Doe",
  });
  const [method, setMethod] = useState<"Payoneer" | "Mastercard" | "Visa">(
    "Payoneer",
  );
  const [period, setPeriod] = useState<"Monthly" | "Weekly">("Monthly");

  const spendData: Record<
    typeof method,
    { label: string; monthly: number[]; weekly: number[] }
  > = {
    Payoneer: {
      label: "Payoneer",
      monthly: [40, 52, 35, 60, 55, 70, 45, 80],
      weekly: [10, 18, 12, 20, 25, 22, 28],
    },
    Mastercard: {
      label: "Mastercard",
      monthly: [55, 60, 48, 72, 66, 78, 50, 85],
      weekly: [14, 15, 18, 22, 24, 28, 30],
    },
    Visa: {
      label: "Visa",
      monthly: [30, 36, 28, 40, 44, 52, 35, 60],
      weekly: [8, 12, 14, 15, 16, 18, 20],
    },
  };

  const activeSeries =
    period === "Monthly" ? spendData[method].monthly : spendData[method].weekly;

  const addCard = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newCard.number.trim() || !newCard.bank.trim()) {
      toast("Please fill card number and bank", "error");
      return;
    }
    const digits = newCard.number.replace(/\D/g, "").slice(-4);
    const masked =
      "**** **** **** " +
      (digits.length >= 4 ? digits : digits.padStart(4, "*"));
    setCardList((p) => [
      ...p,
      {
        id: Date.now(),
        type: newCard.type,
        status: p.length === 0 ? "Primary" : "",
        bank: newCard.bank,
        number: masked,
        holder: newCard.holder,
        img: (p.length % 10) + 1,
      },
    ]);
    setNewCard({
      type: "Mastercard",
      bank: "",
      number: "",
      holder: user?.name ?? "John Doe",
    });
    setAddCardOpen(false);
    toast("Card added successfully");
  };

  return (
    <section className="grid grid-card-center">
      <div className="card my-cards-card">
        <div className="card-head">
          <h3>My Cards</h3>
          <button
            type="button"
            className="link-add"
            onClick={() => setAddCardOpen(true)}
          >
            Add Card
          </button>
        </div>
        <div className="my-cards-stack">
          {cardList.slice(0, 2).map((c) => (
            <div key={c.id} className="card-visual mini">
              <div className="card-chip" />
              <div className="card-number">{c.number}</div>
              <div className="card-name">{c.holder}</div>
              <div className="card-valid">12/23</div>
              <div className="card-brand">
                {c.type} / {c.bank}
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="card current-balance-card">
        <h3>Current Balance</h3>
        <div className="balance-value">$340,500</div>
        <div className="mini-bars">
          {[40, 65, 45, 80, 55, 70, 50, 90].map((h, i) => (
            <div key={i} className="mini-bar" style={{ height: `${h}%` }} />
          ))}
        </div>
      </div>
      <div className="card payment-method-card">
        <h3>Payment Method</h3>
        <div className="method-tabs">
          <button
            type="button"
            className={`method-tab ${method === "Payoneer" ? "active" : ""}`}
            onClick={() => setMethod("Payoneer")}
          >
            Payoneer
          </button>
          <button
            type="button"
            className={`method-tab ${method === "Mastercard" ? "active" : ""}`}
            onClick={() => setMethod("Mastercard")}
          >
            Mastercard
          </button>
          <button
            type="button"
            className={`method-tab ${method === "Visa" ? "active" : ""}`}
            onClick={() => setMethod("Visa")}
          >
            Visa
          </button>
        </div>
        <div className="period-tabs">
          <button
            type="button"
            className={`period-tab ${period === "Monthly" ? "active" : ""}`}
            onClick={() => setPeriod("Monthly")}
          >
            Monthly
          </button>
          <button
            type="button"
            className={`period-tab ${period === "Weekly" ? "active" : ""}`}
            onClick={() => setPeriod("Weekly")}
          >
            Weekly
          </button>
        </div>
        <div
          className="chart-bars"
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(10px, 1fr))",
            gap: 8,
            alignItems: "end",
            height: 160,
          }}
        >
          {activeSeries.map((v, idx) => (
            <div
              key={idx}
              className="chart-bar"
              style={{
                width: "100%",
                background: "#eef2ff",
                borderRadius: 10,
                height: 100,
                position: "relative",
                overflow: "hidden",
              }}
            >
              <div
                className="chart-bar-fill"
                style={{
                  height: `${v}%`,
                  width: "100%",
                  position: "absolute",
                  bottom: 0,
                  left: 0,
                  background:
                    method === "Payoneer"
                      ? "var(--accent)"
                      : method === "Mastercard"
                        ? "var(--accent-2)"
                        : "#1a3a5c",
                  borderRadius: 10,
                }}
                title={`${v}%`}
              />
            </div>
          ))}
        </div>
        <div className="payment-summary">
          <span>{spendData[method].label}</span>
          <strong>
            Avg {period}:{" "}
            {Math.round(
              activeSeries.reduce((a, b) => a + b, 0) / activeSeries.length,
            )}
            %
          </strong>
        </div>
      </div>
      <div className="card card-expenses-card">
        <h3>Card Expenses</h3>
        <DonutChart
          percent={45}
          segments={[
            { label: "Mastercard 30%", color: "var(--accent)" },
            { label: "Payoneer 25%", color: "var(--accent-2)" },
            { label: "Visa 45%", color: "#1a3a5c" },
          ]}
        />
      </div>
      <div className="card card-list-card span-2">
        <h3>Card List</h3>
        <div className="transactions-table-wrap">
          <table className="transactions-table">
            <thead>
              <tr>
                <th>Card Type</th>
                <th>Status</th>
                <th>Bank</th>
                <th>Card Number</th>
                <th>Card Holder</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {cardList.map((c) => (
                <tr key={c.id}>
                  <td>{c.type}</td>
                  <td>
                    {c.status ? (
                      <span className="status-badge status-completed">
                        {c.status}
                      </span>
                    ) : (
                      ""
                    )}
                  </td>
                  <td className="muted">{c.bank}</td>
                  <td>{c.number}</td>
                  <td>{c.holder}</td>
                  <td>
                    <span className="tx-dots">...</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {addCardOpen && (
        <div className="modal-overlay" onClick={() => setAddCardOpen(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <h3>Add Card</h3>
            <form onSubmit={addCard}>
              <div className="form-group">
                <label>Card Type</label>
                <select
                  value={newCard.type}
                  onChange={(e) =>
                    setNewCard((p) => ({ ...p, type: e.target.value }))
                  }
                >
                  <option value="Mastercard">Mastercard</option>
                  <option value="Visa">Visa</option>
                  <option value="Skrill">Skrill</option>
                </select>
              </div>
              <div className="form-group">
                <label>Bank</label>
                <input
                  type="text"
                  value={newCard.bank}
                  onChange={(e) =>
                    setNewCard((p) => ({ ...p, bank: e.target.value }))
                  }
                  placeholder="Bank name"
                  required
                />
              </div>
              <div className="form-group">
                <label>Card Number</label>
                <input
                  type="text"
                  value={newCard.number}
                  onChange={(e) =>
                    setNewCard((p) => ({ ...p, number: e.target.value }))
                  }
                  placeholder="1234 5678 9012 3456"
                  required
                />
              </div>
              <div className="form-group">
                <label>Card Holder</label>
                <input
                  type="text"
                  value={newCard.holder}
                  onChange={(e) =>
                    setNewCard((p) => ({ ...p, holder: e.target.value }))
                  }
                />
              </div>
              <div className="modal-actions">
                <button
                  type="button"
                  className="pill"
                  onClick={() => setAddCardOpen(false)}
                >
                  Cancel
                </button>
                <button type="submit" className="btn-primary">
                  Add Card
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
      <div className="card recent-transfer-card">
        <h3>Recent Transfer</h3>
        <div className="recent-transfer-list">
          {recentTransfers.map((t, i) => (
            <div key={i} className="recent-transfer-row">
              <img
                src={`https://i.pravatar.cc/40?img=${t.img}`}
                alt=""
                className="tx-recipient-avatar"
              />
              <div className="recent-transfer-info">
                <span>{t.name}</span>
                <span className="muted">{t.date}</span>
              </div>
              <span
                className={`recent-transfer-amount ${t.positive ? "positive" : "negative"}`}
              >
                {t.amount}
              </span>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

type CardCenterCard = {
  id: string;
  type: "Mastercard" | "Visa" | "Payoneer" | "Skrill";
  bank: string;
  holder: string;
  number: string;
  last4: string;
  expiryMonth: string;
  expiryYear: string;
  status: "ACTIVE" | "FROZEN";
  isPrimary: boolean;
  createdAt: string;
  updatedAt: string;
};

type CardCenterActivity = {
  id: string;
  title: string;
  date: string;
  amountLabel: string;
  amountValue: number;
  positive: boolean;
};

const CARD_CENTER_TYPES: CardCenterCard["type"][] = [
  "Mastercard",
  "Visa",
  "Payoneer",
  "Skrill",
];

function CardCenterView() {
  const { user, token } = useAuth();
  const { toast } = useToast();
  const [cardList, setCardList] = useState<CardCenterCard[]>([]);
  const [walletBalance, setWalletBalance] = useState(0);
  const [walletCurrency, setWalletCurrency] = useState("USD");
  const [recentCardActivity, setRecentCardActivity] = useState<
    CardCenterActivity[]
  >([]);
  const [cardsBusy, setCardsBusy] = useState(false);
  const [cardActionBusyId, setCardActionBusyId] = useState("");
  const [addCardOpen, setAddCardOpen] = useState(false);
  const [newCard, setNewCard] = useState({
    type: "Mastercard" as CardCenterCard["type"],
    bank: "",
    number: "",
    expiryMonth: "",
    expiryYear: "",
    holder: user?.name ?? "FPIPay User",
  });
  const [method, setMethod] = useState<CardCenterCard["type"]>("Mastercard");

  const loadCardCenter = useCallback(async () => {
    if (!token) {
      setCardList([]);
      setWalletBalance(0);
      setRecentCardActivity([]);
      return;
    }

    setCardsBusy(true);
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const [cardsResp, walletResp, txResp] = await Promise.all([
        fetch(`${API_BASE}/cards`, { headers }),
        fetch(`${API_BASE}/wallet/me`, { headers }),
        fetch(`${API_BASE}/transactions`, { headers }),
      ]);

      const cardsData = (await cardsResp.json().catch(() => null)) as {
        cards?: CardCenterCard[];
        error?: string;
      } | null;
      const walletData = (await walletResp.json().catch(() => null)) as {
        balance?: number;
        currency?: string;
        error?: string;
      } | null;
      const txData = (await txResp.json().catch(() => null)) as
        | Array<{
            id: string;
            amount: number;
            type: string;
            description?: string;
            createdAt: string;
            metadata?: { entry?: "DEBIT" | "CREDIT" };
          }>
        | { error?: string }
        | null;

      if (!cardsResp.ok || !Array.isArray(cardsData?.cards)) {
        throw new Error(cardsData?.error || "Cannot load cards");
      }
      if (!walletResp.ok) {
        throw new Error(walletData?.error || "Cannot load wallet balance");
      }
      if (!txResp.ok || !Array.isArray(txData)) {
        throw new Error(
          txData && !Array.isArray(txData)
            ? txData.error || "Cannot load activity"
            : "Cannot load activity",
        );
      }

      setCardList(cardsData.cards);
      setWalletBalance(Number(walletData?.balance || 0));
      setWalletCurrency(walletData?.currency || "USD");
      setRecentCardActivity(
        txData.slice(0, 6).map((tx) => {
          const positive =
            tx.type === "DEPOSIT" || tx.metadata?.entry === "CREDIT";
          const amountValue = Math.abs(Number(tx.amount || 0));
          return {
            id: tx.id,
            title: tx.description || tx.type,
            date: new Date(tx.createdAt).toLocaleString("en-US", {
              month: "short",
              day: "2-digit",
              year: "numeric",
            }),
            amountLabel: `${positive ? "+" : "-"}$${amountValue.toLocaleString(
              "en-US",
              {
                minimumFractionDigits: 2,
                maximumFractionDigits: 2,
              },
            )}`,
            amountValue,
            positive,
          };
        }),
      );
    } catch (err) {
      toast(err instanceof Error ? err.message : "Cannot load cards", "error");
    } finally {
      setCardsBusy(false);
    }
  }, [toast, token]);

  useEffect(() => {
    void loadCardCenter();
  }, [loadCardCenter]);

  useEffect(() => {
    setNewCard((prev) => ({
      ...prev,
      holder: user?.name ?? prev.holder ?? "FPIPay User",
    }));
  }, [user?.name]);

  const cardsByType = CARD_CENTER_TYPES.map((type) => ({
    type,
    cards: cardList.filter((card) => card.type === type),
  }));
  const selectedTypeCards =
    cardsByType.find((entry) => entry.type === method)?.cards ?? [];
  const balanceSeries = (
    recentCardActivity.length
      ? recentCardActivity.slice(0, 8).map((entry) => entry.amountValue)
      : [0, 0, 0, 0, 0, 0, 0, 0]
  ).map((value, _index, source) => {
    const max = Math.max(...source, 1);
    return Math.max(12, Math.round((value / max) * 100));
  });
  const selectedTypeShare = cardList.length
    ? Math.round((selectedTypeCards.length / cardList.length) * 100)
    : 0;
  const donutSegments = cardsByType
    .filter((entry) => entry.cards.length > 0)
    .map((entry) => ({
      label: `${entry.type} ${Math.round((entry.cards.length / Math.max(cardList.length, 1)) * 100)}%`,
      color:
        entry.type === "Mastercard"
          ? "var(--accent)"
          : entry.type === "Visa"
            ? "#1a3a5c"
            : entry.type === "Payoneer"
              ? "var(--accent-2)"
              : "#f59e0b",
    }));

  const submitNewCard = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) {
      toast("Session expired. Please login again.", "error");
      return;
    }
    if (
      !newCard.number.trim() ||
      !newCard.bank.trim() ||
      !newCard.expiryMonth.trim() ||
      !newCard.expiryYear.trim()
    ) {
      toast("Please fill all card fields", "error");
      return;
    }

    setCardsBusy(true);
    try {
      const resp = await fetch(`${API_BASE}/cards`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(newCard),
      });
      const data = (await resp.json().catch(() => null)) as {
        cards?: CardCenterCard[];
        error?: string;
      } | null;
      if (!resp.ok || !Array.isArray(data?.cards)) {
        throw new Error(data?.error || "Failed to add card");
      }

      setCardList(data.cards);
      setAddCardOpen(false);
      setNewCard({
        type: "Mastercard",
        bank: "",
        number: "",
        expiryMonth: "",
        expiryYear: "",
        holder: user?.name ?? "FPIPay User",
      });
      toast("Card added successfully");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Failed to add card", "error");
    } finally {
      setCardsBusy(false);
    }
  };

  const runCardAction = async (
    cardId: string,
    action: "set_primary" | "freeze" | "unfreeze" | "delete",
  ) => {
    if (!token) {
      toast("Session expired. Please login again.", "error");
      return;
    }

    setCardActionBusyId(cardId);
    try {
      const resp = await fetch(`${API_BASE}/cards/${cardId}`, {
        method: action === "delete" ? "DELETE" : "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: action === "delete" ? undefined : JSON.stringify({ action }),
      });

      if (action === "delete") {
        if (!resp.ok) {
          const err = (await resp.json().catch(() => null)) as {
            error?: string;
          } | null;
          throw new Error(err?.error || "Failed to delete card");
        }
        setCardList((prev) => prev.filter((card) => card.id !== cardId));
      } else {
        const data = (await resp.json().catch(() => null)) as {
          cards?: CardCenterCard[];
          error?: string;
        } | null;
        if (!resp.ok || !Array.isArray(data?.cards)) {
          throw new Error(data?.error || "Failed to update card");
        }
        setCardList(data.cards);
      }

      toast(
        action === "set_primary"
          ? "Primary card updated"
          : action === "freeze"
            ? "Card frozen"
            : action === "unfreeze"
              ? "Card reactivated"
              : "Card removed",
      );
    } catch (err) {
      toast(err instanceof Error ? err.message : "Card action failed", "error");
    } finally {
      setCardActionBusyId("");
    }
  };

  return (
    <section className="grid grid-card-center">
      <div className="card my-cards-card">
        <div className="card-head">
          <h3>My Cards</h3>
          <button
            type="button"
            className="link-add"
            onClick={() => setAddCardOpen(true)}
          >
            Add Card
          </button>
        </div>
        <div className="my-cards-stack">
          {cardList.length ? (
            cardList.slice(0, 3).map((card) => (
              <div key={card.id} className="card-visual mini">
                <div className="card-chip" />
                <div className="card-number">{card.number}</div>
                <div className="card-name">{card.holder}</div>
                <div className="card-valid">
                  {card.expiryMonth}/{card.expiryYear.slice(-2)}
                </div>
                <div className="card-brand">
                  {card.type} - {card.bank}
                </div>
                <div className="card-meta-row">
                  {card.isPrimary ? (
                    <span className="status-badge status-completed">
                      Primary
                    </span>
                  ) : null}
                  <span
                    className={`status-badge ${card.status === "FROZEN" ? "status-canceled" : "status-pending"}`}
                  >
                    {card.status === "FROZEN" ? "Frozen" : "Active"}
                  </span>
                </div>
              </div>
            ))
          ) : (
            <div className="dashboard-inline-note">
              No cards yet. Add your first card to manage it here.
            </div>
          )}
        </div>
      </div>

      <div className="card current-balance-card">
        <h3>Current Balance</h3>
        <div className="balance-value">
          {walletCurrency === "USD" ? "$" : `${walletCurrency} `}
          {walletBalance.toLocaleString("en-US", {
            minimumFractionDigits: 2,
            maximumFractionDigits: 2,
          })}
        </div>
        <div className="mini-bars">
          {balanceSeries.map((height, index) => (
            <div
              key={index}
              className="mini-bar"
              style={{ height: `${height}%` }}
            />
          ))}
        </div>
        <div className="dashboard-inline-note">
          Based on your latest wallet and transfer activity.
        </div>
      </div>

      <div className="card payment-method-card">
        <h3>Card Portfolio</h3>
        <div className="method-tabs">
          {CARD_CENTER_TYPES.map((type) => (
            <button
              key={type}
              type="button"
              className={`method-tab ${method === type ? "active" : ""}`}
              onClick={() => setMethod(type)}
            >
              {type}
            </button>
          ))}
        </div>
        <div className="card-portfolio-stats">
          <div className="card-portfolio-stat">
            <span>Total Cards</span>
            <strong>{selectedTypeCards.length}</strong>
          </div>
          <div className="card-portfolio-stat">
            <span>Active</span>
            <strong>
              {
                selectedTypeCards.filter((card) => card.status === "ACTIVE")
                  .length
              }
            </strong>
          </div>
          <div className="card-portfolio-stat">
            <span>Frozen</span>
            <strong>
              {
                selectedTypeCards.filter((card) => card.status === "FROZEN")
                  .length
              }
            </strong>
          </div>
        </div>
        <div
          className="chart-bars"
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(10px, 1fr))",
            gap: 8,
            alignItems: "end",
            height: 160,
          }}
        >
          {balanceSeries.map((value, index) => (
            <div
              key={index}
              className="chart-bar"
              style={{
                width: "100%",
                background: "#eef2ff",
                borderRadius: 10,
                height: 100,
                position: "relative",
                overflow: "hidden",
              }}
            >
              <div
                className="chart-bar-fill"
                style={{
                  height: `${value}%`,
                  width: "100%",
                  position: "absolute",
                  bottom: 0,
                  left: 0,
                  background:
                    method === "Payoneer"
                      ? "var(--accent)"
                      : method === "Mastercard"
                        ? "var(--accent-2)"
                        : method === "Visa"
                          ? "#1a3a5c"
                          : "#f59e0b",
                  borderRadius: 10,
                }}
              />
            </div>
          ))}
        </div>
        <div className="payment-summary">
          <span>{method}</span>
          <strong>Share of portfolio: {selectedTypeShare}%</strong>
        </div>
      </div>

      <div className="card card-expenses-card">
        <h3>Card Distribution</h3>
        <DonutChart
          percent={selectedTypeShare}
          segments={
            donutSegments.length
              ? donutSegments
              : [{ label: "No cards yet", color: "var(--accent)" }]
          }
        />
      </div>

      <div className="card card-list-card span-2">
        <div className="card-head">
          <h3>Card List</h3>
          <button
            type="button"
            className="pill"
            disabled={cardsBusy}
            onClick={() => void loadCardCenter()}
          >
            {cardsBusy ? "Refreshing..." : "Refresh"}
          </button>
        </div>
        <div className="transactions-table-wrap">
          <table className="transactions-table">
            <thead>
              <tr>
                <th>Card Type</th>
                <th>Status</th>
                <th>Bank</th>
                <th>Card Number</th>
                <th>Card Holder</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {cardList.length ? (
                cardList.map((card) => (
                  <tr key={card.id}>
                    <td>{card.type}</td>
                    <td>
                      {card.isPrimary ? (
                        <span className="status-badge status-completed">
                          Primary
                        </span>
                      ) : (
                        <span className="status-badge status-pending">
                          Saved
                        </span>
                      )}
                    </td>
                    <td className="muted">{card.bank}</td>
                    <td>{card.number}</td>
                    <td>{card.holder}</td>
                    <td>
                      <div className="card-actions-inline">
                        {!card.isPrimary ? (
                          <button
                            type="button"
                            className="tx-detail-btn"
                            disabled={cardActionBusyId === card.id}
                            onClick={() =>
                              void runCardAction(card.id, "set_primary")
                            }
                          >
                            Primary
                          </button>
                        ) : null}
                        <button
                          type="button"
                          className="tx-detail-btn"
                          disabled={cardActionBusyId === card.id}
                          onClick={() =>
                            void runCardAction(
                              card.id,
                              card.status === "ACTIVE" ? "freeze" : "unfreeze",
                            )
                          }
                        >
                          {card.status === "ACTIVE" ? "Freeze" : "Unfreeze"}
                        </button>
                        <button
                          type="button"
                          className="tx-detail-btn danger"
                          disabled={cardActionBusyId === card.id}
                          onClick={() => void runCardAction(card.id, "delete")}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="muted">
                    No cards saved for this account yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {addCardOpen && (
        <div className="modal-overlay" onClick={() => setAddCardOpen(false)}>
          <div
            className="modal-card card-center-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <h3>Add Card</h3>
            <form onSubmit={submitNewCard}>
              <div className="form-group">
                <label>Card Type</label>
                <select
                  value={newCard.type}
                  onChange={(e) =>
                    setNewCard((prev) => ({
                      ...prev,
                      type: e.target.value as CardCenterCard["type"],
                    }))
                  }
                >
                  {CARD_CENTER_TYPES.map((type) => (
                    <option key={type} value={type}>
                      {type}
                    </option>
                  ))}
                </select>
              </div>
              <div className="form-group">
                <label>Bank</label>
                <input
                  type="text"
                  value={newCard.bank}
                  onChange={(e) =>
                    setNewCard((prev) => ({ ...prev, bank: e.target.value }))
                  }
                  placeholder="Bank name"
                  required
                />
              </div>
              <div className="form-group">
                <label>Card Number</label>
                <input
                  type="text"
                  value={newCard.number}
                  onChange={(e) =>
                    setNewCard((prev) => ({
                      ...prev,
                      number: e.target.value
                        .replace(/[^\d\s]/g, "")
                        .slice(0, 19),
                    }))
                  }
                  placeholder="1234 5678 9012 3456"
                  required
                />
              </div>
              <div className="card-form-grid">
                <div className="form-group">
                  <label>Expiry Month</label>
                  <input
                    type="text"
                    value={newCard.expiryMonth}
                    onChange={(e) =>
                      setNewCard((prev) => ({
                        ...prev,
                        expiryMonth: e.target.value
                          .replace(/\D/g, "")
                          .slice(0, 2),
                      }))
                    }
                    placeholder="MM"
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Expiry Year</label>
                  <input
                    type="text"
                    value={newCard.expiryYear}
                    onChange={(e) =>
                      setNewCard((prev) => ({
                        ...prev,
                        expiryYear: e.target.value
                          .replace(/\D/g, "")
                          .slice(0, 4),
                      }))
                    }
                    placeholder="YYYY"
                    required
                  />
                </div>
              </div>
              <div className="form-group">
                <label>Card Holder</label>
                <input
                  type="text"
                  value={newCard.holder}
                  onChange={(e) =>
                    setNewCard((prev) => ({ ...prev, holder: e.target.value }))
                  }
                  required
                />
              </div>
              <div className="modal-actions">
                <button
                  type="button"
                  className="pill"
                  onClick={() => setAddCardOpen(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn-primary"
                  disabled={cardsBusy}
                >
                  {cardsBusy ? "Saving..." : "Add Card"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <div className="card recent-transfer-card">
        <h3>Recent Activity</h3>
        <div className="recent-transfer-list">
          {recentCardActivity.length ? (
            recentCardActivity.map((activity) => (
              <div key={activity.id} className="recent-transfer-row">
                <div className="recent-transfer-avatar">
                  {activity.title.slice(0, 1).toUpperCase()}
                </div>
                <div className="recent-transfer-info">
                  <span>{activity.title}</span>
                  <span className="muted">{activity.date}</span>
                </div>
                <span
                  className={`recent-transfer-amount ${activity.positive ? "positive" : "negative"}`}
                >
                  {activity.amountLabel}
                </span>
              </div>
            ))
          ) : (
            <div className="dashboard-inline-note">
              No recent account activity is available yet.
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function AccountsView() {
  return (
    <section className="grid grid-accounts">
      <div className="card profile-summary-card">
        <div className="profile-summary">
          <img src="https://i.pravatar.cc/80?img=12" alt="" />
          <h3>John Doe</h3>
          <p className="muted">UI/UX Designer</p>
          <p className="muted">Los Angeles, USA</p>
        </div>
        <div className="profile-stats">
          <div className="stat-circle">
            <span className="stat-label">Income</span>
            <strong>$35,450</strong>
          </div>
          <div className="stat-circle">
            <span className="stat-label">Expense</span>
            <strong>$12,800</strong>
          </div>
        </div>
        <div className="profile-mycard">
          <span className="muted">My Card</span>
          <strong>4 Cards Available</strong>
          <div className="card-visual mini">
            <div className="card-chip" />
            <div className="card-number">1234 5678 9012 3456</div>
            <div className="card-name">John Doe</div>
            <div className="card-valid">12/23</div>
            <div className="card-brand">Bank Asia</div>
          </div>
        </div>
      </div>
      <div className="card span-2">
        <div className="card-head">
          <h3>Last Transactions</h3>
          <button className="pill">All Time v</button>
        </div>
        <div className="txn-list">
          {accountsRecentTransactions.map((t, i) => (
            <div key={i} className="txn-row">
              <span className="txn-icon">CARD</span>
              <span>{t.name}</span>
              <span className="muted">{t.status}</span>
              <span className="muted">{t.date}</span>
              <span className="muted">{t.card}</span>
              <span>{t.amount}</span>
              <span className="muted">...</span>
            </div>
          ))}
        </div>
      </div>
      <div className="card quick-transfer-card">
        <h3>Quick Transfer</h3>
        <div className="form-group">
          <label>Choose Your Card</label>
          <input
            type="text"
            defaultValue="3778 4545 9685 1234"
            readOnly
            className="readonly"
          />
        </div>
        <div className="form-group">
          <label>Receiver</label>
          <input type="text" placeholder="Enter receiver card number" />
        </div>
        <div className="form-group">
          <label>Amount</label>
          <input type="text" placeholder="Choose amount" />
        </div>
      </div>
      <div className="card revenue-card">
        <div className="card-head">
          <h3>Revenue</h3>
          <span className="revenue-period">This Month $2,600</span>
        </div>
        <div className="history-tabs">
          <button type="button" className="history-tab active">
            Monthly
          </button>
          <button type="button" className="history-tab">
            Weekly
          </button>
          <button type="button" className="history-tab">
            All Time
          </button>
        </div>
        <div className="chart-placeholder chart-bars">
          <BarChart
            labels={["Jan", "Feb", "Mar", "Apr", "May", "Jun"]}
            data={[
              { debit: 20, credit: 15 },
              { debit: 35, credit: 28 },
              { debit: 25, credit: 22 },
              { debit: 40, credit: 35 },
              { debit: 30, credit: 25 },
              { debit: 45, credit: 38 },
            ]}
          />
        </div>
      </div>
    </section>
  );
}

const SETTING_PROFILE_KEY = "fpipay_profile";
const PROFILE_AVATAR_KEY = "fpipay_profile_avatar";
const SETTING_SECURITY_KEY = "fpipay_security";
type ProfileForm = {
  name: string;
  userName: string;
  email: string;
  phone: string;
  password: string;
  dateOfBirth: string;
  address: string;
};
const defaultProfile: ProfileForm = {
  name: "John Doe",
  userName: "johndoe",
  email: "johndoe@mail.com",
  phone: "",
  password: "**********",
  dateOfBirth: "25/01/1990",
  address: "San Jose, California, USA",
};

const formatDobInput = (raw: string) => {
  const digits = raw.replace(/\D/g, "").slice(0, 8);
  if (digits.length <= 2) return digits;
  if (digits.length <= 4) return `${digits.slice(0, 2)}/${digits.slice(2)}`;
  return `${digits.slice(0, 2)}/${digits.slice(2, 4)}/${digits.slice(4)}`;
};

const normalizeDobForForm = (value: string) => {
  const v = value.trim();
  if (!v) return "";
  const dmy = v.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  if (dmy) return v;
  const ymd = v.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (ymd) return `${ymd[3]}/${ymd[2]}/${ymd[1]}`;
  return formatDobInput(v);
};

type FaceIdAccountStatus = {
  enabled: boolean;
  enrolledAt: string | null;
  verifiedAt: string | null;
};

const parseFaceIdAccountStatus = (
  metadata?: Record<string, unknown> | null,
) => {
  const source = metadata && typeof metadata === "object" ? metadata : {};
  return {
    enabled: source.faceIdEnabled === true,
    enrolledAt:
      typeof source.faceIdEnrolledAt === "string"
        ? source.faceIdEnrolledAt
        : null,
    verifiedAt:
      typeof source.faceIdVerifiedAt === "string"
        ? source.faceIdVerifiedAt
        : null,
  } satisfies FaceIdAccountStatus;
};

type SettingTabId = "profile" | "preferences" | "security" | "notification";

const settingMenuItems: {
  id: SettingTabId;
  label: string;
  desc: string;
  icon: string;
  active: boolean;
}[] = [
  {
    id: "preferences",
    label: "Preferences",
    desc: "Dark and light mode, Font size.",
    icon: "PREF",
    active: false,
  },
  {
    id: "security",
    label: "Security",
    desc: "Change password, Authentication.",
    icon: "LOCK",
    active: false,
  },
  {
    id: "notification",
    label: "Notification",
    desc: "Change password, Authentication.",
    icon: "BELL",
    active: false,
  },
];

function Toggle({
  checked,
  onChange,
  id,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  id?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      id={id}
      className={`setting-toggle ${checked ? "on" : ""}`}
      onClick={() => onChange(!checked)}
    >
      <span className="setting-toggle-thumb" />
    </button>
  );
}

function SettingView() {
  const { updateUser } = useAuth();
  const { toast } = useToast();
  const { theme } = useTheme();
  const [settingTab, setSettingTab] = useState<SettingTabId>("preferences");
  const [profile, setProfile] = useState<ProfileForm>(() => {
    try {
      const s = localStorage.getItem(SETTING_PROFILE_KEY);
      return s ? { ...defaultProfile, ...JSON.parse(s) } : defaultProfile;
    } catch {
      return defaultProfile;
    }
  });
  const [prefStartPage, setPrefStartPage] = useState(false);
  const [prefContinue, setPrefContinue] = useState(false);
  const [prefSpecificPage, setPrefSpecificPage] = useState(true);
  const [prefBlockAds, setPrefBlockAds] = useState(true);
  const [notifLogin, setNotifLogin] = useState(true);
  const [notifDeposit, setNotifDeposit] = useState(false);
  const [notifWithdraw1, setNotifWithdraw1] = useState(true);
  const [notifWithdraw2, setNotifWithdraw2] = useState(true);
  const [passwordForm, setPasswordForm] = useState({
    current: "",
    next: "",
    confirm: "",
  });
  const [security, setSecurity] = useState(() => {
    try {
      const s = localStorage.getItem(SETTING_SECURITY_KEY);
      return s
        ? JSON.parse(s)
        : {
            twofa: false,
            saveLogin: true,
            devices: [
              {
                id: "mbp-16",
                name: 'MacBook Pro 16"',
                lastUsed: "2026-02-22 / San Francisco, US",
                trusted: true,
              },
              {
                id: "iphone-14",
                name: "iPhone 14 Pro",
                lastUsed: "2026-02-23 / San Francisco, US",
                trusted: true,
              },
              {
                id: "office-pc",
                name: "Windows PC",
                lastUsed: "2026-02-10 / Ho Chi Minh, VN",
                trusted: false,
              },
            ],
          };
    } catch {
      return {
        twofa: false,
        saveLogin: true,
        devices: [],
      };
    }
  });

  const persistSecurity = (next: typeof security) => {
    setSecurity(next);
    localStorage.setItem(SETTING_SECURITY_KEY, JSON.stringify(next));
  };

  const toggle2fa = (v: boolean) => {
    persistSecurity({ ...security, twofa: v });
    toast(v ? "Two-factor enabled" : "Two-factor disabled");
  };

  const toggleSaveLogin = (v: boolean) => {
    persistSecurity({ ...security, saveLogin: v });
    toast(v ? "Login info will be remembered" : "Login info will not be saved");
  };

  const toggleTrusted = (id: string) => {
    const devices = security.devices.map((d: any) =>
      d.id === id ? { ...d, trusted: !d.trusted } : d,
    );
    persistSecurity({ ...security, devices });
  };

  const removeDevice = (id: string) => {
    const devices = security.devices.filter((d: any) => d.id !== id);
    persistSecurity({ ...security, devices });
    toast("Device removed");
  };

  const changePassword = () => {
    if (!passwordForm.current || !passwordForm.next) {
      toast("Fill current and new password", "error");
      return;
    }
    if (passwordForm.next.length < 8) {
      toast("New password must be at least 8 characters", "error");
      return;
    }
    if (passwordForm.next !== passwordForm.confirm) {
      toast("Passwords do not match", "error");
      return;
    }
    setPasswordForm({ current: "", next: "", confirm: "" });
    toast("Password updated (demo)");
  };

  const saveProfile = () => {
    localStorage.setItem(SETTING_PROFILE_KEY, JSON.stringify(profile));
    updateUser({ name: profile.name, email: profile.email });
    toast("Profile saved successfully");
  };

  return (
    <section className="setting-section">
      <div className="card setting-menu-card">
        <h3 className="sr-only">Settings</h3>
        {settingMenuItems.map((item) => (
          <div
            key={item.id}
            className={`setting-menu-item ${settingTab === item.id ? "active" : ""}`}
            onClick={() => setSettingTab(item.id)}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => e.key === "Enter" && setSettingTab(item.id)}
          >
            <span className="setting-menu-icon">{item.icon}</span>
            <div>
              <strong>{item.label}</strong>
              <p className="muted">{item.desc}</p>
            </div>
          </div>
        ))}
      </div>
      <div className="card setting-detail-card">
        {settingTab === "profile" && (
          <>
            <div className="setting-profile-header">
              <div className="setting-avatar-wrap">
                <img
                  src="https://i.pravatar.cc/120?img=12"
                  alt=""
                  className="setting-avatar"
                />
                <span className="setting-avatar-edit">Edit</span>
              </div>
            </div>
            <div className="form-grid setting-form">
              <div className="form-group">
                <label>Name</label>
                <input
                  type="text"
                  value={profile.name}
                  onChange={(e) =>
                    setProfile((p) => ({ ...p, name: e.target.value }))
                  }
                />
              </div>
              <div className="form-group">
                <label>User Name</label>
                <input
                  type="text"
                  value={profile.userName}
                  onChange={(e) =>
                    setProfile((p) => ({ ...p, userName: e.target.value }))
                  }
                />
              </div>
              <div className="form-group">
                <label>Email</label>
                <input
                  type="email"
                  value={profile.email}
                  onChange={(e) =>
                    setProfile((p) => ({ ...p, email: e.target.value }))
                  }
                />
              </div>
              <div className="form-group">
                <label>Password</label>
                <input
                  type="password"
                  value={profile.password}
                  onChange={(e) =>
                    setProfile((p) => ({ ...p, password: e.target.value }))
                  }
                />
              </div>
              <div className="form-group">
                <label>Date of Birth</label>
                <input
                  type="text"
                  inputMode="numeric"
                  placeholder="dd/mm/yyyy"
                  value={profile.dateOfBirth}
                  onChange={(e) =>
                    setProfile((p) => ({
                      ...p,
                      dateOfBirth: formatDobInput(e.target.value),
                    }))
                  }
                />
              </div>
              <div className="form-group">
                <label>Permanent Address</label>
                <input
                  type="text"
                  value={profile.address}
                  onChange={(e) =>
                    setProfile((p) => ({
                      ...p,
                      address: e.target.value,
                    }))
                  }
                />
              </div>
            </div>
            <div className="setting-actions">
              <button
                type="button"
                className="btn-primary"
                onClick={saveProfile}
              >
                Save Changes
              </button>
            </div>
          </>
        )}
        {settingTab === "preferences" && (
          <>
            <h3 className="setting-panel-title">Preference Setting</h3>
            <div className="setting-block">
              <h4 className="setting-block-head">Theme</h4>
              <p className="muted">Dark mode is fixed for this project.</p>
              <div className="setting-row toggle-row">
                <span>Enable dark mode</span>
                <Toggle id="pref-theme" checked onChange={() => {}} />
              </div>
            </div>
            <div className="setting-block">
              <h4 className="setting-block-head">On Startup</h4>
              <div className="setting-row toggle-row">
                <label htmlFor="pref-start">Open the start page</label>
                <Toggle
                  id="pref-start"
                  checked={prefStartPage}
                  onChange={setPrefStartPage}
                />
              </div>
              <div className="setting-row toggle-row">
                <label htmlFor="pref-continue">Continue where I left off</label>
                <Toggle
                  id="pref-continue"
                  checked={prefContinue}
                  onChange={setPrefContinue}
                />
              </div>
              <div className="setting-row toggle-row">
                <label htmlFor="pref-specific">
                  Open a specific page or set of pages
                </label>
                <Toggle
                  id="pref-specific"
                  checked={prefSpecificPage}
                  onChange={setPrefSpecificPage}
                />
              </div>
            </div>
            <div className="setting-block">
              <h4 className="setting-block-head">Block Ads</h4>
              <p className="setting-block-desc muted">
                Block ads and surf the web up to three times faster.
              </p>
              <div className="setting-row toggle-row">
                <span>Enable block ads</span>
                <Toggle checked={prefBlockAds} onChange={setPrefBlockAds} />
              </div>
            </div>
          </>
        )}
        {settingTab === "security" && (
          <>
            <h3 className="setting-panel-title">Security</h3>
            <div className="setting-block">
              <h4 className="setting-block-head">Two-Factor Authentication</h4>
              <div className="setting-row toggle-row">
                <div>
                  <strong>Use two-factor authentication</strong>
                  <p className="muted">
                    We'll ask for a code when a login is from an unrecognized
                    device or browser.
                  </p>
                </div>
                <Toggle checked={security.twofa} onChange={toggle2fa} />
              </div>
              <div className="setting-row toggle-row">
                <div>
                  <strong>Save login info</strong>
                  <p className="muted">
                    Only on browsers/devices you trust. Turn off on shared
                    machines.
                  </p>
                </div>
                <Toggle
                  checked={security.saveLogin}
                  onChange={toggleSaveLogin}
                />
              </div>
            </div>
            <div className="setting-block">
              <h4 className="setting-block-head">Trusted devices</h4>
              <div className="trusted-devices">
                {security.devices.map((d: any) => (
                  <div key={d.id} className="trusted-row">
                    <div>
                      <strong>{d.name}</strong>
                      <p className="muted">{d.lastUsed}</p>
                    </div>
                    <div className="trusted-actions">
                      <button
                        type="button"
                        className={`pill ${d.trusted ? "pill-on" : ""}`}
                        onClick={() => toggleTrusted(d.id)}
                      >
                        {d.trusted ? "Trusted" : "Trust"}
                      </button>
                      <button
                        type="button"
                        className="pill danger-pill"
                        onClick={() => removeDevice(d.id)}
                      >
                        Remove
                      </button>
                    </div>
                  </div>
                ))}
                {security.devices.length === 0 && (
                  <p className="muted">No devices saved.</p>
                )}
              </div>
            </div>
            <div className="setting-block">
              <h4 className="setting-block-head">Change Password</h4>
              <div className="form-grid setting-form">
                <div className="form-group">
                  <label>Current password</label>
                  <input
                    type="password"
                    value={passwordForm.current}
                    onChange={(e) =>
                      setPasswordForm((p) => ({
                        ...p,
                        current: e.target.value,
                      }))
                    }
                  />
                </div>
                <div className="form-group">
                  <label>New password</label>
                  <input
                    type="password"
                    value={passwordForm.next}
                    onChange={(e) =>
                      setPasswordForm((p) => ({ ...p, next: e.target.value }))
                    }
                  />
                </div>
                <div className="form-group">
                  <label>Confirm new password</label>
                  <input
                    type="password"
                    value={passwordForm.confirm}
                    onChange={(e) =>
                      setPasswordForm((p) => ({
                        ...p,
                        confirm: e.target.value,
                      }))
                    }
                  />
                </div>
              </div>
              <div className="setting-actions">
                <button
                  type="button"
                  className="btn-primary"
                  onClick={changePassword}
                >
                  Update Password
                </button>
              </div>
            </div>
          </>
        )}
        {settingTab === "notification" && (
          <>
            <h3 className="setting-panel-title">General Notification</h3>
            <div className="setting-block">
              <div className="setting-row toggle-row">
                <label htmlFor="notif-login">
                  Show notification when someone login to my account
                </label>
                <Toggle
                  id="notif-login"
                  checked={notifLogin}
                  onChange={setNotifLogin}
                />
              </div>
              <div className="setting-row toggle-row">
                <label htmlFor="notif-deposit">
                  Show notification when depositing from another account
                </label>
                <Toggle
                  id="notif-deposit"
                  checked={notifDeposit}
                  onChange={setNotifDeposit}
                />
              </div>
              <div className="setting-row toggle-row">
                <label htmlFor="notif-withdraw1">
                  Notify me when withdrawal money from my account
                </label>
                <Toggle
                  id="notif-withdraw1"
                  checked={notifWithdraw1}
                  onChange={setNotifWithdraw1}
                />
              </div>
              <div className="setting-row toggle-row">
                <label htmlFor="notif-withdraw2">
                  Notify me when withdrawal money from my account
                </label>
                <Toggle
                  id="notif-withdraw2"
                  checked={notifWithdraw2}
                  onChange={setNotifWithdraw2}
                />
              </div>
            </div>
          </>
        )}
      </div>
    </section>
  );
}

function MyProfileView({
  faceIdStatus,
  faceIdStatusLoading,
  onOpenFaceEnrollment,
}: {
  faceIdStatus: FaceIdAccountStatus;
  faceIdStatusLoading: boolean;
  onOpenFaceEnrollment: () => void;
}) {
  const { user, token, updateUser, logout } = useAuth();
  const { toast } = useToast();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const isAuthExpired = (status: number, message?: string) =>
    status === 401 ||
    status === 403 ||
    /invalid|expired|token|jwt/i.test((message || "").toLowerCase());
  const [accountNumber, setAccountNumber] = useState("");
  const [profile, setProfile] = useState<ProfileForm>(() => {
    const baseProfile = (() => {
      try {
        const s = localStorage.getItem(SETTING_PROFILE_KEY);
        return s ? { ...defaultProfile, ...JSON.parse(s) } : defaultProfile;
      } catch {
        return defaultProfile;
      }
    })();
    return user
      ? { ...baseProfile, name: user.name, email: user.email }
      : baseProfile;
  });
  const [avatarUrl, setAvatarUrl] = useState(() => {
    try {
      return (
        localStorage.getItem(PROFILE_AVATAR_KEY) ??
        user?.avatar ??
        "https://i.pravatar.cc/120?img=12"
      );
    } catch {
      return user?.avatar ?? "https://i.pravatar.cc/120?img=12";
    }
  });

  useEffect(() => {
    if (!token) return;
    const loadProfile = async () => {
      try {
        const resp = await fetch(`${API_BASE}/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = (await resp.json().catch(() => null)) as {
          error?: string;
          fullName?: string;
          email?: string;
          phone?: string;
          address?: string;
          dob?: string;
          avatar?: string;
          metadata?: Record<string, unknown>;
        } | null;
        if (!resp.ok) {
          if (isAuthExpired(resp.status, data?.error)) {
            toast("Session expired. Please sign in again.", "error");
            logout();
          }
          return;
        }
        if (!data) return;
        const metadata = data.metadata ?? {};
        setProfile((prev) => ({
          ...prev,
          name: data.fullName || user?.name || prev.name,
          userName:
            (typeof metadata.userName === "string" && metadata.userName) ||
            (data.email?.split("@")[0] ?? prev.userName),
          email: data.email || user?.email || prev.email,
          phone: data.phone || "",
          dateOfBirth: normalizeDobForForm(data.dob || ""),
          address: data.address || "",
          password: "**********",
        }));
        const nextAvatar =
          (typeof data.avatar === "string" && data.avatar) ||
          (typeof metadata.avatar === "string" && metadata.avatar) ||
          "";
        if (nextAvatar) {
          setAvatarUrl(nextAvatar);
          updateUser({ avatar: nextAvatar });
        }
        const walletResp = await fetch(`${API_BASE}/wallet/me`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!walletResp.ok) {
          const walletErr = (await walletResp.json().catch(() => null)) as {
            error?: string;
          } | null;
          if (isAuthExpired(walletResp.status, walletErr?.error)) {
            toast("Session expired. Please sign in again.", "error");
            logout();
          }
          setAccountNumber("");
          return;
        }
        if (walletResp.ok) {
          const walletData = (await walletResp.json().catch(() => null)) as {
            accountNumber?: string;
          } | null;
          setAccountNumber(walletData?.accountNumber || "");
        }
      } catch {
        // keep current local profile when API is unavailable
      }
    };
    void loadProfile();
  }, [logout, toast, token, updateUser, user?.email, user?.name]);

  const saveProfile = async () => {
    if (!token) {
      toast("Session expired. Please login again.", "error");
      return;
    }

    try {
      const resp = await fetch(`${API_BASE}/auth/me`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          fullName: profile.name,
          phone: profile.phone,
          address: profile.address,
          dob: profile.dateOfBirth,
          metadata: {
            userName: profile.userName,
            avatar: avatarUrl,
          },
        }),
      });
      const data = (await resp.json().catch(() => null)) as {
        error?: string;
        fullName?: string;
        email?: string;
      } | null;
      if (!resp.ok) {
        if (isAuthExpired(resp.status, data?.error)) {
          toast("Session expired. Please sign in again.", "error");
          logout();
          return;
        }
        toast(data?.error || "Failed to save profile", "error");
        return;
      }

      localStorage.setItem(SETTING_PROFILE_KEY, JSON.stringify(profile));
      updateUser({
        name: data?.fullName || profile.name,
        email: data?.email || profile.email,
        avatar: avatarUrl,
      });
      toast("Profile saved successfully");
    } catch {
      toast("Cannot connect to API server.", "error");
    }
  };

  const openAvatarPicker = () => {
    fileInputRef.current?.click();
  };

  const handleAvatarChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (!file.type.startsWith("image/")) {
      toast("Please choose an image file", "error");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const next = String(reader.result ?? "");
      if (!next) return;
      setAvatarUrl(next);
      try {
        localStorage.setItem(PROFILE_AVATAR_KEY, next);
      } catch (err) {
        console.error(err);
        toast(
          "Image too large to store locally. Please choose a smaller one.",
          "error",
        );
        return;
      }
      updateUser({ avatar: next });
      toast("Profile image updated");
    };
    reader.readAsDataURL(file);
    e.currentTarget.value = "";
  };

  return (
    <section className="card setting-detail-card user-profile-shell">
      <div className="user-profile-header">
        <button
          type="button"
          className="setting-avatar-wrap"
          onClick={openAvatarPicker}
          aria-label="Change profile image"
        >
          <img
            src={avatarUrl}
            alt="Profile avatar"
            className="setting-avatar"
          />
          <span className="setting-avatar-edit">Edit</span>
          <input
            ref={fileInputRef}
            type="file"
            accept="image/*"
            className="sr-only"
            onChange={handleAvatarChange}
          />
        </button>
        <div className="user-profile-identity">
          <h2>{profile.name || "User"}</h2>
          <p>{profile.email}</p>
          <div className="user-profile-meta">
            <span className="user-profile-pill">
              Role: {user?.role ?? "USER"}
            </span>
            <span className="user-profile-pill">
              Account: {accountNumber || "Not available"}
            </span>
          </div>
        </div>
      </div>

      <div className="user-profile-grid">
        <div className="form-group">
          <label>Full Name</label>
          <input
            type="text"
            value={profile.name}
            onChange={(e) =>
              setProfile((p) => ({ ...p, name: e.target.value }))
            }
          />
        </div>
        <div className="form-group">
          <label>Username</label>
          <input
            type="text"
            value={profile.userName}
            onChange={(e) =>
              setProfile((p) => ({ ...p, userName: e.target.value }))
            }
          />
        </div>
        <div className="form-group">
          <label>Email</label>
          <input
            type="email"
            value={profile.email}
            onChange={(e) =>
              setProfile((p) => ({ ...p, email: e.target.value }))
            }
          />
        </div>
        <div className="form-group">
          <label>Phone Number</label>
          <input
            type="text"
            value={profile.phone}
            onChange={(e) =>
              setProfile((p) => ({ ...p, phone: e.target.value }))
            }
          />
        </div>
        <div className="form-group">
          <label>Date of Birth</label>
          <input
            type="text"
            inputMode="numeric"
            placeholder="dd/mm/yyyy"
            value={profile.dateOfBirth}
            onChange={(e) =>
              setProfile((p) => ({
                ...p,
                dateOfBirth: formatDobInput(e.target.value),
              }))
            }
          />
        </div>
        <div className="form-group profile-address">
          <label>Permanent Address</label>
          <input
            type="text"
            value={profile.address}
            onChange={(e) =>
              setProfile((p) => ({ ...p, address: e.target.value }))
            }
          />
        </div>
      </div>

      <section className="card faceid-banner">
        <div className="faceid-banner-copy">
          <strong>
            {faceIdStatus.enabled ? "FaceID is active" : "FaceID is not set up"}
          </strong>
          <p>
            {faceIdStatusLoading
              ? "Checking your current FaceID status..."
              : faceIdStatus.enabled
                ? "Update your live face sample here whenever recognition becomes unreliable or your appearance changes."
                : "Add a live face sample here so your account can pass future security checks and large-transfer verification."}
          </p>
        </div>
        <div className="faceid-banner-actions">
          <button
            type="button"
            className="btn-primary"
            onClick={onOpenFaceEnrollment}
            disabled={faceIdStatusLoading}
          >
            {faceIdStatusLoading
              ? "Checking..."
              : faceIdStatus.enabled
                ? "Update FaceID"
                : "Add FaceID"}
          </button>
        </div>
      </section>

      <div className="setting-actions">
        <button type="button" className="btn-primary" onClick={saveProfile}>
          Save Changes
        </button>
      </div>
    </section>
  );
}
function App() {
  const {
    user,
    token,
    logout,
    requestLoginOtp,
    verifyLoginOtp,
    requestRegisterOtp,
    verifyRegisterOtp,
    requestPasswordResetOtp,
    resetPasswordWithOtp,
    respondToSessionAlert,
  } = useAuth();
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState("Dashboard");
  const [showNotifications, setShowNotifications] = useState(false);
  const [notificationFilter, setNotificationFilter] = useState<
    "all" | "transactions" | "security"
  >("all");
  const [showAllNotificationsInDropdown, setShowAllNotificationsInDropdown] =
    useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const userMenuRef = useRef<HTMLDivElement>(null);
  const supportMenuRef = useRef<HTMLDivElement>(null);
  const notificationMenuRef = useRef<HTMLDivElement>(null);
  const [invoicesExpanded, setInvoicesExpanded] = useState(false);
  const [utilitiesExpanded, setUtilitiesExpanded] = useState(false);
  const [pendingSessionAlert, setPendingSessionAlert] =
    useState<SessionReplacementAlert | null>(() => {
      try {
        const raw = sessionStorage.getItem(
          SESSION_REPLACEMENT_ALERT_STORAGE_KEY,
        );
        if (!raw) return null;
        const parsed = JSON.parse(raw) as Partial<SessionReplacementAlert>;
        if (
          !parsed ||
          typeof parsed.token !== "string" ||
          typeof parsed.email !== "string"
        ) {
          return null;
        }
        return {
          token: parsed.token,
          email: parsed.email,
          issuedAt:
            typeof parsed.issuedAt === "string" ? parsed.issuedAt : undefined,
          ipAddress:
            typeof parsed.ipAddress === "string" ? parsed.ipAddress : undefined,
          userAgent:
            typeof parsed.userAgent === "string" ? parsed.userAgent : undefined,
        };
      } catch {
        return null;
      }
    });
  const [faceIdStatus, setFaceIdStatus] = useState<FaceIdAccountStatus>({
    enabled: false,
    enrolledAt: null,
    verifiedAt: null,
  });
  const [faceIdStatusLoading, setFaceIdStatusLoading] = useState(false);
  const [faceEnrollmentOpen, setFaceEnrollmentOpen] = useState(false);
  const [faceEnrollmentBusy, setFaceEnrollmentBusy] = useState(false);
  const [faceEnrollmentProof, setFaceEnrollmentProof] =
    useState<FaceIdProof | null>(null);
  const [faceEnrollmentResetKey, setFaceEnrollmentResetKey] = useState(0);

  const isInvoicesActive =
    activeTab === "Invoice List" || activeTab === "Create Invoices";
  const invoicesExpandedShow = invoicesExpanded || isInvoicesActive;
  const utilitiesExpandedShow = utilitiesExpanded;

  useEffect(() => {
    const close = (event: MouseEvent | TouchEvent) => {
      const target = event.target as Node | null;
      if (!target) return;
      if (
        notificationMenuRef.current &&
        !notificationMenuRef.current.contains(target)
      ) {
        setShowNotifications(false);
        setShowAllNotificationsInDropdown(false);
      }
      if (userMenuRef.current && !userMenuRef.current.contains(target))
        setUserMenuOpen(false);
      if (supportMenuRef.current && !supportMenuRef.current.contains(target)) {
        setUtilitiesExpanded(false);
      }
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setShowNotifications(false);
        setShowAllNotificationsInDropdown(false);
        setUserMenuOpen(false);
        setUtilitiesExpanded(false);
      }
    };
    document.addEventListener("mousedown", close);
    document.addEventListener("touchstart", close, { passive: true });
    document.addEventListener("keydown", closeOnEscape);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("touchstart", close);
      document.removeEventListener("keydown", closeOnEscape);
    };
  }, []);

  useEffect(() => {
    if (user) {
      setActiveTab("Dashboard");
      setPendingSessionAlert(null);
    }
  }, [user?.id]);

  useEffect(() => {
    if (!user || !token) {
      setFaceIdStatus({
        enabled: false,
        enrolledAt: null,
        verifiedAt: null,
      });
      setFaceIdStatusLoading(false);
      return;
    }

    let cancelled = false;
    const loadFaceIdStatus = async () => {
      setFaceIdStatusLoading(true);
      try {
        const resp = await fetch(`${API_BASE}/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = (await resp.json().catch(() => null)) as {
          metadata?: Record<string, unknown>;
        } | null;
        if (!resp.ok || !data || cancelled) return;
        setFaceIdStatus(parseFaceIdAccountStatus(data.metadata ?? {}));
      } catch {
        // ignore temporary network errors here
      } finally {
        if (!cancelled) {
          setFaceIdStatusLoading(false);
        }
      }
    };

    void loadFaceIdStatus();
    return () => {
      cancelled = true;
    };
  }, [token, user?.id]);

  useEffect(() => {
    if (typeof document === "undefined") return;
    document.body.classList.toggle("faceid-screen-open", faceEnrollmentOpen);
    document.documentElement.classList.toggle(
      "faceid-screen-open",
      faceEnrollmentOpen,
    );

    return () => {
      document.body.classList.remove("faceid-screen-open");
      document.documentElement.classList.remove("faceid-screen-open");
    };
  }, [faceEnrollmentOpen]);

  const resetFaceEnrollmentModal = useCallback(() => {
    setFaceEnrollmentProof(null);
    setFaceEnrollmentResetKey((value) => value + 1);
  }, []);

  const closeFaceEnrollmentModal = useCallback(() => {
    setFaceEnrollmentOpen(false);
    resetFaceEnrollmentModal();
  }, [resetFaceEnrollmentModal]);

  const openFaceEnrollmentModal = useCallback(() => {
    resetFaceEnrollmentModal();
    setFaceEnrollmentOpen(true);
  }, [resetFaceEnrollmentModal]);

  const handleEnrollFaceId = useCallback(async () => {
    if (!token) {
      toast("Session expired. Please login again.", "error");
      return;
    }
    if (!faceEnrollmentProof) {
      toast("Complete the live FaceID scan first.", "error");
      return;
    }

    setFaceEnrollmentBusy(true);
    try {
      const resp = await fetch(`${API_BASE}/auth/face/enroll`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          faceIdEnrollment: faceEnrollmentProof,
        }),
      });
      const data = (await resp.json().catch(() => null)) as {
        error?: string;
        message?: string;
        metadata?: Record<string, unknown>;
      } | null;
      if (!resp.ok) {
        toast(data?.error || "Failed to enroll FaceID", "error");
        return;
      }

      setFaceIdStatus(parseFaceIdAccountStatus(data?.metadata ?? {}));
      closeFaceEnrollmentModal();
      toast(data?.message || "FaceID enrolled successfully.");
    } catch {
      toast("Cannot connect to API server.", "error");
    } finally {
      setFaceEnrollmentBusy(false);
    }
  }, [closeFaceEnrollmentModal, faceEnrollmentProof, toast, token]);

  useEffect(() => {
    if (!showNotifications) {
      setShowAllNotificationsInDropdown(false);
    }
  }, [showNotifications]);

  useEffect(() => {
    setShowAllNotificationsInDropdown(false);
  }, [notificationFilter]);

  useEffect(() => {
    try {
      if (pendingSessionAlert) {
        sessionStorage.setItem(
          SESSION_REPLACEMENT_ALERT_STORAGE_KEY,
          JSON.stringify(pendingSessionAlert),
        );
      } else {
        sessionStorage.removeItem(SESSION_REPLACEMENT_ALERT_STORAGE_KEY);
      }
    } catch {
      // ignore storage permission errors
    }
  }, [pendingSessionAlert]);

  useEffect(() => {
    const onSessionExpired = (event: Event) => {
      const detail = (
        event as CustomEvent<{
          reason?: "expired" | "replaced";
          sessionAlert?: SessionReplacementAlert;
        }>
      ).detail;
      if (detail?.reason === "replaced" && detail.sessionAlert) {
        setPendingSessionAlert(detail.sessionAlert);
      }
      toast(
        detail?.reason === "replaced"
          ? "This account was signed in on another device. This device has been signed out."
          : "Your login session has expired. Please sign in again.",
        "error",
      );
    };
    window.addEventListener("auth:session-expired", onSessionExpired);
    return () => {
      window.removeEventListener("auth:session-expired", onSessionExpired);
    };
  }, [toast]);
  const {
    notifications,
    notificationsBusy,
    notificationsError,
    unreadNotificationCount,
    markNotificationRead,
    markAllNotificationsRead,
  } = useActivityNotifications({
    apiBase: API_BASE,
    token,
    userId: user?.id,
  });
  const dropdownNotifications = notifications.filter(
    (notification) =>
      notificationFilter === "all" || notification.type === notificationFilter,
  );
  const latestDropdownNotifications = dropdownNotifications.slice(0, 3);
  const visibleDropdownNotifications = showAllNotificationsInDropdown
    ? dropdownNotifications
    : latestDropdownNotifications;

  const displayUser = user ?? {
    name: "Guest User",
    email: "guest@fpipay.app",
    avatar: "https://i.pravatar.cc/80?img=13",
  };

  // If not logged in, show dedicated auth shell
  if (!user) {
    return (
      <AuthShell
        onRequestLoginOtp={requestLoginOtp}
        onVerifyLoginOtp={verifyLoginOtp}
        onRequestRegisterOtp={requestRegisterOtp}
        onVerifyRegisterOtp={verifyRegisterOtp}
        onRequestPasswordResetOtp={requestPasswordResetOtp}
        onResetPasswordWithOtp={resetPasswordWithOtp}
        onRespondToSessionAlert={respondToSessionAlert}
        pendingSessionAlert={pendingSessionAlert}
        onClearSessionAlert={() => setPendingSessionAlert(null)}
      />
    );
  }

  const expanded = (item: { id: string }) =>
    item.id === "Invoices"
      ? invoicesExpandedShow
      : item.id === "Support"
        ? utilitiesExpandedShow
        : false;
  const toggleExpanded = (item: { id: string }) => {
    if (item.id === "Invoices") setInvoicesExpanded(!invoicesExpandedShow);
    if (item.id === "Support") setUtilitiesExpanded(!utilitiesExpandedShow);
  };

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="logo">FPIPay</div>
        <nav>
          {NAV_ITEMS.map((item) => {
            if (item.children) {
              const isExpanded = expanded(item);
              return (
                <div
                  key={item.id}
                  className="nav-group"
                  ref={item.id === "Support" ? supportMenuRef : undefined}
                >
                  <div
                    className={`nav-item nav-item-parent ${activeTab === item.id ? "active" : ""} ${isExpanded ? "expanded" : ""}`}
                    onClick={() => toggleExpanded(item)}
                    onKeyDown={(e) => e.key === "Enter" && toggleExpanded(item)}
                    role="button"
                    tabIndex={0}
                  >
                    <span className="nav-dot" /> {item.label}
                    <span className="nav-chevron">
                      {isExpanded ? "v" : ">"}
                    </span>
                  </div>
                  {isExpanded &&
                    item.children.map((child) => (
                      <div
                        key={child.id}
                        className={`nav-item nav-item-child ${activeTab === child.id ? "active" : ""}`}
                        onClick={() => {
                          setActiveTab(child.id);
                          setUtilitiesExpanded(false);
                        }}
                        onKeyDown={(e) =>
                          e.key === "Enter" &&
                          (() => {
                            setActiveTab(child.id);
                            setUtilitiesExpanded(false);
                          })()
                        }
                        role="button"
                        tabIndex={0}
                      >
                        <span className="nav-dot" /> {child.label}
                      </div>
                    ))}
                </div>
              );
            }
            return (
              <div
                key={item.id}
                className={`nav-item ${activeTab === item.id ? "active" : ""}`}
                onClick={() => {
                  setActiveTab(item.id);
                  setUtilitiesExpanded(false);
                }}
                onKeyDown={(e) =>
                  e.key === "Enter" &&
                  (() => {
                    setActiveTab(item.id);
                    setUtilitiesExpanded(false);
                  })()
                }
                role="button"
                tabIndex={0}
              >
                <span className="nav-dot" /> {item.label}
              </div>
            );
          })}
        </nav>
        <div className="top-actions top-actions-inline">
          <div className="bell-wrap" ref={notificationMenuRef}>
            <button
              type="button"
              className="bell"
              onClick={() => setShowNotifications((v) => !v)}
              aria-haspopup="true"
              aria-expanded={showNotifications}
              aria-label={`Notifications${unreadNotificationCount > 0 ? `, ${unreadNotificationCount} unread` : ""}`}
            >
              <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                <path
                  d="M12 4.75a4.25 4.25 0 0 0-4.25 4.25v2.12c0 .86-.27 1.69-.77 2.39l-1.01 1.39a1.25 1.25 0 0 0 1.01 1.99h10.04a1.25 1.25 0 0 0 1.01-1.99l-1.01-1.39a4.1 4.1 0 0 1-.77-2.39V9A4.25 4.25 0 0 0 12 4.75Zm0 15.5a2.74 2.74 0 0 1-2.48-1.58h4.96A2.74 2.74 0 0 1 12 20.25Z"
                  fill="currentColor"
                />
              </svg>
              {unreadNotificationCount > 0 && (
                <span className="badge">{unreadNotificationCount}</span>
              )}
            </button>
            {showNotifications && (
              <div className="notif-dropdown">
                <div className="notif-dropdown-head">
                  <strong>Account activity</strong>
                  <span className="muted">
                    {unreadNotificationCount} unread
                  </span>
                </div>
                <div className="notif-filter">
                  <select
                    value={notificationFilter}
                    onChange={(e) =>
                      setNotificationFilter(
                        e.target.value as typeof notificationFilter,
                      )
                    }
                  >
                    <option value="all">All</option>
                    <option value="transactions">Balance</option>
                    <option value="security">Security</option>
                  </select>
                </div>
                {notificationsBusy && notifications.length === 0 && (
                  <div className="notif-empty">Loading activity...</div>
                )}
                {!notificationsBusy &&
                  visibleDropdownNotifications.map((notification) => (
                    <button
                      key={notification.id}
                      type="button"
                      className={`notif-row ${!notification.read ? "unread" : ""}`}
                      onClick={() => {
                        markNotificationRead(notification.id);
                        setActiveTab("Notifications");
                        setShowNotifications(false);
                      }}
                    >
                      <div className="notif-row-head">
                        <span
                          className={`notif-pill notif-${notification.type}`}
                        >
                          {notification.type === "transactions"
                            ? "Balance"
                            : "Security"}
                        </span>
                        <span className="notif-time">
                          {notification.timeLabel}
                        </span>
                      </div>
                      <strong className="notif-title">
                        {notification.title}
                      </strong>
                      <div className="notif-message">
                        {notification.message}
                      </div>
                      {notification.meta && (
                        <div className="notif-meta" title={notification.meta}>
                          {notification.meta}
                        </div>
                      )}
                      {notification.amountText && (
                        <span
                          className={`notif-amount notif-amount-${notification.amountTone || "positive"}`}
                        >
                          {notification.amountText}
                        </span>
                      )}
                    </button>
                  ))}
                {!notificationsBusy &&
                  visibleDropdownNotifications.length === 0 && (
                    <div className="notif-empty">
                      {notificationsError || "No account activity yet."}
                    </div>
                  )}
                <div className="notif-actions">
                  <button
                    type="button"
                    className="pill"
                    onClick={() => {
                      markAllNotificationsRead();
                      setShowNotifications(false);
                    }}
                    disabled={unreadNotificationCount === 0}
                  >
                    Mark all read
                  </button>
                  <button
                    type="button"
                    className="pill"
                    onClick={() =>
                      setShowAllNotificationsInDropdown((current) => !current)
                    }
                    disabled={dropdownNotifications.length <= 3}
                  >
                    {showAllNotificationsInDropdown
                      ? "Show less"
                      : `View all (${dropdownNotifications.length})`}
                  </button>
                </div>
              </div>
            )}
          </div>
          <div className="user-menu-wrap" ref={userMenuRef}>
            <button
              type="button"
              className="user-menu-trigger"
              onClick={() => setUserMenuOpen(!userMenuOpen)}
              aria-expanded={userMenuOpen}
              aria-haspopup="true"
            >
              <img className="avatar" src={displayUser.avatar} alt="" />
              <span className="avatar-chevron">v</span>
            </button>
            {userMenuOpen && (
              <div className="user-menu-dropdown">
                <span
                  className="muted"
                  style={{
                    padding: "8px 14px",
                    display: "block",
                    fontSize: 13,
                  }}
                >
                  {displayUser.email}
                </span>
                <button
                  type="button"
                  onClick={() => {
                    setActiveTab("My Profile");
                    setUserMenuOpen(false);
                  }}
                >
                  My profile
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setActiveTab("Setting");
                    setUserMenuOpen(false);
                  }}
                >
                  Setting
                </button>
                <button
                  type="button"
                  className="danger"
                  onClick={() => {
                    logout();
                    setUserMenuOpen(false);
                  }}
                >
                  Logout
                </button>
              </div>
            )}
          </div>
        </div>
      </aside>

      <main className="content">
        <Suspense
          fallback={
            <section className="grid">
              <div className="card span-2">
                <p className="muted">Loading view...</p>
              </div>
            </section>
          }
        >
          {activeTab === "Dashboard" && <DashboardView />}
          {activeTab === "Invoice List" && <LazyInvoiceListView />}
          {activeTab === "Create Invoices" && <LazyCreateInvoicesView />}
          {activeTab === "Card Center" && <CardCenterView />}
          {activeTab === "Accounts" && <AccountsView />}
          {activeTab === "My Profile" && (
            <MyProfileView
              faceIdStatus={faceIdStatus}
              faceIdStatusLoading={faceIdStatusLoading}
              onOpenFaceEnrollment={openFaceEnrollmentModal}
            />
          )}
          {activeTab === "Setting" && <SettingView />}
          {activeTab === "Knowledge base" && <LazyKnowledgeBaseView />}
          {activeTab === "Notifications" && (
            <LazyNotificationsView
              notifications={notifications}
              busy={notificationsBusy}
              error={notificationsError}
              onMarkRead={markNotificationRead}
              onMarkAllRead={markAllNotificationsRead}
            />
          )}
          {activeTab === "KYC Verification" && <LazyKycView />}
          {![
            "Dashboard",
            "Invoice List",
            "Create Invoices",
            "Card Center",
            "Accounts",
            "My Profile",
            "Setting",
            "Knowledge base",
            "Notifications",
            "KYC Verification",
          ].includes(activeTab) && (
            <section className="grid">
              <div className="card span-2">
                <h3>{activeTab}</h3>
                <p className="muted">Content is being built.</p>
              </div>
            </section>
          )}

          <footer className="foot"> FPIPay by My Team</footer>
        </Suspense>
        {faceEnrollmentOpen && typeof document !== "undefined"
          ? createPortal(
              <div
                className="faceid-modal-overlay"
                onClick={() => closeFaceEnrollmentModal()}
              >
                <div
                  className="faceid-modal"
                  onClick={(event) => event.stopPropagation()}
                >
                  <div className="faceid-modal-head">
                    <div>
                      <h3>
                        {faceIdStatus.enabled ? "Update FaceID" : "Add FaceID"}
                      </h3>
                      <p>
                        {faceIdStatus.enabled
                          ? "Complete a fresh live face scan to replace the current FaceID sample for this wallet."
                          : "Complete one live face scan to bind this wallet account to your protected identity profile."}
                      </p>
                    </div>
                    <button
                      type="button"
                      className="faceid-modal-close"
                      onClick={() => closeFaceEnrollmentModal()}
                      aria-label="Close FaceID popup"
                    >
                      X
                    </button>
                  </div>
                  <FaceIdCapture
                    apiBase={API_BASE}
                    resetKey={faceEnrollmentResetKey}
                    disabled={faceEnrollmentBusy}
                    onChange={setFaceEnrollmentProof}
                  />
                  <div className="faceid-modal-actions">
                    <button
                      type="button"
                      className="pill"
                      disabled={faceEnrollmentBusy}
                      onClick={() => resetFaceEnrollmentModal()}
                    >
                      Retry
                    </button>
                    <button
                      type="button"
                      className="btn-primary"
                      disabled={faceEnrollmentBusy || !faceEnrollmentProof}
                      onClick={() => void handleEnrollFaceId()}
                    >
                      {faceEnrollmentBusy
                        ? "Processing FaceID..."
                        : faceIdStatus.enabled
                          ? "Update FaceID"
                          : "Enroll FaceID"}
                    </button>
                  </div>
                </div>
              </div>,
              document.body,
            )
          : null}
      </main>
    </div>
  );
}

export default App;

// -------- Auth Shell (shown when user is null) ----------
const SIGNUP_TERMS_SECTIONS = [
  {
    title: "Account security",
    body: "Protect your password, OTP, and trusted devices. FPIPay staff will never ask you to share verification codes.",
  },
  {
    title: "Authorized use",
    body: "You confirm the wallet is opened for your own identity and lawful payments, transfers, and account management.",
  },
  {
    title: "Privacy and monitoring",
    body: "We process account, login, and device signals to prevent fraud, secure your balance, and review suspicious activity.",
  },
  {
    title: "Risk controls",
    body: "High-risk sign-ins or transfers may trigger extra verification, temporary limits, or session replacement alerts until the device is trusted.",
  },
];

type AuthShellProps = {
  onRequestLoginOtp: (
    email: string,
    password: string,
    captcha: SliderCaptchaValue,
  ) => Promise<LoginResult>;
  onVerifyLoginOtp: (
    challengeId: string,
    otp: string,
    captcha: SliderCaptchaValue,
  ) => Promise<AuthCompletionResult>;
  onRequestRegisterOtp: (payload: {
    fullName: string;
    userName: string;
    email: string;
    phone: string;
    address: string;
    dob: string;
    password: string;
    captcha: SliderCaptchaValue;
    faceEnrollment: FaceIdProof;
  }) => Promise<{
    challengeId: string;
    destination: string;
    expiresAt: string;
    retryAfterSeconds: number;
  }>;
  onVerifyRegisterOtp: (
    challengeId: string,
    otp: string,
  ) => Promise<AuthCompletionResult>;
  onRequestPasswordResetOtp: (
    email: string,
    captcha: SliderCaptchaValue,
  ) => Promise<{
    challengeId: string;
    destination: string;
    expiresAt: string;
    retryAfterSeconds: number;
  }>;
  onResetPasswordWithOtp: (payload: {
    email: string;
    challengeId: string;
    otp: string;
    newPassword: string;
  }) => Promise<void>;
  onRespondToSessionAlert: (
    alertToken: string,
    action: "confirm" | "secure_account",
  ) => Promise<{
    status: "acknowledged" | "secured";
    message: string;
    email?: string;
    destination?: string;
    challengeId?: string;
    expiresAt?: string;
    retryAfterSeconds?: number;
  }>;
  pendingSessionAlert: SessionReplacementAlert | null;
  onClearSessionAlert: () => void;
};

function AuthShell({
  onRequestLoginOtp,
  onVerifyLoginOtp,
  onRequestRegisterOtp,
  onVerifyRegisterOtp,
  onRequestPasswordResetOtp,
  onResetPasswordWithOtp,
  onRespondToSessionAlert,
  pendingSessionAlert,
  onClearSessionAlert,
}: AuthShellProps) {
  useTheme();
  const { lastLoginMonitoring, clearLoginMonitoring } = useAuth();

  const { toast } = useToast();
  const [mode, setMode] = useState<
    | "signin"
    | "signinOtp"
    | "signup"
    | "signupOtp"
    | "forgot"
    | "forgotOtp"
    | null
  >(null);
  const [showPassword, setShowPassword] = useState(false);
  const [termsOpen, setTermsOpen] = useState(false);
  const [authBusy, setAuthBusy] = useState(false);
  const [sessionAlertBusy, setSessionAlertBusy] = useState(false);
  const [authClock, setAuthClock] = useState(Date.now());

  const [signinForm, setSigninForm] = useState({ email: "", password: "" });
  const [signupForm, setSignupForm] = useState({
    fullName: "",
    username: "",
    email: "",
    phone: "",
    address: "",
    dob: "",
    password: "",
    confirm: "",
    agree: false,
  });
  const [signinCaptcha, setSigninCaptcha] = useState<SliderCaptchaValue | null>(
    null,
  );
  const [signupCaptcha, setSignupCaptcha] = useState<SliderCaptchaValue | null>(
    null,
  );
  const [signupFaceEnrollment, setSignupFaceEnrollment] =
    useState<FaceIdProof | null>(null);
  const [signupFaceModalOpen, setSignupFaceModalOpen] = useState(false);
  const [signupOtpInput, setSignupOtpInput] = useState("");
  const [signupOtpChallengeId, setSignupOtpChallengeId] = useState("");
  const [signupOtpDestination, setSignupOtpDestination] = useState("");
  const [signupOtpExpiresAt, setSignupOtpExpiresAt] = useState("");
  const [signupOtpResendAt, setSignupOtpResendAt] = useState(0);
  const [forgotEmail, setForgotEmail] = useState("");
  const [forgotCaptcha, setForgotCaptcha] = useState<SliderCaptchaValue | null>(
    null,
  );
  const [loginOtpInput, setLoginOtpInput] = useState("");
  const [loginOtpChallengeId, setLoginOtpChallengeId] = useState("");
  const [loginOtpDestination, setLoginOtpDestination] = useState("");
  const [loginOtpExpiresAt, setLoginOtpExpiresAt] = useState("");
  const [loginOtpAvailableAt, setLoginOtpAvailableAt] = useState("");
  const [loginOtpResendAt, setLoginOtpResendAt] = useState(0);
  const [forgotOtpInput, setForgotOtpInput] = useState("");
  const [forgotChallengeId, setForgotChallengeId] = useState("");
  const [forgotDestination, setForgotDestination] = useState("");
  const [forgotExpiresAt, setForgotExpiresAt] = useState("");
  const [forgotResendAt, setForgotResendAt] = useState(0);
  const [forgotNewPassword, setForgotNewPassword] = useState("");
  const [forgotConfirmPassword, setForgotConfirmPassword] = useState("");
  const [signinCaptchaResetKey, setSigninCaptchaResetKey] = useState(0);
  const [signupCaptchaResetKey, setSignupCaptchaResetKey] = useState(0);
  const [signupFaceResetKey, setSignupFaceResetKey] = useState(0);
  const [forgotCaptchaResetKey, setForgotCaptchaResetKey] = useState(0);
  const signupPasswordStrength = getPasswordStrength(signupForm.password);
  const forgotPasswordStrength = getPasswordStrength(forgotNewPassword);

  useEffect(() => {
    if (
      loginOtpResendAt <= Date.now() &&
      signupOtpResendAt <= Date.now() &&
      forgotResendAt <= Date.now()
    ) {
      return;
    }
    const timer = window.setInterval(() => setAuthClock(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [forgotResendAt, loginOtpResendAt, signupOtpResendAt]);

  const loginOtpCooldownSeconds = Math.max(
    0,
    Math.ceil((loginOtpResendAt - authClock) / 1000),
  );
  const loginOtpAvailableInSeconds = loginOtpAvailableAt
    ? Math.max(
        0,
        Math.ceil((new Date(loginOtpAvailableAt).getTime() - authClock) / 1000),
      )
    : 0;
  const signupOtpCooldownSeconds = Math.max(
    0,
    Math.ceil((signupOtpResendAt - authClock) / 1000),
  );
  const forgotOtpCooldownSeconds = Math.max(
    0,
    Math.ceil((forgotResendAt - authClock) / 1000),
  );

  const resetSigninCaptcha = () => {
    setSigninCaptcha(null);
    setSigninCaptchaResetKey((value) => value + 1);
  };

  const resetSignupCaptcha = () => {
    setSignupCaptcha(null);
    setSignupCaptchaResetKey((value) => value + 1);
  };

  const resetSignupFaceEnrollment = () => {
    setSignupFaceEnrollment(null);
    setSignupFaceResetKey((value) => value + 1);
  };

  const closeSignupFaceModal = () => {
    setSignupFaceModalOpen(false);
    resetSignupFaceEnrollment();
  };

  const resetForgotCaptcha = () => {
    setForgotCaptcha(null);
    setForgotCaptchaResetKey((value) => value + 1);
  };

  useEffect(() => {
    if (mode !== "signup" && mode !== "signupOtp") {
      setSignupFaceModalOpen(false);
      resetSignupFaceEnrollment();
    }
  }, [mode]);

  const validateSignupBeforeFaceScan = () => {
    const {
      fullName,
      username,
      email,
      phone,
      address,
      dob,
      password,
      confirm,
      agree,
    } = signupForm;
    if (
      !fullName ||
      !username ||
      !email ||
      !phone ||
      !address ||
      !dob ||
      !password
    ) {
      toast("Please fill all required fields", "error");
      return false;
    }
    if (password !== confirm) {
      toast("Password confirmation does not match", "error");
      return false;
    }
    if (!signupPasswordStrength.meetsPolicy) {
      toast(
        "Password must be at least 12 characters and include uppercase, lowercase, number, and special character.",
        "error",
      );
      return false;
    }
    if (!agree) {
      setTermsOpen(true);
      toast("Please agree to terms & privacy", "error");
      return false;
    }
    if (!signupCaptcha) {
      toast("Please complete the slider captcha", "error");
      return false;
    }
    return true;
  };

  const submitSignupOtpRequest = async () => {
    if (!signupFaceEnrollment) {
      toast("Please complete the FaceID scan to continue", "error");
      return;
    }
    setAuthBusy(true);
    try {
      const data = await onRequestRegisterOtp({
        fullName: signupForm.fullName,
        userName: signupForm.username,
        email: signupForm.email,
        phone: signupForm.phone,
        address: signupForm.address,
        dob: signupForm.dob,
        password: signupForm.password,
        captcha: signupCaptcha!,
        faceEnrollment: signupFaceEnrollment,
      });
      setSignupOtpChallengeId(data.challengeId);
      setSignupOtpDestination(data.destination);
      setSignupOtpExpiresAt(data.expiresAt);
      setSignupOtpResendAt(Date.now() + data.retryAfterSeconds * 1000);
      setSignupOtpInput("");
      setSignupFaceModalOpen(false);
      setMode("signupOtp");
      resetSignupCaptcha();
      toast("A verification code has been sent to your email.");
    } catch (err) {
      resetSignupCaptcha();
      toast(err instanceof Error ? err.message : "Sign up failed", "error");
    } finally {
      setAuthBusy(false);
    }
  };

  const sessionAlertIssuedAt = pendingSessionAlert?.issuedAt
    ? new Date(pendingSessionAlert.issuedAt).toLocaleString("en-US", {
        month: "short",
        day: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "Just now";

  const renderLoginMonitoring = (monitoring: LoginMonitoring | null) => {
    if (!monitoring) return null;
    const riskLevel = monitoring.riskLevel.toLowerCase();
    const normalizedRisk =
      riskLevel === "high" || riskLevel === "medium" ? riskLevel : "low";
    const filteredReasons = monitoring.reasons
      .filter((reason) => reason !== "AI monitoring unavailable")
      .slice(0, 3);
    if (normalizedRisk === "low" && !monitoring.requireOtp) return null;
    const riskLabel =
      normalizedRisk === "high"
        ? "High risk"
        : normalizedRisk === "medium"
          ? "Medium risk"
          : "Low risk";

    return (
      <div className={`auth-ai-monitor auth-ai-monitor-${normalizedRisk}`}>
        <div className="auth-ai-monitor-head">
          <strong>Security Review</strong>
          <span className={`auth-ai-badge auth-ai-badge-${normalizedRisk}`}>
            {riskLabel}
          </span>
        </div>
        <p className="auth-ai-copy">
          Additional security checks were triggered for this sign-in attempt.
        </p>
        {monitoring.requireOtp && (
          <p className="auth-ai-signal">
            Additional verification is required
            {monitoring.otpChannel ? ` via ${monitoring.otpChannel}` : ""}.
            {monitoring.otpReason ? ` ${monitoring.otpReason}` : ""}
          </p>
        )}
        {filteredReasons.length > 0 && (
          <ul className="auth-ai-reasons">
            {filteredReasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        )}
      </div>
    );
  };

  const renderPasswordStrength = (
    strength: ReturnType<typeof getPasswordStrength>,
  ) => {
    const fillWidth =
      strength.totalChecks > 0
        ? `${Math.max(8, (strength.passedChecks / strength.totalChecks) * 100)}%`
        : "8%";
    const unmetChecks = strength.checks.filter((check) => !check.met);
    const visibleChecks = strength.meetsPolicy ? strength.checks : unmetChecks;

    return (
      <div
        className={`auth-password-strength auth-password-strength-${strength.level}`}
        aria-live="polite"
      >
        <div className="auth-password-strength-head">
          <span>
            Password security
            <small>
              {strength.passedChecks}/{strength.totalChecks} requirements
            </small>
          </span>
          <strong>{strength.label}</strong>
        </div>
        <div className="auth-password-strength-bar" aria-hidden="true">
          <span style={{ width: fillWidth }} />
        </div>
        <p className="auth-password-strength-message">{strength.message}</p>
        <div className="auth-password-checks">
          {visibleChecks.map((check) => (
            <span
              key={check.id}
              className={
                check.met ? "auth-password-check is-met" : "auth-password-check"
              }
              title={check.label}
            >
              {check.met ? "OK" : "Need"}: {check.shortLabel}
            </span>
          ))}
        </div>
      </div>
    );
  };

  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!signinForm.email || !signinForm.password) {
      toast("Please enter email and password", "error");
      return;
    }
    if (!signinCaptcha) {
      toast("Please complete the slider captcha", "error");
      return;
    }
    clearLoginMonitoring();
    setAuthBusy(true);
    try {
      const data = await onRequestLoginOtp(
        signinForm.email,
        signinForm.password,
        signinCaptcha,
      );
      if (data.status === "authenticated") {
        setLoginOtpChallengeId("");
        setLoginOtpDestination("");
        setLoginOtpExpiresAt("");
        setLoginOtpAvailableAt("");
        setLoginOtpResendAt(0);
        setLoginOtpInput("");
        resetSigninCaptcha();
        setMode(null);
        toast("Signed in successfully");
        if (data.monitoring && data.monitoring.riskLevel !== "low") {
          toast(
            "Additional security checks were applied to this sign-in.",
            "info",
          );
        }
        if (data.notice) {
          toast(data.notice, "info");
        }
        return;
      }

      setLoginOtpChallengeId(data.challengeId);
      setLoginOtpDestination(data.destination);
      setLoginOtpExpiresAt(data.expiresAt);
      setLoginOtpAvailableAt(data.availableAt || "");
      setLoginOtpResendAt(Date.now() + data.retryAfterSeconds * 1000);
      setLoginOtpInput("");
      resetSigninCaptcha();
      setMode("signinOtp");
      toast(
        data.notice || "A verification code has been sent to your email.",
        "info",
      );
    } catch (err) {
      resetSigninCaptcha();
      toast(err instanceof Error ? err.message : "Sign in failed", "error");
    } finally {
      setAuthBusy(false);
    }
  };

  const handleSignUp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validateSignupBeforeFaceScan()) {
      return;
    }
    resetSignupFaceEnrollment();
    setSignupFaceModalOpen(true);
  };

  const handleVerifyRegisterOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!signupOtpChallengeId || !/^\d{6}$/.test(signupOtpInput)) {
      toast("Please enter the 6-digit verification code", "error");
      return;
    }
    setAuthBusy(true);
    try {
      const result = await onVerifyRegisterOtp(
        signupOtpChallengeId,
        signupOtpInput,
      );
      resetSignupCaptcha();
      toast("Account created successfully");
      if (result.notice) {
        toast(result.notice, "info");
      }
    } catch (err) {
      toast(
        err instanceof Error ? err.message : "OTP verification failed",
        "error",
      );
    } finally {
      setAuthBusy(false);
    }
  };

  const handleForgot = (e: React.FormEvent) => {
    void (async () => {
      e.preventDefault();
      if (!forgotEmail) {
        toast("Please enter your email", "error");
        return;
      }
      if (!forgotCaptcha) {
        toast("Please complete the slider captcha", "error");
        return;
      }
      setAuthBusy(true);
      try {
        const data = await onRequestPasswordResetOtp(
          forgotEmail,
          forgotCaptcha,
        );
        setForgotChallengeId(data.challengeId);
        setForgotDestination(data.destination);
        setForgotExpiresAt(data.expiresAt);
        setForgotResendAt(Date.now() + data.retryAfterSeconds * 1000);
        setForgotOtpInput("");
        setForgotNewPassword("");
        setForgotConfirmPassword("");
        resetForgotCaptcha();
        setMode("forgotOtp");
        toast("Password reset code sent to your email.");
      } catch (err) {
        resetForgotCaptcha();
        toast(
          err instanceof Error ? err.message : "Failed to send reset code",
          "error",
        );
      } finally {
        setAuthBusy(false);
      }
    })();
  };

  const handleVerifyLoginOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!loginOtpChallengeId || !/^\d{6}$/.test(loginOtpInput)) {
      toast("Please enter the 6-digit verification code", "error");
      return;
    }
    if (!signinCaptcha) {
      toast("Please complete the slider captcha", "error");
      return;
    }
    if (loginOtpAvailableInSeconds > 0) {
      toast(
        `This new-device sign-in is still blocked. Try again in ${loginOtpAvailableInSeconds}s.`,
        "error",
      );
      return;
    }
    setAuthBusy(true);
    try {
      const result = await onVerifyLoginOtp(
        loginOtpChallengeId,
        loginOtpInput,
        signinCaptcha,
      );
      setLoginOtpAvailableAt("");
      resetSigninCaptcha();
      toast("Signed in successfully");
      if (result.notice) {
        toast(result.notice, "info");
      }
    } catch (err) {
      toast(
        err instanceof Error ? err.message : "OTP verification failed",
        "error",
      );
    } finally {
      setAuthBusy(false);
    }
  };

  const resendLoginOtp = async () => {
    if (loginOtpCooldownSeconds > 0) return;
    if (!signinCaptcha) {
      toast("Complete the slider captcha before resending OTP", "error");
      return;
    }
    clearLoginMonitoring();
    setAuthBusy(true);
    try {
      const data = await onRequestLoginOtp(
        signinForm.email,
        signinForm.password,
        signinCaptcha,
      );
      if (data.status === "authenticated") {
        setLoginOtpChallengeId("");
        setLoginOtpDestination("");
        setLoginOtpExpiresAt("");
        setLoginOtpAvailableAt("");
        setLoginOtpResendAt(0);
        setLoginOtpInput("");
        resetSigninCaptcha();
        setMode(null);
        toast("Signed in successfully");
        if (data.monitoring && data.monitoring.riskLevel !== "low") {
          toast(
            "Additional security checks were applied to this sign-in.",
            "info",
          );
        }
        if (data.notice) {
          toast(data.notice, "info");
        }
        return;
      }
      setLoginOtpChallengeId(data.challengeId);
      setLoginOtpDestination(data.destination);
      setLoginOtpExpiresAt(data.expiresAt);
      setLoginOtpAvailableAt(data.availableAt || "");
      setLoginOtpResendAt(Date.now() + data.retryAfterSeconds * 1000);
      resetSigninCaptcha();
      toast(data.notice || "A new verification code has been sent.", "info");
    } catch (err) {
      resetSigninCaptcha();
      toast(
        err instanceof Error ? err.message : "Failed to resend OTP",
        "error",
      );
    } finally {
      setAuthBusy(false);
    }
  };

  const resendRegisterOtp = async () => {
    if (signupOtpCooldownSeconds > 0) return;
    if (!signupCaptcha) {
      toast("Complete the slider captcha before resending OTP", "error");
      return;
    }
    if (!signupFaceEnrollment) {
      toast("Complete FaceID registration before resending OTP", "error");
      return;
    }
    setAuthBusy(true);
    try {
      const data = await onRequestRegisterOtp({
        fullName: signupForm.fullName,
        userName: signupForm.username,
        email: signupForm.email,
        phone: signupForm.phone,
        address: signupForm.address,
        dob: signupForm.dob,
        password: signupForm.password,
        captcha: signupCaptcha,
        faceEnrollment: signupFaceEnrollment,
      });
      setSignupOtpChallengeId(data.challengeId);
      setSignupOtpDestination(data.destination);
      setSignupOtpExpiresAt(data.expiresAt);
      setSignupOtpResendAt(Date.now() + data.retryAfterSeconds * 1000);
      resetSignupCaptcha();
      toast("A new verification code has been sent.");
    } catch (err) {
      resetSignupCaptcha();
      toast(
        err instanceof Error ? err.message : "Failed to resend OTP",
        "error",
      );
    } finally {
      setAuthBusy(false);
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!forgotChallengeId || !/^\d{6}$/.test(forgotOtpInput)) {
      toast("Please enter the 6-digit reset code", "error");
      return;
    }
    if (forgotNewPassword.length < 12) {
      toast("New password must be at least 12 characters", "error");
      return;
    }
    if (!forgotPasswordStrength.meetsPolicy) {
      toast(
        "New password must include uppercase, lowercase, number, and special character.",
        "error",
      );
      return;
    }
    if (forgotNewPassword !== forgotConfirmPassword) {
      toast("Password confirmation does not match", "error");
      return;
    }
    setAuthBusy(true);
    try {
      await onResetPasswordWithOtp({
        email: forgotEmail,
        challengeId: forgotChallengeId,
        otp: forgotOtpInput,
        newPassword: forgotNewPassword,
      });
      toast("Password reset successfully. Please sign in.");
      setSigninForm({ email: forgotEmail, password: "" });
      setForgotEmail("");
      setForgotChallengeId("");
      setForgotOtpInput("");
      setForgotNewPassword("");
      setForgotConfirmPassword("");
      resetForgotCaptcha();
      setMode("signin");
    } catch (err) {
      toast(
        err instanceof Error ? err.message : "Failed to reset password",
        "error",
      );
    } finally {
      setAuthBusy(false);
    }
  };

  const resendForgotOtp = async () => {
    if (forgotOtpCooldownSeconds > 0) return;
    if (!forgotCaptcha) {
      toast("Complete the slider captcha before resending OTP", "error");
      return;
    }
    setAuthBusy(true);
    try {
      const data = await onRequestPasswordResetOtp(forgotEmail, forgotCaptcha);
      setForgotChallengeId(data.challengeId);
      setForgotDestination(data.destination);
      setForgotExpiresAt(data.expiresAt);
      setForgotResendAt(Date.now() + data.retryAfterSeconds * 1000);
      resetForgotCaptcha();
      toast("A new reset code has been sent.");
    } catch (err) {
      resetForgotCaptcha();
      toast(
        err instanceof Error ? err.message : "Failed to resend OTP",
        "error",
      );
    } finally {
      setAuthBusy(false);
    }
  };

  const handleConfirmSessionAlert = async () => {
    if (!pendingSessionAlert) return;
    setSessionAlertBusy(true);
    try {
      const result = await onRespondToSessionAlert(
        pendingSessionAlert.token,
        "confirm",
      );
      onClearSessionAlert();
      toast(result.message || "Security notice dismissed.");
    } catch (err) {
      toast(
        err instanceof Error
          ? err.message
          : "Failed to confirm sign-in activity",
        "error",
      );
    } finally {
      setSessionAlertBusy(false);
    }
  };

  const handleSecureCompromisedSession = async () => {
    if (!pendingSessionAlert) return;
    setSessionAlertBusy(true);
    try {
      const result = await onRespondToSessionAlert(
        pendingSessionAlert.token,
        "secure_account",
      );
      onClearSessionAlert();
      setForgotEmail(result.email || pendingSessionAlert.email);
      setForgotChallengeId(result.challengeId || "");
      setForgotDestination(result.destination || pendingSessionAlert.email);
      setForgotExpiresAt(result.expiresAt || "");
      setForgotResendAt(Date.now() + (result.retryAfterSeconds || 60) * 1000);
      setForgotOtpInput("");
      setForgotNewPassword("");
      setForgotConfirmPassword("");
      setMode(result.challengeId ? "forgotOtp" : "forgot");
      toast(result.message, "info");
    } catch (err) {
      toast(
        err instanceof Error ? err.message : "Failed to secure account",
        "error",
      );
    } finally {
      setSessionAlertBusy(false);
    }
  };

  const acceptSignupTerms = () => {
    setSignupForm((current) => ({ ...current, agree: true }));
    setTermsOpen(false);
  };

  const renderSignupTermsModal = () => {
    if (!termsOpen) return null;

    return (
      <div
        className="terms-modal-overlay"
        role="dialog"
        aria-modal="true"
        aria-labelledby="signup-terms-title"
        onClick={() => setTermsOpen(false)}
      >
        <div
          className="terms-modal-card"
          onClick={(event) => event.stopPropagation()}
        >
          <div className="terms-modal-head">
            <div>
              <span className="terms-modal-kicker">FPIPay Legal</span>
              <h3 id="signup-terms-title">Terms & Privacy Notice</h3>
              <p>
                Review the core conditions for using a professional digital
                wallet before creating your account.
              </p>
            </div>
            <button
              type="button"
              className="terms-modal-close"
              onClick={() => setTermsOpen(false)}
              aria-label="Close terms"
            >
              Close
            </button>
          </div>
          <div className="terms-modal-body">
            {SIGNUP_TERMS_SECTIONS.map((section, index) => (
              <section key={section.title} className="terms-section">
                <span className="terms-section-index">0{index + 1}</span>
                <div>
                  <h4>{section.title}</h4>
                  <p>{section.body}</p>
                </div>
              </section>
            ))}
            <div className="terms-note">
              By continuing, you confirm that the information you provide is
              accurate and that you accept FPIPay security controls for account
              protection and compliance review.
            </div>
          </div>
          <div className="terms-modal-actions">
            <button
              type="button"
              className="pill"
              onClick={() => setTermsOpen(false)}
            >
              Review later
            </button>
            <button
              type="button"
              className="btn-primary"
              onClick={acceptSignupTerms}
            >
              Agree & Continue
            </button>
          </div>
        </div>
      </div>
    );
  };

  const renderChoice = () => (
    <div className="welcome-hero">
      <div className="hero-copy">
        <div
          className="hero-pill hero-reveal"
          style={{ "--delay": "0.05s" } as CSSProperties}
        >
          Fast / Protected / Intelligent
        </div>
        <h1
          className="hero-reveal"
          style={{ "--delay": "0.12s" } as CSSProperties}
        >
          FPIPay - <span className="hero-accent">Fast</span>,{" "}
          <span className="hero-accent-2">Protected</span>,{" "}
          <span className="hero-accent-3">Intelligent</span>
        </h1>
        <p
          className="hero-lead hero-reveal"
          style={{ "--delay": "0.2s" } as CSSProperties}
        >
          Built for modern wallets with instant payment flows, protected account
          controls, and intelligent insights that keep every move clear.
        </p>

        <div
          className="hero-features hero-reveal"
          style={{ "--delay": "0.28s" } as CSSProperties}
        >
          {[
            {
              icon: "F",
              title: "Fast Flows",
              copy: "Real-time transfers and instant confirmations across every device.",
              accent: "#38bdf8",
              accent2: "#2563eb",
            },
            {
              icon: "P",
              title: "Protected Profiles",
              copy: "Layered access checks, trusted sessions, and privacy-first recovery.",
              accent: "#4ade80",
              accent2: "#22c55e",
            },
            {
              icon: "I",
              title: "Intelligent Insights",
              copy: "Live wallet signals and spending intelligence that feels proactive.",
              accent: "#f59e0b",
              accent2: "#14b8a6",
            },
          ].map((f, index) => (
            <div
              className="hero-feature"
              key={f.title}
              style={
                {
                  "--feature-delay": `${0.34 + index * 0.08}s`,
                  "--feature-accent": f.accent,
                  "--feature-accent-2": f.accent2,
                } as CSSProperties
              }
            >
              <span className="hero-feature-ico">{f.icon}</span>
              <span className="hero-feature-title">{f.title}</span>
              <span className="hero-feature-copy">{f.copy}</span>
            </div>
          ))}
        </div>

        <div
          className="hero-cta hero-reveal"
          style={{ "--delay": "0.42s" } as CSSProperties}
        >
          <button
            type="button"
            className="btn-primary hero-cta-btn"
            onClick={() => setMode("signin")}
          >
            Log In
          </button>
          <button
            type="button"
            className="btn-primary hero-cta-btn secondary"
            onClick={() => setMode("signup")}
          >
            Sign Up
          </button>
        </div>

        <div
          className="hero-meta hero-reveal"
          style={{ "--delay": "0.5s" } as CSSProperties}
        >
          24/7 Fraud Watch / Payment Tracking / Mobile + Desktop Ready
        </div>
      </div>

      <div className="hero-visual">
        <div className="hero-visual-grid" aria-hidden="true" />
        <div className="hero-ambient ambient-1" aria-hidden="true" />
        <div className="hero-ambient ambient-2" aria-hidden="true" />
        <div className="hero-screen">
          <div className="screen-sheen" aria-hidden="true" />
          <div className="screen-header">
            <span className="dot red" />
            <span className="dot yellow" />
            <span className="dot green" />
            <span className="screen-title">FPI Command</span>
            <span className="screen-pill">Live shield</span>
          </div>
          <div className="screen-body">
            <div className="screen-topline">
              {[
                { letter: "F", label: "Fast lane" },
                { letter: "P", label: "Protected mode" },
                { letter: "I", label: "Insight live" },
              ].map((item, index) => (
                <div
                  key={item.letter}
                  className="screen-chip"
                  style={
                    {
                      "--chip-delay": `${1.2 + index * 0.12}s`,
                    } as CSSProperties
                  }
                >
                  <span>{item.letter}</span>
                  {item.label}
                </div>
              ))}
            </div>
            <div className="screen-balance">
              <div className="screen-balance-copy">
                <div className="muted">Protected balance</div>
                <div className="big">$12,450.00</div>
                <div className="screen-balance-note">
                  Smart routing active across wallet, card, and mobile sign-in.
                </div>
              </div>
              <div className="screen-balance-trend" aria-hidden="true">
                {[38, 54, 46, 72, 58, 88, 76].map((height, index) => (
                  <span
                    key={height}
                    style={
                      {
                        "--trend-height": `${height}%`,
                        "--trend-delay": `${1.35 + index * 0.08}s`,
                      } as CSSProperties
                    }
                  />
                ))}
              </div>
            </div>
            <div className="screen-bars">
              {Array.from({ length: 6 }).map((_, i) => (
                <div
                  key={i}
                  className="bar"
                  style={
                    {
                      "--bar-height": `${50 + i * 10}%`,
                      "--bar-delay": `${0.55 + i * 0.08}s`,
                    } as CSSProperties
                  }
                />
              ))}
            </div>
            <div className="screen-stats">
              <div>
                <span className="muted">Income</span>
                <strong>$6,320</strong>
                <small>Flow stable</small>
              </div>
              <div>
                <span className="muted">Expenses</span>
                <strong>$3,980</strong>
                <small>Policy guarded</small>
              </div>
              <div className="screen-stat-highlight">
                <span className="muted">Intelligence</span>
                <strong>Active</strong>
                <small>Adaptive alerts on</small>
              </div>
            </div>
          </div>
        </div>
        <div className="hero-orb orb-1" />
        <div className="hero-orb orb-2" />
      </div>
    </div>
  );

  return (
    <div className={mode ? "auth-shell" : "auth-shell auth-shell-hero"}>
      <div
        className={
          mode ? "auth-card-panel" : "auth-card-panel auth-card-panel-hero"
        }
      >
        {!mode && renderChoice()}

        {mode === "signin" && (
          <div className="auth-form-shell">
            <form className="auth-form-modern" onSubmit={handleSignIn}>
              <h2>Sign In</h2>
              <p className="muted">
                Welcome back! Enter your credentials to access FPIPay.
              </p>
              <label className="auth-label">
                Email Address
                <input
                  type="email"
                  value={signinForm.email}
                  onChange={(e) => {
                    clearLoginMonitoring();
                    setSigninForm({ ...signinForm, email: e.target.value });
                  }}
                  placeholder="Enter your email"
                  required
                />
              </label>
              <label className="auth-label">
                Password
                <div className="password-wrap">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={signinForm.password}
                    onChange={(e) => {
                      clearLoginMonitoring();
                      setSigninForm({
                        ...signinForm,
                        password: e.target.value,
                      });
                    }}
                    placeholder="Enter your password"
                    required
                  />
                  <button
                    type="button"
                    className="eye"
                    onClick={() => setShowPassword((s) => !s)}
                    aria-label="Toggle password"
                  >
                    {showPassword ? "Hide" : "Show"}
                  </button>
                </div>
              </label>
              <div className="auth-row">
                <label className="auth-checkbox">
                  <input type="checkbox" /> Remember me
                </label>
                <a
                  href="#"
                  onClick={(e) => {
                    e.preventDefault();
                    setMode("forgot");
                  }}
                  className="muted"
                >
                  Forgot password
                </a>
              </div>
              <SliderCaptcha
                apiBase={API_BASE}
                resetKey={signinCaptchaResetKey}
                disabled={authBusy}
                onChange={setSigninCaptcha}
              />
              {renderLoginMonitoring(lastLoginMonitoring)}
              <button
                type="submit"
                className="btn-primary auth-submit"
                disabled={authBusy}
              >
                {authBusy ? "Signing in..." : "Sign In"}
              </button>
              <p className="auth-switch">
                Don&apos;t have an account?{" "}
                <button
                  type="button"
                  className="link-btn"
                  onClick={() => setMode("signup")}
                >
                  Sign Up
                </button>
                <span className="muted"> / </span>
                <button
                  type="button"
                  className="link-btn"
                  onClick={() => setMode(null)}
                >
                  Back
                </button>
              </p>
            </form>
          </div>
        )}
        {mode === "signinOtp" && (
          <div className="auth-form-shell">
            <form className="auth-form-modern" onSubmit={handleVerifyLoginOtp}>
              <h2>Verify Sign In</h2>
              <p className="muted">
                Enter the 6-digit code sent to{" "}
                <strong>{loginOtpDestination}</strong>.
              </p>
              <label className="auth-label">
                Verification Code
                <input
                  inputMode="numeric"
                  maxLength={6}
                  value={loginOtpInput}
                  onChange={(e) =>
                    setLoginOtpInput(
                      e.target.value.replace(/\D/g, "").slice(0, 6),
                    )
                  }
                  placeholder="Enter 6-digit OTP"
                  required
                />
                <span className="muted" style={{ fontSize: 12 }}>
                  {loginOtpAvailableInSeconds > 0
                    ? `This new-device sign-in can be verified in ${loginOtpAvailableInSeconds}s.`
                    : null}
                </span>
                <span className="muted" style={{ fontSize: 12 }}>
                  {loginOtpExpiresAt
                    ? `Code expires at ${new Date(
                        loginOtpExpiresAt,
                      ).toLocaleTimeString("en-US", {
                        hour: "2-digit",
                        minute: "2-digit",
                      })}`
                    : "Check your messages for the latest code."}
                </span>
              </label>
              {renderLoginMonitoring(lastLoginMonitoring)}
              <SliderCaptcha
                apiBase={API_BASE}
                resetKey={signinCaptchaResetKey}
                disabled={authBusy}
                onChange={setSigninCaptcha}
              />
              <div className="auth-otp-actions">
                <button
                  type="button"
                  className="pill"
                  disabled={authBusy || loginOtpCooldownSeconds > 0}
                  onClick={() => void resendLoginOtp()}
                >
                  {loginOtpCooldownSeconds > 0
                    ? `Resend in ${loginOtpCooldownSeconds}s`
                    : "Resend OTP"}
                </button>
                <button
                  type="submit"
                  className="btn-primary auth-submit"
                  disabled={authBusy || loginOtpAvailableInSeconds > 0}
                >
                  {authBusy ? "Verifying..." : "Verify & Sign In"}
                </button>
              </div>
              <p className="auth-switch">
                <button
                  type="button"
                  className="link-btn"
                  onClick={() => setMode("signin")}
                >
                  Back to credentials
                </button>
              </p>
            </form>
          </div>
        )}
        {mode === "signup" && (
          <div className="auth-form-shell">
            <form className="auth-form-modern" onSubmit={handleSignUp}>
              <h2>Sign Up</h2>
              <p className="muted">
                Create your FPIPay account to start managing finances smartly.
              </p>
              <div className="grid-two">
                <label className="auth-label">
                  Full Name
                  <input
                    value={signupForm.fullName}
                    onChange={(e) =>
                      setSignupForm({ ...signupForm, fullName: e.target.value })
                    }
                    placeholder="Enter your full name"
                    required
                  />
                </label>
                <label className="auth-label">
                  Username
                  <input
                    value={signupForm.username}
                    onChange={(e) =>
                      setSignupForm({ ...signupForm, username: e.target.value })
                    }
                    placeholder="Enter your username"
                    required
                  />
                </label>
              </div>
              <div className="grid-two">
                <label className="auth-label">
                  Phone Number
                  <input
                    value={signupForm.phone}
                    onChange={(e) =>
                      setSignupForm({ ...signupForm, phone: e.target.value })
                    }
                    placeholder="Enter your phone number"
                    required
                  />
                </label>
                <label className="auth-label">
                  Date of Birth
                  <input
                    type="date"
                    value={signupForm.dob}
                    onChange={(e) =>
                      setSignupForm({ ...signupForm, dob: e.target.value })
                    }
                    placeholder="Enter your date of birth"
                    required
                  />
                </label>
              </div>
              <label className="auth-label">
                Address
                <input
                  value={signupForm.address}
                  onChange={(e) =>
                    setSignupForm({ ...signupForm, address: e.target.value })
                  }
                  placeholder="Enter your address"
                  required
                />
              </label>
              <label className="auth-label">
                Email Address
                <input
                  type="email"
                  value={signupForm.email}
                  onChange={(e) =>
                    setSignupForm({ ...signupForm, email: e.target.value })
                  }
                  placeholder="Enter your email"
                  required
                />
              </label>
              <div className="grid-two">
                <label className="auth-label">
                  Password
                  <div className="password-wrap">
                    <input
                      type={showPassword ? "text" : "password"}
                      className={
                        signupForm.password &&
                        !signupPasswordStrength.meetsPolicy
                          ? "input-invalid"
                          : undefined
                      }
                      value={signupForm.password}
                      onChange={(e) =>
                        setSignupForm({
                          ...signupForm,
                          password: e.target.value,
                        })
                      }
                      placeholder="Enter your password"
                      autoComplete="new-password"
                      minLength={12}
                      required
                    />
                    <button
                      type="button"
                      className="eye"
                      onClick={() => setShowPassword((s) => !s)}
                      aria-label="Toggle password"
                    >
                      {showPassword ? "Hide" : "Show"}
                    </button>
                  </div>
                  {renderPasswordStrength(signupPasswordStrength)}
                </label>
                <label className="auth-label">
                  Confirm Password
                  <input
                    type={showPassword ? "text" : "password"}
                    value={signupForm.confirm}
                    onChange={(e) =>
                      setSignupForm({ ...signupForm, confirm: e.target.value })
                    }
                    placeholder="Confirm your password"
                    autoComplete="new-password"
                    required
                  />
                </label>
              </div>
              <div className="auth-terms-row">
                <label className="auth-checkbox">
                  <input
                    type="checkbox"
                    checked={signupForm.agree}
                    onChange={(e) =>
                      setSignupForm({ ...signupForm, agree: e.target.checked })
                    }
                    required
                  />
                  <span>I agree to</span>
                </label>
                <button
                  type="button"
                  className="auth-terms-trigger"
                  onClick={() => setTermsOpen(true)}
                >
                  terms & privacy
                </button>
              </div>
              <SliderCaptcha
                apiBase={API_BASE}
                resetKey={signupCaptchaResetKey}
                disabled={authBusy}
                onChange={setSignupCaptcha}
              />
              <button
                type="submit"
                className="btn-primary auth-submit"
                disabled={authBusy}
              >
                {authBusy ? "Creating..." : "Create Account"}
              </button>
              <p className="auth-switch">
                Already have an account?{" "}
                <button
                  type="button"
                  className="link-btn"
                  onClick={() => setMode("signin")}
                >
                  Sign In
                </button>
                <span className="muted"> / </span>
                <button
                  type="button"
                  className="link-btn"
                  onClick={() => setMode(null)}
                >
                  Back
                </button>
              </p>
            </form>
          </div>
        )}
        {signupFaceModalOpen && typeof document !== "undefined"
          ? createPortal(
              <div
                className="faceid-modal-overlay"
                onClick={() => closeSignupFaceModal()}
              >
                <div
                  className="faceid-modal"
                  onClick={(event) => event.stopPropagation()}
                >
                  <div className="faceid-modal-head">
                    <div>
                      <h3>Create Account with FaceID</h3>
                      <p>
                        Complete one live face scan to finish your account
                        protection setup before we send the signup code.
                      </p>
                    </div>
                    <button
                      type="button"
                      className="faceid-modal-close"
                      onClick={() => closeSignupFaceModal()}
                      aria-label="Close signup FaceID popup"
                    >
                      X
                    </button>
                  </div>
                  <FaceIdCapture
                    apiBase={API_BASE}
                    resetKey={signupFaceResetKey}
                    disabled={authBusy}
                    onChange={setSignupFaceEnrollment}
                  />
                  <div className="faceid-modal-actions">
                    <button
                      type="button"
                      className="pill"
                      disabled={authBusy}
                      onClick={() => resetSignupFaceEnrollment()}
                    >
                      Retry
                    </button>
                    <button
                      type="button"
                      className="btn-primary"
                      disabled={authBusy || !signupFaceEnrollment}
                      onClick={() => void submitSignupOtpRequest()}
                    >
                      {authBusy ? "Preparing account..." : "Continue Signup"}
                    </button>
                  </div>
                </div>
              </div>,
              document.body,
            )
          : null}
        {mode === "signupOtp" && (
          <div className="auth-form-shell">
            <form
              className="auth-form-modern"
              onSubmit={handleVerifyRegisterOtp}
            >
              <h2>Verify Email</h2>
              <p className="muted">
                Enter the 6-digit code sent to{" "}
                <strong>{signupOtpDestination}</strong> to activate your
                account.
              </p>
              <label className="auth-label">
                Verification Code
                <input
                  inputMode="numeric"
                  maxLength={6}
                  value={signupOtpInput}
                  onChange={(e) =>
                    setSignupOtpInput(
                      e.target.value.replace(/\D/g, "").slice(0, 6),
                    )
                  }
                  placeholder="Enter 6-digit OTP"
                  required
                />
                <span className="muted" style={{ fontSize: 12 }}>
                  {signupOtpExpiresAt
                    ? `Code expires at ${new Date(
                        signupOtpExpiresAt,
                      ).toLocaleTimeString("en-US", {
                        hour: "2-digit",
                        minute: "2-digit",
                      })}`
                    : "Check your inbox for the latest code."}
                </span>
              </label>
              <SliderCaptcha
                apiBase={API_BASE}
                resetKey={signupCaptchaResetKey}
                disabled={authBusy}
                onChange={setSignupCaptcha}
              />
              <div className="auth-otp-actions">
                <button
                  type="button"
                  className="pill"
                  disabled={authBusy || signupOtpCooldownSeconds > 0}
                  onClick={() => void resendRegisterOtp()}
                >
                  {signupOtpCooldownSeconds > 0
                    ? `Resend in ${signupOtpCooldownSeconds}s`
                    : "Resend OTP"}
                </button>
                <button
                  type="submit"
                  className="btn-primary auth-submit"
                  disabled={authBusy}
                >
                  {authBusy ? "Verifying..." : "Verify & Create Account"}
                </button>
              </div>
              <p className="auth-switch">
                <button
                  type="button"
                  className="link-btn"
                  onClick={() => setMode("signup")}
                >
                  Back to sign up
                </button>
              </p>
            </form>
          </div>
        )}
        {mode === "forgot" && (
          <div className="auth-form-shell">
            <form className="auth-form-modern" onSubmit={handleForgot}>
              <h2>Forgot Password</h2>
              <p className="muted">
                Enter the email linked to your account and we&apos;ll email you
                a reset code.
              </p>
              <label className="auth-label">
                Email Address
                <input
                  type="email"
                  value={forgotEmail}
                  onChange={(e) => setForgotEmail(e.target.value)}
                  placeholder="Enter your email"
                  required
                />
              </label>
              <SliderCaptcha
                apiBase={API_BASE}
                resetKey={forgotCaptchaResetKey}
                disabled={authBusy}
                onChange={setForgotCaptcha}
              />
              <button
                type="submit"
                className="btn-primary auth-submit"
                disabled={authBusy}
              >
                {authBusy ? "Sending..." : "Send Reset Code"}
              </button>
              <p className="auth-switch">
                Remembered it?{" "}
                <button
                  type="button"
                  className="link-btn"
                  onClick={() => setMode("signin")}
                >
                  Back to Sign In
                </button>
              </p>
            </form>
          </div>
        )}
        {mode === "forgotOtp" && (
          <div className="auth-form-shell">
            <form className="auth-form-modern" onSubmit={handleResetPassword}>
              <h2>Reset Password</h2>
              <p className="muted">
                Enter the 6-digit code sent to{" "}
                <strong>{forgotDestination}</strong> and set a new password.
              </p>
              <label className="auth-label">
                Reset Code
                <input
                  inputMode="numeric"
                  maxLength={6}
                  value={forgotOtpInput}
                  onChange={(e) =>
                    setForgotOtpInput(
                      e.target.value.replace(/\D/g, "").slice(0, 6),
                    )
                  }
                  placeholder="Enter 6-digit OTP"
                  required
                />
                <span className="muted" style={{ fontSize: 12 }}>
                  {forgotExpiresAt
                    ? `Code expires at ${new Date(
                        forgotExpiresAt,
                      ).toLocaleTimeString("en-US", {
                        hour: "2-digit",
                        minute: "2-digit",
                      })}`
                    : "Check your inbox for the latest code."}
                </span>
              </label>
              <SliderCaptcha
                apiBase={API_BASE}
                resetKey={forgotCaptchaResetKey}
                disabled={authBusy}
                onChange={setForgotCaptcha}
              />
              <label className="auth-label">
                New Password
                <input
                  type="password"
                  value={forgotNewPassword}
                  onChange={(e) => setForgotNewPassword(e.target.value)}
                  placeholder="Enter new password"
                  autoComplete="new-password"
                  minLength={12}
                  required
                />
                {renderPasswordStrength(forgotPasswordStrength)}
              </label>
              <label className="auth-label">
                Confirm New Password
                <input
                  type="password"
                  value={forgotConfirmPassword}
                  onChange={(e) => setForgotConfirmPassword(e.target.value)}
                  placeholder="Confirm new password"
                  required
                />
              </label>
              <div className="auth-otp-actions">
                <button
                  type="button"
                  className="pill"
                  disabled={authBusy || forgotOtpCooldownSeconds > 0}
                  onClick={() => void resendForgotOtp()}
                >
                  {forgotOtpCooldownSeconds > 0
                    ? `Resend in ${forgotOtpCooldownSeconds}s`
                    : "Resend OTP"}
                </button>
                <button
                  type="submit"
                  className="btn-primary auth-submit"
                  disabled={authBusy}
                >
                  {authBusy ? "Resetting..." : "Reset Password"}
                </button>
              </div>
              <p className="auth-switch">
                <button
                  type="button"
                  className="link-btn"
                  onClick={() => setMode("signin")}
                >
                  Back to Sign In
                </button>
              </p>
            </form>
          </div>
        )}
      </div>
      {pendingSessionAlert && (
        <div className="session-alert-overlay">
          <div className="session-alert-banner">
            <div className="session-alert-copy">
              <span className="session-alert-kicker">Security Review</span>
              <h3>Your previous device was signed out</h3>
              <p>
                A newer sign-in was detected for this account. Review it before
                continuing.
              </p>
              <div className="session-alert-meta">
                <span>Time: {sessionAlertIssuedAt}</span>
                <span>
                  Device: {pendingSessionAlert.userAgent || "Unknown device"}
                </span>
                <span>
                  IP: {pendingSessionAlert.ipAddress || "Unavailable"}
                </span>
              </div>
            </div>
            <div className="session-alert-actions">
              <button
                type="button"
                className="pill"
                disabled={sessionAlertBusy}
                onClick={() => void handleConfirmSessionAlert()}
              >
                {sessionAlertBusy ? "Processing..." : "Yes, it was me"}
              </button>
              <button
                type="button"
                className="btn-primary auth-submit"
                disabled={sessionAlertBusy}
                onClick={() => void handleSecureCompromisedSession()}
              >
                {sessionAlertBusy ? "Securing..." : "No, secure account"}
              </button>
            </div>
          </div>
        </div>
      )}
      {renderSignupTermsModal()}
    </div>
  );
}
