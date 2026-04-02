import {
  Suspense,
  lazy,
  startTransition,
  useEffect,
  useLayoutEffect,
  useCallback,
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
import type { FaceIdProof } from "../components/FaceIdCapture";
import type { SliderCaptchaValue } from "../components/SliderCaptcha";
import { useToast } from "../context/ToastContext";
import { useTheme } from "../context/ThemeContext";
import { useActivityNotifications } from "./hooks/useActivityNotifications";
import { API_BASE } from "../lib/apiBase";
import "../index.css";

const LazyInvoiceListView = lazy(() => import("./views/InvoiceListView"));
const LazyCreateInvoicesView = lazy(() => import("./views/CreateInvoicesView"));
const LazyKnowledgeBaseView = lazy(() => import("./views/KnowledgeBaseView"));
const LazyNotificationsView = lazy(() => import("./views/NotificationsView"));
const LazyKycView = lazy(() => import("./views/KycView"));
const LazyFaceIdCapture = lazy(async () => {
  const mod = await import("../components/FaceIdCapture");
  return { default: mod.FaceIdCapture };
});
const LazySliderCaptcha = lazy(async () => {
  const mod = await import("../components/SliderCaptcha");
  return { default: mod.SliderCaptcha };
});

const SESSION_REPLACEMENT_ALERT_STORAGE_KEY =
  "fpipay_session_replacement_alert";
const NOTIFICATION_READ_STORAGE_PREFIX = "fpipay_notification_reads";
const SIGNUP_TEST_BALANCE_STORAGE_KEY = "fpipay_signup_test_balance_v1";
const COPILOT_REQUEST_TIMEOUT_MS = 90000;
const PROFESSIONAL_PASSWORD_MIN_LENGTH = 12;
const TRANSFER_FACE_ID_THRESHOLD = 1000;
const FORCE_AUTH_HERO_MOTION_CLASS = "force-auth-hero-motion";
const SIGNUP_TEST_BALANCE_AMOUNT = 99999;

const getSignupTestBalanceBonus = (userId?: string | null) => {
  if (!userId || typeof window === "undefined") return 0;
  try {
    const raw = window.localStorage.getItem(SIGNUP_TEST_BALANCE_STORAGE_KEY);
    if (!raw) return 0;
    const parsed = JSON.parse(raw) as Record<string, number>;
    const bonus = Number(parsed?.[userId] || 0);
    return Number.isFinite(bonus) ? bonus : 0;
  } catch {
    return 0;
  }
};

function DeferredFaceIdCapture(props: {
  apiBase: string;
  resetKey?: number;
  disabled?: boolean;
  mode?: "enroll" | "verify";
  onChange: (value: FaceIdProof | null) => void;
}) {
  return (
    <Suspense
      fallback={<div className="faceid-card">Loading FaceID scanner...</div>}
    >
      <LazyFaceIdCapture {...props} />
    </Suspense>
  );
}

function DeferredSliderCaptcha(props: {
  apiBase: string;
  resetKey?: number;
  disabled?: boolean;
  onChange: (value: SliderCaptchaValue | null) => void;
}) {
  return (
    <Suspense
      fallback={
        <div className="auth-password-strength">Loading security check...</div>
      }
    >
      <LazySliderCaptcha {...props} />
    </Suspense>
  );
}

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
  { id: "Copilot", label: "Copilot" },
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
    id: "sign-in-activity",
    title: "View Sign-In Activity",
    detail: "Review trusted devices and recent sign-ins",
    icon: "SH",
  },
  {
    id: "transfer",
    title: "Internal Transfer",
    detail: "Move funds between accounts",
    icon: "TX",
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
  recipientName?: string;
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

const getTransactionHistoryTimeLabel = (value: string) => {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  const dateLabel = parsed.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
  });
  const timeLabel = parsed.toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
  });
  return `${dateLabel} • ${timeLabel}`;
};

type SavedTransferRecipient = {
  accountNumber: string;
  holderName: string;
  userId?: string;
  lastTransferredAt: string;
  transferCount: number;
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
  archetype?: string | null;
  timeline?: string[];
  recommendedActions?: string[];
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

type CopilotSessionState = {
  id: string;
  title: string;
  pinned: boolean;
  createdAt: string;
  updatedAt: string;
  messages: CopilotMessage[];
  insight: CopilotInsight;
};

type CopilotWorkspaceState = {
  activeSessionId: string;
  sessions: CopilotSessionState[];
};

const isCopilotWorkspaceShape = (
  value: unknown,
): value is Partial<CopilotWorkspaceState> => {
  return value !== null && typeof value === "object" && "sessions" in value;
};

const IPV4_ADDRESS_PATTERN = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
const COPILOT_HISTORY_STORAGE_PREFIX = "fpipay_copilot_history";
const TRANSFER_HARD_BLOCK_NOTE_PATTERNS = [
  /\b(otp|ma otp|verification code|ma xac minh|faceid|sinh trac)\b/i,
  /\b(safe account|tai khoan an toan|security team|support team)\b/i,
  /\b(anydesk|teamviewer|remote access|screen share|chia se man hinh)\b/i,
];
const TRANSFER_BLOCKED_NOTE_PATTERNS = [
  /\b(refund|hoan tien|unlock|mo khoa|verification fee|phi xac minh)\b/i,
  /\b(customs|hai quan|tax|thue|penalty|phat)\b/i,
];
const TRANSFER_WARNING_NOTE_PATTERNS = [
  /\b(urgent|gap|immediately|right now|ngay lap tuc|khan cap)\b/i,
  /\b(invest|investment|dau tu|broker|forex|crypto signal|guaranteed return|bao loi nhuan)\b/i,
];
const TRANSFER_GENERIC_NOTE_PATTERN =
  /^(transfer|payment|test|chuyen tien|ck|thanh toan|gui tien)$/i;

const translateTransferRiskCopy = (value?: string) => {
  const text = (value || "").replace(/\s+/g, " ").trim();
  if (!text) return "";

  let localized = text
    .replace(
      /^tài khoản đuôi (\d{4}) chưa xuất hiện trong lịch sử chuyển tiền hoàn tất của bạn\.?$/i,
      "Account ending $1 has not appeared in your completed transfer history yet.",
    )
    .replace(
      /^người nhận này còn mới so với lịch sử chuyển tiền hoàn tất của bạn\.?$/i,
      "The recipient is new relative to your completed transfer history.",
    )
    .replace(
      /^đây là giao dịch giá trị cao đối với ví cá nhân \(usd ([\d,]+(?:\.\d+)?)\)\.?$/i,
      "This is a high-value transfer for a consumer wallet (USD $1).",
    )
    .replace(
      /^hành vi chuyển tiền gần đây đã kích hoạt (\d+) lần ai rà soát hoặc chặn trong 30 ngày qua\.?$/i,
      "Recent outbound transfer behavior has triggered $1 AI reviews or blocks in the last 30 days.",
    )
    .replace(
      /^bạn có (\d+) lần thử chuyển gần mức tiền này đã bị đưa vào diện rà soát hoặc chặn trước khi hoàn tất\.?$/i,
      "You had $1 recent transfer attempts near this amount that were reviewed or blocked before completion.",
    )
    .replace(
      /^xác minh người nhận qua số điện thoại hoặc kênh bạn đã tin cậy từ trước\.?$/i,
      "Verify the recipient using a phone number or channel you already trust.",
    )
    .replace(
      /^xác minh người nhận, số tiền và mục đích thanh toán trong kênh liên hệ do chính bạn chủ động mở\.?$/i,
      "Confirm the recipient, amount, and payment purpose in a channel you initiated yourself.",
    )
    .replace(
      /^không tiếp tục nếu có người hướng dẫn bạn qua điện thoại, chat hoặc chia sẻ màn hình\.?$/i,
      "Do not continue if someone is guiding you over phone, chat, or screen share.",
    )
    .replace(
      /^không tiếp tục nếu bạn bị hối thúc hoặc bị yêu cầu bỏ qua bước bảo mật\.?$/i,
      "Do not continue if you feel rushed or are being told to bypass security checks.",
    )
    .replace(/^rủi ro người nhận mới$/i, "New Recipient Risk")
    .replace(
      /^tôi đã kiểm tra, tiếp tục nhận otp$/i,
      "I reviewed the warning, continue to OTP",
    )
    .replace(
      /^otp kết hợp xác thực faceid trực tiếp$/i,
      "OTP plus live FaceID check",
    )
    .replace(/^rà soát trước khi gửi otp$/i, "Review, then release OTP")
    .replace(/^tạm dừng và tự xác minh$/i, "Pause and verify independently")
    .replace(/^cảnh báo tăng cường xác minh$/i, "Step-up warning")
    .replace(/^tạm dừng để bảo vệ tài khoản$/i, "Protection pause")
    .replace(/^kiểm tra độ tin cậy$/i, "Trust check")
    .replace(
      /^account ending (\d{4}) has not appeared in your completed transfer history yet\.?$/i,
      "Account ending $1 has not appeared in your completed transfer history yet.",
    )
    .replace(
      /^the recipient is new relative to your completed transfer history\.?$/i,
      "The recipient is new relative to your completed transfer history.",
    )
    .replace(
      /^this is a high-value transfer for a consumer wallet \(usd ([\d,]+(?:\.\d+)?)\)\.?$/i,
      "This is a high-value transfer for a consumer wallet (USD $1).",
    )
    .replace(
      /^recent outbound transfer behavior has triggered (\d+) ai reviews or blocks in the last 30 days\.?$/i,
      "Recent outbound transfer behavior has triggered $1 AI reviews or blocks in the last 30 days.",
    )
    .replace(
      /^you had (\d+) recent transfer attempt(?:s)? near this amount that (?:were|was) reviewed or blocked before completion\.?$/i,
      "You had $1 recent transfer attempts near this amount that were reviewed or blocked before completion.",
    )
    .replace(
      /^a large amount of funds entered this wallet recently and the current transfer would move most of it back out quickly\.?$/i,
      "This wallet was funded recently and the current transfer would cash most of it back out too quickly.",
    )
    .replace(
      /^recent admin top-up is being cashed out unusually quickly, which matches a source-in\/source-out laundering pattern\.?$/i,
      "A recent admin top-up is being moved back out unusually quickly, which matches a source-in/source-out laundering pattern.",
    )
    .replace(
      /^verify the recipient using a phone number or channel you already trust\.?$/i,
      "Verify the recipient using a phone number or channel you already trust.",
    )
    .replace(
      /^confirm the recipient, amount, and payment purpose in a channel you initiated yourself\.?$/i,
      "Confirm the recipient, amount, and payment purpose in a channel you initiated yourself.",
    )
    .replace(
      /^do not continue if someone is guiding you over phone, chat, or screen share\.?$/i,
      "Do not continue if someone is guiding you over phone, chat, or screen share.",
    )
    .replace(
      /^do not continue if you feel rushed or are being told to bypass security checks\.?$/i,
      "Do not continue if you feel rushed or are being told to bypass security checks.",
    )
    .replace(
      /^tam dung giao dich va goi hotline chinh thuc\.?$/i,
      "Pause the transfer and call the official support hotline.",
    )
    .replace(
      /^tạm dừng giao dịch và gọi hotline chính thức\.?$/i,
      "Pause the transfer and call the official support hotline.",
    )
    .replace(/^new recipient risk$/i, "New Recipient Risk")
    .replace(/^rapid cash-out risk$/i, "Rapid Cash-Out Risk")
    .replace(/^continue carefully$/i, "I reviewed the warning, continue to OTP")
    .replace(/^otp plus live faceid check$/i, "OTP plus live FaceID check")
    .replace(/^review, then release otp$/i, "Review, then release OTP")
    .replace(
      /^pause and verify independently$/i,
      "Pause and verify independently",
    )
    .replace(/^step-up warning$/i, "Step-up warning")
    .replace(/^protection pause$/i, "Protection pause")
    .replace(/^trust check$/i, "Trust check");

  localized = localized
    .replace(/\bAI\b/g, "AI")
    .replace(/\bOTP\b/g, "OTP")
    .replace(/\bFaceID\b/g, "FaceID");

  return localized;
};

const normalizeNotificationCopy = (value?: string) =>
  (value || "").replace(/\s+/g, " ").trim();

const truncateNotificationCopy = (value: string, maxLength: number) =>
  value.length <= maxLength
    ? value
    : `${value.slice(0, maxLength - 3).trimEnd()}...`;

const getNotificationDayLabel = (createdAt: string) => {
  const date = new Date(createdAt);
  if (Number.isNaN(date.getTime())) return "Recent";

  const dayStart = new Date(date);
  dayStart.setHours(0, 0, 0, 0);

  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);

  const yesterdayStart = new Date(todayStart);
  yesterdayStart.setDate(todayStart.getDate() - 1);

  if (dayStart.getTime() === todayStart.getTime()) return "Today";
  if (dayStart.getTime() === yesterdayStart.getTime()) return "Yesterday";

  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  }).format(date);
};

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

const buildDefaultCopilotMessages = (): CopilotMessage[] => [
  {
    role: "assistant",
    content:
      "Ask me anything about spending, savings, transfers, statements, scams, or market decisions. I will use your wallet context when it helps.",
  },
];

const buildDefaultCopilotInsight = (): CopilotInsight => ({
  topic: "",
  suggestedActions: [],
  suggestedDepositAmount: null,
  riskLevel: "low",
  confidence: 0,
  followUpQuestion: null,
});

const COPILOT_TITLE_STOP_WORDS = new Set([
  "toi",
  "dang",
  "can",
  "muon",
  "nho",
  "giup",
  "hay",
  "cho",
  "ve",
  "la",
  "co",
  "nen",
  "khong",
  "hom",
  "nay",
  "please",
  "help",
  "me",
  "with",
  "for",
  "about",
  "should",
  "can",
  "you",
  "my",
  "the",
  "a",
  "an",
  "to",
  "of",
  "and",
]);

const COPILOT_DEFAULT_TITLE = "New Conversation";

const COPILOT_MARKET_ENTITY_RULES: Array<{
  pattern: RegExp;
  ticker: string;
}> = [
  { pattern: /\bfpt\b|fpt telecom|fpt shop/i, ticker: "FPT" },
  {
    pattern: /\btcb\b|techcombank/i,
    ticker: "TCB",
  },
  { pattern: /\bvcb\b|vietcombank/i, ticker: "VCB" },
  { pattern: /\bbid\b|bidv/i, ticker: "BID" },
  { pattern: /\bctg\b|vietinbank/i, ticker: "CTG" },
  { pattern: /\bvpb\b|vpbank/i, ticker: "VPB" },
  { pattern: /\bmbb\b|mbbank/i, ticker: "MBB" },
  { pattern: /\bacb\b|asia commercial bank/i, ticker: "ACB" },
  { pattern: /\bstb\b|sacombank/i, ticker: "STB" },
  { pattern: /\bhdb\b|hdbank/i, ticker: "HDB" },
  { pattern: /\bvnm\b|vinamilk/i, ticker: "VNM" },
  { pattern: /\bhpg\b|hoa phat|hòa phát/i, ticker: "HPG" },
  { pattern: /\bvhm\b|vinhomes/i, ticker: "VHM" },
  { pattern: /\bvic\b|vingroup/i, ticker: "VIC" },
  {
    pattern: /\bmwg\b|the gioi di dong|thế giới di động/i,
    ticker: "MWG",
  },
  { pattern: /\bmsn\b|masan/i, ticker: "MSN" },
  { pattern: /\bpnj\b|phu nhuan jewelry/i, ticker: "PNJ" },
  { pattern: /\bssi\b|ssi securities/i, ticker: "SSI" },
  { pattern: /\bhcm\b|hsc|ho chi minh securities/i, ticker: "HCM" },
  { pattern: /\bvci\b|vietcap|ban viet/i, ticker: "VCI" },
  { pattern: /\bvnd\b|vndirect/i, ticker: "VND" },
  { pattern: /\bfts\b|fpts|fpt securities/i, ticker: "FTS" },
  { pattern: /\bbvh\b|bao viet/i, ticker: "BVH" },
];

const toHeadlineCase = (value: string) =>
  value
    .split(/\s+/)
    .filter(Boolean)
    .map((word) => {
      if (/^[A-Z0-9]{2,8}$/.test(word)) return word;
      return word.charAt(0).toLocaleUpperCase("vi-VN") + word.slice(1);
    })
    .join(" ");

const getCopilotMarketEntity = (input: string) =>
  COPILOT_MARKET_ENTITY_RULES.find((rule) => rule.pattern.test(input));

const buildSmartCopilotTitle = (input?: string) => {
  const cleaned = (input || "")
    .replace(/\s+/g, " ")
    .replace(/[!?.,;:]+$/g, "")
    .trim();
  if (!cleaned) return COPILOT_DEFAULT_TITLE;
  const lowered = cleaned.toLowerCase();

  const marketEntity = getCopilotMarketEntity(lowered);
  if (
    /\bcổ phiếu\b|\bstock\b|\bmã\b|\bmarket\b|\bgiá\b|\bprice\b/i.test(lowered)
  ) {
    if (
      /\bso sánh\b|\bcompare\b|\bversus\b|\bvs\b|\bkhác nhau\b/i.test(lowered)
    ) {
      return marketEntity
        ? `So Sánh Cổ Phiếu ${marketEntity.ticker}`
        : "So Sánh Cổ Phiếu";
    }
    if (
      /\bgiá\b|\bprice\b|\bbao nhiêu\b|\bthế nào\b|\bdiễn biến\b|\bhôm nay\b/i.test(
        lowered,
      )
    ) {
      return marketEntity
        ? `Theo Dõi Cổ Phiếu ${marketEntity.ticker}`
        : "Theo Dõi Giá Cổ Phiếu";
    }
    return marketEntity
      ? `Phân Tích Cổ Phiếu ${marketEntity.ticker}`
      : "Phân Tích Cổ Phiếu";
  }

  const topicRules: Array<{ pattern: RegExp; title: string }> = [
    {
      pattern: /\botp\b|\blừa đảo\b|\bscam\b|\bgian lận\b|\bđiều tra\b/,
      title: "Rà Soát Rủi Ro Gian Lận",
    },
    {
      pattern: /\bchuyển tiền\b|\btransfer\b|\bchuyển khoản\b/,
      title: "Tư Vấn Chuyển Tiền",
    },
    {
      pattern: /\btiết kiệm\b|\bsaving\b|\bgửi tiết kiệm\b/,
      title: "Tư Vấn Tiết Kiệm",
    },
    {
      pattern: /\bđầu tư\b|\binvest\b|\bquỹ\b|\bdanh mục\b|\bportfolio\b/,
      title: "Tư Vấn Chiến Lược Đầu Tư",
    },
    {
      pattern: /\bbảo mật\b|\bsecurity\b|\btài khoản\b/,
      title: "Rà Soát Bảo Mật Tài Khoản",
    },
    {
      pattern: /\bchi tiêu\b|\bspending\b|\bngân sách\b/,
      title: "Phân Tích Chi Tiêu",
    },
  ];
  const matchedTopic = topicRules.find((rule) => rule.pattern.test(lowered));
  if (matchedTopic) return matchedTopic.title;
  const significantWords = cleaned
    .split(" ")
    .map((word) => word.replace(/^[^\p{L}\p{N}]+|[^\p{L}\p{N}%/.-]+$/gu, ""))
    .filter(Boolean)
    .filter(
      (word, index) =>
        index === 0 || !COPILOT_TITLE_STOP_WORDS.has(word.toLowerCase()),
    );
  const compact = significantWords.slice(0, 5).join(" ").trim();
  return toHeadlineCase(compact || cleaned);
};

const buildCopilotSessionTitle = (input?: string) => {
  const cleaned = buildSmartCopilotTitle(input).replace(/\s+/g, " ").trim();
  if (!cleaned) return COPILOT_DEFAULT_TITLE;
  return cleaned.length <= 44
    ? cleaned
    : `${cleaned.slice(0, 41).trimEnd()}...`;
};

const buildDefaultCopilotSession = (seed?: {
  id?: string;
  title?: string;
  createdAt?: string;
  updatedAt?: string;
}): CopilotSessionState => {
  const now = new Date().toISOString();
  return {
    id:
      seed?.id ||
      (typeof crypto !== "undefined" && "randomUUID" in crypto
        ? crypto.randomUUID()
        : `copilot-${Date.now()}`),
    title: seed?.title || COPILOT_DEFAULT_TITLE,
    pinned: false,
    createdAt: seed?.createdAt || now,
    updatedAt: seed?.updatedAt || now,
    messages: buildDefaultCopilotMessages(),
    insight: buildDefaultCopilotInsight(),
  };
};

const buildDefaultCopilotWorkspace = (): CopilotWorkspaceState => {
  const session = buildDefaultCopilotSession();
  return {
    activeSessionId: session.id,
    sessions: [session],
  };
};

const summarizeDeviceUserAgent = (value?: string) => {
  const userAgent = normalizeNotificationCopy(value);
  if (!userAgent) {
    return {
      title: "Unknown device",
      detail: "Browser and device details unavailable",
    };
  }

  let browserLabel = "";
  for (const [pattern, label] of [
    [/Edg\/(\d+)/, "Edge"],
    [/Chrome\/(\d+)/, "Chrome"],
    [/Firefox\/(\d+)/, "Firefox"],
    [/Version\/(\d+).+Safari\//, "Safari"],
  ] as Array<[RegExp, string]>) {
    const match = userAgent.match(pattern);
    if (match) {
      browserLabel = `${label}${match[1] ? ` ${match[1]}` : ""}`;
      break;
    }
  }

  let osLabel = "";
  let deviceTitle = "Unknown device";
  if (/Windows NT 10\.0|Windows NT 11\.0/i.test(userAgent)) {
    osLabel = "Windows";
    deviceTitle = "Windows PC";
  } else if (/Mac OS X [\d_]+/i.test(userAgent)) {
    osLabel = "macOS";
    deviceTitle = "Mac device";
  } else if (/iPhone/i.test(userAgent)) {
    osLabel = "iOS";
    deviceTitle = "iPhone";
  } else if (/iPad/i.test(userAgent)) {
    osLabel = "iPadOS";
    deviceTitle = "iPad";
  } else if (/Android/i.test(userAgent) && /Mobile/i.test(userAgent)) {
    osLabel = "Android";
    deviceTitle = "Android phone";
  } else if (/Android/i.test(userAgent)) {
    osLabel = "Android";
    deviceTitle = "Android tablet";
  } else if (/Linux/i.test(userAgent)) {
    osLabel = "Linux";
    deviceTitle = "Linux device";
  }

  const detail = [browserLabel, osLabel].filter(Boolean).join(" / ");
  return {
    title: deviceTitle,
    detail:
      detail ||
      (userAgent.length > 64 ? `${userAgent.slice(0, 64)}...` : userAgent),
  };
};

const normalizeSavedTransferRecipients = (value: unknown) =>
  Array.isArray(value)
    ? value
        .reduce<SavedTransferRecipient[]>((acc, item) => {
          if (!item || typeof item !== "object" || Array.isArray(item)) {
            return acc;
          }
          const record = item as Record<string, unknown>;
          const accountNumber =
            typeof record.accountNumber === "string"
              ? record.accountNumber.replace(/\D/g, "").slice(0, 19)
              : "";
          const holderName =
            typeof record.holderName === "string"
              ? record.holderName.trim()
              : "";
          const userId =
            typeof record.userId === "string" && record.userId.trim()
              ? record.userId.trim()
              : undefined;
          const lastTransferredAt =
            typeof record.lastTransferredAt === "string"
              ? record.lastTransferredAt
              : "";
          const transferCountRaw =
            typeof record.transferCount === "number"
              ? record.transferCount
              : Number(record.transferCount);
          const transferCount =
            Number.isFinite(transferCountRaw) && transferCountRaw > 0
              ? Math.trunc(transferCountRaw)
              : 1;

          if (!accountNumber || !holderName || !lastTransferredAt) {
            return acc;
          }

          acc.push({
            accountNumber,
            holderName,
            userId,
            lastTransferredAt,
            transferCount,
          });
          return acc;
        }, [])
        .sort(
          (left, right) =>
            Date.parse(right.lastTransferredAt) -
            Date.parse(left.lastTransferredAt),
        )
    : [];

const upsertSavedTransferRecipient = (
  recipients: SavedTransferRecipient[],
  input: {
    accountNumber: string;
    holderName: string;
    userId?: string;
    occurredAt: string;
  },
) => {
  const accountNumber = input.accountNumber.replace(/\D/g, "").slice(0, 19);
  const holderName = input.holderName.trim();
  if (!accountNumber || !holderName) return recipients;

  const matched = recipients.find(
    (item) => item.accountNumber === accountNumber,
  );
  return [
    {
      accountNumber,
      holderName,
      userId: input.userId?.trim() || matched?.userId,
      lastTransferredAt: input.occurredAt,
      transferCount: (matched?.transferCount || 0) + 1,
    } satisfies SavedTransferRecipient,
    ...recipients.filter((item) => item.accountNumber !== accountNumber),
  ].slice(0, 8);
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
  baseScore?: number | null;
  finalScore?: number | null;
  mitigationScore?: number | null;
  archetype?: string | null;
  timeline?: string[];
  headline?: string | null;
  summary?: string | null;
  nextStep?: string | null;
  recommendedActions?: string[];
  monitoringOnly: boolean;
  action?: string;
  modelSource?: string | null;
  modelVersion?: string | null;
  requestKey?: string | null;
  modelRiskLevel?: string | null;
  ruleRiskLevel?: string | null;
  finalAction?: string | null;
  stepUpLevel?: string | null;
  ruleScore?: number | null;
  ruleHitCount?: number | null;
  ruleHits?: Array<{
    ruleId?: string;
    title?: string;
    reason?: string;
    userWarning?: string;
    riskLevel?: string;
  }>;
  warning?: {
    title?: string;
    message?: string;
    doNot?: string[];
    mustDo?: string[];
    promptTemplateId?: string;
  } | null;
  analysisSignals?: Record<string, unknown> | null;
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

function DashboardView({
  mode = "dashboard",
  onOpenCopilotWorkspace,
  onCloseCopilotWorkspace,
}: {
  mode?: "dashboard" | "copilot";
  onOpenCopilotWorkspace?: () => void;
  onCloseCopilotWorkspace?: () => void;
}) {
  const { user, token, sessionSecurity } = useAuth();
  const { toast } = useToast();
  const transferQrVideoRef = useRef<HTMLVideoElement>(null);
  const transferQrStreamRef = useRef<MediaStream | null>(null);
  const transferQrScanTimerRef = useRef<number | null>(null);
  const copilotThreadRef = useRef<HTMLDivElement>(null);
  const copilotPersistTimerRef = useRef<number | null>(null);
  const copilotFreshOnOpenAppliedRef = useRef(false);
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
  const [otpInput, setOtpInput] = useState("");
  const [otpError, setOtpError] = useState("");
  const [cardOtpVerifying, setCardOtpVerifying] = useState(false);
  const [verifiedCardDetails, setVerifiedCardDetails] = useState<{
    holder: string;
    number: string;
    type: string;
    expiry: string;
    cvv: string;
    status: string;
    issuedAt: string;
    linkedAccount: string;
    dailyLimit: string;
    contactless: string;
    onlinePayment: string;
    lastActivity: string;
  } | null>(null);
  const [transferOpen, setTransferOpen] = useState(false);
  const [copilotBusy, setCopilotBusy] = useState(false);
  const [copilotInput, setCopilotInput] = useState("");
  const [copilotWorkspace, setCopilotWorkspace] =
    useState<CopilotWorkspaceState>(buildDefaultCopilotWorkspace);
  const [copilotDraftSession, setCopilotDraftSession] =
    useState<CopilotSessionState | null>(null);
  const [copilotHistoryHydrated, setCopilotHistoryHydrated] = useState(false);
  const [copilotRenameSessionId, setCopilotRenameSessionId] = useState("");
  const [copilotRenameDraft, setCopilotRenameDraft] = useState("");
  const [copilotSessionMenuId, setCopilotSessionMenuId] = useState("");
  const [copilotSessionMenuPlacement, setCopilotSessionMenuPlacement] =
    useState<"up" | "down">("down");
  const [copilotMobileHistoryOpen, setCopilotMobileHistoryOpen] =
    useState(false);
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
  const [savedTransferRecipients, setSavedTransferRecipients] = useState<
    SavedTransferRecipient[]
  >([]);
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
  const [transferPinInput, setTransferPinInput] = useState("");
  const [transferPinError, setTransferPinError] = useState("");
  const [transferOtpRequired, setTransferOtpRequired] = useState(false);
  const [transferPinSetupOpen, setTransferPinSetupOpen] = useState(false);
  const [transferPinSetupBusy, setTransferPinSetupBusy] = useState(false);
  const [transferPinSetupError, setTransferPinSetupError] = useState("");
  const [transferPinSetupForm, setTransferPinSetupForm] = useState({
    pin: "",
    confirm: "",
  });
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
  const [transferPinEnabled, setTransferPinEnabled] = useState(false);
  const [transferServerFaceIdRequired, setTransferServerFaceIdRequired] =
    useState(false);
  const [transferServerFaceIdReason, setTransferServerFaceIdReason] =
    useState("");
  const [transferRollingOutflowAmount, setTransferRollingOutflowAmount] =
    useState<number | null>(null);
  const [transferOtpResendAt, setTransferOtpResendAt] = useState(0);
  const [transferOtpClock, setTransferOtpClock] = useState(Date.now());
  const [transferAdvisoryClock, setTransferAdvisoryClock] = useState(
    Date.now(),
  );
  const [transferMonitoring, setTransferMonitoring] =
    useState<AiMonitoringSummary | null>(null);
  const [transferPreviewBusy, setTransferPreviewBusy] = useState(false);
  const [transferOtpBusy, setTransferOtpBusy] = useState(false);
  const [transferOtpVerifyBusy, setTransferOtpVerifyBusy] = useState(false);
  const [transferAdvisory, setTransferAdvisory] =
    useState<TransferSafetyAdvisory | null>(null);
  const [transferAdvisoryAcknowledged, setTransferAdvisoryAcknowledged] =
    useState(false);
  const [transferAiInterventionOpen, setTransferAiInterventionOpen] =
    useState(false);
  const [recentTransactions, setRecentTransactions] = useState<
    RecentTransaction[]
  >([]);
  const [transactionHistory, setTransactionHistory] = useState<
    TransactionHistoryItem[]
  >([]);
  const [dashboardCards, setDashboardCards] = useState<CardCenterCard[]>([]);
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

  const primaryDashboardCard =
    dashboardCards.find((card) => card.isPrimary) || dashboardCards[0] || null;
  const walletDigitsForCard = (wallet?.accountNumber || wallet?.id || "")
    .replace(/\D/g, "")
    .padStart(12, "0");
  const virtualCardNumber = `4${walletDigitsForCard.repeat(4).slice(0, 15)}`
    .replace(/(.{4})/g, "$1 ")
    .trim();
  const virtualCardCvv = String(
    ((walletDigitsForCard
      .split("")
      .map((digit) => Number(digit))
      .reduce((sum, value) => sum + value, 0) %
      900) +
      100) %
      1000 || 382,
  ).padStart(3, "0");
  const cardProfile = {
    holder:
      verifiedCardDetails?.holder ||
      primaryDashboardCard?.holder ||
      user?.name ||
      "FPIPay User",
    number:
      verifiedCardDetails?.number ||
      primaryDashboardCard?.number ||
      virtualCardNumber,
    type:
      verifiedCardDetails?.type ||
      (primaryDashboardCard
        ? `${primaryDashboardCard.type}${primaryDashboardCard.bank ? ` - ${primaryDashboardCard.bank}` : ""}`
        : "Virtual Debit"),
    expiry:
      verifiedCardDetails?.expiry ||
      (primaryDashboardCard
        ? `${primaryDashboardCard.expiryMonth}/${primaryDashboardCard.expiryYear.slice(-2)}`
        : "12/29"),
    cvv: verifiedCardDetails?.cvv || virtualCardCvv,
    status:
      verifiedCardDetails?.status ||
      (primaryDashboardCard?.status === "FROZEN"
        ? "Frozen"
        : primaryDashboardCard
          ? "Active"
          : "Virtual"),
    issuedAt: verifiedCardDetails?.issuedAt
      ? verifiedCardDetails.issuedAt
      : primaryDashboardCard
        ? new Date(primaryDashboardCard.createdAt).toLocaleString("en-US", {
            month: "short",
            day: "2-digit",
            year: "numeric",
          })
        : new Date().toLocaleDateString("en-US", {
            month: "short",
            day: "2-digit",
            year: "numeric",
          }),
    linkedAccount:
      verifiedCardDetails?.linkedAccount ||
      (wallet?.accountNumber ? `Wallet ${wallet.accountNumber}` : "Wallet"),
    dailyLimit:
      verifiedCardDetails?.dailyLimit ||
      (sessionSecurity.restrictLargeTransfers &&
      typeof sessionSecurity.maxTransferAmount === "number"
        ? `$${sessionSecurity.maxTransferAmount.toLocaleString("en-US", {
            minimumFractionDigits: 2,
            maximumFractionDigits: 2,
          })}`
        : "Policy based"),
    contactless:
      verifiedCardDetails?.contactless ||
      (primaryDashboardCard ? "Enabled" : "Virtual"),
    onlinePayment:
      verifiedCardDetails?.onlinePayment ||
      (primaryDashboardCard ? "Enabled" : "Virtual"),
    lastActivity:
      verifiedCardDetails?.lastActivity ||
      (recentTransactions[0]
        ? new Date(recentTransactions[0].createdAt).toLocaleString("en-US")
        : "No recent activity"),
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
  const localTransferPreflightAdvisory =
    useMemo<TransferSafetyAdvisory | null>(() => {
      if (
        !wallet ||
        !Number.isFinite(transferAmountNumber) ||
        transferAmountNumber <= 0
      ) {
        return null;
      }

      const note = transferContent.trim();
      const balance = Math.max(Number(wallet.balance) || 0, 1);
      const ratio = transferAmountNumber / balance;
      const remainingBalance = Math.max(balance - transferAmountNumber, 0);
      const recipientLabel =
        transferReceiverName.trim() ||
        (transferAccount
          ? `account ending ${transferAccount.slice(-4)}`
          : "this recipient");

      const hardBlockedReasons = TRANSFER_HARD_BLOCK_NOTE_PATTERNS.filter(
        (pattern) => pattern.test(note),
      ).map(
        () =>
          "Transfer content contains phrases strongly associated with OTP theft, fake support, or remote-access scams.",
      );

      if (hardBlockedReasons.length > 0) {
        return {
          requestKey: null,
          severity: "blocked",
          title: "High-risk transfer wording detected",
          message: `This payment note looks like a scam script targeting ${recipientLabel}. FPIPay recommends stopping and verifying through an official channel before sending any money.`,
          confirmationLabel: "Blocked for safety review",
          reasons: hardBlockedReasons,
          requiresAcknowledgement: false,
          transferRatio: ratio,
          remainingBalance,
          remainingBalanceRatio: remainingBalance / balance,
          amount: transferAmountNumber,
          currency: wallet.currency || "USD",
          blockedUntil: null,
        };
      }

      const warningReasons: string[] = [];
      if (
        TRANSFER_BLOCKED_NOTE_PATTERNS.some((pattern) => pattern.test(note))
      ) {
        warningReasons.push(
          "Transfer content includes refund, fee, tax, or penalty wording that often appears in scam instructions.",
        );
      }
      if (
        TRANSFER_WARNING_NOTE_PATTERNS.some((pattern) => pattern.test(note))
      ) {
        warningReasons.push(
          "Transfer content includes urgency, investment, or guaranteed-return language often seen in scams.",
        );
      }
      if (
        note &&
        TRANSFER_GENERIC_NOTE_PATTERN.test(note) &&
        transferAmountNumber >= 5000
      ) {
        warningReasons.push(
          "Payment note is too generic for a meaningful transfer and may be hard to verify later.",
        );
      }

      if (warningReasons.length === 0) {
        return null;
      }

      return {
        requestKey: null,
        severity: "warning",
        title: "Pre-transfer safety warning",
        message: `Before sending money to ${recipientLabel}, verify the request through a trusted contact path and confirm why this payment needs this amount and note.`,
        confirmationLabel: "Continue carefully",
        reasons: warningReasons,
        requiresAcknowledgement: false,
        transferRatio: ratio,
        remainingBalance,
        remainingBalanceRatio: remainingBalance / balance,
        amount: transferAmountNumber,
        currency: wallet.currency || "USD",
        blockedUntil: null,
      };
    }, [
      transferAccount,
      transferAmountNumber,
      transferContent,
      transferReceiverName,
      wallet,
    ]);
  const effectiveTransferAdvisory =
    transferAdvisory || localTransferPreflightAdvisory;
  const isTransferHardBlocked =
    effectiveTransferAdvisory?.severity === "blocked";
  const isTransferPreOtpWarning =
    effectiveTransferAdvisory?.severity === "blocked" ||
    effectiveTransferAdvisory?.requiresAcknowledgement === true;
  const transferContinueLabel = transferOtpBusy
    ? "Preparing security check..."
    : isTransferHardBlocked
      ? "Blocked for safety review"
      : "Continue to security";
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
  const copilotStorageKey = user?.id
    ? `${COPILOT_HISTORY_STORAGE_PREFIX}_${user.id}`
    : "";
  const copilotSessions = copilotWorkspace.sessions;
  const activeCommittedCopilotSession = copilotWorkspace.activeSessionId
    ? copilotSessions.find(
        (session) => session.id === copilotWorkspace.activeSessionId,
      ) || null
    : null;
  const activeCopilotSession =
    activeCommittedCopilotSession || copilotDraftSession;
  const copilotMessages =
    activeCopilotSession?.messages || buildDefaultCopilotMessages();
  const copilotDefaultGreeting =
    buildDefaultCopilotMessages()[0]?.content || "";
  const copilotInsight =
    activeCopilotSession?.insight || buildDefaultCopilotInsight();
  const copilotHasInsight = Boolean(
    copilotInsight.topic ||
    copilotInsight.suggestedActions.length ||
    copilotInsight.suggestedDepositAmount ||
    copilotInsight.followUpQuestion,
  );
  const copilotSummaryText =
    copilotInsight.followUpQuestion ||
    copilotInsight.suggestedActions[0] ||
    (copilotInsight.suggestedDepositAmount
      ? `Suggested deposit ${copilotInsight.suggestedDepositAmount.toLocaleString(
          "en-US",
        )}`
      : "");
  const copilotRiskTone =
    copilotInsight.riskLevel === "high" || copilotInsight.riskLevel === "medium"
      ? copilotInsight.riskLevel
      : "low";
  const copilotThreadTitle =
    activeCopilotSession?.title || COPILOT_DEFAULT_TITLE;
  const copilotIsFreshSession =
    copilotMessages.length === 1 && copilotMessages[0]?.role === "assistant";
  const copilotSessionList = [...copilotSessions].sort((a, b) => {
    if (a.pinned !== b.pinned) {
      return a.pinned ? -1 : 1;
    }
    return new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime();
  });
  const transactionHistoryPreview = transactionHistory.slice(0, 3);

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
        recipientName:
          tx.description && tx.description.trim().length > 0
            ? tx.description.trim()
            : tx.metadata?.toAccount
              ? `Account ****${tx.metadata.toAccount.slice(-4)}`
              : undefined,
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

  const parseUserAgentSummary = useCallback(
    (value?: string) => summarizeDeviceUserAgent(value),
    [],
  );

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
      const asStringList = (input: unknown) =>
        Array.isArray(input)
          ? input.filter((item): item is string => typeof item === "string")
          : [];
      const score =
        typeof data.score === "number"
          ? data.score
          : typeof data.anomaly_score === "number"
            ? data.anomaly_score
            : 0;
      const warningRaw =
        data.warning ?? data.warning_vi ?? data.warningVi ?? null;
      const warning =
        warningRaw && typeof warningRaw === "object"
          ? (() => {
              const warningData = warningRaw as Record<string, unknown>;
              return {
                title:
                  typeof warningData.title === "string"
                    ? warningData.title
                    : undefined,
                message:
                  typeof warningData.message === "string"
                    ? warningData.message
                    : undefined,
                doNot: asStringList(warningData.doNot ?? warningData.do_not),
                mustDo: asStringList(warningData.mustDo ?? warningData.must_do),
                promptTemplateId:
                  typeof warningData.promptTemplateId === "string"
                    ? warningData.promptTemplateId
                    : typeof warningData.prompt_template_id === "string"
                      ? warningData.prompt_template_id
                      : undefined,
              };
            })()
          : null;
      const rawRuleHits = data.ruleHits ?? data.rule_hits;
      const ruleHits = Array.isArray(rawRuleHits)
        ? rawRuleHits.flatMap((entry) => {
            if (!entry || typeof entry !== "object") return [];
            const hit = entry as Record<string, unknown>;
            return [
              {
                ruleId:
                  typeof hit.ruleId === "string"
                    ? hit.ruleId
                    : typeof hit.rule_id === "string"
                      ? hit.rule_id
                      : undefined,
                title: typeof hit.title === "string" ? hit.title : undefined,
                reason: typeof hit.reason === "string" ? hit.reason : undefined,
                userWarning:
                  typeof hit.userWarning === "string"
                    ? hit.userWarning
                    : typeof hit.user_warning === "string"
                      ? hit.user_warning
                      : undefined,
                riskLevel:
                  typeof hit.riskLevel === "string"
                    ? hit.riskLevel
                    : typeof hit.risk_level === "string"
                      ? hit.risk_level
                      : undefined,
              },
            ];
          })
        : [];
      return {
        score,
        riskLevel:
          typeof data.riskLevel === "string"
            ? data.riskLevel
            : typeof data.risk_level === "string"
              ? data.risk_level
              : "low",
        baseScore:
          typeof data.baseScore === "number"
            ? data.baseScore
            : typeof data.base_score === "number"
              ? data.base_score
              : null,
        finalScore:
          typeof data.finalScore === "number"
            ? data.finalScore
            : typeof data.final_score === "number"
              ? data.final_score
              : null,
        mitigationScore:
          typeof data.mitigationScore === "number"
            ? data.mitigationScore
            : typeof data.mitigation_score === "number"
              ? data.mitigation_score
              : null,
        reasons: asStringList(data.reasons),
        archetype: typeof data.archetype === "string" ? data.archetype : null,
        timeline: Array.isArray(data.timeline)
          ? data.timeline.filter(
              (item): item is string => typeof item === "string",
            )
          : [],
        headline: typeof data.headline === "string" ? data.headline : null,
        summary: typeof data.summary === "string" ? data.summary : null,
        nextStep:
          typeof data.nextStep === "string"
            ? data.nextStep
            : typeof data.next_step === "string"
              ? data.next_step
              : null,
        recommendedActions: Array.isArray(data.recommendedActions)
          ? data.recommendedActions.filter(
              (item): item is string => typeof item === "string",
            )
          : Array.isArray(data.recommended_actions)
            ? data.recommended_actions.filter(
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
        modelRiskLevel:
          typeof data.modelRiskLevel === "string"
            ? data.modelRiskLevel
            : typeof data.model_risk_level === "string"
              ? data.model_risk_level
              : null,
        ruleRiskLevel:
          typeof data.ruleRiskLevel === "string"
            ? data.ruleRiskLevel
            : typeof data.rule_risk_level === "string"
              ? data.rule_risk_level
              : null,
        finalAction:
          typeof data.finalAction === "string"
            ? data.finalAction
            : typeof data.final_action === "string"
              ? data.final_action
              : null,
        stepUpLevel:
          typeof data.stepUpLevel === "string"
            ? data.stepUpLevel
            : typeof data.step_up_level === "string"
              ? data.step_up_level
              : null,
        ruleScore:
          typeof data.ruleScore === "number"
            ? data.ruleScore
            : typeof data.rule_score === "number"
              ? data.rule_score
              : null,
        ruleHitCount:
          typeof data.ruleHitCount === "number"
            ? data.ruleHitCount
            : typeof data.rule_hit_count === "number"
              ? data.rule_hit_count
              : null,
        ruleHits,
        warning,
        analysisSignals:
          data.analysisSignals &&
          typeof data.analysisSignals === "object" &&
          !Array.isArray(data.analysisSignals)
            ? (data.analysisSignals as Record<string, unknown>)
            : data.analysis_signals &&
                typeof data.analysis_signals === "object" &&
                !Array.isArray(data.analysis_signals)
              ? (data.analysis_signals as Record<string, unknown>)
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
        archetype: typeof data.archetype === "string" ? data.archetype : null,
        timeline: Array.isArray(data.timeline)
          ? data.timeline.filter(
              (item): item is string => typeof item === "string",
            )
          : [],
        recommendedActions: Array.isArray(data.recommendedActions)
          ? data.recommendedActions.filter(
              (item): item is string => typeof item === "string",
            )
          : [],
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
    (amount: number, currency: string) => {
      if (!Number.isFinite(amount)) {
        return `${currency} unavailable`;
      }
      const absolute = Math.abs(amount);
      if (absolute >= 1e15) {
        return `${currency} ${amount.toExponential(2)}`;
      }
      return `${currency} ${amount.toLocaleString("en-US", {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2,
      })}`;
    },
    [],
  );
  const formatTransferBalanceUsage = useCallback((ratio: number) => {
    if (!Number.isFinite(ratio) || ratio <= 0) return "0%";
    const percent = ratio * 100;
    if (percent >= 9999) return ">9,999%";
    if (percent >= 1000)
      return `${Math.round(percent).toLocaleString("en-US")}%`;
    if (percent >= 100) return `${Math.round(percent)}%`;
    return `${percent.toLocaleString("en-US", {
      minimumFractionDigits: 0,
      maximumFractionDigits: 1,
    })}%`;
  }, []);
  const formatTransferHoldCountdown = useCallback((remainingMs: number) => {
    const totalSeconds = Math.max(0, Math.ceil(remainingMs / 1000));
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    if (minutes <= 0) return `${seconds}s`;
    return `${minutes}m ${String(seconds).padStart(2, "0")}s`;
  }, []);

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
      const rawBalance = Number(wallet?.balance) || 0;
      const afterTransferRaw =
        advisory?.remainingBalance ?? rawBalance - amount;
      const blockedUntilMs = advisory?.blockedUntil
        ? Date.parse(advisory.blockedUntil)
        : Number.NaN;
      const holdRemainingMs = Number.isNaN(blockedUntilMs)
        ? 0
        : Math.max(0, blockedUntilMs - transferAdvisoryClock);
      const hasActiveHold = holdRemainingMs > 0;
      const exceedsBalance = !advisory && rawBalance > 0 && amount > rawBalance;
      const afterTransferLabel = exceedsBalance
        ? formatTransferAdvisoryAmount(Math.abs(afterTransferRaw), "USD")
        : formatTransferAdvisoryAmount(Math.max(afterTransferRaw, 0), "USD");
      const recipientLabel =
        transferReceiverName.trim() ||
        (transferAccount
          ? `account ending ${transferAccount.slice(-4)}`
          : "this recipient");
      const confidence =
        typeof monitoring?.score === "number"
          ? Math.max(1, Math.min(99, Math.round(monitoring.score * 100)))
          : tone === "blocked"
            ? 96
            : tone === "warning"
              ? 82
              : tone === "safe"
                ? 28
                : 61;
      const assessmentLabel =
        tone === "blocked"
          ? "High-risk pattern"
          : tone === "warning"
            ? "Step-up recommended"
            : tone === "safe"
              ? "Light anomaly signal"
              : "Review signal detected";
      const actionLabel =
        tone === "blocked"
          ? "Hold transfer"
          : transferStep === 3 && transferServerFaceIdReason
            ? "OTP + FaceID"
            : tone === "warning"
              ? "OTP verification"
              : "Continue review";
      const title =
        tone === "blocked"
          ? `AI risk engine paused transfer to ${recipientLabel}`
          : tone === "warning"
            ? `AI identified unusual signals for ${recipientLabel}`
            : tone === "safe"
              ? `AI noted a low-severity deviation for ${recipientLabel}`
              : `AI is reviewing this transfer to ${recipientLabel}`;

      const message =
        advisory?.message ||
        monitoring?.warning?.message ||
        (tone === "blocked"
          ? `Multiple signals align with patterns that previously required intervention. The transfer is being held pending review.`
          : tone === "warning"
            ? `This transfer is still allowed to continue, but the model sees enough unusual behavior to request stronger verification before release.`
            : tone === "safe"
              ? `The model noticed a mild deviation from your normal transfer behavior. This does not indicate confirmed fraud, but it is worth reviewing before approval.`
              : `The model found a few unusual features compared with your recent transfer behavior.`);

      const reasonPool = [
        ...(external && transferStep === 3 && transferServerFaceIdReason
          ? [transferServerFaceIdReason]
          : []),
        ...(advisory?.reasons || []),
        ...(monitoring?.reasons || []),
        ...(monitoring?.ruleHits || []).flatMap((hit) =>
          [hit.userWarning, hit.reason, hit.title].filter(
            (value): value is string =>
              typeof value === "string" && value.trim().length > 0,
          ),
        ),
        ...((monitoring?.warning?.mustDo || []).map((item) => `Do: ${item}`) ||
          []),
        ...((monitoring?.warning?.doNot || []).map(
          (item) => `Do not: ${item}`,
        ) || []),
      ];
      const reasons = reasonPool
        .map((item) => item.replace(/\s+/g, " ").trim())
        .filter((item, index, arr) => item && arr.indexOf(item) === index)
        .slice(0, 4);
      const recommendedActions = [
        ...(advisory?.recommendedActions || []),
        ...(monitoring?.recommendedActions || []),
      ]
        .map((item) => item.replace(/\s+/g, " ").trim())
        .filter((item, index, arr) => item && arr.indexOf(item) === index)
        .slice(0, 3);
      const timeline = [
        ...(advisory?.timeline || []),
        ...(monitoring?.timeline || []),
      ]
        .map((item) => item.replace(/\s+/g, " ").trim())
        .filter((item, index, arr) => item && arr.indexOf(item) === index)
        .slice(0, 4);
      const archetype = advisory?.archetype || monitoring?.archetype || "";

      return (
        <aside
          className={`transfer-ai-amount-panel transfer-ai-amount-panel-${tone} ${
            external ? "external" : ""
          }`}
        >
          <div className="transfer-ai-amount-head">
            <span className="transfer-ai-amount-badge">AI Risk Analyst</span>
            <span className={`transfer-advisory-pill ${tone}`}>
              {tone === "blocked"
                ? "Blocked"
                : tone === "warning"
                  ? "Step-up"
                  : tone === "safe"
                    ? "Observed"
                    : "Review"}
            </span>
          </div>
          <div className="transfer-ai-amount-summary">
            <div>
              <span>Assessment</span>
              <strong>{assessmentLabel}</strong>
            </div>
            <div>
              <span>Confidence</span>
              <strong>{confidence}%</strong>
            </div>
            <div>
              <span>Next action</span>
              <strong>{actionLabel}</strong>
            </div>
          </div>
          <strong>{title}</strong>
          {archetype ? (
            <p className="transfer-ai-amount-archetype">Pattern: {archetype}</p>
          ) : null}
          <p>{message}</p>
          {advisory?.blockedUntil ? (
            <div className="transfer-advisory-hold-banner" role="status">
              <strong>
                {hasActiveHold
                  ? `Wait ${formatTransferHoldCountdown(holdRemainingMs)} before retrying this transfer.`
                  : "The temporary hold has expired. You can retry now."}
              </strong>
              <span>
                Release time:{" "}
                {new Date(advisory.blockedUntil).toLocaleString("en-US")}.
              </span>
            </div>
          ) : null}
          <dl className="transfer-ai-amount-metrics">
            <div>
              <dt>Amount</dt>
              <dd>{formatTransferAdvisoryAmount(amount, "USD")}</dd>
            </div>
            <div>
              <dt>Balance used</dt>
              <dd>
                {exceedsBalance
                  ? "Exceeds balance"
                  : formatTransferBalanceUsage(balanceUsed)}
              </dd>
            </div>
            <div>
              <dt>{exceedsBalance ? "Shortfall" : "After"}</dt>
              <dd>{afterTransferLabel}</dd>
            </div>
          </dl>
          {reasons.length > 0 ? (
            <ul>
              {reasons.map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
          ) : null}
          {recommendedActions.length > 0 ? (
            <ul>
              {recommendedActions.map((action) => (
                <li key={action}>{action}</li>
              ))}
            </ul>
          ) : null}
          {timeline.length > 0 ? (
            <ul>
              {timeline.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ul>
          ) : null}
        </aside>
      );
    },
    [
      formatTransferBalanceUsage,
      formatTransferAdvisoryAmount,
      formatTransferHoldCountdown,
      transferAccount,
      transferAmount,
      transferAdvisoryClock,
      transferReceiverName,
      transferServerFaceIdReason,
      transferStep,
      wallet?.balance,
    ],
  );

  const visibleTransferMonitoring = useMemo(() => {
    if (!transferMonitoring) return null;
    const riskLevel = transferMonitoring.riskLevel.toLowerCase();
    if (riskLevel === "low") return null;
    const filteredReasons = transferMonitoring.reasons.filter(
      (reason) => reason !== "AI monitoring unavailable",
    );
    if (filteredReasons.length === 0) {
      return null;
    }
    return {
      ...transferMonitoring,
      reasons: filteredReasons,
    };
  }, [transferMonitoring]);
  const transferBlockedUntilMs = transferAdvisory?.blockedUntil
    ? Date.parse(transferAdvisory.blockedUntil)
    : Number.NaN;
  const isTransferHoldActive =
    transferAdvisory?.severity === "blocked" &&
    !Number.isNaN(transferBlockedUntilMs) &&
    transferBlockedUntilMs > transferAdvisoryClock;
  const transferHoldRemainingLabel = isTransferHoldActive
    ? formatTransferHoldCountdown(
        transferBlockedUntilMs - transferAdvisoryClock,
      )
    : "";
  const transferAiIntervention = useMemo(() => {
    const monitoring = visibleTransferMonitoring;
    const advisory = effectiveTransferAdvisory;
    if (!advisory && !monitoring) return null;

    const monitoringRisk = (monitoring?.riskLevel || "").toLowerCase();
    const monitoringFinalAction = (monitoring?.finalAction || "").toUpperCase();
    const requiresStrongStepUp =
      monitoringFinalAction === "HOLD_REVIEW" ||
      monitoringFinalAction === "REQUIRE_OTP_FACE_ID";
    const requiresOtpStepUp = monitoringFinalAction === "REQUIRE_OTP";
    const allowsWithWarning = monitoringFinalAction === "ALLOW_WITH_WARNING";
    const tone =
      advisory?.severity === "blocked" || isTransferHoldActive
        ? "blocked"
        : advisory?.severity === "warning" ||
            requiresStrongStepUp ||
            requiresOtpStepUp
          ? "warning"
          : allowsWithWarning || monitoringRisk === "high"
            ? "caution"
            : "caution";
    const recipientLabel =
      transferReceiverName.trim() ||
      (transferAccount
        ? `account ending ${transferAccount.slice(-4)}`
        : "this recipient");
    const amount =
      Number(transferAmount.replace(/,/g, "")) || advisory?.amount || 0;
    const amountLabel = formatTransferAdvisoryAmount(amount, "USD");
    const analysisSignals =
      monitoring?.analysisSignals &&
      typeof monitoring.analysisSignals === "object" &&
      !Array.isArray(monitoring.analysisSignals)
        ? monitoring.analysisSignals
        : null;
    const rapidCashOutRiskScore =
      typeof analysisSignals?.rapidCashOutRiskScore === "number"
        ? analysisSignals.rapidCashOutRiskScore
        : typeof analysisSignals?.rapid_cash_out_risk_score === "number"
          ? analysisSignals.rapid_cash_out_risk_score
          : null;
    const recentInboundAmount24h =
      typeof analysisSignals?.recentInboundAmount24h === "number"
        ? analysisSignals.recentInboundAmount24h
        : typeof analysisSignals?.recent_inbound_amount_24h === "number"
          ? analysisSignals.recent_inbound_amount_24h
          : null;
    const recentAdminTopUpAmount24h =
      typeof analysisSignals?.recentAdminTopUpAmount24h === "number"
        ? analysisSignals.recentAdminTopUpAmount24h
        : typeof analysisSignals?.recent_admin_topup_amount_24h === "number"
          ? analysisSignals.recent_admin_topup_amount_24h
          : null;
    const rapidCashOutSignal =
      rapidCashOutRiskScore !== null && rapidCashOutRiskScore >= 0.45
        ? recentAdminTopUpAmount24h && recentAdminTopUpAmount24h > 0
          ? `A recent ${formatTransferAdvisoryAmount(recentAdminTopUpAmount24h, "USD")} admin top-up is being moved back out unusually quickly.`
          : recentInboundAmount24h && recentInboundAmount24h > 0
            ? `The wallet received ${formatTransferAdvisoryAmount(recentInboundAmount24h, "USD")} recently and this transfer would cash most of it back out too quickly.`
            : "This transfer matches a rapid source-in/source-out cash-out pattern."
        : null;
    const nextAction =
      tone === "blocked"
        ? "Pause and verify independently"
        : transferServerFaceIdReason
          ? "OTP plus live FaceID check"
          : "Review, then release OTP";
    const title =
      tone === "blocked"
        ? "Transfer paused before funds leave your wallet"
        : tone === "warning"
          ? "AI wants one more review before sending OTP"
          : "Quick AI safety review before OTP";
    const summary =
      tone === "blocked"
        ? `This transfer to ${recipientLabel} matches patterns that often appear when attackers test small payments, pressure victims, or route money through unfamiliar recipients. Funds stay in your wallet until the risk clears.`
        : tone === "warning"
          ? `This transfer to ${recipientLabel} can still continue, but the behavior is unusual enough that FPIPay wants you to pause, confirm the recipient, and re-check the purpose before OTP is issued.`
          : `AI noticed a mild deviation for this transfer to ${recipientLabel}. Nothing is confirmed as fraud, but a short review helps prevent accidental or manipulated payments.`;
    const signals = [
      rapidCashOutSignal,
      ...(advisory?.reasons || []),
      ...(monitoring?.reasons || []),
      ...((monitoring?.ruleHits || []).flatMap((hit) =>
        [hit.userWarning, hit.reason, hit.title].filter(
          (value): value is string =>
            typeof value === "string" && value.trim().length > 0,
        ),
      ) || []),
    ]
      .filter(
        (item): item is string =>
          typeof item === "string" && item.trim().length > 0,
      )
      .map((item) => translateTransferRiskCopy(item))
      .filter((item, index, arr) => item && arr.indexOf(item) === index)
      .slice(0, 2);
    const protectSteps = [
      tone === "blocked"
        ? "Verify the recipient using a phone number or channel you already trust."
        : "Confirm the recipient, amount, and payment purpose in a channel you initiated yourself.",
      ...((monitoring?.warning?.mustDo || []).map((item) =>
        item.replace(/^do[:\s-]*/i, "").trim(),
      ) || []),
      ...(advisory?.recommendedActions || []),
      ...(monitoring?.recommendedActions || []),
    ]
      .map((item) => translateTransferRiskCopy(item))
      .filter((item, index, arr) => item && arr.indexOf(item) === index)
      .slice(0, 2);
    const stopList = [
      tone === "blocked"
        ? "Do not continue if someone is guiding you over phone, chat, or screen share."
        : "Do not continue if you feel rushed or are being told to bypass security checks.",
      ...((monitoring?.warning?.doNot || []).map((item) =>
        item.replace(/^do not[:\s-]*/i, "").trim(),
      ) || []),
    ]
      .map((item) => translateTransferRiskCopy(item))
      .filter((item, index, arr) => item && arr.indexOf(item) === index)
      .slice(0, 1);
    const timeline = [
      ...(advisory?.timeline || []),
      ...(monitoring?.timeline || []),
    ]
      .map((item) => translateTransferRiskCopy(item))
      .filter((item, index, arr) => item && arr.indexOf(item) === index)
      .slice(0, 2);
    const shouldPrompt =
      tone === "blocked" ||
      isTransferHoldActive ||
      advisory?.severity === "warning" ||
      advisory?.requiresAcknowledgement === true ||
      requiresStrongStepUp ||
      requiresOtpStepUp;

    return {
      tone,
      title,
      summary,
      recipientLabel,
      amountLabel,
      nextAction,
      confidence:
        typeof monitoring?.finalScore === "number"
          ? Math.max(1, Math.min(99, Math.round(monitoring.finalScore)))
          : typeof monitoring?.score === "number"
            ? Math.max(1, Math.min(99, Math.round(monitoring.score * 100)))
            : tone === "blocked"
              ? 96
              : tone === "warning"
                ? 82
                : 61,
      statusLabel:
        tone === "blocked"
          ? "Protection pause"
          : tone === "warning"
            ? "Step-up warning"
            : "Trust check",
      primaryLabel:
        tone === "blocked" || isTransferHoldActive
          ? "Understood"
          : translateTransferRiskCopy(advisory?.confirmationLabel) ||
            "I reviewed the warning, continue to OTP",
      signals,
      protectSteps,
      stopList,
      timeline,
      archetype: advisory?.archetype || monitoring?.archetype || "",
      shouldPrompt,
    };
  }, [
    effectiveTransferAdvisory,
    formatTransferAdvisoryAmount,
    isTransferHoldActive,
    transferAccount,
    transferAmount,
    transferReceiverName,
    transferServerFaceIdReason,
    visibleTransferMonitoring,
  ]);

  useEffect(() => {
    if (!token || transferStep !== 2) {
      setTransferPreviewBusy(false);
      return;
    }
    if (
      !transferAccount.trim() ||
      !transferReceiverName.trim() ||
      !Number.isFinite(transferAmountNumber) ||
      transferAmountNumber <= 0
    ) {
      setTransferPreviewBusy(false);
      setTransferMonitoring(null);
      setTransferAdvisory(null);
      setTransferAiInterventionOpen(false);
      setTransferServerFaceIdRequired(false);
      setTransferServerFaceIdReason("");
      setTransferRollingOutflowAmount(null);
      return;
    }

    const controller = new AbortController();
    const timer = window.setTimeout(async () => {
      setTransferPreviewBusy(true);
      try {
        const resp = await fetch(`${API_BASE}/transfer/preview`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            toAccount: transferAccount,
            amount: transferAmountNumber,
            note: transferContent || defaultTransferContent,
          }),
          signal: controller.signal,
        });
        const data = (await resp.json().catch(() => null)) as {
          error?: string;
          anomaly?: unknown;
          transferAdvisory?: unknown;
          faceIdRequired?: boolean;
          faceIdReason?: string;
          rollingOutflowAmount?: number;
        } | null;
        if (!resp.ok) {
          setTransferMonitoring(null);
          setTransferAdvisory(localTransferPreflightAdvisory);
          setTransferAiInterventionOpen(false);
          setTransferServerFaceIdRequired(false);
          setTransferServerFaceIdReason("");
          setTransferRollingOutflowAmount(null);
          return;
        }
        const monitoring = parseAiMonitoringSummary(data?.anomaly);
        const advisory = parseTransferSafetyAdvisory(data?.transferAdvisory);
        setTransferMonitoring(monitoring);
        setTransferAdvisory(advisory);
        setTransferServerFaceIdRequired(data?.faceIdRequired === true);
        setTransferServerFaceIdReason(data?.faceIdReason || "");
        setTransferRollingOutflowAmount(
          typeof data?.rollingOutflowAmount === "number"
            ? data.rollingOutflowAmount
            : null,
        );
      } catch (error) {
        if ((error as Error).name === "AbortError") return;
      } finally {
        if (!controller.signal.aborted) {
          setTransferPreviewBusy(false);
        }
      }
    }, 350);

    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [
    defaultTransferContent,
    localTransferPreflightAdvisory,
    parseAiMonitoringSummary,
    token,
    transferAccount,
    transferAmountNumber,
    transferContent,
    transferReceiverName,
    transferStep,
  ]);

  useEffect(() => {
    if (!transferOpen || transferStep !== 3) {
      setTransferAiInterventionOpen(false);
    }
  }, [transferOpen, transferStep]);

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
          const signupTestBonus = getSignupTestBalanceBonus(user?.id);
          setWallet({
            ...w,
            balance: Number(w.balance || 0) + signupTestBonus,
          });
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
    [buildTransactionReceipt, token, user?.id],
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
    if (!content || copilotBusy || !activeCopilotSession) {
      return;
    }

    const isDraftSession =
      !copilotWorkspace.activeSessionId &&
      Boolean(copilotDraftSession) &&
      activeCopilotSession.id === copilotDraftSession?.id;
    const nextMessages: CopilotMessage[] = [
      ...activeCopilotSession.messages,
      { role: "user", content },
    ];
    const nextTitle =
      activeCopilotSession.messages.length <= 1 &&
      activeCopilotSession.title === COPILOT_DEFAULT_TITLE
        ? buildCopilotSessionTitle(content)
        : activeCopilotSession.title;
    const nextUpdatedAt = new Date().toISOString();
    const targetSessionId = activeCopilotSession.id;
    if (isDraftSession) {
      setCopilotWorkspace((current) => ({
        activeSessionId: targetSessionId,
        sessions: [
          {
            ...activeCopilotSession,
            title: nextTitle,
            updatedAt: nextUpdatedAt,
            messages: nextMessages,
          },
          ...current.sessions,
        ].slice(0, 20),
      }));
      setCopilotDraftSession(null);
    } else {
      setCopilotWorkspace((current) => ({
        ...current,
        sessions: current.sessions.map((session) =>
          session.id === targetSessionId
            ? {
                ...session,
                title: nextTitle,
                updatedAt: nextUpdatedAt,
                messages: nextMessages,
              }
            : session,
        ),
      }));
    }
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
        return;
      }

      const assistantMessage = data.followUpQuestion
        ? `${data.reply}\n\n${data.followUpQuestion}`
        : data.reply;
      setCopilotWorkspace((current) => ({
        ...current,
        sessions: current.sessions.map((session) =>
          session.id === targetSessionId
            ? {
                ...session,
                title: nextTitle,
                updatedAt: new Date().toISOString(),
                messages: [
                  ...nextMessages,
                  { role: "assistant", content: assistantMessage },
                ],
                insight: {
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
                },
              }
            : session,
        ),
      }));
    } catch (error) {
      const isTimeout =
        error instanceof DOMException && error.name === "AbortError";
      toast(
        isTimeout
          ? "AI copilot took too long to respond. Local 7B replies can take up to a minute."
          : "Cannot reach AI copilot right now.",
        "error",
      );
    } finally {
      window.clearTimeout(timeout);
      setCopilotBusy(false);
    }
  };

  useEffect(() => {
    if (mode !== "copilot") return;
    const thread = copilotThreadRef.current;
    if (!thread) return;
    thread.scrollTo({
      top: thread.scrollHeight,
      behavior: "smooth",
    });
  }, [mode, copilotMessages, copilotBusy]);

  useEffect(() => {
    if (!copilotSessionMenuId) return;
    const handlePointerDown = (event: MouseEvent) => {
      const target = event.target as HTMLElement | null;
      if (target?.closest(".ai-copilot-session-menu-wrap")) return;
      setCopilotSessionMenuId("");
    };
    window.addEventListener("mousedown", handlePointerDown);
    return () => window.removeEventListener("mousedown", handlePointerDown);
  }, [copilotSessionMenuId]);

  useEffect(() => {
    if (!copilotStorageKey) {
      setCopilotWorkspace(buildDefaultCopilotWorkspace());
      return;
    }

    try {
      const raw = localStorage.getItem(copilotStorageKey);
      if (!raw) {
        setCopilotWorkspace(buildDefaultCopilotWorkspace());
        return;
      }

      const parsed = JSON.parse(raw) as Partial<CopilotWorkspaceState> | null;
      const nextSessions = Array.isArray(parsed?.sessions)
        ? parsed.sessions
            .filter(
              (session): session is CopilotSessionState =>
                Boolean(session) &&
                typeof session === "object" &&
                typeof (session as { id?: unknown }).id === "string" &&
                typeof (session as { title?: unknown }).title === "string" &&
                Array.isArray((session as { messages?: unknown }).messages),
            )
            .map((session) => ({
              id: session.id,
              title: session.title || COPILOT_DEFAULT_TITLE,
              pinned: Boolean(session.pinned),
              createdAt: session.createdAt || new Date().toISOString(),
              updatedAt: session.updatedAt || new Date().toISOString(),
              messages:
                session.messages.filter(
                  (item): item is CopilotMessage =>
                    Boolean(item) &&
                    typeof item === "object" &&
                    ((item as { role?: unknown }).role === "user" ||
                      (item as { role?: unknown }).role === "assistant") &&
                    typeof (item as { content?: unknown }).content === "string",
                ) || buildDefaultCopilotMessages(),
              insight: {
                ...buildDefaultCopilotInsight(),
                ...(session.insight || {}),
              },
            }))
        : [];
      const fallbackWorkspace = buildDefaultCopilotWorkspace();
      const sessions = nextSessions.length
        ? nextSessions.map((session) => ({
            ...session,
            messages: session.messages.length
              ? session.messages
              : buildDefaultCopilotMessages(),
          }))
        : fallbackWorkspace.sessions;
      const activeSessionId =
        parsed?.activeSessionId &&
        sessions.some((session) => session.id === parsed.activeSessionId)
          ? parsed.activeSessionId
          : sessions[0].id;

      setCopilotWorkspace({ activeSessionId, sessions });
    } catch {
      setCopilotWorkspace(buildDefaultCopilotWorkspace());
    }
  }, [copilotStorageKey]);

  useEffect(() => {
    if (!copilotStorageKey || !token) {
      setCopilotHistoryHydrated(true);
      return;
    }

    const controller = new AbortController();
    let cancelled = false;
    setCopilotHistoryHydrated(false);

    const loadCopilotHistory = async () => {
      try {
        const resp = await fetch(`${API_BASE}/ai/copilot-history`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
        });
        const data = (await resp.json().catch(() => null)) as
          | Partial<CopilotWorkspaceState>
          | { error?: string }
          | null;

        if (
          cancelled ||
          !resp.ok ||
          !isCopilotWorkspaceShape(data) ||
          !Array.isArray(data.sessions)
        ) {
          return;
        }

        const sessions = data.sessions
          .filter(
            (session): session is CopilotSessionState =>
              Boolean(session) &&
              typeof session === "object" &&
              typeof (session as { id?: unknown }).id === "string" &&
              Array.isArray((session as { messages?: unknown }).messages),
          )
          .map((session) => ({
            id: session.id,
            title: session.title || COPILOT_DEFAULT_TITLE,
            pinned: Boolean(session.pinned),
            createdAt: session.createdAt || new Date().toISOString(),
            updatedAt: session.updatedAt || new Date().toISOString(),
            messages: session.messages.filter(
              (item): item is CopilotMessage =>
                Boolean(item) &&
                typeof item === "object" &&
                ((item as { role?: unknown }).role === "user" ||
                  (item as { role?: unknown }).role === "assistant") &&
                typeof (item as { content?: unknown }).content === "string",
            ),
            insight: {
              ...buildDefaultCopilotInsight(),
              ...(session.insight || {}),
            },
          }));

        if (!sessions.length) return;

        setCopilotWorkspace({
          activeSessionId:
            typeof data.activeSessionId === "string" &&
            sessions.some((session) => session.id === data.activeSessionId)
              ? data.activeSessionId
              : sessions[0].id,
          sessions: sessions.map((session) => ({
            ...session,
            messages: session.messages.length
              ? session.messages
              : buildDefaultCopilotMessages(),
          })),
        });
      } catch {
        // keep local cache fallback
      } finally {
        if (!cancelled) {
          setCopilotHistoryHydrated(true);
        }
      }
    };

    void loadCopilotHistory();

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [copilotStorageKey, token]);

  useEffect(() => {
    if (!copilotStorageKey) return;
    try {
      localStorage.setItem(copilotStorageKey, JSON.stringify(copilotWorkspace));
    } catch {
      // ignore storage issues
    }
  }, [copilotStorageKey, copilotWorkspace]);

  useEffect(() => {
    if (!copilotStorageKey || !token || !copilotHistoryHydrated) return;
    if (copilotPersistTimerRef.current !== null) {
      window.clearTimeout(copilotPersistTimerRef.current);
    }

    const payload: CopilotWorkspaceState = copilotWorkspace;

    copilotPersistTimerRef.current = window.setTimeout(() => {
      void fetch(`${API_BASE}/ai/copilot-history`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      }).catch(() => {
        // keep local cache if server sync fails
      });
    }, 450);

    return () => {
      if (copilotPersistTimerRef.current !== null) {
        window.clearTimeout(copilotPersistTimerRef.current);
        copilotPersistTimerRef.current = null;
      }
    };
  }, [copilotHistoryHydrated, copilotStorageKey, copilotWorkspace, token]);

  useEffect(() => {
    if (mode !== "copilot") {
      copilotFreshOnOpenAppliedRef.current = false;
      return;
    }
    if (!copilotHistoryHydrated || copilotFreshOnOpenAppliedRef.current) {
      return;
    }
    copilotFreshOnOpenAppliedRef.current = true;
    const nextSession = buildDefaultCopilotSession();
    setCopilotWorkspace((current) => ({
      ...current,
      activeSessionId: "",
    }));
    setCopilotDraftSession(nextSession);
    setCopilotInput("");
    setCopilotSessionMenuId("");
    setCopilotRenameSessionId("");
    setCopilotRenameDraft("");
  }, [mode, copilotHistoryHydrated]);

  const resetCopilotConversation = useCallback(() => {
    const nextSession = buildDefaultCopilotSession();
    setCopilotWorkspace((current) => ({
      ...current,
      activeSessionId: "",
    }));
    setCopilotDraftSession(nextSession);
    setCopilotRenameSessionId("");
    setCopilotRenameDraft("");
    setCopilotSessionMenuId("");
    setCopilotInput("");
  }, []);

  const selectCopilotSession = useCallback((sessionId: string) => {
    setCopilotWorkspace((current) =>
      current.sessions.some((session) => session.id === sessionId)
        ? { ...current, activeSessionId: sessionId }
        : current,
    );
    setCopilotDraftSession(null);
    setCopilotRenameSessionId("");
    setCopilotRenameDraft("");
    setCopilotSessionMenuId("");
    setCopilotInput("");
  }, []);

  const startCopilotRename = useCallback((session: CopilotSessionState) => {
    setCopilotRenameSessionId(session.id);
    setCopilotRenameDraft(session.title);
    setCopilotSessionMenuId("");
  }, []);

  const commitCopilotRename = useCallback(() => {
    if (!copilotRenameSessionId) return;
    const nextTitle = buildCopilotSessionTitle(copilotRenameDraft);
    setCopilotWorkspace((current) => ({
      ...current,
      sessions: current.sessions.map((session) =>
        session.id === copilotRenameSessionId
          ? {
              ...session,
              title: nextTitle,
              updatedAt: new Date().toISOString(),
            }
          : session,
      ),
    }));
    setCopilotRenameSessionId("");
    setCopilotRenameDraft("");
    setCopilotSessionMenuId("");
  }, [copilotRenameDraft, copilotRenameSessionId]);

  const toggleCopilotSessionPin = useCallback((sessionId: string) => {
    setCopilotWorkspace((current) => ({
      ...current,
      sessions: current.sessions.map((session) =>
        session.id === sessionId
          ? {
              ...session,
              pinned: !session.pinned,
              updatedAt: new Date().toISOString(),
            }
          : session,
      ),
    }));
    setCopilotSessionMenuId("");
  }, []);

  const deleteCopilotSession = useCallback(
    (sessionId: string) => {
      setCopilotWorkspace((current) => {
        const remaining = current.sessions.filter(
          (session) => session.id !== sessionId,
        );
        if (!remaining.length) {
          return {
            activeSessionId: "",
            sessions: [],
          };
        }
        const nextActiveId =
          current.activeSessionId === sessionId
            ? remaining[0].id
            : current.activeSessionId;
        return {
          activeSessionId: nextActiveId,
          sessions: remaining,
        };
      });
      // Keep a draft conversation ready so the user can type immediately
      // without forcing a persisted default conversation into history.
      setCopilotDraftSession((current) =>
        current ? current : buildDefaultCopilotSession(),
      );
      if (copilotRenameSessionId === sessionId) {
        setCopilotRenameSessionId("");
        setCopilotRenameDraft("");
      }
      setCopilotSessionMenuId("");
    },
    [copilotRenameSessionId],
  );

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
    if (!token || !user?.id) {
      setDashboardCards([]);
      return;
    }
    let cancelled = false;
    const loadDashboardCards = async () => {
      try {
        const resp = await fetch(`${API_BASE}/cards`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = (await resp.json().catch(() => null)) as {
          cards?: CardCenterCard[];
        } | null;
        if (!resp.ok || !Array.isArray(data?.cards) || cancelled) {
          if (!cancelled) setDashboardCards([]);
          return;
        }
        setDashboardCards(data.cards);
      } catch {
        if (!cancelled) setDashboardCards([]);
      }
    };
    void loadDashboardCards();
    return () => {
      cancelled = true;
    };
  }, [token, user?.id]);

  useEffect(() => {
    void refreshSecurityAlerts({ silent: true });
  }, [refreshSecurityAlerts]);

  useEffect(() => {
    if (!user || !token) {
      setTransferFaceIdEnabled(false);
      setTransferPinEnabled(false);
      setSavedTransferRecipients([]);
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
        setTransferPinEnabled(data.metadata?.transferPinEnabled === true);
        setSavedTransferRecipients(
          normalizeSavedTransferRecipients(
            data.metadata?.recentTransferRecipients,
          ),
        );
      } catch {
        if (!cancelled) {
          setTransferFaceIdEnabled(false);
          setTransferPinEnabled(false);
          setSavedTransferRecipients([]);
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

    const interval = window.setInterval(refreshIfVisible, 20000);
    window.addEventListener("focus", refreshIfVisible);
    document.addEventListener("visibilitychange", refreshIfVisible);

    return () => {
      window.clearInterval(interval);
      window.removeEventListener("focus", refreshIfVisible);
      document.removeEventListener("visibilitychange", refreshIfVisible);
    };
  }, [refreshSecurityAlerts, refreshWalletSnapshot, token]);

  const openDetailsModal = () => {
    setDetailsModalOpen(true);
    setDetailsStep("otp");
    setOtpInput("");
    setOtpError("");
    setVerifiedCardDetails(null);
  };

  const closeDetailsModal = () => {
    setDetailsModalOpen(false);
    setOtpInput("");
    setOtpError("");
    setVerifiedCardDetails(null);
    setDetailsStep("otp");
  };

  const verifyOtpAndShowDetails = async () => {
    if (!/^\d{6}$/.test(otpInput)) {
      setOtpError("Passcode must be exactly 6 digits.");
      return;
    }
    if (!token) {
      setOtpError("Session expired. Please login again.");
      return;
    }
    setCardOtpVerifying(true);
    try {
      const resp = await fetch(`${API_BASE}/card/details/pin/verify`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          pin: otpInput,
        }),
      });
      const data = (await resp.json().catch(() => null)) as {
        error?: string;
        cardDetails?: {
          holder?: string;
          number?: string;
          type?: string;
          expiry?: string;
          cvv?: string;
          status?: string;
          issuedAt?: string;
          linkedAccount?: string;
          dailyLimit?: string;
          contactless?: string;
          onlinePayment?: string;
          lastActivity?: string;
        };
      } | null;
      if (!resp.ok) {
        setOtpError(data?.error || "6-digit passcode verification failed");
        return;
      }
      if (data?.cardDetails) {
        setVerifiedCardDetails({
          holder: data.cardDetails.holder || "",
          number: data.cardDetails.number || "",
          type: data.cardDetails.type || "",
          expiry: data.cardDetails.expiry || "",
          cvv: data.cardDetails.cvv || "",
          status: data.cardDetails.status || "",
          issuedAt: data.cardDetails.issuedAt || "",
          linkedAccount: data.cardDetails.linkedAccount || "",
          dailyLimit: data.cardDetails.dailyLimit || "",
          contactless: data.cardDetails.contactless || "",
          onlinePayment: data.cardDetails.onlinePayment || "",
          lastActivity: data.cardDetails.lastActivity || "",
        });
      }
      setOtpError("");
      setDetailsStep("details");
      toast("Passcode verified successfully");
    } catch {
      setOtpError("Cannot connect to API server.");
    } finally {
      setCardOtpVerifying(false);
    }
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
    setTransferPinInput("");
    setTransferPinError("");
    setTransferOtpRequired(false);
    setTransferPinSetupOpen(false);
    setTransferPinSetupBusy(false);
    setTransferPinSetupError("");
    setTransferPinSetupForm({ pin: "", confirm: "" });
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
    setTransferPreviewBusy(false);
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
    const blockedUntil = transferAdvisory?.blockedUntil;
    if (!blockedUntil) return;
    const blockedUntilMs = Date.parse(blockedUntil);
    if (Number.isNaN(blockedUntilMs) || blockedUntilMs <= Date.now()) return;
    setTransferAdvisoryClock(Date.now());
    const timer = window.setInterval(
      () => setTransferAdvisoryClock(Date.now()),
      1000,
    );
    return () => window.clearInterval(timer);
  }, [transferAdvisory?.blockedUntil]);

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

  const applyCompletedTransferResult = useCallback(
    async (
      transferPayload: {
        anomaly?: unknown;
        transaction?: {
          id: string;
          toAccount?: string;
        };
      } | null,
    ) => {
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
      const confirmedMonitoring = parseAiMonitoringSummary(
        transferPayload?.anomaly,
      );
      if (
        confirmedMonitoring &&
        confirmedMonitoring.riskLevel.toLowerCase() !== "low"
      ) {
        setTransferMonitoring(confirmedMonitoring);
      } else {
        setTransferMonitoring(null);
      }
      setTransferAdvisory(null);
      const targetAccount =
        transferPayload?.transaction?.toAccount || transferAccount;
      const occurredAt = new Date().toISOString();
      setTransferReceipt({
        txId: transferPayload?.transaction?.id || txId,
        executedAt,
        fromAccount: wallet?.accountNumber || "Primary Checking",
        toAccount: targetAccount,
        recipientName:
          transferReceiverName.trim() ||
          `Account ****${targetAccount.slice(-4)}`,
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
            recipientName:
              transferReceiverName.trim() ||
              `Account ****${targetAccount.slice(-4)}`,
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
      setSavedTransferRecipients((prev) =>
        upsertSavedTransferRecipient(prev, {
          accountNumber: targetAccount,
          holderName:
            transferReceiverName.trim() ||
            `Account ****${targetAccount.slice(-4)}`,
          userId: transferRecipientUserId,
          occurredAt,
        }),
      );
      setTransferFaceVerifyOpen(false);
      setTransferOpen(true);
      setTransferFaceProof(null);
      setTransferFaceResetKey((value) => value + 1);
      setTransferFaceVerifyBusy(false);
      await refreshWalletSnapshot({ force: true });
      goToTransferStep(4);
      toast("Transfer completed successfully");
    },
    [
      defaultTransferContent,
      goToTransferStep,
      refreshWalletSnapshot,
      toast,
      transferAccount,
      transferAmount,
      transferContent,
      transferReceiverName,
      transferRecipientUserId,
      wallet?.accountNumber,
    ],
  );

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
          transferPin: transferPinInput,
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
        status?: string;
        error?: string;
        otpRequired?: boolean;
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
        setTransferAiInterventionOpen(true);
        return false;
      }

      if (resp.ok && data?.status === "completed") {
        setTransferAdvisoryAcknowledged(
          options?.advisoryAcknowledged === true ||
            transferAdvisoryAcknowledged ||
            Boolean(advisory),
        );
        setTransferOtpRequired(false);
        setTransferOtpChallengeId("");
        setTransferOtpDestination("");
        setTransferOtpExpiresAt("");
        setTransferOtpInput("");
        setTransferOtpError("");
        setTransferPinError("");
        await applyCompletedTransferResult(data);
        return true;
      }

      if (!resp.ok || !data?.challengeId) {
        const errorMessage = data?.error || "Failed to continue transfer";
        setTransferPinError(/pin/i.test(errorMessage) ? errorMessage : "");
        if (/must create a 6-digit transfer pin/i.test(errorMessage)) {
          setTransferPinSetupError("");
          setTransferPinSetupForm({ pin: "", confirm: "" });
          setTransferPinSetupOpen(true);
        }
        if (!/pin/i.test(errorMessage)) {
          setTransferOtpError(errorMessage);
        }
        toast(errorMessage, "error");
        return false;
      }
      setTransferAdvisoryAcknowledged(
        options?.advisoryAcknowledged === true ||
          transferAdvisoryAcknowledged ||
          Boolean(advisory),
      );
      setTransferOtpRequired(data.otpRequired === true);
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
      setTransferPinError("");
      toast(
        data.destination
          ? `OTP sent to ${data.destination}`
          : "OTP sent to your email",
        "info",
      );
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
    if (localTransferPreflightAdvisory?.severity === "blocked") {
      toast(
        localTransferPreflightAdvisory.title ||
          "This transfer is blocked for safety review.",
        "error",
      );
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
    if (!transferPinEnabled) {
      setTransferPinSetupError("");
      setTransferPinSetupForm({ pin: "", confirm: "" });
      setTransferPinSetupOpen(true);
      return;
    }
    setTransferPinError("");
    setTransferOtpError("");
    setTransferOtpRequired(false);
    setTransferOtpChallengeId("");
    setTransferOtpDestination("");
    setTransferOtpExpiresAt("");
    setTransferOtpInput("");
    goToTransferStep(3);
  };

  const closeTransferFaceVerification = useCallback(() => {
    setTransferFaceVerifyOpen(false);
    setTransferOpen(true);
    goToTransferStep(3);
    setTransferFaceProof(null);
    setTransferFaceResetKey((value) => value + 1);
    setTransferFaceVerifyBusy(false);
  }, []);

  const submitTransferPinSetup = useCallback(async () => {
    if (!token) {
      toast("Session expired. Please login again.", "error");
      return false;
    }
    if (!/^\d{6}$/.test(transferPinSetupForm.pin)) {
      setTransferPinSetupError("Transfer PIN must be exactly 6 digits.");
      return false;
    }
    if (transferPinSetupForm.pin !== transferPinSetupForm.confirm) {
      setTransferPinSetupError("Transfer PIN confirmation does not match.");
      return false;
    }

    setTransferPinSetupBusy(true);
    try {
      let resp: Response;
      try {
        resp = await fetch(`${API_BASE}/security/transfer-pin`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            newPin: transferPinSetupForm.pin,
          }),
        });
      } catch {
        setTransferPinSetupError("Cannot connect to API server.");
        return false;
      }

      const data = (await resp.json().catch(() => null)) as {
        error?: string;
        message?: string;
        metadata?: Record<string, unknown>;
      } | null;
      if (!resp.ok) {
        setTransferPinSetupError(
          data?.error || "Failed to create transfer PIN.",
        );
        return false;
      }

      setTransferPinEnabled(data?.metadata?.transferPinEnabled === true);
      setTransferPinInput(transferPinSetupForm.pin);
      setTransferPinSetupError("");
      setTransferPinSetupForm({ pin: "", confirm: "" });
      setTransferPinSetupOpen(false);
      goToTransferStep(3);
      toast(data?.message || "Transfer PIN created successfully.");
      return true;
    } finally {
      setTransferPinSetupBusy(false);
    }
  }, [goToTransferStep, toast, token, transferPinSetupForm]);

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
      await applyCompletedTransferResult(transferPayload);
      return true;
    },
    [
      applyCompletedTransferResult,
      token,
      transferServerFaceIdRequired,
      transferOtpChallengeId,
      transferOtpInput,
      toast,
    ],
  );

  const verifyTransferOtpAndSubmit = async () => {
    if (!/^\d{6}$/.test(transferPinInput)) {
      setTransferPinError("Transfer PIN must be exactly 6 digits.");
      return;
    }
    setTransferPinError("");
    if (!transferOtpRequired) {
      if (
        transferAiIntervention?.shouldPrompt &&
        !transferAdvisoryAcknowledged
      ) {
        setTransferAiInterventionOpen(true);
        return;
      }
      await generateTransferOtp({
        advisoryAcknowledged:
          Boolean(transferAdvisory) ||
          Boolean(transferAiIntervention?.shouldPrompt),
      });
      return;
    }
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
  const closeTransferAiIntervention = useCallback(() => {
    setTransferAiInterventionOpen(false);
  }, []);
  const reviewTransferBeforeProceeding = useCallback(() => {
    setTransferAiInterventionOpen(false);
    setTransferOtpRequired(false);
    setTransferOtpInput("");
    setTransferOtpError("");
    setTransferOtpChallengeId("");
    setTransferOtpDestination("");
    setTransferOtpExpiresAt("");
    goToTransferStep(2);
  }, [goToTransferStep]);
  const proceedTransferAfterAiWarning = useCallback(async () => {
    setTransferAiInterventionOpen(false);
    if (!transferAiIntervention) return;
    if (transferAiIntervention.tone === "blocked" || isTransferHoldActive) {
      return;
    }
    setTransferAdvisoryAcknowledged(true);
    await generateTransferOtp({ advisoryAcknowledged: true });
  }, [generateTransferOtp, isTransferHoldActive, transferAiIntervention]);

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

  useEffect(() => {
    if (mode !== "copilot") {
      setCopilotMobileHistoryOpen(false);
      return;
    }
    const syncMobileDrawer = () => {
      if (window.innerWidth > 960) {
        setCopilotMobileHistoryOpen(false);
      }
    };
    syncMobileDrawer();
    window.addEventListener("resize", syncMobileDrawer);
    const toggleFromHeader = () => {
      setCopilotMobileHistoryOpen((current) => !current);
    };
    window.addEventListener(
      "fpipay-copilot-toggle-history",
      toggleFromHeader as EventListener,
    );
    return () => {
      window.removeEventListener("resize", syncMobileDrawer);
      window.removeEventListener(
        "fpipay-copilot-toggle-history",
        toggleFromHeader as EventListener,
      );
    };
  }, [mode]);

  useEffect(() => {
    if (mode !== "copilot") {
      document.documentElement.style.removeProperty("--fpipay-app-height");
      document.documentElement.style.removeProperty("--fpipay-keyboard-inset");
      return;
    }

    const syncViewportMetrics = () => {
      const viewport = window.visualViewport;
      const appHeight = Math.round(viewport?.height ?? window.innerHeight);
      const keyboardInset = Math.max(
        0,
        Math.round(
          window.innerHeight -
            ((viewport?.height ?? window.innerHeight) +
              (viewport?.offsetTop ?? 0)),
        ),
      );

      document.documentElement.style.setProperty(
        "--fpipay-app-height",
        `${appHeight}px`,
      );
      document.documentElement.style.setProperty(
        "--fpipay-keyboard-inset",
        `${keyboardInset}px`,
      );
    };

    syncViewportMetrics();

    const viewport = window.visualViewport;
    window.addEventListener("resize", syncViewportMetrics);
    viewport?.addEventListener("resize", syncViewportMetrics);
    viewport?.addEventListener("scroll", syncViewportMetrics);

    return () => {
      window.removeEventListener("resize", syncViewportMetrics);
      viewport?.removeEventListener("resize", syncViewportMetrics);
      viewport?.removeEventListener("scroll", syncViewportMetrics);
      document.documentElement.style.removeProperty("--fpipay-app-height");
      document.documentElement.style.removeProperty("--fpipay-keyboard-inset");
    };
  }, [mode]);

  const openCopilotWorkspace = () => {
    onOpenCopilotWorkspace?.();
  };
  const copilotWorkspacePanel = (
    <section className="ai-copilot-page">
      <button
        type="button"
        className={`ai-copilot-mobile-history-backdrop${copilotMobileHistoryOpen ? " open" : ""}`}
        aria-label="Close chat history"
        onClick={() => setCopilotMobileHistoryOpen(false)}
      />
      <div className="ai-copilot-page-shell">
        <aside
          className={`ai-copilot-page-sidebar${copilotMobileHistoryOpen ? " open" : ""}`}
        >
          <div className="ai-copilot-page-sidebar-panel">
            <div className="ai-copilot-page-profile ai-copilot-page-profile-minimal">
              <div className="ai-copilot-page-profile-row">
                <img
                  className="ai-copilot-page-profile-avatar"
                  src={user?.avatar}
                  alt=""
                />
                <div className="ai-copilot-page-profile-copy">
                  <div className="ai-copilot-page-profile-head">
                    <strong className="ai-copilot-page-profile-name">
                      {user?.name || "FPIPay User"}
                    </strong>
                    <span className="ai-copilot-page-profile-status">
                      <span className="ai-copilot-page-profile-status-dot" />
                      {copilotBusy ? "Thinking" : "Active session"}
                    </span>
                  </div>
                  <span className="ai-copilot-page-profile-subtitle">
                    FPIPay Copilot workspace
                  </span>
                </div>
              </div>
              <button
                type="button"
                className="pill ai-copilot-page-new"
                onClick={() => {
                  resetCopilotConversation();
                  setCopilotMobileHistoryOpen(false);
                }}
                disabled={copilotBusy}
              >
                + New Conversation
              </button>
            </div>

            <div className="ai-copilot-page-history">
              <div className="ai-copilot-sidebar-title-wrap">
                <div className="ai-copilot-sidebar-title">
                  Conversation History
                </div>
              </div>
              <div className="ai-copilot-session-list ai-copilot-page-session-list">
                {copilotSessionList.map((session) => {
                  const isActive =
                    session.id === copilotWorkspace.activeSessionId;
                  const isRenaming = session.id === copilotRenameSessionId;
                  const isMenuOpen = session.id === copilotSessionMenuId;

                  return (
                    <div
                      key={session.id}
                      className={`ai-copilot-session-card${isActive ? " active" : ""}${isMenuOpen ? " menu-open" : ""}`}
                    >
                      {isRenaming ? (
                        <input
                          className="ai-copilot-session-rename"
                          value={copilotRenameDraft}
                          autoFocus
                          maxLength={120}
                          onChange={(e) =>
                            setCopilotRenameDraft(e.target.value)
                          }
                          onBlur={commitCopilotRename}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") {
                              e.preventDefault();
                              commitCopilotRename();
                            }
                            if (e.key === "Escape") {
                              setCopilotRenameSessionId("");
                              setCopilotRenameDraft("");
                            }
                          }}
                        />
                      ) : (
                        <button
                          type="button"
                          className="ai-copilot-session-main"
                          onClick={() => {
                            selectCopilotSession(session.id);
                            setCopilotMobileHistoryOpen(false);
                          }}
                        >
                          <strong>{session.title}</strong>
                        </button>
                      )}
                      <div className="ai-copilot-session-menu-wrap">
                        <button
                          type="button"
                          className="ai-copilot-session-menu-trigger"
                          aria-label="Conversation options"
                          aria-expanded={isMenuOpen}
                          onClick={(event) => {
                            event.stopPropagation();
                            const currentTarget = event.currentTarget;
                            setCopilotSessionMenuId((current) => {
                              if (current === session.id) return "";
                              const rect =
                                currentTarget.getBoundingClientRect();
                              const listRect = currentTarget
                                .closest(".ai-copilot-page-session-list")
                                ?.getBoundingClientRect();
                              const estimatedMenuHeight = 128;
                              const spaceBelow = listRect
                                ? listRect.bottom - rect.bottom
                                : window.innerHeight - rect.bottom;
                              const spaceAbove = listRect
                                ? rect.top - listRect.top
                                : rect.top;
                              const placement =
                                spaceBelow < estimatedMenuHeight &&
                                spaceAbove > spaceBelow
                                  ? "up"
                                  : "down";
                              setCopilotSessionMenuPlacement(placement);
                              return session.id;
                            });
                          }}
                        >
                          ...
                        </button>
                        {isMenuOpen ? (
                          <div
                            className={`ai-copilot-session-menu ${
                              copilotSessionMenuPlacement === "up"
                                ? "open-up"
                                : "open-down"
                            }`}
                          >
                            <button
                              type="button"
                              className="ai-copilot-session-menu-item"
                              onClick={() =>
                                toggleCopilotSessionPin(session.id)
                              }
                              disabled={copilotBusy}
                            >
                              {session.pinned ? "Unpin" : "Pin"}
                            </button>
                            <button
                              type="button"
                              className="ai-copilot-session-menu-item"
                              onClick={() => startCopilotRename(session)}
                              disabled={copilotBusy}
                            >
                              Rename
                            </button>
                            <button
                              type="button"
                              className="ai-copilot-session-menu-item danger"
                              onClick={() => deleteCopilotSession(session.id)}
                              disabled={copilotBusy}
                            >
                              Delete
                            </button>
                          </div>
                        ) : null}
                      </div>
                    </div>
                  );
                })}
                {!copilotSessionList.length ? (
                  <div className="ai-copilot-session-empty">
                    No chats match your search.
                  </div>
                ) : null}
              </div>
            </div>
          </div>
        </aside>

        <div className="ai-copilot-page-main">
          <div className="ai-copilot-page-main-frame">
            <div className="ai-copilot-thread-wrap ai-copilot-thread-wrap-page">
              <div
                className={`ai-copilot-thread${copilotIsFreshSession ? " is-fresh" : ""}`}
                ref={copilotThreadRef}
              >
                {copilotIsFreshSession ? (
                  <div className="ai-copilot-welcome-overlay">
                    <div className="ai-copilot-welcome-kicker">
                      FPIPay Copilot ready
                    </div>
                    <h4>Ask one focused finance question to get started.</h4>
                    <p>{copilotMessages[0]?.content}</p>
                  </div>
                ) : null}
                {copilotMessages.map((message, index) =>
                  index === 0 &&
                  message.role === "assistant" &&
                  message.content.trim() ===
                    copilotDefaultGreeting.trim() ? null : (
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
                      {message.role === "user" ? (
                        <div className="ai-copilot-avatar ai-copilot-avatar-user">
                          {user?.avatar ? (
                            <img src={user.avatar} alt={user?.name || "You"} />
                          ) : (
                            user?.name?.trim().charAt(0).toUpperCase() || "U"
                          )}
                        </div>
                      ) : null}
                    </div>
                  ),
                )}
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
                      <p>Analyzing your financial context...</p>
                    </div>
                  </div>
                )}
              </div>
            </div>

            <div className="ai-copilot-compose ai-copilot-compose-page">
              <input
                type="text"
                className="ai-copilot-inline-input"
                value={copilotInput}
                onChange={(e) => setCopilotInput(e.target.value)}
                placeholder="Ask about spending, savings, statements, transfers, market context, or any finance question..."
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    void sendCopilotMessage();
                  }
                }}
              />
              <div className="ai-copilot-compose-actions">
                <button
                  type="button"
                  className="btn-primary ai-copilot-primary"
                  disabled={copilotBusy || !copilotInput.trim()}
                  onClick={() => void sendCopilotMessage()}
                >
                  {copilotBusy ? "..." : "Send"}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );

  if (mode === "copilot") {
    return copilotWorkspacePanel;
  }

  return (
    <section className="dashboard-v2">
      <div className="dashboard-v2-top">
        <article className="dashboard-wallet-card">
          <div className="dashboard-wallet-orb dashboard-wallet-orb-a" />
          <div className="dashboard-wallet-orb dashboard-wallet-orb-b" />
          <div className="dashboard-wallet-orb dashboard-wallet-orb-c" />
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
              <div className="dashboard-wallet-trust-row">
                <span className="dashboard-wallet-trust-pill">
                  Protected Wallet
                </span>
                <span className="dashboard-wallet-trust-dot" />
                <span className="dashboard-wallet-trust-meta">
                  Realtime Ledger
                </span>
              </div>
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
                  <svg
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                    focusable="false"
                    fill="none"
                  >
                    {showWalletId ? (
                      <>
                        <path
                          d="M3 3l18 18"
                          stroke="currentColor"
                          strokeWidth="1.7"
                          strokeLinecap="round"
                        />
                        <path
                          d="M10.58 10.58a2 2 0 0 0 2.84 2.84"
                          stroke="currentColor"
                          strokeWidth="1.7"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        />
                        <path
                          d="M9.88 5.08A10.94 10.94 0 0 1 12 4.9c4.78 0 8.73 2.88 10 6.85a1 1 0 0 1 0 .5 11.47 11.47 0 0 1-4.09 5.71M6.61 6.6A11.42 11.42 0 0 0 2 11.75a1 1 0 0 0 0 .5C3.27 16.22 7.22 19.1 12 19.1c1.79 0 3.47-.4 4.95-1.1"
                          stroke="currentColor"
                          strokeWidth="1.7"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        />
                      </>
                    ) : (
                      <>
                        <path
                          d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z"
                          stroke="currentColor"
                          strokeWidth="1.7"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        />
                        <circle
                          cx="12"
                          cy="12"
                          r="3"
                          stroke="currentColor"
                          strokeWidth="1.7"
                        />
                      </>
                    )}
                  </svg>
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
                    } else if (action.id === "sign-in-activity") {
                      setSecurityAlertsModalOpen(true);
                      void refreshSecurityAlerts();
                    } else if (action.id === "copilot") {
                      openCopilotWorkspace();
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
              openCopilotWorkspace();
            }}
          >
            Open AI workspace
          </button>
        </aside>
      </div>

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
          <div className="transaction-history-list">
            <div className="transaction-history-group-items">
              {transactionHistoryPreview.map((tx) => (
                <button
                  key={tx.id}
                  type="button"
                  className="transaction-history-item"
                  onClick={() => setSelectedTransactionReceipt(tx.receipt)}
                >
                  <span
                    className={`transaction-history-item-icon ${tx.amountTone}`}
                    aria-hidden="true"
                  >
                    {tx.amountTone === "positive" ? "IN" : "OUT"}
                  </span>
                  <span className="transaction-history-item-main">
                    <strong>{tx.entity}</strong>
                    <small>{tx.receipt.note || tx.status}</small>
                  </span>
                  <span
                    className={`transaction-history-item-amount ${tx.amountTone}`}
                  >
                    {tx.amount}
                  </span>
                  <span className="transaction-history-item-time">
                    {getTransactionHistoryTimeLabel(tx.date)}
                  </span>
                </button>
              ))}
            </div>
          </div>
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
            </div>
            <div className="security-alerts-toolbar">
              <span className="dashboard-tag">LIVE</span>
              <div className="security-alerts-head-actions">
                <button
                  type="button"
                  className="pill"
                  disabled={securityAlertsBusy}
                  onClick={() => void refreshSecurityAlerts()}
                >
                  {securityAlertsBusy ? "Refreshing..." : "Refresh"}
                </button>
                <button
                  type="button"
                  className="card-details-close"
                  onClick={() => setSecurityAlertsModalOpen(false)}
                >
                  x
                </button>
              </div>
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
              <div className="transaction-history-list transaction-history-list-modal">
                <div className="transaction-history-group-items">
                  {transactionHistory.map((tx) => (
                    <button
                      key={`modal-${tx.id}`}
                      type="button"
                      className="transaction-history-item"
                      onClick={() => setSelectedTransactionReceipt(tx.receipt)}
                    >
                      <span
                        className={`transaction-history-item-icon ${tx.amountTone}`}
                        aria-hidden="true"
                      >
                        {tx.amountTone === "positive" ? "IN" : "OUT"}
                      </span>
                      <span className="transaction-history-item-main">
                        <strong>{tx.entity}</strong>
                        <small>{tx.receipt.note || tx.status}</small>
                      </span>
                      <span
                        className={`transaction-history-item-amount ${tx.amountTone}`}
                      >
                        {tx.amount}
                      </span>
                      <span className="transaction-history-item-time">
                        {getTransactionHistoryTimeLabel(tx.date)}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
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
                  To view full card details, enter your 6-digit passcode.
                </p>
                <label className="form-group">
                  <span>Enter 6-digit passcode</span>
                  <input
                    type="password"
                    inputMode="numeric"
                    maxLength={6}
                    value={otpInput}
                    onChange={(e) =>
                      setOtpInput(e.target.value.replace(/\D/g, "").slice(0, 6))
                    }
                    placeholder="6-digit passcode"
                    disabled={cardOtpVerifying}
                  />
                </label>
                {otpError && <div className="card-otp-error">{otpError}</div>}
                <div className="card-otp-actions">
                  <button
                    type="button"
                    className="btn-primary"
                    onClick={() => void verifyOtpAndShowDetails()}
                    disabled={cardOtpVerifying || otpInput.length !== 6}
                  >
                    {cardOtpVerifying ? "Verifying..." : "Unlock Details"}
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
                      <>
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
                              setTransferAiInterventionOpen(false);
                            }}
                          />
                        </label>
                        {savedTransferRecipients.length > 0 && (
                          <div className="transfer-saved-recipients">
                            <div className="transfer-saved-recipients-head">
                              Recent recipients
                            </div>
                            <div className="transfer-saved-recipients-list">
                              {savedTransferRecipients
                                .slice(0, 6)
                                .map((item) => (
                                  <button
                                    key={item.accountNumber}
                                    type="button"
                                    className="transfer-saved-recipient-chip"
                                    onClick={() => {
                                      void dismissTransferAdvisory();
                                      setTransferAccount(item.accountNumber);
                                      setTransferRecipientUserId(
                                        item.userId || "",
                                      );
                                      setTransferReceiverName(item.holderName);
                                      setTransferMonitoring(null);
                                      setTransferAdvisory(null);
                                      setTransferAdvisoryAcknowledged(false);
                                      setTransferAiInterventionOpen(false);
                                      void (async () => {
                                        const resolved =
                                          await resolveTransferRecipient(
                                            item.accountNumber,
                                          );
                                        if (!resolved) return;
                                        await logTransferFlowEvent("STARTED");
                                        goToTransferStep(2);
                                      })();
                                    }}
                                  >
                                    <strong>{item.holderName}</strong>
                                    <span>
                                      ****{item.accountNumber.slice(-4)}
                                    </span>
                                  </button>
                                ))}
                            </div>
                          </div>
                        )}
                      </>
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
                          setTransferAiInterventionOpen(false);
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
                          setTransferAiInterventionOpen(false);
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
                          setTransferAiInterventionOpen(false);
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
                    {!transferPinEnabled && (
                      <div className="transfer-summary">
                        <span>Transfer PIN</span>
                        <strong>Transfer PIN required</strong>
                        <small>
                          You need to create a 6-digit transfer PIN before
                          making transfers.
                        </small>
                      </div>
                    )}
                    {!transferOtpRequired && (
                      <>
                        <label className="form-group">
                          <span>Enter transfer PIN</span>
                          <input
                            type="password"
                            inputMode="numeric"
                            maxLength={6}
                            disabled={transferOtpBusy || transferOtpVerifyBusy}
                            value={transferPinInput}
                            onChange={(e) =>
                              setTransferPinInput(
                                e.target.value.replace(/\D/g, "").slice(0, 6),
                              )
                            }
                            placeholder="6-digit transfer PIN"
                          />
                        </label>
                        {transferPinError && (
                          <div className="card-otp-error">
                            {transferPinError}
                          </div>
                        )}
                      </>
                    )}
                    {transferOtpRequired && transferOtpDestination && (
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
                    {transferOtpRequired && (
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
                    )}
                    {transferOtpError && (
                      <div className="card-otp-error">{transferOtpError}</div>
                    )}
                    <div className="transfer-actions">
                      {transferOtpRequired ? (
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
                      ) : (
                        <button
                          type="button"
                          className="pill"
                          onClick={() => {
                            setTransferOtpRequired(false);
                            setTransferOtpInput("");
                            setTransferOtpError("");
                            setTransferOtpChallengeId("");
                            setTransferOtpDestination("");
                            setTransferOtpExpiresAt("");
                            setTransferAiInterventionOpen(false);
                            goToTransferStep(2);
                          }}
                        >
                          Back
                        </button>
                      )}
                      <button
                        type="button"
                        className="btn-primary"
                        onClick={verifyTransferOtpAndSubmit}
                        disabled={
                          transferOtpBusy ||
                          transferOtpVerifyBusy ||
                          isTransferHoldActive
                        }
                      >
                        {isTransferHoldActive
                          ? `Retry in ${transferHoldRemainingLabel}`
                          : transferOtpRequired
                            ? transferOtpVerifyBusy
                              ? "Verifying OTP..."
                              : "Confirm Transfer"
                            : transferOtpBusy
                              ? "Checking risk..."
                              : "Authorize Transfer"}
                      </button>
                    </div>
                  </div>
                )}

                {transferStep === 4 && (
                  <div className="transfer-body transfer-success">
                    <div className="transfer-success-icon" aria-hidden="true">
                      <span>✓</span>
                    </div>
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
            {transferPinSetupOpen && (
              <div
                className="transfer-pin-setup-overlay"
                onClick={() => {
                  if (transferPinSetupBusy) return;
                  setTransferPinSetupOpen(false);
                  setTransferPinSetupError("");
                }}
              >
                <div
                  className="transfer-pin-setup-card"
                  onClick={(e) => e.stopPropagation()}
                >
                  <div className="transfer-pin-setup-head">
                    <div>
                      <h4>Create Transfer PIN</h4>
                      <p>
                        Set your 6-digit transfer PIN now to continue this
                        transfer.
                      </p>
                    </div>
                    <button
                      type="button"
                      className="icon-btn"
                      onClick={() => {
                        if (transferPinSetupBusy) return;
                        setTransferPinSetupOpen(false);
                        setTransferPinSetupError("");
                      }}
                      aria-label="Close transfer PIN setup"
                    >
                      ×
                    </button>
                  </div>
                  <label className="form-group">
                    <span>Transfer PIN</span>
                    <input
                      type="password"
                      inputMode="numeric"
                      maxLength={6}
                      disabled={transferPinSetupBusy}
                      value={transferPinSetupForm.pin}
                      onChange={(e) =>
                        setTransferPinSetupForm((prev) => ({
                          ...prev,
                          pin: e.target.value.replace(/\D/g, "").slice(0, 6),
                        }))
                      }
                      placeholder="Enter 6 digits"
                    />
                  </label>
                  <label className="form-group">
                    <span>Confirm transfer PIN</span>
                    <input
                      type="password"
                      inputMode="numeric"
                      maxLength={6}
                      disabled={transferPinSetupBusy}
                      value={transferPinSetupForm.confirm}
                      onChange={(e) =>
                        setTransferPinSetupForm((prev) => ({
                          ...prev,
                          confirm: e.target.value
                            .replace(/\D/g, "")
                            .slice(0, 6),
                        }))
                      }
                      placeholder="Re-enter 6 digits"
                    />
                  </label>
                  {transferPinSetupError && (
                    <div className="card-otp-error">
                      {transferPinSetupError}
                    </div>
                  )}
                  <div className="transfer-actions">
                    <button
                      type="button"
                      className="pill"
                      disabled={transferPinSetupBusy}
                      onClick={() => {
                        setTransferPinSetupOpen(false);
                        setTransferPinSetupError("");
                      }}
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      className="btn-primary"
                      disabled={transferPinSetupBusy}
                      onClick={() => {
                        void submitTransferPinSetup();
                      }}
                    >
                      {transferPinSetupBusy ? "Saving..." : "Create PIN"}
                    </button>
                  </div>
                </div>
              </div>
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
                      <strong className="transfer-faceid-money">
                        ${transferAmount}
                      </strong>
                    </div>
                    <div>
                      <span>OTP</span>
                      <strong>{transferOtpInput || "******"}</strong>
                    </div>
                    {transferRollingOutflowAmount !== null ? (
                      <div>
                        <span>24h outgoing</span>
                        <strong className="transfer-faceid-money">
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

                {transferOtpError ? (
                  <div className="card-otp-error transfer-faceid-error">
                    {transferOtpError}
                  </div>
                ) : null}

                <DeferredFaceIdCapture
                  apiBase={API_BASE}
                  resetKey={transferFaceResetKey}
                  disabled={transferFaceVerifyBusy}
                  mode="verify"
                  onChange={setTransferFaceProof}
                />

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

      {transferAiInterventionOpen &&
      transferAiIntervention &&
      typeof document !== "undefined"
        ? createPortal(
            <div
              className="transfer-ai-warning-overlay"
              onClick={closeTransferAiIntervention}
            >
              <div
                className={`transfer-ai-warning-card ${transferAiIntervention.tone}`}
                onClick={(event) => event.stopPropagation()}
              >
                <div className="transfer-ai-warning-head">
                  <div>
                    <span className="transfer-ai-warning-kicker">
                      AI transfer guard
                    </span>
                    <h4>{transferAiIntervention.title}</h4>
                    <p>{transferAiIntervention.summary}</p>
                  </div>
                  <button
                    type="button"
                    className="icon-btn"
                    onClick={closeTransferAiIntervention}
                    aria-label="Close AI transfer warning"
                  >
                    ×
                  </button>
                </div>
                <div className="transfer-ai-warning-body">
                  <div className="transfer-ai-warning-summary">
                    <div>
                      <span>Status</span>
                      <strong>{transferAiIntervention.statusLabel}</strong>
                    </div>
                    <div>
                      <span>Confidence</span>
                      <strong>{transferAiIntervention.confidence}%</strong>
                    </div>
                    <div>
                      <span>Next action</span>
                      <strong>{transferAiIntervention.nextAction}</strong>
                    </div>
                  </div>
                  <div className="transfer-ai-warning-grid">
                    <div className="transfer-ai-warning-section">
                      <span className="transfer-ai-warning-section-label">
                        Transfer snapshot
                      </span>
                      <strong>{transferAiIntervention.recipientLabel}</strong>
                      <p>Amount: {transferAiIntervention.amountLabel}</p>
                      {transferAiIntervention.archetype ? (
                        <small>
                          Pattern:{" "}
                          {translateTransferRiskCopy(
                            transferAiIntervention.archetype,
                          )}
                        </small>
                      ) : null}
                      {isTransferHoldActive ? (
                        <small>
                          Retry after {transferHoldRemainingLabel} or wait for
                          manual review to clear the hold.
                        </small>
                      ) : null}
                    </div>
                    <div className="transfer-ai-warning-section">
                      <span className="transfer-ai-warning-section-label">
                        Why AI flagged this
                      </span>
                      {transferAiIntervention.signals.length > 0 ? (
                        <ul>
                          {transferAiIntervention.signals.map((item) => (
                            <li key={item}>{item}</li>
                          ))}
                        </ul>
                      ) : (
                        <p>
                          AI detected enough deviation from your normal behavior
                          to trigger a safety review before OTP is sent.
                        </p>
                      )}
                      {transferAiIntervention.timeline.length > 0 ? (
                        <small>{transferAiIntervention.timeline[0]}</small>
                      ) : null}
                    </div>
                    <div className="transfer-ai-warning-section">
                      <span className="transfer-ai-warning-section-label">
                        Before continuing
                      </span>
                      <ul>
                        {transferAiIntervention.protectSteps.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                        {transferAiIntervention.stopList.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
                <div className="transfer-actions">
                  <button
                    type="button"
                    className="pill"
                    onClick={reviewTransferBeforeProceeding}
                  >
                    Edit transfer
                  </button>
                  <button
                    type="button"
                    className="btn-primary"
                    onClick={() => void proceedTransferAfterAiWarning()}
                    disabled={transferOtpBusy || transferOtpVerifyBusy}
                  >
                    {transferAiIntervention.primaryLabel}
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
              <div className="transfer-success-icon" aria-hidden="true">
                <span>✓</span>
              </div>
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
    </section>
  );
}

function TransactionReceiptCard({ receipt }: { receipt: TransactionReceipt }) {
  const statusTone =
    receipt.status.toLowerCase() === "completed"
      ? "completed"
      : receipt.status.toLowerCase() === "pending"
        ? "pending"
        : "other";
  return (
    <div className="transfer-receipt">
      <div className="transfer-receipt-head">
        <div>
          <small className="transfer-receipt-kicker">Digital receipt</small>
          <strong>FPIPay Transfer Confirmation</strong>
        </div>
        <span className={`transfer-receipt-status-pill ${statusTone}`}>
          {receipt.status}
        </span>
      </div>
      <div className="transfer-receipt-amount-block">
        <span>Total Amount</span>
        <strong>${receipt.amountUsd}</strong>
        <small>
          Fee ${receipt.feeUsd} • Executed at {receipt.executedAt}
        </small>
      </div>
      <div className="transfer-receipt-grid">
        <div className="transfer-receipt-row">
          <span>Transaction ID</span>
          <strong className="transfer-receipt-mono">{receipt.txId}</strong>
        </div>
        <div className="transfer-receipt-row">
          <span>Status</span>
          <strong className="transfer-receipt-status">{receipt.status}</strong>
        </div>
        <div className="transfer-receipt-row">
          <span>From Account</span>
          <strong className="transfer-receipt-mono">
            {receipt.fromAccount}
          </strong>
        </div>
        <div className="transfer-receipt-row">
          <span>To Account</span>
          <strong className="transfer-receipt-mono">{receipt.toAccount}</strong>
        </div>
        <div className="transfer-receipt-row">
          <span>Recipient</span>
          <strong>{receipt.recipientName || "Unavailable"}</strong>
        </div>
        <div className="transfer-receipt-row transfer-receipt-row-wide">
          <span>Content</span>
          <strong>{receipt.note}</strong>
        </div>
      </div>
      <div className="transfer-receipt-foot">
        <span>Reference: {receipt.txId.slice(-10)}</span>
        <span>Keep this receipt for support and dispute resolution.</span>
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
    cvv: "",
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
      setWalletBalance(
        Number(walletData?.balance || 0) + getSignupTestBalanceBonus(user?.id),
      );
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
      !newCard.expiryYear.trim() ||
      !newCard.cvv.trim()
    ) {
      toast("Please fill all card fields", "error");
      return;
    }
    if (!/^\d{3,4}$/.test(newCard.cvv.trim())) {
      toast("CVV must be 3 or 4 digits", "error");
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
        cvv: "",
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
                <div className="form-group">
                  <label>CVV</label>
                  <input
                    type="password"
                    value={newCard.cvv}
                    onChange={(e) =>
                      setNewCard((prev) => ({
                        ...prev,
                        cvv: e.target.value.replace(/\D/g, "").slice(0, 4),
                      }))
                    }
                    placeholder="123"
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
const DEFAULT_PROFILE_AVATAR = "https://i.pravatar.cc/120?img=12";
const MAX_PROFILE_AVATAR_FILE_SIZE = 6 * 1024 * 1024;
const MAX_PROFILE_AVATAR_OUTPUT_BYTES = 900 * 1024;
const PROFILE_AVATAR_MAX_DIMENSION = 640;

const readStoredSaveLoginPreference = () => {
  try {
    const raw = localStorage.getItem(SETTING_SECURITY_KEY);
    if (!raw) return true;
    const parsed = JSON.parse(raw) as { saveLogin?: unknown } | null;
    return typeof parsed?.saveLogin === "boolean" ? parsed.saveLogin : true;
  } catch {
    return true;
  }
};

const writeStoredSaveLoginPreference = (saveLogin: boolean) => {
  try {
    const raw = localStorage.getItem(SETTING_SECURITY_KEY);
    const parsed =
      raw && typeof raw === "string"
        ? (JSON.parse(raw) as Record<string, unknown> | null)
        : null;
    const next =
      parsed && typeof parsed === "object" && !Array.isArray(parsed)
        ? parsed
        : {};
    next.saveLogin = saveLogin;
    localStorage.setItem(SETTING_SECURITY_KEY, JSON.stringify(next));
  } catch {
    // ignore storage permission errors
  }
};

const getProfileAvatarStorageKey = (userId?: string | null) =>
  userId ? `${PROFILE_AVATAR_KEY}:${userId}` : PROFILE_AVATAR_KEY;

const readStoredProfileAvatar = (
  user?: { id?: string | null; avatar?: string | null } | null,
) => {
  try {
    return (
      user?.avatar ??
      localStorage.getItem(getProfileAvatarStorageKey(user?.id)) ??
      DEFAULT_PROFILE_AVATAR
    );
  } catch {
    return user?.avatar ?? DEFAULT_PROFILE_AVATAR;
  }
};

const writeStoredProfileAvatar = (
  userId: string | null | undefined,
  avatar: string,
) => {
  try {
    localStorage.setItem(getProfileAvatarStorageKey(userId), avatar);
  } catch {
    // Ignore storage quota issues here; the server remains the source of truth.
  }
};

const loadImageElement = (src: string) =>
  new Promise<HTMLImageElement>((resolve, reject) => {
    const image = new Image();
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error("IMAGE_LOAD_FAILED"));
    image.src = src;
  });

const compressProfileAvatar = async (file: File) => {
  if (!file.type.startsWith("image/")) {
    throw new Error("Please choose an image file");
  }
  if (file.size > MAX_PROFILE_AVATAR_FILE_SIZE) {
    throw new Error("Please choose an image smaller than 6MB");
  }

  const fileDataUrl = await new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = String(reader.result ?? "");
      if (!result) {
        reject(new Error("IMAGE_READ_FAILED"));
        return;
      }
      resolve(result);
    };
    reader.onerror = () => reject(new Error("IMAGE_READ_FAILED"));
    reader.readAsDataURL(file);
  });

  const image = await loadImageElement(fileDataUrl);
  const longestEdge = Math.max(image.width, image.height, 1);
  const scale = Math.min(1, PROFILE_AVATAR_MAX_DIMENSION / longestEdge);
  const targetWidth = Math.max(1, Math.round(image.width * scale));
  const targetHeight = Math.max(1, Math.round(image.height * scale));

  const canvas = document.createElement("canvas");
  canvas.width = targetWidth;
  canvas.height = targetHeight;
  const context = canvas.getContext("2d");
  if (!context) {
    throw new Error("IMAGE_PROCESSING_UNAVAILABLE");
  }

  context.drawImage(image, 0, 0, targetWidth, targetHeight);

  let quality = 0.9;
  let output = canvas.toDataURL("image/jpeg", quality);
  while (output.length > MAX_PROFILE_AVATAR_OUTPUT_BYTES && quality > 0.45) {
    quality -= 0.1;
    output = canvas.toDataURL("image/jpeg", quality);
  }

  if (output.length > MAX_PROFILE_AVATAR_OUTPUT_BYTES) {
    throw new Error("Please choose a smaller image");
  }

  return output;
};

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

type AccountProfileCategory = "PERSONAL" | "BUSINESS";
type AccountProfileTier =
  | "BASIC"
  | "STANDARD"
  | "PREMIUM"
  | "SMALL_BUSINESS"
  | "MEDIUM_BUSINESS"
  | "ENTERPRISE";
type AccountProfileStatus =
  | "SYSTEM_ASSIGNED"
  | "PENDING_REVIEW"
  | "VERIFIED"
  | "REQUIRES_REVIEW";
type AccountProfileRequestContext = {
  usagePurpose?: string;
  expectedTransactionLevel?: string;
  expectedTransactionFrequency?: string;
  businessSize?: string;
  justification?: string;
};
type AccountProfileAutomation = {
  mode: "AUTOMATIC" | "ADMIN_CONTROLLED";
  reviewWindowDays: number;
  lastEvaluatedAt: string | null;
  autoUpgradeApplied: boolean;
  eligibleForUpgrade: boolean;
  recommendedCategory: AccountProfileCategory;
  recommendedTier: AccountProfileTier;
  nextTier: AccountProfileTier | null;
  rationale: string[];
  milestones: string[];
  stats: {
    completedCount: number;
    totalVolume: number;
    outgoingVolume: number;
    incomingVolume: number;
    largeTransferCount: number;
    counterpartyCount: number;
    sourceCoverageRatio: number;
    cleanActivityRatio: number;
  };
};
type AccountProfileView = {
  category: AccountProfileCategory;
  tier: AccountProfileTier;
  label: string;
  status: AccountProfileStatus;
  confidence: number;
  requestedCategory: AccountProfileCategory | null;
  requestedTier: AccountProfileTier | null;
  hasPendingRequest: boolean;
  requestContext: AccountProfileRequestContext | null;
  automation: AccountProfileAutomation | null;
};

const PERSONAL_PROFILE_OPTIONS = [
  { value: "BASIC", label: "P1 Basic" },
  { value: "STANDARD", label: "P2 Standard" },
  { value: "PREMIUM", label: "P3 Premium" },
] as const;

const BUSINESS_PROFILE_OPTIONS = [
  { value: "SMALL_BUSINESS", label: "B1 Small Business" },
  { value: "MEDIUM_BUSINESS", label: "B2 Medium Business" },
  { value: "ENTERPRISE", label: "B3 Enterprise" },
] as const;

const DEFAULT_ACCOUNT_PROFILE_VIEW: AccountProfileView = {
  category: "PERSONAL",
  tier: "STANDARD",
  label: "Personal Standard",
  status: "SYSTEM_ASSIGNED",
  confidence: 0.6,
  requestedCategory: null,
  requestedTier: null,
  hasPendingRequest: false,
  requestContext: null,
  automation: null,
};

const defaultTierForCategory = (
  category: AccountProfileCategory,
): AccountProfileTier =>
  category === "BUSINESS" ? "SMALL_BUSINESS" : "STANDARD";

const formatAccountProfileLabel = (
  category: AccountProfileCategory,
  tier: AccountProfileTier | null | undefined,
) => {
  if (category === "BUSINESS") {
    if (tier === "ENTERPRISE") return "B3 Enterprise";
    if (tier === "MEDIUM_BUSINESS") return "B2 Medium Business";
    return "B1 Small Business";
  }
  if (tier === "BASIC") return "P1 Basic";
  if (tier === "PREMIUM") return "P3 Premium";
  return "P2 Standard";
};

const formatAccountProfileStatus = (status: AccountProfileStatus) => {
  if (status === "PENDING_REVIEW") return "Pending admin review";
  if (status === "VERIFIED") return "Verified baseline";
  if (status === "REQUIRES_REVIEW") return "Needs review";
  return "System assigned";
};

const formatAccountProfileAutomationMode = (
  mode?: AccountProfileAutomation["mode"] | null,
) => {
  if (mode === "ADMIN_CONTROLLED") return "Admin-controlled";
  return "Automatic monthly review";
};

const parseAccountProfileMetadata = (
  metadata?: Record<string, unknown> | null,
) => {
  const source = metadata && typeof metadata === "object" ? metadata : {};
  const rawProfile =
    source.accountProfile && typeof source.accountProfile === "object"
      ? (source.accountProfile as Record<string, unknown>)
      : {};
  const category = rawProfile.category === "BUSINESS" ? "BUSINESS" : "PERSONAL";
  const tierSource =
    typeof rawProfile.tier === "string"
      ? rawProfile.tier
      : defaultTierForCategory(category);
  const tier = (
    tierSource === "BASIC" ||
    tierSource === "STANDARD" ||
    tierSource === "PREMIUM" ||
    tierSource === "SMALL_BUSINESS" ||
    tierSource === "MEDIUM_BUSINESS" ||
    tierSource === "ENTERPRISE"
      ? tierSource
      : defaultTierForCategory(category)
  ) as AccountProfileTier;
  const requestedCategory =
    rawProfile.requestedCategory === "BUSINESS" ||
    rawProfile.requestedCategory === "PERSONAL"
      ? (rawProfile.requestedCategory as AccountProfileCategory)
      : null;
  const requestedTier =
    typeof rawProfile.requestedTier === "string"
      ? (rawProfile.requestedTier as AccountProfileTier)
      : null;
  const status =
    rawProfile.status === "PENDING_REVIEW" ||
    rawProfile.status === "VERIFIED" ||
    rawProfile.status === "REQUIRES_REVIEW"
      ? (rawProfile.status as AccountProfileStatus)
      : "SYSTEM_ASSIGNED";
  const requestContext =
    rawProfile.requestContext && typeof rawProfile.requestContext === "object"
      ? (rawProfile.requestContext as AccountProfileRequestContext)
      : null;
  const rawAutomation =
    rawProfile.automation && typeof rawProfile.automation === "object"
      ? (rawProfile.automation as Record<string, unknown>)
      : null;
  const automationStats =
    rawAutomation?.stats && typeof rawAutomation.stats === "object"
      ? (rawAutomation.stats as Record<string, unknown>)
      : null;
  const automation =
    rawAutomation !== null
      ? ({
          mode:
            rawAutomation.mode === "ADMIN_CONTROLLED"
              ? "ADMIN_CONTROLLED"
              : "AUTOMATIC",
          reviewWindowDays:
            typeof rawAutomation.reviewWindowDays === "number"
              ? rawAutomation.reviewWindowDays
              : 30,
          lastEvaluatedAt:
            typeof rawAutomation.lastEvaluatedAt === "string"
              ? rawAutomation.lastEvaluatedAt
              : null,
          autoUpgradeApplied: rawAutomation.autoUpgradeApplied === true,
          eligibleForUpgrade: rawAutomation.eligibleForUpgrade === true,
          recommendedCategory:
            rawAutomation.recommendedCategory === "BUSINESS"
              ? "BUSINESS"
              : "PERSONAL",
          recommendedTier:
            typeof rawAutomation.recommendedTier === "string"
              ? (rawAutomation.recommendedTier as AccountProfileTier)
              : tier,
          nextTier:
            typeof rawAutomation.nextTier === "string"
              ? (rawAutomation.nextTier as AccountProfileTier)
              : null,
          rationale: Array.isArray(rawAutomation.rationale)
            ? rawAutomation.rationale.filter(
                (item): item is string =>
                  typeof item === "string" && item.trim().length > 0,
              )
            : [],
          milestones: Array.isArray(rawAutomation.milestones)
            ? rawAutomation.milestones.filter(
                (item): item is string =>
                  typeof item === "string" && item.trim().length > 0,
              )
            : [],
          stats: {
            completedCount:
              typeof automationStats?.completedCount === "number"
                ? automationStats.completedCount
                : 0,
            totalVolume:
              typeof automationStats?.totalVolume === "number"
                ? automationStats.totalVolume
                : 0,
            outgoingVolume:
              typeof automationStats?.outgoingVolume === "number"
                ? automationStats.outgoingVolume
                : 0,
            incomingVolume:
              typeof automationStats?.incomingVolume === "number"
                ? automationStats.incomingVolume
                : 0,
            largeTransferCount:
              typeof automationStats?.largeTransferCount === "number"
                ? automationStats.largeTransferCount
                : 0,
            counterpartyCount:
              typeof automationStats?.counterpartyCount === "number"
                ? automationStats.counterpartyCount
                : 0,
            sourceCoverageRatio:
              typeof automationStats?.sourceCoverageRatio === "number"
                ? automationStats.sourceCoverageRatio
                : 0,
            cleanActivityRatio:
              typeof automationStats?.cleanActivityRatio === "number"
                ? automationStats.cleanActivityRatio
                : 1,
          },
        } satisfies AccountProfileAutomation)
      : null;

  return {
    category,
    tier,
    label:
      typeof rawProfile.label === "string"
        ? rawProfile.label
        : formatAccountProfileLabel(category, tier),
    status,
    confidence:
      typeof rawProfile.confidence === "number" ? rawProfile.confidence : 0.6,
    requestedCategory,
    requestedTier,
    hasPendingRequest: rawProfile.hasPendingRequest === true,
    requestContext,
    automation,
  } satisfies AccountProfileView;
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
  const { user, token, logout, updateUser } = useAuth();
  const { toast } = useToast();
  const { theme } = useTheme();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const isAuthExpired = (status: number, message?: string) =>
    status === 401 ||
    status === 403 ||
    /invalid|expired|token|jwt/i.test((message || "").toLowerCase());
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
  const [transferPinForm, setTransferPinForm] = useState({
    current: "",
    next: "",
    confirm: "",
  });
  const [transferPinBusy, setTransferPinBusy] = useState(false);
  const [transferPinEnabledStatus, setTransferPinEnabledStatus] =
    useState(false);
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
  const [avatarUrl, setAvatarUrl] = useState(() => {
    return readStoredProfileAvatar(user);
  });
  const [accountProfile, setAccountProfile] = useState<AccountProfileView>(
    DEFAULT_ACCOUNT_PROFILE_VIEW,
  );
  const [profileRequest, setProfileRequest] = useState(() => ({
    category: DEFAULT_ACCOUNT_PROFILE_VIEW.category,
    tier: DEFAULT_ACCOUNT_PROFILE_VIEW.tier,
    usagePurpose: "personal_spending",
    expectedTransactionLevel: "MEDIUM",
    expectedTransactionFrequency: "REGULAR",
    businessSize: "SMALL",
    justification: "",
  }));
  const [profileRequestBusy, setProfileRequestBusy] = useState(false);

  useEffect(() => {
    setAvatarUrl(readStoredProfileAvatar(user));
  }, [user?.avatar, user?.id]);

  const persistSecurity = (next: typeof security) => {
    setSecurity(next);
    localStorage.setItem(SETTING_SECURITY_KEY, JSON.stringify(next));
  };

  const toggle2fa = (v: boolean) => {
    persistSecurity({ ...security, twofa: v });
    toast(v ? "Two-factor enabled" : "Two-factor disabled");
  };

  const toggleSaveLogin = (v: boolean) => {
    writeStoredSaveLoginPreference(v);
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

  useEffect(() => {
    if (!token) return;
    let cancelled = false;

    const loadTransferPinStatus = async () => {
      try {
        const resp = await fetch(`${API_BASE}/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = (await resp.json().catch(() => null)) as {
          metadata?: Record<string, unknown>;
        } | null;
        if (!resp.ok || !data || cancelled) return;
        setTransferPinEnabledStatus(data.metadata?.transferPinEnabled === true);
      } catch {
        // ignore temporary load errors in settings
      }
    };

    void loadTransferPinStatus();
    return () => {
      cancelled = true;
    };
  }, [token, user?.id]);

  const saveTransferPin = async () => {
    if (!token) {
      toast("Session expired. Please login again.", "error");
      return;
    }
    if (!/^\d{6}$/.test(transferPinForm.next)) {
      toast("Transfer PIN must be exactly 6 digits", "error");
      return;
    }
    if (transferPinForm.next !== transferPinForm.confirm) {
      toast("Transfer PIN confirmation does not match", "error");
      return;
    }

    setTransferPinBusy(true);
    try {
      const resp = await fetch(`${API_BASE}/security/transfer-pin`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          currentPin: transferPinForm.current || undefined,
          newPin: transferPinForm.next,
        }),
      });
      const data = (await resp.json().catch(() => null)) as {
        error?: string;
        message?: string;
        metadata?: Record<string, unknown>;
      } | null;
      if (!resp.ok) {
        toast(data?.error || "Failed to update transfer PIN", "error");
        return;
      }

      setTransferPinEnabledStatus(data?.metadata?.transferPinEnabled === true);
      setTransferPinForm({ current: "", next: "", confirm: "" });
      toast(data?.message || "Transfer PIN updated successfully");
    } finally {
      setTransferPinBusy(false);
    }
  };

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
      writeStoredProfileAvatar(user?.id, avatarUrl);
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

  const persistAvatar = async (next: string, fallbackAvatar: string) => {
    if (!token) {
      toast("Session expired. Please sign in again.", "error");
      setAvatarUrl(fallbackAvatar);
      writeStoredProfileAvatar(user?.id, fallbackAvatar);
      updateUser({ avatar: fallbackAvatar });
      return false;
    }

    try {
      const resp = await fetch(`${API_BASE}/auth/me`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          metadata: {
            avatar: next,
          },
        }),
      });
      const data = (await resp.json().catch(() => null)) as {
        error?: string;
        avatar?: string;
        metadata?: Record<string, unknown>;
      } | null;
      if (!resp.ok) {
        if (isAuthExpired(resp.status, data?.error)) {
          toast("Session expired. Please sign in again.", "error");
          logout();
          return false;
        }
        setAvatarUrl(fallbackAvatar);
        writeStoredProfileAvatar(user?.id, fallbackAvatar);
        updateUser({ avatar: fallbackAvatar });
        toast(data?.error || "Failed to update avatar", "error");
        return false;
      }

      const persistedAvatar =
        (typeof data?.avatar === "string" && data.avatar) ||
        (typeof data?.metadata?.avatar === "string" && data.metadata.avatar) ||
        next;

      setAvatarUrl(persistedAvatar);
      writeStoredProfileAvatar(user?.id, persistedAvatar);
      updateUser({ avatar: persistedAvatar });
      toast("Profile image updated");
      return true;
    } catch {
      setAvatarUrl(fallbackAvatar);
      writeStoredProfileAvatar(user?.id, fallbackAvatar);
      updateUser({ avatar: fallbackAvatar });
      toast("Cannot connect to API server.", "error");
      return false;
    }
  };

  const handleAvatarChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const previousAvatar = avatarUrl;
    void compressProfileAvatar(file)
      .then((next) => {
        setAvatarUrl(next);
        updateUser({ avatar: next });
        writeStoredProfileAvatar(user?.id, next);
        return persistAvatar(next, previousAvatar);
      })
      .catch((err) => {
        const message =
          err instanceof Error && err.message
            ? err.message
            : "Failed to process image";
        toast(message, "error");
      });
    e.currentTarget.value = "";
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
            <div className="setting-block">
              <h4 className="setting-block-head">Transfer PIN</h4>
              <p className="setting-block-desc muted">
                Every transfer starts with your 6-digit transfer PIN. OTP is
                only added when AI classifies the risk as medium.
              </p>
              <div className="form-grid setting-form">
                {transferPinEnabledStatus && (
                  <div className="form-group">
                    <label>Current transfer PIN</label>
                    <input
                      type="password"
                      inputMode="numeric"
                      maxLength={6}
                      value={transferPinForm.current}
                      onChange={(e) =>
                        setTransferPinForm((prev) => ({
                          ...prev,
                          current: e.target.value
                            .replace(/\D/g, "")
                            .slice(0, 6),
                        }))
                      }
                    />
                  </div>
                )}
                <div className="form-group">
                  <label>
                    {transferPinEnabledStatus
                      ? "New transfer PIN"
                      : "Transfer PIN"}
                  </label>
                  <input
                    type="password"
                    inputMode="numeric"
                    maxLength={6}
                    value={transferPinForm.next}
                    onChange={(e) =>
                      setTransferPinForm((prev) => ({
                        ...prev,
                        next: e.target.value.replace(/\D/g, "").slice(0, 6),
                      }))
                    }
                  />
                </div>
                <div className="form-group">
                  <label>Confirm transfer PIN</label>
                  <input
                    type="password"
                    inputMode="numeric"
                    maxLength={6}
                    value={transferPinForm.confirm}
                    onChange={(e) =>
                      setTransferPinForm((prev) => ({
                        ...prev,
                        confirm: e.target.value.replace(/\D/g, "").slice(0, 6),
                      }))
                    }
                  />
                </div>
              </div>
              <div className="setting-actions">
                <button
                  type="button"
                  className="btn-primary"
                  onClick={saveTransferPin}
                  disabled={transferPinBusy}
                >
                  {transferPinBusy
                    ? "Saving..."
                    : transferPinEnabledStatus
                      ? "Update Transfer PIN"
                      : "Create Transfer PIN"}
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
    return readStoredProfileAvatar(user);
  });
  const [accountProfile, setAccountProfile] = useState<AccountProfileView>(
    DEFAULT_ACCOUNT_PROFILE_VIEW,
  );
  const [profileRequest, setProfileRequest] = useState(() => ({
    category: DEFAULT_ACCOUNT_PROFILE_VIEW.category,
    tier: DEFAULT_ACCOUNT_PROFILE_VIEW.tier,
    usagePurpose: "personal_spending",
    expectedTransactionLevel: "MEDIUM",
    expectedTransactionFrequency: "REGULAR",
    businessSize: "SMALL",
    justification: "",
  }));
  const [profileRequestBusy, setProfileRequestBusy] = useState(false);

  useEffect(() => {
    setAvatarUrl(readStoredProfileAvatar(user));
  }, [user?.avatar, user?.id]);

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
        const parsedAccountProfile = parseAccountProfileMetadata(metadata);
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
          writeStoredProfileAvatar(user?.id, nextAvatar);
          updateUser({ avatar: nextAvatar });
        }
        setAccountProfile(parsedAccountProfile);
        setProfileRequest((prev) => ({
          ...prev,
          category:
            parsedAccountProfile.requestedCategory ??
            parsedAccountProfile.category,
          tier: parsedAccountProfile.requestedTier ?? parsedAccountProfile.tier,
          usagePurpose:
            parsedAccountProfile.requestContext?.usagePurpose ||
            prev.usagePurpose,
          expectedTransactionLevel:
            parsedAccountProfile.requestContext?.expectedTransactionLevel ||
            prev.expectedTransactionLevel,
          expectedTransactionFrequency:
            parsedAccountProfile.requestContext?.expectedTransactionFrequency ||
            prev.expectedTransactionFrequency,
          businessSize:
            parsedAccountProfile.requestContext?.businessSize ||
            prev.businessSize,
          justification:
            parsedAccountProfile.requestContext?.justification || "",
        }));
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
      writeStoredProfileAvatar(user?.id, avatarUrl);
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

  const submitAccountProfileRequest = async () => {
    if (!token) {
      toast("Session expired. Please login again.", "error");
      return;
    }
    try {
      setProfileRequestBusy(true);
      const resp = await fetch(`${API_BASE}/auth/me/account-profile`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          category: profileRequest.category,
          tier: profileRequest.tier,
          usagePurpose: profileRequest.usagePurpose,
          expectedTransactionLevel: profileRequest.expectedTransactionLevel,
          expectedTransactionFrequency:
            profileRequest.expectedTransactionFrequency,
          businessSize:
            profileRequest.category === "BUSINESS"
              ? profileRequest.businessSize
              : undefined,
          justification: profileRequest.justification,
        }),
      });
      const data = (await resp.json().catch(() => null)) as {
        error?: string;
        message?: string;
        metadata?: Record<string, unknown>;
        accountProfile?: Record<string, unknown>;
      } | null;
      if (!resp.ok) {
        if (isAuthExpired(resp.status, data?.error)) {
          toast("Session expired. Please sign in again.", "error");
          logout();
          return;
        }
        toast(data?.error || "Failed to submit profile request", "error");
        return;
      }
      const parsedAccountProfile = parseAccountProfileMetadata(data?.metadata);
      setAccountProfile(parsedAccountProfile);
      toast(
        data?.message ||
          "Profile request submitted. The current risk baseline stays active until admin approval.",
      );
    } catch {
      toast("Cannot connect to API server.", "error");
    } finally {
      setProfileRequestBusy(false);
    }
  };

  const openAvatarPicker = () => {
    fileInputRef.current?.click();
  };

  const persistAvatar = async (next: string, fallbackAvatar: string) => {
    if (!token) {
      toast("Session expired. Please sign in again.", "error");
      setAvatarUrl(fallbackAvatar);
      writeStoredProfileAvatar(user?.id, fallbackAvatar);
      updateUser({ avatar: fallbackAvatar });
      return false;
    }

    try {
      const resp = await fetch(`${API_BASE}/auth/me`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          metadata: {
            avatar: next,
          },
        }),
      });
      const data = (await resp.json().catch(() => null)) as {
        error?: string;
        avatar?: string;
        metadata?: Record<string, unknown>;
      } | null;
      if (!resp.ok) {
        if (isAuthExpired(resp.status, data?.error)) {
          toast("Session expired. Please sign in again.", "error");
          logout();
          return false;
        }
        setAvatarUrl(fallbackAvatar);
        writeStoredProfileAvatar(user?.id, fallbackAvatar);
        updateUser({ avatar: fallbackAvatar });
        toast(data?.error || "Failed to update avatar", "error");
        return false;
      }

      const persistedAvatar =
        (typeof data?.avatar === "string" && data.avatar) ||
        (typeof data?.metadata?.avatar === "string" && data.metadata.avatar) ||
        next;

      setAvatarUrl(persistedAvatar);
      writeStoredProfileAvatar(user?.id, persistedAvatar);
      updateUser({ avatar: persistedAvatar });
      toast("Profile image updated");
      return true;
    } catch {
      setAvatarUrl(fallbackAvatar);
      writeStoredProfileAvatar(user?.id, fallbackAvatar);
      updateUser({ avatar: fallbackAvatar });
      toast("Cannot connect to API server.", "error");
      return false;
    }
  };

  const handleAvatarChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const previousAvatar = avatarUrl;
    void compressProfileAvatar(file)
      .then((next) => {
        setAvatarUrl(next);
        updateUser({ avatar: next });
        writeStoredProfileAvatar(user?.id, next);
        return persistAvatar(next, previousAvatar);
      })
      .catch((err) => {
        const message =
          err instanceof Error && err.message
            ? err.message
            : "Failed to process image";
        toast(message, "error");
      });
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
            <span className="user-profile-pill accent">
              Tier:{" "}
              {formatAccountProfileLabel(
                accountProfile.category,
                accountProfile.tier,
              )}
            </span>
            <span className="user-profile-pill">
              {formatAccountProfileAutomationMode(
                accountProfile.automation?.mode,
              )}
            </span>
            <span className="user-profile-pill">
              Confidence {Math.round(accountProfile.confidence * 100)}%
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

      <section className="account-profile-panel">
        <div className="account-profile-head">
          <div>
            <strong>Automatic Card Tier Review</strong>
            <p>
              Personal tiers now upgrade automatically from clean activity over
              the last {accountProfile.automation?.reviewWindowDays ?? 30} days.
              Users can no longer widen their own AI baseline manually.
            </p>
          </div>
        </div>

        <div className="account-profile-meta-row">
          <span className="account-profile-meta-item">
            <strong>Status</strong>
            <em>{formatAccountProfileStatus(accountProfile.status)}</em>
          </span>
          <span className="account-profile-meta-item">
            <strong>Completed</strong>
            <em>
              {accountProfile.automation?.stats.completedCount ?? 0} transfers
            </em>
          </span>
          <span className="account-profile-meta-item">
            <strong>30d volume</strong>
            <em>
              $
              {(
                accountProfile.automation?.stats.totalVolume ?? 0
              ).toLocaleString("en-US", {
                minimumFractionDigits: 2,
                maximumFractionDigits: 2,
              })}
            </em>
          </span>
          <span className="account-profile-meta-item">
            <strong>Clean ratio</strong>
            <em>
              {Math.round(
                (accountProfile.automation?.stats.cleanActivityRatio ?? 1) *
                  100,
              )}
              %
            </em>
          </span>
          {accountProfile.automation?.nextTier ? (
            <span className="account-profile-meta-item">
              <strong>Next target</strong>
              <em>
                {formatAccountProfileLabel(
                  accountProfile.category,
                  accountProfile.automation.nextTier,
                )}
              </em>
            </span>
          ) : null}
        </div>

        <div className="account-profile-compact-grid">
          <div className="profile-review-card">
            <strong>Automatic review result</strong>
            <small>
              {accountProfile.automation?.autoUpgradeApplied
                ? "Your tier was upgraded automatically after the latest monthly review."
                : accountProfile.automation?.eligibleForUpgrade
                  ? "You already meet the next upgrade conditions and the baseline is ready to widen automatically."
                  : accountProfile.automation?.mode === "ADMIN_CONTROLLED"
                    ? "This account stays under admin-controlled tiering for demo and business review."
                    : "FPIPay is still collecting enough clean monthly behavior before widening your baseline."}
            </small>
            <small>
              Recommended baseline:{" "}
              {formatAccountProfileLabel(
                accountProfile.automation?.recommendedCategory ||
                  accountProfile.category,
                accountProfile.automation?.recommendedTier ||
                  accountProfile.tier,
              )}
            </small>
            {accountProfile.automation?.nextTier ? (
              <small>
                Next target:{" "}
                {formatAccountProfileLabel(
                  accountProfile.category,
                  accountProfile.automation.nextTier,
                )}
              </small>
            ) : null}
          </div>

          {accountProfile.automation?.milestones?.length ? (
            <div className="profile-review-context compact">
              <strong>Next upgrade</strong>
              {accountProfile.automation.milestones.slice(0, 3).map((item) => (
                <p key={item}>{item}</p>
              ))}
            </div>
          ) : null}
        </div>
      </section>

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
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const userMenuRef = useRef<HTMLDivElement>(null);
  const userMenuDropdownRef = useRef<HTMLDivElement>(null);
  const userMenuTriggerRef = useRef<HTMLButtonElement>(null);
  const [userMenuDropdownStyle, setUserMenuDropdownStyle] =
    useState<CSSProperties | null>(null);
  const supportMenuRef = useRef<HTMLDivElement>(null);
  const supportMenuTriggerRef = useRef<HTMLDivElement>(null);
  const supportMenuDropdownRef = useRef<HTMLDivElement>(null);
  const [supportMenuDropdownStyle, setSupportMenuDropdownStyle] =
    useState<CSSProperties | null>(null);
  const notificationMenuRef = useRef<HTMLDivElement>(null);
  const notificationDropdownRef = useRef<HTMLDivElement>(null);
  const notificationTriggerRef = useRef<HTMLButtonElement>(null);
  const [notificationDropdownStyle, setNotificationDropdownStyle] =
    useState<CSSProperties | null>(null);
  const updateUserMenuDropdownPosition = useCallback(() => {
    const triggerRect = userMenuTriggerRef.current?.getBoundingClientRect();
    if (!triggerRect) return;
    const maxWidth = 280;
    const minPadding = 12;
    const width = Math.min(maxWidth, window.innerWidth - minPadding * 2);
    const left = Math.min(
      Math.max(minPadding, triggerRect.right - width),
      window.innerWidth - width - minPadding,
    );
    const top = Math.min(
      window.innerHeight - minPadding,
      triggerRect.bottom + 10,
    );
    setUserMenuDropdownStyle({
      position: "fixed",
      top,
      left,
      width,
    });
  }, []);
  const updateSupportMenuDropdownPosition = useCallback(() => {
    const triggerRect = supportMenuTriggerRef.current?.getBoundingClientRect();
    if (!triggerRect) return;
    const maxWidth = 320;
    const minPadding = 12;
    const width = Math.min(maxWidth, window.innerWidth - minPadding * 2);
    const left = Math.min(
      Math.max(minPadding, triggerRect.right - width),
      window.innerWidth - width - minPadding,
    );
    const top = Math.min(
      window.innerHeight - minPadding,
      triggerRect.bottom + 10,
    );
    setSupportMenuDropdownStyle({
      position: "fixed",
      top,
      left,
      width,
    });
  }, []);
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
      const targetElement =
        target instanceof Element ? target : target.parentElement;
      const clickedNotificationTrigger =
        !!notificationMenuRef.current &&
        notificationMenuRef.current.contains(target);
      const clickedNotificationDropdown =
        !!notificationDropdownRef.current &&
        notificationDropdownRef.current.contains(target);
      if (!clickedNotificationTrigger && !clickedNotificationDropdown) {
        setShowNotifications(false);
        setShowAllNotificationsInDropdown(false);
      }
      const clickedUserTrigger =
        !!userMenuRef.current && userMenuRef.current.contains(target);
      const clickedUserDropdown =
        !!userMenuDropdownRef.current &&
        userMenuDropdownRef.current.contains(target);
      if (!clickedUserTrigger && !clickedUserDropdown) {
        setUserMenuOpen(false);
      }
      const clickedSupportTrigger =
        !!supportMenuRef.current && supportMenuRef.current.contains(target);
      const clickedSupportDropdown =
        !!supportMenuDropdownRef.current &&
        supportMenuDropdownRef.current.contains(target);
      if (!clickedSupportTrigger && !clickedSupportDropdown) {
        setUtilitiesExpanded(false);
      }
      const clickedMobileNavToggle =
        targetElement instanceof Element
          ? Boolean(targetElement.closest(".mobile-nav-toggle"))
          : false;
      const clickedMobileNavPanel =
        targetElement instanceof Element
          ? Boolean(targetElement.closest(".sidebar-menu-area"))
          : false;
      if (!clickedMobileNavToggle && !clickedMobileNavPanel) {
        setMobileNavOpen(false);
      }
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setShowNotifications(false);
        setShowAllNotificationsInDropdown(false);
        setUserMenuOpen(false);
        setUtilitiesExpanded(false);
        setMobileNavOpen(false);
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
    setMobileNavOpen(false);
  }, [activeTab]);

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
      setNotificationDropdownStyle(null);
      return;
    }
    const updateDropdownPosition = () => {
      const triggerRect =
        notificationTriggerRef.current?.getBoundingClientRect();
      if (!triggerRect) return;

      const maxWidth = 540;
      const minPadding = 12;
      const isMobileViewport = window.innerWidth <= 720;
      const width = Math.min(maxWidth, window.innerWidth - minPadding * 2);
      const mobileWidth = window.innerWidth - minPadding * 2;
      const left = isMobileViewport
        ? minPadding
        : Math.min(
            Math.max(minPadding, triggerRect.right - width),
            window.innerWidth - width - minPadding,
          );
      const top = Math.min(
        window.innerHeight - minPadding,
        triggerRect.bottom + (isMobileViewport ? 12 : 10),
      );
      const resolvedWidth = isMobileViewport ? mobileWidth : width;

      setNotificationDropdownStyle({
        position: "fixed",
        top,
        left,
        width: resolvedWidth,
        maxHeight: Math.min(window.innerHeight - top - minPadding, 760),
      });
    };

    updateDropdownPosition();
    window.addEventListener("resize", updateDropdownPosition);
    window.addEventListener("scroll", updateDropdownPosition, true);
    return () => {
      window.removeEventListener("resize", updateDropdownPosition);
      window.removeEventListener("scroll", updateDropdownPosition, true);
    };
  }, [showNotifications]);

  useLayoutEffect(() => {
    if (!userMenuOpen) {
      setUserMenuDropdownStyle(null);
      return;
    }
    updateUserMenuDropdownPosition();
    window.addEventListener("resize", updateUserMenuDropdownPosition);
    window.addEventListener("scroll", updateUserMenuDropdownPosition, true);
    return () => {
      window.removeEventListener("resize", updateUserMenuDropdownPosition);
      window.removeEventListener(
        "scroll",
        updateUserMenuDropdownPosition,
        true,
      );
    };
  }, [userMenuOpen, updateUserMenuDropdownPosition]);

  useLayoutEffect(() => {
    if (!utilitiesExpanded) {
      setSupportMenuDropdownStyle(null);
      return;
    }
    updateSupportMenuDropdownPosition();
    window.addEventListener("resize", updateSupportMenuDropdownPosition);
    window.addEventListener("scroll", updateSupportMenuDropdownPosition, true);
    return () => {
      window.removeEventListener("resize", updateSupportMenuDropdownPosition);
      window.removeEventListener(
        "scroll",
        updateSupportMenuDropdownPosition,
        true,
      );
    };
  }, [utilitiesExpanded, updateSupportMenuDropdownPosition]);

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
  const groupedDropdownNotifications = useMemo(() => {
    const groups: Array<{
      key: string;
      label: string;
      items: typeof visibleDropdownNotifications;
    }> = [];
    const groupIndexByKey = new Map<string, number>();

    visibleDropdownNotifications.forEach((notification) => {
      const label = getNotificationDayLabel(notification.createdAt);
      const createdAtDate = new Date(notification.createdAt);
      const key = Number.isNaN(createdAtDate.getTime())
        ? `unknown-${notification.id}`
        : createdAtDate.toISOString().slice(0, 10);
      const existingIndex = groupIndexByKey.get(key);
      if (existingIndex !== undefined) {
        groups[existingIndex].items.push(notification);
        return;
      }
      groupIndexByKey.set(key, groups.length);
      groups.push({
        key,
        label,
        items: [notification],
      });
    });

    return groups;
  }, [visibleDropdownNotifications]);

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
        <button
          type="button"
          className={`mobile-history-toggle ${activeTab === "Copilot" ? "show" : ""}`}
          aria-label="Toggle chat history"
          onClick={() =>
            window.dispatchEvent(new Event("fpipay-copilot-toggle-history"))
          }
        >
          ☰
        </button>
        <div className="logo">FPIPay</div>
        <div className="mobile-header-actions">
          <div className="bell-wrap mobile-bell-wrap" ref={notificationMenuRef}>
            <button
              type="button"
              className="bell"
              ref={notificationTriggerRef}
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
            {showNotifications &&
              createPortal(
                <div
                  className="notif-dropdown notif-dropdown-premium"
                  ref={notificationDropdownRef}
                  style={notificationDropdownStyle || undefined}
                >
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
                  <div className="notif-dropdown-list">
                    {!notificationsBusy &&
                      groupedDropdownNotifications.map((group, groupIndex) => (
                        <div key={group.key} className="notif-group">
                          <div className="notif-group-label">{group.label}</div>
                          {group.items.map((notification, itemIndex) => (
                            <button
                              key={notification.id}
                              type="button"
                              className={`notif-row notif-row-premium ${!notification.read ? "unread" : ""}`}
                              style={
                                {
                                  "--notif-delay": `${groupIndex * 36 + itemIndex * 48}ms`,
                                } as CSSProperties
                              }
                              onClick={() => {
                                markNotificationRead(notification.id);
                                setActiveTab("Notifications");
                                setShowNotifications(false);
                              }}
                            >
                              <div className="notif-row-head">
                                <span
                                  className={`notif-icon notif-icon-${notification.type}`}
                                  aria-hidden="true"
                                >
                                  {notification.type === "transactions"
                                    ? "TX"
                                    : "SH"}
                                </span>
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
                                <div
                                  className="notif-meta"
                                  title={notification.meta}
                                >
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
                        </div>
                      ))}
                    {!notificationsBusy &&
                      visibleDropdownNotifications.length === 0 && (
                        <div className="notif-empty">
                          {notificationsError || "No account activity yet."}
                        </div>
                      )}
                  </div>
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
                </div>,
                document.body,
              )}
          </div>
          <div
            className="user-menu-wrap mobile-user-menu-wrap"
            ref={userMenuRef}
          >
            <button
              type="button"
              className="user-menu-trigger"
              ref={userMenuTriggerRef}
              onClick={() =>
                setUserMenuOpen((current) => {
                  const next = !current;
                  if (next) {
                    updateUserMenuDropdownPosition();
                  }
                  return next;
                })
              }
              aria-expanded={userMenuOpen}
              aria-haspopup="true"
            >
              <img className="avatar" src={displayUser.avatar} alt="" />
              <span className="avatar-chevron">v</span>
            </button>
            {userMenuOpen &&
              createPortal(
                <div
                  className="user-menu-dropdown user-menu-dropdown-premium"
                  ref={userMenuDropdownRef}
                  style={userMenuDropdownStyle || undefined}
                >
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
                      setMobileNavOpen(false);
                    }}
                  >
                    My profile
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setActiveTab("Setting");
                      setUserMenuOpen(false);
                      setMobileNavOpen(false);
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
                </div>,
                document.body,
              )}
          </div>
          <button
            type="button"
            className="mobile-nav-toggle"
            aria-label="Toggle navigation menu"
            aria-expanded={mobileNavOpen}
            onClick={() => setMobileNavOpen((current) => !current)}
          >
            ☰
          </button>
        </div>
        <div className={`sidebar-menu-area ${mobileNavOpen ? "open" : ""}`}>
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
                      ref={
                        item.id === "Support"
                          ? supportMenuTriggerRef
                          : undefined
                      }
                      onClick={() => {
                        if (item.id === "Support") {
                          setUtilitiesExpanded((current) => {
                            const next = !current;
                            if (next) {
                              updateSupportMenuDropdownPosition();
                            }
                            return next;
                          });
                          return;
                        }
                        toggleExpanded(item);
                      }}
                      onKeyDown={(e) =>
                        e.key === "Enter" &&
                        (() => {
                          if (item.id === "Support") {
                            setUtilitiesExpanded((current) => {
                              const next = !current;
                              if (next) {
                                updateSupportMenuDropdownPosition();
                              }
                              return next;
                            });
                            return;
                          }
                          toggleExpanded(item);
                        })()
                      }
                      role="button"
                      tabIndex={0}
                    >
                      <span className="nav-dot" /> {item.label}
                      <span className="nav-chevron">
                        {isExpanded ? "v" : ">"}
                      </span>
                    </div>
                    {isExpanded &&
                      item.id === "Support" &&
                      createPortal(
                        <div
                          className="support-dropdown support-dropdown-premium"
                          ref={supportMenuDropdownRef}
                          style={supportMenuDropdownStyle || undefined}
                        >
                          {item.children.map((child) => (
                            <button
                              key={child.id}
                              type="button"
                              className={`support-dropdown-item ${activeTab === child.id ? "active" : ""}`}
                              onClick={() => {
                                setActiveTab(child.id);
                                setUtilitiesExpanded(false);
                                setMobileNavOpen(false);
                              }}
                            >
                              <span className="nav-dot" /> {child.label}
                            </button>
                          ))}
                        </div>,
                        document.body,
                      )}
                    {isExpanded &&
                      item.id !== "Support" &&
                      item.children.map((child) => (
                        <div
                          key={child.id}
                          className={`nav-item nav-item-child ${activeTab === child.id ? "active" : ""}`}
                          onClick={() => {
                            setActiveTab(child.id);
                            setUtilitiesExpanded(false);
                            setMobileNavOpen(false);
                          }}
                          onKeyDown={(e) =>
                            e.key === "Enter" &&
                            (() => {
                              setActiveTab(child.id);
                              setUtilitiesExpanded(false);
                              setMobileNavOpen(false);
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
                    setMobileNavOpen(false);
                  }}
                  onKeyDown={(e) =>
                    e.key === "Enter" &&
                    (() => {
                      setActiveTab(item.id);
                      setUtilitiesExpanded(false);
                      setMobileNavOpen(false);
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
          <div className="top-actions top-actions-inline" />
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
          {activeTab === "Dashboard" && (
            <DashboardView
              mode="dashboard"
              onOpenCopilotWorkspace={() => {
                setActiveTab("Copilot");
                setUtilitiesExpanded(false);
                setShowNotifications(false);
                setUserMenuOpen(false);
              }}
              onCloseCopilotWorkspace={() => setActiveTab("Dashboard")}
            />
          )}
          {activeTab === "Copilot" && (
            <DashboardView
              mode="copilot"
              onOpenCopilotWorkspace={() => {
                setActiveTab("Copilot");
                setUtilitiesExpanded(false);
                setShowNotifications(false);
                setUserMenuOpen(false);
              }}
              onCloseCopilotWorkspace={() => setActiveTab("Dashboard")}
            />
          )}
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
            "Copilot",
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
                  <DeferredFaceIdCapture
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
    options?: { rememberSession?: boolean },
  ) => Promise<LoginResult>;
  onVerifyLoginOtp: (
    challengeId: string,
    otp: string,
    captcha: SliderCaptchaValue,
    options?: { rememberSession?: boolean },
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
  const [signinRemember, setSigninRemember] = useState(() =>
    readStoredSaveLoginPreference(),
  );
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
    document.documentElement.classList.add(FORCE_AUTH_HERO_MOTION_CLASS);
    return () => {
      document.documentElement.classList.remove(FORCE_AUTH_HERO_MOTION_CLASS);
    };
  }, []);

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
  const sessionAlertDevice = summarizeDeviceUserAgent(
    pendingSessionAlert?.userAgent,
  );

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
    const confidence = Math.max(
      1,
      Math.min(99, Math.round((monitoring.score || 0) * 100)),
    );
    const headline =
      monitoring.headline ||
      (monitoring.requireOtp
        ? "AI requested a step-up verification for this sign-in"
        : "AI detected an unusual sign-in pattern");
    const summary =
      monitoring.summary ||
      "This sign-in differs from your normal pattern enough to trigger extra review.";
    const nextStep =
      monitoring.nextStep ||
      (monitoring.requireOtp
        ? "Complete the verification challenge before access is granted."
        : "Review the signals and continue only if the activity is yours.");
    const recommendedActions = (monitoring.recommendedActions || []).slice(
      0,
      3,
    );
    const timeline = (monitoring.timeline || []).slice(0, 3);

    return (
      <div className={`auth-ai-monitor auth-ai-monitor-${normalizedRisk}`}>
        <div className="auth-ai-monitor-head">
          <strong>AI Security Analyst</strong>
          <span className={`auth-ai-badge auth-ai-badge-${normalizedRisk}`}>
            {riskLabel}
          </span>
        </div>
        <p className="auth-ai-copy">{headline}</p>
        {monitoring.archetype ? (
          <p className="auth-ai-signal">Pattern: {monitoring.archetype}</p>
        ) : null}
        <p className="auth-ai-signal">
          Confidence {confidence}%. {summary}
        </p>
        {monitoring.requireOtp && (
          <p className="auth-ai-signal">
            Additional verification is required
            {monitoring.otpChannel ? ` via ${monitoring.otpChannel}` : ""}.
            {monitoring.otpReason ? ` ${monitoring.otpReason}` : ""}
          </p>
        )}
        <p className="auth-ai-signal">{nextStep}</p>
        {filteredReasons.length > 0 && (
          <ul className="auth-ai-reasons">
            {filteredReasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        )}
        {recommendedActions.length > 0 && (
          <ul className="auth-ai-reasons">
            {recommendedActions.map((action) => (
              <li key={action}>{action}</li>
            ))}
          </ul>
        )}
        {timeline.length > 0 && (
          <ul className="auth-ai-reasons">
            {timeline.map((step) => (
              <li key={step}>{step}</li>
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
          {strength.checks.map((check) => (
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
        { rememberSession: signinRemember },
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
        { rememberSession: signinRemember },
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
        { rememberSession: signinRemember },
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
            <span className="screen-title screen-title-fall">FPI Command</span>
            <span className="screen-pill screen-title-fall">Live shield</span>
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
              <div className="screen-balance-copy screen-copy-fall">
                <div className="muted screen-copy-text">Protected balance</div>
                <div className="big screen-copy-title">$12,450.00</div>
                <div className="screen-balance-note screen-copy-text">
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
              <div className="screen-copy-fall">
                <span className="muted screen-copy-text">Income</span>
                <strong className="screen-copy-title">$6,320</strong>
                <small className="screen-copy-text">Flow stable</small>
              </div>
              <div
                className="screen-copy-fall"
                style={{ "--copy-delay": "1.02s" } as CSSProperties}
              >
                <span className="muted screen-copy-text">Expenses</span>
                <strong className="screen-copy-title">$3,980</strong>
                <small className="screen-copy-text">Policy guarded</small>
              </div>
              <div
                className="screen-stat-highlight screen-copy-fall"
                style={{ "--copy-delay": "1.12s" } as CSSProperties}
              >
                <span className="muted screen-copy-text">Intelligence</span>
                <strong className="screen-copy-title">Active</strong>
                <small className="screen-copy-text">Adaptive alerts on</small>
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
                  <input
                    type="checkbox"
                    checked={signinRemember}
                    onChange={(e) => {
                      const nextValue = e.target.checked;
                      setSigninRemember(nextValue);
                      writeStoredSaveLoginPreference(nextValue);
                    }}
                  />{" "}
                  Remember me
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
              <DeferredSliderCaptcha
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
              <DeferredSliderCaptcha
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
            <form
              className="auth-form-modern auth-form-signup"
              onSubmit={handleSignUp}
            >
              <h2>Sign Up</h2>
              <p className="muted">
                Create your FPIPay account to start managing finances smartly.
              </p>
              <div className="grid-signup-top">
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
              </div>
              <div className="grid-signup-top">
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
              </div>
              <div className="grid-signup-password">
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
                <div className="auth-strength-slot">
                  {renderPasswordStrength(signupPasswordStrength)}
                </div>
              </div>
              <div className="auth-terms-row auth-span-two">
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
              <div className="auth-span-two">
                <DeferredSliderCaptcha
                  apiBase={API_BASE}
                  resetKey={signupCaptchaResetKey}
                  disabled={authBusy}
                  onChange={setSignupCaptcha}
                />
              </div>
              <button
                type="submit"
                className="btn-primary auth-submit auth-span-two"
                disabled={authBusy}
              >
                {authBusy ? "Creating..." : "Create Account"}
              </button>
              <p className="auth-switch auth-span-two">
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
                  <DeferredFaceIdCapture
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
              <DeferredSliderCaptcha
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
              <DeferredSliderCaptcha
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
              <DeferredSliderCaptcha
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
                  Device: {sessionAlertDevice.title}
                  {sessionAlertDevice.detail
                    ? ` · ${sessionAlertDevice.detail}`
                    : ""}
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
