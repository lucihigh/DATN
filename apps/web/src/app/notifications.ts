export const NOTIFICATION_READ_STORAGE_PREFIX = "fpipay_notification_reads";

export type ActivityNotificationType =
  | "transactions"
  | "security"
  | "assistant";

export type ActivityNotification = {
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

type SecurityAlertTone = "safe" | "info" | "warn";

export type SecurityOverviewAlert = {
  id?: string;
  title?: string;
  location?: string;
  detail?: string;
  tone?: SecurityAlertTone;
  occurredAt?: string;
};

export type SecurityRecentLoginItem = {
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

export type SecurityTrustedDeviceItem = {
  id: string;
  ipAddress: string;
  location: string;
  userAgent: string;
  firstSeenAt: string;
  lastSeenAt: string;
  lastVerifiedAt: string;
  current: boolean;
};

export type SecurityOverviewResponse = {
  alerts: SecurityOverviewAlert[];
  recentLogins: SecurityRecentLoginItem[];
  trustedDevices: SecurityTrustedDeviceItem[];
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

  const edgeVersion = userAgent.match(/Edg\/(\d+)/)?.[1];
  const chromeVersion = userAgent.match(/Chrome\/(\d+)/)?.[1];
  const firefoxVersion = userAgent.match(/Firefox\/(\d+)/)?.[1];
  const safariVersion = userAgent.match(/Version\/(\d+).+Safari\//)?.[1];

  const browser = edgeVersion
    ? `Edge ${edgeVersion}`
    : chromeVersion
      ? `Chrome ${chromeVersion}`
      : firefoxVersion
        ? `Firefox ${firefoxVersion}`
        : safariVersion
          ? `Safari ${safariVersion}`
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

export const formatSecurityNotification = (alert: SecurityOverviewAlert) => {
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
    meta: meta.length ? meta.join(" • ") : undefined,
  };
};
