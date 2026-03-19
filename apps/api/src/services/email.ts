import nodemailer from "nodemailer";

let cachedTransporter: nodemailer.Transporter | null = null;

const getEmailConfig = () => {
  const smtpPort = Number(process.env.SMTP_PORT || "587");
  return {
    emailOtpMode: (process.env.EMAIL_OTP_MODE || "console").toLowerCase(),
    smtpHost: process.env.SMTP_HOST || "",
    smtpPort,
    smtpUser: process.env.SMTP_USER || "",
    smtpPass: process.env.SMTP_PASS || "",
    smtpFrom:
      process.env.SMTP_FROM || process.env.SMTP_USER || "no-reply@fpipay.local",
    smtpSecure:
      String(process.env.SMTP_SECURE || "").toLowerCase() === "true" ||
      smtpPort === 465,
  };
};

const getTransporter = () => {
  const config = getEmailConfig();
  if (cachedTransporter) return cachedTransporter;
  if (!config.smtpHost || !config.smtpUser || !config.smtpPass) {
    throw new Error("SMTP is not configured");
  }
  cachedTransporter = nodemailer.createTransport({
    host: config.smtpHost,
    port: config.smtpPort,
    secure: config.smtpSecure,
    auth: {
      user: config.smtpUser,
      pass: config.smtpPass,
    },
  });
  return cachedTransporter;
};

const renderOtpEmailHtml = (input: {
  preheader: string;
  title: string;
  subtitle: string;
  recipientName: string;
  otpCode: string;
  expiresInMinutes: number;
  summaryLabel: string;
  summaryValue: string;
  securityNote: string;
}) => `
  <div style="margin:0;padding:24px 12px;background:#f3f4f6;font-family:Arial,Helvetica,sans-serif;color:#111827">
    <div style="display:none;opacity:0;visibility:hidden;overflow:hidden;height:0;width:0">${input.preheader}</div>
    <div style="max-width:560px;margin:0 auto;background:#ffffff;border:1px solid #d1d5db">
      <div style="padding:20px 24px;border-bottom:1px solid #e5e7eb">
        <div style="font-size:18px;font-weight:700;color:#111827">FPIPay</div>
        <div style="margin-top:6px;font-size:20px;font-weight:700;color:#111827">${input.title}</div>
        <p style="margin:10px 0 0;font-size:14px;line-height:1.6;color:#374151">${input.subtitle}</p>
      </div>
      <div style="padding:24px">
        <p style="margin:0 0 12px;font-size:14px;color:#111827">Hello ${input.recipientName},</p>
        <p style="margin:0 0 16px;font-size:14px;line-height:1.7;color:#374151">
          Use the verification code below to continue. This code can only be used once.
        </p>
        <div style="margin:0 0 16px;padding:16px;border:1px solid #d1d5db;background:#f9fafb;text-align:center">
          <div style="font-size:12px;font-weight:700;letter-spacing:1px;color:#6b7280;text-transform:uppercase">Verification code</div>
          <div style="margin-top:8px;font-size:32px;font-weight:700;letter-spacing:8px;color:#111827">${input.otpCode}</div>
        </div>
        <div style="margin-bottom:16px;border:1px solid #e5e7eb;background:#ffffff">
          <div style="padding:10px 14px;border-bottom:1px solid #e5e7eb;font-size:12px;font-weight:700;color:#6b7280;text-transform:uppercase">${input.summaryLabel}</div>
          <div style="padding:12px 14px;font-size:14px;color:#111827">${input.summaryValue}</div>
          <div style="padding:0 14px 12px;font-size:13px;color:#6b7280">Expires in ${input.expiresInMinutes} minutes</div>
        </div>
        <p style="margin:0 0 10px;font-size:13px;line-height:1.7;color:#374151">${input.securityNote}</p>
        <p style="margin:0;font-size:12px;line-height:1.6;color:#6b7280">
          Do not share this code with anyone. FPIPay staff will never ask for your OTP.
        </p>
      </div>
    </div>
  </div>
`;

const formatMoney = (currency: string, amount: number) =>
  `${currency} ${amount.toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;

const sendEmail = async (input: {
  to: string;
  subject: string;
  text: string;
  html: string;
  debug: Record<string, unknown>;
}) => {
  const config = getEmailConfig();

  if (config.emailOtpMode === "console") {
    console.log("[EMAIL_OTP:console]", {
      to: input.to,
      subject: input.subject,
      ...input.debug,
    });
    return { mode: "console" as const };
  }

  if (config.emailOtpMode === "smtp") {
    const transporter = getTransporter();
    const info = await transporter.sendMail({
      from: config.smtpFrom,
      to: input.to,
      subject: input.subject,
      text: input.text,
      html: input.html,
    });
    console.log("[EMAIL_OTP:smtp]", {
      to: input.to,
      subject: input.subject,
      messageId: info.messageId,
      accepted: info.accepted,
      rejected: info.rejected,
    });
    return { mode: "smtp" as const };
  }

  throw new Error(`Unsupported EMAIL_OTP_MODE: ${config.emailOtpMode}`);
};

export const sendTransferOtpEmail = async (input: {
  to: string;
  recipientName: string;
  otpCode: string;
  expiresInMinutes: number;
  amount: number;
  toAccount: string;
}) =>
  sendEmail({
    to: input.to,
    subject: "FPIPay transfer verification code",
    text: `Your FPIPay transfer OTP is ${input.otpCode}. It expires in ${input.expiresInMinutes} minutes. Transfer amount: $${input.amount.toFixed(
      2,
    )}. Recipient account: ${input.toAccount}.`,
    html: renderOtpEmailHtml({
      preheader: "Verify your transfer with this one-time password.",
      title: "Transfer verification code",
      subtitle:
        "We received a request to approve an internal transfer from your FPIPay account.",
      recipientName: input.recipientName,
      otpCode: input.otpCode,
      expiresInMinutes: input.expiresInMinutes,
      summaryLabel: "Transfer details",
      summaryValue: `$${input.amount.toLocaleString("en-US", {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2,
      })} to account ${input.toAccount}`,
      securityNote:
        "If you did not initiate this transfer, sign in immediately and review your recent activity.",
    }),
    debug: {
      otpCode: input.otpCode,
      amount: input.amount,
      toAccount: input.toAccount,
    },
  });

export const sendTransferRiskAlertEmail = async (input: {
  to: string;
  recipientName: string;
  amount: number;
  currency: string;
  toAccount: string;
  reason: string;
  totalOutflowWindow: number;
  windowLabel: string;
  actionRequired: "faceid" | "blocked";
}) => {
  const amountLabel = formatMoney(input.currency, input.amount);
  const totalWindowLabel = formatMoney(
    input.currency,
    input.totalOutflowWindow,
  );
  const actionLabel =
    input.actionRequired === "blocked"
      ? "Transfer blocked for security review"
      : "Additional biometric verification required";

  return sendEmail({
    to: input.to,
    subject:
      input.actionRequired === "blocked"
        ? "FPIPay security alert: transfer temporarily blocked"
        : "FPIPay security alert: FaceID verification required",
    text:
      `Hello ${input.recipientName},\n\n` +
      `${actionLabel}\n\n` +
      `Transfer amount: ${amountLabel}\n` +
      `Recipient account: ${input.toAccount}\n` +
      `Reason: ${input.reason}\n` +
      `Total outgoing in the last ${input.windowLabel}: ${totalWindowLabel}\n\n` +
      `${
        input.actionRequired === "blocked"
          ? "This transfer cannot continue until the security waiting period ends."
          : "Please complete FaceID verification in FPIPay before the transfer can continue."
      }\n\n` +
      `If you do not recognize this activity, secure your account immediately.`,
    html: `
      <div style="margin:0;padding:24px 12px;background:#f3f4f6;font-family:Arial,Helvetica,sans-serif;color:#111827">
        <div style="max-width:620px;margin:0 auto;background:#ffffff;border:1px solid #d1d5db">
          <div style="padding:18px 24px;border-bottom:3px solid #b91c1c">
            <div style="font-size:18px;font-weight:700;color:#111827">FPIPay Security Alert</div>
            <div style="margin-top:8px;font-size:24px;font-weight:700;color:#991b1b">${actionLabel}</div>
          </div>
          <div style="padding:24px">
            <p style="margin:0 0 14px;font-size:14px;color:#111827">Hello ${input.recipientName},</p>
            <p style="margin:0 0 16px;font-size:14px;line-height:1.7;color:#374151">
              FPIPay applied a security control to a transfer attempt because the activity matched a monitored risk condition.
            </p>
            <table role="presentation" style="width:100%;border-collapse:collapse;border:1px solid #d1d5db;margin:0 0 16px">
              <tr><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;background:#f9fafb;width:42%;font-size:13px;color:#6b7280">Transfer amount</td><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;font-size:14px;font-weight:700;color:#111827">${amountLabel}</td></tr>
              <tr><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;background:#f9fafb;font-size:13px;color:#6b7280">Recipient account</td><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;font-size:14px;color:#111827">${input.toAccount}</td></tr>
              <tr><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;background:#f9fafb;font-size:13px;color:#6b7280">Detected reason</td><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;font-size:14px;color:#111827">${input.reason}</td></tr>
              <tr><td style="padding:10px 12px;background:#f9fafb;font-size:13px;color:#6b7280">Recent outgoing total</td><td style="padding:10px 12px;font-size:14px;color:#111827">${totalWindowLabel} in the last ${input.windowLabel}</td></tr>
            </table>
            <p style="margin:0;font-size:13px;line-height:1.7;color:#374151">
              ${
                input.actionRequired === "blocked"
                  ? "This transfer remains blocked until the current security waiting period ends."
                  : "Please complete FaceID verification in FPIPay before the transfer can continue."
              }
            </p>
            <p style="margin:12px 0 0;font-size:13px;line-height:1.7;color:#374151">
              If you do not recognize this activity, review recent sign-ins, reset your password, and contact support immediately.
            </p>
          </div>
        </div>
      </div>
    `,
    debug: {
      amount: input.amount,
      currency: input.currency,
      toAccount: input.toAccount,
      reason: input.reason,
      totalOutflowWindow: input.totalOutflowWindow,
      windowLabel: input.windowLabel,
      actionRequired: input.actionRequired,
    },
  });
};

export const sendLoginOtpEmail = async (input: {
  to: string;
  recipientName: string;
  otpCode: string;
  expiresInMinutes: number;
}) =>
  sendEmail({
    to: input.to,
    subject: "FPIPay sign-in verification code",
    text: `Your FPIPay sign-in OTP is ${input.otpCode}. It expires in ${input.expiresInMinutes} minutes.`,
    html: renderOtpEmailHtml({
      preheader: "Verify your sign-in with this one-time password.",
      title: "Sign-in verification code",
      subtitle:
        "A sign-in attempt matched your password. Enter this one-time password to finish accessing your account.",
      recipientName: input.recipientName,
      otpCode: input.otpCode,
      expiresInMinutes: input.expiresInMinutes,
      summaryLabel: "Request type",
      summaryValue: "Secure account sign-in",
      securityNote:
        "If this sign-in was not requested by you, change your password and review your account security settings.",
    }),
    debug: { otpCode: input.otpCode },
  });

export const sendLoginRiskAlertEmail = async (input: {
  to: string;
  recipientName: string;
  ipAddress?: string;
  userAgent?: string;
  reason?: string;
}) =>
  sendEmail({
    to: input.to,
    subject: "FPIPay security alert: unusual sign-in detected",
    text:
      `Hello ${input.recipientName},\n\n` +
      `We detected a sign-in that requires additional attention.\n` +
      `${input.reason ? `Reason: ${input.reason}\n` : ""}` +
      `${input.ipAddress ? `IP address: ${input.ipAddress}\n` : ""}` +
      `${input.userAgent ? `Device: ${input.userAgent}\n` : ""}` +
      `\nIf this activity was not initiated by you, secure your account immediately.`,
    html: `
      <div style="margin:0;padding:24px 12px;background:#f3f4f6;font-family:Arial,Helvetica,sans-serif;color:#111827">
        <div style="max-width:620px;margin:0 auto;background:#ffffff;border:1px solid #d1d5db">
          <div style="padding:18px 24px;border-bottom:3px solid #b91c1c">
            <div style="font-size:18px;font-weight:700;color:#111827">FPIPay Security Alert</div>
            <div style="margin-top:8px;font-size:24px;font-weight:700;color:#991b1b">Unusual sign-in detected</div>
          </div>
          <div style="padding:24px">
            <p style="margin:0 0 14px;font-size:14px;color:#111827">Hello ${input.recipientName},</p>
            <p style="margin:0 0 16px;font-size:14px;line-height:1.7;color:#374151">
              We detected a sign-in that requires additional monitoring.
            </p>
            <table role="presentation" style="width:100%;border-collapse:collapse;border:1px solid #d1d5db;margin:0 0 16px">
              <tr><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;background:#f9fafb;width:42%;font-size:13px;color:#6b7280">Reason</td><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;font-size:14px;color:#111827">${input.reason || "New or unusual sign-in pattern detected"}</td></tr>
              <tr><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;background:#f9fafb;font-size:13px;color:#6b7280">IP address</td><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;font-size:14px;color:#111827">${input.ipAddress || "Unavailable"}</td></tr>
              <tr><td style="padding:10px 12px;background:#f9fafb;font-size:13px;color:#6b7280">Device</td><td style="padding:10px 12px;font-size:14px;color:#111827">${input.userAgent || "Unavailable"}</td></tr>
            </table>
            <p style="margin:0;font-size:13px;line-height:1.7;color:#374151">
              If this was not you, reset your password immediately and review recent account activity.
            </p>
          </div>
        </div>
      </div>
    `,
    debug: {
      ipAddress: input.ipAddress,
      userAgent: input.userAgent,
      reason: input.reason,
    },
  });

export const sendRegisterOtpEmail = async (input: {
  to: string;
  recipientName: string;
  otpCode: string;
  expiresInMinutes: number;
}) =>
  sendEmail({
    to: input.to,
    subject: "FPIPay Verify Code",
    text: `Your FPIPay registration OTP is ${input.otpCode}. It expires in ${input.expiresInMinutes} minutes.`,
    html: renderOtpEmailHtml({
      preheader:
        "Use this verification code to complete your FPIPay registration.",
      title: "Registration verification code",
      subtitle:
        "We received a request to create or complete an FPIPay account.",
      recipientName: input.recipientName,
      otpCode: input.otpCode,
      expiresInMinutes: input.expiresInMinutes,
      summaryLabel: "Request type",
      summaryValue: "Account registration",
      securityNote:
        "If you did not request this code, you can ignore this email.",
    }),
    debug: { otpCode: input.otpCode },
  });

export const sendPasswordResetOtpEmail = async (input: {
  to: string;
  recipientName: string;
  otpCode: string;
  expiresInMinutes: number;
}) =>
  sendEmail({
    to: input.to,
    subject: "FPIPay password reset code",
    text: `Your FPIPay password reset OTP is ${input.otpCode}. It expires in ${input.expiresInMinutes} minutes.`,
    html: renderOtpEmailHtml({
      preheader: "Use this one-time password to reset your FPIPay password.",
      title: "Password reset code",
      subtitle:
        "We received a request to reset the password for your FPIPay account.",
      recipientName: input.recipientName,
      otpCode: input.otpCode,
      expiresInMinutes: input.expiresInMinutes,
      summaryLabel: "Request type",
      summaryValue: "Reset account password",
      securityNote:
        "If you did not request a password reset, ignore this email and keep monitoring your inbox for unusual activity.",
    }),
    debug: { otpCode: input.otpCode },
  });

export const sendBalanceChangeEmail = async (input: {
  to: string;
  recipientName: string;
  direction: "credit" | "debit";
  amount: number;
  balance: number;
  currency: string;
  transactionType: "DEPOSIT" | "TRANSFER";
  description: string;
  occurredAt: string;
  counterpartyLabel?: string;
}) => {
  const amountLabel = formatMoney(input.currency, input.amount);
  const balanceLabel = formatMoney(input.currency, input.balance);
  const isCredit = input.direction === "credit";
  const subject = isCredit
    ? `FPIPay alert: +${amountLabel} credited`
    : `FPIPay alert: -${amountLabel} debited`;
  const movementLabel = isCredit ? "credited to" : "debited from";
  const counterpartyLine = input.counterpartyLabel
    ? `Counterparty: ${input.counterpartyLabel}.`
    : "";
  const transactionTypeLabel =
    input.transactionType === "DEPOSIT" ? "Deposit" : "Transfer";

  return sendEmail({
    to: input.to,
    subject,
    text:
      `Hello ${input.recipientName},\n\n` +
      `${amountLabel} has been ${movementLabel} your FPIPay account.\n` +
      `Available balance: ${balanceLabel}.\n` +
      `Transaction type: ${transactionTypeLabel}.\n` +
      `Description: ${input.description}.\n` +
      `${counterpartyLine ? `${counterpartyLine}\n` : ""}` +
      `Time: ${input.occurredAt}.\n\n` +
      `If you do not recognize this activity, secure your account immediately.`,
    html: `
      <div style="margin:0;padding:24px 12px;background:#f5f5f5;font-family:Arial,Helvetica,sans-serif;color:#111827">
        <div style="max-width:640px;margin:0 auto;background:#ffffff;border:1px solid #d1d5db">
          <div style="padding:18px 24px;border-bottom:1px solid #d1d5db">
            <div style="font-size:18px;font-weight:700;color:#111827">BALANCE CHANGE NOTIFICATION</div>
            <div style="margin-top:4px;font-size:13px;color:#6b7280">FPIPay Electronic Wallet Notice</div>
          </div>
          <div style="padding:24px">
            <p style="margin:0 0 14px;font-size:14px;color:#111827">Dear ${input.recipientName},</p>
            <p style="margin:0 0 16px;font-size:14px;line-height:1.7;color:#374151">
              Our system recorded a successful transaction and updated your account balance as follows:
            </p>
            <table role="presentation" style="width:100%;border-collapse:collapse;border:1px solid #d1d5db">
              <tr><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;background:#f9fafb;width:38%;font-size:13px;color:#6b7280">Transaction Type</td><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;font-size:14px;color:#111827">${transactionTypeLabel}</td></tr>
              <tr><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;background:#f9fafb;font-size:13px;color:#6b7280">Balance Change</td><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;font-size:14px;font-weight:700;color:#111827">${isCredit ? "+" : "-"}${amountLabel}</td></tr>
              <tr><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;background:#f9fafb;font-size:13px;color:#6b7280">Available Balance</td><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;font-size:14px;font-weight:700;color:#111827">${balanceLabel}</td></tr>
              <tr><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;background:#f9fafb;font-size:13px;color:#6b7280">Description</td><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;font-size:14px;color:#111827">${input.description}</td></tr>
              ${
                input.counterpartyLabel
                  ? `<tr><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;background:#f9fafb;font-size:13px;color:#6b7280">Counterparty</td><td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;font-size:14px;color:#111827">${input.counterpartyLabel}</td></tr>`
                  : ""
              }
              <tr><td style="padding:10px 12px;background:#f9fafb;font-size:13px;color:#6b7280">Time</td><td style="padding:10px 12px;font-size:14px;color:#111827">${input.occurredAt}</td></tr>
            </table>
            <p style="margin:16px 0 0;font-size:12px;line-height:1.7;color:#6b7280">
              Please review this activity and contact support immediately if you do not recognize this transaction.
            </p>
          </div>
        </div>
      </div>
    `,
    debug: {
      direction: input.direction,
      amount: input.amount,
      balance: input.balance,
      currency: input.currency,
      transactionType: input.transactionType,
      occurredAt: input.occurredAt,
    },
  });
};
