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
      process.env.SMTP_FROM ||
      process.env.SMTP_USER ||
      "no-reply@secure-wallet.local",
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
  <div style="margin:0;padding:32px 16px;background:#071120;font-family:Segoe UI,Arial,sans-serif;color:#dbeafe">
    <div style="display:none;opacity:0;visibility:hidden;overflow:hidden;height:0;width:0">${input.preheader}</div>
    <div style="max-width:620px;margin:0 auto;background:#0c1730;border:1px solid #1d3a66;border-radius:24px;overflow:hidden;box-shadow:0 18px 48px rgba(0,0,0,0.35)">
      <div style="padding:28px 32px;background:radial-gradient(circle at top right,#1f8ef1 0%,#10264d 40%,#09162e 100%)">
        <div style="display:inline-block;padding:8px 12px;border-radius:999px;background:rgba(14,165,233,0.18);color:#7dd3fc;font-size:12px;font-weight:700;letter-spacing:1px;text-transform:uppercase">Secure Wallet</div>
        <h1 style="margin:16px 0 10px;color:#f8fafc;font-size:30px;line-height:1.2">${input.title}</h1>
        <p style="margin:0;color:#bfd4ff;font-size:15px;line-height:1.65">${input.subtitle}</p>
      </div>
      <div style="padding:32px">
        <p style="margin:0 0 14px;font-size:15px;color:#bfd4ff">Hello ${input.recipientName},</p>
        <p style="margin:0 0 18px;font-size:15px;color:#bfd4ff;line-height:1.7">
          Use the one-time password below to continue. This code can be used once and will expire automatically.
        </p>
        <div style="margin:0 0 20px;padding:22px;border-radius:18px;background:linear-gradient(90deg,#22d3ee,#22c55e,#f59e0b);text-align:center">
          <div style="font-size:12px;font-weight:700;letter-spacing:1.6px;color:#0f172a;text-transform:uppercase">One-time password</div>
          <div style="margin-top:10px;font-size:34px;font-weight:800;letter-spacing:10px;color:#04101f">${input.otpCode}</div>
        </div>
        <div style="padding:18px;border-radius:16px;background:#0a1327;border:1px solid #1d345a;margin-bottom:18px">
          <div style="font-size:12px;font-weight:700;letter-spacing:1px;color:#7dd3fc;text-transform:uppercase;margin-bottom:8px">${input.summaryLabel}</div>
          <div style="font-size:16px;font-weight:700;color:#f8fafc">${input.summaryValue}</div>
          <div style="margin-top:10px;font-size:13px;color:#93a9d2">Expires in ${input.expiresInMinutes} minutes</div>
        </div>
        <p style="margin:0 0 12px;font-size:14px;color:#bfd4ff;line-height:1.65">${input.securityNote}</p>
        <p style="margin:0;font-size:12px;color:#6b86b3;line-height:1.6">
          For your security, never share this code with anyone. Secure Wallet staff will never ask for your OTP.
        </p>
      </div>
    </div>
  </div>
`;

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
    subject: "Secure Wallet transfer verification code",
    text: `Your Secure Wallet transfer OTP is ${input.otpCode}. It expires in ${input.expiresInMinutes} minutes. Transfer amount: $${input.amount.toFixed(
      2,
    )}. Recipient account: ${input.toAccount}.`,
    html: renderOtpEmailHtml({
      preheader: "Verify your transfer with this one-time password.",
      title: "Transfer verification code",
      subtitle:
        "We received a request to approve an internal transfer from your Secure Wallet account.",
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

export const sendLoginOtpEmail = async (input: {
  to: string;
  recipientName: string;
  otpCode: string;
  expiresInMinutes: number;
}) =>
  sendEmail({
    to: input.to,
    subject: "Secure Wallet sign-in verification code",
    text: `Your Secure Wallet sign-in OTP is ${input.otpCode}. It expires in ${input.expiresInMinutes} minutes.`,
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
    html: `
      <div style="font-family:Arial,sans-serif;line-height:1.5;color:#111">
        <p>Hello ${input.recipientName},</p>
        <p>Your FPIPay verification code is:</p>
        <p style="font-size:28px;font-weight:700;letter-spacing:6px;margin:12px 0">${input.otpCode}</p>
        <p>This code expires in ${input.expiresInMinutes} minutes.</p>
        <p>If you did not request this, please ignore this email.</p>
      </div>
    `,
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
    subject: "Secure Wallet password reset code",
    text: `Your Secure Wallet password reset OTP is ${input.otpCode}. It expires in ${input.expiresInMinutes} minutes.`,
    html: renderOtpEmailHtml({
      preheader: "Use this one-time password to reset your Secure Wallet password.",
      title: "Password reset code",
      subtitle:
        "We received a request to reset the password for your Secure Wallet account.",
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
