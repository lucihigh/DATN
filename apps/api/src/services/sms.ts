import fetch from "node-fetch";

const getSmsConfig = () => ({
  mode: (process.env.SMS_OTP_MODE || "console").toLowerCase(),
  twilioAccountSid: process.env.TWILIO_ACCOUNT_SID || "",
  twilioAuthToken: process.env.TWILIO_AUTH_TOKEN || "",
  twilioFromNumber: process.env.TWILIO_FROM_NUMBER || "",
});

const sendSms = async (input: {
  to: string;
  body: string;
  debug: Record<string, unknown>;
}) => {
  const config = getSmsConfig();

  if (config.mode === "console") {
    console.log("[SMS_OTP:console]", {
      to: input.to,
      body: input.body,
      ...input.debug,
    });
    return { mode: "console" as const };
  }

  if (config.mode === "twilio") {
    if (
      !config.twilioAccountSid ||
      !config.twilioAuthToken ||
      !config.twilioFromNumber
    ) {
      throw new Error("Twilio SMS is not configured");
    }

    const body = new URLSearchParams({
      To: input.to,
      From: config.twilioFromNumber,
      Body: input.body,
    });
    const token = Buffer.from(
      `${config.twilioAccountSid}:${config.twilioAuthToken}`,
    ).toString("base64");
    const resp = await fetch(
      `https://api.twilio.com/2010-04-01/Accounts/${config.twilioAccountSid}/Messages.json`,
      {
        method: "POST",
        headers: {
          Authorization: `Basic ${token}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      },
    );

    if (!resp.ok) {
      const data = (await resp.json().catch(() => null)) as {
        message?: string;
      } | null;
      throw new Error(data?.message || `Twilio SMS failed with ${resp.status}`);
    }

    console.log("[SMS_OTP:twilio]", {
      to: input.to,
      ...input.debug,
    });
    return { mode: "twilio" as const };
  }

  throw new Error(`Unsupported SMS_OTP_MODE: ${config.mode}`);
};

export const sendHighRiskLoginOtpSms = async (input: {
  to: string;
  otpCode: string;
  expiresInMinutes: number;
}) =>
  sendSms({
    to: input.to,
    body:
      `FPIPay security check: your sign-in verification code is ${input.otpCode}. ` +
      `It expires in ${input.expiresInMinutes} minutes.`,
    debug: {
      otpCode: input.otpCode,
      expiresInMinutes: input.expiresInMinutes,
    },
  });
