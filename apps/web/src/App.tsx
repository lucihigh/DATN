import { useState, useEffect, useRef } from "react";
import jsQR from "jsqr";

import { useAuth } from "./context/AuthContext";
import { useToast } from "./context/ToastContext";
import { useTheme } from "./context/ThemeContext";
import "./index.css";

const API_BASE =
  (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, "") ||
  "http://localhost:4000";

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
    title: "Deposit (Demo)",
    detail: "Add funds instantly",
    icon: "💳",
  },
  {
    id: "transfer",
    title: "Internal Transfer",
    detail: "Move funds between accounts",
    icon: "➤",
  },
];

const dashboardSecurityAlerts = [
  {
    title: "Login Verified",
    location: "San Francisco, US",
    detail:
      "Device: MacBook Pro (Chrome 124). AI analyzed behavior patterns and confirmed identity matches your typical usage.",
    time: "2 minutes ago",
    tone: "safe",
  },
  {
    title: "New Device Registered",
    location: "London, UK",
    detail:
      "Device: iPhone 15 Pro. Device fingerprint added to encrypted vault. Bio-auth enabled successfully.",
    time: "Today, 10:45 AM",
    tone: "info",
  },
  {
    title: "Anomalous Connection Blocked",
    location: "Unrecognized IP",
    detail:
      "AI detection engine automatically blocked a login attempt from a known malicious proxy server. No data compromised.",
    time: "Yesterday, 11:20 PM",
    tone: "warn",
  },
];

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
  const { user, token } = useAuth();
  const { toast } = useToast();
  const transferQrVideoRef = useRef<HTMLVideoElement>(null);
  const transferQrStreamRef = useRef<MediaStream | null>(null);
  const transferQrScanTimerRef = useRef<number | null>(null);
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
  const [transferStep, setTransferStep] = useState<1 | 2 | 3 | 4>(1);
  const [transferMethod, setTransferMethod] = useState<"account" | "qr">(
    "account",
  );
  const [transferAccount, setTransferAccount] = useState("");
  const [transferReceiverName, setTransferReceiverName] = useState("");
  const [transferAmount, setTransferAmount] = useState("");
  const [transferContent, setTransferContent] = useState("");
  const [transferQrFile, setTransferQrFile] = useState("");
  const [transferQrRaw, setTransferQrRaw] = useState("");
  const [transferQrCameraOn, setTransferQrCameraOn] = useState(false);
  const [transferQrCameraError, setTransferQrCameraError] = useState("");
  const [transferQrFacingMode, setTransferQrFacingMode] = useState<
    "environment" | "user"
  >("environment");
  const [transferQrDevices, setTransferQrDevices] = useState<MediaDeviceInfo[]>(
    [],
  );
  const [transferQrDeviceId, setTransferQrDeviceId] = useState("");
  const [transferShowMyQr, setTransferShowMyQr] = useState(false);
  const [transferOtpCode, setTransferOtpCode] = useState("");
  const [transferOtpInput, setTransferOtpInput] = useState("");
  const [transferOtpError, setTransferOtpError] = useState("");
  const [transferOtpAttempts, setTransferOtpAttempts] = useState(0);
  const [transactionHistory, setTransactionHistory] = useState<
    { entity: string; date: string; status: string; amount: string; amountTone: "positive" | "negative" }[]
  >([]);
  const [historyModalOpen, setHistoryModalOpen] = useState(false);
  const [transferReceipt, setTransferReceipt] = useState<{
    txId: string;
    executedAt: string;
    fromAccount: string;
    toAccount: string;
    amountUsd: string;
    feeUsd: string;
    note: string;
    status: string;
  } | null>(null);

  const cardProfile = {
    holder: "Alex Thompson",
    number: "1234 5678 9012 5678",
    type: "Visa Signature",
    expiry: "09/29",
    cvv: "***",
    status: "Active",
    issuedAt: "San Francisco Main Branch",
    linkedAccount: "Checking •••• 8841",
    dailyLimit: "$10,000.00",
    contactless: "Enabled",
    onlinePayment: "Enabled",
    lastActivity: "Mar 05, 2026 · 09:42 AM",
  };

  const walletRaw = wallet?.accountNumber || wallet?.id || "";
  const walletDigits = walletRaw.replace(/\D/g, "").slice(0, 19);
  const maskedDigits =
    showWalletId || walletDigits.length <= 4
      ? walletDigits
      : `${"*".repeat(walletDigits.length - 4)}${walletDigits.slice(-4)}`;
  const walletGroups = (maskedDigits.match(/.{1,4}/g) ?? []).map((group) =>
    group.replace(/\*/g, "•"),
  );
  const defaultTransferContent = `${user?.name ?? "User"} transfer`;
  const transferAmountNumber = Number(transferAmount.replace(/,/g, ""));
  const isInsufficientBalance =
    wallet !== null &&
    transferAmount.trim().length > 0 &&
    Number.isFinite(transferAmountNumber) &&
    transferAmountNumber > Number(wallet.balance);
  const canContinueTransferAmount =
    wallet !== null &&
    transferAmount.trim().length > 0 &&
    Number.isFinite(transferAmountNumber) &&
    transferAmountNumber > 0 &&
    !isInsufficientBalance;
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

  const extractAccountFromQrPayload = (payload: string) =>
    payload.match(/ACC:(\d{8,19})/i)?.[1] || payload.replace(/\D/g, "").slice(0, 19);

  const stopTransferQrCameraScan = () => {
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

  const handleTransferQrPayloadDetected = (payload: string) => {
    setTransferQrRaw(payload);
    const extracted = extractAccountFromQrPayload(payload);
    if (!/^\d{8,19}$/.test(extracted)) {
      toast("Cannot detect a valid account number from QR payload.", "error");
      return;
    }
    setTransferAccount(extracted);
    setTransferReceiverName(`QR Recipient •••• ${extracted.slice(-4)}`);
    toast("QR scanned successfully.");
  };

  const startTransferQrCameraScan = async (
    preferredFacingMode: "environment" | "user" = transferQrFacingMode,
  ) => {
    const BarcodeDetectorCtor = (
      window as Window & {
        BarcodeDetector?: new (opts?: {
          formats?: string[];
        }) => { detect: (source: ImageBitmapSource) => Promise<Array<{ rawValue?: string }>> };
      }
    ).BarcodeDetector;

    stopTransferQrCameraScan();

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
          facingMode: { ideal: preferredFacingMode === "environment" ? "user" : "environment" },
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
        | (new (track: MediaStreamTrack) => { grabFrame: () => Promise<ImageBitmap> })
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
              const imageData = frameCtx.getImageData(0, 0, vw, vh);
              const decoded = jsQR(imageData.data, imageData.width, imageData.height, {
                inversionAttempts: "attemptBoth",
              });
              raw = decoded?.data?.trim() || "";
            }
          }

          if (!raw && activeTrack && ImageCaptureCtor && activeTrack.readyState === "live") {
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
                const imageData = frameCtx.getImageData(
                  0,
                  0,
                  bitmap.width,
                  bitmap.height,
                );
                const decoded = jsQR(
                  imageData.data,
                  imageData.width,
                  imageData.height,
                  {
                    inversionAttempts: "attemptBoth",
                  },
                );
                raw = decoded?.data?.trim() || "";
              }
            } finally {
              bitmap.close();
            }
          }

          if (!raw) return;
          stopTransferQrCameraScan();
          handleTransferQrPayloadDetected(raw);
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
        setTransferQrCameraError("Camera permission denied. Please allow camera access.");
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
        BarcodeDetector?: new (opts?: {
          formats?: string[];
        }) => { detect: (source: ImageBitmapSource) => Promise<Array<{ rawValue?: string }>> };
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
          handleTransferQrPayloadDetected(raw);
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
          const decoded = jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: "attemptBoth",
          });
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
        handleTransferQrPayloadDetected(raw);
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
    if (!token) return;
    const headers = { Authorization: `Bearer ${token}` };
    const load = async () => {
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
            description?: string;
            createdAt: string;
            metadata?: {
              entry?: "DEBIT" | "CREDIT";
              fromAccount?: string;
              toAccount?: string;
            };
          }>;
          setTransactionHistory(
            txs.map((tx) => {
              const isCredit =
                tx.type === "DEPOSIT" || tx.metadata?.entry === "CREDIT";
              return {
                entity: tx.description || tx.type,
                date: new Date(tx.createdAt).toLocaleString("en-US"),
                status: "Completed",
                amount: `${isCredit ? "+" : "-"}$${Math.abs(
                  Number(tx.amount || 0),
                ).toLocaleString("en-US", {
                  minimumFractionDigits: 2,
                  maximumFractionDigits: 2,
                })}`,
                amountTone: isCredit ? "positive" : "negative",
              };
            }),
          );
        }
      } catch {
        setWallet(null);
        setTransactionHistory([]);
      }
    };
    void load();
  }, [token]);

  const generateOtp = () => {
    const next = String(Math.floor(100000 + Math.random() * 900000));
    setOtpCode(next);
    setOtpInput("");
    setOtpError("");
    setOtpAttempts(0);
    toast(`OTP sent to +1 ••• ••67 (demo OTP: ${next})`, "info");
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
    stopTransferQrCameraScan();
    setTransferStep(1);
    setTransferMethod("account");
    setTransferAccount("");
    setTransferReceiverName("");
    setTransferAmount("");
    setTransferContent(defaultTransferContent);
    setTransferQrFile("");
    setTransferQrRaw("");
    setTransferQrCameraError("");
    setTransferQrFacingMode("environment");
    setTransferShowMyQr(false);
    setTransferOtpCode("");
    setTransferOtpInput("");
    setTransferOtpError("");
    setTransferOtpAttempts(0);
    setTransferReceipt(null);
  };

  const openTransferModal = () => {
    setTransferOpen(true);
    resetTransferFlow();
  };

  const closeTransferModal = () => {
    setTransferOpen(false);
    resetTransferFlow();
  };

  useEffect(() => {
    return () => {
      stopTransferQrCameraScan();
    };
  }, []);

  useEffect(() => {
    if (!transferOpen || transferStep !== 1 || transferMethod !== "qr") return;
    void loadTransferQrDevices();
  }, [transferOpen, transferStep, transferMethod]);

  const generateTransferOtp = () => {
    const next = String(Math.floor(100000 + Math.random() * 900000));
    setTransferOtpCode(next);
    setTransferOtpInput("");
    setTransferOtpError("");
    setTransferOtpAttempts(0);
    toast(`Transfer OTP sent (demo OTP: ${next})`, "info");
  };
  const continueTransferRecipient = async () => {
    if (!token) {
      toast("Session expired. Please login again.", "error");
      return;
    }

    if (transferMethod === "account") {
      if (!/^\d{8,19}$/.test(transferAccount)) {
        toast("Please enter a valid account number (8-19 digits).", "error");
        return;
      }
    } else if (!transferAccount) {
      toast("Please scan QR by camera or extract account from QR payload first.", "error");
      return;
    }

    try {
      const resp = await fetch(
        `${API_BASE}/wallet/resolve/${encodeURIComponent(transferAccount)}`,
        {
          headers: { Authorization: `Bearer ${token}` },
        },
      );
      const data = (await resp.json().catch(() => null)) as
        | { error?: string; holderName?: string; accountNumber?: string }
        | null;
      if (!resp.ok || !data?.accountNumber) {
        toast(data?.error || "Recipient account not found", "error");
        return;
      }

      setTransferAccount(data.accountNumber);
      setTransferReceiverName(
        data.holderName || `Account ���� ${data.accountNumber.slice(-4)}`,
      );
    } catch {
      toast("Cannot verify account with server", "error");
      return;
    }

    setTransferStep(2);
  };

  const continueTransferAmount = () => {
    const amount = Number(transferAmount.replace(/,/g, ""));
    if (!transferAmount || Number.isNaN(amount) || amount <= 0) {
      toast("Please enter a valid transfer amount.", "error");
      return;
    }
    if (!canContinueTransferAmount) {
      return;
    }
    if (!transferContent.trim()) {
      setTransferContent(defaultTransferContent);
    }
    generateTransferOtp();
    setTransferStep(3);
  };

  const verifyTransferOtpAndSubmit = async () => {
    if (!/^\d{6}$/.test(transferOtpInput)) {
      setTransferOtpError("OTP must be exactly 6 digits.");
      return;
    }
    if (transferOtpInput !== transferOtpCode) {
      const nextAttempts = transferOtpAttempts + 1;
      setTransferOtpAttempts(nextAttempts);
      setTransferOtpError("Incorrect OTP. Please try again.");
      if (nextAttempts >= 3) {
        generateTransferOtp();
        setTransferOtpError(
          "Too many failed attempts. A new OTP has been sent.",
        );
      }
      return;
    }
    setTransferOtpError("");
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
      return;
    }
    const transferResp = await fetch(`${API_BASE}/transfer`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        toAccount: transferAccount,
        amount,
        note: transferContent || defaultTransferContent,
      }),
    });
    if (!transferResp.ok) {
      const err = (await transferResp.json().catch(() => null)) as
        | { error?: string }
        | null;
      toast(err?.error || "Transfer failed", "error");
      return;
    }

    const transferPayload = (await transferResp.json().catch(() => null)) as
      | {
          reconciliationId?: string;
          transaction?: {
            id: string;
            toAccount?: string;
          };
        }
      | null;
    const targetAccount = transferPayload?.transaction?.toAccount || transferAccount;
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
        entity: `Transfer to •••• ${targetAccount.slice(-4)}`,
        date: executedAt,
        status: "Completed",
        amount: `-$${amount.toLocaleString("en-US", {
          minimumFractionDigits: 2,
          maximumFractionDigits: 2,
        })}`,
        amountTone: "negative",
      },
      ...prev,
    ]);
    setTransferStep(4);
    toast("Transfer completed successfully");
  };

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
                  title={showWalletId ? "Hide account number" : "Show account number"}
                >
                  {showWalletId ? "🙈" : "👁"}
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
            {dashboardQuickActions.map((action) => (
              <button
                type="button"
                className="dashboard-action-item"
                key={action.title}
                onClick={async () => {
                  if (action.id === "transfer") {
                    openTransferModal();
                  } else {
                    if (!token) {
                      toast("Session expired. Please login again.", "error");
                      return;
                    }
                    const resp = await fetch(`${API_BASE}/wallet/deposit`, {
                      method: "POST",
                      headers: {
                        "Content-Type": "application/json",
                        Authorization: `Bearer ${token}`,
                      },
                      body: JSON.stringify({ amount: 100 }),
                    });
                    if (!resp.ok) {
                      toast("Deposit failed", "error");
                      return;
                    }
                    const walletResp = await fetch(`${API_BASE}/wallet/me`, {
                      headers: { Authorization: `Bearer ${token}` },
                    });
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
                    const txResp = await fetch(`${API_BASE}/transactions`, {
                      headers: { Authorization: `Bearer ${token}` },
                    });
                    if (txResp.ok) {
                      const txs = (await txResp.json()) as Array<{
                        id: string;
                        amount: number;
                        type: string;
                        description?: string;
                        createdAt: string;
                        metadata?: { entry?: "DEBIT" | "CREDIT" };
                      }>;
                      setTransactionHistory(
                        txs.map((tx) => ({
                          entity: tx.description || tx.type,
                          date: new Date(tx.createdAt).toLocaleString("en-US"),
                          status: "Completed",
                          amount: `${tx.type === "DEPOSIT" || tx.metadata?.entry === "CREDIT" ? "+" : "-"}$${Math.abs(
                            Number(tx.amount || 0),
                          ).toLocaleString("en-US", {
                            minimumFractionDigits: 2,
                            maximumFractionDigits: 2,
                          })}`,
                          amountTone:
                            tx.type === "DEPOSIT" || tx.metadata?.entry === "CREDIT"
                              ? "positive"
                              : "negative",
                        })),
                      );
                    }
                    toast("Deposited $100 successfully");
                  }
                }}
              >
                <span className="dashboard-action-icon">{action.icon}</span>
                <span className="dashboard-action-text">
                  <strong>{action.title}</strong>
                  <small>{action.detail}</small>
                </span>
                <span className="dashboard-action-arrow">›</span>
              </button>
            ))}
          </div>
          <button type="button" className="dashboard-all-actions">
            View all actions
          </button>
        </aside>
      </div>

      <section className="dashboard-block">
        <div className="dashboard-block-head">
          <h3>Security Alerts</h3>
          <span className="dashboard-tag">AI MONITORED</span>
          <button type="button" className="dashboard-link">
            Full Audit Log
          </button>
        </div>
        <div className="dashboard-alert-list">
          {dashboardSecurityAlerts.map((alert) => (
            <article
              className={`dashboard-alert-item ${alert.tone}`}
              key={alert.title}
            >
              <div className="dashboard-alert-icon">
                {alert.tone === "safe"
                  ? "✓"
                  : alert.tone === "info"
                    ? "i"
                    : "!"}
              </div>
              <div className="dashboard-alert-content">
                <div className="dashboard-alert-title-row">
                  <strong>{alert.title}</strong>
                  <span className="dashboard-alert-location">
                    {alert.location}
                  </span>
                </div>
                <p>{alert.detail}</p>
              </div>
              <div className="dashboard-alert-time">{alert.time}</div>
            </article>
          ))}
        </div>
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
              </tr>
            </thead>
            <tbody>
              {transactionHistory.slice(0, 3).map((tx) => (
                <tr key={tx.entity + tx.date}>
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
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

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
                ✕
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
                  </tr>
                </thead>
                <tbody>
                  {transactionHistory.map((tx) => (
                    <tr key={`modal-${tx.entity}-${tx.date}`}>
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
                ✕
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
        <div className="modal-overlay" onClick={closeTransferModal}>
          <div
            className="modal-card transfer-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="transfer-head">
              <h3>Secure Bank Transfer</h3>
              <button
                type="button"
                className="card-details-close"
                onClick={closeTransferModal}
              >
                ✕
              </button>
            </div>
            <div className="transfer-steps">
              <span className={transferStep >= 1 ? "active" : ""}>
                Recipient
              </span>
              <span className={transferStep >= 2 ? "active" : ""}>Amount</span>
              <span className={transferStep >= 3 ? "active" : ""}>OTP</span>
              <span className={transferStep >= 4 ? "active" : ""}>Done</span>
            </div>

            {transferStep === 1 && (
              <div className="transfer-body">
                <div className="transfer-method-tabs">
                  <button
                    type="button"
                    className={transferMethod === "account" ? "active" : ""}
                    onClick={() => {
                      setTransferMethod("account");
                      stopTransferQrCameraScan();
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
                      onChange={(e) =>
                        setTransferAccount(
                          e.target.value.replace(/\D/g, "").slice(0, 19),
                        )
                      }
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
                          onClick={() => void startTransferQrCameraScan()}
                        >
                          Scan QR by camera
                        </button>
                      ) : (
                        <>
                          <button
                            type="button"
                            className="pill"
                            onClick={stopTransferQrCameraScan}
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
                        onClick={() => setTransferShowMyQr((v) => !v)}
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
                    <div className="transfer-qr-device-row">
                      <label className="transfer-qr-device-label">
                        Camera
                        <select
                          value={transferQrDeviceId}
                          onChange={(e) => setTransferQrDeviceId(e.target.value)}
                          disabled={transferQrDevices.length === 0}
                        >
                          {transferQrDevices.length === 0 ? (
                            <option value="">No camera found</option>
                          ) : (
                            transferQrDevices.map((cam, idx) => (
                              <option key={cam.deviceId || String(idx)} value={cam.deviceId}>
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
                    {transferQrCameraOn && (
                      <div className="transfer-qr-camera">
                        <video
                          ref={transferQrVideoRef}
                          className="transfer-qr-video"
                          autoPlay
                          playsInline
                          muted
                        />
                        <small className="muted">
                          Align QR code inside camera frame to auto-detect. Current camera:{" "}
                          {transferQrFacingMode === "environment" ? "Back" : "Front"}.
                        </small>
                      </div>
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
                        {ownQrPayload && (
                          <small className="muted transfer-my-qr-payload">
                            {ownQrPayload}
                          </small>
                        )}
                      </div>
                    )}
                    <label className="form-group" style={{ marginTop: 10 }}>
                      <span>QR payload</span>
                      <input
                        type="text"
                        placeholder="EWALLET|ACC:971234567890|BANK:SECURE-WALLET"
                        value={transferQrRaw}
                        onChange={(e) => setTransferQrRaw(e.target.value)}
                      />
                    </label>
                    <button
                      type="button"
                      className="pill"
                      onClick={() => {
                        const extracted = extractAccountFromQrPayload(transferQrRaw);
                        if (!/^\d{8,19}$/.test(extracted)) {
                          toast("Invalid QR payload.", "error");
                          return;
                        }
                        setTransferAccount(extracted);
                        setTransferReceiverName(
                          `QR Recipient •••• ${extracted.slice(-4)}`,
                        );
                        toast("QR payload parsed successfully.");
                      }}
                    >
                      Extract account from QR
                    </button>
                    {transferAccount && (
                      <div className="transfer-qr-result">
                        Extracted account: <strong>{transferAccount}</strong>
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
                <label className="form-group">
                  <span>Amount (USD)</span>
                  <input
                    type="text"
                    inputMode="decimal"
                    placeholder="Enter transfer amount"
                    value={transferAmount}
                    onChange={(e) =>
                      setTransferAmount(e.target.value.replace(/[^0-9.]/g, ""))
                    }
                  />
                  {isInsufficientBalance && (
                    <small className="transfer-input-error">
                      Insufficient balance</small>
                  )}
                </label>
                <label className="form-group">
                  <span>Transfer Content</span>
                  <input
                    type="text"
                    value={transferContent}
                    onChange={(e) => setTransferContent(e.target.value)}
                  />
                </label>
                <div className="transfer-actions">
                  <button
                    type="button"
                    className="pill"
                    onClick={() => setTransferStep(1)}
                  >
                    Back
                  </button>
                  <button
                    type="button"
                    className="btn-primary"
                    onClick={continueTransferAmount}
                    disabled={!canContinueTransferAmount}
                  >
                    Continue to OTP
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
                    <strong>{transferContent || defaultTransferContent}</strong>
                  </div>
                </div>
                <label className="form-group">
                  <span>Enter OTP</span>
                  <input
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
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
                    onClick={generateTransferOtp}
                  >
                    Resend OTP
                  </button>
                  <button
                    type="button"
                    className="btn-primary"
                    onClick={verifyTransferOtpAndSubmit}
                  >
                    Confirm Transfer
                  </button>
                </div>
              </div>
            )}

            {transferStep === 4 && (
              <div className="transfer-body transfer-success">
                <div className="transfer-success-icon">✓</div>
                <h4>Transfer Successful</h4>
                {transferReceipt && (
                  <div className="transfer-receipt">
                    <div className="transfer-receipt-row">
                      <span>Transaction ID</span>
                      <strong>{transferReceipt.txId}</strong>
                    </div>
                    <div className="transfer-receipt-row">
                      <span>Execution Time</span>
                      <strong>{transferReceipt.executedAt}</strong>
                    </div>
                    <div className="transfer-receipt-row">
                      <span>From Account</span>
                      <strong>{transferReceipt.fromAccount}</strong>
                    </div>
                    <div className="transfer-receipt-row">
                      <span>To Account</span>
                      <strong>{transferReceipt.toAccount}</strong>
                    </div>
                    <div className="transfer-receipt-row">
                      <span>Amount</span>
                      <strong>${transferReceipt.amountUsd}</strong>
                    </div>
                    <div className="transfer-receipt-row">
                      <span>Transfer Fee</span>
                      <strong>${transferReceipt.feeUsd}</strong>
                    </div>
                    <div className="transfer-receipt-row">
                      <span>Content</span>
                      <strong>{transferReceipt.note}</strong>
                    </div>
                    <div className="transfer-receipt-row">
                      <span>Status</span>
                      <strong className="transfer-receipt-status">
                        {transferReceipt.status}
                      </strong>
                    </div>
                  </div>
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
      )}
    </section>
  );
}

// Invoice list for Invoice List tab (full list view)
const invoiceListData = [
  {
    id: "#VM056DL8",
    name: "Freshbooks",
    date: "25 February, 2021",
    amount: "$1,970",
    status: "Paid",
    statusType: "completed",
    img: 20,
  },
  {
    id: "#VM056DL7",
    name: "Randi Press",
    date: "24 February, 2021",
    amount: "$490",
    status: "Pending",
    statusType: "pending",
    img: 1,
  },
  {
    id: "#VM056DL6",
    name: "Apple Store",
    date: "10 February, 2021",
    amount: "$230",
    status: "Paid",
    statusType: "completed",
    img: 3,
  },
  {
    id: "#VM056DL5",
    name: "Amazon",
    date: "7 February, 2021",
    amount: "$95",
    status: "Overdue",
    statusType: "canceled",
    img: 6,
  },
];

function InvoiceListView() {
  return (
    <section className="invoice-list-section">
      <div className="card invoice-list-card">
        <h3>Invoice List</h3>
        <div className="invoice-list-table-wrap">
          <table className="transactions-table invoice-list-table">
            <thead>
              <tr>
                <th>Invoice ID</th>
                <th>Client</th>
                <th>Due Date</th>
                <th>Amount</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {invoiceListData.map((inv) => (
                <tr key={inv.id + inv.date}>
                  <td className="tx-id">{inv.id}</td>
                  <td>
                    <div className="tx-recipient">
                      <img
                        src={`https://i.pravatar.cc/40?img=${inv.img}`}
                        alt=""
                        className="tx-recipient-avatar"
                      />
                      <span>{inv.name}</span>
                    </div>
                  </td>
                  <td className="muted">{inv.date}</td>
                  <td className="tx-amount">{inv.amount}</td>
                  <td>
                    <span className={`status-badge status-${inv.statusType}`}>
                      {inv.status}
                    </span>
                  </td>
                  <td>
                    <span className="tx-dots">⋮</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

function parseMoney(s: string): number {
  const n = parseFloat(String(s).replace(/[^0-9.-]/g, ""));
  return isNaN(n) ? 0 : n;
}
function formatMoney(n: number): string {
  return (
    "$" +
    (Math.round(n * 100) / 100).toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ",")
  );
}

type ProductRow = {
  id: number;
  name: string;
  qty: string;
  unitPrice: string;
  discount: string;
};
const createInvoiceInitialProducts: ProductRow[] = [
  { id: 1, name: "Story Book", qty: "5", unitPrice: "150", discount: "50" },
  {
    id: 2,
    name: "Computer Equipment",
    qty: "1",
    unitPrice: "1030",
    discount: "30",
  },
  {
    id: 3,
    name: "Laptop Servicing",
    qty: "1",
    unitPrice: "270",
    discount: "0",
  },
];

function CreateInvoicesView() {
  const { toast } = useToast();
  const [products, setProducts] = useState<ProductRow[]>(
    createInvoiceInitialProducts,
  );
  const [nextId, setNextId] = useState(4);
  const [notes, setNotes] = useState("");

  const updateRow = (id: number, field: keyof ProductRow, value: string) => {
    setProducts((p) =>
      p.map((r) => (r.id === id ? { ...r, [field]: value } : r)),
    );
  };

  const addProduct = () => {
    setProducts((p) => [
      ...p,
      { id: nextId, name: "", qty: "", unitPrice: "", discount: "" },
    ]);
    setNextId((n) => n + 1);
  };

  const removeRow = (id: number) => {
    if (products.length <= 1) return;
    setProducts((p) => p.filter((r) => r.id !== id));
  };

  const subtotal = products.reduce((sum, r) => {
    const q = parseMoney(r.qty);
    const u = parseMoney(r.unitPrice);
    const d = parseMoney(r.discount);
    return sum + (q * u - d);
  }, 0);
  const tax = subtotal * 0.08;
  const grandTotal = subtotal + tax;

  const saveInvoice = () => {
    const payload = {
      products,
      subtotal,
      tax,
      grandTotal,
      notes,
      savedAt: new Date().toISOString(),
    };
    try {
      localStorage.setItem("invoice_draft", JSON.stringify(payload));
      toast("Invoice saved locally (key: invoice_draft)");
    } catch (err) {
      console.error(err);
      toast("Cannot save invoice to localStorage", "error");
    }
  };

  return (
    <section className="create-invoices-section">
      <div className="card create-invoice-card">
        <h3>Buyer Information</h3>
        <div className="form-grid">
          <div className="form-group">
            <label>Name</label>
            <input type="text" defaultValue="Freshbooks" />
          </div>
          <div className="form-group">
            <label>Address</label>
            <input type="text" defaultValue="Los Angeles, California, USA" />
          </div>
          <div className="form-group">
            <label>Email</label>
            <input type="email" defaultValue="freshbooks@mail.com" />
          </div>
          <div className="form-group">
            <label>Phone Number</label>
            <input type="text" defaultValue="444 565 233 889" />
          </div>
          <div className="form-group">
            <label>Due Date</label>
            <input
              type="text"
              defaultValue="25 February, 2021"
              className="with-icon"
            />
          </div>
          <div className="form-group">
            <label>Invoice ID</label>
            <input type="text" defaultValue="#VM056DL8" />
          </div>
        </div>
      </div>
      <div className="card create-invoice-card">
        <h3>Product Information</h3>
        <div className="products-table-wrap">
          <table className="products-table">
            <thead>
              <tr>
                <th>SL No</th>
                <th>Product Name</th>
                <th>Quantity</th>
                <th>Unit Price</th>
                <th>Discount</th>
                <th>Total Price</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {products.map((row, i) => {
                const q = parseMoney(row.qty);
                const u = parseMoney(row.unitPrice);
                const d = parseMoney(row.discount);
                const total = q * u - d;
                return (
                  <tr key={row.id}>
                    <td>{i + 1}</td>
                    <td>
                      <input
                        type="text"
                        value={row.name}
                        onChange={(e) =>
                          updateRow(row.id, "name", e.target.value)
                        }
                        className="cell-input"
                      />
                    </td>
                    <td>
                      <input
                        type="text"
                        value={row.qty}
                        onChange={(e) =>
                          updateRow(row.id, "qty", e.target.value)
                        }
                        className="cell-input"
                      />
                    </td>
                    <td>
                      <input
                        type="text"
                        value={row.unitPrice}
                        onChange={(e) =>
                          updateRow(row.id, "unitPrice", e.target.value)
                        }
                        className="cell-input"
                      />
                    </td>
                    <td>
                      <input
                        type="text"
                        value={row.discount}
                        onChange={(e) =>
                          updateRow(row.id, "discount", e.target.value)
                        }
                        className="cell-input"
                      />
                    </td>
                    <td>
                      <span className="cell-total">{formatMoney(total)}</span>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn-remove-row"
                        onClick={() => removeRow(row.id)}
                        title="Remove"
                      >
                        ✕
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="invoice-grand-total">
          <div className="invoice-summary-row">
            <span>Subtotal</span>
            <strong>{formatMoney(subtotal)}</strong>
          </div>
          <div className="invoice-summary-row">
            <span>Tax (8%)</span>
            <strong>{formatMoney(tax)}</strong>
          </div>
          <div className="invoice-summary-row total">
            <span>Grand Total</span>
            <strong>{formatMoney(grandTotal)}</strong>
          </div>
        </div>
        <textarea
          className="invoice-notes"
          placeholder="Notes for buyer or internal remarks"
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
        />
        <div className="invoice-actions">
          <button
            type="button"
            className="btn-add-product"
            onClick={addProduct}
          >
            + Add Product
          </button>
          <button type="button" className="btn-primary" onClick={saveInvoice}>
            Save Draft
          </button>
        </div>
      </div>
    </section>
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

function CardCenterView() {
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
                {c.type} · {c.bank}
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
                    <span className="tx-dots">⋮</span>
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
          <button className="pill">All Time ▼</button>
        </div>
        <div className="txn-list">
          {accountsRecentTransactions.map((t, i) => (
            <div key={i} className="txn-row">
              <span className="txn-icon">💳</span>
              <span>{t.name}</span>
              <span className="muted">{t.status}</span>
              <span className="muted">{t.date}</span>
              <span className="muted">{t.card}</span>
              <span>{t.amount}</span>
              <span className="muted">⋮</span>
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

const SETTING_PROFILE_KEY = "moneyfarm_profile";
const PROFILE_AVATAR_KEY = "moneyfarm_profile_avatar";
const SETTING_SECURITY_KEY = "moneyfarm_security";
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
    icon: "❤",
    active: false,
  },
  {
    id: "security",
    label: "Security",
    desc: "Change password, Authentication.",
    icon: "🔒",
    active: false,
  },
  {
    id: "notification",
    label: "Notification",
    desc: "Change password, Authentication.",
    icon: "🔔",
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
                lastUsed: "2026-02-22 · San Francisco, US",
                trusted: true,
              },
              {
                id: "iphone-14",
                name: "iPhone 14 Pro",
                lastUsed: "2026-02-23 · San Francisco, US",
                trusted: true,
              },
              {
                id: "office-pc",
                name: "Windows PC",
                lastUsed: "2026-02-10 · Ho Chi Minh, VN",
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
                <span className="setting-avatar-edit">📷</span>
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
                <Toggle
                  id="pref-theme"
                  checked
                  onChange={() => {}}
                />
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
                    We’ll ask for a code when a login is from an unrecognized
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

function MyProfileView() {
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
        const data = (await resp.json().catch(() => null)) as
          | {
              error?: string;
              fullName?: string;
              email?: string;
              phone?: string;
              address?: string;
              dob?: string;
              avatar?: string;
              metadata?: Record<string, unknown>;
            }
          | null;
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
          const walletErr = (await walletResp.json().catch(() => null)) as
            | { error?: string }
            | null;
          if (isAuthExpired(walletResp.status, walletErr?.error)) {
            toast("Session expired. Please sign in again.", "error");
            logout();
          }
          setAccountNumber("");
          return;
        }
        if (walletResp.ok) {
          const walletData = (await walletResp.json().catch(() => null)) as
            | { accountNumber?: string }
            | null;
          setAccountNumber(walletData?.accountNumber || "");
        }
      } catch {
        // keep current local profile when API is unavailable
      }
    };
    void loadProfile();
  }, [token, user?.email, user?.name]);

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
      const data = (await resp.json().catch(() => null)) as
        | { error?: string; fullName?: string; email?: string }
        | null;
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
          <img src={avatarUrl} alt="Profile avatar" className="setting-avatar" />
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
            <span className="user-profile-pill">Role: {user?.role ?? "USER"}</span>
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
            onChange={(e) => setProfile((p) => ({ ...p, name: e.target.value }))}
          />
        </div>
        <div className="form-group">
          <label>Username</label>
          <input
            type="text"
            value={profile.userName}
            onChange={(e) => setProfile((p) => ({ ...p, userName: e.target.value }))}
          />
        </div>
        <div className="form-group">
          <label>Email</label>
          <input
            type="email"
            value={profile.email}
            onChange={(e) => setProfile((p) => ({ ...p, email: e.target.value }))}
          />
        </div>
        <div className="form-group">
          <label>Phone Number</label>
          <input
            type="text"
            value={profile.phone}
            onChange={(e) => setProfile((p) => ({ ...p, phone: e.target.value }))}
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
            onChange={(e) => setProfile((p) => ({ ...p, address: e.target.value }))}
          />
        </div>
      </div>

      <div className="setting-actions">
        <button type="button" className="btn-primary" onClick={saveProfile}>
          Save Changes
        </button>
      </div>
    </section>
  );
}
// --- Utilities: FAQ (Knowledge base) ---
const faqGeneral = [
  {
    q: "Can I use Master card for shopping?",
    detail:
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut eu feugiat amet.",
  },
  { q: "Have any loan product for women entrepreneurs?" },
  { q: "Who are eligible for availing SME loan?" },
  { q: "What is the maximum amount of SME loan?" },
];
const faqOthers = [
  { q: "What tenor is offered for SME loan?" },
  { q: "What is the early settlement fee?" },
  { q: "What is the partial settlement fee?" },
  { q: "Is there any insurance policy required to avail this loan?" },
];

function KnowledgeBaseView() {
  const [openGeneral, setOpenGeneral] = useState<number | null>(null);
  const [openOthers, setOpenOthers] = useState<number | null>(null);
  return (
    <section className="utility-faq-section">
      <div className="card faq-card">
        <h3>General Inquires</h3>
        <ul className="faq-list">
          {faqGeneral.map((item, i) => (
            <li key={i} className="faq-item">
              <div
                className="faq-item-inner"
                onClick={() => setOpenGeneral(openGeneral === i ? null : i)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) =>
                  e.key === "Enter" &&
                  setOpenGeneral(openGeneral === i ? null : i)
                }
              >
                <span className="faq-q">{item.q}</span>
                <span className="faq-info-icon">
                  {openGeneral === i ? "−" : "ⓘ"}
                </span>
              </div>
              {(item.detail || openGeneral === i) && (
                <p className="muted faq-detail">
                  {item.detail || "No additional details."}
                </p>
              )}
            </li>
          ))}
        </ul>
      </div>
      <div className="card faq-card">
        <h3>Others Informations</h3>
        <ul className="faq-list">
          {faqOthers.map((item, i) => (
            <li key={i} className="faq-item">
              <div
                className="faq-item-inner"
                onClick={() => setOpenOthers(openOthers === i ? null : i)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) =>
                  e.key === "Enter" &&
                  setOpenOthers(openOthers === i ? null : i)
                }
              >
                <span className="faq-q">{item.q}</span>
                <span className="faq-info-icon">
                  {openOthers === i ? "−" : "ⓘ"}
                </span>
              </div>
              {openOthers === i && (
                <p className="muted faq-detail">No additional details.</p>
              )}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

function Error404View({ onGoHome }: { onGoHome?: () => void }) {
  return (
    <section className="utility-404-section">
      <div className="error-404-content">
        <div className="error-404-number">
          <span>4</span>
          <span className="error-404-char">🥔</span>
          <span>4</span>
        </div>
        <h2 className="error-404-title">Page not Found</h2>
        <p className="muted error-404-desc">
          It looks like that page does not exist. Please check the URL and try
          again.
        </p>
        <button type="button" className="btn-primary" onClick={onGoHome}>
          Go Home
        </button>
      </div>
    </section>
  );
}

function ChangelogView() {
  return (
    <section className="utility-changelog-section">
      <div className="card changelog-card">
        <h3 className="changelog-version">Version 1</h3>
        <p className="changelog-subtitle">Dash Release v1.0</p>
        <p className="muted changelog-desc">
          03-11-2022 - Updated visuals & overall design improvements.
        </p>
      </div>
    </section>
  );
}

function LicenseView() {
  return (
    <section className="utility-license-section">
      <div className="card license-card">
        <h3>Icons</h3>
        <p className="muted license-sub">All icon used from Flaticon</p>
        <div className="license-icon-row">
          {["🏢", "📄", "🏛", "💳", "👤", "⚙", "✱"].map((icon, i) => (
            <button key={i} type="button" className="license-icon-btn">
              {icon}
            </button>
          ))}
        </div>
        <button type="button" className="btn-primary license-btn">
          License
        </button>
      </div>
      <div className="card license-card">
        <h3>Typography</h3>
        <p className="muted license-typo">
          accusamus et iusto odio dignissimos ducimus qui blanditiis praesentium
          voluptatum deleniti atque corrupti quos dolores et quas molestias
          excepturi sint occaecati cupiditate non provident, similique sunt in
          culpa qui officia deserunt mollitia animi, id est laborum et dolorum
          fuga. Et harum quidem rerum facilis est et expedita distinctio. Nam
          libero tempore, cum soluta nobis est eligendi optio cumque nihil
          impedit quo minus id quod
        </p>
        <button type="button" className="btn-primary license-btn">
          License
        </button>
      </div>
    </section>
  );
}

function NotificationsView({
  notifications,
}: {
  notifications: { type: string; message: string }[];
}) {
  const [filter, setFilter] = useState<
    "all" | "transactions" | "security" | "offers"
  >("all");

  const filtered = notifications.filter(
    (n) => filter === "all" || n.type === filter,
  );

  return (
    <section className="card notifications-card">
      <div className="card-head">
        <h3>Notifications</h3>
        <select
          className="pill"
          value={filter}
          onChange={(e) => setFilter(e.target.value as typeof filter)}
        >
          <option value="all">All</option>
          <option value="transactions">Transactions</option>
          <option value="security">Security</option>
          <option value="offers">Offers</option>
        </select>
      </div>
      <div className="notifications-list">
        {filtered.map((n, i) => (
          <div key={i} className="notification-row">
            <div className={`notif-pill notif-${n.type}`}>{n.type}</div>
            <div>{n.message}</div>
            <button type="button" className="pill tiny">
              Mark read
            </button>
          </div>
        ))}
        {filtered.length === 0 && <p className="muted">No notifications.</p>}
      </div>
    </section>
  );
}

function KycView() {
  const steps = ["Identity document", "Selfie check", "Review & submit"];
  const [active, setActive] = useState(0);

  return (
    <section className="card kyc-card">
      <h3>KYC Verification</h3>
      <p className="muted">Verify your identity to unlock higher limits.</p>
      <div className="kyc-steps">
        {steps.map((s, i) => (
          <div
            key={s}
            className={`kyc-step ${i === active ? "active" : ""} ${i < active ? "done" : ""}`}
          >
            <span className="kyc-step-index">{i + 1}</span>
            <span>{s}</span>
          </div>
        ))}
      </div>
      {active === 0 && (
        <div className="kyc-upload">
          <label className="upload-drop">
            <span>Upload ID (front)</span>
            <input type="file" accept="image/*" />
          </label>
          <label className="upload-drop">
            <span>Upload ID (back)</span>
            <input type="file" accept="image/*" />
          </label>
        </div>
      )}
      {active === 1 && (
        <div className="kyc-upload">
          <label className="upload-drop">
            <span>Upload selfie</span>
            <input type="file" accept="image/*" />
          </label>
          <p className="muted small">
            Make sure your face is clear and well lit.
          </p>
        </div>
      )}
      {active === 2 && (
        <div className="kyc-review">
          <p>Review your documents and submit for verification.</p>
          <ul>
            <li>Valid government ID</li>
            <li>Clear selfie</li>
            <li>Matching name & birth date</li>
          </ul>
        </div>
      )}
      <div className="kyc-actions">
        <button
          type="button"
          className="pill"
          onClick={() => setActive((a) => Math.max(0, a - 1))}
          disabled={active === 0}
        >
          Back
        </button>
        <button
          type="button"
          className="btn-primary"
          onClick={() => setActive((a) => Math.min(steps.length - 1, a + 1))}
        >
          {active === steps.length - 1 ? "Submit" : "Next"}
        </button>
      </div>
    </section>
  );
}

const PAGE_TITLE: Record<string, string> = {
  "Knowledge base": "FAQ",
  Notifications: "Notifications",
  "KYC Verification": "KYC Verification",
};

function App() {
  const { user, logout, login, signUp } = useAuth();
  const [activeTab, setActiveTab] = useState("Dashboard");
  const [showNotifications, setShowNotifications] = useState(false);
  const [notificationFilter, setNotificationFilter] = useState<
    "all" | "transactions" | "security" | "offers"
  >("all");
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const userMenuRef = useRef<HTMLDivElement>(null);
  const supportMenuRef = useRef<HTMLDivElement>(null);
  const [invoicesExpanded, setInvoicesExpanded] = useState(false);
  const [utilitiesExpanded, setUtilitiesExpanded] = useState(false);

  const isInvoicesActive =
    activeTab === "Invoice List" || activeTab === "Create Invoices";
  const invoicesExpandedShow = invoicesExpanded || isInvoicesActive;
  const utilitiesExpandedShow = utilitiesExpanded;

  useEffect(() => {
    const close = (e: MouseEvent) => {
      const target = e.target as Node;
      if (userMenuRef.current && !userMenuRef.current.contains(target))
        setUserMenuOpen(false);
      if (supportMenuRef.current && !supportMenuRef.current.contains(target)) {
        setUtilitiesExpanded(false);
      }
    };
    document.addEventListener("click", close);
    return () => document.removeEventListener("click", close);
  }, []);

  useEffect(() => {
    if (user) {
      setActiveTab("Dashboard");
    }
  }, [user?.id]);

  const displayUser = user ?? {
    name: "Guest User",
    email: "guest@moneyfarm.app",
    avatar: "https://i.pravatar.cc/80?img=13",
  };

  // If not logged in, show dedicated auth shell
  if (!user) {
    return <AuthShell onLogin={login} onSignUp={signUp} />;
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

  const notifications = [
    { type: "security", message: "New login from Chrome on MacOS" },
    { type: "transactions", message: "Invoice INV-42015 paid" },
    { type: "security", message: "Security: 2FA enabled" },
    { type: "offers", message: "Cashback 5% this weekend" },
  ];

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="logo">E-Wallet Banking</div>
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
                      {isExpanded ? "▼" : "▶"}
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
          <div className="bell-wrap">
            <button
              type="button"
              className="bell"
              onClick={() => setShowNotifications((v) => !v)}
              aria-haspopup="true"
              aria-expanded={showNotifications}
            >
              🔔<span className="badge">{notifications.length}</span>
            </button>
            {showNotifications && (
              <div className="notif-dropdown">
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
                    <option value="transactions">Transactions</option>
                    <option value="security">Security</option>
                    <option value="offers">Offers</option>
                  </select>
                </div>
                {notifications
                  .filter(
                    (n) =>
                      notificationFilter === "all" ||
                      n.type === notificationFilter,
                  )
                  .map((n, i) => (
                    <div key={i} className="notif-row">
                      <strong style={{ textTransform: "capitalize" }}>
                        {n.type}
                      </strong>
                      <div>{n.message}</div>
                    </div>
                  ))}
                <button
                  type="button"
                  className="pill"
                  onClick={() => setShowNotifications(false)}
                >
                  Mark read & close
                </button>
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
              <span className="avatar-chevron">▼</span>
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
        {activeTab === "Dashboard" && <DashboardView />}
        {activeTab === "Invoice List" && <InvoiceListView />}
        {activeTab === "Create Invoices" && <CreateInvoicesView />}
        {activeTab === "Card Center" && <CardCenterView />}
        {activeTab === "Accounts" && <AccountsView />}
        {activeTab === "My Profile" && <MyProfileView />}
        {activeTab === "Setting" && <SettingView />}
        {activeTab === "Knowledge base" && <KnowledgeBaseView />}
        {activeTab === "Notifications" && (
          <NotificationsView notifications={notifications} />
        )}
        {activeTab === "KYC Verification" && <KycView />}
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
              <p className="muted">Nội dung đang được xây dựng.</p>
            </div>
          </section>
        )}

        <footer className="foot">© E-Wallet Banking by My Team</footer>
      </main>
    </div>
  );
}

export default App;

// -------- Auth Shell (shown when user is null) ----------
type AuthShellProps = {
  onLogin: (email: string, password: string) => Promise<void>;
  onSignUp: (payload: {
    fullName: string;
    userName: string;
    email: string;
    phone: string;
    address: string;
    dob: string;
    password: string;
  }) => Promise<void>;
};

function AuthShell({ onLogin, onSignUp }: AuthShellProps) {
  useTheme();

  const { toast } = useToast();
  const [mode, setMode] = useState<"signin" | "signup" | "forgot" | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [authBusy, setAuthBusy] = useState(false);

  const [signinForm, setSigninForm] = useState({ email: "", password: "" });
  const [captchaToken, setCaptchaToken] = useState("");
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
  const [forgotEmail, setForgotEmail] = useState("");

  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!signinForm.email || !signinForm.password || !captchaToken) {
      toast("Please enter email, password, and CAPTCHA", "error");
      return;
    }
    setAuthBusy(true);
    try {
      await onLogin(signinForm.email, signinForm.password);
      toast("Signed in successfully");
    } catch (err) {
      toast(err instanceof Error ? err.message : "Sign in failed", "error");
    } finally {
      setAuthBusy(false);
    }
  };

  const handleSignUp = async (e: React.FormEvent) => {
    e.preventDefault();
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
      return;
    }
    if (password !== confirm) {
      toast("Password confirmation does not match", "error");
      return;
    }
    if (!agree) {
      toast("Please agree to terms & privacy", "error");
      return;
    }
    setAuthBusy(true);
    try {
      await onSignUp({
        fullName,
        userName: username,
        email,
        phone,
        address,
        dob,
        password,
      });
      toast("Account created successfully");
      setSigninForm({ email, password });
    } catch (err) {
      toast(err instanceof Error ? err.message : "Sign up failed", "error");
    } finally {
      setAuthBusy(false);
    }
  };

  const handleForgot = (e: React.FormEvent) => {
    e.preventDefault();
    if (!forgotEmail) {
      toast("Please enter your email", "error");
      return;
    }
    toast("Password reset link sent (demo)");
    setForgotEmail("");
    setMode("signin");
  };

  const renderChoice = () => (
    <div className="welcome-hero">
      <div className="hero-copy">
        <div className="hero-pill">Secure · Fast · Smart</div>
        <h1>
          Secure E-Wallet — <span className="hero-accent">Fast</span>,{" "}
          <span className="hero-accent-2">Safe</span>, Easy to Use
        </h1>
        <p className="hero-lead">
          Experience multi-layer security and seamless transactions. Protect
          your digital assets with E-Wallet Banking and stay in control
          everywhere.
        </p>

        <div className="hero-features">
          {[
            { icon: "🛡️", title: "Multi-layer Security" },
            { icon: "⚡", title: "Fast Transactions" },
            { icon: "📊", title: "Transparent Management" },
          ].map((f) => (
            <div className="hero-feature" key={f.title}>
              <span className="hero-feature-ico">{f.icon}</span>
              <span>{f.title}</span>
            </div>
          ))}
        </div>

        <div className="hero-cta">
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

        <div className="hero-meta">
          24/7 Support · Transaction Tracking · Mobile &amp; Desktop Optimized
        </div>
      </div>

      <div className="hero-visual">
        <div className="hero-screen">
          <div className="screen-header">
            <span className="dot red" />
            <span className="dot yellow" />
            <span className="dot green" />
            <span className="screen-title">Dashboard</span>
            <span className="screen-pill">Encrypted</span>
          </div>
          <div className="screen-body">
            <div className="screen-balance">
              <div className="muted">Balance</div>
              <div className="big">$12,450.00</div>
            </div>
            <div className="screen-bars">
              {Array.from({ length: 6 }).map((_, i) => (
                <div
                  key={i}
                  className="bar"
                  style={{ height: `${50 + i * 10}%` }}
                />
              ))}
            </div>
            <div className="screen-stats">
              <div>
                <span className="muted">Income</span>
                <strong>$6,320</strong>
              </div>
              <div>
                <span className="muted">Expenses</span>
                <strong>$3,980</strong>
              </div>
              <div>
                <span className="muted">Security</span>
                <strong>Active</strong>
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
    <div className="auth-shell">
      <div className="auth-card-panel">
        {!mode && renderChoice()}

        {mode === "signin" && (
          <div className="auth-form-shell">
            <form className="auth-form-modern" onSubmit={handleSignIn}>
              <h2>Sign In</h2>
              <p className="muted">
                Welcome back! Enter your credentials to access E-Wallet Banking.
              </p>
              <label className="auth-label">
                Email Address
                <input
                  type="email"
                  value={signinForm.email}
                  onChange={(e) =>
                    setSigninForm({ ...signinForm, email: e.target.value })
                  }
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
                    onChange={(e) =>
                      setSigninForm({ ...signinForm, password: e.target.value })
                    }
                    placeholder="Enter your password"
                    required
                  />
                  <button
                    type="button"
                    className="eye"
                    onClick={() => setShowPassword((s) => !s)}
                    aria-label="Toggle password"
                  >
                    {showPassword ? "🙈" : "👁"}
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
              <button
                type="submit"
                className="btn-primary auth-submit"
                disabled={authBusy}
              >
                {authBusy ? "Signing in..." : "Sign In"}
              </button>
              <label className="auth-label" style={{ marginTop: 12 }}>
                CAPTCHA token (demo)
                <input
                  value={captchaToken}
                  onChange={(e) => setCaptchaToken(e.target.value)}
                  placeholder="Paste CAPTCHA token"
                  required
                />
                <span className="muted" style={{ fontSize: 12 }}>
                  UI placeholder; will be connected to CAPTCHA widget later.
                </span>
              </label>
              <p className="auth-switch">
                Don&apos;t have an account?{" "}
                <button
                  type="button"
                  className="link-btn"
                  onClick={() => setMode("signup")}
                >
                  Sign Up
                </button>
                <span className="muted"> · </span>
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
        {mode === "signup" && (
          <div className="auth-form-shell">
            <form className="auth-form-modern" onSubmit={handleSignUp}>
              <h2>Sign Up</h2>
              <p className="muted">
                Create your E-Wallet Banking account to start managing finances
                smartly.
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
                      value={signupForm.password}
                      onChange={(e) =>
                        setSignupForm({
                          ...signupForm,
                          password: e.target.value,
                        })
                      }
                      placeholder="Enter your password"
                      required
                    />
                    <button
                      type="button"
                      className="eye"
                      onClick={() => setShowPassword((s) => !s)}
                      aria-label="Toggle password"
                    >
                      {showPassword ? "🙈" : "👁"}
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
                    required
                  />
                </label>
              </div>
              <label className="auth-checkbox">
                <input
                  type="checkbox"
                  checked={signupForm.agree}
                  onChange={(e) =>
                    setSignupForm({ ...signupForm, agree: e.target.checked })
                  }
                  required
                />{" "}
                I agree to terms & privacy.
              </label>
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
                <span className="muted"> · </span>
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
        {mode === "forgot" && (
          <div className="auth-form-shell">
            <form className="auth-form-modern" onSubmit={handleForgot}>
              <h2>Forgot Password</h2>
              <p className="muted">
                Enter the email linked to your account and we&apos;ll email you
                a reset link (demo).
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
              <button type="submit" className="btn-primary auth-submit">
                Send Reset Link
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
      </div>
    </div>
  );
}



