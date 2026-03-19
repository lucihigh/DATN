import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type CSSProperties,
  type PointerEvent as ReactPointerEvent,
} from "react";

export type SliderCaptchaValue = {
  captchaToken: string;
  captchaOffset: number;
};

type SliderCaptchaChallenge = {
  captchaToken: string;
  targetOffsetPx: number;
  tolerancePx: number;
  stageWidthPx: number;
  pieceWidthPx: number;
  expiresAt: string;
};

type SliderCaptchaProps = {
  apiBase: string;
  resetKey?: number;
  disabled?: boolean;
  onChange: (value: SliderCaptchaValue | null) => void;
};

const CAPTCHA_SOURCE_WIDTH = 736;
const CAPTCHA_SOURCE_HEIGHT = 440;
const CAPTCHA_SOURCE_LINES: Array<{ text: string; color: string }> = [
  { text: "package com.example.demo.controller;", color: "#f4b4ff" },
  { text: "", color: "#e5e7eb" },
  {
    text: "import com.example.demo.service.CaptchaService;",
    color: "#f4b4ff",
  },
  {
    text: "import org.springframework.beans.factory.annotation.Autowired;",
    color: "#f4b4ff",
  },
  {
    text: "import org.springframework.web.bind.annotation.*;",
    color: "#f4b4ff",
  },
  { text: "", color: "#e5e7eb" },
  { text: "@RestController", color: "#d8b4fe" },
  { text: "public class CaptchaController {", color: "#f8fafc" },
  { text: "", color: "#e5e7eb" },
  { text: "    @Autowired", color: "#d8b4fe" },
  { text: "    private CaptchaService captchaService;", color: "#f8fafc" },
  { text: "", color: "#e5e7eb" },
  { text: '    @PostMapping("/verify-captcha")', color: "#c084fc" },
  {
    text: '    public String verifyCaptcha(@RequestParam("g-recaptcha-response") String captchaResponse) {',
    color: "#f8fafc",
  },
  {
    text: "        boolean isValid = captchaService.verifyCaptcha(captchaResponse);",
    color: "#e5e7eb",
  },
  { text: "", color: "#e5e7eb" },
  { text: "        if (isValid) {", color: "#f8fafc" },
  {
    text: '            return "Xac minh thanh cong, ban khong phai robot.";',
    color: "#4ade80",
  },
  { text: "        } else {", color: "#f8fafc" },
  { text: '            return "Xac minh that bai.";', color: "#4ade80" },
  { text: "        }", color: "#f8fafc" },
  { text: "    }", color: "#f8fafc" },
  { text: "}", color: "#f8fafc" },
];

const escapeXml = (value: string) =>
  value
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

const CAPTCHA_IMAGE_SRC = (() => {
  const startY = 50;
  const lineHeight = 15.8;
  const textNodes = CAPTCHA_SOURCE_LINES.map(
    (line, index) => `
      <text
        x="22"
        y="${startY + index * lineHeight}"
        fill="${line.color}"
        font-family="Consolas, 'Cascadia Code', 'Fira Code', monospace"
        font-size="13.1"
        xml:space="preserve"
      >${escapeXml(line.text)}</text>`,
  ).join("");

  const svg = `
    <svg xmlns="http://www.w3.org/2000/svg" width="${CAPTCHA_SOURCE_WIDTH}" height="${CAPTCHA_SOURCE_HEIGHT}" viewBox="0 0 ${CAPTCHA_SOURCE_WIDTH} ${CAPTCHA_SOURCE_HEIGHT}">
      <defs>
        <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stop-color="#11131a" />
          <stop offset="100%" stop-color="#171124" />
        </linearGradient>
        <radialGradient id="glow" cx="84%" cy="12%" r="44%">
          <stop offset="0%" stop-color="#7c3aed" stop-opacity="0.42" />
          <stop offset="100%" stop-color="#7c3aed" stop-opacity="0" />
        </radialGradient>
      </defs>
      <rect width="${CAPTCHA_SOURCE_WIDTH}" height="${CAPTCHA_SOURCE_HEIGHT}" rx="16" fill="url(#bg)" />
      <rect width="${CAPTCHA_SOURCE_WIDTH}" height="${CAPTCHA_SOURCE_HEIGHT}" rx="16" fill="url(#glow)" />
      <rect x="0" y="0" width="${CAPTCHA_SOURCE_WIDTH}" height="${CAPTCHA_SOURCE_HEIGHT}" rx="16" fill="none" stroke="rgba(255,255,255,0.04)" />
      ${textNodes}
    </svg>`;

  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
})();

const clamp = (value: number, min: number, max: number) =>
  Math.min(Math.max(value, min), max);

export function SliderCaptcha({
  apiBase,
  resetKey = 0,
  disabled = false,
  onChange,
}: SliderCaptchaProps) {
  const [challenge, setChallenge] = useState<SliderCaptchaChallenge | null>(
    null,
  );
  const [offset, setOffset] = useState(0);
  const [message, setMessage] = useState("Drag the slider to fit the puzzle.");
  const [status, setStatus] = useState<
    "idle" | "loading" | "verified" | "error"
  >("idle");
  const [dragging, setDragging] = useState(false);
  const [isOpen, setIsOpen] = useState(false);
  const dragStartXRef = useRef(0);
  const dragStartOffsetRef = useRef(0);
  const offsetRef = useRef(0);

  const updateOffset = useCallback((nextOffset: number) => {
    offsetRef.current = nextOffset;
    setOffset(nextOffset);
  }, []);

  const resetInternalState = useCallback(() => {
    setChallenge(null);
    setIsOpen(false);
    setStatus("idle");
    setMessage("Drag the slider to fit the puzzle.");
    updateOffset(0);
    onChange(null);
  }, [onChange, updateOffset]);

  const loadChallenge = useCallback(async () => {
    setStatus("loading");
    setMessage("Loading puzzle...");
    setChallenge(null);
    updateOffset(0);
    onChange(null);

    try {
      const resp = await fetch(`${apiBase}/auth/captcha/slider`, {
        cache: "no-store",
      });
      const data = (await resp
        .json()
        .catch(() => null)) as SliderCaptchaChallenge | null;
      if (
        !resp.ok ||
        !data ||
        typeof data.captchaToken !== "string" ||
        typeof data.targetOffsetPx !== "number" ||
        typeof data.tolerancePx !== "number" ||
        typeof data.stageWidthPx !== "number" ||
        typeof data.pieceWidthPx !== "number"
      ) {
        throw new Error("Cannot load puzzle");
      }
      setChallenge(data);
      setStatus("idle");
      setMessage("Drag the slider to fit the puzzle piece.");
    } catch (err) {
      setStatus("error");
      setMessage(err instanceof Error ? err.message : "Cannot load puzzle.");
    }
  }, [apiBase, onChange, updateOffset]);

  useEffect(() => {
    resetInternalState();
  }, [resetInternalState, resetKey]);

  useEffect(() => {
    if (!dragging || !challenge) {
      return;
    }

    const maxOffset = challenge.stageWidthPx - challenge.pieceWidthPx;
    const handleMove = (event: PointerEvent) => {
      const nextOffset = clamp(
        dragStartOffsetRef.current + (event.clientX - dragStartXRef.current),
        0,
        maxOffset,
      );
      updateOffset(nextOffset);
    };

    const handleUp = () => {
      const finalOffset = offsetRef.current;
      const matched =
        Math.abs(finalOffset - challenge.targetOffsetPx) <=
        challenge.tolerancePx;

      setDragging(false);
      if (!matched) {
        updateOffset(0);
        onChange(null);
        setStatus("idle");
        setMessage("Position is not correct. Try again.");
        return;
      }

      updateOffset(challenge.targetOffsetPx);
      onChange({
        captchaToken: challenge.captchaToken,
        captchaOffset: challenge.targetOffsetPx,
      });
      setStatus("verified");
      setMessage("Verification complete.");
      window.setTimeout(() => setIsOpen(false), 260);
    };

    window.addEventListener("pointermove", handleMove);
    window.addEventListener("pointerup", handleUp, { once: true });
    return () => {
      window.removeEventListener("pointermove", handleMove);
      window.removeEventListener("pointerup", handleUp);
    };
  }, [challenge, dragging, onChange, updateOffset]);

  const handleOpen = () => {
    if (disabled || status === "verified") {
      return;
    }
    setIsOpen(true);
    if (!challenge || status === "error") {
      void loadChallenge();
    }
  };

  const handleClose = () => {
    if (dragging) {
      return;
    }
    setIsOpen(false);
  };

  const handlePointerDown = (event: ReactPointerEvent<HTMLElement>) => {
    if (disabled || !challenge || status === "loading" || status === "error") {
      return;
    }
    if (status === "verified") {
      return;
    }
    dragStartXRef.current = event.clientX;
    dragStartOffsetRef.current = offsetRef.current;
    setDragging(true);
  };

  const stageWidth = challenge?.stageWidthPx ?? 360;
  const pieceWidth = challenge?.pieceWidthPx ?? 72;
  const thumbWidth = 58;
  const stageHeight = Math.round(
    (stageWidth * CAPTCHA_SOURCE_HEIGHT) / CAPTCHA_SOURCE_WIDTH,
  );
  const pieceHeight = Math.min(
    Math.max(Math.round(pieceWidth * 1.66), 124),
    stageHeight - 22,
  );
  const pieceTop = Math.max(10, Math.round(stageHeight * 0.08));
  const maxOffset = Math.max(0, stageWidth - pieceWidth);
  const targetOffset = clamp(challenge?.targetOffsetPx ?? 0, 0, maxOffset);

  const panelStyle = {
    width: `min(100%, ${stageWidth + 78}px)`,
  } satisfies CSSProperties;
  const surfaceStyle = {
    width: `${stageWidth}px`,
    height: `${stageHeight}px`,
  } satisfies CSSProperties;
  const targetStyle = {
    width: `${pieceWidth}px`,
    height: `${pieceHeight}px`,
    top: `${pieceTop}px`,
    transform: `translateX(${targetOffset}px)`,
  } satisfies CSSProperties;
  const pieceStyle = {
    width: `${pieceWidth}px`,
    height: `${pieceHeight}px`,
    top: `${pieceTop}px`,
    transform: `translateX(${offset}px)`,
  } satisfies CSSProperties;
  const pieceImageStyle = {
    width: `${stageWidth}px`,
    height: `${stageHeight}px`,
    transform: `translate(${-targetOffset}px, -${pieceTop}px)`,
  } satisfies CSSProperties;
  const thumbStyle = {
    width: `${thumbWidth}px`,
    transform: `translateX(${offset}px)`,
  } satisfies CSSProperties;
  const sliderProgressStyle = {
    width: `${Math.max(thumbWidth + 12, offset + thumbWidth + 12)}px`,
  } satisfies CSSProperties;
  const checkboxChecked = status === "verified";

  return (
    <>
      <button
        type="button"
        className={`slider-captcha-check slider-captcha-check-${status}`}
        onClick={handleOpen}
        disabled={disabled}
        aria-haspopup="dialog"
        aria-expanded={isOpen}
      >
        <span
          className={`slider-captcha-check-box ${
            checkboxChecked ? "is-checked" : ""
          }`}
          aria-hidden="true"
        >
          {checkboxChecked ? "OK" : ""}
        </span>
        <span className="slider-captcha-check-label">I&apos;m not a robot</span>
        <span className="slider-captcha-check-brand">reCAPTCHA</span>
      </button>

      {isOpen ? (
        <div className="slider-captcha-modal" role="dialog" aria-modal="true">
          <div
            className="slider-captcha-backdrop-layer"
            onClick={handleClose}
          />
          <div className="slider-captcha-panel" style={panelStyle}>
            <button
              type="button"
              className="slider-captcha-close"
              onClick={handleClose}
              aria-label="Close verification"
            >
              x
            </button>
            <div className="slider-captcha-panel-head">
              <div className="slider-captcha-panel-title">Verification:</div>
              <p>{message}</p>
            </div>

            <div className="slider-captcha-stage-large" style={surfaceStyle}>
              <img
                src={CAPTCHA_IMAGE_SRC}
                alt="Captcha code background"
                className="slider-captcha-source-image"
                draggable={false}
              />
              <div
                className="slider-captcha-target-piece"
                style={targetStyle}
              />
              <div
                className="slider-captcha-floating-piece"
                style={pieceStyle}
                onPointerDown={handlePointerDown}
              >
                <img
                  src={CAPTCHA_IMAGE_SRC}
                  alt=""
                  className="slider-captcha-floating-image"
                  style={pieceImageStyle}
                  draggable={false}
                />
              </div>
            </div>

            <div
              className="slider-captcha-slider-shell"
              style={{ width: `${stageWidth}px` }}
            >
              <div
                className="slider-captcha-slider-progress"
                style={sliderProgressStyle}
              />
              <button
                type="button"
                className="slider-captcha-slider-thumb"
                style={thumbStyle}
                onPointerDown={handlePointerDown}
                disabled={
                  disabled || status === "loading" || status === "error"
                }
                aria-label="Drag slider captcha"
              >
                <span>{checkboxChecked ? "OK" : ">>"}</span>
              </button>
              <span className="slider-captcha-slider-copy">
                Drag the slider to fit the puzzle piece
              </span>
            </div>

            <div className="slider-captcha-panel-actions">
              <button
                type="button"
                className="slider-captcha-link"
                onClick={() => void loadChallenge()}
              >
                Refresh
              </button>
              <button
                type="button"
                className="slider-captcha-link"
                onClick={() => void loadChallenge()}
              >
                Report a problem
              </button>
              {challenge?.expiresAt ? (
                <span className="slider-captcha-time">
                  {new Date(challenge.expiresAt).toLocaleTimeString("en-US", {
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
                </span>
              ) : null}
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}
