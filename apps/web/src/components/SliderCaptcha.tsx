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
const CAPTCHA_MAX_STAGE_WIDTH = 360;
const randomInt = (min: number, max: number) =>
  Math.floor(Math.random() * (max - min + 1)) + min;

const pickOne = <T,>(items: readonly T[]) =>
  items[Math.floor(Math.random() * items.length)];

const asDataImage = (svg: string) =>
  `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;

const buildSkylineCaptchaImage = () => {
  const stops = pickOne([
    ["#082f49", "#172554", "#0f172a"],
    ["#0f172a", "#1d4ed8", "#0f766e"],
    ["#111827", "#3b0764", "#1e293b"],
  ] as const);
  const buildingWidths = Array.from({ length: 9 }, () => randomInt(46, 90));
  let currentX = -8;
  const buildings = buildingWidths
    .map((width, index) => {
      const height = randomInt(110, 270);
      currentX += randomInt(8, 14);
      const x = currentX;
      currentX += width;
      const windows = Array.from({ length: randomInt(5, 10) })
        .map(() => {
          const wx = x + randomInt(8, Math.max(9, width - 16));
          const wy =
            CAPTCHA_SOURCE_HEIGHT - height + randomInt(14, height - 18);
          return `<rect x="${wx}" y="${wy}" width="8" height="10" rx="2" fill="rgba(250, 204, 21, ${Math.random() > 0.5 ? 0.72 : 0.22})" />`;
        })
        .join("");
      return `
        <rect x="${x}" y="${CAPTCHA_SOURCE_HEIGHT - height}" width="${width}" height="${height}" rx="12" fill="rgba(15, 23, 42, ${0.78 + index * 0.01})" />
        ${windows}`;
    })
    .join("");

  const svg = `
    <svg xmlns="http://www.w3.org/2000/svg" width="${CAPTCHA_SOURCE_WIDTH}" height="${CAPTCHA_SOURCE_HEIGHT}" viewBox="0 0 ${CAPTCHA_SOURCE_WIDTH} ${CAPTCHA_SOURCE_HEIGHT}">
      <defs>
        <linearGradient id="sky" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stop-color="${stops[0]}" />
          <stop offset="52%" stop-color="${stops[1]}" />
          <stop offset="100%" stop-color="${stops[2]}" />
        </linearGradient>
        <radialGradient id="sun" cx="76%" cy="22%" r="38%">
          <stop offset="0%" stop-color="rgba(250, 204, 21, 0.86)" />
          <stop offset="55%" stop-color="rgba(96, 165, 250, 0.24)" />
          <stop offset="100%" stop-color="rgba(96, 165, 250, 0)" />
        </radialGradient>
      </defs>
      <rect width="${CAPTCHA_SOURCE_WIDTH}" height="${CAPTCHA_SOURCE_HEIGHT}" rx="18" fill="url(#sky)" />
      <rect width="${CAPTCHA_SOURCE_WIDTH}" height="${CAPTCHA_SOURCE_HEIGHT}" rx="18" fill="url(#sun)" />
      <ellipse cx="${randomInt(470, 600)}" cy="${randomInt(82, 134)}" rx="${randomInt(70, 110)}" ry="${randomInt(36, 58)}" fill="rgba(255,255,255,0.16)" />
      <ellipse cx="${randomInt(120, 260)}" cy="${randomInt(56, 100)}" rx="${randomInt(50, 88)}" ry="${randomInt(26, 46)}" fill="rgba(255,255,255,0.09)" />
      <rect x="0" y="292" width="${CAPTCHA_SOURCE_WIDTH}" height="148" fill="rgba(2, 6, 23, 0.22)" />
      ${buildings}
      <rect x="0" y="0" width="${CAPTCHA_SOURCE_WIDTH}" height="${CAPTCHA_SOURCE_HEIGHT}" rx="18" fill="none" stroke="rgba(255,255,255,0.08)" />
    </svg>`;

  return asDataImage(svg);
};

const buildLandscapeCaptchaImage = () => {
  const mountainColors = pickOne([
    ["#1d4ed8", "#0f766e", "#022c22"],
    ["#1e3a8a", "#0f766e", "#14532d"],
    ["#0f172a", "#1d4ed8", "#166534"],
  ] as const);
  const svg = `
    <svg xmlns="http://www.w3.org/2000/svg" width="${CAPTCHA_SOURCE_WIDTH}" height="${CAPTCHA_SOURCE_HEIGHT}" viewBox="0 0 ${CAPTCHA_SOURCE_WIDTH} ${CAPTCHA_SOURCE_HEIGHT}">
      <defs>
        <linearGradient id="sky" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#38bdf8" />
          <stop offset="50%" stop-color="#93c5fd" />
          <stop offset="100%" stop-color="#dbeafe" />
        </linearGradient>
        <linearGradient id="water" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stop-color="#0f766e" />
          <stop offset="100%" stop-color="#1d4ed8" />
        </linearGradient>
      </defs>
      <rect width="${CAPTCHA_SOURCE_WIDTH}" height="${CAPTCHA_SOURCE_HEIGHT}" rx="18" fill="url(#sky)" />
      <circle cx="${randomInt(520, 630)}" cy="${randomInt(86, 136)}" r="${randomInt(34, 48)}" fill="rgba(254, 240, 138, 0.92)" />
      <path d="M0 270 C110 202 172 210 244 258 C330 158 448 148 548 248 C620 204 678 214 736 252 L736 440 L0 440 Z" fill="${mountainColors[0]}" />
      <path d="M0 296 C98 244 188 256 268 308 C354 224 432 222 526 304 C620 252 690 264 736 296 L736 440 L0 440 Z" fill="${mountainColors[1]}" opacity="0.95" />
      <path d="M0 328 C120 296 210 308 290 334 C376 286 464 286 560 336 C644 312 702 316 736 330 L736 440 L0 440 Z" fill="${mountainColors[2]}" />
      <rect x="0" y="310" width="${CAPTCHA_SOURCE_WIDTH}" height="130" fill="url(#water)" opacity="0.52" />
      <path d="M0 352 C84 342 164 370 246 360 C340 348 416 324 512 342 C598 358 664 380 736 362" stroke="rgba(255,255,255,0.26)" stroke-width="4" fill="none" />
      <rect x="0" y="0" width="${CAPTCHA_SOURCE_WIDTH}" height="${CAPTCHA_SOURCE_HEIGHT}" rx="18" fill="none" stroke="rgba(255,255,255,0.12)" />
    </svg>`;

  return asDataImage(svg);
};

const buildAbstractCaptchaImage = () => {
  const palette = pickOne([
    ["#0f172a", "#7c3aed", "#06b6d4", "#22c55e"],
    ["#111827", "#2563eb", "#38bdf8", "#f59e0b"],
    ["#172554", "#0f766e", "#14b8a6", "#84cc16"],
  ] as const);
  const rings = Array.from({ length: 6 })
    .map(
      (_, index) => `
        <circle
          cx="${randomInt(80, 660)}"
          cy="${randomInt(64, 360)}"
          r="${randomInt(26, 88)}"
          fill="none"
          stroke="rgba(255,255,255,${0.06 + index * 0.03})"
          stroke-width="${randomInt(8, 18)}"
        />`,
    )
    .join("");
  const cards = Array.from({ length: 8 })
    .map(
      () => `
        <rect
          x="${randomInt(-20, 640)}"
          y="${randomInt(-10, 340)}"
          width="${randomInt(70, 180)}"
          height="${randomInt(42, 110)}"
          rx="20"
          fill="rgba(255,255,255,0.08)"
          transform="rotate(${randomInt(-24, 24)} ${randomInt(120, 620)} ${randomInt(80, 320)})"
        />`,
    )
    .join("");

  const svg = `
    <svg xmlns="http://www.w3.org/2000/svg" width="${CAPTCHA_SOURCE_WIDTH}" height="${CAPTCHA_SOURCE_HEIGHT}" viewBox="0 0 ${CAPTCHA_SOURCE_WIDTH} ${CAPTCHA_SOURCE_HEIGHT}">
      <defs>
        <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stop-color="${palette[0]}" />
          <stop offset="32%" stop-color="${palette[1]}" />
          <stop offset="68%" stop-color="${palette[2]}" />
          <stop offset="100%" stop-color="${palette[3]}" />
        </linearGradient>
      </defs>
      <rect width="${CAPTCHA_SOURCE_WIDTH}" height="${CAPTCHA_SOURCE_HEIGHT}" rx="18" fill="url(#bg)" />
      <rect width="${CAPTCHA_SOURCE_WIDTH}" height="${CAPTCHA_SOURCE_HEIGHT}" rx="18" fill="rgba(15,23,42,0.22)" />
      ${rings}
      ${cards}
      <path d="M-10 344 C122 280 224 398 348 344 C470 290 570 230 746 318 L746 440 L-10 440 Z" fill="rgba(15,23,42,0.32)" />
      <rect x="0" y="0" width="${CAPTCHA_SOURCE_WIDTH}" height="${CAPTCHA_SOURCE_HEIGHT}" rx="18" fill="none" stroke="rgba(255,255,255,0.1)" />
    </svg>`;

  return asDataImage(svg);
};

const buildRandomCaptchaImage = () =>
  pickOne([
    buildSkylineCaptchaImage,
    buildLandscapeCaptchaImage,
    buildAbstractCaptchaImage,
  ])();

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
  const [imageSrc, setImageSrc] = useState(buildRandomCaptchaImage);
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
    setImageSrc(buildRandomCaptchaImage());
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
    setImageSrc(buildRandomCaptchaImage());
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

    const scale =
      challenge.stageWidthPx > CAPTCHA_MAX_STAGE_WIDTH
        ? CAPTCHA_MAX_STAGE_WIDTH / challenge.stageWidthPx
        : 1;
    const displayStageWidth = Math.round(challenge.stageWidthPx * scale);
    const displayPieceWidth = Math.max(
      52,
      Math.round(challenge.pieceWidthPx * scale),
    );
    const displayTargetOffset = clamp(
      Math.round(challenge.targetOffsetPx * scale),
      0,
      Math.max(0, displayStageWidth - displayPieceWidth),
    );
    const displayTolerance = Math.max(
      6,
      Math.round(challenge.tolerancePx * scale),
    );
    const maxOffset = displayStageWidth - displayPieceWidth;
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
        Math.abs(finalOffset - displayTargetOffset) <= displayTolerance;

      setDragging(false);
      if (!matched) {
        updateOffset(0);
        onChange(null);
        setStatus("idle");
        setMessage("Position is not correct. Try again.");
        return;
      }

      updateOffset(displayTargetOffset);
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

  const displayScale =
    challenge && challenge.stageWidthPx > CAPTCHA_MAX_STAGE_WIDTH
      ? CAPTCHA_MAX_STAGE_WIDTH / challenge.stageWidthPx
      : 1;
  const stageWidth = challenge
    ? Math.round(challenge.stageWidthPx * displayScale)
    : CAPTCHA_MAX_STAGE_WIDTH;
  const pieceWidth = challenge
    ? Math.max(52, Math.round(challenge.pieceWidthPx * displayScale))
    : 72;
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
  const targetOffset = clamp(
    challenge ? Math.round(challenge.targetOffsetPx * displayScale) : 0,
    0,
    maxOffset,
  );

  const panelStyle = {
    width: `${stageWidth + 78}px`,
    maxWidth: "calc(100vw - 28px)",
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
          {checkboxChecked ? (
            <span className="slider-captcha-check-tick" />
          ) : null}
        </span>
        <span className="slider-captcha-check-label">I&apos;m not a robot</span>
        <span className="slider-captcha-check-brand-stack" aria-hidden="true">
          <span className="slider-captcha-check-brand-mark" />
          <span className="slider-captcha-check-brand">Security check</span>
        </span>
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
                src={imageSrc}
                alt="Captcha background"
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
                  src={imageSrc}
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
                <span
                  className={`slider-captcha-slider-thumb-icon ${
                    checkboxChecked ? "is-checked" : ""
                  }`}
                  aria-hidden="true"
                />
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
