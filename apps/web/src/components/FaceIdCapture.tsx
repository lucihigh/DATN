import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
} from "react";

export type FaceIdStepId =
  | "center"
  | "move_left"
  | "move_right"
  | "move_closer";

export type FaceIdStepCapture = {
  step: FaceIdStepId;
  image: string;
  centerX: number;
  centerY: number;
  coverage: number;
  motion: number;
  aligned?: boolean;
};

export type FaceIdProof = {
  challengeToken: string;
  descriptor: string;
  livenessScore: number;
  motionScore: number;
  faceCoverage: number;
  sampleCount: number;
  completedSteps: FaceIdStepId[];
  stepCaptures: FaceIdStepCapture[];
  previewImage?: string;
};

type FaceIdChallenge = {
  challengeToken: string;
  steps: { id: FaceIdStepId; label: string }[];
  expiresAt: string;
};

type FaceIdCaptureProps = {
  apiBase: string;
  resetKey?: number;
  disabled?: boolean;
  onChange: (value: FaceIdProof | null) => void;
};

type CameraOption = {
  id: string;
  label: string;
};

type DetectedFace = {
  boundingBox: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
};

type AlignmentSnapshot = {
  centerX: number;
  centerY: number;
  coverage: number;
  deltaX: number;
  deltaY: number;
  sizeRatio: number;
  glow: number;
  aligned: boolean;
};

type BrowserFaceDetector = {
  detect: (image: CanvasImageSource) => Promise<DetectedFace[]>;
};

type BrowserFaceDetectorCtor = new (options?: {
  fastMode?: boolean;
  maxDetectedFaces?: number;
}) => BrowserFaceDetector;

type DetectorAdapter = {
  detect: (image: CanvasImageSource) => Promise<DetectedFace[]>;
};

type BrowserImageCapture = {
  grabFrame: () => Promise<ImageBitmap>;
};

type BrowserImageCaptureCtor = new (
  track: MediaStreamTrack,
) => BrowserImageCapture;

const STEP_COLORS: Record<FaceIdStepId, string> = {
  center: "#38bdf8",
  move_left: "#a78bfa",
  move_right: "#22c55e",
  move_closer: "#f59e0b",
};

const PROCESS_INTERVAL_MS = 140;
const REQUIRED_STEP_STREAK = 3;
const COMPAT_REQUIRED_STEP_STREAK = 3;
const MEDIAPIPE_WASM_PATH =
  "https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.32/wasm";
const MEDIAPIPE_FACE_MODEL_PATH =
  "https://storage.googleapis.com/mediapipe-models/face_detector/blaze_face_short_range/float16/1/blaze_face_short_range.tflite";

const clamp = (value: number, min: number, max: number) =>
  Math.min(Math.max(value, min), max);

const base64FromBytes = (bytes: Uint8Array) => {
  let result = "";
  for (const byte of bytes) {
    result += String.fromCharCode(byte);
  }
  return btoa(result);
};

const waitForVideoReady = (video: HTMLVideoElement) =>
  new Promise<void>((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      video.removeEventListener("loadedmetadata", onReady);
      video.removeEventListener("canplay", onReady);
      video.removeEventListener("error", onError);
      window.clearTimeout(timeoutId);
    };
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      cleanup();
      fn();
    };
    const onReady = () => finish(resolve);
    const onError = () =>
      finish(() => reject(new Error("Cannot render camera preview.")));
    const timeoutId = window.setTimeout(() => {
      finish(() => reject(new Error("Camera preview took too long to start.")));
    }, 5000);

    if (
      video.readyState >= HTMLMediaElement.HAVE_METADATA &&
      video.videoWidth
    ) {
      finish(resolve);
      return;
    }

    video.addEventListener("loadedmetadata", onReady);
    video.addEventListener("canplay", onReady);
    video.addEventListener("error", onError);
  });

const buildFaceDescriptor = (
  sourceCanvas: HTMLCanvasElement,
  box: { x: number; y: number; width: number; height: number },
) => {
  const paddingX = box.width * 0.18;
  const paddingY = box.height * 0.2;
  const cropX = clamp(Math.round(box.x - paddingX), 0, sourceCanvas.width);
  const cropY = clamp(Math.round(box.y - paddingY), 0, sourceCanvas.height);
  const cropWidth = clamp(
    Math.round(box.width + paddingX * 2),
    1,
    sourceCanvas.width - cropX,
  );
  const cropHeight = clamp(
    Math.round(box.height + paddingY * 2),
    1,
    sourceCanvas.height - cropY,
  );

  const descriptorCanvas = document.createElement("canvas");
  descriptorCanvas.width = 16;
  descriptorCanvas.height = 16;
  const descriptorCtx = descriptorCanvas.getContext("2d");
  if (!descriptorCtx) {
    throw new Error("faceid-canvas-unavailable");
  }

  descriptorCtx.drawImage(
    sourceCanvas,
    cropX,
    cropY,
    cropWidth,
    cropHeight,
    0,
    0,
    descriptorCanvas.width,
    descriptorCanvas.height,
  );

  const pixels = descriptorCtx.getImageData(
    0,
    0,
    descriptorCanvas.width,
    descriptorCanvas.height,
  ).data;
  const bytes = new Uint8Array(
    descriptorCanvas.width * descriptorCanvas.height,
  );
  for (let index = 0; index < bytes.length; index += 1) {
    const offset = index * 4;
    const gray = Math.round(
      pixels[offset] * 0.299 +
        pixels[offset + 1] * 0.587 +
        pixels[offset + 2] * 0.114,
    );
    bytes[index] = gray;
  }
  return base64FromBytes(bytes);
};

const computeCueScore = (
  imageData: Uint8ClampedArray,
  cueColor: string,
): number => {
  let red = 0;
  let green = 0;
  let blue = 0;
  const samples = Math.max(1, imageData.length / 4);
  for (let index = 0; index < imageData.length; index += 4) {
    red += imageData[index];
    green += imageData[index + 1];
    blue += imageData[index + 2];
  }
  red /= samples;
  green /= samples;
  blue /= samples;

  switch (cueColor) {
    case "#38bdf8":
      return clamp((blue - red * 0.35 - green * 0.35) / 80, 0, 1);
    case "#a78bfa":
      return clamp((blue + red - green * 1.2) / 170, 0, 1);
    case "#22c55e":
      return clamp((green - red * 0.35 - blue * 0.35) / 80, 0, 1);
    default:
      return clamp((red + green - blue * 1.1) / 160, 0, 1);
  }
};

const computePresenceScore = (imageData: Uint8ClampedArray): number => {
  let luminanceSum = 0;
  let luminanceSquaredSum = 0;
  let edgeDelta = 0;
  let samples = 0;

  for (let index = 0; index < imageData.length; index += 16) {
    const luminance =
      imageData[index] * 0.299 +
      imageData[index + 1] * 0.587 +
      imageData[index + 2] * 0.114;
    luminanceSum += luminance;
    luminanceSquaredSum += luminance * luminance;
    samples += 1;

    const neighborOffset = index + 20;
    if (neighborOffset < imageData.length) {
      const neighborLuminance =
        imageData[neighborOffset] * 0.299 +
        imageData[neighborOffset + 1] * 0.587 +
        imageData[neighborOffset + 2] * 0.114;
      edgeDelta += Math.abs(luminance - neighborLuminance);
    }
  }

  if (!samples) return 0;

  const averageLuminance = luminanceSum / samples;
  const variance = Math.max(
    luminanceSquaredSum / samples - averageLuminance * averageLuminance,
    0,
  );
  const contrast = Math.sqrt(variance) / 255;
  const edgeStrength = edgeDelta / samples / 255;
  const exposureScore =
    averageLuminance > 32 && averageLuminance < 220 ? 0.18 : 0;

  return clamp(contrast * 1.9 + edgeStrength * 0.8 + exposureScore, 0, 1);
};

export function FaceIdCapture({
  apiBase,
  resetKey = 0,
  disabled = false,
  onChange,
}: FaceIdCaptureProps) {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const detectorRef = useRef<DetectorAdapter | null>(null);
  const detectorLoadRef = useRef<Promise<DetectorAdapter | null> | null>(null);
  const imageCaptureRef = useRef<BrowserImageCapture | null>(null);
  const imageBitmapRef = useRef<ImageBitmap | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const rafRef = useRef<number | null>(null);
  const lastProcessAtRef = useRef(0);
  const stepStreakRef = useRef(0);
  const prevFaceCenterRef = useRef<{
    x: number;
    y: number;
    coverage: number;
  } | null>(null);
  const motionAccumulatorRef = useRef(0);
  const cueAccumulatorRef = useRef(0);
  const sampleCountRef = useRef(0);
  const lastBoxRef = useRef<DetectedFace["boundingBox"] | null>(null);
  const stepCaptureRef = useRef<
    Partial<Record<FaceIdStepId, FaceIdStepCapture>>
  >({});
  const centerSnapshotRef = useRef<{
    centerX: number;
    centerY: number;
    coverage: number;
  } | null>(null);
  const previousFrameRef = useRef<Uint8ClampedArray | null>(null);
  const compatScanProgressRef = useRef(0);
  const compatAlignedSamplesRef = useRef(0);
  const noDetectionFramesRef = useRef(0);

  const [challenge, setChallenge] = useState<FaceIdChallenge | null>(null);
  const [active, setActive] = useState(false);
  const [captureMode, setCaptureMode] = useState<"native" | "compat">("native");
  const [status, setStatus] = useState<
    "idle" | "loading" | "ready" | "scanning" | "verified" | "error"
  >("idle");
  const [message, setMessage] = useState(
    "Register a real face scan that is fixed to this account.",
  );
  const [stepIndex, setStepIndex] = useState(0);
  const [completedSteps, setCompletedSteps] = useState<FaceIdStepId[]>([]);
  const [previewImage, setPreviewImage] = useState<string | null>(null);
  const [diagnostic, setDiagnostic] = useState("");
  const [availableCameras, setAvailableCameras] = useState<CameraOption[]>([]);
  const [selectedDeviceId, setSelectedDeviceId] = useState("");
  const [scanProgress, setScanProgress] = useState(0);
  const [faceAligned, setFaceAligned] = useState(false);
  const [alignmentGlow, setAlignmentGlow] = useState(0);

  const activeStep = challenge?.steps[stepIndex] ?? null;
  const activeCueColor = activeStep ? STEP_COLORS[activeStep.id] : "#38bdf8";

  const stopCamera = useCallback(() => {
    if (rafRef.current !== null) {
      window.cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((track) => track.stop());
      streamRef.current = null;
    }
    imageCaptureRef.current = null;
    if (imageBitmapRef.current) {
      imageBitmapRef.current.close();
      imageBitmapRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
    setActive(false);
  }, []);

  const resetState = useCallback(() => {
    stopCamera();
    setChallenge(null);
    setStatus("idle");
    setMessage("Register a real face scan that is fixed to this account.");
    setStepIndex(0);
    setCompletedSteps([]);
    setPreviewImage(null);
    setDiagnostic("");
    stepStreakRef.current = 0;
    prevFaceCenterRef.current = null;
    motionAccumulatorRef.current = 0;
    cueAccumulatorRef.current = 0;
    sampleCountRef.current = 0;
    lastBoxRef.current = null;
    stepCaptureRef.current = {};
    centerSnapshotRef.current = null;
    previousFrameRef.current = null;
    compatScanProgressRef.current = 0;
    compatAlignedSamplesRef.current = 0;
    noDetectionFramesRef.current = 0;
    setCaptureMode("native");
    setScanProgress(0);
    setFaceAligned(false);
    setAlignmentGlow(0);
    onChange(null);
  }, [onChange, stopCamera]);

  useEffect(() => {
    resetState();
  }, [resetKey, resetState]);

  useEffect(() => () => stopCamera(), [stopCamera]);

  const refreshAvailableCameras = useCallback(async () => {
    if (!navigator.mediaDevices?.enumerateDevices) return;
    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      const cameras = devices
        .filter((device) => device.kind === "videoinput")
        .map((device, index) => ({
          id: device.deviceId,
          label: device.label || `Camera ${index + 1}`,
        }));
      setAvailableCameras(cameras);
      if (!selectedDeviceId && cameras[0]?.id) {
        setSelectedDeviceId(cameras[0].id);
      }
    } catch {
      // ignore
    }
  }, [selectedDeviceId]);

  useEffect(() => {
    void refreshAvailableCameras();
  }, [refreshAvailableCameras]);

  const loadChallenge = useCallback(async () => {
    const response = await fetch(`${apiBase}/auth/face/challenge`, {
      cache: "no-store",
    });
    const data = (await response
      .json()
      .catch(() => null)) as FaceIdChallenge | null;
    if (
      !response.ok ||
      !data ||
      typeof data.challengeToken !== "string" ||
      !Array.isArray(data.steps)
    ) {
      throw new Error("Cannot load FaceID challenge");
    }
    return data;
  }, [apiBase]);

  const ensureDetector = useCallback(async () => {
    if (detectorRef.current) return detectorRef.current;
    if (detectorLoadRef.current) {
      return detectorLoadRef.current;
    }

    const ctor = (window as Window & { FaceDetector?: BrowserFaceDetectorCtor })
      .FaceDetector;
    if (ctor) {
      const browserDetector = new ctor({ fastMode: true, maxDetectedFaces: 1 });
      detectorRef.current = {
        detect: (image) => browserDetector.detect(image),
      };
      return detectorRef.current;
    }

    detectorLoadRef.current = (async () => {
      try {
        const { FaceDetector, FilesetResolver } =
          await import("@mediapipe/tasks-vision");
        const vision =
          await FilesetResolver.forVisionTasks(MEDIAPIPE_WASM_PATH);
        const detector = await FaceDetector.createFromOptions(vision, {
          baseOptions: {
            modelAssetPath: MEDIAPIPE_FACE_MODEL_PATH,
          },
          runningMode: "VIDEO",
          minDetectionConfidence: 0.55,
        });

        const adapter: DetectorAdapter = {
          detect: async (image) => {
            const result = detector.detectForVideo(
              image as TexImageSource,
              performance.now(),
            );
            return (result.detections ?? [])
              .map((detection) => {
                const box = detection.boundingBox;
                if (!box) return null;
                return {
                  boundingBox: {
                    x: box.originX,
                    y: box.originY,
                    width: box.width,
                    height: box.height,
                  },
                };
              })
              .filter((face): face is DetectedFace => Boolean(face));
          },
        };

        detectorRef.current = adapter;
        return adapter;
      } catch {
        return null;
      } finally {
        detectorLoadRef.current = null;
      }
    })();

    return detectorLoadRef.current;
  }, []);

  const createImageCapture = useCallback((track: MediaStreamTrack) => {
    const ctor = (
      window as unknown as {
        ImageCapture?: BrowserImageCaptureCtor;
      }
    ).ImageCapture;
    if (!ctor) return null;
    try {
      return new ctor(track);
    } catch {
      return null;
    }
  }, []);

  const getCompatibilityBox = useCallback((canvas: HTMLCanvasElement) => {
    const width = canvas.width * 0.34;
    const height = canvas.height * 0.48;
    return {
      x: (canvas.width - width) / 2,
      y: (canvas.height - height) / 2.15,
      width,
      height,
    };
  }, []);

  const computeFrameMotion = useCallback(
    (frame: Uint8ClampedArray, previous: Uint8ClampedArray | null) => {
      if (!previous || previous.length !== frame.length) return 0;

      let delta = 0;
      let samples = 0;
      for (let index = 0; index < frame.length; index += 16) {
        delta +=
          Math.abs(frame[index] - previous[index]) +
          Math.abs(frame[index + 1] - previous[index + 1]) +
          Math.abs(frame[index + 2] - previous[index + 2]);
        samples += 3;
      }

      return samples > 0 ? clamp(delta / samples / 28, 0, 1) : 0;
    },
    [],
  );

  const buildEvidenceImage = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return null;

    const evidenceCanvas = document.createElement("canvas");
    evidenceCanvas.width = 256;
    evidenceCanvas.height = 192;
    const ctx = evidenceCanvas.getContext("2d");
    if (!ctx) return null;

    ctx.drawImage(canvas, 0, 0, evidenceCanvas.width, evidenceCanvas.height);
    return evidenceCanvas.toDataURL("image/jpeg", 0.68);
  }, []);

  const captureStepEvidence = useCallback(
    (
      step: FaceIdStepId,
      alignment: AlignmentSnapshot,
      motionMetric: number,
    ) => {
      const image = buildEvidenceImage();
      if (!image) return;

      stepCaptureRef.current[step] = {
        step,
        image,
        centerX: clamp(alignment.centerX, 0, 1),
        centerY: clamp(alignment.centerY, 0, 1),
        coverage: clamp(alignment.coverage, 0, 1),
        motion: clamp(motionMetric, 0, 1),
        aligned: alignment.aligned,
      };
    },
    [buildEvidenceImage],
  );

  const finalizeProof = useCallback(
    (resolvedSteps: FaceIdStepId[]) => {
      const canvas = canvasRef.current;
      const box = lastBoxRef.current;
      if (!canvas || !box || !challenge) {
        setStatus("error");
        setMessage("Face sample was incomplete. Please scan again.");
        onChange(null);
        return;
      }

      try {
        if (resolvedSteps.length !== challenge.steps.length) {
          throw new Error("Face scan steps were incomplete.");
        }
        const orderedStepCaptures = challenge.steps
          .map((step) => stepCaptureRef.current[step.id])
          .filter((capture): capture is FaceIdStepCapture => Boolean(capture));
        if (orderedStepCaptures.length !== challenge.steps.length) {
          throw new Error(
            "Live step evidence was incomplete. Please scan again.",
          );
        }
        const descriptor = buildFaceDescriptor(canvas, box);
        const completedRatio =
          challenge.steps.length > 0
            ? resolvedSteps.length / challenge.steps.length
            : 0;
        const motionScore = clamp(motionAccumulatorRef.current / 0.6, 0, 1);
        const cueScore = clamp(
          sampleCountRef.current > 0
            ? cueAccumulatorRef.current / sampleCountRef.current
            : 0,
          0,
          1,
        );
        const faceCoverage = clamp(
          (box.width * box.height) / (canvas.width * canvas.height),
          0,
          1,
        );
        const livenessScore = clamp(
          completedRatio * 0.45 + motionScore * 0.35 + cueScore * 0.2,
          0,
          1,
        );
        const preview = canvas.toDataURL("image/jpeg", 0.78);

        const proof: FaceIdProof = {
          challengeToken: challenge.challengeToken,
          descriptor,
          livenessScore,
          motionScore,
          faceCoverage,
          sampleCount: sampleCountRef.current,
          completedSteps: resolvedSteps,
          stepCaptures: orderedStepCaptures,
          previewImage: preview,
        };

        setPreviewImage(preview);
        setScanProgress(1);
        setStatus("verified");
        setMessage(
          "FaceID registered. This biometric sample is now linked to the account.",
        );
        setDiagnostic("");
        onChange(proof);
        stopCamera();
      } catch (error) {
        setStatus("error");
        setMessage(
          error instanceof Error ? error.message : "FaceID capture failed.",
        );
        onChange(null);
      }
    },
    [challenge, onChange, stopCamera],
  );

  const renderCurrentFrameToCanvas = useCallback(async () => {
    const canvas = canvasRef.current;
    const video = videoRef.current;
    if (!canvas) {
      throw new Error("Camera canvas is not ready.");
    }

    const ctx = canvas.getContext("2d");
    if (!ctx) {
      throw new Error("Camera preview context is unavailable.");
    }

    if (video && video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA) {
      canvas.width = video.videoWidth || 640;
      canvas.height = video.videoHeight || 480;
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      return canvas;
    }

    if (imageCaptureRef.current) {
      const bitmap = await imageCaptureRef.current.grabFrame();
      if (imageBitmapRef.current) {
        imageBitmapRef.current.close();
      }
      imageBitmapRef.current = bitmap;
      canvas.width = bitmap.width || 640;
      canvas.height = bitmap.height || 480;
      ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
      return canvas;
    }

    throw new Error("Live camera frame is not available yet.");
  }, []);

  const getAlignmentSnapshot = useCallback(
    (box: DetectedFace["boundingBox"], canvas: HTMLCanvasElement) => {
      const rawCenterX = (box.x + box.width / 2) / canvas.width;
      const centerY = (box.y + box.height / 2) / canvas.height;
      const centerX = 1 - rawCenterX;
      const coverage =
        (box.width * box.height) / (canvas.width * canvas.height);
      const targetBox = getCompatibilityBox(canvas);
      const targetCenterX =
        1 - (targetBox.x + targetBox.width / 2) / canvas.width;
      const targetCenterY =
        (targetBox.y + targetBox.height / 2) / canvas.height;
      const targetCoverage =
        (targetBox.width * targetBox.height) / (canvas.width * canvas.height);
      const deltaX = centerX - targetCenterX;
      const deltaY = centerY - targetCenterY;
      const sizeRatio = coverage / Math.max(targetCoverage, 0.0001);
      const horizontalScore = clamp(1 - Math.abs(deltaX) / 0.14, 0, 1);
      const verticalScore = clamp(1 - Math.abs(deltaY) / 0.15, 0, 1);
      const sizeScore = clamp(1 - Math.abs(1 - sizeRatio) / 0.65, 0, 1);
      const glow = clamp(
        horizontalScore * 0.35 + verticalScore * 0.35 + sizeScore * 0.3,
        0,
        1,
      );
      const aligned =
        sizeRatio >= 0.56 &&
        sizeRatio <= 1.34 &&
        Math.abs(deltaX) <= 0.11 &&
        Math.abs(deltaY) <= 0.12;

      return {
        centerX,
        centerY,
        coverage,
        deltaX,
        deltaY,
        sizeRatio,
        glow,
        aligned,
      };
    },
    [getCompatibilityBox],
  );

  const evaluateStep = useCallback(
    (
      alignment: AlignmentSnapshot,
      motionMetric: number,
      totalSteps: number,
    ) => {
      if (!activeStep) return false;

      const baseline = centerSnapshotRef.current;
      let matched = false;
      let hint = activeStep.label;

      if (activeStep.id === "center") {
        matched =
          alignment.aligned &&
          alignment.coverage >= 0.1 &&
          motionMetric <= 0.07;
        hint = matched
          ? "Hold still to lock the center step."
          : "Center your face inside the oval and hold still.";
      } else if (activeStep.id === "move_left") {
        matched = Boolean(
          baseline &&
          alignment.centerX <= baseline.centerX - 0.08 &&
          Math.abs(alignment.centerY - baseline.centerY) <= 0.13 &&
          alignment.coverage >= baseline.coverage * 0.68 &&
          alignment.coverage <= baseline.coverage * 1.38 &&
          motionMetric >= 0.01,
        );
        hint = "Turn or move your face slightly to the left.";
      } else if (activeStep.id === "move_right") {
        matched = Boolean(
          baseline &&
          alignment.centerX >= baseline.centerX + 0.08 &&
          Math.abs(alignment.centerY - baseline.centerY) <= 0.13 &&
          alignment.coverage >= baseline.coverage * 0.68 &&
          alignment.coverage <= baseline.coverage * 1.38 &&
          motionMetric >= 0.01,
        );
        hint = "Turn or move your face slightly to the right.";
      } else if (activeStep.id === "move_closer") {
        matched = Boolean(
          baseline &&
          alignment.coverage >= Math.max(baseline.coverage * 1.12, 0.135) &&
          Math.abs(alignment.deltaX) <= 0.13 &&
          Math.abs(alignment.deltaY) <= 0.14 &&
          motionMetric >= 0.008,
        );
        hint = "Move closer until your face fills more of the oval.";
      }

      if (!matched) {
        stepStreakRef.current = Math.max(stepStreakRef.current - 1, 0);
        setMessage(hint);
        return false;
      }

      stepStreakRef.current = Math.min(
        REQUIRED_STEP_STREAK,
        stepStreakRef.current + 1,
      );

      setScanProgress(
        clamp(
          (completedSteps.length +
            stepStreakRef.current / REQUIRED_STEP_STREAK) /
            Math.max(totalSteps, 1),
          0,
          0.99,
        ),
      );
      setMessage(
        `Good. ${activeStep.label} ${stepStreakRef.current}/${REQUIRED_STEP_STREAK}`,
      );

      if (stepStreakRef.current < REQUIRED_STEP_STREAK) {
        return true;
      }

      stepStreakRef.current = 0;
      if (activeStep.id === "center") {
        centerSnapshotRef.current = {
          centerX: alignment.centerX,
          centerY: alignment.centerY,
          coverage: alignment.coverage,
        };
      }
      captureStepEvidence(activeStep.id, alignment, motionMetric);

      const nextCompletedSteps = completedSteps.includes(activeStep.id)
        ? completedSteps
        : [...completedSteps, activeStep.id];
      setCompletedSteps(nextCompletedSteps);

      if (stepIndex + 1 >= (challenge?.steps.length ?? 0)) {
        window.setTimeout(() => finalizeProof(nextCompletedSteps), 160);
        return true;
      }

      setStepIndex((current) => current + 1);
      setMessage(
        `Step complete. Next: ${challenge?.steps[stepIndex + 1]?.label}`,
      );
      return true;
    },
    [
      activeStep,
      captureStepEvidence,
      challenge?.steps,
      completedSteps,
      finalizeProof,
      stepIndex,
    ],
  );

  const evaluateCompatibilityStep = useCallback(
    (box: DetectedFace["boundingBox"], motionMetric: number) => {
      if (!activeStep) return;

      const matched =
        activeStep.id === "center"
          ? sampleCountRef.current >= 4 && motionMetric >= 0.01
          : motionMetric >= (activeStep.id === "move_closer" ? 0.085 : 0.05);

      stepStreakRef.current = matched ? stepStreakRef.current + 1 : 0;
      if (stepStreakRef.current < COMPAT_REQUIRED_STEP_STREAK) {
        return;
      }

      stepStreakRef.current = 0;
      lastBoxRef.current = box;
      const nextCompletedSteps = completedSteps.includes(activeStep.id)
        ? completedSteps
        : [...completedSteps, activeStep.id];
      setCompletedSteps(nextCompletedSteps);

      if (stepIndex + 1 >= (challenge?.steps.length ?? 0)) {
        window.setTimeout(() => finalizeProof(nextCompletedSteps), 220);
        return;
      }

      setStepIndex((current) => current + 1);
      setMessage(
        `Compatibility mode: ${challenge?.steps[stepIndex + 1]?.label || "Continue the live scan."}`,
      );
    },
    [activeStep, challenge?.steps, completedSteps, finalizeProof, stepIndex],
  );

  const processFrame = useCallback(async () => {
    const video = videoRef.current;
    const canvas = canvasRef.current;
    if (!canvas || !active) return;
    const useImageCapture =
      !video && captureMode === "compat" && imageCaptureRef.current;
    if (!useImageCapture && !video) return;
    if (
      !useImageCapture &&
      video &&
      video.readyState < HTMLMediaElement.HAVE_CURRENT_DATA
    ) {
      rafRef.current = window.requestAnimationFrame(() => void processFrame());
      return;
    }

    const now = performance.now();
    if (now - lastProcessAtRef.current < PROCESS_INTERVAL_MS) {
      rafRef.current = window.requestAnimationFrame(() => void processFrame());
      return;
    }
    lastProcessAtRef.current = now;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    if (useImageCapture) {
      const bitmap = await imageCaptureRef.current!.grabFrame();
      if (imageBitmapRef.current) {
        imageBitmapRef.current.close();
      }
      imageBitmapRef.current = bitmap;
      canvas.width = bitmap.width || 640;
      canvas.height = bitmap.height || 480;
      ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    } else if (video) {
      canvas.width = video.videoWidth || 640;
      canvas.height = video.videoHeight || 480;
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    }

    try {
      const detector = detectorRef.current;
      if (detector) {
        const faces = await detector.detect(canvas);
        if (!faces.length) {
          noDetectionFramesRef.current += 1;
          setFaceAligned(false);
          setAlignmentGlow(0);
          setScanProgress(
            challenge?.steps.length
              ? completedSteps.length / challenge.steps.length
              : 0,
          );
          setMessage(
            noDetectionFramesRef.current > 8
              ? "Face not recognized yet. Keep your full face inside the oval."
              : "Scanning camera feed...",
          );
          rafRef.current = window.requestAnimationFrame(
            () => void processFrame(),
          );
          return;
        }
        noDetectionFramesRef.current = 0;

        const box = faces[0].boundingBox;
        lastBoxRef.current = box;
        const alignment = getAlignmentSnapshot(box, canvas);
        const totalSteps = challenge?.steps.length ?? 0;
        let alignmentMessage = "Face aligned. Scanning now.";

        if (alignment.sizeRatio < 0.46) {
          alignmentMessage = "Move closer until your face fits the oval.";
        } else if (alignment.sizeRatio > 1.48) {
          alignmentMessage = "Move a little back so your full face fits.";
        } else if (alignment.deltaX < -0.11) {
          alignmentMessage = "Move slightly to the right.";
        } else if (alignment.deltaX > 0.11) {
          alignmentMessage = "Move slightly to the left.";
        } else if (alignment.deltaY < -0.13) {
          alignmentMessage = "Lower your face into the oval.";
        } else if (alignment.deltaY > 0.13) {
          alignmentMessage = "Raise your face into the oval.";
        } else if (activeStep?.id === "move_left") {
          alignmentMessage = "Turn or move slightly to the left.";
        } else if (activeStep?.id === "move_right") {
          alignmentMessage = "Turn or move slightly to the right.";
        } else if (activeStep?.id === "move_closer") {
          alignmentMessage = "Lean a little closer to the camera.";
        } else if (activeStep?.id === "center") {
          alignmentMessage = "Keep your face centered for a moment.";
        }

        const motionMetric = prevFaceCenterRef.current
          ? clamp(
              Math.abs(alignment.centerX - prevFaceCenterRef.current.x) +
                Math.abs(alignment.centerY - prevFaceCenterRef.current.y) +
                Math.abs(
                  alignment.coverage - prevFaceCenterRef.current.coverage,
                ) *
                  2,
              0,
              1,
            )
          : 0;

        if (prevFaceCenterRef.current) {
          motionAccumulatorRef.current += Math.min(0.12, motionMetric);
        }
        prevFaceCenterRef.current = {
          x: alignment.centerX,
          y: alignment.centerY,
          coverage: alignment.coverage,
        };

        const sampleX = clamp(Math.round(box.x), 0, canvas.width - 1);
        const sampleY = clamp(Math.round(box.y), 0, canvas.height - 1);
        const sampleW = clamp(Math.round(box.width), 1, canvas.width - sampleX);
        const sampleH = clamp(
          Math.round(box.height),
          1,
          canvas.height - sampleY,
        );
        const cueImage = ctx.getImageData(
          sampleX,
          sampleY,
          sampleW,
          sampleH,
        ).data;
        cueAccumulatorRef.current += computeCueScore(cueImage, activeCueColor);
        sampleCountRef.current += 1;
        cueAccumulatorRef.current += 0.4;
        const stepMatched =
          challenge && totalSteps > 0
            ? evaluateStep(alignment, motionMetric, totalSteps)
            : false;
        const partialProgress =
          totalSteps > 0
            ? clamp(
                (completedSteps.length +
                  (stepMatched
                    ? stepStreakRef.current / REQUIRED_STEP_STREAK
                    : 0)) /
                  totalSteps,
                0,
                0.99,
              )
            : 0;
        setScanProgress(partialProgress);
        setFaceAligned(
          stepMatched ||
            (activeStep?.id === "center" && alignment.aligned) ||
            alignment.glow >= 0.72,
        );
        setAlignmentGlow(
          stepMatched
            ? Math.max(alignment.glow, 0.88)
            : activeStep?.id === "center" && alignment.aligned
              ? Math.max(alignment.glow, 0.64)
              : alignment.glow * 0.72,
        );
        if (!stepMatched) {
          setMessage(alignmentMessage);
        }
      } else {
        const box = getCompatibilityBox(canvas);
        const sampleX = clamp(Math.round(box.x), 0, canvas.width - 1);
        const sampleY = clamp(Math.round(box.y), 0, canvas.height - 1);
        const sampleW = clamp(Math.round(box.width), 1, canvas.width - sampleX);
        const sampleH = clamp(
          Math.round(box.height),
          1,
          canvas.height - sampleY,
        );
        const frame = ctx.getImageData(sampleX, sampleY, sampleW, sampleH).data;
        const motionMetric = computeFrameMotion(
          frame,
          previousFrameRef.current,
        );
        const presenceScore = computePresenceScore(frame);
        previousFrameRef.current = new Uint8ClampedArray(frame);

        const centerX = (box.x + box.width / 2) / canvas.width;
        const centerY = (box.y + box.height / 2) / canvas.height;
        const coverage =
          (box.width * box.height) / (canvas.width * canvas.height);

        if (prevFaceCenterRef.current) {
          motionAccumulatorRef.current += Math.min(
            0.1,
            motionMetric +
              Math.abs(coverage - prevFaceCenterRef.current.coverage) * 0.8,
          );
        }
        prevFaceCenterRef.current = { x: centerX, y: centerY, coverage };

        sampleCountRef.current += 1;
        lastBoxRef.current = box;

        const totalSteps = challenge?.steps.length ?? 0;
        const requiredCompatSamples = Math.max(18, totalSteps * 6, 1);
        const frameHasSignal =
          presenceScore >= 0.005 ||
          motionMetric >= 0.002 ||
          sampleCountRef.current > 3;
        if (frameHasSignal) {
          setFaceAligned(true);
          setAlignmentGlow(
            clamp(
              0.4 + compatAlignedSamplesRef.current / requiredCompatSamples,
              0,
              1,
            ),
          );
          compatAlignedSamplesRef.current = clamp(
            compatAlignedSamplesRef.current + 1,
            0,
            requiredCompatSamples,
          );
          motionAccumulatorRef.current += Math.max(
            0.03,
            motionMetric * 2 + Math.min(presenceScore, 0.18) * 0.1,
          );
        }
        cueAccumulatorRef.current += Math.max(0.82, presenceScore);
        compatScanProgressRef.current =
          compatAlignedSamplesRef.current / requiredCompatSamples;
        if (!frameHasSignal) {
          setFaceAligned(false);
          setAlignmentGlow(0.12);
        }

        const progressRatio = clamp(compatScanProgressRef.current, 0, 1);
        setScanProgress(progressRatio);

        if (!frameHasSignal) {
          setMessage("Align your face inside the oval to start auto scan.");
        } else if (progressRatio < 1) {
          setMessage(
            `Face detected. Hold steady while we auto scan ${Math.round(progressRatio * 100)}%.`,
          );
        }

        if (challenge && totalSteps > 0) {
          const nextCompletedCount = Math.min(
            totalSteps,
            Math.floor(progressRatio * totalSteps + 0.0001),
          );
          const nextCompletedSteps = challenge.steps
            .slice(0, nextCompletedCount)
            .map((step) => step.id);
          setCompletedSteps((current) =>
            current.length === nextCompletedSteps.length &&
            current.every((step, index) => step === nextCompletedSteps[index])
              ? current
              : nextCompletedSteps,
          );
          setStepIndex(Math.min(nextCompletedCount, totalSteps - 1));

          if (
            progressRatio >= 1 &&
            sampleCountRef.current >= requiredCompatSamples
          ) {
            finalizeProof(challenge.steps.map((step) => step.id));
            return;
          }
        } else {
          evaluateCompatibilityStep(box, motionMetric);
        }
      }
    } catch (error) {
      setStatus("error");
      setMessage(
        error instanceof Error ? error.message : "FaceID scan failed.",
      );
      onChange(null);
      stopCamera();
      return;
    }

    rafRef.current = window.requestAnimationFrame(() => void processFrame());
  }, [
    active,
    activeCueColor,
    challenge,
    computeFrameMotion,
    createImageCapture,
    captureMode,
    ensureDetector,
    evaluateStep,
    evaluateCompatibilityStep,
    getAlignmentSnapshot,
    getCompatibilityBox,
    onChange,
    stopCamera,
  ]);

  const startCapture = useCallback(async () => {
    if (disabled) return;
    setStatus("loading");
    setMessage("Starting camera and preparing your live face scan...");
    onChange(null);

    try {
      const detector = await ensureDetector();
      if (!detector) {
        throw new Error(
          "Live FaceID detection is unavailable on this browser. Use the latest Chrome or Edge.",
        );
      }
      if (!navigator.mediaDevices?.getUserMedia) {
        throw new Error("Camera access is not available in this browser.");
      }
      const video = videoRef.current;
      if (!video) {
        throw new Error("Camera preview is not ready yet.");
      }

      const nextChallenge = await loadChallenge();
      const constraintsList: MediaStreamConstraints[] = [
        { video: true, audio: false },
        ...(selectedDeviceId
          ? [
              {
                video: {
                  deviceId: { exact: selectedDeviceId },
                  width: { ideal: 1280 },
                  height: { ideal: 720 },
                },
                audio: false,
              } as MediaStreamConstraints,
            ]
          : []),
        ...(selectedDeviceId
          ? [
              {
                video: {
                  deviceId: selectedDeviceId,
                  width: { ideal: 1280 },
                  height: { ideal: 720 },
                },
                audio: false,
              } as MediaStreamConstraints,
            ]
          : []),
        {
          video: {
            facingMode: { ideal: "user" },
            width: { ideal: 1280 },
            height: { ideal: 720 },
          },
          audio: false,
        },
        {
          video: {
            facingMode: { ideal: "environment" },
            width: { ideal: 1280 },
            height: { ideal: 720 },
          },
          audio: false,
        },
      ];
      for (const camera of availableCameras) {
        if (!camera.id || camera.id === selectedDeviceId) continue;
        constraintsList.push({
          video: {
            deviceId: { exact: camera.id },
            width: { ideal: 1280 },
            height: { ideal: 720 },
          },
          audio: false,
        });
      }

      let activeStream: MediaStream | null = null;
      const attemptErrors: string[] = [];
      for (const constraints of constraintsList) {
        try {
          const stream = await navigator.mediaDevices.getUserMedia(constraints);
          video.srcObject = stream;
          video.muted = true;
          video.defaultMuted = true;
          video.autoplay = true;
          video.playsInline = true;
          video.setAttribute("playsinline", "true");
          video.setAttribute("autoplay", "true");
          await waitForVideoReady(video);
          await video.play().catch(() => {
            // Preview can still work after user gesture
          });
          activeStream = stream;
          break;
        } catch (openErr) {
          const name =
            openErr && typeof openErr === "object" && "name" in openErr
              ? String((openErr as { name?: unknown }).name || "Error")
              : "Error";
          attemptErrors.push(name);
        }
      }

      if (!activeStream) {
        throw new Error(
          attemptErrors.length
            ? `Cannot open camera. Attempts failed: ${attemptErrors.join(" / ")}`
            : "Cannot open camera stream.",
        );
      }

      streamRef.current = activeStream;
      const primaryTrack = activeStream.getVideoTracks()[0];
      await refreshAvailableCameras();
      imageCaptureRef.current = primaryTrack
        ? createImageCapture(primaryTrack)
        : null;
      const trackSettings = primaryTrack?.getSettings();
      setDiagnostic(
        [
          primaryTrack?.label ? `Source: ${primaryTrack.label}` : "",
          trackSettings?.width && trackSettings?.height
            ? `${trackSettings.width}x${trackSettings.height}`
            : "",
          imageCaptureRef.current ? "grabFrame enabled" : "video stream mode",
        ]
          .filter(Boolean)
          .join(" / "),
      );

      stepStreakRef.current = 0;
      prevFaceCenterRef.current = null;
      motionAccumulatorRef.current = 0;
      cueAccumulatorRef.current = 0;
      sampleCountRef.current = 0;
      lastBoxRef.current = null;
      centerSnapshotRef.current = null;
      previousFrameRef.current = null;
      noDetectionFramesRef.current = 0;

      setChallenge(nextChallenge);
      setCompletedSteps([]);
      setStepIndex(0);
      setPreviewImage(null);
      setActive(true);
      setCaptureMode("native");
      compatScanProgressRef.current = 0;
      compatAlignedSamplesRef.current = 0;
      setScanProgress(0);
      setStatus("scanning");
      setMessage(
        detector
          ? "Look into the oval frame. The ring will brighten when your face is ready."
          : "Look into the oval frame. Auto scan starts when the ring turns bright.",
      );
    } catch (error) {
      stopCamera();
      setStatus("error");
      setMessage(
        error instanceof Error ? error.message : "Cannot start FaceID scan.",
      );
      setDiagnostic(
        streamRef.current?.getVideoTracks?.()[0]?.label
          ? `Source: ${streamRef.current.getVideoTracks()[0]?.label || ""}`
          : "",
      );
      onChange(null);
    }
  }, [
    createImageCapture,
    disabled,
    ensureDetector,
    loadChallenge,
    onChange,
    processFrame,
    refreshAvailableCameras,
    availableCameras,
    selectedDeviceId,
    stopCamera,
  ]);

  useEffect(() => {
    if (!active || status !== "scanning") return;

    rafRef.current = window.requestAnimationFrame(() => void processFrame());
    return () => {
      if (rafRef.current !== null) {
        window.cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
    };
  }, [active, processFrame, status]);

  const badgeLabel = useMemo(() => {
    if (status === "verified") return "Ready";
    if (status === "scanning") return "Live";
    if (status === "error") return "Retry";
    return "Required";
  }, [status]);

  const shouldShowCameraPicker =
    !active && !disabled && availableCameras.length > 1;
  const visibleProgress = active ? scanProgress : status === "verified" ? 1 : 0;

  const cueStyle = {
    "--faceid-cue": activeCueColor,
    "--faceid-lock-strength": alignmentGlow.toFixed(3),
  } as CSSProperties;

  return (
    <div className={`faceid-card faceid-card-${status}`} style={cueStyle}>
      <div className="faceid-head">
        <div>
          <strong>FaceID Enrollment</strong>
          <p>{message}</p>
          {status === "error" && diagnostic ? (
            <small className="faceid-diagnostic">{diagnostic}</small>
          ) : null}
        </div>
        <span className="faceid-badge">
          {status === "scanning" ? "Auto scan" : badgeLabel}
        </span>
      </div>

      {shouldShowCameraPicker ? (
        <div className="faceid-device-row">
          <label className="faceid-camera-select">
            <span>Camera source</span>
            <select
              value={selectedDeviceId}
              onChange={(event) => setSelectedDeviceId(event.target.value)}
              disabled={active || disabled || availableCameras.length === 0}
            >
              {availableCameras.length === 0 ? (
                <option value="">No camera found</option>
              ) : (
                availableCameras.map((camera) => (
                  <option key={camera.id} value={camera.id}>
                    {camera.label}
                  </option>
                ))
              )}
            </select>
          </label>
          <button
            type="button"
            className="pill"
            disabled={active || disabled}
            onClick={() => void refreshAvailableCameras()}
          >
            Reload cameras
          </button>
        </div>
      ) : null}

      <div className={`faceid-camera ${active ? "active" : ""}`}>
        <div
          className={`faceid-stage ${active ? "is-live" : ""} ${
            faceAligned ? "is-aligned" : ""
          }`}
        >
          <video
            ref={videoRef}
            className="faceid-video"
            playsInline
            muted
            autoPlay
          />
          {active ? (
            <div className="faceid-overlay" aria-hidden="true">
              <div
                className={`faceid-oval ${faceAligned ? "is-aligned" : ""}`}
              />
            </div>
          ) : previewImage ? (
            <img
              src={previewImage}
              alt="Registered face sample"
              className="faceid-preview"
            />
          ) : (
            <div className="faceid-placeholder">
              <span>Live face scan required</span>
              <small>
                Real user only. Printed images and static frames should fail
                liveness.
              </small>
            </div>
          )}
          <canvas
            ref={canvasRef}
            className="faceid-canvas"
            aria-hidden="true"
          />
        </div>
        <small className="muted faceid-camera-help">
          {active
            ? activeStep
              ? `Current step: ${activeStep.label}. Keep your face inside the oval and follow the hint above.`
              : "Keep your face inside the oval. The scan will continue automatically."
            : "Camera preview will appear here after you start scanning."}
        </small>
      </div>

      <div className="faceid-scan-progress" aria-hidden="true">
        <div className="faceid-scan-progress-bar">
          <span style={{ width: `${Math.round(visibleProgress * 100)}%` }} />
        </div>
        <small>
          {status === "verified"
            ? "Scan complete"
            : active
              ? activeStep
                ? `${activeStep.label} • ${Math.round(visibleProgress * 100)}%`
                : `Auto scanning ${Math.round(visibleProgress * 100)}%`
              : "Ready to scan"}
        </small>
      </div>

      <div className="faceid-actions">
        {active ? (
          <button
            type="button"
            className="pill"
            onClick={stopCamera}
            disabled={disabled}
          >
            Stop
          </button>
        ) : (
          <button
            type="button"
            className="pill"
            onClick={startCapture}
            disabled={disabled}
          >
            {status === "verified" ? "Scan again" : "Start scan"}
          </button>
        )}
        {challenge?.expiresAt ? (
          <span className="faceid-expiry">
            Expires{" "}
            {new Date(challenge.expiresAt).toLocaleTimeString("en-US", {
              hour: "2-digit",
              minute: "2-digit",
            })}
          </span>
        ) : null}
      </div>
    </div>
  );
}
