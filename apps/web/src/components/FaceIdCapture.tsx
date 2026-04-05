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
  eyeMotionScore: number;
  faceCoverage: number;
  sampleCount: number;
  completedSteps: FaceIdStepId[];
  stepCaptures: FaceIdStepCapture[];
  previewImage?: string;
  videoEvidence?: string;
  videoDurationMs?: number;
  videoMimeType?: string;
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
  mode?: "enroll" | "verify";
  onChange: (value: FaceIdProof | null) => void;
  onFeedbackChange?: (input: {
    status: "idle" | "loading" | "ready" | "scanning" | "verified" | "error";
    message: string;
  }) => void;
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
  landmarks?: Array<{
    x: number;
    y: number;
  }>;
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
  scanReady: boolean;
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

type RecordedVideoEvidence = {
  dataUrl: string;
  durationMs: number;
  mimeType: string;
};

type EyeMetrics = {
  leftEar: number;
  rightEar: number;
  averageEar: number;
};

const STEP_COLORS: Record<FaceIdStepId, string> = {
  center: "#38bdf8",
  move_left: "#a78bfa",
  move_right: "#22c55e",
  move_closer: "#f59e0b",
};

const PROCESS_INTERVAL_MS = 220;
const MIN_VIDEO_DURATION_MS = 5000;
const MIN_SCAN_DURATION_MS = MIN_VIDEO_DURATION_MS;
const TIMED_CAPTURE_GRACE_MS = 1200;
const REQUIRED_STEP_STREAK = 3;
const COMPAT_REQUIRED_STEP_STREAK = 4;
const MEDIAPIPE_WASM_PATH =
  "https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.32/wasm";
const MEDIAPIPE_FACE_MODEL_PATH =
  "https://storage.googleapis.com/mediapipe-models/face_detector/blaze_face_short_range/float16/1/blaze_face_short_range.tflite";
const MEDIAPIPE_FACE_LANDMARKER_MODEL_PATH =
  "https://storage.googleapis.com/mediapipe-models/face_landmarker/face_landmarker/float16/1/face_landmarker.task";
const FACE_DESCRIPTOR_V2_PREFIX = "faceid_v2:";
const LEFT_EYE_INDICES = [33, 133, 159, 145];
const RIGHT_EYE_INDICES = [362, 263, 386, 374];
const GEOMETRY_INDICES = [33, 133, 362, 263, 1, 61, 291, 13, 14, 152, 10];

const clamp = (value: number, min: number, max: number) =>
  Math.min(Math.max(value, min), max);

const base64FromBytes = (bytes: Uint8Array) => {
  let result = "";
  for (const byte of bytes) {
    result += String.fromCharCode(byte);
  }
  return btoa(result);
};

const blobToDataUrl = (blob: Blob) =>
  new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onloadend = () => {
      if (typeof reader.result === "string") {
        resolve(reader.result);
        return;
      }
      reject(new Error("Cannot encode FaceID verification video."));
    };
    reader.onerror = () => {
      reject(new Error("Cannot encode FaceID verification video."));
    };
    reader.readAsDataURL(blob);
  });

const pickVideoMimeType = () => {
  if (typeof MediaRecorder === "undefined") return "";
  const candidates = [
    "video/webm;codecs=vp9",
    "video/webm;codecs=vp8",
    "video/webm",
    "video/mp4",
  ];
  return (
    candidates.find((mimeType) => MediaRecorder.isTypeSupported(mimeType)) || ""
  );
};

const averagePoint = (
  points: Array<{ x: number; y: number }>,
  indices: number[],
) => {
  let sumX = 0;
  let sumY = 0;
  let count = 0;
  for (const index of indices) {
    const point = points[index];
    if (!point) continue;
    sumX += point.x;
    sumY += point.y;
    count += 1;
  }
  return count ? { x: sumX / count, y: sumY / count } : null;
};

const getEyeAspectRatio = (
  landmarks: Array<{ x: number; y: number }>,
  indices: number[],
) => {
  if (indices.length < 4) return null;
  const outer = landmarks[indices[0]];
  const inner = landmarks[indices[1]];
  const upper = landmarks[indices[2]];
  const lower = landmarks[indices[3]];
  if (!outer || !inner || !upper || !lower) return null;

  const width = Math.hypot(inner.x - outer.x, inner.y - outer.y);
  const height = Math.hypot(lower.x - upper.x, lower.y - upper.y);
  if (!Number.isFinite(width) || !Number.isFinite(height) || width < 1) {
    return null;
  }

  return height / width;
};

const getEyeMetrics = (landmarks?: Array<{ x: number; y: number }>) => {
  if (!landmarks?.length) return null;
  const leftEar = getEyeAspectRatio(landmarks, LEFT_EYE_INDICES);
  const rightEar = getEyeAspectRatio(landmarks, RIGHT_EYE_INDICES);
  if (
    !Number.isFinite(leftEar ?? Number.NaN) ||
    !Number.isFinite(rightEar ?? Number.NaN)
  ) {
    return null;
  }
  return {
    leftEar: leftEar as number,
    rightEar: rightEar as number,
    averageEar: ((leftEar as number) + (rightEar as number)) / 2,
  } satisfies EyeMetrics;
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

const getExpandedFaceCrop = (
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

  return { cropX, cropY, cropWidth, cropHeight };
};

const buildLegacyFaceDescriptor = (
  sourceCanvas: HTMLCanvasElement,
  box: { x: number; y: number; width: number; height: number },
) => {
  const { cropX, cropY, cropWidth, cropHeight } = getExpandedFaceCrop(
    sourceCanvas,
    box,
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

const buildAlignedFaceDescriptor = (
  sourceCanvas: HTMLCanvasElement,
  landmarks: Array<{ x: number; y: number }>,
) => {
  const leftEye = averagePoint(landmarks, LEFT_EYE_INDICES);
  const rightEye = averagePoint(landmarks, RIGHT_EYE_INDICES);
  if (!leftEye || !rightEye) {
    return null;
  }

  const eyeDistance = Math.hypot(
    rightEye.x - leftEye.x,
    rightEye.y - leftEye.y,
  );
  if (!Number.isFinite(eyeDistance) || eyeDistance < 18) {
    return null;
  }

  const eyeAngle = Math.atan2(rightEye.y - leftEye.y, rightEye.x - leftEye.x);
  const eyeMidX = (leftEye.x + rightEye.x) / 2;
  const eyeMidY = (leftEye.y + rightEye.y) / 2;

  const alignedCanvas = document.createElement("canvas");
  alignedCanvas.width = 112;
  alignedCanvas.height = 112;
  const alignedCtx = alignedCanvas.getContext("2d");
  if (!alignedCtx) {
    throw new Error("faceid-canvas-unavailable");
  }
  alignedCtx.fillStyle = "#000";
  alignedCtx.fillRect(0, 0, alignedCanvas.width, alignedCanvas.height);
  alignedCtx.save();
  alignedCtx.translate(alignedCanvas.width / 2, alignedCanvas.height * 0.39);
  const scale = 48 / eyeDistance;
  alignedCtx.scale(scale, scale);
  alignedCtx.rotate(-eyeAngle);
  alignedCtx.translate(-eyeMidX, -eyeMidY);
  alignedCtx.drawImage(sourceCanvas, 0, 0);
  alignedCtx.restore();

  const descriptorCanvas = document.createElement("canvas");
  descriptorCanvas.width = 32;
  descriptorCanvas.height = 32;
  const descriptorCtx = descriptorCanvas.getContext("2d");
  if (!descriptorCtx) {
    throw new Error("faceid-canvas-unavailable");
  }
  descriptorCtx.drawImage(
    alignedCanvas,
    0,
    0,
    alignedCanvas.width,
    alignedCanvas.height,
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
  const grayscale = new Float32Array(
    descriptorCanvas.width * descriptorCanvas.height,
  );
  let luminanceSum = 0;

  for (let index = 0; index < grayscale.length; index += 1) {
    const offset = index * 4;
    const value =
      pixels[offset] * 0.299 +
      pixels[offset + 1] * 0.587 +
      pixels[offset + 2] * 0.114;
    grayscale[index] = value;
    luminanceSum += value;
  }

  const mean = luminanceSum / Math.max(1, grayscale.length);
  let variance = 0;
  for (const value of grayscale) {
    variance += (value - mean) ** 2;
  }
  const deviation = Math.max(
    10,
    Math.sqrt(variance / Math.max(1, grayscale.length)),
  );
  const bytes = new Uint8Array(grayscale.length);
  for (let index = 0; index < grayscale.length; index += 1) {
    const normalized = ((grayscale[index] - mean) / deviation) * 42 + 128;
    bytes[index] = clamp(Math.round(normalized), 0, 255);
  }
  return base64FromBytes(bytes);
};

const buildGeometryDescriptor = (
  landmarks: Array<{ x: number; y: number }>,
) => {
  const leftEye = averagePoint(landmarks, LEFT_EYE_INDICES);
  const rightEye = averagePoint(landmarks, RIGHT_EYE_INDICES);
  if (!leftEye || !rightEye) {
    return null;
  }

  const eyeMidX = (leftEye.x + rightEye.x) / 2;
  const eyeMidY = (leftEye.y + rightEye.y) / 2;
  const eyeDistance = Math.hypot(
    rightEye.x - leftEye.x,
    rightEye.y - leftEye.y,
  );
  if (!Number.isFinite(eyeDistance) || eyeDistance < 18) {
    return null;
  }
  const cos = (rightEye.x - leftEye.x) / eyeDistance;
  const sin = (rightEye.y - leftEye.y) / eyeDistance;
  const bytes = new Uint8Array(GEOMETRY_INDICES.length * 2);

  GEOMETRY_INDICES.forEach((index, pointIndex) => {
    const point = landmarks[index];
    const dx = (point?.x ?? eyeMidX) - eyeMidX;
    const dy = (point?.y ?? eyeMidY) - eyeMidY;
    const alignedX = (dx * cos + dy * sin) / eyeDistance;
    const alignedY = (-dx * sin + dy * cos) / eyeDistance;
    bytes[pointIndex * 2] = clamp(
      Math.round(((alignedX + 1.4) / 2.8) * 255),
      0,
      255,
    );
    bytes[pointIndex * 2 + 1] = clamp(
      Math.round(((alignedY + 1.6) / 3.2) * 255),
      0,
      255,
    );
  });

  return base64FromBytes(bytes);
};

const buildFaceDescriptor = (
  sourceCanvas: HTMLCanvasElement,
  face: DetectedFace,
) => {
  const legacy = buildLegacyFaceDescriptor(sourceCanvas, face.boundingBox);
  if (!face.landmarks?.length) {
    return legacy;
  }

  const aligned = buildAlignedFaceDescriptor(sourceCanvas, face.landmarks);
  const geometry = buildGeometryDescriptor(face.landmarks);
  if (!aligned && !geometry) {
    return legacy;
  }

  return `${FACE_DESCRIPTOR_V2_PREFIX}${btoa(
    JSON.stringify({
      kind: "faceid_v2",
      legacy,
      aligned,
      geometry,
    }),
  )}`;
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
  mode = "enroll",
  onChange,
  onFeedbackChange,
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
  const prevEyeMetricsRef = useRef<EyeMetrics | null>(null);
  const motionAccumulatorRef = useRef(0);
  const eyeMotionAccumulatorRef = useRef(0);
  const eyeMotionPeakRef = useRef(0);
  const cueAccumulatorRef = useRef(0);
  const sampleCountRef = useRef(0);
  const scanStartedAtRef = useRef(0);
  const accumulatedScanMsRef = useRef(0);
  const scanTickStartedAtRef = useRef(0);
  const lostTrackStartedAtRef = useRef(0);
  const lastBoxRef = useRef<DetectedFace["boundingBox"] | null>(null);
  const lastDetectedFaceRef = useRef<DetectedFace | null>(null);
  const stepCaptureRef = useRef<
    Partial<Record<FaceIdStepId, FaceIdStepCapture>>
  >({});
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const recordedChunksRef = useRef<Blob[]>([]);
  const recordingStartedAtRef = useRef(0);
  const recordingAccumulatedMsRef = useRef(0);
  const recordingTickStartedAtRef = useRef(0);
  const recordingStopPromiseRef =
    useRef<Promise<RecordedVideoEvidence | null> | null>(null);
  const capturePhaseRef = useRef<
    "idle" | "scanning" | "finalizing" | "verified"
  >("idle");
  const finalizeRequestedRef = useRef(false);
  const readyFrameStreakRef = useRef(0);
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
    "Record a 5-second face video for this account.",
  );
  const [stepIndex, setStepIndex] = useState(0);
  const [completedSteps, setCompletedSteps] = useState<FaceIdStepId[]>([]);
  const [diagnostic, setDiagnostic] = useState("");
  const [availableCameras, setAvailableCameras] = useState<CameraOption[]>([]);
  const [selectedDeviceId, setSelectedDeviceId] = useState("");
  const [scanProgress, setScanProgress] = useState(0);
  const [faceAligned, setFaceAligned] = useState(false);
  const [alignmentGlow, setAlignmentGlow] = useState(0);
  const isVerifyMode = mode === "verify";

  useEffect(() => {
    onFeedbackChange?.({ status, message });
  }, [message, onFeedbackChange, status]);

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
    const recorder = mediaRecorderRef.current;
    if (recorder && recorder.state !== "inactive") {
      try {
        recorder.stop();
      } catch {
        // ignore recorder shutdown failures during teardown
      }
    }
    imageCaptureRef.current = null;
    if (imageBitmapRef.current) {
      imageBitmapRef.current.close();
      imageBitmapRef.current = null;
    }
    recordingAccumulatedMsRef.current = 0;
    recordingTickStartedAtRef.current = 0;
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
    setActive(false);
  }, []);

  const resetState = useCallback(() => {
    stopCamera();
    setChallenge(null);
    setStatus("idle");
    setMessage(
      isVerifyMode
        ? "Record a 5-second face video before the transfer is approved."
        : "Record a 5-second face video for this account.",
    );
    setStepIndex(0);
    setCompletedSteps([]);
    setDiagnostic("");
    stepStreakRef.current = 0;
    prevFaceCenterRef.current = null;
    prevEyeMetricsRef.current = null;
    motionAccumulatorRef.current = 0;
    eyeMotionAccumulatorRef.current = 0;
    eyeMotionPeakRef.current = 0;
    cueAccumulatorRef.current = 0;
    sampleCountRef.current = 0;
    scanStartedAtRef.current = 0;
    accumulatedScanMsRef.current = 0;
    scanTickStartedAtRef.current = 0;
    lostTrackStartedAtRef.current = 0;
    lastBoxRef.current = null;
    lastDetectedFaceRef.current = null;
    stepCaptureRef.current = {};
    recordedChunksRef.current = [];
    mediaRecorderRef.current = null;
    recordingStartedAtRef.current = 0;
    recordingAccumulatedMsRef.current = 0;
    recordingTickStartedAtRef.current = 0;
    recordingStopPromiseRef.current = null;
    capturePhaseRef.current = "idle";
    finalizeRequestedRef.current = false;
    readyFrameStreakRef.current = 0;
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
  }, [isVerifyMode, onChange, stopCamera]);

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

    detectorLoadRef.current = (async () => {
      try {
        const { FaceDetector, FaceLandmarker, FilesetResolver } =
          await import("@mediapipe/tasks-vision");
        const vision =
          await FilesetResolver.forVisionTasks(MEDIAPIPE_WASM_PATH);
        const landmarker = await FaceLandmarker.createFromOptions(vision, {
          baseOptions: {
            modelAssetPath: MEDIAPIPE_FACE_LANDMARKER_MODEL_PATH,
          },
          runningMode: "VIDEO",
          numFaces: 1,
          minFaceDetectionConfidence: 0.55,
          minFacePresenceConfidence: 0.55,
          minTrackingConfidence: 0.5,
          outputFaceBlendshapes: false,
          outputFacialTransformationMatrixes: false,
        });

        const adapter: DetectorAdapter = {
          detect: async (image) => {
            const result = landmarker.detectForVideo(
              image as TexImageSource,
              performance.now(),
            );
            const faces = (result.faceLandmarks ?? [])
              .map((faceLandmarks): DetectedFace | null => {
                if (!faceLandmarks.length) return null;
                let minX = Number.POSITIVE_INFINITY;
                let minY = Number.POSITIVE_INFINITY;
                let maxX = Number.NEGATIVE_INFINITY;
                let maxY = Number.NEGATIVE_INFINITY;
                const landmarks = faceLandmarks.map((point) => {
                  const x = point.x * (image as HTMLCanvasElement).width;
                  const y = point.y * (image as HTMLCanvasElement).height;
                  minX = Math.min(minX, x);
                  minY = Math.min(minY, y);
                  maxX = Math.max(maxX, x);
                  maxY = Math.max(maxY, y);
                  return { x, y };
                });
                if (!Number.isFinite(minX) || !Number.isFinite(minY)) {
                  return null;
                }
                return {
                  boundingBox: {
                    x: minX,
                    y: minY,
                    width: Math.max(1, maxX - minX),
                    height: Math.max(1, maxY - minY),
                  },
                  landmarks,
                };
              })
              .filter((face): face is DetectedFace => face !== null);
            return faces;
          },
        };

        detectorRef.current = adapter;
        return adapter;
      } catch {
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
            minDetectionConfidence: 0.42,
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
          const ctor = (
            window as Window & { FaceDetector?: BrowserFaceDetectorCtor }
          ).FaceDetector;
          if (!ctor) {
            return null;
          }
          const browserDetector = new ctor({
            fastMode: true,
            maxDetectedFaces: 1,
          });
          const adapter: DetectorAdapter = {
            detect: (image) => browserDetector.detect(image),
          };
          detectorRef.current = adapter;
          return adapter;
        }
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

  const getRemainingScanMs = useCallback(() => {
    if (!scanStartedAtRef.current) return MIN_SCAN_DURATION_MS;
    const elapsedMs =
      accumulatedScanMsRef.current +
      (scanTickStartedAtRef.current
        ? Math.max(0, performance.now() - scanTickStartedAtRef.current)
        : 0);
    return Math.max(0, MIN_SCAN_DURATION_MS - elapsedMs);
  }, []);

  const getTimedScanProgress = useCallback((now: number) => {
    if (!scanStartedAtRef.current) return 0;
    const elapsedMs =
      accumulatedScanMsRef.current +
      (scanTickStartedAtRef.current
        ? Math.max(0, now - scanTickStartedAtRef.current)
        : 0);
    return clamp(elapsedMs / MIN_SCAN_DURATION_MS, 0, 1);
  }, []);

  const pauseVideoRecording = useCallback((now: number) => {
    if (recordingTickStartedAtRef.current) {
      recordingAccumulatedMsRef.current += Math.max(
        0,
        now - recordingTickStartedAtRef.current,
      );
      recordingTickStartedAtRef.current = 0;
    }

    const recorder = mediaRecorderRef.current;
    if (!recorder || recorder.state !== "recording") {
      return;
    }

    if (typeof recorder.pause === "function") {
      try {
        recorder.pause();
      } catch {
        // Keep the live preview running even if recorder pause fails.
      }
    }
  }, []);

  const startVideoRecording = useCallback(
    (stream: MediaStream, now: number) => {
      if (typeof MediaRecorder === "undefined") {
        throw new Error(
          "5-second FaceID video capture is unavailable on this browser. Use the latest Chrome or Edge.",
        );
      }
      const mimeType = pickVideoMimeType();
      const recorderOptions = {
        ...(mimeType ? { mimeType } : {}),
        videoBitsPerSecond: 900_000,
      };
      const recorder = new MediaRecorder(stream, recorderOptions);
      recordedChunksRef.current = [];
      recordingStartedAtRef.current = now;
      recordingAccumulatedMsRef.current = 0;
      recordingTickStartedAtRef.current = now;
      const stopPromise = new Promise<RecordedVideoEvidence | null>(
        (resolve) => {
          recorder.ondataavailable = (event) => {
            if (event.data && event.data.size > 0) {
              recordedChunksRef.current.push(event.data);
            }
          };
          recorder.onerror = () => {
            resolve(null);
          };
          recorder.onstop = () => {
            const elapsedMs =
              recordingAccumulatedMsRef.current +
              (recordingTickStartedAtRef.current
                ? Math.max(
                    0,
                    performance.now() - recordingTickStartedAtRef.current,
                  )
                : 0);
            const chunks = recordedChunksRef.current.slice();
            recordedChunksRef.current = [];
            mediaRecorderRef.current = null;
            recordingAccumulatedMsRef.current = 0;
            recordingTickStartedAtRef.current = 0;
            if (!chunks.length) {
              resolve(null);
              return;
            }
            const blob = new Blob(chunks, {
              type: recorder.mimeType || mimeType || "video/webm",
            });
            void blobToDataUrl(blob)
              .then((dataUrl) =>
                resolve({
                  dataUrl,
                  durationMs: elapsedMs,
                  mimeType:
                    blob.type || recorder.mimeType || mimeType || "video/webm",
                }),
              )
              .catch(() => resolve(null));
          };
        },
      );

      mediaRecorderRef.current = recorder;
      recordingStopPromiseRef.current = stopPromise;
      recorder.start(250);
    },
    [],
  );

  const resumeVideoRecording = useCallback(
    (now: number) => {
      const stream = streamRef.current;
      if (!stream) {
        return;
      }

      const recorder = mediaRecorderRef.current;
      if (!recorder) {
        startVideoRecording(stream, now);
        return;
      }

      if (recorder.state === "paused") {
        try {
          recorder.resume();
        } catch {
          return;
        }
      }

      if (
        recorder.state === "recording" &&
        !recordingTickStartedAtRef.current
      ) {
        recordingTickStartedAtRef.current = now;
      }
    },
    [startVideoRecording],
  );

  const discardVideoRecording = useCallback(() => {
    recordingAccumulatedMsRef.current = 0;
    recordingTickStartedAtRef.current = 0;
    recordingStartedAtRef.current = 0;
    recordedChunksRef.current = [];
    recordingStopPromiseRef.current = null;
    const recorder = mediaRecorderRef.current;
    if (!recorder || recorder.state === "inactive") {
      mediaRecorderRef.current = null;
      return;
    }

    recorder.ondataavailable = null;
    recorder.onerror = null;
    recorder.onstop = null;
    mediaRecorderRef.current = null;
    try {
      recorder.stop();
    } catch {
      // Ignore recorder teardown failures while restarting a scan.
    }
  }, []);

  const pauseTimedCapture = useCallback(
    (now: number) => {
      if (scanTickStartedAtRef.current) {
        accumulatedScanMsRef.current += Math.max(
          0,
          now - scanTickStartedAtRef.current,
        );
        scanTickStartedAtRef.current = 0;
      }
      pauseVideoRecording(now);
      if (!lostTrackStartedAtRef.current) {
        lostTrackStartedAtRef.current = now;
      }
    },
    [pauseVideoRecording],
  );

  const resumeTimedCapture = useCallback(
    (now: number) => {
      if (!scanStartedAtRef.current) {
        scanStartedAtRef.current = now;
        accumulatedScanMsRef.current = 0;
      }
      if (!scanTickStartedAtRef.current) {
        scanTickStartedAtRef.current = now;
      }
      lostTrackStartedAtRef.current = 0;
      resumeVideoRecording(now);
    },
    [resumeVideoRecording],
  );

  const resetTimedCaptureProgress = useCallback(() => {
    scanStartedAtRef.current = 0;
    accumulatedScanMsRef.current = 0;
    scanTickStartedAtRef.current = 0;
    lostTrackStartedAtRef.current = 0;
    readyFrameStreakRef.current = 0;
    centerSnapshotRef.current = null;
    setScanProgress(0);
    setFaceAligned(false);
    setAlignmentGlow(0);
    discardVideoRecording();
  }, [discardVideoRecording]);

  const finalizeVideoRecording = useCallback(async () => {
    const recorder = mediaRecorderRef.current;
    const stopPromise = recordingStopPromiseRef.current;
    if (!recorder || !stopPromise) {
      throw new Error("FaceID 5-second video is missing. Please scan again.");
    }
    if (recordingTickStartedAtRef.current) {
      recordingAccumulatedMsRef.current += Math.max(
        0,
        performance.now() - recordingTickStartedAtRef.current,
      );
      recordingTickStartedAtRef.current = 0;
    }
    if (recorder.state !== "inactive") {
      recorder.stop();
    }
    const videoEvidence = await stopPromise;
    recordingStopPromiseRef.current = null;
    if (!videoEvidence || !videoEvidence.dataUrl.startsWith("data:video/")) {
      throw new Error(
        "FaceID video evidence could not be recorded. Please try again.",
      );
    }
    if (videoEvidence.durationMs < MIN_VIDEO_DURATION_MS - 250) {
      throw new Error(
        "Keep recording for the full 5 seconds before finishing FaceID.",
      );
    }
    return videoEvidence;
  }, []);

  const finalizeProof = useCallback(
    async (resolvedSteps: FaceIdStepId[]) => {
      if (capturePhaseRef.current !== "scanning") {
        return;
      }
      capturePhaseRef.current = "finalizing";
      finalizeRequestedRef.current = true;
      const canvas = canvasRef.current;
      const box = lastBoxRef.current;
      if (!canvas || !box || !challenge) {
        capturePhaseRef.current = "idle";
        setStatus("error");
        setMessage("Face sample was incomplete. Please scan again.");
        onChange(null);
        return;
      }

      try {
        const remainingScanMs = getRemainingScanMs();
        if (remainingScanMs > 0) {
          throw new Error(
            `Face scan is still stabilizing. Hold steady for ${Math.ceil(
              remainingScanMs / 1000,
            )}s more.`,
          );
        }
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
        const descriptor = buildFaceDescriptor(canvas, {
          boundingBox: box,
          landmarks: lastDetectedFaceRef.current?.landmarks,
        });
        const completedRatio =
          challenge.steps.length > 0
            ? resolvedSteps.length / challenge.steps.length
            : 0;
        const motionScore = clamp(motionAccumulatorRef.current / 0.45, 0, 1);
        const eyeMotionScore = clamp(
          Math.max(
            eyeMotionAccumulatorRef.current / 0.1,
            eyeMotionPeakRef.current / 0.02,
          ),
          0,
          1,
        );
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
          completedRatio * 0.35 +
            motionScore * 0.25 +
            eyeMotionScore * 0.25 +
            cueScore * 0.15,
          0,
          1,
        );
        const preview =
          orderedStepCaptures[0]?.image || canvas.toDataURL("image/jpeg", 0.78);
        const videoEvidence = await finalizeVideoRecording();

        const proof: FaceIdProof = {
          challengeToken: challenge.challengeToken,
          descriptor,
          livenessScore,
          motionScore,
          eyeMotionScore,
          faceCoverage,
          sampleCount: sampleCountRef.current,
          completedSteps: resolvedSteps,
          stepCaptures: orderedStepCaptures,
          previewImage: preview,
          videoEvidence: videoEvidence.dataUrl,
          videoDurationMs: Math.round(videoEvidence.durationMs),
          videoMimeType: videoEvidence.mimeType,
        };

        setScanProgress(1);
        capturePhaseRef.current = "verified";
        setStatus("verified");
        setMessage(
          isVerifyMode
            ? "5-second FaceID video verification is ready for this transfer."
            : "5-second FaceID video captured. This biometric sample is now linked to the account.",
        );
        setDiagnostic("");
        onChange(proof);
        stopCamera();
      } catch (error) {
        capturePhaseRef.current = "idle";
        finalizeRequestedRef.current = false;
        setStatus("error");
        setMessage(
          error instanceof Error ? error.message : "FaceID capture failed.",
        );
        onChange(null);
      }
    },
    [
      challenge,
      finalizeVideoRecording,
      getRemainingScanMs,
      isVerifyMode,
      onChange,
      stopCamera,
    ],
  );

  const renderCurrentFrameToCanvas = useCallback(async () => {
    const canvas = canvasRef.current;
    const video = videoRef.current;
    if (!canvas) {
      throw new Error("Camera canvas is not ready.");
    }

    const ctx = canvas.getContext("2d", { willReadFrequently: true });
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
      const horizontalScore = clamp(1 - Math.abs(deltaX) / 0.18, 0, 1);
      const verticalScore = clamp(1 - Math.abs(deltaY) / 0.19, 0, 1);
      const sizeScore = clamp(1 - Math.abs(1 - sizeRatio) / 0.82, 0, 1);
      const framePaddingX = targetBox.width * 0.12;
      const framePaddingY = targetBox.height * 0.12;
      const withinScanWindow =
        box.x >= targetBox.x - framePaddingX &&
        box.y >= targetBox.y - framePaddingY &&
        box.x + box.width <= targetBox.x + targetBox.width + framePaddingX &&
        box.y + box.height <= targetBox.y + targetBox.height + framePaddingY;
      const glow = clamp(
        horizontalScore * 0.35 + verticalScore * 0.35 + sizeScore * 0.3,
        0,
        1,
      );
      const aligned =
        withinScanWindow &&
        sizeRatio >= 0.46 &&
        sizeRatio <= 1.38 &&
        Math.abs(deltaX) <= 0.16 &&
        Math.abs(deltaY) <= 0.17;
      const scanReady =
        withinScanWindow &&
        sizeRatio >= 0.54 &&
        sizeRatio <= 1.2 &&
        Math.abs(deltaX) <= 0.125 &&
        Math.abs(deltaY) <= 0.13;

      return {
        centerX,
        centerY,
        coverage,
        deltaX,
        deltaY,
        sizeRatio,
        glow,
        aligned,
        scanReady,
      };
    },
    [getCompatibilityBox],
  );

  const isReadyToStartTimedCapture = useCallback(
    (alignment: AlignmentSnapshot, motionMetric: number) =>
      alignment.scanReady &&
      alignment.coverage >= 0.085 &&
      motionMetric <= 0.16,
    [],
  );

  const canContinueTimedCapture = useCallback(
    (alignment: AlignmentSnapshot, motionMetric: number) =>
      alignment.aligned && alignment.coverage >= 0.072 && motionMetric <= 0.24,
    [],
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
          alignment.scanReady &&
          alignment.coverage >= 0.085 &&
          motionMetric <= 0.16;
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
          alignment.coverage >= Math.max(baseline.coverage * 1.08, 0.12) &&
          Math.abs(alignment.deltaX) <= 0.18 &&
          Math.abs(alignment.deltaY) <= 0.19 &&
          motionMetric >= 0.005,
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
        const remainingScanMs = getRemainingScanMs();
        setMessage(
          remainingScanMs > 0
            ? `Hold steady for ${Math.ceil(
                remainingScanMs / 1000,
              )}s to finish FaceID verification.`
            : "Finalizing FaceID verification...",
        );
        window.setTimeout(
          () => void finalizeProof(nextCompletedSteps),
          Math.max(420, remainingScanMs),
        );
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
      getRemainingScanMs,
      stepIndex,
    ],
  );

  const evaluateCompatibilityStep = useCallback(
    (box: DetectedFace["boundingBox"], motionMetric: number) => {
      if (!activeStep) return;

      const matched =
        activeStep.id === "center"
          ? sampleCountRef.current >= 3 && motionMetric >= 0.006
          : motionMetric >= (activeStep.id === "move_closer" ? 0.045 : 0.03);

      stepStreakRef.current = matched ? stepStreakRef.current + 1 : 0;
      if (stepStreakRef.current < COMPAT_REQUIRED_STEP_STREAK) {
        return;
      }

      stepStreakRef.current = 0;
      lastBoxRef.current = box;
      lastDetectedFaceRef.current = {
        boundingBox: box,
      };
      const nextCompletedSteps = completedSteps.includes(activeStep.id)
        ? completedSteps
        : [...completedSteps, activeStep.id];
      setCompletedSteps(nextCompletedSteps);

      if (stepIndex + 1 >= (challenge?.steps.length ?? 0)) {
        const remainingScanMs = getRemainingScanMs();
        setMessage(
          remainingScanMs > 0
            ? `Keep still for ${Math.ceil(
                remainingScanMs / 1000,
              )}s so the FaceID scan can stabilize.`
            : "Finalizing FaceID verification...",
        );
        window.setTimeout(
          () => void finalizeProof(nextCompletedSteps),
          Math.max(520, remainingScanMs),
        );
        return;
      }

      setStepIndex((current) => current + 1);
      setMessage(
        `Compatibility mode: ${challenge?.steps[stepIndex + 1]?.label || "Continue the live scan."}`,
      );
    },
    [
      activeStep,
      challenge?.steps,
      completedSteps,
      finalizeProof,
      getRemainingScanMs,
      stepIndex,
    ],
  );

  const processFrame = useCallback(async () => {
    const video = videoRef.current;
    const canvas = canvasRef.current;
    if (!canvas || !active || capturePhaseRef.current !== "scanning") return;
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

    const ctx = canvas.getContext("2d", { willReadFrequently: true });
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
          lastDetectedFaceRef.current = null;
          prevEyeMetricsRef.current = null;
          if (scanStartedAtRef.current > 0) {
            pauseTimedCapture(now);
            const pausedProgress = getTimedScanProgress(now);
            const pausedTooLong =
              lostTrackStartedAtRef.current > 0 &&
              now - lostTrackStartedAtRef.current >= TIMED_CAPTURE_GRACE_MS;
            if (pausedTooLong) {
              resetTimedCaptureProgress();
              setMessage(
                "Your face stayed outside the oval too long. Bring it back into the frame to restart the 5-second recording.",
              );
            } else {
              setFaceAligned(false);
              setAlignmentGlow(0);
              setScanProgress(pausedProgress);
              setMessage(
                "Keep your face inside the oval to continue recording.",
              );
            }
          } else {
            setFaceAligned(false);
            setAlignmentGlow(0);
            setScanProgress(0);
            setMessage(
              noDetectionFramesRef.current > 8
                ? "Face not recognized yet. Keep your full face inside the oval."
                : "Scanning camera feed...",
            );
          }
          rafRef.current = window.requestAnimationFrame(
            () => void processFrame(),
          );
          return;
        }
        noDetectionFramesRef.current = 0;

        const detectedFace = faces[0];
        const box = detectedFace.boundingBox;
        lastBoxRef.current = box;
        lastDetectedFaceRef.current = detectedFace;
        const alignment = getAlignmentSnapshot(box, canvas);
        const totalSteps = challenge?.steps.length ?? 0;
        let alignmentMessage = "Face aligned. Scanning now.";

        if (alignment.sizeRatio < 0.58) {
          alignmentMessage = "Move closer until your face fits the oval.";
        } else if (alignment.sizeRatio > 1.12) {
          alignmentMessage = "Move a little back so your full face fits.";
        } else if (alignment.deltaX < -0.09) {
          alignmentMessage = "Move slightly to the right.";
        } else if (alignment.deltaX > 0.09) {
          alignmentMessage = "Move slightly to the left.";
        } else if (alignment.deltaY < -0.1) {
          alignmentMessage = "Lower your face into the oval.";
        } else if (alignment.deltaY > 0.1) {
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

        const eyeMetrics = getEyeMetrics(detectedFace.landmarks);
        if (eyeMetrics && prevEyeMetricsRef.current) {
          const eyeDelta =
            Math.abs(
              eyeMetrics.averageEar - prevEyeMetricsRef.current.averageEar,
            ) +
            Math.abs(eyeMetrics.leftEar - prevEyeMetricsRef.current.leftEar) *
              0.7 +
            Math.abs(eyeMetrics.rightEar - prevEyeMetricsRef.current.rightEar) *
              0.7;
          eyeMotionAccumulatorRef.current += Math.min(0.05, eyeDelta * 1.8);
          eyeMotionPeakRef.current = Math.max(
            eyeMotionPeakRef.current,
            eyeDelta,
          );
        }
        prevEyeMetricsRef.current = eyeMetrics;

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
        const readyToStartTimedCapture = isReadyToStartTimedCapture(
          alignment,
          motionMetric,
        );
        const canContinueCapture = canContinueTimedCapture(
          alignment,
          motionMetric,
        );
        readyFrameStreakRef.current = readyToStartTimedCapture
          ? Math.min(readyFrameStreakRef.current + 1, 12)
          : 0;
        if (
          !scanStartedAtRef.current &&
          readyToStartTimedCapture &&
          readyFrameStreakRef.current >= 2
        ) {
          resumeTimedCapture(now);
        }
        const timedProgress = scanStartedAtRef.current
          ? getTimedScanProgress(now)
          : 0;
        if (
          scanStartedAtRef.current > 0 &&
          !canContinueCapture &&
          !finalizeRequestedRef.current
        ) {
          pauseTimedCapture(now);
          const pausedProgress = getTimedScanProgress(now);
          const pausedTooLong =
            lostTrackStartedAtRef.current > 0 &&
            now - lostTrackStartedAtRef.current >= TIMED_CAPTURE_GRACE_MS;
          if (pausedTooLong) {
            resetTimedCaptureProgress();
            setMessage(
              "Your face moved out of the oval for too long. Hold it inside the frame to restart recording.",
            );
          } else {
            setFaceAligned(false);
            setAlignmentGlow(Math.max(alignment.glow * 0.35, 0.12));
            setScanProgress(pausedProgress);
            setMessage("Hold your face inside the oval to continue recording.");
          }
          rafRef.current = window.requestAnimationFrame(
            () => void processFrame(),
          );
          return;
        }
        if (canContinueCapture && scanStartedAtRef.current > 0) {
          resumeTimedCapture(now);
        }
        setScanProgress(timedProgress);
        setFaceAligned(
          canContinueCapture ||
            stepMatched ||
            (activeStep?.id === "center" && alignment.scanReady),
        );
        setAlignmentGlow(
          canContinueCapture
            ? Math.max(alignment.glow, 0.92)
            : stepMatched
              ? Math.max(alignment.glow, 0.84)
              : activeStep?.id === "center" && alignment.aligned
                ? Math.max(alignment.glow, 0.6)
                : alignment.glow * 0.62,
        );
        if (!scanStartedAtRef.current && !readyToStartTimedCapture) {
          setMessage(
            `${alignmentMessage} Hold still for a moment to start recording.`,
          );
        } else if (!stepMatched) {
          setMessage(alignmentMessage);
        }
        const currentChallenge = challenge;
        const isCenterOnlyChallenge =
          currentChallenge?.steps.length === 1 &&
          currentChallenge.steps[0]?.id === "center";
        if (
          isCenterOnlyChallenge &&
          scanStartedAtRef.current &&
          timedProgress >= 1 &&
          canContinueCapture &&
          !finalizeRequestedRef.current
        ) {
          finalizeRequestedRef.current = true;
          centerSnapshotRef.current = {
            centerX: alignment.centerX,
            centerY: alignment.centerY,
            coverage: alignment.coverage,
          };
          captureStepEvidence("center", alignment, motionMetric);
          const resolvedSteps: FaceIdStepId[] = ["center"];
          setCompletedSteps(resolvedSteps);
          setMessage("Finalizing FaceID verification...");
          window.setTimeout(() => void finalizeProof(resolvedSteps), 120);
          return;
        }
      } else {
        prevEyeMetricsRef.current = null;
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
        const requiredCompatSamples = Math.max(36, totalSteps * 12, 1);
        const frameHasSignal =
          presenceScore >= 0.005 ||
          motionMetric >= 0.002 ||
          sampleCountRef.current > 3;
        if (frameHasSignal) {
          resumeTimedCapture(now);
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
          pauseTimedCapture(now);
          setFaceAligned(false);
          setAlignmentGlow(0.12);
        }

        const progressRatio = clamp(compatScanProgressRef.current, 0, 1);
        setScanProgress(
          scanStartedAtRef.current ? getTimedScanProgress(now) : 0,
        );

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
            const remainingScanMs = getRemainingScanMs();
            const resolvedSteps = challenge.steps.map((step) => step.id);
            setMessage(
              remainingScanMs > 0
                ? `Keep still for ${Math.ceil(
                    remainingScanMs / 1000,
                  )}s so the FaceID scan can stabilize.`
                : "Finalizing FaceID verification...",
            );
            window.setTimeout(
              () => void finalizeProof(resolvedSteps),
              Math.max(520, remainingScanMs),
            );
            return;
          }
        } else {
          evaluateCompatibilityStep(box, motionMetric);
        }
      }
    } catch (error) {
      if (capturePhaseRef.current !== "scanning") {
        return;
      }
      capturePhaseRef.current = "idle";
      setStatus("error");
      setMessage(
        error instanceof Error ? error.message : "FaceID scan failed.",
      );
      onChange(null);
      stopCamera();
      return;
    }

    if (capturePhaseRef.current === "scanning") {
      rafRef.current = window.requestAnimationFrame(() => void processFrame());
    }
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
    getTimedScanProgress,
    canContinueTimedCapture,
    isReadyToStartTimedCapture,
    onChange,
    pauseTimedCapture,
    resetTimedCaptureProgress,
    resumeTimedCapture,
    stopCamera,
  ]);

  const startCapture = useCallback(async () => {
    if (disabled) return;
    setStatus("loading");
    setMessage(
      "Starting camera and preparing your 5-second face verification...",
    );
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
      prevEyeMetricsRef.current = null;
      motionAccumulatorRef.current = 0;
      eyeMotionAccumulatorRef.current = 0;
      eyeMotionPeakRef.current = 0;
      cueAccumulatorRef.current = 0;
      sampleCountRef.current = 0;
      scanStartedAtRef.current = 0;
      accumulatedScanMsRef.current = 0;
      scanTickStartedAtRef.current = 0;
      lostTrackStartedAtRef.current = 0;
      lastBoxRef.current = null;
      lastDetectedFaceRef.current = null;
      centerSnapshotRef.current = null;
      previousFrameRef.current = null;
      noDetectionFramesRef.current = 0;
      finalizeRequestedRef.current = false;
      readyFrameStreakRef.current = 0;

      setChallenge(nextChallenge);
      setCompletedSteps([]);
      setStepIndex(0);
      setActive(true);
      setCaptureMode("native");
      capturePhaseRef.current = "scanning";
      compatScanProgressRef.current = 0;
      compatAlignedSamplesRef.current = 0;
      setScanProgress(0);
      setStatus("scanning");
      setMessage(
        detector
          ? "Look into the oval frame and keep recording for 5 seconds. The ring will brighten when your face is ready."
          : "Look into the oval frame and keep recording for 5 seconds. Auto scan starts when the ring turns bright.",
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

  const statusCopy = useMemo(() => {
    if (status === "verified") {
      return isVerifyMode
        ? "5-second FaceID video verified. Review the preview, then continue."
        : "5-second FaceID enrollment video captured and ready to bind.";
    }
    if (status === "error") {
      return "The scan was interrupted. Keep the frame steady and try the 5-second capture again.";
    }
    if (status === "scanning") {
      return isVerifyMode
        ? "Keep your face inside the frame while the 5-second verification video records."
        : "Keep your face inside the frame while the 5-second enrollment video records.";
    }
    if (status === "loading") {
      return "Camera is starting. Hold steady and get ready for the 5-second capture.";
    }
    return isVerifyMode
      ? "Record a 5-second face video before the transfer is approved."
      : "Record a 5-second face video for this account.";
  }, [isVerifyMode, status]);

  const shouldShowCameraPicker = availableCameras.length > 1;
  const visibleProgress = active ? scanProgress : status === "verified" ? 1 : 0;
  const visibleProgressSeconds = (
    (Math.min(visibleProgress, 1) * MIN_SCAN_DURATION_MS) /
    1000
  ).toFixed(1);
  const cueStyle = {
    "--faceid-cue": activeCueColor,
    "--faceid-lock-strength": alignmentGlow.toFixed(3),
  } as CSSProperties;

  return (
    <div className={`faceid-card faceid-card-${status}`} style={cueStyle}>
      {status === "error" && diagnostic ? (
        <small className="faceid-diagnostic">{diagnostic}</small>
      ) : null}

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
          ) : (
            <div className="faceid-placeholder">
              <span>
                {status === "verified"
                  ? "5-second video captured"
                  : "5-second face video required"}
              </span>
              <small>
                {status === "verified"
                  ? "FaceID is ready to submit. You can update the wallet now or record again."
                  : "Center your face inside the oval and let the 5-second recording complete."}
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
              : "Keep your face inside the oval until the 5-second recording finishes automatically."
            : isVerifyMode
              ? status === "verified"
                ? "FaceID verification is complete and ready to submit."
                : "The scan area will switch to verification-ready state after recording."
              : status === "verified"
                ? "FaceID enrollment is complete and ready to update."
                : "The scan area will switch to ready state after recording."}
        </small>
      </div>

      <div className="faceid-feedback-panel">
        <div className="faceid-live-hint" aria-live="polite">
          {message}
        </div>

        <div className="faceid-scan-progress" aria-hidden="true">
          <div className="faceid-progress-top">
            <span>
              {status === "verified"
                ? "Capture complete"
                : active
                  ? "Recording in progress"
                  : "Awaiting capture"}
            </span>
            <strong>
              {status === "verified"
                ? "5.0s"
                : active
                  ? `${visibleProgressSeconds}s`
                  : "0.0s"}
            </strong>
          </div>
          <div className="faceid-scan-progress-bar">
            <span style={{ width: `${Math.round(visibleProgress * 100)}%` }} />
          </div>
          <small>
            {status === "verified"
              ? "5-second video complete"
              : active
                ? `Recording ${visibleProgressSeconds}s / ${(MIN_SCAN_DURATION_MS / 1000).toFixed(1)}s`
                : "Ready to record"}
          </small>
        </div>
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
            {status === "verified" ? "Capture again" : "Start capture"}
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
