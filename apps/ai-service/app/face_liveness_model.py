import base64
import io
import math
from typing import Literal

import numpy as np
from PIL import Image
from pydantic import AliasChoices, BaseModel, Field

FaceStep = Literal["center", "move_left", "move_right", "move_closer"]

MIN_SHARPNESS = 0.0008
MIN_DYNAMIC_RANGE = 0.09
MIN_ENTROPY = 1.0
MAX_DOMINANT_BIN_RATIO = 0.3
MAX_CLIP_RATIO = 0.34
MIN_MEAN_STEP_DELTA = 0.02
MIN_STEP_DELTA = 0.012
MIN_MOTION_SCORE = 0.28
MIN_LIVENESS_SCORE = 0.72
MIN_FACE_COVERAGE = 0.13
MIN_SAMPLE_COUNT = 20
MAX_SPOOF_SCORE_TO_PASS = 0.68
MIN_CONFIDENCE_TO_PASS = 0.34
MIN_FACE_PARALLAX_SCORE = 0.008
MIN_FACE_BACKGROUND_SEPARATION = 0.004


class FaceLivenessStepCapture(BaseModel):
    step: FaceStep
    image: str
    center_x: float = Field(validation_alias=AliasChoices("center_x", "centerX"))
    center_y: float = Field(validation_alias=AliasChoices("center_y", "centerY"))
    coverage: float
    motion: float
    aligned: bool | None = None


class FaceLivenessRequest(BaseModel):
    preview_image: str = Field(validation_alias=AliasChoices("preview_image", "previewImage"))
    step_captures: list[FaceLivenessStepCapture] = Field(
        default_factory=list,
        validation_alias=AliasChoices("step_captures", "stepCaptures"),
    )
    liveness_score: float = Field(validation_alias=AliasChoices("liveness_score", "livenessScore"))
    motion_score: float = Field(validation_alias=AliasChoices("motion_score", "motionScore"))
    face_coverage: float = Field(validation_alias=AliasChoices("face_coverage", "faceCoverage"))
    sample_count: int = Field(validation_alias=AliasChoices("sample_count", "sampleCount"))
    completed_steps: list[FaceStep] = Field(
        default_factory=list,
        validation_alias=AliasChoices("completed_steps", "completedSteps"),
    )


def _clamp(value: float, minimum: float = 0.0, maximum: float = 1.0) -> float:
    return float(min(maximum, max(minimum, value)))


def _decode_data_url_image(image_data: str) -> Image.Image:
    if not isinstance(image_data, str) or "," not in image_data:
        raise ValueError("invalid_image")
    _, payload = image_data.split(",", 1)
    raw = base64.b64decode(payload)
    image = Image.open(io.BytesIO(raw)).convert("RGB")
    return image


def _gray_matrix(image: Image.Image, size: tuple[int, int] = (160, 160)) -> np.ndarray:
    resized = image.resize(size, Image.Resampling.BILINEAR)
    rgb = np.asarray(resized, dtype=np.float32) / 255.0
    return rgb[..., 0] * 0.299 + rgb[..., 1] * 0.587 + rgb[..., 2] * 0.114


def _laplacian_variance(gray: np.ndarray) -> float:
    padded = np.pad(gray, 1, mode="reflect")
    laplacian = (
        padded[:-2, 1:-1]
        + padded[2:, 1:-1]
        + padded[1:-1, :-2]
        + padded[1:-1, 2:]
        - 4.0 * gray
    )
    return float(np.var(laplacian))


def _entropy(gray: np.ndarray) -> float:
    histogram, _ = np.histogram(gray, bins=32, range=(0.0, 1.0), density=True)
    histogram = histogram[histogram > 0]
    if histogram.size == 0:
        return 0.0
    return float(-(histogram * np.log2(histogram)).sum())


def _edge_density(gray: np.ndarray) -> float:
    grad_x = np.abs(gray[:, 1:] - gray[:, :-1])
    grad_y = np.abs(gray[1:, :] - gray[:-1, :])
    density = (
        float(np.mean(grad_x > 0.08)) + float(np.mean(grad_y > 0.08))
    ) / 2.0
    return density


def _dynamic_range(gray: np.ndarray) -> float:
    low = float(np.percentile(gray, 5))
    high = float(np.percentile(gray, 95))
    return max(high - low, 0.0)


def _dominant_bin_ratio(gray: np.ndarray) -> float:
    histogram, _ = np.histogram(gray, bins=24, range=(0.0, 1.0))
    total = int(histogram.sum())
    if total <= 0:
        return 1.0
    return float(histogram.max() / total)


def _screen_pattern_score(gray: np.ndarray) -> float:
    spectrum = np.abs(np.fft.fftshift(np.fft.fft2(gray - float(gray.mean()))))
    if spectrum.size == 0:
        return 0.0
    height, width = spectrum.shape
    y, x = np.ogrid[:height, :width]
    center_y = height / 2.0
    center_x = width / 2.0
    radius = np.sqrt((x - center_x) ** 2 + (y - center_y) ** 2)
    radius /= max(math.sqrt(center_x**2 + center_y**2), 1.0)
    band = spectrum[(radius >= 0.18) & (radius <= 0.48)]
    if band.size < 16:
        return 0.0
    mean_energy = float(np.mean(band)) + 1e-6
    peak_energy = float(np.percentile(band, 99.7))
    return _clamp((peak_energy / mean_energy - 8.0) / 20.0)


def _frame_delta(left: Image.Image, right: Image.Image) -> float:
    gray_left = _gray_matrix(left, size=(96, 96))
    gray_right = _gray_matrix(right, size=(96, 96))
    return float(np.mean(np.abs(gray_left - gray_right)))


def _estimate_face_box(
    capture: FaceLivenessStepCapture,
    shape: tuple[int, int],
) -> tuple[int, int, int, int]:
    height, width = shape
    total_area = max(width * height, 1)
    face_area = _clamp(capture.coverage, 0.04, 0.72) * total_area
    aspect = 0.78
    face_width = max(18, min(width - 2, int(round(math.sqrt(face_area * aspect)))))
    face_height = max(24, min(height - 2, int(round(face_area / max(face_width, 1)))))
    center_x = int(round(_clamp(capture.center_x, 0.0, 1.0) * width))
    center_y = int(round(_clamp(capture.center_y, 0.0, 1.0) * height))
    x0 = max(0, min(width - face_width, center_x - face_width // 2))
    y0 = max(0, min(height - face_height, center_y - face_height // 2))
    return x0, y0, face_width, face_height


def _build_face_and_background_masks(
    shape: tuple[int, int],
    capture: FaceLivenessStepCapture,
) -> tuple[np.ndarray, np.ndarray]:
    height, width = shape
    x0, y0, face_width, face_height = _estimate_face_box(capture, shape)
    face_mask = np.zeros((height, width), dtype=bool)
    face_mask[y0 : y0 + face_height, x0 : x0 + face_width] = True

    ring_scale = 1.65
    ring_width = min(
        width,
        max(face_width + 12, int(round(face_width * ring_scale))),
    )
    ring_height = min(
        height,
        max(face_height + 12, int(round(face_height * ring_scale))),
    )
    ring_x0 = max(0, min(width - ring_width, x0 + face_width // 2 - ring_width // 2))
    ring_y0 = max(0, min(height - ring_height, y0 + face_height // 2 - ring_height // 2))

    background_mask = np.zeros((height, width), dtype=bool)
    background_mask[ring_y0 : ring_y0 + ring_height, ring_x0 : ring_x0 + ring_width] = True
    background_mask &= ~face_mask
    return face_mask, background_mask


def _masked_delta(
    gray_left: np.ndarray,
    gray_right: np.ndarray,
    mask: np.ndarray,
) -> float:
    if mask.shape != gray_left.shape or mask.shape != gray_right.shape:
        return 0.0
    if not np.any(mask):
        return 0.0
    return float(np.mean(np.abs(gray_left[mask] - gray_right[mask])))


def _depth_signal_score(
    center_image: Image.Image,
    center_capture: FaceLivenessStepCapture,
    closer_image: Image.Image,
    closer_capture: FaceLivenessStepCapture,
) -> dict[str, float]:
    gray_center = _gray_matrix(center_image, size=(128, 128))
    gray_closer = _gray_matrix(closer_image, size=(128, 128))
    face_mask, background_mask = _build_face_and_background_masks(
        gray_center.shape,
        center_capture,
    )

    face_delta = _masked_delta(gray_center, gray_closer, face_mask)
    background_delta = _masked_delta(gray_center, gray_closer, background_mask)
    coverage_gain = max(closer_capture.coverage - center_capture.coverage, 0.0)
    parallax_score = max(face_delta - background_delta, 0.0) + coverage_gain * 0.22
    rigidity_score = max(background_delta - face_delta, 0.0)

    return {
        "face_delta": face_delta,
        "background_delta": background_delta,
        "coverage_gain": coverage_gain,
        "parallax_score": parallax_score,
        "rigidity_score": rigidity_score,
    }


def _extract_preview_features(image: Image.Image) -> dict[str, float]:
    gray = _gray_matrix(image)
    return {
        "sharpness": _laplacian_variance(gray),
        "entropy": _entropy(gray),
        "edge_density": _edge_density(gray),
        "dynamic_range": _dynamic_range(gray),
        "dominant_bin_ratio": _dominant_bin_ratio(gray),
        "screen_pattern_score": _screen_pattern_score(gray),
        "brightness_std": float(np.std(gray)),
        "clip_ratio": float(np.mean((gray <= 0.02) | (gray >= 0.98))),
    }


def _telemetry_findings(step_map: dict[FaceStep, FaceLivenessStepCapture]) -> list[str]:
    findings: list[str] = []
    center = step_map.get("center")
    closer = step_map.get("move_closer")

    if not center or not closer:
        findings.append("Live challenge evidence is incomplete.")
        return findings

    if closer.coverage < max(center.coverage * 1.12, center.coverage + 0.02):
        findings.append("Closer-step frame did not increase face coverage enough.")
    if closer.motion < 0.008:
        findings.append("Challenge movement looked too limited for a live scan.")
    return findings


def analyze_face_liveness(payload: FaceLivenessRequest) -> dict[str, object]:
    preview = _decode_data_url_image(payload.preview_image)
    preview_features = _extract_preview_features(preview)

    step_images: dict[FaceStep, Image.Image] = {}
    step_map: dict[FaceStep, FaceLivenessStepCapture] = {}
    for capture in payload.step_captures:
        step_map[capture.step] = capture
        try:
            step_images[capture.step] = _decode_data_url_image(capture.image)
        except Exception:
            continue

    reasons: list[str] = []
    spoof_score = 0.0

    if len(step_images) < 2 or len(payload.completed_steps) < 2:
        spoof_score += 0.35
        reasons.append("The server did not receive a complete live challenge sequence.")

    telemetry_findings = _telemetry_findings(step_map)
    if telemetry_findings:
        spoof_score += min(0.32, 0.12 * len(telemetry_findings))
        reasons.extend(telemetry_findings)

    sharpness = preview_features["sharpness"]
    dynamic_range = preview_features["dynamic_range"]
    entropy = preview_features["entropy"]
    dominant_bin_ratio = preview_features["dominant_bin_ratio"]
    screen_pattern_score = preview_features["screen_pattern_score"]
    clip_ratio = preview_features["clip_ratio"]

    # The browser challenge already enforces motion, liveness, coverage, and sample
    # count. These image heuristics stay conservative so dim laptop webcams do not
    # get rejected as spoofed as often.
    if sharpness < MIN_SHARPNESS:
        spoof_score += 0.05
        reasons.append("Face preview looked too flat or blurred for a confident live scan.")
    if dynamic_range < MIN_DYNAMIC_RANGE:
        spoof_score += 0.04
        reasons.append("Preview contrast was unusually low.")
    if entropy < MIN_ENTROPY:
        spoof_score += 0.04
        reasons.append("Preview texture looked overly uniform.")
    if dominant_bin_ratio > MAX_DOMINANT_BIN_RATIO:
        spoof_score += 0.03
        reasons.append("Preview tones looked posterized like a displayed image.")
    if screen_pattern_score > 0.45:
        spoof_score += 0.18
        reasons.append("Periodic screen-like patterns were detected in the face preview.")
    if clip_ratio > MAX_CLIP_RATIO:
        spoof_score += 0.03
        reasons.append("Preview had excessive clipped shadows or highlights.")

    sequence_deltas: list[float] = []
    center_image = step_images.get("center")
    center_capture = step_map.get("center")
    closer_image = step_images.get("move_closer")
    closer_capture = step_map.get("move_closer")
    if center_image is not None:
        for step in ("move_closer",):
            step_image = step_images.get(step)
            if step_image is not None:
                sequence_deltas.append(_frame_delta(center_image, step_image))

    mean_step_delta = float(np.mean(sequence_deltas)) if sequence_deltas else 0.0
    min_step_delta = float(np.min(sequence_deltas)) if sequence_deltas else 0.0
    if mean_step_delta < MIN_MEAN_STEP_DELTA:
        spoof_score += 0.08
        reasons.append("Challenge frames changed too little between steps.")
    elif min_step_delta < MIN_STEP_DELTA:
        spoof_score += 0.05
        reasons.append("At least one challenge step looked nearly identical to the center frame.")

    depth_signals = {
        "face_delta": 0.0,
        "background_delta": 0.0,
        "coverage_gain": 0.0,
        "parallax_score": 0.0,
        "rigidity_score": 0.0,
    }
    if (
        center_image is not None
        and closer_image is not None
        and center_capture is not None
        and closer_capture is not None
    ):
        depth_signals = _depth_signal_score(
            center_image,
            center_capture,
            closer_image,
            closer_capture,
        )
        if (
            depth_signals["coverage_gain"] >= 0.02
            and depth_signals["parallax_score"] < MIN_FACE_PARALLAX_SCORE
        ):
            spoof_score += 0.1
            reasons.append(
                "Face moved closer but the scene still looked too flat, like a photo or screen."
            )
        elif (
            depth_signals["face_delta"] - depth_signals["background_delta"]
            < MIN_FACE_BACKGROUND_SEPARATION
            and depth_signals["coverage_gain"] >= 0.015
        ):
            spoof_score += 0.06
            reasons.append(
                "Face and background changed too uniformly during the closer step."
            )
        if depth_signals["rigidity_score"] > 0.018:
            spoof_score += 0.04
            reasons.append(
                "Background motion dominated the challenge like a rigid flat object."
            )

    if payload.motion_score < MIN_MOTION_SCORE:
        spoof_score += 0.06
        reasons.append("Motion score was lower than expected for a live face movement challenge.")
    if payload.liveness_score < MIN_LIVENESS_SCORE:
        spoof_score += 0.05
        reasons.append("Combined liveness evidence was below the hardened server threshold.")
    if payload.face_coverage < MIN_FACE_COVERAGE:
        spoof_score += 0.05
        reasons.append("Face coverage was too small for reliable anti-spoof analysis.")
    if payload.sample_count < MIN_SAMPLE_COUNT:
        spoof_score += 0.05
        reasons.append("Too few camera samples were captured during the live challenge.")

    image_quality_score = _clamp(
        preview_features["brightness_std"] * 1.4
        + preview_features["edge_density"] * 0.8
        + dynamic_range * 1.2,
    )
    temporal_score = _clamp(mean_step_delta / 0.11)
    confidence = _clamp(
        payload.liveness_score * 0.3
        + payload.motion_score * 0.2
        + temporal_score * 0.25
        + image_quality_score * 0.25
        - spoof_score * 0.35
    )
    spoof_score = _clamp(spoof_score)

    passed = spoof_score < MAX_SPOOF_SCORE_TO_PASS and confidence >= MIN_CONFIDENCE_TO_PASS
    risk_level = "low" if spoof_score < 0.2 else "medium" if spoof_score < 0.42 else "high"

    if not reasons:
        reasons.append("Live challenge sequence and preview texture passed the server anti-spoof checks.")

    return {
        "passed": passed,
        "spoofScore": spoof_score,
        "confidence": confidence,
        "riskLevel": risk_level,
        "reasons": reasons[:6],
        "analysisSignals": {
            "sharpness": round(sharpness, 6),
            "dynamicRange": round(dynamic_range, 6),
            "entropy": round(entropy, 6),
            "screenPatternScore": round(screen_pattern_score, 6),
            "meanStepDelta": round(mean_step_delta, 6),
            "minStepDelta": round(min_step_delta, 6),
            "faceDelta": round(depth_signals["face_delta"], 6),
            "backgroundDelta": round(depth_signals["background_delta"], 6),
            "coverageGain": round(depth_signals["coverage_gain"], 6),
            "parallaxScore": round(depth_signals["parallax_score"], 6),
            "rigidityScore": round(depth_signals["rigidity_score"], 6),
            "imageQualityScore": round(image_quality_score, 6),
            "temporalScore": round(temporal_score, 6),
        },
    }
