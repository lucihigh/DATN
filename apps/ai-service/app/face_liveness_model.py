import base64
import io
import math
from typing import Literal

import numpy as np
from PIL import Image
from pydantic import AliasChoices, BaseModel, Field

FaceStep = Literal["center", "move_left", "move_right", "move_closer"]


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

    if sharpness < 0.0018:
        spoof_score += 0.12
        reasons.append("Face preview looked too flat or blurred for a confident live scan.")
    if dynamic_range < 0.16:
        spoof_score += 0.1
        reasons.append("Preview contrast was unusually low.")
    if entropy < 1.35:
        spoof_score += 0.1
        reasons.append("Preview texture looked overly uniform.")
    if dominant_bin_ratio > 0.24:
        spoof_score += 0.08
        reasons.append("Preview tones looked posterized like a displayed image.")
    if screen_pattern_score > 0.45:
        spoof_score += 0.18
        reasons.append("Periodic screen-like patterns were detected in the face preview.")
    if clip_ratio > 0.22:
        spoof_score += 0.06
        reasons.append("Preview had excessive clipped shadows or highlights.")

    sequence_deltas: list[float] = []
    center_image = step_images.get("center")
    if center_image is not None:
        for step in ("move_closer",):
            step_image = step_images.get(step)
            if step_image is not None:
                sequence_deltas.append(_frame_delta(center_image, step_image))

    mean_step_delta = float(np.mean(sequence_deltas)) if sequence_deltas else 0.0
    min_step_delta = float(np.min(sequence_deltas)) if sequence_deltas else 0.0
    if mean_step_delta < 0.055:
        spoof_score += 0.22
        reasons.append("Challenge frames changed too little between steps.")
    elif min_step_delta < 0.03:
        spoof_score += 0.12
        reasons.append("At least one challenge step looked nearly identical to the center frame.")

    if payload.motion_score < 0.42:
        spoof_score += 0.14
        reasons.append("Motion score was lower than expected for a live face movement challenge.")
    if payload.liveness_score < 0.85:
        spoof_score += 0.1
        reasons.append("Combined liveness evidence was below the hardened server threshold.")
    if payload.face_coverage < 0.15:
        spoof_score += 0.08
        reasons.append("Face coverage was too small for reliable anti-spoof analysis.")
    if payload.sample_count < 28:
        spoof_score += 0.08
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

    passed = spoof_score < 0.42 and confidence >= 0.55
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
            "imageQualityScore": round(image_quality_score, 6),
            "temporalScore": round(temporal_score, 6),
        },
    }
