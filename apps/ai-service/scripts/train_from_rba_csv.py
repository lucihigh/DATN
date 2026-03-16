import argparse
import csv
import json
import sys
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

import joblib
import numpy as np
from pyod.models.iforest import IForest

AI_SERVICE_ROOT = Path(__file__).resolve().parents[1]
if str(AI_SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_SERVICE_ROOT))

from app.login_model import FEATURE_NAMES, OFF_HOURS


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train Isolation Forest from RBA CSV and save model artifacts."
    )
    parser.add_argument(
        "--csv",
        default=str(Path(__file__).resolve().parents[1] / "Train" / "rba-dataset.csv"),
        help="Path to rba-dataset.csv",
    )
    parser.add_argument(
        "--output-dir",
        default=str(Path(__file__).resolve().parents[1] / "models"),
        help="Directory to store model + metadata",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.02,
        help="Isolation Forest contamination",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=1_000_000,
        help="Print progress every N rows",
    )
    parser.add_argument(
        "--model-version",
        default=None,
        help="Explicit model version (default: auto-generated, e.g. iforest_rba_YYYYMMDD_HHMMSS)",
    )
    parser.add_argument(
        "--promote",
        action="store_true",
        help="Update models/active_model.json to point to the newly generated artifacts",
    )
    return parser.parse_args()


def parse_bool(value: str | None) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def parse_timestamp(value: str) -> datetime:
    # RBA dataset format: 2020-02-03 12:43:30.772
    return datetime.fromisoformat(str(value).strip())


def rba_bot_score_proxy(is_attack_ip: bool, is_account_takeover: bool) -> float:
    if is_account_takeover:
        return 0.95
    if is_attack_ip:
        return 0.85
    return 0.05


def stream_rba_rows(
    csv_path: Path, progress_prefix: str, progress_every: int, fill_array: np.ndarray | None = None
) -> dict:
    failed_windows: dict[str, deque[datetime]] = {}
    recent_1h_by_user: dict[str, deque[datetime]] = {}
    seen_countries_by_user: dict[str, set[str]] = {}
    seen_devices_by_user: dict[str, set[str]] = {}
    hour_history_by_user: dict[str, deque[int]] = {}
    rows_seen = 0
    parsed_rows = 0
    normal_rows = 0
    failed_rows = 0
    skipped_rows = 0
    write_idx = 0
    countries: set[str] = set()
    devices: set[str] = set()

    with csv_path.open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            rows_seen += 1
            try:
                timestamp = parse_timestamp(row["Login Timestamp"])
                user_id = str(row["User ID"])
                country = (row.get("Country") or "").strip() or "UNK"
                device = (row.get("User Agent String") or row.get("Device Type") or "").strip()
                login_successful = parse_bool(row.get("Login Successful"))
                is_attack_ip = parse_bool(row.get("Is Attack IP"))
                is_account_takeover = parse_bool(row.get("Is Account Takeover"))
            except Exception:
                skipped_rows += 1
                continue

            parsed_rows += 1
            user_failures = failed_windows.get(user_id)
            if user_failures is None:
                user_failures = deque()
            recent_1h = recent_1h_by_user.get(user_id)
            if recent_1h is None:
                recent_1h = deque()
            seen_countries = seen_countries_by_user.get(user_id)
            if seen_countries is None:
                seen_countries = set()
            seen_devices = seen_devices_by_user.get(user_id)
            if seen_devices is None:
                seen_devices = set()
            hour_history = hour_history_by_user.get(user_id)
            if hour_history is None:
                hour_history = deque(maxlen=50)

            cutoff = timestamp - timedelta(minutes=10)
            while user_failures and user_failures[0] < cutoff:
                user_failures.popleft()
            failed_10m = len(user_failures)

            cutoff_1h = timestamp - timedelta(hours=1)
            while recent_1h and recent_1h[0] < cutoff_1h:
                recent_1h.popleft()
            recent_attempts_1h = len(recent_1h)
            country_norm = country.lower()
            device_norm = device.lower()
            is_new_country = 1.0 if seen_countries and country_norm not in seen_countries else 0.0
            is_new_device = 1.0 if seen_devices and device_norm not in seen_devices else 0.0
            off_hour_baseline = sum(1 for hour in hour_history if hour in OFF_HOURS)
            off_hour_for_user = (
                timestamp.hour in OFF_HOURS
                and len(hour_history) >= 5
                and off_hour_baseline <= max(1, len(hour_history) // 5)
            )

            if login_successful:
                normal_rows += 1
                if fill_array is not None:
                    fill_array[write_idx, 0] = timestamp.hour
                    fill_array[write_idx, 1] = timestamp.weekday()
                    fill_array[write_idx, 2] = failed_10m
                    fill_array[write_idx, 3] = len(device)
                    fill_array[write_idx, 4] = rba_bot_score_proxy(is_attack_ip, is_account_takeover)
                    fill_array[write_idx, 5] = recent_attempts_1h
                    fill_array[write_idx, 6] = is_new_country
                    fill_array[write_idx, 7] = is_new_device
                    fill_array[write_idx, 8] = 1.0 if off_hour_for_user else 0.0
                    fill_array[write_idx, 9] = 0.0
                    write_idx += 1
                    countries.add(country.lower())
                    devices.add(device.lower())
                if user_failures:
                    failed_windows[user_id] = user_failures
                elif user_id in failed_windows:
                    del failed_windows[user_id]
            else:
                failed_rows += 1
                user_failures.append(timestamp)
                failed_windows[user_id] = user_failures

            recent_1h.append(timestamp)
            recent_1h_by_user[user_id] = recent_1h
            if country_norm:
                seen_countries.add(country_norm)
            if device_norm:
                seen_devices.add(device_norm)
            seen_countries_by_user[user_id] = seen_countries
            seen_devices_by_user[user_id] = seen_devices
            hour_history.append(timestamp.hour)
            hour_history_by_user[user_id] = hour_history

            if rows_seen % progress_every == 0:
                message = (
                    f"{progress_prefix} rows={rows_seen:,} parsed={parsed_rows:,} "
                    f"normal={normal_rows:,} failed={failed_rows:,} skipped={skipped_rows:,} "
                    f"active_failed_users={len(failed_windows):,}"
                )
                if fill_array is not None:
                    message += f" write_idx={write_idx:,}"
                print(message, flush=True)

    return {
        "rows_seen": rows_seen,
        "parsed_rows": parsed_rows,
        "normal_rows": normal_rows,
        "failed_rows": failed_rows,
        "skipped_rows": skipped_rows,
        "write_idx": write_idx,
        "countries": countries,
        "devices": devices,
    }


def main() -> None:
    args = parse_args()
    csv_path = Path(args.csv).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    print("PASS1_START", flush=True)
    pass1 = stream_rba_rows(csv_path, "PASS1", args.progress_every)
    print(
        "PASS1_DONE "
        f"rows={pass1['rows_seen']:,} parsed={pass1['parsed_rows']:,} "
        f"normal={pass1['normal_rows']:,} failed={pass1['failed_rows']:,} "
        f"skipped={pass1['skipped_rows']:,}",
        flush=True,
    )

    train_rows = int(pass1["normal_rows"])
    if train_rows < 10:
        raise RuntimeError("Not enough normal rows (success=True) to train")

    bytes_estimate = train_rows * len(FEATURE_NAMES) * np.dtype(np.float32).itemsize
    print(
        "ALLOCATING "
        f"rows={train_rows:,} features={len(FEATURE_NAMES)} dtype=float32 "
        f"approx_bytes={bytes_estimate:,} (~{bytes_estimate / 1024 / 1024 / 1024:.2f} GB)",
        flush=True,
    )
    features = np.empty((train_rows, len(FEATURE_NAMES)), dtype=np.float32)

    print("PASS2_START", flush=True)
    pass2 = stream_rba_rows(csv_path, "PASS2", args.progress_every, fill_array=features)
    print(
        "PASS2_DONE "
        f"rows={pass2['rows_seen']:,} parsed={pass2['parsed_rows']:,} "
        f"normal={pass2['normal_rows']:,} failed={pass2['failed_rows']:,} "
        f"skipped={pass2['skipped_rows']:,} write_idx={pass2['write_idx']:,}",
        flush=True,
    )

    if int(pass2["write_idx"]) != train_rows:
        raise RuntimeError(
            f"Write index mismatch: expected {train_rows}, got {int(pass2['write_idx'])}"
        )

    trained_at = datetime.now(timezone.utc)
    model_version = args.model_version or trained_at.strftime("iforest_rba_%Y%m%d_%H%M%S")

    print("FIT_START", flush=True)
    model = IForest(contamination=args.contamination, random_state=42)
    model.fit(features)
    print("FIT_DONE", flush=True)

    scores = model.decision_scores_
    thresholds = {
        "p90": float(np.percentile(scores, 90)),
        "p97": float(np.percentile(scores, 97)),
        "score_min": float(np.min(scores)),
        "score_max": float(np.max(scores)),
    }
    feature_mean = features.mean(axis=0)
    feature_std = features.std(axis=0)
    feature_std[feature_std == 0] = 1.0

    model_path = output_dir / "iforest_rba.joblib"
    metadata_path = output_dir / "iforest_rba_metadata.json"

    joblib.dump(model, model_path)
    metadata = {
        "artifact_version": 1,
        "model_type": "pyod.IForest",
        "model_version": model_version,
        "trained_at": trained_at.isoformat(),
        "source_csv": str(csv_path),
        "contamination": args.contamination,
        "feature_names": FEATURE_NAMES,
        "train_size": train_rows,
        "rows_seen": int(pass2["rows_seen"]),
        "failed_rows_seen": int(pass2["failed_rows"]),
        "skipped_rows": int(pass2["skipped_rows"]),
        "thresholds": thresholds,
        "feature_mean": [float(x) for x in feature_mean.tolist()],
        "feature_std": [float(x) for x in feature_std.tolist()],
        "countries": sorted(pass2["countries"]),
        "devices": sorted(pass2["devices"]),
        "bot_score_proxy": {
            "is_account_takeover_true": 0.95,
            "is_attack_ip_true": 0.85,
            "default": 0.05,
        },
    }
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=True), encoding="utf-8")

    if args.promote:
        active_file = output_dir / "active_model.json"
        active_cfg = {
            "model_version": model_version,
            "model_path": str(model_path),
            "metadata_path": str(metadata_path),
            "promoted_at": datetime.now(timezone.utc).isoformat(),
        }
        active_file.write_text(json.dumps(active_cfg, ensure_ascii=True), encoding="utf-8")

    print("TRAIN_FULL_DONE", flush=True)
    print(f"model_version={model_version}", flush=True)
    print(f"model_path={model_path}", flush=True)
    print(f"metadata_path={metadata_path}", flush=True)
    if args.promote:
        print(f"active_model_file={output_dir / 'active_model.json'}", flush=True)
    print(f"train_rows={train_rows:,}", flush=True)
    print(f"score_p90={thresholds['p90']:.6f}", flush=True)
    print(f"score_p97={thresholds['p97']:.6f}", flush=True)
    print(f"unique_countries={len(pass2['countries']):,}", flush=True)
    print(f"unique_devices={len(pass2['devices']):,}", flush=True)


if __name__ == "__main__":
    main()
