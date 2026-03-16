import argparse
import csv
import json
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from pyod.models.iforest import IForest

AI_SERVICE_ROOT = Path(__file__).resolve().parents[1]
if str(AI_SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_SERVICE_ROOT))

from app.transaction_model import TX_FEATURE_NAMES as FEATURE_NAMES


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train transaction Isolation Forest from CSV and save artifacts."
    )
    parser.add_argument(
        "--csv",
        default=str(Path(__file__).resolve().parents[1] / "Train" / "PS_20174392719_1491204439457_log.csv"),
        help="Path to transaction CSV",
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
        default=500_000,
        help="Print progress every N rows",
    )
    parser.add_argument(
        "--model-version",
        default=None,
        help="Explicit model version (default: iforest_tx_YYYYMMDD_HHMMSS)",
    )
    parser.add_argument(
        "--promote",
        action="store_true",
        help="Update models/active_tx_model.json to point to the newly generated artifacts",
    )
    return parser.parse_args()


def _to_int(value: str | None) -> int:
    return int(float(str(value).strip()))


def _to_float(value: str | None) -> float:
    return float(str(value).strip())


def _to_bool(value: str | None) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def _get_col(row: dict[str, str], name: str) -> str | None:
    if name in row:
        return row[name]
    lower_map = {k.lower(): k for k in row.keys()}
    key = lower_map.get(name.lower())
    return row.get(key) if key else None


def _safe_log10_amount(amount: float) -> float:
    return float(np.log10(max(amount, 0.0) + 1.0))


def _safe_ratio(numerator: float, denominator: float) -> float:
    if denominator > 0:
        return float(max(numerator, 0.0) / denominator)
    return float(max(numerator, 0.0))


def stream_tx_rows(
    csv_path: Path, progress_prefix: str, progress_every: int, fill_array: np.ndarray | None = None
) -> dict:
    rows_seen = 0
    parsed_rows = 0
    normal_rows = 0
    fraud_rows = 0
    skipped_rows = 0
    write_idx = 0

    payment_methods: set[str] = set()
    merchant_categories: set[str] = set()
    countries: set[str] = {"unk"}

    # Keep a short rolling history per source account (nameOrig) for proxy signals.
    # step unit in this dataset is hour.
    recent_24h_fraud_by_user: dict[str, deque[int]] = {}
    recent_1h_tx_by_user: dict[str, deque[int]] = {}
    daily_totals_by_user: dict[str, dict[int, float]] = {}

    with csv_path.open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            rows_seen += 1
            try:
                step_raw = _get_col(row, "step")
                if step_raw is None:
                    step_raw = _get_col(row, "mstep")
                step = _to_int(step_raw)
                tx_type = str(_get_col(row, "type") or "unknown").strip().lower() or "unknown"
                amount = _to_float(_get_col(row, "amount"))
                user_id = str(_get_col(row, "nameOrig") or "").strip() or "unknown_user"
                is_fraud = _to_bool(_get_col(row, "isFraud"))
            except Exception:
                skipped_rows += 1
                continue

            parsed_rows += 1
            payment_methods.add(tx_type)
            merchant_categories.add(tx_type)

            user_fraud_history = recent_24h_fraud_by_user.get(user_id)
            if user_fraud_history is None:
                user_fraud_history = deque()
            while user_fraud_history and (step - user_fraud_history[0]) > 24:
                user_fraud_history.popleft()
            failed_tx_24h = len(user_fraud_history)

            user_tx_history = recent_1h_tx_by_user.get(user_id)
            if user_tx_history is None:
                user_tx_history = deque()
            while user_tx_history and (step - user_tx_history[0]) > 1:
                user_tx_history.popleft()
            velocity_1h = len(user_tx_history)

            hour_of_day = step % 24
            day_of_week = (step // 24) % 7
            device_length_proxy = len(tx_type)
            amount_log10 = _safe_log10_amount(amount)
            day_number = step // 24
            user_daily_totals = daily_totals_by_user.get(user_id)
            if user_daily_totals is None:
                user_daily_totals = {}
            active_day_totals = [
                float(total)
                for day, total in user_daily_totals.items()
                if total > 0 and (day_number - day) <= 30
            ]
            today_spend_before = float(user_daily_totals.get(day_number, 0.0))
            daily_spend_avg_30d = (
                float(sum(active_day_totals) / len(active_day_totals)) if active_day_totals else 0.0
            )
            projected_daily_spend = today_spend_before + max(amount, 0.0)
            projected_spend_ratio_log10 = _safe_log10_amount(
                _safe_ratio(projected_daily_spend, daily_spend_avg_30d)
            )
            amount_to_daily_avg_ratio_log10 = _safe_log10_amount(
                _safe_ratio(amount, daily_spend_avg_30d)
            )
            today_spend_before_log10 = _safe_log10_amount(today_spend_before)
            projected_spend_delta_log10 = _safe_log10_amount(
                max(projected_daily_spend - daily_spend_avg_30d, 0.0)
            )

            if not is_fraud:
                normal_rows += 1
                if fill_array is not None:
                    fill_array[write_idx, 0] = float(hour_of_day)
                    fill_array[write_idx, 1] = float(day_of_week)
                    fill_array[write_idx, 2] = amount_log10
                    fill_array[write_idx, 3] = float(failed_tx_24h)
                    fill_array[write_idx, 4] = float(velocity_1h)
                    fill_array[write_idx, 5] = float(device_length_proxy)
                    fill_array[write_idx, 6] = float(projected_spend_ratio_log10)
                    fill_array[write_idx, 7] = float(amount_to_daily_avg_ratio_log10)
                    fill_array[write_idx, 8] = float(today_spend_before_log10)
                    fill_array[write_idx, 9] = float(projected_spend_delta_log10)
                    write_idx += 1
            else:
                fraud_rows += 1
                user_fraud_history.append(step)

            user_tx_history.append(step)
            recent_24h_fraud_by_user[user_id] = user_fraud_history
            recent_1h_tx_by_user[user_id] = user_tx_history
            user_daily_totals[day_number] = today_spend_before + max(amount, 0.0)
            daily_totals_by_user[user_id] = user_daily_totals

            if rows_seen % progress_every == 0:
                message = (
                    f"{progress_prefix} rows={rows_seen:,} parsed={parsed_rows:,} "
                    f"normal={normal_rows:,} fraud={fraud_rows:,} skipped={skipped_rows:,}"
                )
                if fill_array is not None:
                    message += f" write_idx={write_idx:,}"
                print(message, flush=True)

    return {
        "rows_seen": rows_seen,
        "parsed_rows": parsed_rows,
        "normal_rows": normal_rows,
        "fraud_rows": fraud_rows,
        "skipped_rows": skipped_rows,
        "write_idx": write_idx,
        "countries": countries,
        "payment_methods": payment_methods,
        "merchant_categories": merchant_categories,
    }


def main() -> None:
    args = parse_args()
    csv_path = Path(args.csv).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    print("PASS1_START", flush=True)
    pass1 = stream_tx_rows(csv_path, "PASS1", args.progress_every)
    print(
        "PASS1_DONE "
        f"rows={pass1['rows_seen']:,} parsed={pass1['parsed_rows']:,} "
        f"normal={pass1['normal_rows']:,} fraud={pass1['fraud_rows']:,} "
        f"skipped={pass1['skipped_rows']:,}",
        flush=True,
    )

    train_rows = int(pass1["normal_rows"])
    if train_rows < 10:
        raise RuntimeError("Not enough non-fraud rows (isFraud=0) to train")

    bytes_estimate = train_rows * len(FEATURE_NAMES) * np.dtype(np.float32).itemsize
    print(
        "ALLOCATING "
        f"rows={train_rows:,} features={len(FEATURE_NAMES)} dtype=float32 "
        f"approx_bytes={bytes_estimate:,} (~{bytes_estimate / 1024 / 1024 / 1024:.2f} GB)",
        flush=True,
    )
    features = np.empty((train_rows, len(FEATURE_NAMES)), dtype=np.float32)

    print("PASS2_START", flush=True)
    pass2 = stream_tx_rows(csv_path, "PASS2", args.progress_every, fill_array=features)
    print(
        "PASS2_DONE "
        f"rows={pass2['rows_seen']:,} parsed={pass2['parsed_rows']:,} "
        f"normal={pass2['normal_rows']:,} fraud={pass2['fraud_rows']:,} "
        f"skipped={pass2['skipped_rows']:,} write_idx={pass2['write_idx']:,}",
        flush=True,
    )

    if int(pass2["write_idx"]) != train_rows:
        raise RuntimeError(f"Write index mismatch: expected {train_rows}, got {int(pass2['write_idx'])}")

    trained_at = datetime.now(timezone.utc)
    model_version = args.model_version or trained_at.strftime("iforest_tx_%Y%m%d_%H%M%S")

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

    model_path = output_dir / "iforest_tx.joblib"
    metadata_path = output_dir / "iforest_tx_metadata.json"

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
        "fraud_rows_seen": int(pass2["fraud_rows"]),
        "skipped_rows": int(pass2["skipped_rows"]),
        "thresholds": thresholds,
        "feature_mean": [float(x) for x in feature_mean.tolist()],
        "feature_std": [float(x) for x in feature_std.tolist()],
        "countries": sorted(pass2["countries"]),
        "payment_methods": sorted(pass2["payment_methods"]),
        "merchant_categories": sorted(pass2["merchant_categories"]),
        "feature_proxy_notes": {
            "hour_of_day": "step % 24",
            "day_of_week": "(step // 24) % 7",
            "failed_tx_24h": "rolling count of prior isFraud=1 by nameOrig in 24h window",
            "velocity_1h": "rolling count of prior transactions by nameOrig in 1h window",
            "device_length": "len(type) as proxy",
            "projected_spend_ratio_log10": "log10(projectedDailySpend / dailySpendAvg30d + 1) proxy",
            "amount_to_daily_avg_ratio_log10": "log10(amount / dailySpendAvg30d + 1) proxy",
            "today_spend_before_log10": "log10(todaySpendBefore + 1) proxy",
            "projected_spend_delta_log10": "log10(max(projectedDailySpend - dailySpendAvg30d, 0) + 1) proxy",
            "country": "UNK (not present in CSV)",
            "merchant_category": "mapped from type",
        },
    }
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=True), encoding="utf-8")

    if args.promote:
        active_file = output_dir / "active_tx_model.json"
        active_cfg = {
            "model_version": model_version,
            "model_path": str(model_path),
            "metadata_path": str(metadata_path),
            "promoted_at": datetime.now(timezone.utc).isoformat(),
        }
        active_file.write_text(json.dumps(active_cfg, ensure_ascii=True), encoding="utf-8")
    else:
        active_file = None

    print("TRAIN_TX_DONE", flush=True)
    print(f"model_version={model_version}", flush=True)
    print(f"model_path={model_path}", flush=True)
    print(f"metadata_path={metadata_path}", flush=True)
    if active_file is not None:
        print(f"active_model_file={active_file}", flush=True)
    print(f"train_rows={train_rows:,}", flush=True)
    print(f"score_p90={thresholds['p90']:.6f}", flush=True)
    print(f"score_p97={thresholds['p97']:.6f}", flush=True)
    print(f"unique_payment_methods={len(pass2['payment_methods']):,}", flush=True)
    print(f"unique_merchant_categories={len(pass2['merchant_categories']):,}", flush=True)


if __name__ == "__main__":
    main()
