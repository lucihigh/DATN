import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from pymongo import MongoClient
from pyod.models.iforest import IForest

FEATURE_NAMES = ["hour_of_day", "day_of_week", "failed_10m", "device_length", "bot_score"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Retrain Isolation Forest from Mongo LOGIN_EVENTS(success=true)."
    )
    parser.add_argument("--mongo-uri", default=os.getenv("MONGODB_URI", "mongodb://127.0.0.1:27017"))
    parser.add_argument("--mongo-db", default=os.getenv("MONGODB_DB", "secure_wallet_local"))
    parser.add_argument("--output-dir", default=str(Path(__file__).resolve().parents[1] / "models"))
    parser.add_argument("--contamination", type=float, default=0.02)
    parser.add_argument("--max-rows", type=int, default=500_000)
    parser.add_argument("--model-version", default=None)
    parser.add_argument("--promote", action="store_true")
    return parser.parse_args()


def normalize_country(value: str | None) -> str:
    cleaned = str(value or "").strip().upper()
    return cleaned[:2] if len(cleaned) >= 2 else (cleaned or "UNK")


def normalize_device(value: str | None) -> str:
    return str(value or "").strip().lower()


def main() -> None:
    args = parse_args()
    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    client = MongoClient(args.mongo_uri, serverSelectionTimeoutMS=5000)
    client.admin.command("ping")
    db = client[args.mongo_db]

    cursor = (
        db["LOGIN_EVENTS"]
        .find(
            {"success": True},
            {
                "createdAt": 1,
                "failed10m": 1,
                "device": 1,
                "userAgent": 1,
                "botScore": 1,
                "country": 1,
            },
        )
        .sort("createdAt", -1)
        .limit(max(100, int(args.max_rows)))
    )

    features: list[list[float]] = []
    countries: set[str] = set()
    devices: set[str] = set()

    for doc in cursor:
        ts = doc.get("createdAt")
        if not isinstance(ts, datetime):
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        else:
            ts = ts.astimezone(timezone.utc)
        failed_10m = float(doc.get("failed10m") or 0.0)
        device = str(doc.get("device") or doc.get("userAgent") or "")
        bot_score = float(doc.get("botScore") or 0.0)
        country = normalize_country(doc.get("country"))
        countries.add(country.lower())
        devices.add(normalize_device(device))
        features.append(
            [
                float(ts.hour),
                float(ts.weekday()),
                failed_10m,
                float(len(device)),
                bot_score,
            ]
        )

    if len(features) < 100:
        raise RuntimeError(f"Not enough normal rows from Mongo for retrain: {len(features)}")

    X = np.asarray(features, dtype=np.float32)
    model = IForest(contamination=args.contamination, random_state=42)
    model.fit(X)
    scores = model.decision_scores_

    trained_at = datetime.now(timezone.utc)
    model_version = args.model_version or trained_at.strftime("iforest_mongo_%Y%m%d_%H%M%S")
    model_path = out_dir / "iforest_rba.joblib"
    metadata_path = out_dir / "iforest_rba_metadata.json"

    metadata = {
        "artifact_version": 1,
        "model_type": "pyod.IForest",
        "model_version": model_version,
        "trained_at": trained_at.isoformat(),
        "source": "mongo:LOGIN_EVENTS(success=true)",
        "contamination": args.contamination,
        "feature_names": FEATURE_NAMES,
        "train_size": int(X.shape[0]),
        "thresholds": {
            "p90": float(np.percentile(scores, 90)),
            "p97": float(np.percentile(scores, 97)),
            "score_min": float(np.min(scores)),
            "score_max": float(np.max(scores)),
        },
        "feature_mean": [float(v) for v in X.mean(axis=0).tolist()],
        "feature_std": [float(v) for v in X.std(axis=0).tolist()],
        "countries": sorted(countries),
        "devices": sorted(devices),
    }

    joblib.dump(model, model_path)
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=True), encoding="utf-8")

    if args.promote:
        active_path = out_dir / "active_model.json"
        active_cfg = {
            "model_version": model_version,
            "model_path": str(model_path),
            "metadata_path": str(metadata_path),
            "promoted_at": datetime.now(timezone.utc).isoformat(),
        }
        active_path.write_text(json.dumps(active_cfg, ensure_ascii=True), encoding="utf-8")
        print(f"promoted={active_path}")

    print(f"trained_rows={len(features)}")
    print(f"model_version={model_version}")
    print(f"model_path={model_path}")
    print(f"metadata_path={metadata_path}")
    client.close()


if __name__ == "__main__":
    main()
