import argparse
import csv
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Quickstart trainer for open datasets: OpenML+PaySim (transaction) and LANL/CERT (login)."
        )
    )
    parser.add_argument("--openml-creditcard-csv", default=None, help="Path to OpenML/UCI creditcard CSV")
    parser.add_argument("--paysim-csv", default=None, help="Path to PaySim CSV")
    parser.add_argument("--lanl-auth", default=None, help="Path to LANL auth file")
    parser.add_argument("--cert-logon-csv", default=None, help="Path to CERT logon.csv")
    parser.add_argument(
        "--work-dir",
        default=str(Path(__file__).resolve().parents[1] / "Train" / "prepared"),
        help="Directory to write prepared intermediate CSV files",
    )
    parser.add_argument(
        "--output-dir",
        default=str(Path(__file__).resolve().parents[1] / "models"),
        help="Directory to write model artifacts",
    )
    parser.add_argument("--contamination", type=float, default=0.02, help="Isolation Forest contamination")
    parser.add_argument("--progress-every", type=int, default=500_000, help="Progress rows")
    parser.add_argument("--model-version-prefix", default="open_data", help="Model version prefix")
    parser.add_argument("--promote", action="store_true", help="Promote active model pointers after train")
    return parser.parse_args()


def _parse_bool(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "success", "succeeded"}


def _normalize_binary_label(value: str | None) -> bool:
    cleaned = str(value or "").strip().strip("'\"").lower()
    return cleaned in {"1", "true", "yes", "y", "fraud", "positive"}


def _parse_iso_datetime(value: str | None) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    fmts = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
        "%d/%m/%Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
    )
    for fmt in fmts:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except Exception:
        return None


def _normalize_tx_row_from_paysim(row: dict[str, str]) -> dict[str, str] | None:
    try:
        step = int(float(str(row.get("step", "")).strip()))
        amount = float(str(row.get("amount", "")).strip())
        user_id = str(row.get("nameOrig", "")).strip() or "unknown_user"
        is_fraud = _normalize_binary_label(row.get("isFraud"))
        tx_type = str(row.get("type", "")).strip() or "unknown"
        return {
            "step": str(step),
            "type": tx_type,
            "amount": str(amount),
            "nameOrig": user_id,
            "isFraud": "1" if is_fraud else "0",
        }
    except Exception:
        return None


def _normalize_tx_row_from_openml(row: dict[str, str], row_index: int) -> dict[str, str] | None:
    try:
        amount = float(str(row.get("Amount", row.get("amount", "0"))).strip())
        raw_label = row.get("Class", row.get("class", "0"))
        is_fraud = _normalize_binary_label(raw_label)

        raw_time = row.get("Time", row.get("time"))
        if raw_time is None:
            step = row_index // 3
        else:
            seconds = float(str(raw_time).strip())
            step = max(int(seconds // 3600), 0)
        user_bucket = row_index % 5000
        return {
            "step": str(step),
            "type": "card_payment",
            "amount": str(max(amount, 0.0)),
            "nameOrig": f"openml_user_{user_bucket}",
            "isFraud": "1" if is_fraud else "0",
        }
    except Exception:
        return None


def _prepare_openml_arff_rows(openml_path: Path, writer: csv.DictWriter, start_index: int) -> int:
    written = 0
    in_data = False
    with openml_path.open("r", encoding="utf-8", newline="") as file:
        for raw_line in file:
            line = raw_line.strip()
            if not line or line.startswith("%"):
                continue
            if not in_data:
                if line.lower() == "@data":
                    in_data = True
                continue

            parts = [part.strip() for part in line.split(",")]
            if len(parts) < 31:
                continue

            row = _normalize_tx_row_from_openml(
                {
                    "Time": parts[0],
                    "Amount": parts[29],
                    "Class": parts[30],
                },
                start_index + written,
            )
            if row is None:
                continue
            writer.writerow(row)
            written += 1
    return written


def prepare_transaction_csv(
    *,
    output_path: Path,
    paysim_csv: Path | None,
    openml_csv: Path | None,
) -> int:
    written = 0
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as out_file:
        writer = csv.DictWriter(out_file, fieldnames=["step", "type", "amount", "nameOrig", "isFraud"])
        writer.writeheader()

        if paysim_csv is not None:
            with paysim_csv.open("r", encoding="utf-8", newline="") as file:
                for row in csv.DictReader(file):
                    normalized = _normalize_tx_row_from_paysim(row)
                    if normalized is None:
                        continue
                    writer.writerow(normalized)
                    written += 1

        if openml_csv is not None:
            if openml_csv.suffix.lower() == ".arff":
                written += _prepare_openml_arff_rows(openml_csv, writer, written)
            else:
                with openml_csv.open("r", encoding="utf-8", newline="") as file:
                    for idx, row in enumerate(csv.DictReader(file), start=written):
                        normalized = _normalize_tx_row_from_openml(row, idx)
                        if normalized is None:
                            continue
                        writer.writerow(normalized)
                        written += 1
    return written


def _to_cert_login_row(row: dict[str, str]) -> dict[str, str] | None:
    timestamp = _parse_iso_datetime(row.get("date") or row.get("timestamp"))
    if timestamp is None:
        return None
    user_id = str(row.get("user", "")).strip()
    device = str(row.get("pc", "")).strip() or "unknown_device"
    activity = str(row.get("activity", "")).strip().lower()
    successful = "logon" in activity and "fail" not in activity
    is_ato = "fail" in activity and ("remote" in activity or "vpn" in activity)
    return {
        "Login Timestamp": timestamp.replace(tzinfo=None).isoformat(sep=" ", timespec="seconds"),
        "User ID": user_id or "unknown_user",
        "Country": "UNK",
        "User Agent String": device,
        "Device Type": "workstation",
        "Login Successful": "true" if successful else "false",
        "Is Attack IP": "false",
        "Is Account Takeover": "true" if is_ato else "false",
    }


def _parse_lanl_timestamp(raw: str, base_time: datetime) -> datetime | None:
    text = str(raw or "").strip()
    if not text:
        return None
    if text.isdigit():
        number = int(text)
        if number >= 1_000_000_000:
            return datetime.fromtimestamp(number, tz=timezone.utc)
        return base_time + timedelta(seconds=number)
    dt = _parse_iso_datetime(text)
    return dt


def _to_lanl_login_row(parts: list[str], base_time: datetime) -> dict[str, str] | None:
    if len(parts) < 8:
        return None
    timestamp = _parse_lanl_timestamp(parts[0], base_time)
    if timestamp is None:
        return None
    raw_user = parts[1]
    user_id = str(raw_user).split("@", 1)[0].strip() or "unknown_user"
    device = str(parts[3]).strip() or "unknown_device"
    success_text = str(parts[-1]).strip().lower()
    successful = success_text in {"success", "succeeded", "1", "true", "t"}
    is_attack = not successful
    return {
        "Login Timestamp": timestamp.replace(tzinfo=None).isoformat(sep=" ", timespec="seconds"),
        "User ID": user_id,
        "Country": "UNK",
        "User Agent String": device,
        "Device Type": "workstation",
        "Login Successful": "true" if successful else "false",
        "Is Attack IP": "true" if is_attack else "false",
        "Is Account Takeover": "false",
    }


def prepare_login_csv(
    *,
    output_path: Path,
    cert_logon_csv: Path | None,
    lanl_auth_file: Path | None,
) -> int:
    written = 0
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as out_file:
        headers = [
            "Login Timestamp",
            "User ID",
            "Country",
            "User Agent String",
            "Device Type",
            "Login Successful",
            "Is Attack IP",
            "Is Account Takeover",
        ]
        writer = csv.DictWriter(out_file, fieldnames=headers)
        writer.writeheader()

        if cert_logon_csv is not None:
            with cert_logon_csv.open("r", encoding="utf-8", newline="") as file:
                for row in csv.DictReader(file):
                    normalized = _to_cert_login_row(row)
                    if normalized is None:
                        continue
                    writer.writerow(normalized)
                    written += 1

        if lanl_auth_file is not None:
            base_time = datetime(2011, 1, 1, tzinfo=timezone.utc)
            with lanl_auth_file.open("r", encoding="utf-8", newline="") as file:
                for raw in file:
                    line = raw.strip()
                    if not line:
                        continue
                    if "," in line:
                        parts = [part.strip() for part in line.split(",")]
                    else:
                        parts = [part.strip() for part in line.split()]
                    normalized = _to_lanl_login_row(parts, base_time=base_time)
                    if normalized is None:
                        continue
                    writer.writerow(normalized)
                    written += 1
    return written


def _run_train(command: list[str], cwd: Path) -> None:
    print("RUN", " ".join(command), flush=True)
    completed = subprocess.run(command, cwd=str(cwd), check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"Command failed ({completed.returncode}): {' '.join(command)}")


def main() -> None:
    args = parse_args()
    script_dir = Path(__file__).resolve().parent
    ai_root = script_dir.parent

    work_dir = Path(args.work_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    paysim_csv = Path(args.paysim_csv).resolve() if args.paysim_csv else None
    openml_csv = Path(args.openml_creditcard_csv).resolve() if args.openml_creditcard_csv else None
    lanl_auth = Path(args.lanl_auth).resolve() if args.lanl_auth else None
    cert_logon = Path(args.cert_logon_csv).resolve() if args.cert_logon_csv else None

    if paysim_csv is None and openml_csv is None:
        raise ValueError("Provide at least one transaction dataset: --paysim-csv or --openml-creditcard-csv")
    if lanl_auth is None and cert_logon is None:
        raise ValueError("Provide at least one login dataset: --lanl-auth or --cert-logon-csv")

    tx_csv = work_dir / "transaction_open_data.csv"
    login_csv = work_dir / "login_open_data.csv"

    tx_rows = prepare_transaction_csv(output_path=tx_csv, paysim_csv=paysim_csv, openml_csv=openml_csv)
    if tx_rows < 20:
        raise RuntimeError(f"Prepared transaction rows too small: {tx_rows}")
    print(f"PREPARED_TX rows={tx_rows:,} file={tx_csv}", flush=True)

    login_rows = prepare_login_csv(output_path=login_csv, cert_logon_csv=cert_logon, lanl_auth_file=lanl_auth)
    if login_rows < 20:
        raise RuntimeError(f"Prepared login rows too small: {login_rows}")
    print(f"PREPARED_LOGIN rows={login_rows:,} file={login_csv}", flush=True)

    login_version = f"{args.model_version_prefix}_login_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    tx_version = f"{args.model_version_prefix}_tx_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

    train_login_cmd = [
        sys.executable,
        str(script_dir / "train_from_rba_csv.py"),
        "--csv",
        str(login_csv),
        "--output-dir",
        str(output_dir),
        "--contamination",
        str(args.contamination),
        "--progress-every",
        str(max(1, args.progress_every)),
        "--model-version",
        login_version,
    ]
    if args.promote:
        train_login_cmd.append("--promote")

    train_tx_cmd = [
        sys.executable,
        str(script_dir / "train_from_tx_csv.py"),
        "--csv",
        str(tx_csv),
        "--output-dir",
        str(output_dir),
        "--contamination",
        str(args.contamination),
        "--progress-every",
        str(max(1, args.progress_every)),
        "--model-version",
        tx_version,
    ]
    if args.promote:
        train_tx_cmd.append("--promote")

    _run_train(train_login_cmd, cwd=ai_root)
    _run_train(train_tx_cmd, cwd=ai_root)
    print("OPEN_DATA_TRAIN_DONE", flush=True)
    print(f"login_model_version={login_version}", flush=True)
    print(f"tx_model_version={tx_version}", flush=True)
    if args.promote:
        print(f"active_login_pointer={output_dir / 'active_model.json'}", flush=True)
        print(f"active_tx_pointer={output_dir / 'active_tx_model.json'}", flush=True)


if __name__ == "__main__":
    main()
