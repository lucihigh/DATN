# AI Service (FastAPI)

Service AI phát hiện bất thường cho đăng nhập và giao dịch, sử dụng `PyOD` + `Isolation Forest`.

## Phạm vi sử dụng

Tài liệu này **chỉ áp dụng cho thư mục `apps/ai-service`**.  
Tất cả lệnh bên dưới được hiểu là chạy tại:

```powershell
cd apps/ai-service
```

## API endpoints

- `GET /health` - kiểm tra trạng thái service và trạng thái nạp model
- `GET /ai/status` - trạng thái train/model artifact (cần API key)
- `GET /ai/metrics` - số liệu runtime (cần API key)
- `GET /ai/admin/alerts` - danh sách cảnh báo cho trang admin (cần API key)
- `GET /ai/admin/stats` - phân phối mức độ rủi ro cho admin (cần API key)
- `POST /ai/reload-model` - nạp lại con trỏ active model (cần API key)
- `POST /ai/train` - train model login anomaly trong bộ nhớ (hỗ trợ `?persist=true&promote=true`, cần API key)
- `POST /ai/score` - chấm điểm một sự kiện đăng nhập (`monitoring_only=true`, không tự động chặn)
- `POST /ai/tx/train` - train model transaction anomaly trong bộ nhớ (hỗ trợ `?persist=true&promote=true`, cần API key)
- `POST /ai/tx/score` - chấm điểm giao dịch (`monitoring_only=true`, chỉ để review)

## Chạy local

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Giao diện test:

- Mở `http://127.0.0.1:8000/ui`
- Trong phần **Login Model**, dùng khối **Login attack demo** để mô phỏng tấn công login khi thuyết trình:
  - `Run attack demo (auto train)`: tự train profile bình thường rồi bắn chuỗi login đáng ngờ
  - `Run attack only`: chỉ bắn chuỗi login đáng ngờ trên model hiện tại
  - Xem kết quả tổng hợp `attack_risk_counts`, `high_risk_attempts` trong khung Output
- Trong phần **Transaction Model**, dùng khối **Transaction anomaly demo** để mô phỏng giao dịch bất thường:
  - `Run anomaly demo (auto train)`: tự train profile giao dịch bình thường rồi bắn chuỗi giao dịch bất thường
  - `Run anomaly only`: chỉ bắn chuỗi giao dịch bất thường trên model hiện tại
  - Xem kết quả tổng hợp `anomaly_risk_counts`, `high_risk_attempts` trong khung Output

## Train model login từ RBA CSV

Đường dẫn dataset mặc định:
`Train/rba-dataset.csv`

```powershell
py scripts/train_from_rba_csv.py
```

Artifact được tạo:

- `models/iforest_rba.joblib`
- `models/iforest_rba_metadata.json`

Khi các file này tồn tại, service sẽ tự nạp model lúc khởi động.

## Train model giao dịch từ CSV

Đường dẫn dataset mặc định:
`Train/PS_20174392719_1491204439457_log.csv`

```powershell
py scripts/train_from_tx_csv.py
```

Artifact được tạo:

- `models/iforest_tx.joblib`
- `models/iforest_tx_metadata.json`

## Biến môi trường (tuỳ chọn)

- `AI_MODEL_PATH` - đường dẫn model artifact cho login
- `AI_METADATA_PATH` - đường dẫn metadata cho login
- `AI_ACTIVE_MODEL_FILE` - file con trỏ rollout login (mặc định: `models/active_model.json`)
- `AI_MODEL_VERSION` - ghi đè model version runtime
- `AI_TX_MODEL_PATH` - đường dẫn model artifact cho transaction
- `AI_TX_METADATA_PATH` - đường dẫn metadata cho transaction
- `AI_TX_ACTIVE_MODEL_FILE` - file con trỏ rollout transaction (mặc định: `models/active_tx_model.json`)
- `AI_AUTH_MODE` - `api_key` (mặc định), `jwt`, hoặc `both`
- `MONGODB_URI`, `MONGODB_DB` - cấu hình kết nối MongoDB
- `AI_API_KEY` - API key cho endpoint bảo vệ (mặc định local: `local-dev-key`)
- `AI_JWT_SECRET` - secret JWT để kiểm tra bearer token (bắt buộc khi `AI_AUTH_MODE=jwt|both`)
- `AI_JWT_ALGORITHM` - thuật toán JWT (mặc định: `HS256`)
- `AI_JWT_AUDIENCE` - audience JWT (tuỳ chọn)
- `AI_JWT_ISSUER` - issuer JWT (tuỳ chọn)
- `AI_DISABLE_AUTH=1` - tắt kiểm tra API key (chỉ dùng môi trường dev)

## JWT với Postman

Thiết lập biến môi trường (ví dụ):

```powershell
$env:AI_AUTH_MODE = "jwt"
$env:AI_JWT_SECRET = "replace-with-a-random-secret-at-least-32-chars"
$env:AI_JWT_ALGORITHM = "HS256"
```

Sinh token test:

```powershell
py -c "import jwt,datetime; print(jwt.encode({'sub':'postman-user','exp':datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=12)}, 'change-me', algorithm='HS256'))"
```

Trong Postman:

- Tab Authorization: chọn `Bearer Token`
- Dán token vừa tạo
- Gọi endpoint có bảo vệ, ví dụ: `POST /ai/score`, `POST /ai/tx/score`, `GET /ai/status`

## Retrain và rollout model

Train từ CSV login:

```powershell
py scripts/train_from_rba_csv.py --model-version iforest_rba_20260305_v1 --promote
```

Train từ CSV transaction:

```powershell
py scripts/train_from_tx_csv.py --model-version iforest_tx_20260309_v1 --promote
```

Retrain batch từ Mongo `LOGIN_EVENTS`:

```powershell
py scripts/retrain_from_mongo.py --promote
```

## Chạy test

```powershell
pytest -q
```

## Anti-scam and AML rule engine (transaction score)

`POST /ai/tx/score` now returns extra fields from deterministic anti-scam/AML rules:

- `model_risk_level`: risk from IF model + adaptive thresholds
- `rule_risk_level`: risk from rule engine
- `rule_score`, `rule_hit_count`, `rule_hits`
- `warning_vi`: Vietnamese warning package for end-user UX

Rule implementation file:

- `app/fraud_rules.py`

Training/operations documents:

- `docs/aml_scam_dataset_schema.json`
- `docs/aml_scam_labeling_guideline.vi.md`
- `docs/aml_scam_warning_prompts.vi.md`
- `docs/aml_scam_scenario_catalog.csv` (240 scenarios)

## Train nhanh tu OpenML + PaySim + LANL/CERT

Script quickstart:

```powershell
py scripts/train_quickstart_open_data.py ^
  --openml-creditcard-csv "F:\data\creditcard.csv" ^
  --paysim-csv "F:\data\PS_20174392719_1491204439457_log.csv" ^
  --lanl-auth "F:\data\auth.txt" ^
  --cert-logon-csv "F:\data\logon.csv" ^
  --promote
```

Script se:

- chuan hoa transaction data ve CSV trung gian (`step,type,amount,nameOrig,isFraud`)
- chuan hoa login data ve schema RBA (`Login Timestamp`, `User ID`, ...)
- goi lai `scripts/train_from_rba_csv.py` va `scripts/train_from_tx_csv.py`
- tu rollout `active_model.json` + `active_tx_model.json` neu co `--promote`

Ghi chu map dataset:

- OpenML/UCI creditcard: dung `Amount`, `Class`, `Time` (neu co)
- PaySim: dung truc tiep `step,type,amount,nameOrig,isFraud`
- CERT logon.csv: cac cot mong doi `date,user,pc,activity`
- LANL auth: ho tro dong CSV hoac whitespace, token cuoi cung la trang thai success/failure
