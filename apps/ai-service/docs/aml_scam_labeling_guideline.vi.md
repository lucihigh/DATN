# Huong dan gan nhan AML/Scam (v1)

## 1) Muc tieu
- Gan nhan nhat quan de train AI canh bao lua dao va phat hien rua tien.
- Uu tien `recall` cho nhom `HIGH`, sau do toi uu `precision`.

## 2) Taxonomy nhan
- `label_risk_level`: `LOW | MEDIUM | HIGH`
- `label_case_type`:
  - `normal`
  - `account_takeover`
  - `impersonation_scam`
  - `investment_scam`
  - `romance_scam`
  - `job_scam`
  - `ecommerce_scam`
  - `chargeback_abuse`
  - `mule_account`
  - `smurfing`
  - `layering`
  - `cash_out`
  - `sanction_evasion`
  - `synthetic_identity`
- `label_is_aml`: danh dau nghieng ve hanh vi rua tien.
- `label_is_scam`: danh dau nghieng ve hanh vi lua dao.

## 3) Tieu chi muc rui ro
- `HIGH`:
  - Co tu 1 bang chung manh (vi du: chia nho giao dich + toc do cao + kenh cash-out nhanh).
  - Hoac co phan hoi xac nhan gian lan/rua tien.
  - Hoac co dau hieu rut can so du, tai khoan trung gian (mule), layering ro.
- `MEDIUM`:
  - Co nhieu tin hieu bat thuong nhung chua du bang chung ket luan.
  - Can canh bao va xac minh bo sung.
- `LOW`:
  - Hanh vi gan voi baseline lich su, khong co tin hieu rong.

## 4) Rule gan nhan nhanh theo tinh huong
- `mule_account`: nhan/chuyen lien tuc, fan-out cao, nhieu nguon nap khac nhau.
- `smurfing`: nhieu khoan nho trong 1h de ne nguong.
- `layering`: qua nhieu tai khoan trung gian trong thoi gian ngan.
- `cash_out`: nap vao roi rut/doi qua crypto, gift card, wallet topup nhanh.
- `account_takeover`: that bai dang nhap/giao dich tang dot bien, doi thiet bi/IP.

## 5) Quy trinh review 2 lop
- Lop 1 (analyst A): gan nhan ban dau + diem tu tin (`label_confidence`).
- Lop 2 (analyst B): kiem tra doc lap.
- Neu bat dong > 1 cap rui ro: chuyen senior reviewer phan xu.

## 6) Chat luong du lieu train
- Ti le khuyen nghi:
  - `LOW`: 60-75%
  - `MEDIUM`: 15-25%
  - `HIGH`: 10-15%
- Tranh leakage:
  - Khong dua truong `manual_blocked` vao feature train online.
- Time split:
  - Train: du lieu cu
  - Validation/Test: du lieu moi hon theo thoi gian.

## 7) KPI danh gia model
- Bat buoc:
  - Recall cho `HIGH`
  - Precision cho `HIGH`
  - FPR tren nhom `LOW`
  - Mean time to alert (MTTA)
- Muc tieu goi y:
  - Recall HIGH >= 0.92
  - Precision HIGH >= 0.55 (co the tang dan theo tung phase)

## 8) Mappings cho canh bao nguoi dung
- `HIGH`: canh bao do + tam dung + xac minh da lop.
- `MEDIUM`: canh bao vang + delay + xac nhan 2 buoc.
- `LOW`: thong bao theo doi + nhac khong chia se OTP/PIN.
