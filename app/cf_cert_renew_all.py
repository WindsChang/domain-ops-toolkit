# -*- coding: utf-8 -*-
"""
批次檢查 certs/ 底下所有已簽發的憑證，剩餘天數低於門檻（預設 7 天）就自動重新簽發（續期）。
續期後重新掃描，若仍是過期狀態（代表續期一直失敗），會直接刪除該憑證資料夾。

設計給排程工具（例如 Windows 工作排程器）定期呼叫，非互動執行，
所有結果寫進 certs/renew.log，不會跳出任何畫面。

用法：
    python cf_cert_renew_all.py                # 用預設 7 天門檻，正式環境簽發
    python cf_cert_renew_all.py --days 14      # 改成 14 天門檻
    python cf_cert_renew_all.py --staging      # 用 Let's Encrypt 測試環境（僅供測試排程本身是否正常運作）

排入 Windows 工作排程器範例（每天凌晨 3 點執行一次）：
    程式：python.exe
    引數：C:\\path\\to\\domain-ops-toolkit\\cf_cert_renew_all.py
    起始位置：C:\\path\\to\\domain-ops-toolkit
"""

import argparse
import asyncio
import datetime
import os

import db
from cf_cert_ops import certs_dir, delete_local_cert, issue_certificate, list_local_certs
from cf_purge_core import load_accounts

DEFAULT_THRESHOLD_DAYS = 7


def _log_path() -> str:
    return os.path.join(certs_dir(), "renew.log")


def _log_to_file(message: str):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(_log_path(), "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {message}\n")


async def renew_all(threshold_days: int = DEFAULT_THRESHOLD_DAYS, staging: bool = False):
    db.wait_for_db(log=_log_to_file)
    db.init_schema()  # 獨立跑這支腳本時（沒先啟動過主服務）schema 可能還不存在，這裡確保一定有
    accounts = load_accounts()
    certs = list_local_certs()
    due = [c for c in certs if c["days_left"] <= threshold_days]

    _log_to_file(f"=== 開始檢查，共有 {len(certs)} 張憑證，{len(due)} 張需要續期（門檻 {threshold_days} 天）===")

    for cert in due:
        domains = cert["domains"]
        label = "、".join(domains)
        _log_to_file(f"--- 續期 {label}（剩 {cert['days_left']} 天）---")
        try:
            await issue_certificate(domains, accounts, _log_to_file, staging=staging)
        except Exception as e:
            _log_to_file(f"❌ {label} 續期失敗：{e}")

    # 續期後重新掃描：如果還是過期狀態（代表續期一直失敗），直接刪除該憑證資料夾
    expired = [c for c in list_local_certs() if c["days_left"] < 0]
    for cert in expired:
        label = "、".join(cert["domains"])
        try:
            delete_local_cert(cert["hostname"])
            _log_to_file(f"🗑️ 已刪除過期憑證：{label}（certs/{cert['hostname']}/）")
        except Exception as e:
            _log_to_file(f"❌ 刪除過期憑證失敗：{label} - {e}")

    _log_to_file("=== 檢查結束 ===")


def main():
    parser = argparse.ArgumentParser(description="批次續期即將到期的 Let's Encrypt 憑證")
    parser.add_argument("--days", type=int, default=DEFAULT_THRESHOLD_DAYS, help="剩餘天數低於這個門檻就續期，預設 7")
    parser.add_argument("--staging", action="store_true", help="使用 Let's Encrypt 測試環境（僅供測試排程本身）")
    args = parser.parse_args()

    asyncio.run(renew_all(threshold_days=args.days, staging=args.staging))


if __name__ == "__main__":
    main()
