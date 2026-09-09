# -*- coding: utf-8 -*-
"""
CF 快取清除核心邏輯

讀取資料庫（cf_accounts 表）內設定的多組 Cloudflare 帳號（各自獨立的
Email + Global API Key，API Key 存放時已加密），對每組帳號底下的所有
網域 (zone) 執行 purge_everything。
"""

import asyncio
import os
from typing import Callable, Dict, List, Tuple

import aiohttp

# API 限制設定
MAX_CONCURRENT_REQUESTS = 5    # 同一帳號內同時進行的請求數量
REQUEST_DELAY = 0.5            # 每個請求之間的延遲（秒）
MAX_RETRIES = 3                # 重試次數
RETRY_DELAY = 2                # 重試延遲基準（秒，指數退避）

LogFn = Callable[[str], None]


def get_base_dir() -> str:
    """取得 certs/ 等執行期資料的存放目錄。

    預設放在原始碼外層的 data/ 資料夾（跟 app/ 平行），讓 app/ 保持純原始碼、
    方便進版控；容器化執行時可用環境變數 OPS_TOOLS_DATA_DIR 指定掛載的資料目錄
    （例如 /data）"""
    env_dir = os.environ.get("OPS_TOOLS_DATA_DIR")
    if env_dir:
        return env_dir
    return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data"))


def load_accounts() -> List[Dict[str, str]]:
    """從資料庫讀取目前設定的所有 Cloudflare 帳號（api_key 已解密）"""
    import db  # 延遲 import，避免 db.py／cf_purge_core.py 互相 import 造成循環相依

    accounts = db.list_cf_accounts(decrypt=True)
    if not accounts:
        raise ValueError("目前資料庫裡沒有任何 Cloudflare 帳號，請先到「CF 帳號管理」新增")
    return accounts


async def get_all_zones(session: aiohttp.ClientSession, headers: Dict[str, str], log: LogFn) -> List[Tuple[str, str]]:
    zones = []
    page = 1
    while True:
        url = f"https://api.cloudflare.com/client/v4/zones?page={page}&per_page=50"
        async with session.get(url, headers=headers) as resp:
            data = await resp.json()
            if not data.get("success") or not data.get("result"):
                log(f"⚠️ 無法取得 zones：{data}")
                break
            zones.extend(data["result"])
            if page >= data["result_info"]["total_pages"]:
                break
            page += 1
    return [(zone["id"], zone["name"]) for zone in zones]


async def purge_cache_with_retry(session, semaphore, headers, zone_id, zone_name, log: LogFn, retry_count=0):
    async with semaphore:
        try:
            if retry_count == 0:
                await asyncio.sleep(REQUEST_DELAY)

            url_api = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/purge_cache"
            payload = {"purge_everything": True}

            async with session.post(url_api, json=payload, headers=headers) as resp:
                result = await resp.json()

                if resp.status == 429:
                    if retry_count < MAX_RETRIES:
                        retry_delay = RETRY_DELAY * (2 ** retry_count)
                        log(f"[RETRY] API 限制觸發，{retry_delay} 秒後重試：{zone_name}（第 {retry_count + 1} 次）")
                        await asyncio.sleep(retry_delay)
                        return await purge_cache_with_retry(session, semaphore, headers, zone_id, zone_name, log, retry_count + 1)
                    log(f"[FAIL] 重試次數已達上限：{zone_name}")
                    return {"success": False, "error": "Max retries exceeded"}

                if result.get("success"):
                    log(f"[OK] 清除快取成功：{zone_name}")
                else:
                    log(f"[FAIL] 清除快取失敗：{zone_name} - {result}")

                return result

        except Exception as e:
            if retry_count < MAX_RETRIES:
                retry_delay = RETRY_DELAY * (2 ** retry_count)
                log(f"[ERROR] 發生錯誤，{retry_delay} 秒後重試：{zone_name} - {e}")
                await asyncio.sleep(retry_delay)
                return await purge_cache_with_retry(session, semaphore, headers, zone_id, zone_name, log, retry_count + 1)
            log(f"[FAIL] 錯誤重試次數已達上限：{zone_name} - {e}")
            return {"success": False, "error": str(e)}


async def purge_account(account: Dict[str, str], log: LogFn) -> Tuple[str, int, int]:
    """清除單一帳號底下所有網域的快取，回傳 (帳號名稱, 成功數, 總數)"""
    name = account["name"]
    headers = {
        "X-Auth-Email": account["email"],
        "X-Auth-Key": account["api_key"],
        "Content-Type": "application/json",
    }

    log(f"\n===== 帳號【{name}】開始 =====")
    async with aiohttp.ClientSession() as session:
        zones = await get_all_zones(session, headers, log)
        if not zones:
            log(f"⚠️ 帳號【{name}】沒有取得任何網域，請確認 Email / API Key 是否正確。")
            return name, 0, 0

        log(f"🔍 帳號【{name}】找到 {len(zones)} 個網域")
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        tasks = [
            purge_cache_with_retry(session, semaphore, headers, zone_id, zone_name, log)
            for zone_id, zone_name in zones
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        success_count = sum(1 for r in results if isinstance(r, dict) and r.get("success"))
        log(f"✅ 帳號【{name}】完成：{success_count}/{len(zones)} 成功")
        return name, success_count, len(zones)


async def purge_all_accounts(accounts: List[Dict[str, str]], log: LogFn):
    """同時處理多組帳號（帳號之間平行，帳號內部照原本節流邏輯）"""
    summaries = await asyncio.gather(*[purge_account(acc, log) for acc in accounts])

    log("\n========== 全部帳號處理完成 ==========")
    total_success = total_zones = 0
    for name, success_count, zone_count in summaries:
        log(f"帳號【{name}】：{success_count}/{zone_count} 成功")
        total_success += success_count
        total_zones += zone_count
    log(f"\n🎉 總計：{total_success}/{total_zones} 個網域清除成功")
