# -*- coding: utf-8 -*-
"""
依網域 NS 找出所屬 Cloudflare 帳號，並對該帳號執行清除快取、
新增/刪除 DNS 紀錄（subdomain）操作，支援多網域批次新增/刪除。

不掃描全部帳號，而是先查詢網域目前的 NS，跟資料庫內每個帳號設定的
"ns" 欄位比對，找到唯一匹配的帳號後，才用該帳號的憑證呼叫 Cloudflare API。

批次新增/刪除都會逐筆處理（非同時併發）並在每筆之間間隔
BATCH_REQUEST_DELAY 秒，單一請求遇到 429 也會依指數退避重試，
且單次批次上限為 MAX_BATCH_SIZE 筆，避免觸發 Cloudflare rate limit。
"""

import asyncio
import re
from typing import Dict, List, Optional, Tuple

import aiohttp
import dns.resolver
import tldextract

from cf_purge_core import LogFn, purge_cache_with_retry

DNS_TIMEOUT = 5  # 秒
# 內網 / 公司預設 DNS 常常不回應 NS 查詢，改用公開 DNS 避免查不到
PUBLIC_DNS_SERVERS = ["1.1.1.1", "8.8.8.8"]

# API 限制設定（批次新增/刪除子網域用）
MAX_RETRIES = 3                    # 單一請求遇到 429 的重試次數
RETRY_DELAY = 2                    # 重試延遲基準（秒，指數退避）
BATCH_REQUEST_DELAY = 0.5          # 批次處理時，每個網域之間的間隔秒數
MAX_BATCH_SIZE = 50                # 批次新增/查詢/刪除單次最多處理的網域數，避免一次送出過多請求觸發 Cloudflare rate limit


async def _request_json(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    headers: Dict[str, str],
    json_body: Optional[Dict] = None,
    log: Optional[LogFn] = None,
    retry_count: int = 0,
) -> Dict:
    """呼叫 Cloudflare API 並解析 JSON，遇到 429 依指數退避重試"""
    async with session.request(method, url, headers=headers, json=json_body) as resp:
        if resp.status == 429:
            if retry_count < MAX_RETRIES:
                delay = RETRY_DELAY * (2 ** retry_count)
                if log:
                    log(f"[RETRY] API 限制觸發，{delay} 秒後重試...")
                await asyncio.sleep(delay)
                return await _request_json(session, method, url, headers, json_body, log, retry_count + 1)
            if log:
                log("[FAIL] 重試次數已達上限")
            return {"success": False, "errors": [{"message": "Max retries exceeded (429)"}]}
        return await resp.json()


def normalize_hostname(raw: str) -> str:
    """去除 https:// 前綴、路徑、port，只留主機名稱"""
    raw = raw.strip()
    raw = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", raw)
    raw = raw.split("/")[0]
    raw = raw.split(":")[0]
    return raw.rstrip(".").lower()


def get_registrable_domain(hostname: str) -> str:
    """從主機名稱取出註冊主體網域（例如 sub.example.com.tw -> example.com.tw）"""
    ext = tldextract.extract(hostname)
    if not ext.domain or not ext.suffix:
        raise ValueError(f"無法解析網域：{hostname}")
    return f"{ext.domain}.{ext.suffix}"


def lookup_ns_records(registrable_domain: str) -> List[str]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = PUBLIC_DNS_SERVERS
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    try:
        answers = resolver.resolve(registrable_domain, "NS")
    except Exception as e:
        raise RuntimeError(f"查詢 {registrable_domain} 的 NS 紀錄失敗：{e}")
    return sorted(str(r.target).rstrip(".").lower() for r in answers)


def resolve_account_by_domain(hostname: str, accounts: List[Dict]) -> Tuple[Dict, str, List[str]]:
    """回傳 (比對到的帳號, 註冊主體網域, 實際 NS 清單)；找不到或有多筆比對時丟例外"""
    hostname = normalize_hostname(hostname)
    registrable_domain = get_registrable_domain(hostname)
    actual_ns = lookup_ns_records(registrable_domain)
    actual_ns_set = set(actual_ns)

    matched = []
    for acc in accounts:
        configured_ns = {ns.rstrip(".").lower() for ns in acc.get("ns", []) if ns}
        if configured_ns and configured_ns & actual_ns_set:
            matched.append(acc)

    if not matched:
        raise LookupError(
            f"{registrable_domain} 目前的 NS（{', '.join(actual_ns)}）沒有比對到任何帳號，"
            f"請到「CF 帳號管理」確認各帳號的 ns 設定是否正確"
        )
    if len(matched) > 1:
        names = "、".join(a["name"] for a in matched)
        raise LookupError(
            f"{registrable_domain} 同時比對到多個帳號（{names}），"
            f"請到「CF 帳號管理」確認是否有帳號的 ns 設定重複"
        )

    return matched[0], registrable_domain, actual_ns


def build_headers(account: Dict) -> Dict[str, str]:
    return {
        "X-Auth-Email": account["email"],
        "X-Auth-Key": account["api_key"],
        "Content-Type": "application/json",
    }


async def get_zone_id(session: aiohttp.ClientSession, headers: Dict[str, str], registrable_domain: str) -> Tuple[str, str]:
    url = f"https://api.cloudflare.com/client/v4/zones?name={registrable_domain}"
    data = await _request_json(session, "GET", url, headers)
    if not data.get("success") or not data.get("result"):
        raise LookupError(f"在該帳號底下找不到網域 {registrable_domain}：{data}")
    zone = data["result"][0]
    return zone["id"], zone["name"]


async def purge_single_domain(hostname: str, accounts: List[Dict], log: LogFn):
    """依 NS 找出帳號後，只清除該網域所在 zone 的快取（不影響同帳號下其他網域）"""
    account, registrable_domain, actual_ns = resolve_account_by_domain(hostname, accounts)
    log(f"🔎 {registrable_domain} 的 NS：{', '.join(actual_ns)} → 比對到帳號【{account['name']}】")

    headers = build_headers(account)
    async with aiohttp.ClientSession() as session:
        zone_id, zone_name = await get_zone_id(session, headers, registrable_domain)
        semaphore = asyncio.Semaphore(1)
        result = await purge_cache_with_retry(session, semaphore, headers, zone_id, zone_name, log)
        if isinstance(result, dict) and result.get("success"):
            log(f"🎉 {zone_name}（帳號【{account['name']}】）快取清除成功")
        else:
            log(f"❌ {zone_name}（帳號【{account['name']}】）快取清除失敗")


async def add_dns_record(hostname: str, record_type: str, content: str, proxied: bool, accounts: List[Dict], log: LogFn):
    """新增單一 DNS 紀錄（供憑證簽發流程建立 _acme-challenge TXT 紀錄使用，不做批次/防呆處理）"""
    account, registrable_domain, actual_ns = resolve_account_by_domain(hostname, accounts)
    hostname = normalize_hostname(hostname)
    log(f"🔎 {registrable_domain} 的 NS：{', '.join(actual_ns)} → 比對到帳號【{account['name']}】")

    headers = build_headers(account)
    async with aiohttp.ClientSession() as session:
        zone_id, zone_name = await get_zone_id(session, headers, registrable_domain)

        payload = {
            "type": record_type,
            "name": hostname,
            "content": content,
            "ttl": 1,  # 1 = Auto
            "proxied": proxied if record_type in ("A", "AAAA", "CNAME") else False,
        }
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        result = await _request_json(session, "POST", url, headers, json_body=payload, log=log)

        if result.get("success"):
            log(f"✅ 新增成功：{hostname}（{record_type} → {content}），帳號【{account['name']}】、zone【{zone_name}】")
        else:
            log(f"❌ 新增失敗：{hostname} - {result}")


async def delete_dns_record(hostname: str, record_type: str, content: Optional[str], accounts: List[Dict], log: LogFn):
    """刪除單一 DNS 紀錄（供憑證簽發流程清除 _acme-challenge TXT 紀錄使用，不做批次/防呆處理）"""
    account, registrable_domain, actual_ns = resolve_account_by_domain(hostname, accounts)
    hostname = normalize_hostname(hostname)
    log(f"🔎 {registrable_domain} 的 NS：{', '.join(actual_ns)} → 比對到帳號【{account['name']}】")

    headers = build_headers(account)
    async with aiohttp.ClientSession() as session:
        zone_id, zone_name = await get_zone_id(session, headers, registrable_domain)

        query_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type={record_type}&name={hostname}"
        data = await _request_json(session, "GET", query_url, headers, log=log)
        records = data.get("result", []) if data.get("success") else []

        if content:
            records = [r for r in records if r.get("content") == content]

        if not records:
            log(f"⚠️ 找不到符合條件的紀錄：{hostname}（{record_type}），帳號【{account['name']}】")
            return

        if len(records) > 1:
            log(f"⚠️ 找到 {len(records)} 筆符合的紀錄，請加上「內容」條件以精確指定要刪除的那一筆：")
            for r in records:
                log(f"   - content={r.get('content')}（id={r['id']}）")
            return

        record = records[0]
        del_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record['id']}"
        result = await _request_json(session, "DELETE", del_url, headers, log=log)

        if result.get("success"):
            log(f"✅ 刪除成功：{hostname}（{record_type}），帳號【{account['name']}】、zone【{zone_name}】")
        else:
            log(f"❌ 刪除失敗：{hostname} - {result}")


async def list_dns_records(hostname: str, accounts: List[Dict], log: LogFn) -> List[Dict]:
    """列出某網域名稱底下所有 DNS 紀錄（不限類型），供刪除功能勾選使用"""
    hostname = normalize_hostname(hostname)
    account, registrable_domain, actual_ns = resolve_account_by_domain(hostname, accounts)
    account_index = accounts.index(account)
    log(f"🔎 {registrable_domain} 的 NS：{', '.join(actual_ns)} → 比對到帳號【{account['name']}】")

    headers = build_headers(account)
    async with aiohttp.ClientSession() as session:
        zone_id, zone_name = await get_zone_id(session, headers, registrable_domain)
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={hostname}"
        data = await _request_json(session, "GET", url, headers, log=log)

    if not data.get("success"):
        log(f"❌ 查詢 {hostname} 的 DNS 紀錄失敗：{data}")
        return []

    records = data.get("result", [])
    if not records:
        log(f"⚠️ {hostname} 目前沒有任何 DNS 紀錄")
    else:
        log(f"📋 {hostname} 找到 {len(records)} 筆紀錄")

    return [
        {
            "account_index": account_index,
            "account_name": account["name"],
            "zone_id": zone_id,
            "zone_name": zone_name,
            "record_id": r["id"],
            "hostname": r.get("name", hostname),
            "type": r.get("type"),
            "content": r.get("content"),
            "proxied": r.get("proxied", False),
        }
        for r in records
    ]


async def list_dns_records_batch(hostnames: List[str], accounts: List[Dict], log: LogFn) -> List[Dict]:
    """依序查詢多個網域的 DNS 紀錄，單一網域查詢失敗不影響其他網域，每筆之間間隔一段時間避免觸發限流"""
    if len(hostnames) > MAX_BATCH_SIZE:
        raise ValueError(f"一次最多查詢 {MAX_BATCH_SIZE} 個網域，請分批查詢")

    all_records: List[Dict] = []
    for i, hostname in enumerate(hostnames):
        try:
            all_records.extend(await list_dns_records(hostname, accounts, log))
        except Exception as e:
            log(f"❌ 查詢 {hostname} 失敗：{e}")
        if i < len(hostnames) - 1:
            await asyncio.sleep(BATCH_REQUEST_DELAY)
    return all_records


async def delete_dns_record_by_id(
    account_index: int,
    zone_id: str,
    zone_name: str,
    record_id: str,
    hostname: str,
    record_type: str,
    accounts: List[Dict],
    log: LogFn,
) -> bool:
    """依 list_dns_records 查出來的確切 record_id 刪除，不需要再用內容去猜是哪一筆"""
    if not (0 <= account_index < len(accounts)):
        raise ValueError("帳號索引無效，請重新查詢一次")
    account = accounts[account_index]
    headers = build_headers(account)
    async with aiohttp.ClientSession() as session:
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
        result = await _request_json(session, "DELETE", url, headers, log=log)

    if result.get("success"):
        log(f"✅ 刪除成功：{hostname}（{record_type}），帳號【{account['name']}】、zone【{zone_name}】")
        return True
    log(f"❌ 刪除失敗：{hostname}（{record_type}） - {result}")
    return False


async def delete_dns_records_batch(records: List[Dict], accounts: List[Dict], log: LogFn):
    """批次刪除多筆 DNS 紀錄（每筆需含 account_index/zone_id/zone_name/record_id/hostname/type），
    逐筆間隔處理避免觸發 Cloudflare rate limit"""
    if len(records) > MAX_BATCH_SIZE:
        raise ValueError(f"一次最多刪除 {MAX_BATCH_SIZE} 筆紀錄，請分批刪除")

    success_count = 0
    for i, r in enumerate(records):
        try:
            ok = await delete_dns_record_by_id(
                r["account_index"], r["zone_id"], r["zone_name"], r["record_id"],
                r["hostname"], r["type"], accounts, log,
            )
            if ok:
                success_count += 1
        except Exception as e:
            log(f"❌ 刪除 {r.get('hostname')} 失敗：{e}")
        if i < len(records) - 1:
            await asyncio.sleep(BATCH_REQUEST_DELAY)

    log(f"\n🎉 總計：{success_count}/{len(records)} 筆紀錄刪除成功")


async def add_dns_record_with_replace(
    hostname: str, record_type: str, content: str, proxied: bool, accounts: List[Dict], log: LogFn,
) -> bool:
    """新增一筆 DNS 紀錄；新增前先刪除同名同類型的舊紀錄，避免新增時因為解析本來就存在而衝突失敗"""
    hostname = normalize_hostname(hostname)
    account, registrable_domain, actual_ns = resolve_account_by_domain(hostname, accounts)
    log(f"🔎 {registrable_domain} 的 NS：{', '.join(actual_ns)} → 比對到帳號【{account['name']}】")

    headers = build_headers(account)
    async with aiohttp.ClientSession() as session:
        zone_id, zone_name = await get_zone_id(session, headers, registrable_domain)

        query_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type={record_type}&name={hostname}"
        data = await _request_json(session, "GET", query_url, headers, log=log)
        existing = data.get("result", []) if data.get("success") else []

        for r in existing:
            log(f"🧹 {hostname} 已存在同類型（{record_type}）舊紀錄（content={r.get('content')}），先刪除再新增")
            del_url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{r['id']}"
            await _request_json(session, "DELETE", del_url, headers, log=log)

        payload = {
            "type": record_type,
            "name": hostname,
            "content": content,
            "ttl": 1,  # 1 = Auto
            "proxied": proxied if record_type in ("A", "AAAA", "CNAME") else False,
        }
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        result = await _request_json(session, "POST", url, headers, json_body=payload, log=log)

    if result.get("success"):
        log(f"✅ 新增成功：{hostname}（{record_type} → {content}），帳號【{account['name']}】、zone【{zone_name}】")
        return True
    log(f"❌ 新增失敗：{hostname} - {result}")
    return False


async def add_dns_records_batch(
    entries: List[Dict[str, str]], record_type: str, proxied: bool, accounts: List[Dict], log: LogFn,
):
    """批次新增多個網域（entries 為 [{"domain": ..., "content": ...}, ...]），
    每筆都先刪除同類型舊紀錄再新增，逐筆間隔處理避免觸發 Cloudflare rate limit"""
    if len(entries) > MAX_BATCH_SIZE:
        raise ValueError(f"一次最多新增 {MAX_BATCH_SIZE} 個網域，請分批新增")

    success_count = 0
    for i, entry in enumerate(entries):
        domain = entry["domain"]
        content = entry["content"]
        try:
            ok = await add_dns_record_with_replace(domain, record_type, content, proxied, accounts, log)
            if ok:
                success_count += 1
        except Exception as e:
            log(f"❌ {domain} 新增失敗：{e}")
        if i < len(entries) - 1:
            await asyncio.sleep(BATCH_REQUEST_DELAY)

    log(f"\n🎉 總計：{success_count}/{len(entries)} 個網域新增成功")
