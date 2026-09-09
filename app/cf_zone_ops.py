# -*- coding: utf-8 -*-
"""
Cloudflare 網域層級設定：強制 HTTPS（Always Use HTTPS zone setting）、Page Rules。

沿用 cf_dns_ops 的帳號比對／重試／批次節流機制，不重新實作一套。
"""

import asyncio
from typing import Dict, List, Optional

import aiohttp

from cf_purge_core import LogFn
from cf_dns_ops import (
    BATCH_REQUEST_DELAY,
    MAX_BATCH_SIZE,
    _request_json,
    build_headers,
    get_registrable_domain,
    get_zone_id,
    normalize_hostname,
    resolve_account_by_domain,
)

# ---------------------------------------------------------------------------
# 強制 HTTPS（Always Use HTTPS zone setting）
# ---------------------------------------------------------------------------

async def set_always_use_https(hostname: str, enabled: bool, accounts: List[Dict], log: LogFn) -> bool:
    hostname = normalize_hostname(hostname)
    account, registrable_domain, actual_ns = resolve_account_by_domain(hostname, accounts)
    log(f"🔎 {registrable_domain} 的 NS：{', '.join(actual_ns)} → 比對到帳號【{account['name']}】")

    headers = build_headers(account)
    async with aiohttp.ClientSession() as session:
        zone_id, zone_name = await get_zone_id(session, headers, registrable_domain)
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/always_use_https"
        payload = {"value": "on" if enabled else "off"}
        result = await _request_json(session, "PATCH", url, headers, json_body=payload, log=log)

    state = "開啟" if enabled else "關閉"
    if result.get("success"):
        log(f"✅ {state}強制 HTTPS 成功：{zone_name}（帳號【{account['name']}】）")
        return True
    log(f"❌ {state}強制 HTTPS 失敗：{zone_name} - {result}")
    return False


async def set_always_use_https_batch(hostnames: List[str], enabled: bool, accounts: List[Dict], log: LogFn):
    if len(hostnames) > MAX_BATCH_SIZE:
        raise ValueError(f"一次最多處理 {MAX_BATCH_SIZE} 個網域，請分批處理")

    success_count = 0
    for i, hostname in enumerate(hostnames):
        try:
            ok = await set_always_use_https(hostname, enabled, accounts, log)
            if ok:
                success_count += 1
        except Exception as e:
            log(f"❌ {hostname} 設定失敗：{e}")
        if i < len(hostnames) - 1:
            await asyncio.sleep(BATCH_REQUEST_DELAY)

    log(f"\n🎉 總計：{success_count}/{len(hostnames)} 個網域設定成功")


# ---------------------------------------------------------------------------
# Page Rules
# ---------------------------------------------------------------------------

ACTION_LABELS = {
    "forwarding_url": "網址轉發",
    "always_use_https": "強制 HTTPS",
    "cache_level": "快取層級",
    "security_level": "安全性等級",
}

CACHE_LEVEL_LABELS = {
    "bypass": "Bypass（不快取）",
    "basic": "Basic",
    "simplified": "Simplified",
    "aggressive": "Aggressive",
    "cache_everything": "Cache Everything（全部快取）",
}

SECURITY_LEVEL_LABELS = {
    "off": "Off",
    "essentially_off": "Essentially Off",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "under_attack": "Under Attack",
}


def _describe_action(action: Dict) -> str:
    action_id = action.get("id")
    label = ACTION_LABELS.get(action_id, action_id)
    value = action.get("value")
    if action_id == "forwarding_url" and isinstance(value, dict):
        return f"{label} → {value.get('url')}（{value.get('status_code')}）"
    if action_id == "cache_level" and isinstance(value, str):
        return f"{label}：{CACHE_LEVEL_LABELS.get(value, value)}"
    if action_id == "security_level" and isinstance(value, str):
        return f"{label}：{SECURITY_LEVEL_LABELS.get(value, value)}"
    if value not in (None, ""):
        return f"{label}：{value}"
    return label


def build_page_rule_action(action_type: str, params: Dict) -> Dict:
    """依動作類型組出 Cloudflare Page Rule 的 actions[] 元素，並驗證參數"""
    if action_type == "forwarding_url":
        target_url = (params.get("target_url") or "").strip()
        if not target_url:
            raise ValueError("網址轉發需要填「目標網址」")
        status_code = int(params.get("status_code") or 301)
        if status_code not in (301, 302):
            raise ValueError("狀態碼只能是 301 或 302")
        return {"id": "forwarding_url", "value": {"url": target_url, "status_code": status_code}}

    if action_type == "always_use_https":
        return {"id": "always_use_https"}

    if action_type == "cache_level":
        value = params.get("cache_level")
        if value not in CACHE_LEVEL_LABELS:
            raise ValueError(f"快取層級必須是 {'/'.join(CACHE_LEVEL_LABELS)} 其中之一")
        return {"id": "cache_level", "value": value}

    if action_type == "security_level":
        value = params.get("security_level")
        if value not in SECURITY_LEVEL_LABELS:
            raise ValueError(f"安全性等級必須是 {'/'.join(SECURITY_LEVEL_LABELS)} 其中之一")
        return {"id": "security_level", "value": value}

    raise ValueError(f"不支援的動作類型：{action_type}")


async def list_page_rules(hostname: str, accounts: List[Dict], log: LogFn) -> List[Dict]:
    """列出某網域所在 zone 底下所有 Page Rule"""
    hostname = normalize_hostname(hostname)
    account, registrable_domain, actual_ns = resolve_account_by_domain(hostname, accounts)
    account_index = accounts.index(account)
    log(f"🔎 {registrable_domain} 的 NS：{', '.join(actual_ns)} → 比對到帳號【{account['name']}】")

    headers = build_headers(account)
    async with aiohttp.ClientSession() as session:
        zone_id, zone_name = await get_zone_id(session, headers, registrable_domain)
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/pagerules"
        data = await _request_json(session, "GET", url, headers, log=log)

    if not data.get("success"):
        log(f"❌ 查詢 Page Rules 失敗：{zone_name} - {data}")
        return []

    rules = data.get("result", [])
    if not rules:
        log(f"⚠️ {zone_name} 目前沒有任何 Page Rule")
    else:
        log(f"📋 {zone_name} 找到 {len(rules)} 筆 Page Rule")

    result = []
    for r in rules:
        targets = r.get("targets") or []
        pattern = targets[0]["constraint"]["value"] if targets else ""
        actions = r.get("actions") or []
        action_desc = "、".join(_describe_action(a) for a in actions) or "（無動作）"
        result.append({
            "account_index": account_index,
            "zone_id": zone_id,
            "zone_name": zone_name,
            "rule_id": r["id"],
            "pattern": pattern,
            "action_desc": action_desc,
            "priority": r.get("priority"),
            "status": r.get("status"),
        })
    return result


async def create_page_rule(
    hostname: str,
    pattern: str,
    action_type: str,
    params: Dict,
    priority: int,
    status: str,
    accounts: List[Dict],
    log: LogFn,
) -> bool:
    hostname = normalize_hostname(hostname)
    account, registrable_domain, actual_ns = resolve_account_by_domain(hostname, accounts)
    log(f"🔎 {registrable_domain} 的 NS：{', '.join(actual_ns)} → 比對到帳號【{account['name']}】")

    action = build_page_rule_action(action_type, params)

    headers = build_headers(account)
    async with aiohttp.ClientSession() as session:
        zone_id, zone_name = await get_zone_id(session, headers, registrable_domain)
        payload = {
            "targets": [{"target": "url", "constraint": {"operator": "matches", "value": pattern}}],
            "actions": [action],
            "priority": priority,
            "status": status,
        }
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/pagerules"
        result = await _request_json(session, "POST", url, headers, json_body=payload, log=log)

    if result.get("success"):
        log(f"✅ 新增 Page Rule 成功：{pattern} → {ACTION_LABELS.get(action_type, action_type)}，zone【{zone_name}】")
        return True
    log(f"❌ 新增 Page Rule 失敗：{pattern} - {result}")
    return False


async def create_page_rules_batch(
    entries: List[Dict[str, str]],
    action_type: str,
    params: Dict,
    priority: int,
    status: str,
    accounts: List[Dict],
    log: LogFn,
):
    """批次新增多筆 Page Rule（entries 為 [{"domain": ..., "pattern": ...}, ...]），
    每筆套用相同的動作／優先序／狀態設定，逐筆間隔處理避免觸發 Cloudflare rate limit"""
    if len(entries) > MAX_BATCH_SIZE:
        raise ValueError(f"一次最多新增 {MAX_BATCH_SIZE} 筆 Page Rule，請分批新增")

    success_count = 0
    for i, entry in enumerate(entries):
        domain = entry["domain"]
        pattern = entry["pattern"]
        try:
            ok = await create_page_rule(domain, pattern, action_type, params, priority, status, accounts, log)
            if ok:
                success_count += 1
        except Exception as e:
            log(f"❌ {domain}（{pattern}）新增 Page Rule 失敗：{e}")
        if i < len(entries) - 1:
            await asyncio.sleep(BATCH_REQUEST_DELAY)

    log(f"\n🎉 總計：{success_count}/{len(entries)} 筆 Page Rule 新增成功")


async def delete_page_rule_by_id(
    account_index: int,
    zone_id: str,
    zone_name: str,
    rule_id: str,
    pattern: str,
    accounts: List[Dict],
    log: LogFn,
) -> bool:
    if not (0 <= account_index < len(accounts)):
        raise ValueError("帳號索引無效，請重新查詢一次")
    account = accounts[account_index]
    headers = build_headers(account)
    async with aiohttp.ClientSession() as session:
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/pagerules/{rule_id}"
        result = await _request_json(session, "DELETE", url, headers, log=log)

    if result.get("success"):
        log(f"✅ 刪除成功：{pattern}，zone【{zone_name}】（帳號【{account['name']}】）")
        return True
    log(f"❌ 刪除失敗：{pattern} - {result}")
    return False


async def delete_page_rules_batch(rules: List[Dict], accounts: List[Dict], log: LogFn):
    if len(rules) > MAX_BATCH_SIZE:
        raise ValueError(f"一次最多刪除 {MAX_BATCH_SIZE} 筆，請分批刪除")

    success_count = 0
    for i, r in enumerate(rules):
        try:
            ok = await delete_page_rule_by_id(
                r["account_index"], r["zone_id"], r["zone_name"], r["rule_id"], r["pattern"], accounts, log,
            )
            if ok:
                success_count += 1
        except Exception as e:
            log(f"❌ 刪除失敗：{e}")
        if i < len(rules) - 1:
            await asyncio.sleep(BATCH_REQUEST_DELAY)

    log(f"\n🎉 總計：{success_count}/{len(rules)} 筆 Page Rule 刪除成功")


# ---------------------------------------------------------------------------
# Zone 管理（新增／刪除網域）
# ---------------------------------------------------------------------------

async def get_cf_account_id(session: aiohttp.ClientSession, headers: Dict[str, str], log: LogFn) -> tuple:
    """建立 zone 時，Cloudflare 要求指定歸屬的帳號 ID（跟這組 Email/API Key 本身是兩回事）；
    一組憑證底下通常只有一個 Cloudflare 帳號，有多個的話取第一個並記錄警告"""
    url = "https://api.cloudflare.com/client/v4/accounts?per_page=50"
    data = await _request_json(session, "GET", url, headers, log=log)
    if not data.get("success") or not data.get("result"):
        raise LookupError(f"取得 Cloudflare 帳號清單失敗，請確認 Email/API Key 是否正確：{data}")

    result = data["result"]
    if len(result) > 1:
        names = "、".join(a.get("name", a["id"]) for a in result)
        log(f"⚠️ 這組憑證底下有多個 Cloudflare 帳號（{names}），預設使用第一個：{result[0].get('name')}")
    acc = result[0]
    return acc["id"], acc.get("name", acc["id"])


async def create_zone(hostname: str, account_name: str, jump_start: bool, accounts: List[Dict], log: LogFn) -> Optional[Dict]:
    """新增一個網域到 Cloudflare（zone 一定是註冊主體網域，不是子網域）；
    建立後 Cloudflare 會指派新的 NS，需要自己到網域註冊商更新才會生效"""
    hostname = normalize_hostname(hostname)
    domain = get_registrable_domain(hostname)

    account = next((a for a in accounts if a["name"] == account_name), None)
    if not account:
        raise ValueError(f"找不到帳號：{account_name}")

    headers = build_headers(account)
    async with aiohttp.ClientSession() as session:
        cf_account_id, cf_account_name = await get_cf_account_id(session, headers, log)
        payload = {"name": domain, "account": {"id": cf_account_id}, "jump_start": jump_start}
        url = "https://api.cloudflare.com/client/v4/zones"
        result = await _request_json(session, "POST", url, headers, json_body=payload, log=log)

    if result.get("success"):
        zone = result["result"]
        ns_list = zone.get("name_servers") or []
        log(f"✅ 建立 Zone 成功：{domain}（帳號【{account['name']}】／Cloudflare 帳號【{cf_account_name}】）")
        if ns_list:
            log(f"📌 請到網域註冊商，把 {domain} 的 NS 改成：{', '.join(ns_list)}（改完生效前，這個網域還不會走 Cloudflare）")
        else:
            log("📌 Cloudflare 沒有立即回傳指派的 NS，請稍後到 Cloudflare 後台該 zone 的 Overview 查看")
        return zone
    log(f"❌ 建立 Zone 失敗：{domain} - {result}")
    return None


async def delete_zone(hostname: str, accounts: List[Dict], log: LogFn) -> bool:
    """刪除整個 zone，連同底下所有 DNS 紀錄、Page Rule、SSL 設定等一併移除，無法復原"""
    account, registrable_domain, actual_ns = resolve_account_by_domain(hostname, accounts)
    log(f"🔎 {registrable_domain} 的 NS：{', '.join(actual_ns)} → 比對到帳號【{account['name']}】")

    headers = build_headers(account)
    async with aiohttp.ClientSession() as session:
        zone_id, zone_name = await get_zone_id(session, headers, registrable_domain)
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}"
        result = await _request_json(session, "DELETE", url, headers, log=log)

    if result.get("success"):
        log(f"✅ 刪除 Zone 成功：{zone_name}（帳號【{account['name']}】），這個 zone 底下所有設定已一併移除")
        return True
    log(f"❌ 刪除 Zone 失敗：{zone_name} - {result}")
    return False
