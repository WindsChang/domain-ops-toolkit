# -*- coding: utf-8 -*-
"""
Let's Encrypt 公開憑證簽發 / 續期（DNS-01 驗證）

流程：
1. 依網域 NS 找出所屬 Cloudflare 帳號（沿用 cf_dns_ops 的機制）
2. 跟 Let's Encrypt 申請憑證訂單，取得 DNS-01 挑戰值
3. 用該帳號的憑證，在 _acme-challenge.<網域> 建立 TXT 紀錄
4. 等 DNS 生效、確認查得到後，通知 Let's Encrypt 驗證並完成簽發
5. 刪除臨時的 TXT 紀錄
6. 把憑證（fullchain.pem）、私鑰（privkey.pem）存到 certs/<網域>/，只產生檔案，不做任何部署動作

Let's Encrypt 帳號金鑰只會在第一次使用時產生一次，之後重複使用（存在 certs/_acme_account_key.pem）。
"""

import os
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Union

import josepy as jose
from acme import challenges
from acme import client as acme_client
from acme import errors as acme_errors
from acme import messages as acme_messages
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

import asyncio

from cf_purge_core import LogFn, get_base_dir
from cf_dns_ops import (
    DNS_TIMEOUT,
    PUBLIC_DNS_SERVERS,
    add_dns_record,
    delete_dns_record,
    normalize_hostname,
    resolve_account_by_domain,
)

LE_PRODUCTION_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
LE_STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"

CERTS_DIR_NAME = "certs"
ACCOUNT_KEY_FILENAME = "_acme_account_key.pem"

DNS_PROPAGATION_WAIT = 20  # 建立 TXT 後，通知 ACME 驗證前先等待的秒數
DNS_POLL_INTERVAL = 5
DNS_POLL_MAX_TRIES = 12  # 5 * 12 = 60 秒


def certs_dir() -> str:
    path = os.path.join(get_base_dir(), CERTS_DIR_NAME)
    os.makedirs(path, exist_ok=True)
    return path


def _load_or_create_account_key() -> jose.JWKRSA:
    path = os.path.join(certs_dir(), ACCOUNT_KEY_FILENAME)
    if os.path.exists(path):
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
    return jose.JWKRSA(key=jose.ComparableRSAKey(key))


def _new_acme_client(staging: bool) -> acme_client.ClientV2:
    directory_url = LE_STAGING_DIRECTORY if staging else LE_PRODUCTION_DIRECTORY
    account_key = _load_or_create_account_key()
    net = acme_client.ClientNetwork(account_key, user_agent="cf-tool/1.0")
    directory = acme_messages.Directory.from_json(net.get(directory_url).json())
    return acme_client.ClientV2(directory, net=net)


def _ensure_registration(acme: acme_client.ClientV2, email: str):
    """註冊 ACME 帳號；帳號金鑰已經註冊過的話，補撈回帳號資訊並設回 client，
    否則之後的請求會因為 JWS 缺少 Key ID 而失敗"""
    try:
        acme.new_account(acme_messages.NewRegistration.from_data(email=email, terms_of_service_agreed=True))
    except acme_errors.ConflictError as e:
        regr = acme_messages.RegistrationResource(uri=e.location, body=acme_messages.Registration())
        acme.query_registration(regr)


def _generate_domain_key_and_csr(hostnames: List[str]):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostnames[0])]))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in hostnames]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, csr


def _lookup_txt_records(name: str) -> List[str]:
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = PUBLIC_DNS_SERVERS
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    try:
        answers = resolver.resolve(name, "TXT")
    except Exception:
        return []
    return [
        "".join(part.decode() if isinstance(part, bytes) else part for part in r.strings)
        for r in answers
    ]


async def issue_certificate(hostnames: Union[str, List[str]], accounts: List[Dict], log: LogFn, staging: bool = True) -> str:
    """簽發（或續期）一張 Let's Encrypt 憑證，可一次簽發多網域 (SAN) 憑證。
    輸出到 certs/<第一個網域>/，回傳輸出資料夾路徑"""
    if isinstance(hostnames, str):
        hostnames = [hostnames]
    hostnames = list(dict.fromkeys(normalize_hostname(h) for h in hostnames if h and h.strip()))
    if not hostnames:
        raise ValueError("請至少輸入一個網域")

    primary = hostnames[0]
    domain_label = "、".join(hostnames)

    # 先逐一驗證每個網域都能比對到帳號，避免建立 order 後才失敗
    first_account = None
    for h in hostnames:
        account, registrable_domain, actual_ns = resolve_account_by_domain(h, accounts)
        log(f"🔎 {registrable_domain} 的 NS：{', '.join(actual_ns)} → 比對到帳號【{account['name']}】")
        if first_account is None:
            first_account = account

    env_label = "測試環境 staging（不計入正式簽發額度，但瀏覽器不信任）" if staging else "正式環境 production"
    log(f"🌐 使用 Let's Encrypt {env_label} 簽發 {domain_label}")

    try:
        acme = await asyncio.to_thread(_new_acme_client, staging)
        await asyncio.to_thread(_ensure_registration, acme, first_account["email"])

        domain_key, csr = _generate_domain_key_and_csr(hostnames)
        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        order = await asyncio.to_thread(acme.new_order, csr_pem)
    except acme_errors.Error as e:
        raise RuntimeError(f"跟 Let's Encrypt 建立訂單失敗：{e}") from e

    # (網域, TXT 紀錄名稱, 驗證值, challenge) 清單，每個網域各自要建立/驗證一筆 DNS-01 TXT 紀錄
    pending = []
    try:
        for authz in order.authorizations:
            domain = authz.body.identifier.value
            challb = next(c for c in authz.body.challenges if isinstance(c.chall, challenges.DNS01))
            digest = challb.chall.validation(acme.net.key)
            record_name = f"_acme-challenge.{domain}"

            log(f"📝 建立 DNS 驗證紀錄：{record_name}（TXT）")
            await add_dns_record(record_name, "TXT", digest, False, accounts, log)
            pending.append((domain, record_name, digest, challb))

        log(f"⏳ 等待 DNS 生效（{DNS_PROPAGATION_WAIT} 秒）...")
        await asyncio.sleep(DNS_PROPAGATION_WAIT)

        unconfirmed = list(pending)
        for attempt in range(1, DNS_POLL_MAX_TRIES + 1):
            still_pending = []
            for item in unconfirmed:
                domain, record_name, digest, challb = item
                values = await asyncio.to_thread(_lookup_txt_records, record_name)
                if digest in values:
                    log(f"✅ 已查到 DNS 驗證紀錄：{record_name}")
                else:
                    still_pending.append(item)
            unconfirmed = still_pending
            if not unconfirmed:
                break
            names = "、".join(record_name for _, record_name, _, _ in unconfirmed)
            log(f"🔁 {names} 尚未查到驗證紀錄，{DNS_POLL_INTERVAL} 秒後重試（{attempt}/{DNS_POLL_MAX_TRIES}）")
            await asyncio.sleep(DNS_POLL_INTERVAL)

        if unconfirmed:
            names = "、".join(record_name for _, record_name, _, _ in unconfirmed)
            raise RuntimeError(f"{names} 的 TXT 驗證紀錄一直查不到，請確認 DNS 是否正確建立、或該帳號是否有權限操作這個 zone")

        try:
            for domain, record_name, digest, challb in pending:
                log(f"📮 通知 Let's Encrypt 進行驗證：{domain}...")
                await asyncio.to_thread(acme.answer_challenge, challb, challb.chall.response(acme.net.key))

            log("⏳ 等待驗證與簽發結果...")
            finalized_order = await asyncio.to_thread(acme.poll_and_finalize, order)
        except acme_errors.Error as e:
            raise RuntimeError(f"Let's Encrypt 驗證/簽發失敗：{e}") from e

    finally:
        for domain, record_name, digest, challb in pending:
            log(f"🧹 清除臨時的 DNS 驗證紀錄：{record_name}")
            await delete_dns_record(record_name, "TXT", digest, accounts, log)

    out_dir = os.path.join(certs_dir(), primary)
    os.makedirs(out_dir, exist_ok=True)

    with open(os.path.join(out_dir, "privkey.pem"), "wb") as f:
        f.write(domain_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(os.path.join(out_dir, "fullchain.pem"), "w", encoding="utf-8") as f:
        f.write(finalized_order.fullchain_pem)

    cert = x509.load_pem_x509_certificate(finalized_order.fullchain_pem.encode())
    not_after = cert.not_valid_after_utc
    log(f"🎉 憑證簽發成功：{domain_label}，到期日 {not_after:%Y-%m-%d}，已存到 certs/{primary}/")

    return out_dir


def list_local_certs() -> List[Dict]:
    """掃描 certs/ 底下每個網域資料夾，回傳到期資訊列表（新到舊排序不重要，依名稱排序）。
    憑證主體名稱 (CN)、主體別名 (SAN，即簽發時的完整網域清單) 都直接從憑證檔案本身讀取，
    不另外存中繼資料，確保跟實際簽出的憑證內容一致"""
    base = certs_dir()
    result = []
    for name in sorted(os.listdir(base)):
        cert_path = os.path.join(base, name, "fullchain.pem")
        if not os.path.isfile(cert_path):
            continue
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        not_after = cert.not_valid_after_utc
        days_left = (not_after - datetime.now(timezone.utc)).days

        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = cn_attrs[0].value if cn_attrs else name

        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            domains = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            domains = [common_name]

        result.append({
            "hostname": name,
            "common_name": common_name,
            "domains": domains,
            "not_after": not_after.strftime("%Y-%m-%d"),
            "days_left": days_left,
        })
    return result


def _resolve_cert_dir(hostname: str) -> str:
    """依資料夾名稱找出憑證所在路徑，同時擋掉路徑跳脫（.. 等）"""
    hostname = (hostname or "").strip()
    if not hostname or hostname in (".", "..") or hostname != os.path.basename(hostname):
        raise ValueError("無效的憑證名稱")
    path = os.path.join(certs_dir(), hostname)
    if not os.path.isfile(os.path.join(path, "fullchain.pem")):
        raise LookupError(f"找不到憑證：{hostname}")
    return path


def build_cert_archive(hostname: str) -> Tuple[bytes, str]:
    """把 fullchain.pem + privkey.pem 打包成 zip，回傳 (zip 內容 bytes, 建議下載檔名)"""
    import io
    import zipfile

    cert_dir = _resolve_cert_dir(hostname)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(os.path.join(cert_dir, "fullchain.pem"), "fullchain.pem")
        privkey_path = os.path.join(cert_dir, "privkey.pem")
        if os.path.isfile(privkey_path):
            zf.write(privkey_path, "privkey.pem")
    return buffer.getvalue(), f"{hostname}.zip"


def delete_local_cert(hostname: str) -> None:
    """刪除整個憑證資料夾（憑證、私鑰都會一併移除，此動作無法復原）"""
    import shutil

    cert_dir = _resolve_cert_dir(hostname)
    shutil.rmtree(cert_dir)
