# -*- coding: utf-8 -*-
"""
資料庫層：使用者（帳密 + 角色）、Cloudflare 帳號（含加密後的 API Key）。

- 使用者存在 users 表，密碼用 werkzeug 的雜湊方式存，不是明文
- Cloudflare 帳號存在 cf_accounts 表，api_key 用 Fernet 對稱加密後才寫進去，
  金鑰可用環境變數 OPS_TOOLS_MASTER_KEY 指定；沒指定的話第一次啟動會自動產生
  一把並存到 data/master.key（跟 Jenkins 的 secrets/master.key 是同一種做法），
  之後都讀同一把，不會每次重啟就變、也不用使用者自己先產生好填進設定檔

角色（role）分三種：
- admin：所有功能都能用，含「使用者管理」「CF 帳號管理」
- operator：能執行清除快取／DNS／憑證等操作，不能管理使用者或 CF 帳號
- readonly：只能看清單（憑證、DNS 查詢結果、執行紀錄），不能執行任何操作
"""

import os
import time
from contextlib import contextmanager
from typing import Dict, List, Optional

import psycopg2
import psycopg2.extras
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import check_password_hash, generate_password_hash

ROLES = ("admin", "operator", "readonly")

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://opstools@db:5432/opstools")

_master_key_cache: Optional[str] = None


def _resolve_master_key() -> str:
    """優先用環境變數 OPS_TOOLS_MASTER_KEY；沒設定的話用 data/master.key（沒有就自動產生一把並存起來）"""
    global _master_key_cache
    if _master_key_cache:
        return _master_key_cache

    env_key = os.environ.get("OPS_TOOLS_MASTER_KEY", "").strip()
    if env_key:
        _master_key_cache = env_key
        return _master_key_cache

    from cf_purge_core import get_base_dir  # 延遲 import，避免跟 cf_purge_core 互相 import 造成循環相依

    key_path = os.path.join(get_base_dir(), "master.key")
    if os.path.exists(key_path):
        with open(key_path, "r", encoding="utf-8") as f:
            _master_key_cache = f.read().strip()
    else:
        _master_key_cache = Fernet.generate_key().decode()
        with open(key_path, "w", encoding="utf-8") as f:
            f.write(_master_key_cache)
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass  # Windows bind mount 可能不支援改權限，忽略即可，不影響功能
    return _master_key_cache


def _get_fernet() -> Fernet:
    try:
        return Fernet(_resolve_master_key().encode())
    except (ValueError, TypeError) as e:
        raise RuntimeError(f"OPS_TOOLS_MASTER_KEY / data/master.key 內容格式不正確：{e}") from e


def encrypt_value(plain: str) -> str:
    return _get_fernet().encrypt(plain.encode()).decode()


def decrypt_value(token: str) -> str:
    try:
        return _get_fernet().decrypt(token.encode()).decode()
    except InvalidToken as e:
        raise RuntimeError("解密失敗，OPS_TOOLS_MASTER_KEY 可能跟加密時不一致") from e


@contextmanager
def get_conn():
    if not DATABASE_URL:
        raise RuntimeError("尚未設定 DATABASE_URL 環境變數")
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def wait_for_db(max_retries: int = 30, delay: float = 1.0, log=print) -> None:
    """容器剛啟動時 Postgres 可能還沒 ready，重試等待"""
    last_err = None
    for attempt in range(1, max_retries + 1):
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
            return
        except Exception as e:
            last_err = e
            log(f"等待資料庫就緒...（第 {attempt}/{max_retries} 次）")
            time.sleep(delay)
    raise RuntimeError(f"連線資料庫逾時：{last_err}")


def init_schema() -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('admin', 'operator', 'readonly')),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            # 用 ALTER TABLE ... ADD COLUMN IF NOT EXISTS 補欄位：CREATE TABLE IF NOT EXISTS
            # 對已經存在的舊表不會生效，這樣升級時既有的 users 表也能補上新欄位
            cur.execute(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT true"
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS cf_accounts (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    api_key_encrypted TEXT NOT NULL,
                    ns TEXT[] NOT NULL DEFAULT '{}',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )


DEFAULT_ADMIN_PASSWORD = "admin123"


def bootstrap_admin(log=print) -> None:
    """第一次啟動、users 表還是空的時候，自動建立一組 admin 帳號，密碼固定為
    DEFAULT_ADMIN_PASSWORD，方便安裝當下就知道密碼、不用去翻 log；因為
    create_user() 建立的帳號 must_change_password 預設是 true，第一次登入
    還是會被強制要求改密碼，不會一直沿用這組固定密碼"""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM users")
            count = cur.fetchone()[0]
    if count > 0:
        return

    create_user("admin", DEFAULT_ADMIN_PASSWORD, "admin")
    log("=" * 64)
    log("首次啟動，已自動建立管理員帳號（第一次登入會被強制要求改密碼）：")
    log("  帳號：admin")
    log(f"  密碼：{DEFAULT_ADMIN_PASSWORD}")
    log("=" * 64)


# ---------------------------------------------------------------------------
# users
# ---------------------------------------------------------------------------

def create_user(username: str, password: str, role: str) -> int:
    if role not in ROLES:
        raise ValueError(f"role 必須是 {ROLES} 其中之一")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s) RETURNING id",
                (username, generate_password_hash(password), role),
            )
            return cur.fetchone()[0]


def list_users() -> List[Dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, username, role, must_change_password, created_at FROM users ORDER BY id"
            )
            return [dict(r) for r in cur.fetchall()]


def get_user_by_username(username: str) -> Optional[Dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            row = cur.fetchone()
            return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[Dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            row = cur.fetchone()
            return dict(row) if row else None


def authenticate(username: str, password: str) -> Optional[Dict]:
    user = get_user_by_username(username)
    if not user or not check_password_hash(user["password_hash"], password):
        return None
    return user


def verify_user_password(user_id: int, password: str) -> bool:
    """驗證「目前密碼」是否正確，供自助修改密碼流程使用"""
    user = get_user_by_id(user_id)
    if not user:
        return False
    return check_password_hash(user["password_hash"], password)


def count_admins() -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
            return cur.fetchone()[0]


def delete_user(user_id: int) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))


def update_user_password(user_id: int, new_password: str) -> None:
    """更新密碼，同時清掉 must_change_password（不管是自助改密碼還是強制改密碼流程都會呼叫這支）"""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET password_hash = %s, must_change_password = false WHERE id = %s",
                (generate_password_hash(new_password), user_id),
            )


# ---------------------------------------------------------------------------
# cf_accounts
# ---------------------------------------------------------------------------

def create_cf_account(name: str, email: str, api_key: str, ns: List[str]) -> int:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO cf_accounts (name, email, api_key_encrypted, ns) VALUES (%s, %s, %s, %s) RETURNING id",
                (name, email, encrypt_value(api_key), ns),
            )
            return cur.fetchone()[0]


def list_cf_accounts(decrypt: bool = False) -> List[Dict]:
    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id, name, email, api_key_encrypted, ns FROM cf_accounts ORDER BY id")
            rows = [dict(r) for r in cur.fetchall()]

    result = []
    for r in rows:
        entry = {"id": r["id"], "name": r["name"], "email": r["email"], "ns": r["ns"] or []}
        if decrypt:
            entry["api_key"] = decrypt_value(r["api_key_encrypted"])
        result.append(entry)
    return result


def update_cf_account(account_id: int, name: str, email: str, api_key: Optional[str], ns: List[str]) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            if api_key:
                cur.execute(
                    "UPDATE cf_accounts SET name=%s, email=%s, api_key_encrypted=%s, ns=%s WHERE id=%s",
                    (name, email, encrypt_value(api_key), ns, account_id),
                )
            else:
                cur.execute(
                    "UPDATE cf_accounts SET name=%s, email=%s, ns=%s WHERE id=%s",
                    (name, email, ns, account_id),
                )


def delete_cf_account(account_id: int) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM cf_accounts WHERE id = %s", (account_id,))
