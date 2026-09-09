# -*- coding: utf-8 -*-
"""
Domain Ops Toolkit 網頁版（僅限本機 localhost 使用）

多使用者帳密登入（帳號/角色/CF 帳號都存在資料庫），角色分三種：
- admin：所有功能，含「使用者管理」「CF 帳號管理」
- operator：能執行清除快取／DNS／憑證等操作，不能管理使用者或 CF 帳號
- readonly：只能看清單，不能執行任何操作

功能：
1. 用勾選清單指定要清除快取的帳號（預設全選 = 清除全部帳號）
2. 輸入網域，自動依 NS 比對出所屬帳號，只清除該網域的快取
3. 輸入一個或多個網域，批次新增該網域下的 DNS 紀錄（subdomain）；新增前會先刪除同名同類型的舊紀錄，避免解析本來就存在造成衝突
4. 輸入一個或多個網域先查詢目前的 DNS 紀錄，再從查詢結果勾選要刪除的紀錄，批次刪除
5. 輸入一個或多個網域，簽發 / 續期 Let's Encrypt 公開憑證（DNS-01 驗證，可簽發多網域 SAN 憑證，只產生檔案，不做部署）
6. 下載過往簽發的憑證（fullchain.pem + privkey.pem 打包成 zip），或手動刪除不需要的憑證資料夾

批次新增/查詢/刪除 DNS 紀錄都會逐筆處理並間隔一段時間、單次上限 50 筆，避免觸發 Cloudflare API 的流量限制。

畫面透過輪詢顯示即時進度，同一時間只允許一個工作在執行。
"""

import asyncio
import io
import json
import os
import re
import threading
from functools import wraps

from flask import Flask, jsonify, redirect, render_template, request, send_file, session, url_for

import db
from cf_purge_core import load_accounts, purge_all_accounts
from cf_dns_ops import (
    add_dns_records_batch,
    delete_dns_records_batch,
    list_dns_records_batch,
    purge_single_domain,
)
from cf_cert_ops import build_cert_archive, delete_local_cert, issue_certificate, list_local_certs
from cf_zone_ops import (
    create_page_rules_batch,
    create_zone,
    delete_page_rules_batch,
    delete_zone,
    list_page_rules,
    set_always_use_https_batch,
)

app = Flask(__name__)
app.secret_key = os.urandom(24)  # 僅本機使用，重啟後需要重新登入

LOG_LINES = []
RUNNING = False
LOCK = threading.Lock()


def _init_db_startup():
    """啟動時：等 DB 就緒 → 建表 → 沒有使用者就自動建立 admin。任一步驟失敗都印出來，
    但不讓整個程式起不來（例如 DB 還沒設定好時，畫面上至少看得到清楚的錯誤訊息）"""
    try:
        db.wait_for_db(log=print)
        db.init_schema()
        db.bootstrap_admin(log=print)
    except Exception as e:
        print(f"[STARTUP] 資料庫初始化失敗：{e}")


_init_db_startup()


def _ensure_logged_in():
    """回傳 None 表示可以繼續往下走；否則回傳應該直接回應的結果（導去登入頁或強制改密碼頁）"""
    if not session.get("user_id"):
        return redirect(url_for("login"))
    if session.get("must_change_password"):
        return redirect(url_for("force_change_password"))
    return None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        blocker = _ensure_logged_in()
        if blocker is not None:
            return blocker
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    """限定角色才能呼叫的 API；未登入導去登入頁，角色不符回 403"""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            blocker = _ensure_logged_in()
            if blocker is not None:
                return blocker
            if session.get("role") not in roles:
                return jsonify(ok=False, message="權限不足，這個操作需要更高的角色權限"), 403
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        try:
            user = db.authenticate(username, password)
        except Exception as e:
            error = str(e)
            user = None
        else:
            if user:
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                session["must_change_password"] = user["must_change_password"]
                return redirect(url_for("index"))
            error = "帳號或密碼錯誤"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/force-change-password", methods=["GET", "POST"])
def force_change_password():
    """第一次登入（或被管理員新增的帳號第一次登入）強制先改密碼，改完才能進主畫面"""
    if not session.get("user_id"):
        return redirect(url_for("login"))
    if not session.get("must_change_password"):
        return redirect(url_for("index"))

    error = None
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        if len(new_password) < 8:
            error = "新密碼至少需要 8 個字元"
        elif new_password != confirm_password:
            error = "兩次輸入的新密碼不一致"
        else:
            db.update_user_password(session["user_id"], new_password)
            session["must_change_password"] = False
            return redirect(url_for("index"))
    return render_template("force_change_password.html", error=error, username=session.get("username"))


@app.route("/api/change-password", methods=["POST"])
@login_required
def api_change_password():
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not db.verify_user_password(session["user_id"], old_password):
        return jsonify(ok=False, message="目前密碼不正確")
    if len(new_password) < 8:
        return jsonify(ok=False, message="新密碼至少需要 8 個字元")
    if new_password != confirm_password:
        return jsonify(ok=False, message="兩次輸入的新密碼不一致")

    db.update_user_password(session["user_id"], new_password)
    session["must_change_password"] = False
    return jsonify(ok=True)


@app.route("/")
@login_required
def index():
    accounts = []
    account_count = 0
    try:
        accounts = load_accounts()
        account_count = len(accounts)
    except Exception as e:
        account_count = f"讀取失敗：{e}"
    return render_template(
        "index.html",
        account_count=account_count,
        accounts=accounts,
        username=session.get("username"),
        role=session.get("role"),
        is_admin=session.get("role") == "admin",
    )


def _run_job(coro_factory):
    """在背景執行緒跑一個 async 工作，log 寫進共用的 LOG_LINES"""
    global RUNNING

    def log(message: str):
        with LOCK:
            LOG_LINES.append(message)

    try:
        asyncio.run(coro_factory(log))
    except (LookupError, ValueError, RuntimeError) as e:
        log(f"❌ {e}")
    except Exception as e:
        log(f"❌ 執行過程發生未預期錯誤：{e}")
    finally:
        with LOCK:
            RUNNING = False


def _start_job(coro_factory):
    """回傳 (是否成功啟動, 錯誤訊息)。同一時間只允許一個工作執行。"""
    global RUNNING
    with LOCK:
        if RUNNING:
            return False, "已經有工作在執行中，請稍候"
        RUNNING = True
        LOG_LINES.clear()

    thread = threading.Thread(target=_run_job, args=(coro_factory,), daemon=True)
    thread.start()
    return True, None


@app.route("/api/purge-accounts", methods=["POST"])
@role_required("admin", "operator")
def api_purge_accounts():
    try:
        accounts = load_accounts()
    except Exception as e:
        return jsonify(ok=False, message=str(e))

    index_list = request.form.getlist("account_index")
    if not all(i.isdigit() and 0 <= int(i) < len(accounts) for i in index_list):
        return jsonify(ok=False, message="帳號勾選內容無效，請重新整理頁面再試一次")
    if not index_list:
        return jsonify(ok=False, message="請至少勾選一個帳號")

    selected_indexes = sorted({int(i) for i in index_list})
    selected_accounts = [accounts[i] for i in selected_indexes]

    ok, message = _start_job(lambda log: purge_all_accounts(selected_accounts, log))
    return jsonify(ok=ok, message=message)


@app.route("/api/purge-domain", methods=["POST"])
@role_required("admin", "operator")
def api_purge_domain():
    domain = request.form.get("domain", "").strip()
    if not domain:
        return jsonify(ok=False, message="請輸入網域")
    try:
        accounts = load_accounts()
    except Exception as e:
        return jsonify(ok=False, message=str(e))

    ok, message = _start_job(lambda log: purge_single_domain(domain, accounts, log))
    return jsonify(ok=ok, message=message)


def _parse_domain_content_lines(raw: str) -> list:
    """解析「網域,內容」多行文字，回傳 [{"domain":..., "content":...}, ...]"""
    entries = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(",", 1)
        if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
            raise ValueError(f"格式錯誤：「{line}」，每行需要是「網域,內容」")
        entries.append({"domain": parts[0].strip(), "content": parts[1].strip()})
    return entries


def _parse_domain_pattern_lines(raw: str) -> list:
    """解析「網域,URL Pattern」多行文字，回傳 [{"domain":..., "pattern":...}, ...]"""
    entries = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(",", 1)
        if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
            raise ValueError(f"格式錯誤：「{line}」，每行需要是「網域,URL Pattern」")
        entries.append({"domain": parts[0].strip(), "pattern": parts[1].strip()})
    return entries


@app.route("/api/dns/add-batch", methods=["POST"])
@role_required("admin", "operator")
def api_dns_add_batch():
    raw = request.form.get("entries", "")
    record_type = request.form.get("type", "A").strip().upper()
    proxied = request.form.get("proxied") == "on"

    try:
        entries = _parse_domain_content_lines(raw)
    except ValueError as e:
        return jsonify(ok=False, message=str(e))
    if not entries:
        return jsonify(ok=False, message="請至少輸入一筆「網域,內容」")
    try:
        accounts = load_accounts()
    except Exception as e:
        return jsonify(ok=False, message=str(e))

    ok, message = _start_job(lambda log: add_dns_records_batch(entries, record_type, proxied, accounts, log))
    return jsonify(ok=ok, message=message)


@app.route("/api/dns/list", methods=["POST"])
@login_required
def api_dns_list():
    raw = request.form.get("domains", "")
    domains = [d.strip() for d in re.split(r"[,\n\r]+", raw) if d.strip()]
    if not domains:
        return jsonify(ok=False, message="請至少輸入一個網域")
    try:
        accounts = load_accounts()
    except Exception as e:
        return jsonify(ok=False, message=str(e))

    messages = []
    try:
        records = asyncio.run(list_dns_records_batch(domains, accounts, messages.append))
    except Exception as e:
        return jsonify(ok=False, message=str(e))

    return jsonify(ok=True, records=records, messages=messages)


@app.route("/api/dns/delete-batch", methods=["POST"])
@role_required("admin", "operator")
def api_dns_delete_batch():
    try:
        records = json.loads(request.form.get("records", "[]"))
    except Exception:
        return jsonify(ok=False, message="刪除清單格式錯誤，請重新查詢一次")
    if not records:
        return jsonify(ok=False, message="請至少勾選一筆要刪除的紀錄")
    try:
        accounts = load_accounts()
    except Exception as e:
        return jsonify(ok=False, message=str(e))

    ok, message = _start_job(lambda log: delete_dns_records_batch(records, accounts, log))
    return jsonify(ok=ok, message=message)


@app.route("/api/zone/create", methods=["POST"])
@role_required("admin", "operator")
def api_zone_create():
    domain = request.form.get("domain", "").strip()
    account_name = request.form.get("account_name", "").strip()
    jump_start = request.form.get("jump_start") == "on"

    if not domain or not account_name:
        return jsonify(ok=False, message="請輸入網域並選擇要歸屬的 CF 帳號")
    try:
        accounts = load_accounts()
    except Exception as e:
        return jsonify(ok=False, message=str(e))

    ok, message = _start_job(lambda log: create_zone(domain, account_name, jump_start, accounts, log))
    return jsonify(ok=ok, message=message)


@app.route("/api/zone/delete", methods=["POST"])
@role_required("admin")
def api_zone_delete():
    domain = request.form.get("domain", "").strip()
    if not domain:
        return jsonify(ok=False, message="請輸入網域")
    try:
        accounts = load_accounts()
    except Exception as e:
        return jsonify(ok=False, message=str(e))

    ok, message = _start_job(lambda log: delete_zone(domain, accounts, log))
    return jsonify(ok=ok, message=message)


@app.route("/api/zone/always-https", methods=["POST"])
@role_required("admin", "operator")
def api_zone_always_https():
    raw = request.form.get("domains", "")
    domains = [d.strip() for d in re.split(r"[,\n\r]+", raw) if d.strip()]
    enabled = request.form.get("enabled") == "on"

    if not domains:
        return jsonify(ok=False, message="請至少輸入一個網域")
    try:
        accounts = load_accounts()
    except Exception as e:
        return jsonify(ok=False, message=str(e))

    ok, message = _start_job(lambda log: set_always_use_https_batch(domains, enabled, accounts, log))
    return jsonify(ok=ok, message=message)


@app.route("/api/pagerules/list", methods=["POST"])
@login_required
def api_pagerules_list():
    domain = request.form.get("domain", "").strip()
    if not domain:
        return jsonify(ok=False, message="請輸入網域")
    try:
        accounts = load_accounts()
    except Exception as e:
        return jsonify(ok=False, message=str(e))

    messages = []
    try:
        rules = asyncio.run(list_page_rules(domain, accounts, messages.append))
    except Exception as e:
        return jsonify(ok=False, message=str(e))

    return jsonify(ok=True, rules=rules, messages=messages)


@app.route("/api/pagerules/create", methods=["POST"])
@role_required("admin", "operator")
def api_pagerules_create():
    raw = request.form.get("entries", "")
    action_type = request.form.get("action_type", "").strip()
    status = request.form.get("status", "active").strip()
    try:
        priority = int(request.form.get("priority", "1"))
    except ValueError:
        return jsonify(ok=False, message="優先序必須是數字")

    params = {
        "target_url": request.form.get("target_url", "").strip(),
        "status_code": request.form.get("status_code", "301").strip(),
        "cache_level": request.form.get("cache_level", "").strip(),
        "security_level": request.form.get("security_level", "").strip(),
    }

    try:
        entries = _parse_domain_pattern_lines(raw)
    except ValueError as e:
        return jsonify(ok=False, message=str(e))
    if not entries:
        return jsonify(ok=False, message="請至少輸入一筆「網域,URL Pattern」")
    if status not in ("active", "disabled"):
        return jsonify(ok=False, message="狀態只能是 active 或 disabled")
    try:
        accounts = load_accounts()
    except Exception as e:
        return jsonify(ok=False, message=str(e))

    ok, message = _start_job(
        lambda log: create_page_rules_batch(entries, action_type, params, priority, status, accounts, log)
    )
    return jsonify(ok=ok, message=message)


@app.route("/api/pagerules/delete-batch", methods=["POST"])
@role_required("admin", "operator")
def api_pagerules_delete_batch():
    try:
        rules = json.loads(request.form.get("rules", "[]"))
    except Exception:
        return jsonify(ok=False, message="刪除清單格式錯誤，請重新查詢一次")
    if not rules:
        return jsonify(ok=False, message="請至少勾選一筆要刪除的 Page Rule")
    try:
        accounts = load_accounts()
    except Exception as e:
        return jsonify(ok=False, message=str(e))

    ok, message = _start_job(lambda log: delete_page_rules_batch(rules, accounts, log))
    return jsonify(ok=ok, message=message)


@app.route("/api/cert/issue", methods=["POST"])
@role_required("admin", "operator")
def api_cert_issue():
    raw = request.form.get("domain", "")
    domains = [d.strip() for d in re.split(r"[,\n\r]+", raw) if d.strip()]
    staging = request.form.get("staging") == "on"

    if not domains:
        return jsonify(ok=False, message="請至少輸入一個完整網域名稱")
    try:
        accounts = load_accounts()
    except Exception as e:
        return jsonify(ok=False, message=str(e))

    ok, message = _start_job(lambda log: issue_certificate(domains, accounts, log, staging=staging))
    return jsonify(ok=ok, message=message)


@app.route("/api/cert/list")
@login_required
def api_cert_list():
    try:
        certs = list_local_certs()
    except Exception as e:
        return jsonify(ok=False, message=str(e))
    return jsonify(ok=True, certs=certs)


@app.route("/api/cert/download/<hostname>")
@role_required("admin", "operator")
def api_cert_download(hostname):
    try:
        data, filename = build_cert_archive(hostname)
    except Exception as e:
        return jsonify(ok=False, message=str(e)), 404
    return send_file(io.BytesIO(data), mimetype="application/zip", as_attachment=True, download_name=filename)


@app.route("/api/cert/delete", methods=["POST"])
@role_required("admin", "operator")
def api_cert_delete():
    hostname = request.form.get("hostname", "").strip()
    if not hostname:
        return jsonify(ok=False, message="請指定要刪除的憑證")
    try:
        delete_local_cert(hostname)
    except Exception as e:
        return jsonify(ok=False, message=str(e))
    return jsonify(ok=True)


@app.route("/api/logs")
@login_required
def api_logs():
    since = request.args.get("since", default=0, type=int)
    with LOCK:
        lines = LOG_LINES[since:]
        next_offset = len(LOG_LINES)
        running = RUNNING
    return jsonify(lines=lines, next_offset=next_offset, running=running)


# ---------------------------------------------------------------------------
# 使用者管理（僅 admin）
# ---------------------------------------------------------------------------

@app.route("/api/admin/users")
@role_required("admin")
def api_admin_users_list():
    return jsonify(ok=True, users=db.list_users())


@app.route("/api/admin/users", methods=["POST"])
@role_required("admin")
def api_admin_users_create():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "").strip()
    if not username or not password:
        return jsonify(ok=False, message="請輸入帳號與密碼")
    if role not in db.ROLES:
        return jsonify(ok=False, message=f"角色必須是 {'、'.join(db.ROLES)} 其中之一")
    try:
        db.create_user(username, password, role)
    except Exception as e:
        return jsonify(ok=False, message=f"新增失敗：{e}")
    return jsonify(ok=True)


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@role_required("admin")
def api_admin_users_delete(user_id):
    if user_id == session.get("user_id"):
        return jsonify(ok=False, message="不能刪除自己目前登入的帳號")
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify(ok=False, message="找不到這個使用者")
    if user["username"] == "admin":
        return jsonify(ok=False, message="admin 帳號不能刪除")
    if user["role"] == "admin" and db.count_admins() <= 1:
        return jsonify(ok=False, message="至少要保留一個 admin 帳號，不能刪除")
    db.delete_user(user_id)
    return jsonify(ok=True)


# ---------------------------------------------------------------------------
# CF 帳號管理（僅 admin）
# ---------------------------------------------------------------------------

@app.route("/api/admin/cf-accounts")
@role_required("admin")
def api_admin_cf_accounts_list():
    return jsonify(ok=True, accounts=db.list_cf_accounts(decrypt=False))


@app.route("/api/admin/cf-accounts", methods=["POST"])
@role_required("admin")
def api_admin_cf_accounts_create():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    api_key = request.form.get("api_key", "").strip()
    ns = [n.strip() for n in request.form.get("ns", "").splitlines() if n.strip()]
    if not name or not email or not api_key:
        return jsonify(ok=False, message="請輸入名稱、Email、API Key")
    try:
        db.create_cf_account(name, email, api_key, ns)
    except Exception as e:
        return jsonify(ok=False, message=f"新增失敗：{e}")
    return jsonify(ok=True)


@app.route("/api/admin/cf-accounts/<int:account_id>", methods=["PUT"])
@role_required("admin")
def api_admin_cf_accounts_update(account_id):
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    api_key = request.form.get("api_key", "").strip() or None
    ns = [n.strip() for n in request.form.get("ns", "").splitlines() if n.strip()]
    if not name or not email:
        return jsonify(ok=False, message="請輸入名稱與 Email")
    try:
        db.update_cf_account(account_id, name, email, api_key, ns)
    except Exception as e:
        return jsonify(ok=False, message=f"更新失敗：{e}")
    return jsonify(ok=True)


@app.route("/api/admin/cf-accounts/<int:account_id>", methods=["DELETE"])
@role_required("admin")
def api_admin_cf_accounts_delete(account_id):
    db.delete_cf_account(account_id)
    return jsonify(ok=True)


if __name__ == "__main__":
    # 預設只綁 localhost；容器化執行時由 Dockerfile / docker-compose 設定
    # OPS_TOOLS_HOST=0.0.0.0，port mapping 再由宿主機那端限制只開放給 127.0.0.1
    host = os.environ.get("OPS_TOOLS_HOST", "127.0.0.1")
    port = int(os.environ.get("OPS_TOOLS_PORT", "5000"))
    app.run(host=host, port=port, debug=False, threaded=True)
