# Domain Ops Toolkit

管理多組 Cloudflare 帳號（各自獨立的 Email + Global API Key）的日常維運工具：清除快取、新增/刪除子網域、簽發與續期 Let's Encrypt 憑證。瀏覽器打 `http://127.0.0.1:5000`，多使用者帳密登入、依角色分權限，僅限本機使用。統一用 Docker Compose 啟動（見下方「使用步驟」）。

使用者、角色權限、Cloudflare 帳號（含 API Key，加密後才存）都放在 Postgres 資料庫，**不是**放在本機的 JSON 設定檔裡——這台機器上不會有一個打開就看得到明文 API Key/密碼的檔案。

## 功能

- 建立 Zone（把網域新增到 Cloudflare）／刪除 Zone（僅 `admin`，整個網域從 Cloudflare 移除，無法復原）
- 清除快取（可勾選帳號，預設全選＝全部帳號）
- 指定網域清除快取（自動比對所屬帳號）
- 新增子網域
- 刪除子網域
- 強制 HTTPS（Zone 層級的 Always Use HTTPS 設定，可一次對多個網域批次開關）
- Page Rule 設置：查詢、批次新增（一次可對多個網域套用同一套動作設定）、批次刪除，支援網址轉發 (Forwarding URL)、強制 HTTPS、快取層級、安全性等級四種動作
- 簽發 / 續期 Let's Encrypt 憑證，支援一次簽發多網域 (SAN) 憑證（排程用的自動續期腳本預設門檻剩餘 7 天，見下方）
- 憑證下載：列出過往簽發過的憑證（含 CN、SAN 網域清單），可下載打包 zip 或手動刪除
- 使用者管理（僅 admin）：新增/刪除登入帳號，指定角色
- CF 帳號管理（僅 admin）：新增/編輯/刪除 Cloudflare 帳號，取代手動編輯 JSON 設定檔

### 角色權限

| 角色 | 能做的事 |
|---|---|
| `admin` | 所有功能，含「使用者管理」「CF 帳號管理」 |
| `operator` | 能執行清除快取／DNS／憑證等操作，看不到、也不能管理使用者或 CF 帳號 |
| `readonly` | 只能查看清單（憑證清單、DNS 查詢結果、執行紀錄），所有會異動資料的按鈕都看不到；就算繞過前端直接呼叫 API，後端也會擋（回 403） |

「清除快取」用勾選清單列出資料庫裡的每組 CF 帳號，**預設全部勾選**（等同一次清除全部帳號快取），取消勾選某幾組就只清除有勾選的帳號，不需要 NS 比對。

**指定網域清除快取 / 新增 / 刪除子網域這三個功能，不會逐一掃描全部帳號去找網域在哪裡**，而是：

1. 查詢你輸入網域目前的 NS（Name Server）
2. 跟資料庫裡每個帳號設定的 `ns` 欄位比對，找出**唯一**匹配的帳號
3. 只用那一組帳號的憑證呼叫 Cloudflare API，不會去試其他帳號

這樣可以避免對著全部帳號一直打 API（容易被限流），也比手動去 Cloudflare 後台一個個帳號找网域快。

⚠️ **重要前提**：這個機制能不能準確運作，取決於「同一個 Cloudflare 帳號底下的所有網域，是不是都固定用同一組 NS」。如果你的帳號是標準方案（非 Enterprise 客製 NS），Cloudflare 通常會讓同帳號的網域共用同一組指派的 NS，但不是 100% 保證。**設定前請自行到 Cloudflare 後台，任選同帳號下 2、3 個網域比對 NS 是否一致**，不一致的話這個自動比對功能就不能用在那個帳號上。

**簽發/續期憑證怎麼運作**：這是 **Let's Encrypt 公開憑證**（不是 Cloudflare Origin CA 憑證），走 **DNS-01 驗證**，畫面上一次輸入框可以填多個網域（每行一個），簽發成一張多網域 (SAN) 憑證：

1. 每個網域各自用 NS 比對出所屬帳號（可以分屬不同 Cloudflare 帳號）
2. 跟 Let's Encrypt 申請訂單，拿到每個網域各自需要驗證的內容
3. 用各自帳號的權限，在每個網域的 `_acme-challenge.<網域>` 建立一筆臨時的 TXT 紀錄
4. 等 DNS 生效、全部網域都確認查得到後，通知 Let's Encrypt 驗證
5. 驗證通過後下載憑證，存到 `data/certs/<第一個網域>/`（`fullchain.pem` + `privkey.pem`），並**刪除**剛剛建立的所有臨時 TXT 紀錄
6. **只會產生檔案**，不會自動部署到任何伺服器 / K8s / 負載均衡器，後續要裝到哪裡需要你自己動手

憑證主體名稱 (CN) 跟主體別名 (SAN，即簽發時的完整網域清單) 都是直接從 `fullchain.pem` 憑證本身讀出來的，不是另外存的中繼資料，保證跟實際簽出的憑證內容一致。

**續期**：Let's Encrypt 憑證效期只有 90 天，畫面上會列出所有已簽發憑證的到期日，快到期的會有提示，按「續期」就是照原本的完整網域清單（SAN）重新走一次上面的簽發流程。如果想要**自動**檢查並續期，不用每次手動點，見下方「自動續期腳本」。

## 資料夾結構

```
domain-ops-toolkit/
├── app/                        # 原始碼（純程式，會進版控、會被打包進 image）
│   ├── ops_tool_web.py         # 主程式，容器啟動時執行這支
│   ├── db.py                   # 資料庫層：使用者/角色、CF 帳號（含加解密）
│   ├── cf_purge_core.py        # 清除快取核心邏輯
│   ├── cf_dns_ops.py           # NS 比對帳號、指定網域清除快取、新增/刪除 DNS 紀錄邏輯
│   ├── cf_zone_ops.py          # 強制 HTTPS（Always Use HTTPS）、Page Rules 邏輯
│   ├── cf_cert_ops.py          # Let's Encrypt 憑證簽發/續期邏輯（DNS-01 驗證，支援多網域 SAN）
│   ├── cf_cert_renew_all.py    # 可排程執行的批次續期腳本
│   └── templates/              # 登入頁、操作頁畫面
├── data/                       # 執行期資料，整個資料夾 .gitignore 排除、不進版控
│   ├── master.key              # 加密主金鑰，沒用 .env 指定的話第一次啟動會自動產生這個檔案
│   └── certs/                  # 已簽發的憑證、私鑰、ACME 帳號金鑰
├── Dockerfile
├── docker-compose.yml          # 含 db（Postgres）、ops-tools、ops-tools-renew 三個服務
├── .dockerignore
├── requirements.txt
└── .gitignore
```

原始碼（`app/`）是乾淨、可以放心公開的內容。使用者帳密、CF 帳號的 Email/API Key 都在 Postgres 資料庫裡（`db` 服務的 named volume，不是 bind mount，見下方說明），API Key 另外用 `data/master.key` 這把主金鑰加密後才寫進資料庫。這台機器上唯一需要小心保管的是這把主金鑰。

## 使用步驟

### 1. 啟動

不用先建 `.env`、不用先準備任何密碼，直接：

```powershell
docker compose up -d
```

第一次執行時，`docker-compose.yml` 裡 `ops-tools`／`db` 服務設定了 `build`/`image`，Compose 偵測到本機還沒有就會自動抓/build，不用額外先下 `docker compose build`。啟動流程是：

1. 先起 `db`（Postgres，等 healthcheck 過）——`db` 完全沒對外開 port，只有同一個 compose network 內的 `ops-tools` 連得到，用 `trust`（同網段免密碼）認證，不需要你準備 DB 密碼
2. 再起 `ops-tools`：第一次啟動會自動建表；沒有指定 `OPS_TOOLS_MASTER_KEY` 的話，會自動產生一把加密 Cloudflare API Key 用的主金鑰存到 `data/master.key`（跟 Jenkins 自動產生 `secrets/master.key` 是同一種做法），之後都讀同一把；並自動建立一組帳密固定的管理員帳號（`admin` / `admin123`），這段訊息只會在資料庫還沒有任何使用者的第一次啟動印出：

```powershell
docker compose logs ops-tools
```

```
================================================================
首次啟動，已自動建立管理員帳號（第一次登入會被強制要求改密碼）：
  帳號：admin
  密碼：admin123
================================================================
```

⚠️ **`admin123` 是寫死在程式裡的固定密碼，不是機密**，任何看得到這份 README 或原始碼的人都會知道；安全性完全靠「第一次登入會被強制要求改密碼」這個機制擋住（沒改密碼就進不了主畫面，見下方），**請務必第一次登入就立刻改密碼**，不要跳過或拖延

只把 port 綁在宿主機的 `127.0.0.1:5000`（維持「僅本機能連」的前提，不要改成對外開放）。要看 log：`docker compose logs -f`；要停掉：`docker compose down`。

`./app` 用 volume 掛進容器的 `/app`，蓋掉 image 裡 `COPY` 進去的版本，所以：
- **改 `app/` 底下的 `.py` / `templates/`（程式邏輯、畫面）**：存檔後 `docker compose restart ops-tools` 就會生效，**不用重新 build image**
- **改 `requirements.txt`（新增/升級 Python 套件）**：這個是在 build image 時安裝進去的，volume 蓋不到，必須 `docker compose up -d --build` 重新 build 才會生效

排程自動續期（見下方「自動續期腳本」）：

```powershell
docker compose --profile renew up -d ops-tools-renew
```

**想自己指定主金鑰的話**（例如搬到別台機器、或不想讓金鑰跟資料放在同一個 `data/` 資料夾）：在專案根目錄建一個 `.env` 檔案（`.gitignore` 已排除，不會進版控），內容：

```
OPS_TOOLS_MASTER_KEY=貼上這裡
```

金鑰產生方式：`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`。`.env` 存在的話 compose 會自動套用，不用額外加參數。這一步完全是選填，不做也能正常使用。

⚠️ **不管金鑰是自動產生還是自己指定，遺失了都無法解密資料庫裡已經存的 Cloudflare API Key**（等於所有 CF 帳號都要重新輸入）。`data/master.key`（或你自訂的 `.env`）建議額外備份一份到密碼管理工具。

### 2. 第一次登入：改密碼、加 CF 帳號

開瀏覽器打開 `http://127.0.0.1:5000`，用 `admin` / `admin123` 登入。**任何帳號（含這組自動建立的 admin、之後管理員新增的每一個使用者）第一次登入都會被強制導去一個只能改密碼的畫面**，不改完新密碼（至少 8 個字元）沒辦法進到主畫面，這個限制前後端都有擋，不是只有畫面上藏起來。

改完密碼後建議照順序做：

1. **左側「系統管理 → 使用者管理」**：幫團隊其他人開帳號、指定角色（`admin`/`operator`/`readonly`，見上方「角色權限」）；新增的帳號一樣會在第一次登入時被要求改密碼
2. **左側「系統管理 → CF 帳號管理」**：新增你要管理的 Cloudflare 帳號（名稱、Email、Global API Key、NS 選填），這裡新增的帳號就會出現在「清除快取」等功能的帳號清單裡

任何角色、任何時候都可以在左側「帳號設定 → 修改密碼」自己改密碼（需要先輸入目前密碼）。

**Global API Key 在哪裡拿？**

1. 登入 Cloudflare，右上角帳號圖示 → **My Profile**
2. 左側選單 **API Tokens**
3. 頁面下方 **API Keys** 區塊 → **Global API Key** → **View**
4. 可能要重新輸入密碼驗證身份，驗證後才會顯示金鑰

**怎麼找 NS？**（只有「指定網域清除快取」「新增/刪除子網域」這兩個功能需要，「清除全部帳號快取」用不到，不填也不影響）

1. 登入該 Cloudflare 帳號 → **Websites**，點進任一個網域
2. **Overview** 頁面中段會顯示 **Cloudflare nameservers**，例如 `xxx.ns.cloudflare.com` / `yyy.ns.cloudflare.com`
3. 建議同帳號下再點 1、2 個其他網域確認 NS 是否一樣，一樣才能填進 NS 欄位

⚠️ **重要前提**：這個機制能不能準確運作，取決於「同一個 Cloudflare 帳號底下的所有網域，是不是都固定用同一組 NS」。如果你的帳號是標準方案（非 Enterprise 客製 NS），Cloudflare 通常會讓同帳號的網域共用同一組指派的 NS，但不是 100% 保證，設定前請自行驗證。

### 4. 操作畫面

畫面左側是導覽選單，分幾個分類（點分類標題可收合／展開）：

- **CDN → Cloudflare**
    1. **建立 Zone**：輸入網域＋選擇要歸屬的 CF 帳號（zone 一律是註冊主體網域，輸入 `sub.example.com` 也會建立 `example.com`），可勾選「自動掃描匯入現有 DNS 紀錄」（Cloudflare 的 `jump_start`，不保證完整或正確）；建立成功後執行紀錄會顯示 Cloudflare 指派的新 NS，**需要自己到網域註冊商把該網域的 NS 改過去**，改完並等 DNS 生效後這個網域才算真的走 Cloudflare
    2. **刪除 Zone**（僅 `admin`）：輸入網域，自動依目前 NS 比對出所屬帳號；因為是**整個網域**從 Cloudflare 移除（連同底下所有 DNS 紀錄、Page Rule、SSL 設定等），按下刪除後會跳出輸入框要求**打字輸入完整網域名稱確認**才會真的執行，比一般刪除多一層防呆
    3. **清除快取**：勾選清單列出全部帳號，預設全選；按「全選」「全不選」快速切換，或自己勾要清的帳號後按「清除已勾選帳號的快取」
    4. **依網域清除快取**：輸入網域（例如 `example.com` 或 `sub.example.com`），自動比對出所屬帳號，只清那個網域的快取
    5. **新增子網域**：文字框每行輸入「網域,內容」（例如 `test.example.com,1.2.3.4`），可一次貼多行批次新增，共用下面選的紀錄類型（A / AAAA / CNAME / TXT / MX）跟是否套 Proxy（橘雲）；**新增前會先刪除同名同類型的舊紀錄**再新增，避免解析本來就存在造成衝突
    6. **刪除子網域**：不用自己填類型或內容——文字框每行輸入一個網域，按「查詢 DNS 紀錄」列出該網域目前所有紀錄，勾選要刪的那幾筆（可跨多個網域一起勾），按「刪除已勾選的紀錄」批次刪除
    7. **強制 HTTPS**：文字框每行輸入一個網域，按開啟或關閉即可批次設定該網域所屬 zone 的 Always Use HTTPS（自動比對所屬帳號，跟其他功能一樣）
    8. **Page Rule 設置**：文字框每行輸入「網域,URL Pattern」（例如 `www.example.com,www.example.com/old-page*`，支援 `*` 萬用字元），可一次貼多行對多個網域批次新增；選動作類型（網址轉發／強制 HTTPS／快取層級／安全性等級），依動作類型會顯示對應的參數欄位（例如網址轉發要填「目標網址」＋狀態碼 301/302），設定優先序（1-5，數字越小優先權越高）與狀態（active/disabled）後按新增，同一批文字框裡的每一筆都套用相同的動作／優先序／狀態設定；下方可輸入網域按「查詢」列出該 zone 現有的 Page Rule，勾選後按「刪除已勾選」批次刪除
- **憑證 → 憑證簽發**
    1. **申請 / 續期憑證**：文字框每行輸入一個網域（可只填一個，或填多個簽發成多網域 SAN 憑證），勾選「測試模式」用 Let's Encrypt staging（不算正式額度，適合第一次測試流程），不勾就是正式簽發；下方會列出已簽發憑證的到期日，快到期的會標示提醒，按「續期」直接照原本的網域清單重簽
- **憑證 → 憑證下載**
    1. **憑證下載**：列出所有已簽發過的憑證，欄位顯示憑證主體名稱 (CN) 跟主體別名 (SAN，即這張憑證涵蓋的所有網域)，可以看到過往簽發過哪些網域；按「下載」取得 `fullchain.pem` + `privkey.pem` 打包的 zip，按「刪除」可手動移除不再需要的憑證資料夾（會跳出確認視窗，此動作無法復原）
- **系統管理 → 使用者管理**（僅 `admin` 看得到）：新增/刪除登入帳號，指定角色；表格會顯示每個使用者「密碼狀態」（尚未設定 = 還沒完成強制改密碼流程）。**`admin` 這個帳號本身不能被刪除**（跟「至少保留一個 admin」是分開的兩條規則，就算還有其他 admin 帳號存在也一樣不能刪 `admin`）
- **系統管理 → CF 帳號管理**（僅 `admin` 看得到）：新增/編輯/刪除 Cloudflare 帳號；編輯時 API Key 欄位留空代表不變更
- **帳號設定 → 修改密碼**（所有角色都看得到）：輸入目前密碼＋新密碼（至少 8 個字元）即可更新，改完不用重新登入

`operator`／`readonly` 角色登入時，畫面上不會出現「系統管理」這個分類；`readonly` 角色則連清除快取/新增刪除子網域/簽發憑證這些會異動資料的按鈕都不會出現（後端也擋，不是只有前端藏起來）。

畫面下方「執行紀錄」在 CDN／憑證這幾個頁面共用，會即時顯示進度，同一時間只能跑一個工作（按鈕會鎖住），跑完自動解鎖；「系統管理」「帳號設定」底下的頁面都是同步 API（新增/刪除/改密碼一按下去就有結果），不會透過這個機制寫紀錄，所以這幾頁沒有顯示執行紀錄面板。要結束伺服器：`docker compose down`。

進度訊息範例（清除全部帳號快取）：

```
===== 帳號【帳號1】開始 =====
🔍 帳號【帳號1】找到 12 個網域
[OK] 清除快取成功：example.com
✅ 帳號【帳號1】完成：12/12 成功
...
========== 全部帳號處理完成 ==========
🎉 總計：20/20 個網域清除成功
```

進度訊息範例（依網域清除快取 / NS 比對成功）：

```
🔎 example.com 的 NS：xxx.ns.cloudflare.com, yyy.ns.cloudflare.com → 比對到帳號【帳號1】
[OK] 清除快取成功：example.com
🎉 example.com（帳號【帳號1】）快取清除成功
```

進度訊息範例（簽發憑證成功）：

```
🔎 example.com 的 NS：xxx.ns.cloudflare.com, yyy.ns.cloudflare.com → 比對到帳號【帳號1】
🌐 使用 Let's Encrypt 測試環境 staging（不計入正式簽發額度，但瀏覽器不信任） 簽發 test.example.com
📝 建立 DNS 驗證紀錄：_acme-challenge.test.example.com（TXT）
⏳ 等待 DNS 生效（20 秒）...
✅ 已查到 DNS 驗證紀錄
📮 通知 Let's Encrypt 進行驗證...
⏳ 等待驗證與簽發結果...
🧹 清除臨時的 DNS 驗證紀錄：_acme-challenge.test.example.com
🎉 憑證簽發成功：test.example.com，到期日 2026-12-07，已存到 data/certs/test.example.com/
```

### 3. 常見狀況

| 訊息 | 原因 / 處理方式 |
|---|---|
| 容器啟動失敗、log 顯示「OPS_TOOLS_MASTER_KEY / data/master.key 內容格式不正確」| 通常是自己手動編輯 `.env` 或 `data/master.key` 時貼錯內容，確認是 `Fernet.generate_key()` 產生的完整字串，或乾脆刪掉讓它重新自動產生（前提是資料庫裡還沒有任何 CF 帳號，不然舊資料會解不開） |
| `ops-tools` 一直重啟、log 顯示連不到資料庫 | `docker compose ps` 確認 `db` 服務是 `healthy`；剛啟動時 Postgres 需要幾秒初始化，`ops-tools` 有內建重試，等一下通常會自己好 |
| 登入頁一直顯示「帳號或密碼錯誤」| 確認帳密輸入正確；如果是全新啟動，預設帳密是 `admin` / `admin123`（固定值），或去 `docker compose logs ops-tools` 確認第一次啟動有沒有正常印出建立管理員帳號的訊息 |
| 忘記 admin 密碼 | 用另一個 admin 帳號登入去使用者管理改；如果只有一個 admin 又忘記密碼，需要直接連資料庫用 SQL 重設 `password_hash`（`werkzeug.security.generate_password_hash` 產生），或砍掉 `pgdata` volume 重新來過（會遺失所有使用者跟 CF 帳號設定） |
| 打不開 `127.0.0.1:5000` | `docker compose ps` 確認容器是 running、`docker compose logs -f` 看有沒有錯誤 |
| `⚠️ 帳號【XXX】沒有取得任何網域，請確認 Email / API Key 是否正確` | 該組帳號的 Email 或 API Key 打錯，或這組金鑰已失效，到「CF 帳號管理」編輯更新 |
| `❌ XXX 目前的 NS（...）沒有比對到任何帳號` | 該網域的 NS 沒有任何帳號的 NS 欄位對得上，到「CF 帳號管理」檢查對應帳號是否漏填、填錯，或這個網域根本不在你管理的任何帳號底下 |
| `❌ XXX 同時比對到多個帳號` | 有 2 組以上帳號的 NS 欄位重複，代表這個判斷方式在你的帳號配置下不可靠，需要到「CF 帳號管理」調整或改用別的方式指定帳號 |
| `⚠️ 找到 N 筆符合的紀錄，請加上「內容」條件` | 刪除子網域時同名稱有多筆紀錄，畫面/log 會列出每筆的內容，把想刪的那筆內容填進「內容」欄位再送一次 |
| `[RETRY] API 限制觸發` | 正常現象，代表短時間內請求太多被 Cloudflare 限速，程式會自動延遲重試，不用理它 |
| `[FAIL] 重試次數已達上限` | 重試 3 次後仍失敗，可以之後手動重跑一次，或去 Cloudflare 後台確認狀態 |
| `❌ ... 的 TXT 驗證紀錄一直查不到` | DNS 生效比預期慢，或該帳號其實沒有這個網域的操作權限；可以稍後重試，或先手動確認 `_acme-challenge.<網域>` 的 TXT 紀錄有沒有建立成功 |
| `❌ Let's Encrypt 驗證/簽發失敗` | 通常是 Let's Encrypt 自己做 DNS 查詢時查不到（可能是我方查得到但對方查不到，DNS 傳播還沒完全生效），或申請次數觸及 Let's Encrypt 的[速率限制](https://letsencrypt.org/docs/rate-limits/)；先用「測試模式 staging」確認流程能跑完，再切回正式環境 |
| `❌ 跟 Let's Encrypt 建立訂單失敗` | 通常是 ACME 帳號註冊/連線問題，或正式環境的簽發額度用完（同網域一週內申請上限），先看錯誤訊息內容 |

## 注意事項

- 首次啟動自動建立的管理員帳密固定是 `admin` / `admin123`（寫死在 `db.py` 的 `DEFAULT_ADMIN_PASSWORD`），**不是隨機產生、任何人看程式碼都知道**；靠「第一次登入強制改密碼」機制擋住風險，只要每次部署都確實在第一次登入時改掉密碼就沒問題，**不要跳過這一步**
- `data/master.key`（或自訂在 `.env` 裡的 `OPS_TOOLS_MASTER_KEY`）是**明文儲存**（沒有更上層的地方可以加密它了，這是加密鏈最底層的根），不要外流、不要進版控、不要隨意分享；遺失等於資料庫裡所有 CF 帳號的 API Key 都救不回來，請額外備份
- `db` 服務用 `POSTGRES_HOST_AUTH_METHOD: trust`（同網段免密碼），這是刻意的設計決定，因為 `db` 完全沒對外開 port，只有 compose network 內的 `ops-tools`/`ops-tools-renew` 連得到；**這個前提不能破壞**——不要幫 `db` 加 `ports:` 對外開放，否則等於資料庫完全不設防
- Cloudflare API Key 存在資料庫時已加密，但**傳輸過程、還有它在瀏覽器記憶體/畫面上輸入的當下**都是明文，跟任何人共用畫面或截圖時留意「CF 帳號管理」頁面
- 「清除全部帳號快取」「依網域清除快取」都是**整站/整個 zone 快取全清**（purge everything），不是清特定 URL；執行後短時間內該網域流量會直接打到源站，尖峰時段執行請評估源站負載
- 新增/刪除子網域是**直接對正式環境的 DNS 生效**；刪除是先查詢清單勾選、送出前會跳確認視窗，新增沒有二次確認（且會先刪除同名同類型的舊紀錄），操作前請再三確認網域、內容是否正確
- 批次新增/查詢/刪除 DNS 紀錄單次最多處理 50 個網域，逐筆間隔約 0.5 秒處理、遇到 Cloudflare 429 限流會自動重試，避免一次送出大量請求觸發帳號被限速
- Cloudflare **免費方案每個 zone 最多 3 條 Page Rule**，超過會直接被 Cloudflare API 拒絕（畫面上會顯示錯誤訊息），付費方案上限較高；新增前建議先查詢確認目前用量
- 強制 HTTPS／Page Rule 都是**直接對正式環境的 zone 設定生效**，Page Rule 新增沒有二次確認（刪除有），操作前請再三確認網域與參數是否正確
- **刪除 Zone 是這個工具裡最危險的操作**：會把整個網域從 Cloudflare 移除，連同底下所有 DNS 紀錄、Page Rule、SSL 設定等一併刪除，無法復原，因此限定只有 `admin` 能執行，且畫面上會多一道「輸入網域名稱確認」的關卡；`operator` 能建立 Zone，但不能刪除
- **建立 Zone 後網域不會立刻生效**：Cloudflare 只是指派新的 NS，需要自己到網域註冊商更新該網域的 NS 才會真的生效（NS 生效可能需要數小時到一天），生效前這個網域在 Cloudflare 上是「Pending」狀態
- NS 比對機制需要「同帳號網域共用同一組 NS」這個前提成立，設定 NS 欄位前務必自行驗證（見上方「怎麼找 NS」）
- 只綁定 `127.0.0.1`（localhost），只有自己這台電腦上的瀏覽器能連進去，其他電腦連不到；伺服器每次重啟登入狀態都會失效，需要重新輸入密碼。**容器化執行時容器內部一定要綁 `0.0.0.0`（Dockerfile 已設定），真正的存取限制是靠 `docker-compose.yml` 把 port 綁在宿主機的 `127.0.0.1`**，不要把 port 改成對外全開（例如 `"5000:5000"`），否則同網段的其他人都連得到
- `data/certs/` 資料夾裡的 `privkey.pem`（憑證私鑰）跟 `_acme_account_key.pem`（ACME 帳號金鑰）都是敏感資料，整個 `data/` 已被 `.gitignore` 排除，**這個資料夾不要外流、不要進版控**
- Postgres 的資料放在 named volume（`pgdata`），不是 `data/` 底下的檔案，**看不到、也不要直接複製這個 volume 當備份**，正確備份方式是 `docker compose exec db pg_dump -U opstools opstools > backup.sql`（備份出來的內容含 API Key 密文跟密碼雜湊，一樣要當敏感檔案處理，且離開了資料庫環境無法解密其中的 API Key，除非同時保留對應的 `OPS_TOOLS_MASTER_KEY`）
- `readonly` 角色的權限限制同時在前端（藏起按鈕）跟後端（API 檢查角色）都有實作，就算有人繞過瀏覽器直接呼叫 API 也一樣會被擋；但 `admin`／`operator` 角色能執行的操作沒有再更細的限制（例如不能只給某個角色存取特定幾組 CF 帳號），如果團隊需要更細的權限切分，目前的設計還沒涵蓋
- Let's Encrypt **正式環境**對同一個網域的簽發次數有[速率限制](https://letsencrypt.org/docs/rate-limits/)（例如同註冊網域一週最多簽發數次），測試流程請先勾「測試模式 staging」，確定沒問題再切正式環境，避免額度浪費在除錯上
- 簽出來的憑證**只會存成檔案**，不會自動部署到任何伺服器、K8s、負載均衡器，後續要怎麼裝上去需要你自己處理

## 自動續期腳本（`cf_cert_renew_all.py`）

網頁上的「續期」要人手動點，如果想要**排程自動檢查、快到期就自動續期**（不用開網頁、不用人在電腦前），用這支腳本，支援幾個參數：

```
python cf_cert_renew_all.py                # 掃描 data/certs/ 底下所有憑證，剩餘天數 <= 7 天就續期（正式環境）
python cf_cert_renew_all.py --days 14      # 改成 14 天門檻
python cf_cert_renew_all.py --staging      # 用測試環境（僅用來測試排程本身有沒有跑起來，不會簽出真的憑證）
```

**續期後自動清理**：每次跑完續期，腳本會重新掃描一次 `data/certs/`，凡是**續期後仍處於過期狀態**（代表這張憑證持續續期失敗，例如網域已經停用、NS 設定跑掉等）就會直接刪除該憑證資料夾，避免過期的殘留憑證一直堆在 `data/certs/` 底下，`renew.log` 會記錄被刪除的網域。

執行結果會寫進 `data/certs/renew.log`（累加寫入，不會覆蓋），沒有任何畫面互動，適合排程執行。

用同一份 image 跑一個獨立的排程服務（預設 7 天門檻、正式環境）：

```powershell
docker compose --profile renew up -d ops-tools-renew
```

這個服務背景跑一個「續期 → 睡 24 小時 → 續期 → ...」的迴圈，`docker compose logs -f ops-tools-renew` 可以看執行紀錄，跟 `data/certs/renew.log` 是同一份內容。

想先測試不同參數（例如改門檻天數、切測試環境），不用改設定檔，直接對已啟動的容器下一次性指令即可：

```powershell
docker compose exec ops-tools-renew python cf_cert_renew_all.py --days 14 --staging
```

要長期改預設參數，就編輯 `docker-compose.yml` 裡 `ops-tools-renew` 服務的 `command` 那一段。

## 修改功能

原始碼都在 `app/` 底下：

- 使用者/角色、CF 帳號的資料庫存取、加解密邏輯都在 `app/db.py`
- 清除快取的邏輯統一寫在 `app/cf_purge_core.py`，`load_accounts()` 會呼叫 `db.py` 從資料庫讀出帳號（api_key 已解密）
- NS 比對帳號、新增/刪除子網域的邏輯在 `app/cf_dns_ops.py`
- 強制 HTTPS、Page Rule 的邏輯在 `app/cf_zone_ops.py`，沿用 `cf_dns_ops.py` 的 NS 比對／重試／批次節流機制
- 憑證簽發/續期邏輯在 `app/cf_cert_ops.py`，`app/ops_tool_web.py`（網頁按鈕）跟 `app/cf_cert_renew_all.py`（排程腳本）都共用這支模組
- 使用者登入、角色檢查（`login_required`/`role_required`）、使用者管理/CF 帳號管理的 API 都在 `app/ops_tool_web.py`
- 改完（`app/ops_tool_web.py` / `app/db.py` / `app/cf_purge_core.py` / `app/cf_dns_ops.py` / `app/cf_zone_ops.py` / `app/cf_cert_ops.py` / `app/templates/`）：`app/` 是掛 volume 進去的，`docker compose restart ops-tools` 就會生效，不用重新 build；只有改 `requirements.txt` 才需要 `docker compose up -d --build`
- 改資料庫 schema（`db.py` 的 `init_schema()`）：目前沒有做 migration 機制，只有 `CREATE TABLE IF NOT EXISTS`，要改欄位需要自己手動 `ALTER TABLE` 或砍掉 `pgdata` volume 重建（會遺失所有資料）
