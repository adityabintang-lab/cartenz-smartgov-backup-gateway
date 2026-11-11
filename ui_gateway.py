import os
import json
import secrets
import hashlib
import logging
import re
from typing import Dict, Any
from fastapi import FastAPI, Request, Depends, HTTPException, status, Query, Header
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from qcloud_cos import CosConfig, CosS3Client
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

CONFIG_FILE = "/app/data/gateway_config.json"
logger = logging.getLogger("gateway")

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="SmartGOV Backup Gateway", docs_url=None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

security = HTTPBasic()

def hash_password(password: str, salt: str = None) -> tuple[str, str]:
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()
    return hashed, salt

def load_config() -> Dict[str, Any]:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_config(data: Dict[str, Any]):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=2)

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    cfg = load_config()
    admin_user = cfg.get("admin_user", "admin")
    stored_hash = cfg.get("admin_password_hash", "")
    salt = cfg.get("salt", "")

    # Fallback jika masih berupa plaintext lama
    if not stored_hash and "admin_password" in cfg:
        is_valid = (secrets.compare_digest(credentials.username, admin_user) and 
                    secrets.compare_digest(credentials.password, cfg["admin_password"]))
    elif stored_hash and salt:
        calc_hash, _ = hash_password(credentials.password, salt)
        is_valid = (secrets.compare_digest(credentials.username, admin_user) and 
                    secrets.compare_digest(calc_hash, stored_hash))
    else:
        raise HTTPException(status_code=503, detail="Gateway belum dikonfigurasi via Web Wizard.")

    if not is_valid:
        raise HTTPException(status_code=401, detail="Kredensial tidak valid.", headers={"WWW-Authenticate": "Basic"})
    return credentials.username

@app.get("/healthz")
def health_check():
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
def index():
    cfg = load_config()
    is_setup = ("admin_password_hash" in cfg or "admin_password" in cfg) and "cos_secret_id" in cfg
    page = """<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="dark light">
    <meta name="robots" content="noindex,nofollow">
    <title>SmartGOV Backup Gateway</title>
    <style>
        :root { color-scheme: dark light; --bg:#0f172a; --card:#1e293b; --bd:#334155; --fg:#f8fafc;
            --mut:#94a3b8; --in:#0f172a; --pri:#2563eb; --link:#60a5fa; --ok:#4ade80; --warn:#fbbf24; --err:#f87171; }
        @media (prefers-color-scheme:light) {
            :root { --bg:#f1f5f9; --card:#fff; --bd:#cbd5e1; --fg:#0f172a; --mut:#475569;
                --in:#fff; --link:#1d4ed8; --ok:#15803d; --warn:#b45309; --err:#b91c1c; }
        }
        *,*::before,*::after { box-sizing:border-box; }
        [hidden] { display:none!important; }
        body { margin:0; background:var(--bg); color:var(--fg); font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
        .wrap { max-width:1100px; margin:0 auto; padding:24px 16px 64px; }
        .topbar { display:flex; justify-content:space-between; align-items:center; gap:12px; margin-bottom:20px; }
        h1 { font-size:1.5rem; margin:0 0 4px; } h2 { font-size:1.05rem; margin:0 0 12px; }
        .sub { color:var(--mut); margin:0 0 20px; }
        .card { background:var(--card); border:1px solid var(--bd); border-radius:12px; padding:20px; margin-bottom:16px; }
        .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin-bottom:16px; }
        .k { color:var(--mut); font-size:.78rem; text-transform:uppercase; letter-spacing:.05em; }
        .v { font-weight:600; word-break:break-word; }
        .actions,.toolbar { display:flex; flex-wrap:wrap; align-items:center; gap:8px; }
        .toolbar { justify-content:space-between; margin-bottom:12px; }
        .banner,.notice { border:1px solid currentColor; border-radius:8px; padding:10px 14px; margin-bottom:12px; white-space:pre-line; }
        .ok { color:var(--ok); } .warn { color:var(--warn); } .err { color:var(--err); }
        button { min-height:42px; padding:8px 14px; font:inherit; color:inherit; background:transparent;
            border:1px solid var(--bd); border-radius:8px; cursor:pointer; }
        button.primary { background:var(--pri); border-color:var(--pri); color:#fff; font-weight:600; }
        button:disabled { opacity:.6; cursor:not-allowed; }
        input { width:100%; min-height:44px; padding:8px 12px; font:inherit; color:inherit;
            background:var(--in); border:1px solid var(--bd); border-radius:8px; }
        label { display:block; font-size:.9rem; margin-bottom:4px; }
        .field { min-width:0; flex:1 1 220px; }
        .form-row { display:flex; flex-wrap:wrap; gap:12px; align-items:end; }
        .scroll { overflow-x:auto; }
        table { width:100%; border-collapse:collapse; font-size:.9rem; }
        th,td { text-align:left; padding:10px 8px; border-bottom:1px solid var(--bd); vertical-align:middle; }
        th { color:var(--mut); font-weight:600; }
        td code { color:var(--link); word-break:break-all; }
        .right { text-align:right; white-space:nowrap; }
        .muted { color:var(--mut); }
        .crumbs { display:flex; flex-wrap:wrap; gap:6px; align-items:center; color:var(--mut); }
        .crumbs button { min-height:34px; padding:3px 8px; color:var(--link); }
        .folder { color:var(--link); }
        details>summary { cursor:pointer; min-height:42px; display:flex; align-items:center; font-weight:600; }
        :focus-visible { outline:3px solid var(--link); outline-offset:2px; }
        @media(max-width:600px) {
            .wrap { padding:18px 12px 40px; }
            .topbar { align-items:flex-start; }
            .card { padding:16px; }
            .right { white-space:normal; }
        }
    </style>
</head>
<body>
<main class="wrap">
    <header class="topbar">
        <div><h1>SmartGOV Backup Gateway</h1><p class="sub">Manajemen token agent dan arsip Object Storage.</p></div>
        <div id="authStatus"></div>
    </header>
    <div id="alertBox" role="status" aria-live="polite"></div>
    <div id="app"></div>
</main>
<script>
const isSetup = __IS_SETUP__;
let authHeader = localStorage.getItem('gw_auth') || '';
let currentPrefix = 'backups/';
let nextMarker = '';

function showAlert(message, type='err') {
    const box = document.getElementById('alertBox');
    box.className = message ? 'notice ' + type : '';
    box.textContent = message;
}
async function api(url, options={}) {
    const headers = Object.assign({}, options.headers || {});
    if (authHeader) headers.Authorization = authHeader;
    const response = await fetch(url, Object.assign({}, options, {headers}));
    let data = {};
    try { data = await response.json(); } catch (_) {}
    if (response.status === 401 && authHeader) {
        localStorage.removeItem('gw_auth');
        authHeader = '';
        renderLoginForm();
    }
    if (!response.ok) throw new Error(data.detail || 'Permintaan gagal (HTTP ' + response.status + ').');
    return data;
}
function logout() {
    localStorage.removeItem('gw_auth');
    authHeader = '';
    location.reload();
}
function renderLoginForm() {
    document.getElementById('app').innerHTML = `
        <section class="card" style="max-width:450px;margin:40px auto">
            <h2>Masuk ke Gateway</h2>
            <form onsubmit="handleLogin(event)">
                <div class="field"><label for="login_user">Username admin</label><input id="login_user" autocomplete="username" required></div>
                <div class="field" style="margin-top:12px"><label for="login_pass">Password</label><input id="login_pass" type="password" autocomplete="current-password" required></div>
                <button class="primary" style="width:100%;margin-top:16px">Masuk</button>
            </form>
        </section>`;
}
async function handleLogin(event) {
    event.preventDefault();
    authHeader = 'Basic ' + btoa(document.getElementById('login_user').value + ':' + document.getElementById('login_pass').value);
    try {
        await api('/api/tokens');
        localStorage.setItem('gw_auth', authHeader);
        showAlert('');
        renderDashboard();
    } catch (error) {
        authHeader = '';
        showAlert(error.message);
    }
}
function renderSetupWizard() {
    document.getElementById('app').innerHTML = `
        <section class="card">
            <h2>Setup Gateway</h2>
            <p class="muted">Konfigurasikan akun admin dan koneksi Tencent Cloud COS.</p>
            <form id="setupForm" onsubmit="saveSetup(event)">
                <h3>Keamanan admin</h3>
                <div class="form-row">
                    <div class="field"><label for="admin_user">Username admin</label><input id="admin_user" value="admin" required></div>
                    <div class="field"><label for="admin_pass">Password admin (minimal 6 karakter)</label><input id="admin_pass" type="password" minlength="6" required></div>
                </div>
                <h3 style="margin-top:20px">Tencent Cloud COS</h3>
                <div class="form-row">
                    <div class="field"><label for="cos_id">Secret ID</label><input id="cos_id" required></div>
                    <div class="field"><label for="cos_key">Secret Key</label><input id="cos_key" type="password" required></div>
                    <div class="field"><label for="cos_region">Region</label><input id="cos_region" placeholder="ap-jakarta" required></div>
                    <div class="field"><label for="cos_bucket">Bucket</label><input id="cos_bucket" placeholder="nama-bucket-1234567890" required></div>
                </div>
                <button class="primary" style="margin-top:16px">Simpan &amp; aktifkan Gateway</button>
            </form>
        </section>`;
}
async function saveSetup(event) {
    event.preventDefault();
    const payload = {
        admin_user: document.getElementById('admin_user').value.trim(),
        admin_password: document.getElementById('admin_pass').value,
        cos_secret_id: document.getElementById('cos_id').value.trim(),
        cos_secret_key: document.getElementById('cos_key').value,
        cos_region: document.getElementById('cos_region').value.trim(),
        cos_bucket: document.getElementById('cos_bucket').value.trim()
    };
    try {
        await api('/api/setup', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
        showAlert('Setup berhasil. Memuat ulang...', 'ok');
        setTimeout(() => location.reload(), 1200);
    } catch (error) { showAlert(error.message); }
}
function renderDashboard() {
    document.getElementById('authStatus').innerHTML = '<button type="button" onclick="logout()">Keluar</button>';
    document.getElementById('app').innerHTML = `
        <section class="card">
            <h2>Ringkasan Gateway</h2>
            <div class="grid">
                <div><div class="k">Bucket aktif</div><div class="v" id="bucketName">Memuat…</div></div>
                <div><div class="k">Token agent</div><div class="v" id="tokenCount">Memuat…</div></div>
                <div><div class="k">Lokasi arsip</div><div class="v">backups/</div></div>
            </div>
        </section>
        <section class="card">
            <div class="toolbar"><h2>Token Agent Target</h2></div>
            <form class="form-row" onsubmit="createToken(event)" style="margin-bottom:14px">
                <div class="field"><label for="serverName">Nama server target</label><input id="serverName" placeholder="Contoh: Dinas Kesehatan" maxlength="100" required></div>
                <button class="primary" type="submit">Generate token</button>
            </form>
            <div class="scroll"><table><thead><tr><th>Nama server</th><th>Agent API token</th><th class="right">Aksi</th></tr></thead>
                <tbody id="tokenTable"><tr><td colspan="3" class="muted">Memuat data token…</td></tr></tbody></table></div>
        </section>
        <section class="card">
            <div class="toolbar"><div><h2>File di Bucket</h2><div class="muted" id="bucketPath">backups/</div></div>
                <button type="button" onclick="loadObjects(currentPrefix, '')">Muat ulang</button></div>
            <nav class="crumbs" id="breadcrumbs" aria-label="Lokasi bucket"></nav>
            <div class="scroll" style="margin-top:10px"><table>
                <thead><tr><th>Nama file / folder</th><th>Ukuran</th><th>Terakhir diubah</th><th class="right">Aksi</th></tr></thead>
                <tbody id="objectTable"><tr><td colspan="4" class="muted">Memuat daftar bucket…</td></tr></tbody>
            </table></div>
            <div class="actions" style="justify-content:space-between;margin-top:12px">
                <span class="muted" id="objectPage"></span><button id="nextPage" type="button" hidden>Berikutnya</button>
            </div>
        </section>`;
    loadTokens();
    loadObjects(currentPrefix, '');
}
async function loadTokens() {
    const tbody = document.getElementById('tokenTable');
    try {
        const data = await api('/api/tokens');
        const tokens = data.tokens || {};
        document.getElementById('tokenCount').textContent = Object.keys(tokens).length;
        tbody.textContent = '';
        if (!Object.keys(tokens).length) {
            tbody.innerHTML = '<tr><td colspan="3" class="muted">Belum ada token agent.</td></tr>';
            return;
        }
        Object.entries(tokens).forEach(([token, name]) => {
            const tr = document.createElement('tr');
            const nameCell = document.createElement('td'); nameCell.textContent = name;
            const tokenCell = document.createElement('td'); const code = document.createElement('code'); code.textContent = token; tokenCell.append(code);
            const actionCell = document.createElement('td'); actionCell.className = 'right';
            const copy = document.createElement('button'); copy.textContent = 'Salin'; copy.onclick = () => copyToken(token);
            const remove = document.createElement('button'); remove.textContent = 'Hapus'; remove.style.marginLeft = '6px'; remove.onclick = () => deleteToken(token);
            actionCell.append(copy, remove); tr.append(nameCell, tokenCell, actionCell); tbody.append(tr);
        });
    } catch (error) { showAlert('Gagal memuat token: ' + error.message); }
}
async function createToken(event) {
    if (event) event.preventDefault();
    const input = document.getElementById('serverName');
    const name = input.value.trim();
    if (!name) { input.focus(); return; }
    try {
        const data = await api('/api/tokens/create?server_name=' + encodeURIComponent(name), {method:'POST'});
        input.value = '';
        showAlert('Token dibuat untuk ' + data.server_name + '. Salin token dari daftar.', 'ok');
        loadTokens();
    } catch (error) { showAlert('Gagal membuat token: ' + error.message); }
}
async function copyToken(token) {
    try {
        await navigator.clipboard.writeText(token);
        showAlert('Token berhasil disalin.', 'ok');
    } catch (_) { showAlert('Clipboard tidak tersedia. Salin token secara manual dari tabel.'); }
}
async function deleteToken(token) {
    if (!confirm('Hapus token ini? Agent terkait tidak akan dapat mengunggah backup.')) return;
    try {
        await api('/api/tokens/delete?token=' + encodeURIComponent(token), {method:'DELETE'});
        showAlert('Token berhasil dihapus.', 'ok');
        loadTokens();
    } catch (error) { showAlert('Gagal menghapus token: ' + error.message); }
}
function renderBreadcrumbs(prefix) {
    const nav = document.getElementById('breadcrumbs');
    nav.textContent = '';
    const root = document.createElement('button'); root.textContent = 'backups'; root.onclick = () => loadObjects('backups/', '');
    nav.append(root);
    const parts = prefix.slice('backups/'.length).split('/').filter(Boolean);
    let path = 'backups/';
    parts.forEach(part => {
        const sep = document.createElement('span'); sep.textContent = '/'; nav.append(sep);
        path += part + '/';
        const button = document.createElement('button'); button.textContent = part;
        const target = path; button.onclick = () => loadObjects(target, '');
        nav.append(button);
    });
}
function formatBytes(bytes) {
    let size = Number(bytes) || 0, unit = 0;
    const units = ['B','KB','MB','GB','TB'];
    while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit++; }
    return (unit ? size.toFixed(1) : size) + ' ' + units[unit];
}
function formatDate(value) {
    const date = value ? new Date(value) : null;
    return date && !Number.isNaN(date.getTime()) ? date.toLocaleString('id-ID') : '—';
}
async function loadObjects(prefix, marker) {
    currentPrefix = prefix;
    document.getElementById('bucketPath').textContent = prefix;
    renderBreadcrumbs(prefix);
    const tbody = document.getElementById('objectTable');
    tbody.innerHTML = '<tr><td colspan="4" class="muted">Memuat daftar bucket…</td></tr>';
    document.getElementById('nextPage').hidden = true;
    try {
        const params = new URLSearchParams({prefix});
        if (marker) params.set('marker', marker);
        const data = await api('/api/bucket/objects?' + params.toString());
        document.getElementById('bucketName').textContent = data.bucket;
        nextMarker = data.next_marker || '';
        tbody.textContent = '';
        const entries = [];
        (data.folders || []).forEach(folder => entries.push({folder:true, key:folder}));
        (data.objects || []).forEach(object => entries.push({folder:false, ...object}));
        if (!entries.length) {
            tbody.innerHTML = '<tr><td colspan="4" class="muted">Tidak ada file atau folder pada lokasi ini.</td></tr>';
        }
        entries.forEach(entry => {
            const tr = document.createElement('tr');
            const nameCell = document.createElement('td');
            const label = entry.folder ? entry.key.slice(prefix.length, -1) : entry.key.slice(prefix.length);
            if (entry.folder) {
                const button = document.createElement('button'); button.className = 'folder'; button.textContent = '📁 ' + label;
                button.onclick = () => loadObjects(entry.key, '');
                nameCell.append(button);
            } else nameCell.textContent = label;
            const size = document.createElement('td'); size.textContent = entry.folder ? '—' : formatBytes(entry.size);
            const modified = document.createElement('td'); modified.textContent = entry.folder ? '—' : formatDate(entry.last_modified);
            const actions = document.createElement('td'); actions.className = 'right';
            if (!entry.folder) {
                const download = document.createElement('button'); download.textContent = 'Unduh';
                download.onclick = () => downloadObject(entry.key);
                actions.append(download);
            }
            tr.append(nameCell, size, modified, actions); tbody.append(tr);
        });
        document.getElementById('objectPage').textContent = entries.length + ' item pada halaman ini';
        const next = document.getElementById('nextPage');
        next.hidden = !data.is_truncated || !nextMarker;
        next.onclick = () => loadObjects(currentPrefix, nextMarker);
    } catch (error) {
        tbody.innerHTML = '<tr><td colspan="4" class="err"></td></tr>';
        tbody.querySelector('td').textContent = 'Gagal memuat file bucket: ' + error.message;
    }
}
async function downloadObject(key) {
    const downloadWindow = window.open('about:blank', '_blank');
    if (!downloadWindow) {
        showAlert('Izinkan jendela baru untuk mengunduh file dari bucket.');
        return;
    }
    downloadWindow.opener = null;
    try {
        const data = await api('/api/bucket/download?key=' + encodeURIComponent(key));
        downloadWindow.location = data.download_url;
    } catch (error) {
        downloadWindow.close();
        showAlert('Gagal membuat tautan unduhan: ' + error.message);
    }
}
if (!isSetup) renderSetupWizard();
else if (!authHeader) renderLoginForm();
else renderDashboard();
</script>
</body>
</html>"""
    return HTMLResponse(page.replace("__IS_SETUP__", json.dumps(is_setup)))

@app.post("/api/setup")
@limiter.limit("5/minute")
def api_setup(request: Request, payload: Dict[str, Any]):
    cfg = load_config()
    if ("admin_password_hash" in cfg or "admin_password" in cfg) and "cos_secret_id" in cfg:
        raise HTTPException(status_code=403, detail="Setup Wizard telah selesai digunakan dan dikunci.")
    
    raw_password = payload.get("admin_password", "")
    if len(raw_password) < 6:
        raise HTTPException(status_code=400, detail="Kata sandi admin minimal 6 karakter.")

    hashed_pw, salt = hash_password(raw_password)
    
    config_data = {
        "admin_user": payload.get("admin_user", "admin"),
        "admin_password_hash": hashed_pw,
        "salt": salt,
        "cos_secret_id": payload.get("cos_secret_id"),
        "cos_secret_key": payload.get("cos_secret_key"),
        "cos_region": payload.get("cos_region"),
        "cos_bucket": payload.get("cos_bucket"),
        "tokens": {}
    }
    save_config(config_data)
    return {"status": "ok"}

@app.get("/api/tokens")
def get_tokens(username: str = Depends(verify_credentials)):
    cfg = load_config()
    return {"tokens": cfg.get("tokens", {})}

@app.post("/api/tokens/create")
def create_token(server_name: str = Query(...), username: str = Depends(verify_credentials)):
    cfg = load_config()
    new_token = f"sgtok_{secrets.token_hex(16)}"
    tokens = cfg.get("tokens", {})
    tokens[new_token] = server_name
    cfg["tokens"] = tokens
    save_config(cfg)
    return {"server_name": server_name, "token": new_token}

@app.delete("/api/tokens/delete")
def delete_token(token: str = Query(...), username: str = Depends(verify_credentials)):
    cfg = load_config()
    tokens = cfg.get("tokens", {})
    if token in tokens:
        del tokens[token]
        cfg["tokens"] = tokens
        save_config(cfg)
        return {"status": "ok"}
    raise HTTPException(status_code=404, detail="Token tidak ditemukan.")

def _cos_client(cfg: Dict[str, Any]) -> CosS3Client:
    cos_config = CosConfig(
        Region=cfg["cos_region"],
        SecretId=cfg["cos_secret_id"],
        SecretKey=cfg["cos_secret_key"],
    )
    return CosS3Client(cos_config)


def _valid_backup_path(value: str, *, allow_folder: bool) -> bool:
    if not value.startswith("backups/") or "\\" in value or len(value) > 1024:
        return False
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return False
    parts = value.split("/")
    if any(part in (".", "..") for part in parts):
        return False
    return allow_folder or not value.endswith("/")


@app.get("/api/bucket/objects")
def list_bucket_objects(
    prefix: str = Query("backups/"),
    marker: str = Query(""),
    username: str = Depends(verify_credentials),
):
    if not _valid_backup_path(prefix, allow_folder=True):
        raise HTTPException(status_code=400, detail="Lokasi bucket tidak valid.")
    if marker and (not marker.startswith(prefix) or not _valid_backup_path(marker, allow_folder=True)):
        raise HTTPException(status_code=400, detail="Penanda halaman tidak valid.")

    cfg = load_config()
    try:
        params = {
            "Bucket": cfg["cos_bucket"],
            "Prefix": prefix,
            "Delimiter": "/",
            "MaxKeys": 100,
        }
        if marker:
            params["Marker"] = marker
        response = _cos_client(cfg).list_objects(**params)
    except Exception as exc:
        logger.exception("Gagal mengambil daftar objek dari COS.")
        raise HTTPException(status_code=502, detail="Gagal mengambil daftar file dari bucket COS.") from exc

    folders = [item["Prefix"] for item in response.get("CommonPrefixes", [])]
    objects = [
        {
            "key": item["Key"],
            "size": int(item.get("Size", 0)),
            "last_modified": item.get("LastModified"),
        }
        for item in response.get("Contents", [])
        if item.get("Key") != prefix
    ]
    next_marker = response.get("NextMarker", "")
    if response.get("IsTruncated") and not next_marker:
        keys = [item["key"] for item in objects] + folders
        next_marker = max(keys) if keys else marker
    return {
        "bucket": cfg["cos_bucket"],
        "prefix": prefix,
        "folders": folders,
        "objects": objects,
        "is_truncated": bool(response.get("IsTruncated")),
        "next_marker": next_marker,
    }


@app.get("/api/bucket/download")
def get_download_url(key: str = Query(...), username: str = Depends(verify_credentials)):
    if not _valid_backup_path(key, allow_folder=False):
        raise HTTPException(status_code=400, detail="Lokasi file tidak valid.")
    cfg = load_config()
    try:
        download_url = _cos_client(cfg).get_presigned_url(
            Method="GET",
            Bucket=cfg["cos_bucket"],
            Key=key,
            Expired=300,
        )
    except Exception as exc:
        logger.exception("Gagal membuat tautan unduhan COS.")
        raise HTTPException(status_code=502, detail="Gagal membuat tautan unduhan dari bucket COS.") from exc
    return {"download_url": download_url}

@app.post("/api/v1/get-upload-url")
@limiter.limit("30/minute")
def get_upload_url(
    request: Request, 
    filename: str, 
    authorization: str = Header(None)  # <--- PERBAIKAN DI SINI
):
    if not authorization:
        raise HTTPException(status_code=401, detail="Header Authorization diperlukan.")
        
    token = authorization.replace("Bearer ", "").strip()
    cfg = load_config()
    tokens = cfg.get("tokens", {})
    server_name = tokens.get(token)
    
    if not server_name:
        raise HTTPException(status_code=401, detail="Token Target Agent tidak valid.")
    
    # Sanitasi nama berkas untuk mencegah Path Traversal
    safe_filename = os.path.basename(filename)
    safe_filename = re.sub(r'[^a-zA-Z0-9_.-]', '_', safe_filename)
    
    try:
        client = _cos_client(cfg)
        folder_name = re.sub(r'[^a-zA-Z0-9_-]', '_', server_name.lower().replace(' ', '_'))
        cos_key = f"backups/{folder_name}/{safe_filename}"
        
        upload_url = client.get_presigned_url(
            Method="PUT", 
            Bucket=cfg["cos_bucket"], 
            Key=cos_key, 
            Expired=900
        )
        return {"upload_url": upload_url, "cos_key": cos_key}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Gagal membuat Presigned URL.")
