import os
import json
import secrets
import hashlib
import logging
import re
import asyncio
import time
import tempfile
import shutil
from typing import Dict, Any
from fastapi import FastAPI, Request, Depends, HTTPException, status, Query, Header
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
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
_SCAN_SEGMENTS = {
    ".git", ".github", ".svn", ".hg", "admin", "cgi-bin",
    "phpmyadmin", "wp-admin", "wp-content", "wp-includes",
}


@app.middleware("http")
async def harden_requests(request: Request, call_next):
    path_segments = [segment.lower() for segment in request.url.path.split("/") if segment]
    if any(
        segment in _SCAN_SEGMENTS or segment == ".env" or segment.startswith(".env.")
        for segment in path_segments
    ):
        response = JSONResponse(status_code=404, content={"detail": "Not Found"})
    else:
        response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    return response

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
    config_dir = os.path.dirname(CONFIG_FILE)
    os.makedirs(config_dir, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".gateway-config-", dir=config_dir)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, CONFIG_FILE)
    except Exception:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise

def _authenticate(credentials: HTTPBasicCredentials) -> Dict[str, str]:
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
        is_valid = False

    if is_valid:
        return {"role": "admin", "identity": credentials.username}

    email = credentials.username.strip().lower()
    configured_users = cfg.get("users", {})
    users = configured_users if isinstance(configured_users, dict) else {}
    account = users.get(email)
    if isinstance(account, dict):
        stored_user_hash = account.get("password_hash", "")
        user_salt = account.get("salt", "")
        if stored_user_hash and user_salt:
            calculated_hash, _ = hash_password(credentials.password, user_salt)
            if secrets.compare_digest(calculated_hash, stored_user_hash):
                if account.get("status") != "approved":
                    raise HTTPException(status_code=403, detail="Akun menunggu persetujuan admin.")
                folders = account.get("folders", [])
                if not isinstance(folders, list):
                    folders = []
                return {
                    "role": "viewer",
                    "identity": email,
                    "folders": [folder for folder in folders if isinstance(folder, str)],
                }

    if not (cfg.get("admin_password_hash") or "admin_password" in cfg) or not cfg.get("cos_secret_id"):
        raise HTTPException(status_code=503, detail="Gateway belum dikonfigurasi via Web Wizard.")
    raise HTTPException(status_code=401, detail="Kredensial tidak valid.", headers={"WWW-Authenticate": "Basic"})


def get_current_user(credentials: HTTPBasicCredentials = Depends(security)) -> Dict[str, str]:
    return _authenticate(credentials)


def verify_credentials(user: Dict[str, str] = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Akses khusus admin.")
    return user["identity"]

@app.get("/healthz")
def health_check():
    return {"status": "ok"}


@app.get("/api/auth/me")
@limiter.limit("10/minute")
def auth_me(request: Request, user: Dict[str, str] = Depends(get_current_user)):
    return {"role": user["role"], "identity": user["identity"]}


@app.post("/api/auth/register")
@limiter.limit("5/minute")
def register_user(request: Request, payload: Dict[str, Any]):
    cfg = load_config()
    if not (cfg.get("admin_password_hash") or "admin_password" in cfg) or not cfg.get("cos_secret_id"):
        raise HTTPException(status_code=503, detail="Gateway belum dikonfigurasi via Web Wizard.")

    email = payload.get("email", "")
    password = payload.get("password", "")
    if not isinstance(email, str) or len(email) > 254 or not re.fullmatch(
        r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+",
        email,
    ):
        raise HTTPException(status_code=400, detail="Alamat email tidak valid.")
    if (
        not isinstance(password, str)
        or len(password) < 12
        or len(password) > 256
        or any(ord(char) < 32 or ord(char) == 127 for char in password)
    ):
        raise HTTPException(status_code=400, detail="Password harus berisi 12 hingga 256 karakter.")

    email = email.lower()
    admin_user = str(cfg.get("admin_user", "")).lower()
    configured_users = cfg.get("users", {})
    users = configured_users if isinstance(configured_users, dict) else {}
    if email == admin_user or email in users:
        raise HTTPException(status_code=409, detail="Email sudah terdaftar.")

    password_hash, salt = hash_password(password)
    cfg["users"] = users
    users[email] = {
        "password_hash": password_hash,
        "salt": salt,
        "status": "pending",
        "created_at": time.time(),
    }
    save_config(cfg)
    return {"status": "pending", "message": "Pendaftaran diterima dan menunggu persetujuan admin."}


@app.get("/api/registrations")
def list_users(username: str = Depends(verify_credentials)):
    cfg = load_config()
    users = cfg.get("users", {})
    tokens = cfg.get("tokens", {})
    if not isinstance(users, dict):
        users = {}
    return {
        "users": [
            {
                "email": email,
                "status": account.get("status", "pending"),
                "created_at": account.get("created_at"),
                "folders": account.get("folders", []),
            }
            for email, account in sorted(users.items())
            if isinstance(account, dict)
        ],
        "agents": [
            {"folder": _server_folder_name(name), "name": name}
            for name in tokens.values()
            if isinstance(name, str) and _server_folder_name(name).strip("_")
        ] if isinstance(tokens, dict) else [],
    }


@app.post("/api/registrations/approve")
def approve_user(payload: Dict[str, Any], username: str = Depends(verify_credentials)):
    email = payload.get("email", "")
    folders = payload.get("folders")
    if not isinstance(email, str) or not 3 <= len(email) <= 254:
        raise HTTPException(status_code=400, detail="Alamat email tidak valid.")
    if not isinstance(folders, list) or not 1 <= len(folders) <= 100:
        raise HTTPException(status_code=400, detail="Pilih satu atau beberapa Agent untuk user ini.")
    if any(not isinstance(folder, str) for folder in folders) or len(set(folders)) != len(folders):
        raise HTTPException(status_code=400, detail="Daftar folder Agent tidak valid.")

    normalized_email = email.strip().lower()
    cfg = load_config()
    users = cfg.get("users", {})
    tokens = cfg.get("tokens", {})
    if not isinstance(users, dict) or not isinstance(tokens, dict):
        raise HTTPException(status_code=503, detail="Data user atau token Gateway tidak valid.")
    account = users.get(normalized_email)
    if not isinstance(account, dict):
        raise HTTPException(status_code=404, detail="Pendaftar tidak ditemukan.")
    if account.get("status") != "pending":
        raise HTTPException(status_code=409, detail="Akun tidak sedang menunggu persetujuan.")
    available_folders = {
        _server_folder_name(name)
        for name in tokens.values()
        if isinstance(name, str) and _server_folder_name(name).strip("_")
    }
    if any(folder not in available_folders for folder in folders):
        raise HTTPException(status_code=400, detail="Folder Agent yang dipilih tidak tersedia.")
    account["status"] = "approved"
    account["folders"] = folders
    account["approved_at"] = time.time()
    save_config(cfg)
    return {"status": "approved", "folders": folders}


@app.delete("/api/registrations/pending")
def reject_user(email: str = Query(..., min_length=3, max_length=254), username: str = Depends(verify_credentials)):
    normalized_email = email.strip().lower()
    cfg = load_config()
    users = cfg.get("users", {})
    account = users.get(normalized_email)
    if not isinstance(account, dict):
        raise HTTPException(status_code=404, detail="Pendaftar tidak ditemukan.")
    if account.get("status") != "pending":
        raise HTTPException(status_code=409, detail="Hanya pendaftaran yang masih menunggu yang dapat ditolak.")
    del users[normalized_email]
    save_config(cfg)
    return {"status": "rejected"}


@app.delete("/api/registrations/approved")
def revoke_user(email: str = Query(..., min_length=3, max_length=254), username: str = Depends(verify_credentials)):
    normalized_email = email.strip().lower()
    cfg = load_config()
    users = cfg.get("users", {})
    if not isinstance(users, dict):
        raise HTTPException(status_code=404, detail="User aktif tidak ditemukan.")
    account = users.get(normalized_email)
    if not isinstance(account, dict) or account.get("status") != "approved":
        raise HTTPException(status_code=404, detail="User aktif tidak ditemukan.")
    del users[normalized_email]
    save_config(cfg)
    return {"status": "revoked"}


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
    <script>document.documentElement.dataset.bsTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';</script>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet"
        integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB" crossorigin="anonymous">
    <style>
        :root { color-scheme: dark light; --bg:#0f172a; --card:#1e293b; --bd:#334155; --fg:#f8fafc;
            --mut:#94a3b8; --in:#0f172a; --pri:#2563eb; --link:#60a5fa; --ok:#4ade80; --warn:#fbbf24; --err:#f87171;
            --bs-body-bg:var(--bg); --bs-body-color:var(--fg); --bs-secondary-color:var(--mut);
            --bs-border-color:var(--bd); --bs-tertiary-bg:var(--in); --bs-card-bg:var(--card); --bs-card-border-color:var(--bd); }
        @media (prefers-color-scheme:light) {
            :root { --bg:#f1f5f9; --card:#fff; --bd:#cbd5e1; --fg:#0f172a; --mut:#475569;
                --in:#fff; --link:#1d4ed8; --ok:#15803d; --warn:#b45309; --err:#b91c1c; --bs-card-bg:#fff; }
        }
        [hidden] { display:none!important; }
        body { min-height:100vh; background:var(--bg); color:var(--fg); font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif; }
        .card { border-radius:12px; }
        h1 { font-size:1.5rem; margin:0 0 4px; } h2 { font-size:1.05rem; }
        .sub { color:var(--mut); }
        .k { color:var(--mut); font-size:.78rem; text-transform:uppercase; letter-spacing:.05em; }
        .v { font-weight:600; word-break:break-word; }
        .actions { display:flex; flex-wrap:wrap; align-items:center; gap:8px; }
        .toolbar { display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:.75rem; margin-bottom:12px; }
        .field { min-width:0; }
        .form-control,.form-select { min-height:44px; }
        .scroll { overflow-x:auto; }
        td code { color:var(--link); word-break:break-all; }
        .right { text-align:right; white-space:nowrap; }
        .muted { color:var(--mut); }
        .crumbs { display:flex; flex-wrap:wrap; gap:6px; align-items:center; color:var(--mut); }
        details>summary { cursor:pointer; font-weight:600; }
        :focus-visible { outline:3px solid var(--link); outline-offset:2px; }
        @media(max-width:600px) {
            .right { white-space:normal; }
        }
    </style>
</head>
<body>
<main class="container py-4 pb-5">
    <header class="d-flex justify-content-between align-items-center gap-3 mb-4">
        <div><h1>SmartGOV Backup Gateway</h1><p class="sub mb-0">Manajemen token agent dan arsip Object Storage.</p></div>
        <div id="authStatus"></div>
    </header>
    <div id="alertBox" role="status" aria-live="polite"></div>
    <div id="app"></div>
</main>
<script>
const isSetup = __IS_SETUP__;
let authHeader = localStorage.getItem('gw_auth') || '';
let currentRole = '';
let currentPrefix = 'backups/';
let nextMarker = '';
let currentBucketId = localStorage.getItem('gw_bucket') || '';
let availableBuckets = [];

function showAlert(message, type='err') {
    const box = document.getElementById('alertBox');
    box.className = message ? 'alert alert-' + (type === 'ok' ? 'success' : 'danger') : '';
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
        <section class="card mx-auto my-5" style="max-width:450px"><div class="card-body">
            <h2 class="mb-3">Masuk ke Gateway</h2>
            <form id="loginForm" onsubmit="handleLogin(event)">
                <div class="mb-3"><label class="form-label" for="login_user">Email atau username admin</label><input class="form-control" id="login_user" type="text" autocomplete="username" required></div>
                <div class="mb-3"><label class="form-label" for="login_pass">Password</label><input class="form-control" id="login_pass" type="password" autocomplete="current-password" required></div>
                <button class="btn btn-primary w-100">Masuk</button>
            </form>
            <hr class="my-4">
            <button class="btn btn-outline-secondary" type="button" onclick="renderRegisterForm()">Daftar sebagai user biasa</button>
        </div></section>`;
}
async function handleLogin(event) {
    event.preventDefault();
    const credentials = document.getElementById('login_user').value.trim() + ':' + document.getElementById('login_pass').value;
    authHeader = 'Basic ' + btoa(String.fromCharCode(...new TextEncoder().encode(credentials)));
    try {
        const user = await api('/api/auth/me');
        localStorage.setItem('gw_auth', authHeader);
        showAlert('');
        currentRole = user.role;
        if (currentRole === 'admin') renderDashboard();
        else renderViewer();
    } catch (error) {
        authHeader = '';
        showAlert(error.message);
    }
}
function renderRegisterForm() {
    document.getElementById('app').innerHTML = `
        <section class="card mx-auto my-5" style="max-width:450px"><div class="card-body">
            <h2 class="mb-3">Daftar user biasa</h2>
            <p class="muted">Akses diberikan setelah admin Gateway menyetujui pendaftaran.</p>
            <form onsubmit="handleRegister(event)">
                <div class="mb-3"><label class="form-label" for="register_email">Email</label><input class="form-control" id="register_email" type="email" maxlength="254" autocomplete="email" required></div>
                <div class="mb-3"><label class="form-label" for="register_password">Password (minimal 12 karakter)</label><input class="form-control" id="register_password" type="password" minlength="12" maxlength="256" autocomplete="new-password" required></div>
                <button class="btn btn-primary w-100">Kirim pendaftaran</button>
            </form>
            <button class="btn btn-outline-secondary mt-3" type="button" onclick="renderLoginForm()">Kembali ke login</button>
        </div></section>`;
}
async function handleRegister(event) {
    event.preventDefault();
    try {
        const result = await api('/api/auth/register', {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({
                email:document.getElementById('register_email').value.trim(),
                password:document.getElementById('register_password').value
            })
        });
        renderLoginForm();
        showAlert(result.message, 'ok');
    } catch (error) { showAlert(error.message); }
}
function renderSetupWizard() {
    document.getElementById('app').innerHTML = `
        <section class="card mb-3"><div class="card-body">
            <h2 class="mb-3">Setup Gateway</h2>
            <p class="muted">Konfigurasikan akun admin dan koneksi Tencent Cloud COS.</p>
            <form id="setupForm" onsubmit="saveSetup(event)">
                <h3 class="h5 mt-4">Keamanan admin</h3>
                <div class="row g-3">
                    <div class="col-12 col-md-6"><label class="form-label" for="admin_user">Username admin</label><input class="form-control" id="admin_user" value="admin" required></div>
                    <div class="col-12 col-md-6"><label class="form-label" for="admin_pass">Password admin (minimal 6 karakter)</label><input class="form-control" id="admin_pass" type="password" minlength="6" required></div>
                </div>
                <h3 class="h5 mt-4">Tencent Cloud COS</h3>
                <div class="row g-3">
                    <div class="col-12 col-md-6"><label class="form-label" for="cos_id">Secret ID</label><input class="form-control" id="cos_id" required></div>
                    <div class="col-12 col-md-6"><label class="form-label" for="cos_key">Secret Key</label><input class="form-control" id="cos_key" type="password" required></div>
                    <div class="col-12 col-md-6"><label class="form-label" for="cos_region">Region</label><input class="form-control" id="cos_region" placeholder="ap-jakarta" required></div>
                    <div class="col-12 col-md-6"><label class="form-label" for="cos_bucket">Bucket</label><input class="form-control" id="cos_bucket" placeholder="nama-bucket-1234567890" required></div>
                </div>
                <button class="btn btn-primary mt-3">Simpan &amp; aktifkan Gateway</button>
            </form>
        </div></section>`;
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
    currentRole = 'admin';
    document.getElementById('authStatus').innerHTML = '<button class="btn btn-outline-secondary" type="button" onclick="logout()">Keluar</button>';
    document.getElementById('app').innerHTML = `
        <section class="card mb-3"><div class="card-body">
            <h2 class="mb-3">Ringkasan Gateway</h2>
            <div class="row g-3">
                <div class="col-12 col-md-4"><div class="k">Bucket aktif</div><div class="v" id="bucketName">Memuat…</div></div>
                <div class="col-12 col-md-4"><div class="k">Token agent</div><div class="v" id="tokenCount">Memuat…</div></div>
                <div class="col-12 col-md-4"><div class="k">Lokasi arsip</div><div class="v">backups/</div></div>
            </div>
        </div></section>
        <section class="card mb-3"><div class="card-body">
            <div class="toolbar"><div><h2>Pendaftaran user</h2><div class="muted">Setujui atau tolak permintaan akses baca-saja.</div></div>
                <button class="btn btn-outline-secondary" type="button" onclick="loadUsers()">Muat ulang</button></div>
            <div class="table-responsive"><table class="table table-hover align-middle mb-0"><thead><tr><th>Email</th><th>Status</th><th>Agent diizinkan</th><th>Terdaftar</th><th class="right">Aksi</th></tr></thead>
                <tbody id="userTable"><tr><td colspan="5" class="muted">Memuat pendaftaran…</td></tr></tbody></table></div>
        </div></section>
        <section class="card mb-3"><div class="card-body">
            <h2 class="mb-3">Daftar bucket COS</h2>
            <form id="bucketForm" class="row g-3 align-items-end mb-3" onsubmit="createBucket(event)">
                <div class="col-12 col-md-4"><label class="form-label" for="bucketLabel">Nama tampilan</label><input class="form-control" id="bucketLabel" maxlength="80" required></div>
                <div class="col-12 col-md-4"><label class="form-label" for="bucketRegion">Region</label><input class="form-control" id="bucketRegion" placeholder="ap-jakarta" maxlength="64" required></div>
                <div class="col-12 col-md-4"><label class="form-label" for="bucketNameInput">Nama bucket</label><input class="form-control" id="bucketNameInput" maxlength="256" required></div>
                <div class="col-12 col-md-6"><label class="form-label" for="bucketSecretId">Secret ID</label><input class="form-control" id="bucketSecretId" autocomplete="off" required></div>
                <div class="col-12 col-md-6"><label class="form-label" for="bucketSecretKey">Secret Key</label><input class="form-control" id="bucketSecretKey" type="password" autocomplete="new-password" required></div>
                <div class="col-12"><button class="btn btn-primary" type="submit">Tambah &amp; uji bucket</button></div>
            </form>
            <div class="table-responsive"><table class="table table-hover align-middle mb-0"><thead><tr><th>Nama</th><th>Bucket COS</th><th>Region</th><th class="right">Aksi</th></tr></thead>
                <tbody id="bucketTable"><tr><td colspan="4" class="muted">Memuat bucket…</td></tr></tbody></table></div>
        </div></section>
        <section class="card mb-3"><div class="card-body">
            <div class="toolbar"><h2>Token Agent Target</h2></div>
            <form class="row g-3 align-items-end mb-3" onsubmit="createToken(event)">
                <div class="col-12 col-md-5"><label class="form-label" for="serverName">Nama daerah / Agent</label><input class="form-control" id="serverName" placeholder="Contoh: Kabupaten Bogor" maxlength="100" required></div>
                <div class="col-12 col-md-5"><label class="form-label" for="tokenBucket">Bucket tujuan</label><select class="form-select" id="tokenBucket" required></select></div>
                <div class="col-12 col-md-auto"><button class="btn btn-primary" type="submit">Generate token</button></div>
            </form>
            <div class="table-responsive"><table class="table table-hover align-middle mb-0"><thead><tr><th>Nama server</th><th>Bucket tujuan</th><th>Agent API token</th><th class="right">Aksi</th></tr></thead>
                <tbody id="tokenTable"><tr><td colspan="4" class="muted">Memuat data token…</td></tr></tbody></table></div>
        </div></section>
        ${bucketBrowserMarkup()}`;
    loadUsers();
    loadBuckets().then(() => {
        loadTokens();
        loadObjects(currentPrefix, '');
    });
}
function bucketBrowserMarkup() {
    return `
        <section class="card mb-3"><div class="card-body">
            <div class="toolbar"><div><h2>File di Bucket</h2><div class="muted" id="bucketPath">backups/</div>
                <label class="form-label mt-2" for="activeBucket">Bucket yang ditampilkan</label><select class="form-select" id="activeBucket"></select></div>
                <button class="btn btn-outline-secondary" type="button" onclick="loadObjects(currentPrefix, '')">Muat ulang</button></div>
            <nav class="crumbs" id="breadcrumbs" aria-label="Lokasi bucket"></nav>
            <div class="table-responsive mt-3"><table class="table table-hover align-middle mb-0">
                <thead><tr><th>Nama file / folder</th><th>Ukuran</th><th>Terakhir diubah</th><th class="right">Aksi</th></tr></thead>
                <tbody id="objectTable"><tr><td colspan="4" class="muted">Memuat daftar bucket…</td></tr></tbody>
            </table></div>
            <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mt-3">
                <span class="muted" id="objectPage"></span><button class="btn btn-outline-secondary" id="nextPage" type="button" hidden>Berikutnya</button>
            </div>
        </div></section>`;
}
function renderViewer() {
    currentRole = 'viewer';
    document.getElementById('authStatus').innerHTML = '<button class="btn btn-outline-secondary" type="button" onclick="logout()">Keluar</button>';
    document.getElementById('app').innerHTML = `
        <section class="card mb-3"><div class="card-body">
            <h2>Arsip backup</h2>
            <p class="muted">Akses baca-saja. File yang diunduh tetap terenkripsi; fitur token dan dekripsi hanya tersedia untuk admin.</p>
            <div class="row"><div class="col-12"><div class="k">Bucket</div><div class="v" id="bucketName">Memuat…</div></div></div>
        </div></section>
        ${bucketBrowserMarkup()}`;
    loadBuckets().then(() => loadObjects(currentPrefix, ''));
}
function bucketLabel(bucketId) {
    const bucket = availableBuckets.find(item => item.id === bucketId);
    return bucket ? bucket.name + ' (' + bucket.bucket + ')' : 'Bucket tidak tersedia';
}
async function loadBuckets() {
    try {
        const data = await api('/api/buckets');
        availableBuckets = data.buckets || [];
        if (!availableBuckets.some(bucket => bucket.id === currentBucketId)) {
            currentBucketId = availableBuckets.length ? availableBuckets[0].id : '';
        }
        if (currentBucketId) localStorage.setItem('gw_bucket', currentBucketId);
        const selector = document.getElementById('activeBucket');
        if (selector) {
            selector.textContent = '';
            availableBuckets.forEach(bucket => {
                const option = document.createElement('option');
                option.value = bucket.id;
                option.textContent = bucketLabel(bucket.id);
                selector.append(option);
            });
            selector.value = currentBucketId;
            selector.disabled = availableBuckets.length < 2;
            selector.onchange = () => {
                currentBucketId = selector.value;
                localStorage.setItem('gw_bucket', currentBucketId);
                currentPrefix = 'backups/';
                const table = document.getElementById('bucketName');
                if (table) table.textContent = bucketLabel(currentBucketId);
                loadObjects(currentPrefix, '');
            };
        }
        const tokenSelector = document.getElementById('tokenBucket');
        if (tokenSelector) {
            tokenSelector.textContent = '';
            availableBuckets.forEach(bucket => {
                const option = document.createElement('option');
                option.value = bucket.id;
                option.textContent = bucketLabel(bucket.id);
                tokenSelector.append(option);
            });
            tokenSelector.disabled = !availableBuckets.length;
        }
        const tbody = document.getElementById('bucketTable');
        if (tbody) {
            tbody.textContent = '';
            if (!availableBuckets.length) {
                tbody.innerHTML = '<tr><td colspan="4" class="muted">Belum ada bucket yang tersedia.</td></tr>';
            }
            availableBuckets.forEach(bucket => {
                const row = document.createElement('tr');
                const label = document.createElement('td'); label.textContent = bucket.name;
                const name = document.createElement('td'); name.textContent = bucket.bucket;
                const region = document.createElement('td'); region.textContent = bucket.region;
                const actions = document.createElement('td'); actions.className = 'right';
                const remove = document.createElement('button');
                remove.className = 'btn btn-sm btn-outline-danger';
                remove.textContent = 'Hapus';
                remove.onclick = () => deleteBucket(bucket.id, bucket.name);
                actions.append(remove);
                row.append(label, name, region, actions);
                tbody.append(row);
            });
        }
        const label = document.getElementById('bucketName');
        if (label) label.textContent = bucketLabel(currentBucketId);
    } catch (error) {
        showAlert('Gagal memuat daftar bucket: ' + error.message);
        availableBuckets = [];
    }
}
async function createBucket(event) {
    event.preventDefault();
    const form = document.getElementById('bucketForm');
    const payload = {
        name: document.getElementById('bucketLabel').value.trim(),
        cos_region: document.getElementById('bucketRegion').value.trim(),
        cos_bucket: document.getElementById('bucketNameInput').value.trim(),
        cos_secret_id: document.getElementById('bucketSecretId').value.trim(),
        cos_secret_key: document.getElementById('bucketSecretKey').value
    };
    try {
        await api('/api/buckets', {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify(payload)
        });
        form.reset();
        await loadBuckets();
        showAlert('Bucket ditambahkan dan aksesnya berhasil diuji.', 'ok');
    } catch (error) { showAlert('Gagal menambahkan bucket: ' + error.message); }
}
async function deleteBucket(bucketId, name) {
    if (!confirm('Hapus konfigurasi bucket ' + name + '? Bucket yang dipakai Agent tidak dapat dihapus.')) return;
    try {
        await api('/api/buckets/' + encodeURIComponent(bucketId), {method:'DELETE'});
        await loadBuckets();
        loadTokens();
        loadObjects('backups/', '');
        showAlert('Bucket berhasil dihapus dari daftar Gateway.', 'ok');
    } catch (error) { showAlert('Gagal menghapus bucket: ' + error.message); }
}
async function loadUsers() {
    const tbody = document.getElementById('userTable');
    if (!tbody) return;
    try {
        const data = await api('/api/registrations');
        tbody.textContent = '';
        const users = data.users || [];
        const agents = data.agents || [];
        if (!users.length) {
            tbody.innerHTML = '<tr><td colspan="5" class="muted">Belum ada pendaftaran.</td></tr>';
            return;
        }
        users.forEach(user => {
            const tr = document.createElement('tr');
            const email = document.createElement('td'); email.textContent = user.email;
            const status = document.createElement('td'); status.textContent = user.status === 'approved' ? 'Disetujui' : 'Menunggu';
            const scope = document.createElement('td');
            const created = document.createElement('td'); created.textContent = formatDate(user.created_at ? new Date(user.created_at * 1000).toISOString() : '');
            const actions = document.createElement('td'); actions.className = 'right';
            if (user.status === 'pending') {
                const select = document.createElement('select');
                select.className = 'form-select';
                select.multiple = true;
                select.size = Math.min(Math.max(agents.length, 2), 5);
                select.setAttribute('aria-label', 'Pilih Agent yang boleh dilihat user ini');
                agents.forEach(agent => {
                    const option = document.createElement('option');
                    option.value = agent.folder;
                    option.textContent = agent.name;
                    select.append(option);
                });
                scope.append(select);
                const approve = document.createElement('button'); approve.className = 'btn btn-sm btn-success'; approve.textContent = 'Setujui'; approve.disabled = !agents.length;
                approve.onclick = () => approveUser(user.email, select);
                const reject = document.createElement('button'); reject.className = 'btn btn-sm btn-outline-danger ms-1'; reject.textContent = 'Tolak'; reject.onclick = () => rejectUser(user.email);
                actions.append(approve, reject);
            } else {
                const labels = (user.folders || []).map(folder => {
                    const agent = agents.find(item => item.folder === folder);
                    return agent ? agent.name : folder;
                });
                scope.textContent = labels.join(', ') || 'Tidak ada Agent diizinkan';
                const revoke = document.createElement('button'); revoke.className = 'btn btn-sm btn-outline-danger'; revoke.textContent = 'Cabut akses'; revoke.onclick = () => revokeUser(user.email);
                actions.append(revoke);
            }
            tr.append(email, status, scope, created, actions); tbody.append(tr);
        });
    } catch (error) { showAlert('Gagal memuat pendaftaran: ' + error.message); }
}
async function approveUser(email, select) {
    const folders = Array.from(select.selectedOptions, option => option.value);
    if (!folders.length) { showAlert('Pilih minimal satu Agent untuk user ini.'); return; }
    try {
        await api('/api/registrations/approve', {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body:JSON.stringify({email, folders})
        });
        showAlert('Akun ' + email + ' disetujui.', 'ok');
        loadUsers();
    } catch (error) { showAlert('Gagal menyetujui akun: ' + error.message); }
}
async function rejectUser(email) {
    if (!confirm('Tolak dan hapus pendaftaran ' + email + '?')) return;
    try {
        await api('/api/registrations/pending?email=' + encodeURIComponent(email), {method:'DELETE'});
        showAlert('Pendaftaran ditolak.', 'ok');
        loadUsers();
    } catch (error) { showAlert('Gagal menolak pendaftaran: ' + error.message); }
}
async function revokeUser(email) {
    if (!confirm('Cabut akses baca-saja untuk ' + email + '?')) return;
    try {
        await api('/api/registrations/approved?email=' + encodeURIComponent(email), {method:'DELETE'});
        showAlert('Akses user dicabut.', 'ok');
        loadUsers();
    } catch (error) { showAlert('Gagal mencabut akses: ' + error.message); }
}
async function loadTokens() {
    const tbody = document.getElementById('tokenTable');
    try {
        const data = await api('/api/tokens');
        const tokens = data.tokens || {};
        const tokenBuckets = data.token_buckets || {};
        document.getElementById('tokenCount').textContent = Object.keys(tokens).length;
        tbody.textContent = '';
        if (!Object.keys(tokens).length) {
            tbody.innerHTML = '<tr><td colspan="4" class="muted">Belum ada token agent.</td></tr>';
            return;
        }
        Object.entries(tokens).forEach(([token, name]) => {
            const tr = document.createElement('tr');
            const nameCell = document.createElement('td'); nameCell.textContent = name;
            const bucketCell = document.createElement('td'); bucketCell.textContent = bucketLabel(tokenBuckets[token]);
            const tokenCell = document.createElement('td'); const code = document.createElement('code'); code.textContent = token; tokenCell.append(code);
            const actionCell = document.createElement('td'); actionCell.className = 'right';
            const copy = document.createElement('button'); copy.className = 'btn btn-sm btn-outline-secondary'; copy.textContent = 'Salin'; copy.onclick = () => copyToken(token);
            const remove = document.createElement('button'); remove.className = 'btn btn-sm btn-outline-danger ms-1'; remove.textContent = 'Hapus'; remove.onclick = () => deleteToken(token);
            actionCell.append(copy, remove); tr.append(nameCell, bucketCell, tokenCell, actionCell); tbody.append(tr);
        });
    } catch (error) { showAlert('Gagal memuat token: ' + error.message); }
}
async function createToken(event) {
    if (event) event.preventDefault();
    const input = document.getElementById('serverName');
    const name = input.value.trim();
    if (!name) { input.focus(); return; }
    const bucketId = document.getElementById('tokenBucket').value;
    if (!bucketId) { showAlert('Tambahkan atau pilih bucket COS terlebih dahulu.'); return; }
    try {
        const data = await api('/api/tokens/create?server_name=' + encodeURIComponent(name) +
            '&bucket_id=' + encodeURIComponent(bucketId), {method:'POST'});
        input.value = '';
        showAlert('Token dibuat untuk ' + data.server_name + ' pada ' + bucketLabel(data.bucket_id) + '. Salin token dari daftar.', 'ok');
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
    const root = document.createElement('button'); root.className = 'btn btn-sm btn-link p-0'; root.textContent = 'backups'; root.onclick = () => loadObjects('backups/', '');
    nav.append(root);
    const parts = prefix.slice('backups/'.length).split('/').filter(Boolean);
    let path = 'backups/';
    parts.forEach(part => {
        const sep = document.createElement('span'); sep.textContent = '/'; nav.append(sep);
        path += part + '/';
        const button = document.createElement('button'); button.className = 'btn btn-sm btn-link p-0'; button.textContent = part;
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
        if (currentBucketId) params.set('bucket_id', currentBucketId);
        if (marker) params.set('marker', marker);
        const data = await api('/api/bucket/objects?' + params.toString());
        document.getElementById('bucketName').textContent = data.bucket;
        if (data.bucket_id && data.bucket_id !== currentBucketId) {
            currentBucketId = data.bucket_id;
            localStorage.setItem('gw_bucket', currentBucketId);
            const selector = document.getElementById('activeBucket');
            if (selector) selector.value = currentBucketId;
        }
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
                const button = document.createElement('button'); button.className = 'btn btn-link p-0 text-start'; button.textContent = '📁 ' + label;
                button.onclick = () => loadObjects(entry.key, '');
                nameCell.append(button);
            } else nameCell.textContent = label;
            const size = document.createElement('td'); size.textContent = entry.folder ? '—' : formatBytes(entry.size);
            const modified = document.createElement('td'); modified.textContent = entry.folder ? '—' : formatDate(entry.last_modified);
            const actions = document.createElement('td'); actions.className = 'right';
            if (!entry.folder) {
                const download = document.createElement('button'); download.className = 'btn btn-sm btn-outline-secondary'; download.textContent = 'Unduh';
                download.onclick = () => downloadObject(entry.key);
                if (currentRole === 'admin') {
                const decrypt = document.createElement('button'); decrypt.className = 'btn btn-sm btn-primary ms-1'; decrypt.textContent = 'Dekripsi';
                decrypt.onclick = async () => {
                    const privateKey = window.prompt('Masukkan private key age dari file kunci-backup.txt (teks lengkap):');
                    if (!privateKey) return;
                    try {
                        const response = await fetch('/api/bucket/decrypt', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json', 'Authorization': authHeader},
                            body: JSON.stringify({key: entry.key, private_key: privateKey, bucket_id: currentBucketId})
                        });
                        if (!response.ok) {
                            const err = await response.json().catch(() => ({detail: 'Dekripsi gagal.'}));
                            throw new Error(err.detail || 'Dekripsi gagal.');
                        }
                        const blob = await response.blob();
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = entry.key.replace(/\\.age$/, '');
                        document.body.appendChild(a);
                        a.click();
                        a.remove();
                        setTimeout(() => URL.revokeObjectURL(url), 1000);
                        showAlert('File berhasil didekripsi.', 'ok');
                    } catch (error) {
                        showAlert(error.message);
                    }
                };
                actions.append(download, decrypt);
                } else actions.append(download);
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
        const data = await api('/api/bucket/download?key=' + encodeURIComponent(key) +
            '&bucket_id=' + encodeURIComponent(currentBucketId));
        downloadWindow.location = data.download_url;
    } catch (error) {
        downloadWindow.close();
        showAlert('Gagal membuat tautan unduhan: ' + error.message);
    }
}
async function bootstrapAuth() {
    if (!isSetup) { renderSetupWizard(); return; }
    if (!authHeader) { renderLoginForm(); return; }
    try {
        const user = await api('/api/auth/me');
        currentRole = user.role;
        if (currentRole === 'admin') renderDashboard();
        else renderViewer();
    } catch (error) {
        localStorage.removeItem('gw_auth');
        authHeader = '';
        renderLoginForm();
        showAlert(error.message);
    }
}
bootstrapAuth();
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
    if not isinstance(raw_password, str) or len(raw_password) < 6:
        raise HTTPException(status_code=400, detail="Kata sandi admin minimal 6 karakter.")
    cos_values = {}
    for key in ("cos_secret_id", "cos_secret_key", "cos_region", "cos_bucket"):
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise HTTPException(status_code=400, detail=f"Nilai {key} wajib diisi dan maksimal 256 karakter.")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise HTTPException(status_code=400, detail=f"Nilai {key} tidak valid.")
        cos_values[key] = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", cos_values["cos_region"]):
        raise HTTPException(status_code=400, detail="Region COS tidak valid.")

    hashed_pw, salt = hash_password(raw_password)
    bucket_id = f"b_{secrets.token_hex(8)}"
    bucket = {
        "name": cos_values["cos_bucket"],
        **cos_values,
    }
    config_data = {
        "admin_user": payload.get("admin_user", "admin"),
        "admin_password_hash": hashed_pw,
        "salt": salt,
        **cos_values,
        "cos_buckets": {bucket_id: bucket},
        "active_bucket_id": bucket_id,
        "tokens": {}
    }
    save_config(config_data)
    return {"status": "ok"}

@app.get("/api/buckets")
def get_buckets(user: Dict[str, Any] = Depends(get_current_user)):
    cfg = load_config()
    records = _bucket_records(cfg)
    if user["role"] == "viewer":
        allowed_ids = set(_viewer_bucket_ids(cfg, user))
    else:
        allowed_ids = set(records)
    return {
        "buckets": [
            {
                "id": bucket_id,
                "name": record.get("name") or record.get("cos_bucket", bucket_id),
                "bucket": record.get("cos_bucket", ""),
                "region": record.get("cos_region", ""),
            }
            for bucket_id, record in records.items()
            if bucket_id in allowed_ids
        ]
    }

@app.post("/api/buckets")
def create_bucket(payload: Dict[str, Any], username: str = Depends(verify_credentials)):
    required = ("name", "cos_region", "cos_bucket", "cos_secret_id", "cos_secret_key")
    values = {}
    for key in required:
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise HTTPException(status_code=400, detail=f"Nilai {key} wajib diisi dan maksimal 256 karakter.")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise HTTPException(status_code=400, detail=f"Nilai {key} tidak valid.")
        values[key] = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", values["cos_region"]):
        raise HTTPException(status_code=400, detail="Region COS tidak valid.")
    if len(values["name"]) > 80:
        raise HTTPException(status_code=400, detail="Nama tampilan bucket maksimal 80 karakter.")

    cfg = load_config()
    records = _bucket_records(cfg)
    if any(
        record.get("cos_bucket") == values["cos_bucket"]
        and record.get("cos_region") == values["cos_region"]
        for record in records.values()
    ):
        raise HTTPException(status_code=409, detail="Bucket dan region tersebut sudah terdaftar.")
    new_record = {
        "name": values["name"],
        "cos_region": values["cos_region"],
        "cos_bucket": values["cos_bucket"],
        "cos_secret_id": values["cos_secret_id"],
        "cos_secret_key": values["cos_secret_key"],
    }
    new_bucket_id = f"b_{secrets.token_hex(8)}"
    try:
        _cos_client({"cos_buckets": {new_bucket_id: new_record}}, new_bucket_id).list_objects(
            Bucket=new_record["cos_bucket"], Prefix="backups/", MaxKeys=1
        )
    except Exception as exc:
        logger.exception("Gagal memvalidasi akses ke bucket COS baru.")
        raise HTTPException(status_code=502, detail="Tidak dapat mengakses bucket COS dengan kredensial tersebut.") from exc

    token_buckets = cfg.get("token_buckets", {})
    if not isinstance(token_buckets, dict):
        token_buckets = {}
    default_id = "legacy" if "legacy" in records else next(iter(records), new_bucket_id)
    for token in cfg.get("tokens", {}):
        token_buckets.setdefault(token, default_id)
    records[new_bucket_id] = new_record
    cfg["cos_buckets"] = records
    cfg["token_buckets"] = token_buckets
    cfg.setdefault("active_bucket_id", default_id)
    save_config(cfg)
    return {"id": new_bucket_id, "name": new_record["name"], "bucket": new_record["cos_bucket"]}

@app.delete("/api/buckets/{bucket_id}")
def delete_bucket(bucket_id: str, username: str = Depends(verify_credentials)):
    cfg = load_config()
    records = _bucket_records(cfg)
    if bucket_id not in records:
        raise HTTPException(status_code=404, detail="Bucket tidak ditemukan.")
    tokens = cfg.get("tokens", {})
    if isinstance(tokens, dict) and any(
        _token_bucket_id(cfg, token) == bucket_id for token in tokens
    ):
        raise HTTPException(status_code=409, detail="Bucket masih digunakan oleh token Agent.")
    if len(records) <= 1:
        raise HTTPException(status_code=409, detail="Minimal satu bucket harus tetap terdaftar.")
    del records[bucket_id]
    cfg["cos_buckets"] = records
    if cfg.get("active_bucket_id") == bucket_id:
        cfg["active_bucket_id"] = next(iter(records))
    save_config(cfg)
    return {"status": "ok"}

@app.get("/api/tokens")
def get_tokens(username: str = Depends(verify_credentials)):
    cfg = load_config()
    tokens = cfg.get("tokens", {})
    token_buckets = cfg.get("token_buckets", {})
    if not isinstance(token_buckets, dict):
        token_buckets = {}
    return {
        "tokens": tokens,
        "token_buckets": {
            token: token_buckets[token] if token in token_buckets else _token_bucket_id(cfg, token)
            for token in tokens
        } if isinstance(tokens, dict) else {},
    }

@app.post("/api/tokens/create")
def create_token(
    server_name: str = Query(..., min_length=1, max_length=100),
    bucket_id: str = Query(""),
    username: str = Depends(verify_credentials),
):
    cfg = load_config()
    records = _bucket_records(cfg)
    if not bucket_id:
        bucket_id = _default_bucket_id(cfg)
    if bucket_id not in records:
        raise HTTPException(status_code=400, detail="Pilih bucket COS yang tersedia.")
    server_name = server_name.strip()
    folder_name = _server_folder_name(server_name)
    if not server_name or not folder_name.strip("_") or any(ord(char) < 32 or ord(char) == 127 for char in server_name):
        raise HTTPException(status_code=400, detail="Nama daerah/Agent tidak valid.")
    tokens = cfg.get("tokens", {})
    if any(_server_folder_name(str(existing_name)) == folder_name for existing_name in tokens.values()):
        raise HTTPException(status_code=409, detail="Nama daerah/Agent tersebut sudah digunakan.")
    new_token = f"sgtok_{secrets.token_hex(16)}"
    tokens[new_token] = server_name
    token_buckets = cfg.get("token_buckets", {})
    if not isinstance(token_buckets, dict):
        token_buckets = {}
    token_buckets[new_token] = bucket_id
    cfg["tokens"] = tokens
    cfg["token_buckets"] = token_buckets
    save_config(cfg)
    return {"server_name": server_name, "token": new_token, "bucket_id": bucket_id}

@app.delete("/api/tokens/delete")
def delete_token(token: str = Query(...), username: str = Depends(verify_credentials)):
    cfg = load_config()
    tokens = cfg.get("tokens", {})
    if token in tokens:
        del tokens[token]
        cfg["tokens"] = tokens
        token_buckets = cfg.get("token_buckets", {})
        if isinstance(token_buckets, dict):
            token_buckets.pop(token, None)
            cfg["token_buckets"] = token_buckets
        save_config(cfg)
        return {"status": "ok"}
    raise HTTPException(status_code=404, detail="Token tidak ditemukan.")

def _bucket_records(cfg: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    configured = cfg.get("cos_buckets")
    if isinstance(configured, dict):
        return {
            bucket_id: record
            for bucket_id, record in configured.items()
            if isinstance(bucket_id, str) and isinstance(record, dict)
        }
    if all(cfg.get(key) for key in ("cos_region", "cos_bucket", "cos_secret_id", "cos_secret_key")):
        return {
            "legacy": {
                "name": str(cfg["cos_bucket"]),
                "cos_region": str(cfg["cos_region"]),
                "cos_bucket": str(cfg["cos_bucket"]),
                "cos_secret_id": str(cfg["cos_secret_id"]),
                "cos_secret_key": str(cfg["cos_secret_key"]),
            }
        }
    return {}


def _default_bucket_id(cfg: Dict[str, Any]) -> str:
    records = _bucket_records(cfg)
    if not records:
        raise HTTPException(status_code=503, detail="Belum ada bucket COS yang dikonfigurasi.")
    return next(iter(records))


def _token_bucket_id(cfg: Dict[str, Any], token: str) -> str:
    records = _bucket_records(cfg)
    token_buckets = cfg.get("token_buckets", {})
    bucket_id = token_buckets.get(token) if isinstance(token_buckets, dict) else None
    if bucket_id is None:
        bucket_id = "legacy" if "legacy" in records else next(iter(records), "")
    if bucket_id not in records:
        raise HTTPException(status_code=503, detail="Bucket untuk Agent tidak tersedia.")
    return bucket_id


def _bucket_for_request(cfg: Dict[str, Any], user: Dict[str, Any], bucket_id: str = "") -> tuple[str, Dict[str, str]]:
    records = _bucket_records(cfg)
    if user["role"] == "viewer":
        allowed = _viewer_bucket_ids(cfg, user)
        if not bucket_id and len(allowed) == 1:
            bucket_id = allowed[0]
        if bucket_id not in allowed:
            raise HTTPException(status_code=403, detail="User tidak memiliki akses ke bucket ini.")
    elif not bucket_id:
        bucket_id = cfg.get("active_bucket_id") or _default_bucket_id(cfg)
    record = records.get(bucket_id)
    if not isinstance(record, dict):
        raise HTTPException(status_code=404, detail="Bucket tidak ditemukan.")
    return bucket_id, record


def _cos_client(cfg: Dict[str, Any], bucket_id: str = "") -> CosS3Client:
    if bucket_id:
        record = _bucket_records(cfg).get(bucket_id)
        if not isinstance(record, dict):
            raise HTTPException(status_code=404, detail="Bucket tidak ditemukan.")
    else:
        bucket_id = _default_bucket_id(cfg)
        record = _bucket_records(cfg)[bucket_id]
    cos_config = CosConfig(
        Region=record["cos_region"],
        SecretId=record["cos_secret_id"],
        SecretKey=record["cos_secret_key"],
    )
    return CosS3Client(cos_config)


def _close_cos_response_body(body):
    try:
        body.get_raw_stream().close()
    except Exception:
        logger.exception("Gagal menutup stream arsip dari COS.")


def _agent_cos_key(server_name: str, filename: str, category: str) -> str:
    if category not in ("database", "application", "archive"):
        raise HTTPException(status_code=400, detail="Kategori backup tidak valid.")
    if not isinstance(filename, str) or not filename or len(filename) > 255:
        raise HTTPException(status_code=400, detail="Nama berkas tidak valid.")
    safe_filename = re.sub(r"[^a-zA-Z0-9_.-]", "_", os.path.basename(filename))
    if safe_filename in ("", ".", ".."):
        raise HTTPException(status_code=400, detail="Nama berkas tidak valid.")
    folder_name = _server_folder_name(server_name)
    category_path = "" if category == "archive" else f"{category}/"
    return f"backups/{folder_name}/{category_path}{safe_filename}"


def _multipart_part_size(file_size: int) -> int:
    if type(file_size) is not int or file_size <= 0 or file_size > 50_000_000_000_000:
        raise HTTPException(status_code=400, detail="Ukuran arsip tidak valid atau melebihi batas COS.")
    minimum_size = 64 * 1024 * 1024
    max_parts = 10_000
    return max(minimum_size, (file_size + max_parts - 1) // max_parts)


def _valid_backup_path(value: str, *, allow_folder: bool) -> bool:
    if not value.startswith("backups/") or "\\" in value or len(value) > 1024:
        return False
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        return False
    parts = value.split("/")
    if any(part in (".", "..") for part in parts):
        return False
    return allow_folder or not value.endswith("/")


def _viewer_folder_prefixes(user: Dict[str, str]) -> list[str]:
    folders = user.get("folders", [])
    if not isinstance(folders, list):
        return []
    return [
        f"backups/{folder}/"
        for folder in folders
        if isinstance(folder, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,100}", folder)
    ]


def _viewer_bucket_ids(cfg: Dict[str, Any], user: Dict[str, Any]) -> list[str]:
    folders = set(_viewer_folder_prefixes(user))
    tokens = cfg.get("tokens", {})
    if not isinstance(tokens, dict):
        return []
    bucket_ids = []
    for token, server_name in tokens.items():
        if not isinstance(server_name, str) or f"backups/{_server_folder_name(server_name)}/" not in folders:
            continue
        try:
            bucket_id = _token_bucket_id(cfg, token)
        except HTTPException:
            continue
        if bucket_id not in bucket_ids:
            bucket_ids.append(bucket_id)
    return bucket_ids


def _viewer_folder_prefixes_for_bucket(
    cfg: Dict[str, Any], user: Dict[str, Any], bucket_id: str
) -> list[str]:
    allowed = set(_viewer_folder_prefixes(user))
    tokens = cfg.get("tokens", {})
    if not isinstance(tokens, dict):
        return []
    prefixes = []
    for token, server_name in tokens.items():
        folder = f"backups/{_server_folder_name(server_name)}/" if isinstance(server_name, str) else ""
        try:
            token_bucket_id = _token_bucket_id(cfg, token)
        except HTTPException:
            continue
        if folder in allowed and token_bucket_id == bucket_id and folder not in prefixes:
            prefixes.append(folder)
    return prefixes


def _agent_server_name(authorization: str, cfg: Dict[str, Any]) -> str:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=401, detail="Token Agent diperlukan.")
    server_name = cfg.get("tokens", {}).get(token.strip())
    if not server_name:
        raise HTTPException(status_code=401, detail="Token Target Agent tidak valid.")
    return server_name


def _agent_identity(authorization: str, cfg: Dict[str, Any]) -> tuple[str, str]:
    server_name = _agent_server_name(authorization, cfg)
    _, _, token = (authorization or "").partition(" ")
    return server_name, _token_bucket_id(cfg, token.strip())


def _server_folder_name(server_name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", server_name.lower().replace(" ", "_"))


def _safe_private_key(private_key: str) -> str:
    if not isinstance(private_key, str):
        raise ValueError("Private key harus berupa teks.")
    cleaned = private_key.strip()
    if not cleaned or "\x00" in cleaned or len(cleaned) > 65536:
        raise ValueError("Private key tidak valid.")
    if not re.fullmatch(r"[\x20-\x7E\r\n]+", cleaned):
        raise ValueError("Private key hanya boleh berisi karakter ASCII aman.")
    if "AGE-SECRET-KEY-" not in cleaned:
        raise ValueError("Private key age tidak valid.")
    return cleaned


@app.get("/api/bucket/objects")
def list_bucket_objects(
    prefix: str = Query("backups/"),
    marker: str = Query(""),
    bucket_id: str = Query(""),
    user: Dict[str, str] = Depends(get_current_user),
):
    if not _valid_backup_path(prefix, allow_folder=True):
        raise HTTPException(status_code=400, detail="Lokasi bucket tidak valid.")
    if marker and (not marker.startswith(prefix) or not _valid_backup_path(marker, allow_folder=True)):
        raise HTTPException(status_code=400, detail="Penanda halaman tidak valid.")

    cfg = load_config()
    bucket_id, bucket = _bucket_for_request(cfg, user, bucket_id)
    if user["role"] == "viewer":
        folder_prefixes = _viewer_folder_prefixes_for_bucket(cfg, user, bucket_id)
        if prefix == "backups/":
            if marker:
                raise HTTPException(status_code=400, detail="Penanda halaman tidak valid.")
            return {
                "bucket": bucket.get("name") or bucket["cos_bucket"],
                "bucket_id": bucket_id,
                "prefix": prefix,
                "folders": folder_prefixes,
                "objects": [],
                "is_truncated": False,
                "next_marker": "",
            }
        if not any(prefix.startswith(folder) for folder in folder_prefixes):
            raise HTTPException(status_code=403, detail="User tidak memiliki akses ke folder Agent ini.")
        if marker and not any(marker.startswith(folder) for folder in folder_prefixes):
            raise HTTPException(status_code=403, detail="Penanda halaman di luar cakupan akses user.")

    try:
        params = {
            "Bucket": bucket["cos_bucket"],
            "Prefix": prefix,
            "Delimiter": "/",
            "MaxKeys": 100,
        }
        if marker:
            params["Marker"] = marker
        response = _cos_client(cfg, bucket_id).list_objects(**params)
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
        "bucket": bucket.get("name") or bucket["cos_bucket"],
        "bucket_id": bucket_id,
        "prefix": prefix,
        "folders": folders,
        "objects": objects,
        "is_truncated": bool(response.get("IsTruncated")),
        "next_marker": next_marker,
    }


@app.get("/api/bucket/download")
def get_download_url(
    key: str = Query(...),
    bucket_id: str = Query(""),
    user: Dict[str, str] = Depends(get_current_user),
):
    if not _valid_backup_path(key, allow_folder=False):
        raise HTTPException(status_code=400, detail="Lokasi file tidak valid.")
    if user["role"] == "viewer" and not key.endswith(".age"):
        raise HTTPException(status_code=403, detail="User biasa hanya dapat mengunduh arsip terenkripsi.")
    cfg = load_config()
    bucket_id, bucket = _bucket_for_request(cfg, user, bucket_id)
    if user["role"] == "viewer" and not any(
        key.startswith(folder) for folder in _viewer_folder_prefixes_for_bucket(cfg, user, bucket_id)
    ):
        raise HTTPException(status_code=403, detail="User tidak memiliki akses ke folder Agent ini.")
    try:
        download_url = _cos_client(cfg, bucket_id).get_presigned_url(
            Method="GET",
            Bucket=bucket["cos_bucket"],
            Key=key,
            Expired=300,
        )
    except Exception as exc:
        logger.exception("Gagal membuat tautan unduhan COS.")
        raise HTTPException(status_code=502, detail="Gagal membuat tautan unduhan dari bucket COS.") from exc
    return {"download_url": download_url}


@app.post("/api/bucket/decrypt")
@limiter.limit("3/minute")
async def decrypt_backup(request: Request, payload: Dict[str, Any], username: str = Depends(verify_credentials)):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Payload harus berupa objek JSON.")

    key = str(payload.get("key", "")).strip()
    private_key = str(payload.get("private_key", "")).strip()
    bucket_id = str(payload.get("bucket_id", "")).strip()
    if not _valid_backup_path(key, allow_folder=False) or not key.endswith(".age"):
        raise HTTPException(status_code=400, detail="Lokasi file arsip tidak valid.")

    try:
        private_key = _safe_private_key(private_key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not shutil.which("age"):
        raise HTTPException(status_code=500, detail="Program age tidak tersedia di server gateway.")

    cfg = load_config()
    bucket_id, bucket = _bucket_for_request(cfg, {"role": "admin"}, bucket_id)
    body = None
    try:
        obj = await asyncio.to_thread(
            _cos_client(cfg, bucket_id).get_object,
            Bucket=bucket["cos_bucket"],
            Key=key,
        )
        body = obj.get("Body")
        if body is None:
            raise RuntimeError("COS tidak mengembalikan isi objek.")
        first_chunk = await asyncio.to_thread(body.read, 65536)
    except Exception as exc:
        if body is not None:
            _close_cos_response_body(body)
        logger.exception("Gagal mengambil objek terenkripsi dari COS.")
        raise HTTPException(status_code=502, detail="Gagal mengambil arsip backup dari bucket COS.") from exc

    if not first_chunk:
        _close_cos_response_body(body)
        raise HTTPException(status_code=400, detail="Arsip backup kosong atau rusak.")

    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(prefix="smartgov-age-", suffix=".txt")
        with os.fdopen(fd, "wb") as f:
            f.write(private_key.encode("utf-8"))
        os.chmod(tmp_path, 0o600)
    except OSError as exc:
        _close_cos_response_body(body)
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise HTTPException(status_code=500, detail="Tidak dapat menyiapkan file sementara untuk dekripsi.") from exc

    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(key).removesuffix(".age")) or "backup"

    async def decrypted_chunks():
        proc = None
        feeder = None
        stderr_reader = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "age", "-d", "-i", tmp_path,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            async def feed_ciphertext():
                try:
                    chunk = first_chunk
                    while chunk:
                        proc.stdin.write(chunk)
                        await proc.stdin.drain()
                        chunk = await asyncio.to_thread(body.read, 65536)
                finally:
                    if proc.stdin and not proc.stdin.is_closing():
                        proc.stdin.close()
                        await proc.stdin.wait_closed()

            async def collect_stderr():
                while True:
                    chunk = await proc.stderr.read(4096)
                    if not chunk:
                        break

            feeder = asyncio.create_task(feed_ciphertext())
            stderr_reader = asyncio.create_task(collect_stderr())
            deadline = asyncio.get_running_loop().time() + 21600
            while True:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise TimeoutError("Decrypt arsip melebihi batas waktu.")
                chunk = await asyncio.wait_for(proc.stdout.read(65536), timeout=remaining)
                if not chunk:
                    break
                yield chunk

            await feeder
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError("Decrypt arsip melebihi batas waktu.")
            return_code = await asyncio.wait_for(proc.wait(), timeout=remaining)
            await stderr_reader
            if return_code != 0:
                raise RuntimeError("Private key tidak cocok atau arsip terenkripsi tidak valid.")
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Streaming dekripsi arsip gagal.")
            raise
        finally:
            _close_cos_response_body(body)
            for task in (feeder, stderr_reader):
                if task and not task.done():
                    task.cancel()
            if proc and proc.returncode is None:
                proc.kill()
                await proc.wait()
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    logger.exception("Gagal menghapus file private key sementara.")

    return StreamingResponse(
        decrypted_chunks(),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_name}"',
            "Content-Security-Policy": "default-src 'none'",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


@app.post("/api/v1/get-upload-url")
@limiter.limit("30/minute")
def get_upload_url(
    request: Request, 
    filename: str, 
    category: str = Query("archive"),
    authorization: str = Header(None)  # <--- PERBAIKAN DI SINI
):
    cfg = load_config()
    server_name, bucket_id = _agent_identity(authorization, cfg)
    bucket = _bucket_records(cfg)[bucket_id]
    cos_key = _agent_cos_key(server_name, filename, category)
    try:
        client = _cos_client(cfg, bucket_id)
        upload_url = client.get_presigned_url(
            Method="PUT",
            Bucket=bucket["cos_bucket"],
            Key=cos_key,
            Expired=900
        )
        return {"upload_url": upload_url, "cos_key": cos_key}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Gagal membuat Presigned URL.")


@app.post("/api/v1/multipart/initiate")
@limiter.limit("10/minute")
def initiate_multipart_upload(
    request: Request,
    payload: Dict[str, Any],
    authorization: str = Header(None),
):
    cfg = load_config()
    server_name, bucket_id = _agent_identity(authorization, cfg)
    bucket = _bucket_records(cfg)[bucket_id]
    filename = payload.get("filename")
    category = payload.get("category")
    file_size = payload.get("file_size")
    cos_key = _agent_cos_key(server_name, filename, category)
    part_size = _multipart_part_size(file_size)
    total_parts = (file_size + part_size - 1) // part_size

    try:
        result = _cos_client(cfg, bucket_id).create_multipart_upload(
            Bucket=bucket["cos_bucket"],
            Key=cos_key,
        )
        upload_id = result.get("UploadId")
        if not isinstance(upload_id, str) or not upload_id or len(upload_id) > 1024:
            raise RuntimeError("COS tidak mengembalikan upload ID multipart yang valid.")
    except Exception as exc:
        logger.exception("Gagal memulai multipart upload COS.")
        raise HTTPException(status_code=502, detail="Gagal memulai unggahan multipart ke COS.") from exc

    return {
        "upload_id": upload_id,
        "part_size": part_size,
        "total_parts": total_parts,
    }


@app.post("/api/v1/multipart/part-urls")
@limiter.limit("30/minute")
def get_multipart_part_urls(
    request: Request,
    payload: Dict[str, Any],
    authorization: str = Header(None),
):
    cfg = load_config()
    server_name, bucket_id = _agent_identity(authorization, cfg)
    bucket = _bucket_records(cfg)[bucket_id]
    cos_key = _agent_cos_key(server_name, payload.get("filename"), payload.get("category"))
    upload_id = payload.get("upload_id")
    part_numbers = payload.get("part_numbers")
    if not isinstance(upload_id, str) or not upload_id or len(upload_id) > 1024:
        raise HTTPException(status_code=400, detail="Upload ID multipart tidak valid.")
    if (
        not isinstance(part_numbers, list)
        or not 1 <= len(part_numbers) <= 8
        or any(type(number) is not int or not 1 <= number <= 10_000 for number in part_numbers)
        or part_numbers != sorted(set(part_numbers))
    ):
        raise HTTPException(status_code=400, detail="Daftar nomor bagian multipart tidak valid.")

    try:
        client = _cos_client(cfg, bucket_id)
        part_urls = [
            {
                "part_number": number,
                "upload_url": client.get_presigned_url(
                    Method="PUT",
                    Bucket=bucket["cos_bucket"],
                    Key=cos_key,
                    Params={"partNumber": number, "uploadId": upload_id},
                    Expired=21600,
                ),
            }
            for number in part_numbers
        ]
    except Exception as exc:
        logger.exception("Gagal membuat URL bagian multipart COS.")
        raise HTTPException(status_code=502, detail="Gagal menyiapkan unggahan bagian ke COS.") from exc

    return {"parts": part_urls}


@app.post("/api/v1/multipart/complete")
@limiter.limit("10/minute")
def complete_multipart_upload(
    request: Request,
    payload: Dict[str, Any],
    authorization: str = Header(None),
):
    cfg = load_config()
    server_name, bucket_id = _agent_identity(authorization, cfg)
    bucket = _bucket_records(cfg)[bucket_id]
    cos_key = _agent_cos_key(server_name, payload.get("filename"), payload.get("category"))
    upload_id = payload.get("upload_id")
    parts = payload.get("parts")
    if not isinstance(upload_id, str) or not upload_id or len(upload_id) > 1024:
        raise HTTPException(status_code=400, detail="Upload ID multipart tidak valid.")
    if not isinstance(parts, list) or not 1 <= len(parts) <= 10_000:
        raise HTTPException(status_code=400, detail="Daftar bagian multipart tidak valid.")

    cos_parts = []
    for expected_number, part in enumerate(parts, start=1):
        if not isinstance(part, dict) or type(part.get("part_number")) is not int:
            raise HTTPException(status_code=400, detail="Metadata bagian multipart tidak valid.")
        etag = part.get("etag")
        if not isinstance(etag, str):
            raise HTTPException(status_code=400, detail="ETag bagian multipart tidak valid.")
        normalized_etag = etag[1:-1] if etag.startswith('"') and etag.endswith('"') else etag
        if not normalized_etag or not re.fullmatch(r"[A-Za-z0-9+/=_-]{1,200}", normalized_etag):
            raise HTTPException(status_code=400, detail="ETag bagian multipart tidak valid.")
        if part["part_number"] != expected_number:
            raise HTTPException(status_code=400, detail="Nomor bagian multipart harus berurutan.")
        cos_parts.append({"PartNumber": expected_number, "ETag": f'"{normalized_etag}"'})

    try:
        result = _cos_client(cfg, bucket_id).complete_multipart_upload(
            Bucket=bucket["cos_bucket"],
            Key=cos_key,
            UploadId=upload_id,
            MultipartUpload={"Part": cos_parts},
        )
        if not result.get("ETag"):
            raise RuntimeError("COS tidak mengonfirmasi penyelesaian multipart upload.")
    except Exception as exc:
        logger.exception("Gagal menyelesaikan multipart upload COS.")
        raise HTTPException(status_code=502, detail="COS gagal menyelesaikan unggahan multipart.") from exc

    return {"status": "ok"}


@app.post("/api/v1/multipart/abort")
@limiter.limit("10/minute")
def abort_multipart_upload(
    request: Request,
    payload: Dict[str, Any],
    authorization: str = Header(None),
):
    cfg = load_config()
    server_name, bucket_id = _agent_identity(authorization, cfg)
    bucket = _bucket_records(cfg)[bucket_id]
    cos_key = _agent_cos_key(server_name, payload.get("filename"), payload.get("category"))
    upload_id = payload.get("upload_id")
    if not isinstance(upload_id, str) or not upload_id or len(upload_id) > 1024:
        raise HTTPException(status_code=400, detail="Upload ID multipart tidak valid.")
    try:
        _cos_client(cfg, bucket_id).abort_multipart_upload(
            Bucket=bucket["cos_bucket"],
            Key=cos_key,
            UploadId=upload_id,
        )
    except Exception as exc:
        logger.exception("Gagal membatalkan multipart upload COS.")
        raise HTTPException(status_code=502, detail="Gagal membersihkan unggahan multipart COS.") from exc
    return {"status": "aborted"}


@app.post("/api/v1/rotate-backups")
@limiter.limit("30/minute")
def rotate_agent_backups(
    request: Request,
    category: str = Query(..., pattern="^(database|application)$"),
    max_files: int = Query(..., ge=1, le=3650),
    authorization: str = Header(None),
):
    cfg = load_config()
    server_name, bucket_id = _agent_identity(authorization, cfg)
    bucket = _bucket_records(cfg)[bucket_id]
    prefix = f"backups/{_server_folder_name(server_name)}/{category}/"
    client = _cos_client(cfg, bucket_id)
    objects = []
    marker = ""
    try:
        while True:
            params = {
                "Bucket": bucket["cos_bucket"],
                "Prefix": prefix,
                "MaxKeys": 1000,
            }
            if marker:
                params["Marker"] = marker
            response = client.list_objects(**params)
            objects.extend(
                item for item in response.get("Contents", [])
                if item.get("Key", "").startswith(prefix) and not item.get("Key", "").endswith("/")
            )
            is_truncated = response.get("IsTruncated", False)
            if isinstance(is_truncated, str):
                is_truncated = is_truncated.strip().lower() == "true"
            if not is_truncated:
                break
            next_marker = response.get("NextMarker") or (
                response.get("Contents", [])[-1].get("Key", "") if response.get("Contents") else ""
            )
            if not next_marker or next_marker == marker:
                raise RuntimeError("COS tidak mengembalikan penanda halaman yang valid.")
            marker = next_marker

        objects.sort(key=lambda item: (item.get("LastModified", ""), item.get("Key", "")))
        excess = max(0, len(objects) - max_files)
        oldest_keys = [item["Key"] for item in objects[:excess]]
        for offset in range(0, len(oldest_keys), 1000):
            batch = oldest_keys[offset:offset + 1000]
            result = client.delete_objects(
                Bucket=bucket["cos_bucket"],
                Delete={"Quiet": True, "Object": [{"Key": key} for key in batch]},
            )
            if result.get("Errors"):
                raise RuntimeError("COS gagal menghapus satu atau lebih arsip lama.")
    except Exception as exc:
        logger.exception("Gagal merotasi objek backup Agent di COS.")
        raise HTTPException(status_code=502, detail="Rotasi arsip di bucket COS gagal.") from exc
    return {"deleted": excess, "remaining": len(objects) - excess}
