import os
import json
import secrets
import hashlib
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
    return f"""<!DOCTYPE html>
<html lang="id" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SmartGOV Gateway Management</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
    <style>
        body {{ background: #0f172a; color: #f8fafc; font-family: system-ui, -apple-system, sans-serif; }}
        .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px; }}
        .table {{ border-color: #334155; }}
        code {{ color: #38bdf8; word-break: break-all; }}
    </style>
</head>
<body class="py-5">
<div class="container" style="max-width: 850px;">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h3 class="fw-bold m-0"><i class="bi bi-shield-lock text-primary me-2"></i>SmartGOV Backup Gateway</h3>
        <div id="authStatus"></div>
    </div>
    
    <div id="alertBox"></div>
    <div id="app"></div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
const isSetup = {json.dumps(is_setup)};
let authHeader = localStorage.getItem('gw_auth') || '';

function escapeHtml(str) {{
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}}

function showAlert(msg, type='danger') {{
    document.getElementById('alertBox').innerHTML = `
        <div class="alert alert-${{type}} alert-dismissible fade show" role="alert">
            ${{escapeHtml(msg)}}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>`;
}}

if (!isSetup) {{
    renderSetupWizard();
}} else if (!authHeader) {{
    renderLoginForm();
}} else {{
    renderDashboard();
}}

function renderLoginForm() {{
    document.getElementById('app').innerHTML = `
    <div class="card p-4 mx-auto" style="max-width: 450px;">
        <h5 class="fw-bold mb-3"><i class="bi bi-box-arrow-in-right me-2"></i>Login Admin Gateway</h5>
        <form onsubmit="handleLogin(event)">
            <div class="mb-3">
                <label class="form-label">Username</label>
                <input type="text" id="login_user" class="form-control" required>
            </div>
            <div class="mb-3">
                <label class="form-label">Password</label>
                <input type="password" id="login_pass" class="form-control" required>
            </div>
            <button type="submit" class="btn btn-primary w-100">Masuk</button>
        </form>
    </div>`;
}}

async function handleLogin(e) {{
    e.preventDefault();
    const u = document.getElementById('login_user').value;
    const p = document.getElementById('login_pass').value;
    const auth = 'Basic ' + btoa(u + ':' + p);
    
    const res = await fetch('/api/tokens', {{ headers: {{ 'Authorization': auth }} }});
    if (res.ok) {{
        authHeader = auth;
        localStorage.setItem('gw_auth', auth);
        renderDashboard();
    }} else {{
        showAlert('Username atau password salah.');
    }}
}}

function logout() {{
    localStorage.removeItem('gw_auth');
    authHeader = '';
    location.reload();
}}

function renderDashboard() {{
    document.getElementById('authStatus').innerHTML = `
        <button onclick="logout()" class="btn btn-outline-danger btn-sm"><i class="bi bi-box-arrow-right me-1"></i>Logout</button>`;

    document.getElementById('app').innerHTML = `
    <div class="card p-4 mb-4">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h5 class="fw-bold m-0">Manajemen Token Agent Target</h5>
            <button onclick="showCreateTokenModal()" class="btn btn-success"><i class="bi bi-plus-lg me-1"></i>Generate Token Server</button>
        </div>
        <div class="table-responsive">
            <table class="table table-dark table-hover align-middle">
                <thead>
                    <tr><th>Nama Server Target</th><th>Agent API Token</th><th class="text-end">Aksi</th></tr>
                </thead>
                <tbody id="tokenTable"><tr><td colspan="3" class="text-center text-muted">Memuat data token...</td></tr></tbody>
            </table>
        </div>
    </div>`;
    loadTokens();
}}

function renderSetupWizard() {{
    document.getElementById('app').innerHTML = `
    <div class="card p-4">
        <h5 class="fw-bold mb-3"><i class="bi bi-gear-wide-connected me-2"></i>Initial Setup Wizard Gateway Pusat</h5>
        <form id="setupForm" onsubmit="saveSetup(event)">
            <h6 class="text-info mt-2"><i class="bi bi-person-shield me-1"></i>1. Keamanan Admin Gateway</h6>
            <div class="row g-2 mb-3">
                <div class="col-md-6"><input type="text" id="admin_user" class="form-control" placeholder="Admin Username" value="admin" required></div>
                <div class="col-md-6"><input type="password" id="admin_pass" class="form-control" placeholder="Admin Password" required></div>
            </div>

            <h6 class="text-info mt-3"><i class="bi bi-cloud-check me-1"></i>2. Kredensial Tencent Cloud COS Master</h6>
            <div class="mb-2"><input type="text" id="cos_id" class="form-control" placeholder="Secret ID" required></div>
            <div class="mb-2"><input type="password" id="cos_key" class="form-control" placeholder="Secret Key" required></div>
            <div class="row g-2 mb-3">
                <div class="col-md-6"><input type="text" id="cos_region" class="form-control" placeholder="Region (misal: ap-jakarta)" required></div>
                <div class="col-md-6"><input type="text" id="cos_bucket" class="form-control" placeholder="Bucket Name" required></div>
            </div>
            <button type="submit" class="btn btn-primary w-100 mt-2">Simpan & Aktifkan Gateway</button>
        </form>
    </div>`;
}}

async function saveSetup(e) {{
    e.preventDefault();
    const payload = {{
        admin_user: document.getElementById('admin_user').value,
        admin_password: document.getElementById('admin_pass').value,
        cos_secret_id: document.getElementById('cos_id').value,
        cos_secret_key: document.getElementById('cos_key').value,
        cos_region: document.getElementById('cos_region').value,
        cos_bucket: document.getElementById('cos_bucket').value
    }};
    try {{
        const res = await fetch('/api/setup', {{
            method: 'POST',
            headers: {{'Content-Type':'application/json'}},
            body: JSON.stringify(payload)
        }});
        if(res.ok) {{
            showAlert('Setup Berhasil! Memuat ulang...', 'success');
            setTimeout(() => location.reload(), 1500);
        }} else {{
            const err = await res.json();
            showAlert(err.detail || 'Gagal menyimpan konfigurasi setup.');
        }}
    }} catch(ex) {{
        showAlert('Terjadi kesalahan jaringan.');
    }}
}}

async function loadTokens() {{
    try {{
        const res = await fetch('/api/tokens', {{ headers: {{ 'Authorization': authHeader }} }});
        if(res.status === 401) {{ logout(); return; }}
        if(!res.ok) throw new Error();
        
        const data = await res.json();
        const tbody = document.getElementById('tokenTable');
        tbody.innerHTML = '';
        const tokens = data.tokens || {{}};
        
        if (Object.keys(tokens).length === 0) {{
            tbody.innerHTML = '<tr><td colspan="3" class="text-center text-muted py-3">Belum ada token server yang dibuat.</td></tr>';
            return;
        }}
        
        Object.entries(tokens).forEach(([tok, sname]) => {{
            const safeName = escapeHtml(sname);
            const safeTok = escapeHtml(tok);
            tbody.innerHTML += `
            <tr>
                <td><strong class="text-light">${{safeName}}</strong></td>
                <td><code>${{safeTok}}</code></td>
                <td class="text-end">
                    <button onclick="copyToken('${{safeTok}}')" class="btn btn-sm btn-outline-info me-1"><i class="bi bi-clipboard"></i> Salin</button>
                    <button onclick="deleteToken('${{safeTok}}')" class="btn btn-sm btn-outline-danger"><i class="bi bi-trash"></i> Hapus</button>
                </td>
            </tr>`;
        }});
    }} catch(e) {{
        showAlert('Gagal memuat daftar token server.');
    }}
}}

async function showCreateTokenModal() {{
    const sname = prompt('Masukkan Nama Server Target (misal: Dinas Kesehatan):');
    if(!sname || !sname.trim()) return;
    
    try {{
        const res = await fetch('/api/tokens/create?server_name=' + encodeURIComponent(sname.trim()), {{
            method: 'POST',
            headers: {{ 'Authorization': authHeader }}
        }});
        if(res.ok) {{
            const data = await res.json();
            showAlert('Token berhasil dibuat untuk server ' + data.server_name, 'success');
            loadTokens();
        }} else {{
            showAlert('Gagal membuat token baru.');
        }}
    }} catch(e) {{
        showAlert('Terjadi kesalahan jaringan saat membuat token.');
    }}
}}

function copyToken(tok) {{
    navigator.clipboard.writeText(tok);
    showAlert('Token berhasil disalin ke clipboard!', 'info');
}}

async function deleteToken(tok) {{
    if(!confirm('Apakah Anda yakin ingin menghapus token ini? Agent terkait tidak akan bisa melakukan backup.')) return;
    try {{
        const res = await fetch('/api/tokens/delete?token=' + encodeURIComponent(tok), {{
            method: 'DELETE',
            headers: {{ 'Authorization': authHeader }}
        }});
        if(res.ok) {{
            showAlert('Token berhasil dihapus.', 'success');
            loadTokens();
        }} else {{
            showAlert('Gagal menghapus token.');
        }}
    }} catch(e) {{
        showAlert('Terjadi kesalahan koneksi.');
    }}
}}
</script>
</body>
</html>"""

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
        cos_config = CosConfig(
            Region=cfg["cos_region"], 
            SecretId=cfg["cos_secret_id"], 
            SecretKey=cfg["cos_secret_key"]
        )
        client = CosS3Client(cos_config)
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
