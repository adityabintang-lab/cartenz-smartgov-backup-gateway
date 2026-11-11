#!/usr/bin/env bash
# Install or update the SmartGOV Backup Gateway.
# Usage: sudo bash setup.sh [--dir PATH] [--repo URL] [--branch NAME] [--bind ADDRESS]
set -Eeuo pipefail

APP_DIR="/opt/smartgov-gateway"
REPO_URL="${REPO_URL:-https://github.com/adityabintang-lab/cartenz-smartgov-backup-gateway.git}"
BRANCH="main"
CONTAINER="cartenz-smartgov-backup-gateway"
BIND_ADDR=""

die() { echo "ERROR: $*" >&2; exit 1; }
run() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }
trap 'echo "ERROR: setup berhenti di baris $LINENO." >&2' ERR

while [ $# -gt 0 ]; do
    case "$1" in
        --dir)    [ $# -ge 2 ] || die "--dir membutuhkan lokasi."; APP_DIR="$2"; shift 2 ;;
        --repo)   [ $# -ge 2 ] || die "--repo membutuhkan URL."; REPO_URL="$2"; shift 2 ;;
        --branch) [ $# -ge 2 ] || die "--branch membutuhkan nama branch."; BRANCH="$2"; shift 2 ;;
        --bind)   [ $# -ge 2 ] || die "--bind membutuhkan alamat."; BIND_ADDR="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,3p' "$0"
            exit 0
            ;;
        *) die "Argumen tidak dikenal: $1" ;;
    esac
done

if [ -n "$BIND_ADDR" ] && ! [[ "$BIND_ADDR" =~ ^[0-9a-fA-F:.]+$ ]]; then
    die "Alamat --bind tidak valid: $BIND_ADDR"
fi
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || die "Jalankan sebagai root atau pasang sudo."
fi

echo "================================================="
echo "     SETUP SMARTGOV BACKUP GATEWAY"
echo "================================================="

echo "[1/6] Memeriksa prasyarat..."
command -v git >/dev/null 2>&1 || die "git belum terpasang."
command -v docker >/dev/null 2>&1 || die "Docker belum terpasang."
if run docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1 && run docker-compose version >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
else
    die "Docker Compose tidak ditemukan."
fi

echo "[2/6] Mengambil source Gateway..."
if [ -d "${APP_DIR}/.git" ]; then
    echo "Repository sudah ada; mencoba menarik pembaruan fast-forward..."
    if ! run git -C "$APP_DIR" pull --ff-only; then
        echo "PERINGATAN: git pull gagal; menggunakan source lokal yang ada." >&2
    fi
elif [ -d "$APP_DIR" ] && [ -n "$(run ls -A "$APP_DIR")" ]; then
    die "${APP_DIR} tidak kosong dan bukan repository Git."
else
    run mkdir -p "$(dirname "$APP_DIR")"
    run git clone --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
fi

if [ -f "${APP_DIR}/docker-compose.yml" ]; then
    COMPOSE_DIR="$APP_DIR"
elif [ -f "${APP_DIR}/gateway/docker-compose.yml" ]; then
    COMPOSE_DIR="${APP_DIR}/gateway"
else
    die "docker-compose.yml tidak ditemukan di root repository atau subfolder gateway/."
fi

echo "[3/6] Menyiapkan data persisten..."
DATA_DIR="${COMPOSE_DIR}/gateway_data"
run mkdir -p "$DATA_DIR"
run chown -R 1000:1000 "$DATA_DIR"
run chmod 700 "$DATA_DIR"

if [ -n "$BIND_ADDR" ]; then
    ENV_FILE="${COMPOSE_DIR}/.env"
    if run test -f "$ENV_FILE"; then
        if run grep -q '^GATEWAY_BIND_ADDR=' "$ENV_FILE"; then
            run sed -i "s|^GATEWAY_BIND_ADDR=.*|GATEWAY_BIND_ADDR=${BIND_ADDR}|" "$ENV_FILE"
        else
            printf 'GATEWAY_BIND_ADDR=%s\n' "$BIND_ADDR" | run tee -a "$ENV_FILE" >/dev/null
        fi
    else
        printf 'GATEWAY_BIND_ADDR=%s\n' "$BIND_ADDR" | run tee "$ENV_FILE" >/dev/null
    fi
fi

if [ -z "$BIND_ADDR" ]; then
    BIND_ADDR="$(run sed -n 's/^GATEWAY_BIND_ADDR=//p' "${COMPOSE_DIR}/.env" 2>/dev/null | tail -n 1 || true)"
fi
BIND_ADDR="${BIND_ADDR:-127.0.0.1}"

echo "[4/6] Membangun image dari source dan menjalankan Gateway..."
cd "$COMPOSE_DIR"
run "${COMPOSE[@]}" up -d --build

echo "[5/6] Menunggu Gateway siap..."
READY=0
for _ in $(seq 1 30); do
    if run docker exec "$CONTAINER" curl -fsS http://127.0.0.1:25100/healthz >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 2
done
if [ "$READY" -ne 1 ]; then
    run docker logs --tail 40 "$CONTAINER" >&2 || true
    die "Gateway tidak merespons dalam 60 detik."
fi

echo "[6/6] Setup selesai."
echo
echo "Direktori aplikasi : ${COMPOSE_DIR}"
echo "Direktori data     : ${DATA_DIR}"
echo "Dashboard          : http://${BIND_ADDR}:25100"
run docker ps --filter "name=${CONTAINER}"

if ! run test -s "${DATA_DIR}/gateway_config.json"; then
    echo
    echo "Gateway belum dikonfigurasi. Buka dashboard untuk mengisi akun admin dan kredensial COS."
    if [ "$BIND_ADDR" = "127.0.0.1" ]; then
        HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
        echo "Untuk akses dari komputer lain, buat SSH tunnel:"
        echo "  ssh -L 25100:127.0.0.1:25100 <user>@${HOST_IP:-IP_SERVER}"
        echo "Lalu buka http://127.0.0.1:25100."
    fi
else
    echo
    echo "Konfigurasi dan data Gateway yang sudah ada dipertahankan."
fi

if [ "$BIND_ADDR" != "127.0.0.1" ] && [ "$BIND_ADDR" != "::1" ]; then
    echo "PERINGATAN: dashboard menggunakan HTTP Basic; jangan ekspos langsung ke internet."
    echo "Gunakan HTTPS reverse proxy dan firewall yang sesuai."
fi
