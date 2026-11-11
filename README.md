# SmartGOV Backup Gateway

Gateway pusat mengelola token agent dan menyediakan akses admin ke daftar arsip backup di Tencent Cloud COS. Agent meminta presigned upload URL dari Gateway; kredensial master COS tidak perlu dipasang di server Agent.

## Setup cepat

Jalankan pada server Linux yang sudah memiliki Git, Docker, dan Docker Compose:

```bash
curl -fsSLO https://raw.githubusercontent.com/adityabintang-lab/cartenz-smartgov-backup-gateway/main/setup.sh
sudo bash setup.sh
```

Installer mengambil source, membangun image, membuat direktori data, dan menunggu health check Gateway. Secara default dashboard hanya di-bind ke `127.0.0.1:25100`. Untuk mengakses dari komputer lain, buat SSH tunnel:

```bash
ssh -L 25100:127.0.0.1:25100 <user>@<IP_SERVER>
```

Lalu buka `http://127.0.0.1:25100`. Opsi installer:

```bash
sudo bash setup.sh --dir /opt/smartgov-gateway
sudo bash setup.sh --bind 0.0.0.0  # hanya jika berada di belakang HTTPS reverse proxy
sudo bash setup.sh --repo https://github.com/ORG/REPO.git --branch main
```

Installer aman dijalankan ulang untuk memperbarui source dan membangun ulang image. Data konfigurasi tetap disimpan di `gateway_data/`. Jika Gateway sudah pernah disiapkan, konfigurasi dan token yang ada tidak dihapus.

## Menjalankan dari source

Jalankan dari root repository Gateway:

```bash
mkdir -p gateway_data
sudo chown 1000:1000 gateway_data
sudo chmod 700 gateway_data
docker compose up -d --build
docker logs cartenz-smartgov-backup-gateway
```

Dashboard: `http://127.0.0.1:25100`. Bind address bisa diatur lewat `.env`:

```dotenv
GATEWAY_BIND_ADDR=127.0.0.1
```

Jangan membuka dashboard HTTP langsung ke jaringan publik. Jika akses jaringan diperlukan, batasi port dengan firewall dan gunakan HTTPS reverse proxy. Gateway memakai HTTP Basic untuk autentikasi admin.

## Konfigurasi awal

Pada kunjungan pertama, wizard meminta:

- Username dan password admin (minimal 6 karakter).
- Tencent Cloud COS Secret ID, Secret Key, region, dan nama bucket.

Siapkan kredensial COS dengan hak minimum yang diperlukan untuk membuat presigned upload URL, membaca daftar objek, dan mengunduh objek pada prefix backup. Setelah setup, login menggunakan kredensial admin yang dibuat.

## Dashboard

- Buat, salin, dan hapus token untuk tiap Agent target.
- Telusuri folder dan file pada prefix `backups/` di bucket COS.
- Lihat ukuran dan waktu perubahan file, berpindah folder, dan memuat halaman berikutnya.
- Unduh file lewat tautan presigned yang berlaku singkat.

Daftar objek dan tautan unduhan hanya tersedia setelah autentikasi admin. Dashboard tidak menyediakan penghapusan objek COS.

## Menghubungkan Agent

Isi pengaturan Agent dengan URL Gateway yang dapat dijangkau dari server Agent, misalnya `https://gateway.example.go.id`. Buat token di dashboard Gateway, lalu masukkan token tersebut pada pengaturan Agent. Gunakan HTTPS agar token Agent terenkripsi saat dikirim ke Gateway.

Gateway mendengarkan pada port `25100`; Agent secara default berjalan pada port `25200`.

## Data dan operasi

- Konfigurasi Gateway tersimpan di `gateway_data/gateway_config.json`, termasuk kredensial COS dan hash password admin. Lindungi direktori ini dan jangan memasukkannya ke source control.
- Token Agent tersimpan dalam konfigurasi Gateway. Hapus token dari dashboard jika Agent tidak lagi dipercaya.
- Health check: `http://127.0.0.1:25100/healthz`.
- Log container: `docker logs cartenz-smartgov-backup-gateway`.
