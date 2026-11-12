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

Gateway menolak path probe umum seperti `/.env`, `/.git`, `wp-admin`, dan `cgi-bin` dengan 404, serta mengirim header keamanan pada respons. Ini bukan firewall dan tidak menghentikan scanner mengirim request; pertahankan access log untuk pemantauan, batasi akses di firewall/reverse proxy, dan jangan mengekspos port HTTP langsung. Jika log menampilkan alamat Docker seperti `172.19.0.1`, itu biasanya alamat proxy/container di sisi depan, bukan IP klien asli; pastikan proxy mencatat IP klien dan jangan mempercayai header `X-Forwarded-For` dari koneksi yang tidak tepercaya.

## Konfigurasi awal

Pada kunjungan pertama, wizard meminta:

- Username dan password admin (minimal 6 karakter).
- Tencent Cloud COS Secret ID, Secret Key, region, dan nama bucket.

Siapkan kredensial COS dengan izin membuat presigned upload URL, membaca daftar objek, mengunduh objek, dan menghapus objek lama pada prefix backup. Izin hapus diperlukan agar retensi otomatis per Agent dapat berjalan. Batasi izin tersebut hanya pada bucket/prefix backup. Setelah setup, login menggunakan kredensial admin yang dibuat.

## Dashboard

- Buat, salin, dan hapus token untuk tiap Agent target.
- Telusuri folder berdasarkan nama Agent/daerah pada prefix `backups/`, dengan subfolder `database/` dan `application/`.
- Lihat ukuran dan waktu perubahan file, berpindah folder, dan memuat halaman berikutnya.
- Unduh file lewat tautan presigned yang berlaku singkat.
- Dekripsi arsip `.age` dari browser setelah admin memasukkan private key age. Private key tidak disimpan permanen, tetapi sementara ditulis ke file mode `0600` di `/tmp` untuk dipakai program `age`, lalu file tersebut dihapus. Karena itu lindungi host/container Gateway dan jangan menganggap ini setara decrypt sepenuhnya di perangkat pengguna.

Daftar objek dan tautan unduhan hanya tersedia setelah autentikasi admin. Penghapusan objek lama dilakukan otomatis oleh retensi Agent; dashboard tidak menyediakan penghapusan manual.

### Cara mendekripsi dan memulihkan backup

1. Pastikan Gateway sudah dibangun ulang dengan image terbaru (`docker compose up -d --build`); image harus memiliki program `age`.
2. Siapkan private key yang cocok dengan public key age yang dipakai saat backup dibuat. Jika belum punya keypair, buat di komputer tepercaya, bukan di server:

   ```bash
   age-keygen -o kunci-backup.txt
   ```

   Masukkan public key (`age1...`) pada Pengaturan Agent sebelum backup berikutnya. Simpan `kunci-backup.txt` secara offline dan aman. Private key yang tidak cocok tidak dapat mendekripsi arsip.
3. Buka dashboard Gateway melalui HTTPS atau SSH tunnel, lalu login sebagai admin.
4. Telusuri `backups/` → folder Agent/daerah → `database/` atau `application/`.
5. Pada file berakhiran `.age`, pilih **Dekripsi**. Tempel seluruh isi private key (baris `AGE-SECRET-KEY-...`) ke prompt; jangan masukkan path file. Gateway memproses hanya arsip yang dipilih, lalu browser mengunduh hasil `.tar.gz`.
6. Hasil dekripsi **tidak terenkripsi**. Simpan di media yang terlindungi, ekstrak di mesin restore tepercaya, dan hapus salinan sementara setelah selesai.

Contoh pemulihan database di Linux (ganti nama file dan kredensial sesuai lingkungan):

```bash
mkdir -p ./restore/database
tar -xzf smartgov_database_TIMESTAMP.tar.gz -C ./restore/database
mariadb -h HOST -u USER -p < ./restore/database/database.sql
```

Contoh ekstraksi backup aplikasi ke direktori staging untuk diperiksa sebelum dipulihkan:

```bash
mkdir -p ./restore/application
tar -xzf smartgov_application_TIMESTAMP.tar.gz -C ./restore/application
```

Jangan mengekstrak arsip langsung ke direktori produksi sebelum memeriksa isinya. Proses dekripsi menggunakan streaming di Gateway, tetapi browser dashboard mengumpulkan file hasil sebelum mengunduh; komputer pengguna perlu ruang/memori yang cukup untuk ukuran arsip.

Setiap token Agent menggunakan folder berdasarkan nama token/daerah; nama yang menghasilkan folder sama ditolak agar arsip tidak tercampur. Retensi awal Agent menjaga 7 arsip database dan 2 arsip aplikasi per folder; file COS tertua di kategori tersebut dihapus setelah upload baru berhasil.

## Menghubungkan Agent

Isi pengaturan Agent dengan URL Gateway yang dapat dijangkau dari server Agent, misalnya `https://gateway.example.go.id`. Buat token di dashboard Gateway, lalu masukkan token tersebut pada pengaturan Agent. Gunakan HTTPS agar token Agent terenkripsi saat dikirim ke Gateway.

Gateway mendengarkan pada port `25100`; Agent secara default berjalan pada port `25200`.

## Data dan operasi

- Konfigurasi Gateway tersimpan di `gateway_data/gateway_config.json`, termasuk kredensial COS dan hash password admin. Lindungi direktori ini dan jangan memasukkannya ke source control.
- Token Agent tersimpan dalam konfigurasi Gateway. Hapus token dari dashboard jika Agent tidak lagi dipercaya.
- Health check: `http://127.0.0.1:25100/healthz`.
- Log container: `docker logs cartenz-smartgov-backup-gateway`.
