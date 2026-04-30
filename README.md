# 🛡️ Poltek GT CTF Lab — Panduan Deploy Railway

## Struktur Aplikasi

```
ctf/
├── server.js          # Express backend (semua route)
├── public/
│   ├── index.html     # Login & Register
│   ├── dashboard.html # Dashboard mahasiswa
│   ├── tutorial.html  # Tutorial XSS & SQLi
│   ├── scoreboard.html
│   ├── challenge/     # 6 halaman challenge
│   │   ├── xss-1.html, xss-2.html, xss-3.html
│   │   └── sqli-1.html, sqli-2.html, sqli-3.html
│   ├── admin/index.html  # Panel dosen
│   └── css/style.css
├── railway.toml       # Konfigurasi Railway
└── package.json
```

---

## Langkah Deploy ke Railway

### 1. Push ke GitHub dulu
```bash
cd "d:\POLTEK GT\IT STAFF\APPS\ctf"
git init
git add .
git commit -m "Initial CTF platform"
git remote add origin https://github.com/USERNAME/poltek-gt-ctf.git
git push -u origin main
```

### 2. Buat Project di Railway
1. Buka https://railway.com → Login
2. Klik **"New Project"** → **"Deploy from GitHub repo"**
3. Pilih repo `poltek-gt-ctf`
4. Railway akan otomatis detect Node.js

### 3. Tambah PostgreSQL Database
1. Di Railway project → Klik **"+ New"** → **"Database"** → **"PostgreSQL"**
2. Database otomatis terhubung ke project

### 4. Set Environment Variables
Di Railway project → **Settings** → **Variables**, tambahkan:

| Variable | Value |
|---|---|
| `SESSION_SECRET` | (string acak panjang, contoh: `ctf2024poltekg7xyz`) |
| `ADMIN_USERNAME` | `admin` |
| `ADMIN_PASSWORD` | (password pilihan dosen) |
| `NODE_ENV` | `production` |

> `DATABASE_URL` otomatis terisi dari PostgreSQL plugin Railway!

### 5. Deploy
Railway akan otomatis build & deploy. Tunggu sampai status **"Active"**.

---

## Login Credentials

### Dosen (Admin)
- **URL:** `https://your-app.railway.app`
- **Username:** `admin` (sesuai ADMIN_USERNAME)
- **Password:** sesuai ADMIN_PASSWORD di Railway

### Mahasiswa
- Registrasi mandiri di halaman login
- NIM harus diawali `2402`
- Password bebas (mahasiswa set sendiri)

---

## Flag per Challenge

| Challenge | Flag |
|---|---|
| XSS #1 Reflected | `CTF{r3fl3ct3d_xss_b3rh4s1l}` |
| XSS #2 Stored | `CTF{st0r3d_xss_p3rs1st3n}` |
| XSS #3 Cookie | `CTF{c00k13_h1j4ck_suc3ss}` |
| SQLi #1 Login Bypass | `CTF{sql1_byp4ss_l0g1n}` |
| SQLi #2 UNION | `CTF{un10n_s3l3ct_p0w3r}` |
| SQLi #3 Blind | `CTF{bl1nd_sqli_s4bar_ya}` |

> **Jangan bagikan daftar ini ke mahasiswa!**

---

## Fitur Admin Panel

Akses: `https://your-app.railway.app` → Login sebagai admin

- **Data Mahasiswa**: Lihat semua NIM, nama, poin, progress
- **Detail**: Klik "Detail" untuk lihat challenge mana yang sudah diselesaikan + waktunya
- **Scoreboard**: Ranking real-time
- **Export CSV**: Download nilai semua mahasiswa ke Excel
- **Hapus Mahasiswa**: Reset data jika diperlukan
