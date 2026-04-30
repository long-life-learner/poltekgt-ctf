require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Railway runs behind a proxy — required for express-rate-limit & secure cookies
app.set('trust proxy', 1);

if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL environment variable is not set!');
  console.error('   Di Railway: tambahkan PostgreSQL plugin dan link ke service ini.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('railway') ? { rejectUnauthorized: false } : 
       process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000,
  max: 10
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'ctf-dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });
const requireAuth  = (req, res, next) => req.session.user  ? next() : res.status(401).json({ error: 'Unauthorized' });
const requireAdmin = (req, res, next) => req.session.admin ? next() : res.status(401).json({ error: 'Forbidden' });
// Accepts both logged-in students AND admins (used for shared endpoints like scoreboard)
const requireAnyAuth = (req, res, next) => (req.session.user || req.session.admin) ? next() : res.status(401).json({ error: 'Unauthorized' });

// =================== INIT DB ===================
async function initDB() {
  const c = await pool.connect();
  try {
    // Create each table separately (pg does not support multiple statements in one query)
    await c.query(`CREATE TABLE IF NOT EXISTS students (
      id SERIAL PRIMARY KEY,
      nim VARCHAR(20) UNIQUE NOT NULL,
      name VARCHAR(100) NOT NULL,
      password VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    await c.query(`CREATE TABLE IF NOT EXISTS admins (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL
    )`);

    await c.query(`CREATE TABLE IF NOT EXISTS challenges (
      id SERIAL PRIMARY KEY,
      slug VARCHAR(50) UNIQUE NOT NULL,
      title VARCHAR(100) NOT NULL,
      category VARCHAR(20) NOT NULL,
      difficulty VARCHAR(10) NOT NULL,
      points INTEGER NOT NULL,
      flag VARCHAR(100) NOT NULL,
      description TEXT,
      hint TEXT,
      sort_order INTEGER DEFAULT 0
    )`);

    await c.query(`CREATE TABLE IF NOT EXISTS submissions (
      id SERIAL PRIMARY KEY,
      student_id INTEGER REFERENCES students(id),
      challenge_id INTEGER REFERENCES challenges(id),
      submitted_at TIMESTAMP DEFAULT NOW(),
      UNIQUE(student_id, challenge_id)
    )`);

    await c.query(`CREATE TABLE IF NOT EXISTS ctf_guestbook (
      id SERIAL PRIMARY KEY,
      author VARCHAR(100),
      content TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    await c.query(`CREATE TABLE IF NOT EXISTS ctf_products (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100),
      price VARCHAR(20),
      category VARCHAR(50)
    )`);

    await c.query(`CREATE TABLE IF NOT EXISTS ctf_secrets (
      id SERIAL PRIMARY KEY,
      secret_name VARCHAR(100),
      secret_value VARCHAR(255)
    )`);

    await c.query(`CREATE TABLE IF NOT EXISTS ctf_users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50),
      password VARCHAR(50),
      role VARCHAR(20),
      note VARCHAR(255)
    )`);

    // Seed admin account
    const adminUser = process.env.ADMIN_USERNAME || 'admin';
    const adminPass = process.env.ADMIN_PASSWORD || 'dosenctf2024';
    const adminHash = await bcrypt.hash(adminPass, 10);
    await c.query(
      `INSERT INTO admins (username, password) VALUES ($1, $2) ON CONFLICT (username) DO NOTHING`,
      [adminUser, adminHash]
    );

    // Seed challenges
    const { rows: ch } = await c.query('SELECT COUNT(*) FROM challenges');
    if (parseInt(ch[0].count) === 0) {
      await c.query(`INSERT INTO challenges (slug,title,category,difficulty,points,flag,description,hint,sort_order) VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        ['xss-1','Reflected XSS - Mesin Pencari Berbahaya','xss','Easy',100,'CTF{r3fl3ct3d_xss_b3rh4s1l}',
         'Sebuah halaman pencarian menampilkan input pengguna langsung ke halaman tanpa sanitasi. Temukan flag tersembunyi menggunakan XSS!',
         'Coba payload: <img src=x onerror=alert(document.getElementById("flag-secret").innerText)>',1]);

      await c.query(`INSERT INTO challenges (slug,title,category,difficulty,points,flag,description,hint,sort_order) VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        ['xss-2','Stored XSS - Buku Tamu Berbahaya','xss','Medium',200,'CTF{st0r3d_xss_p3rs1st3n}',
         'Form komentar menyimpan input ke database dan menampilkannya tanpa filter. Injeksikan XSS yang tersimpan!',
         'Payload yang kamu kirim akan dieksekusi setiap halaman dimuat. Flag ada di elemen tersembunyi.',2]);

      await c.query(`INSERT INTO challenges (slug,title,category,difficulty,points,flag,description,hint,sort_order) VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        ['xss-3','XSS + Cookie Stealing','xss','Hard',300,'CTF{c00k13_h1j4ck_suc3ss}',
         'Sebuah halaman menyimpan informasi rahasia di cookie. Gunakan XSS untuk membaca cookie tersebut!',
         'Cookie "secret_flag" tidak ber-HttpOnly. Gunakan: <img src=x onerror=alert(document.cookie)>',3]);

      await c.query(`INSERT INTO challenges (slug,title,category,difficulty,points,flag,description,hint,sort_order) VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        ['sqli-1','SQL Injection - Login Bypass','sqli','Easy',100,'CTF{sql1_byp4ss_l0g1n}',
         'Form login menggunakan query SQL yang rentan. Login sebagai admin tanpa mengetahui password!',
         "Query: SELECT * FROM users WHERE username='input' AND password='input'. Coba: admin'--",4]);

      await c.query(`INSERT INTO challenges (slug,title,category,difficulty,points,flag,description,hint,sort_order) VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        ['sqli-2','SQL Injection - UNION Attack','sqli','Medium',200,'CTF{un10n_s3l3ct_p0w3r}',
         'Fitur pencarian produk rentan terhadap UNION-based SQLi. Ekstrak flag dari tabel tersembunyi!',
         "Coba: ' UNION SELECT 1,secret_value,3,4 FROM ctf_secrets WHERE secret_name='flag_sqli2'--",5]);

      await c.query(`INSERT INTO challenges (slug,title,category,difficulty,points,flag,description,hint,sort_order) VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        ['sqli-3','Blind SQL Injection','sqli','Hard',300,'CTF{bl1nd_sqli_s4bar_ya}',
         'Tidak ada data tampil langsung, hanya "Ditemukan" atau "Tidak Ditemukan". Ekstrak flag karakter per karakter!',
         "Boolean-based: ' AND SUBSTRING(secret_value,1,1)='C'-- dari ctf_secrets WHERE secret_name='flag_sqli3'",6]);
    }

    // Seed guestbook
    const { rows: gb } = await c.query('SELECT COUNT(*) FROM ctf_guestbook');
    if (parseInt(gb[0].count) === 0) {
      await c.query(`INSERT INTO ctf_guestbook (author, content) VALUES ($1,$2)`, ['Admin','Selamat datang di Buku Tamu Poltek GT!']);
      await c.query(`INSERT INTO ctf_guestbook (author, content) VALUES ($1,$2)`, ['System','<span id="flag-stored" style="display:none">CTF{st0r3d_xss_p3rs1st3n}</span>Sistem berjalan normal.']);
      await c.query(`INSERT INTO ctf_guestbook (author, content) VALUES ($1,$2)`, ['Mahasiswa','Website ini keren sekali!']);
    }

    // Seed products
    const { rows: pr } = await c.query('SELECT COUNT(*) FROM ctf_products');
    if (parseInt(pr[0].count) === 0) {
      await c.query(`INSERT INTO ctf_products (name,price,category) VALUES ($1,$2,$3)`,['Laptop Gaming ROG','15000000','Elektronik']);
      await c.query(`INSERT INTO ctf_products (name,price,category) VALUES ($1,$2,$3)`,['Mouse Wireless Logitech','250000','Aksesoris']);
      await c.query(`INSERT INTO ctf_products (name,price,category) VALUES ($1,$2,$3)`,['Keyboard Mechanical','800000','Aksesoris']);
      await c.query(`INSERT INTO ctf_products (name,price,category) VALUES ($1,$2,$3)`,['Monitor 4K','5000000','Elektronik']);
    }

    // Seed secrets (SQLi flags)
    const { rows: sc } = await c.query('SELECT COUNT(*) FROM ctf_secrets');
    if (parseInt(sc[0].count) === 0) {
      await c.query(`INSERT INTO ctf_secrets (secret_name,secret_value) VALUES ($1,$2)`,['flag_sqli2','CTF{un10n_s3l3ct_p0w3r}']);
      await c.query(`INSERT INTO ctf_secrets (secret_name,secret_value) VALUES ($1,$2)`,['flag_sqli3','CTF{bl1nd_sqli_s4bar_ya}']);
      await c.query(`INSERT INTO ctf_secrets (secret_name,secret_value) VALUES ($1,$2)`,['kunci_rahasia','poltek-gt-2024']);
    }

    // Seed CTF login users (for SQLi challenge 1)
    const { rows: cu } = await c.query('SELECT COUNT(*) FROM ctf_users');
    if (parseInt(cu[0].count) === 0) {
      await c.query(`INSERT INTO ctf_users (username,password,role,note) VALUES ($1,$2,$3,$4)`,['admin','s3cr3t_p4ss','admin','CTF{sql1_byp4ss_l0g1n}']);
      await c.query(`INSERT INTO ctf_users (username,password,role,note) VALUES ($1,$2,$3,$4)`,['user1','password123','user','akun biasa']);
      await c.query(`INSERT INTO ctf_users (username,password,role,note) VALUES ($1,$2,$3,$4)`,['user2','qwerty','user','akun biasa']);
    }

    console.log('✅ Database initialized');
  } finally {
    c.release();
  }
}

// =================== AUTH ROUTES ===================
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { nim, name, password } = req.body;
  if (!nim || !name || !password) return res.status(400).json({ error: 'Semua field wajib diisi' });
  if (!nim.startsWith('2402')) return res.status(400).json({ error: 'NIM tidak valid. NIM harus diawali 2402' });
  if (nim.length < 7) return res.status(400).json({ error: 'NIM minimal 7 digit' });
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO students (nim, name, password) VALUES ($1, $2, $3)', [nim, name, hash]);
    res.json({ success: true, message: 'Registrasi berhasil! Silakan login.' });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'NIM sudah terdaftar' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { nim, password } = req.body;
  if (!nim || !password) return res.status(400).json({ error: 'NIM dan password wajib diisi' });

  // Check admin
  if (nim === (process.env.ADMIN_USERNAME || 'admin')) {
    const { rows } = await pool.query('SELECT * FROM admins WHERE username=$1', [nim]);
    if (rows.length && await bcrypt.compare(password, rows[0].password)) {
      req.session.admin = { id: rows[0].id, username: rows[0].username };
      return res.json({ success: true, role: 'admin', redirect: '/admin/' });
    }
    return res.status(401).json({ error: 'Kredensial tidak valid' });
  }

  // Check student
  const { rows } = await pool.query('SELECT * FROM students WHERE nim=$1', [nim]);
  if (!rows.length || !await bcrypt.compare(password, rows[0].password)) {
    return res.status(401).json({ error: 'NIM atau password salah' });
  }
  req.session.user = { id: rows[0].id, nim: rows[0].nim, name: rows[0].name };
  res.json({ success: true, role: 'student', redirect: '/dashboard.html' });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/auth/me', (req, res) => {
  if (req.session.admin) return res.json({ role: 'admin', user: req.session.admin });
  if (req.session.user) return res.json({ role: 'student', user: req.session.user });
  res.status(401).json({ error: 'Not logged in' });
});

// =================== CHALLENGE ROUTES ===================
app.get('/api/challenges', requireAuth, async (req, res) => {
  const { rows: challenges } = await pool.query('SELECT id,slug,title,category,difficulty,points,description,hint FROM challenges ORDER BY sort_order');
  const { rows: subs } = await pool.query('SELECT challenge_id FROM submissions WHERE student_id=$1', [req.session.user.id]);
  const solved = new Set(subs.map(s => s.challenge_id));
  res.json(challenges.map(ch => ({ ...ch, solved: solved.has(ch.id) })));
});

app.post('/api/challenges/submit', requireAuth, async (req, res) => {
  const { slug, flag } = req.body;
  if (!slug || !flag) return res.status(400).json({ error: 'Data tidak lengkap' });
  const { rows: ch } = await pool.query('SELECT * FROM challenges WHERE slug=$1', [slug]);
  if (!ch.length) return res.status(404).json({ error: 'Challenge tidak ditemukan' });
  const challenge = ch[0];
  if (flag.trim() !== challenge.flag) return res.status(400).json({ error: 'Flag salah! Coba lagi.' });

  try {
    await pool.query('INSERT INTO submissions (student_id, challenge_id) VALUES ($1, $2)', [req.session.user.id, challenge.id]);
    res.json({ success: true, message: `Selamat! +${challenge.points} poin`, points: challenge.points });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'Challenge ini sudah kamu selesaikan!' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/scoreboard', requireAnyAuth, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT s.nim, s.name,
      COALESCE(SUM(ch.points),0) AS total_points,
      COUNT(sub.id) AS solved_count,
      MAX(sub.submitted_at) AS last_solved
    FROM students s
    LEFT JOIN submissions sub ON sub.student_id = s.id
    LEFT JOIN challenges ch ON ch.id = sub.challenge_id
    GROUP BY s.id, s.nim, s.name
    ORDER BY total_points DESC, last_solved ASC
  `);
  res.json(rows);
});

// =================== ADMIN ROUTES ===================
app.get('/api/admin/students', requireAdmin, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT s.id, s.nim, s.name, s.created_at,
      COALESCE(SUM(ch.points),0) AS total_points,
      COUNT(sub.id) AS solved_count
    FROM students s
    LEFT JOIN submissions sub ON sub.student_id = s.id
    LEFT JOIN challenges ch ON ch.id = sub.challenge_id
    GROUP BY s.id ORDER BY total_points DESC
  `);
  res.json(rows);
});

app.get('/api/admin/detail/:studentId', requireAdmin, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT ch.title, ch.category, ch.difficulty, ch.points, sub.submitted_at
    FROM submissions sub
    JOIN challenges ch ON ch.id = sub.challenge_id
    WHERE sub.student_id = $1 ORDER BY sub.submitted_at
  `, [req.params.studentId]);
  res.json(rows);
});

app.get('/api/admin/export', requireAdmin, async (req, res) => {
  const { rows } = await pool.query(`
    SELECT s.nim, s.name,
      COALESCE(SUM(ch.points),0) AS total_points,
      COUNT(sub.id) AS solved_count
    FROM students s
    LEFT JOIN submissions sub ON sub.student_id = s.id
    LEFT JOIN challenges ch ON ch.id = sub.challenge_id
    GROUP BY s.id ORDER BY total_points DESC
  `);
  let csv = 'NIM,Nama,Total Poin,Challenge Diselesaikan\n';
  rows.forEach(r => { csv += `${r.nim},"${r.name}",${r.total_points},${r.solved_count}\n`; });
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=nilai-ctf.csv');
  res.send(csv);
});

app.delete('/api/admin/student/:id', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM submissions WHERE student_id=$1', [req.params.id]);
  await pool.query('DELETE FROM students WHERE id=$1', [req.params.id]);
  res.json({ success: true });
});

// =================== VULNERABLE CHALLENGE ENDPOINTS ===================

// XSS-1: Reflected XSS
app.get('/vuln/xss-1', requireAuth, (req, res) => {
  const q = req.query.q || '';
  res.send(`<!DOCTYPE html><html lang="id"><head>
    <meta charset="UTF-8"><title>Mesin Pencari - Challenge XSS #1</title>
    <link rel="stylesheet" href="/css/style.css">
    <style>.vuln-container{max-width:700px;margin:40px auto;padding:20px}</style>
  </head><body class="vuln-page">
    <div class="vuln-header">
      <span class="badge-vuln">⚠️ VULNERABLE PAGE</span>
      <a href="/challenge/xss-1.html" class="btn-back">← Kembali ke Challenge</a>
    </div>
    <div class="vuln-container">
      <h2>🔍 Mesin Pencari Poltek GT</h2>
      <form method="GET" action="/vuln/xss-1">
        <div class="search-box">
          <input type="text" name="q" value="${q}" placeholder="Cari sesuatu..." class="input-vuln">
          <button type="submit" class="btn-primary">Cari</button>
        </div>
      </form>
      ${q ? `<div class="search-result"><p>Menampilkan hasil untuk: <strong>${q}</strong></p><p>Tidak ada hasil ditemukan.</p></div>` : ''}
      <div style="display:none" id="flag-secret">CTF{r3fl3ct3d_xss_b3rh4s1l}</div>
    </div>
    <script>
      // Petunjuk tersembunyi untuk developer
      // Flag ada di: document.getElementById('flag-secret').innerText
    </script>
  </body></html>`);
});

// XSS-2: Stored XSS - Guestbook
app.get('/vuln/xss-2', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM ctf_guestbook ORDER BY created_at');
  let entries = rows.map(r =>
    `<div class="guestbook-entry"><strong>${r.author}</strong><span class="time">${new Date(r.created_at).toLocaleString('id-ID')}</span><p>${r.content}</p></div>`
  ).join('');
  res.send(`<!DOCTYPE html><html lang="id"><head>
    <meta charset="UTF-8"><title>Buku Tamu - Challenge XSS #2</title>
    <link rel="stylesheet" href="/css/style.css">
  </head><body class="vuln-page">
    <div class="vuln-header">
      <span class="badge-vuln">⚠️ VULNERABLE PAGE</span>
      <a href="/challenge/xss-2.html" class="btn-back">← Kembali ke Challenge</a>
    </div>
    <div class="vuln-container">
      <h2>📖 Buku Tamu Poltek GT</h2>
      <form id="gbForm">
        <input type="text" id="author" placeholder="Nama Anda" class="input-vuln" style="margin-bottom:8px">
        <textarea id="content" placeholder="Tulis komentar..." class="input-vuln" rows="3"></textarea>
        <button onclick="submitComment()" class="btn-primary" type="button">Kirim Komentar</button>
      </form>
      <div id="entries">${entries}</div>
    </div>
    <script>
      async function submitComment(){
        const author=document.getElementById('author').value;
        const content=document.getElementById('content').value;
        await fetch('/vuln/xss-2/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({author,content})});
        location.reload();
      }
    </script>
  </body></html>`);
});

app.post('/vuln/xss-2/add', requireAuth, async (req, res) => {
  const { author, content } = req.body;
  if (!author || !content) return res.status(400).json({ error: 'Isi semua field' });
  // INTENTIONALLY VULNERABLE: no sanitization
  await pool.query('INSERT INTO ctf_guestbook (author, content) VALUES ($1, $2)', [author, content]);
  res.json({ success: true });
});

// XSS-3: Cookie-based XSS
app.get('/vuln/xss-3', requireAuth, (req, res) => {
  const q = req.query.q || '';
  res.cookie('secret_flag', 'CTF{c00k13_h1j4ck_suc3ss}', { httpOnly: false });
  res.send(`<!DOCTYPE html><html lang="id"><head>
    <meta charset="UTF-8"><title>Portal Nilai - Challenge XSS #3</title>
    <link rel="stylesheet" href="/css/style.css">
  </head><body class="vuln-page">
    <div class="vuln-header">
      <span class="badge-vuln">⚠️ VULNERABLE PAGE</span>
      <a href="/challenge/xss-3.html" class="btn-back">← Kembali ke Challenge</a>
    </div>
    <div class="vuln-container">
      <h2>📊 Portal Cek Nilai Mahasiswa</h2>
      <form method="GET" action="/vuln/xss-3">
        <div class="search-box">
          <input type="text" name="q" value="${q}" placeholder="Masukkan NIM..." class="input-vuln">
          <button type="submit" class="btn-primary">Cek Nilai</button>
        </div>
      </form>
      ${q ? `<div class="search-result"><p>Mencari nilai untuk NIM: <strong>${q}</strong></p><p>Data tidak ditemukan.</p></div>` : ''}
      <div class="info-box">🔒 Sistem ini menyimpan token autentikasi di browser cookie Anda.</div>
    </div>
  </body></html>`);
});

// SQLi-1: Login Bypass (uses ctf_users table with raw query)
app.get('/vuln/sqli-1', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public/challenge/sqli-1-vuln.html'));
});

app.post('/vuln/sqli-1/login', requireAuth, async (req, res) => {
  const { username, password } = req.body;
  try {
    // INTENTIONALLY VULNERABLE: String interpolation in SQL
    const query = `SELECT * FROM ctf_users WHERE username='${username}' AND password='${password}'`;
    const { rows } = await pool.query(query);
    if (rows.length > 0 && rows[0].role === 'admin') {
      res.json({ success: true, flag: rows[0].note, username: rows[0].username, role: rows[0].role });
    } else if (rows.length > 0) {
      res.json({ success: false, message: 'Login berhasil tapi kamu bukan admin. Coba lagi!' });
    } else {
      res.json({ success: false, message: 'Username atau password salah.' });
    }
  } catch (e) {
    res.json({ success: false, message: 'SQL Error: ' + e.message });
  }
});

// SQLi-2: UNION-based (uses ctf_products with raw query)
app.get('/vuln/sqli-2/search', requireAuth, async (req, res) => {
  const q = req.query.q || '';
  try {
    // INTENTIONALLY VULNERABLE
    const query = `SELECT id, name, price, category FROM ctf_products WHERE name LIKE '%${q}%'`;
    const { rows } = await pool.query(query);
    res.json({ success: true, query_used: query, results: rows });
  } catch (e) {
    res.json({ success: false, error: e.message, query_used: `SELECT id, name, price, category FROM ctf_products WHERE name LIKE '%${q}%'` });
  }
});

// SQLi-3: Blind SQLi
app.get('/vuln/sqli-3/check', requireAuth, async (req, res) => {
  const q = req.query.q || '1';
  try {
    // INTENTIONALLY VULNERABLE
    const query = `SELECT secret_value FROM ctf_secrets WHERE secret_name='flag_sqli3' AND ${q}`;
    const { rows } = await pool.query(query);
    res.json({ found: rows.length > 0, message: rows.length > 0 ? '✅ Data Ditemukan' : '❌ Data Tidak Ditemukan' });
  } catch (e) {
    res.json({ found: false, message: '⚠️ Error: ' + e.message });
  }
});

// =================== SPA ROUTING ===================
app.get('/admin*', (req, res) => {
  if (req.path === '/admin/' || req.path === '/admin') {
    res.sendFile(path.join(__dirname, 'public/admin/index.html'));
  }
});

// =================== START ===================
async function startServer() {
  // Start HTTP server immediately
  app.listen(PORT, () => console.log(`🚀 CTF Server running on port ${PORT}`));

  if (!process.env.DATABASE_URL) {
    console.error('⚠️  DATABASE_URL tidak ditemukan. Server jalan tapi DB tidak terhubung.');
    console.error('   Set DATABASE_URL di Railway environment variables.');
    return;
  }

  // Retry DB connection up to 5 times
  let retries = 5;
  while (retries > 0) {
    try {
      await initDB();
      console.log('✅ Database terhubung dan siap!');
      return;
    } catch (err) {
      retries--;
      if (retries === 0) {
        console.error('❌ Gagal konek database setelah 5 percobaan:', err.message);
        console.error('   Pastikan PostgreSQL plugin sudah ditambahkan di Railway.');
      } else {
        console.log(`⏳ Mencoba koneksi DB lagi... (${retries} percobaan tersisa)`);
        await new Promise(r => setTimeout(r, 3000));
      }
    }
  }
}

startServer();
