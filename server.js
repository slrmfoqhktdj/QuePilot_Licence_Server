const path = require('path');
require('dotenv').config({ path: path.join(__dirname, './.env') });

const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');
const mysql = require('mysql2/promise');
const option = require('./db/dboption')
const bcrypt = require('bcryptjs');
const { log } = require('console');
const multer = require('multer');
const fs = require('fs');
const cookieParser = require('cookie-parser');

// ✅ 수정: app 선언 순서 (set 보다 먼저)
const app = express();

app.set('trust proxy', true);

const port = process.env.PORT || 6000;
const LICENSE_SECRET = process.env.LICENSE_SECRET || 'your-super-secret-key';
const SUPER_ADMIN_EMAIL = process.env.SUPER_ADMIN_EMAIL || 'admin@quepilot.com';
const SUPER_ADMIN_PW = process.env.SUPER_ADMIN_PW || '0000';

// ✅ 수정: express.json()만 사용 (bodyParser 중복 제거)
app.use(express.json({limit: '500mb'}));
app.use(express.urlencoded({ extended: true, limit: '500mb' }));
app.use(cookieParser());

app.use(cors({
  origin: true,
  credentials: true,
}));

app.use(express.static(path.join(__dirname, 'public'), {
  index: false,  // index.html 자동 서빙 비활성화 (선택)
}));

// 업로드 저장 설정
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    // 원본 파일명 유지 (한글 깨짐 방지)
    const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');
    // 동일 파일명 덮어쓰기 방지: timestamp 접두사
    const safeName = `${Date.now()}_${originalName}`;
    cb(null, safeName);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 500 * 1024 * 1024 }, // 500MB
  fileFilter: (req, file, cb) => {
    // exe, zip, msi만 허용
    const allowed = ['.exe', '.zip', '.msi'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('허용되지 않는 파일 형식입니다. (exe, zip, msi만 가능)'));
    }
  },
});



// ========== MySQL 연결 풀 ==========

const pool = mysql.createPool(option.sessionconfig);

// ========== 페이지 ===========

// ---------- 홈페이지 ----------
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---------- 로그인 페이지 ----------
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// ---------- 사용자 대시보드 ----------
app.get('/dashboard', requirePageAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

// ---------- 관리자 페이지 ----------
app.get('/admin/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

app.get('/admin', requireAdminPage, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});




//  ========== 홈페이지 회원 API ==========

// ---------- 회원가입 ----------
app.post('/api/member/register', async (req, res) => {
  try {
    const { email, password, companyName, phone } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: '이메일과 비밀번호를 입력하세요' });
    }

    const [existing] = await pool.execute(
      'SELECT BIN_TO_UUID(id) AS id FROM users WHERE email = ?',
      [email]
    );
    if (existing.length) {
      return res.status(409).json({ success: false, message: '이미 가입된 이메일입니다' });
    }

    const id = crypto.randomUUID();
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.execute(
      `INSERT INTO users (id, email, password, company_name, phone)
       VALUES (UUID_TO_BIN(?), ?, ?, ?, ?)`,
      [id, email, hashedPassword, companyName || '', phone || '']
    );

    console.log(`✅ 회원가입: ${email}`);
    res.json({ success: true });
  } catch (err) {
    console.error('❌ 회원가입 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 홈페이지 로그인 ----------
app.post('/api/member/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: '이메일과 비밀번호를 입력하세요' });
    }

    const result = await authenticateUser(email, password, '24h');

    if (!result.success) {
      return res.status(result.status).json({ success: false, message: result.message });
    }

    // ★ 쿠키에 토큰 저장 추가
    res.cookie('token', result.token, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000,
    });

    console.log(`✅ 홈페이지 로그인: ${email}`);
    res.json({
      success: true,
      token: result.token,
      member: {
        id: result.user.id,
        email: result.user.email,
        companyName: result.user.company_name,
        phone: result.user.phone,
      },
    });
  } catch (err) {
    console.error('❌ 홈페이지 로그인 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// 홈페이지 회원 로그아웃 (없으면 추가)
app.post('/api/member/logout', async (req, res) => {
  try {
    const token = req.cookies?.token 
      || req.headers.authorization?.replace('Bearer ', '');

    if (token) {
      try {
        const decoded = jwt.verify(token, LICENSE_SECRET);
        await pool.execute(
          'DELETE FROM activations WHERE user_id = UUID_TO_BIN(?)',
          [decoded.userId]
        );
      } catch (err) {
        // 만료된 토큰이어도 쿠키는 삭제
      }
    }

    res.clearCookie('token');
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// 관리자 로그아웃 (없으면 추가)
app.post('/api/admin/logout', (req, res) => {
  res.clearCookie('adminToken');
  res.json({ success: true });
});


// ---------- 회원 인증 미들웨어 (DB 확인 추가) ----------
async function requireMember(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: '로그인이 필요합니다' });
  }

  try {
    const token = auth.slice(7);
    const decoded = jwt.verify(token, LICENSE_SECRET);

    // ★ 사용자가 아직 활성 상태인지 확인
    const [rows] = await pool.execute(
      `SELECT BIN_TO_UUID(id) AS id, is_active, expires_at 
       FROM users WHERE id = UUID_TO_BIN(?)`,
      [decoded.userId]
    );

    if (!rows.length) {
      return res.status(401).json({ success: false, message: '사용자를 찾을 수 없습니다' });
    }

    const user = rows[0];

    // 구독 만료 확인
    if (user.is_active !== 1 || !user.expires_at || new Date(user.expires_at) < new Date()) {
      return res.status(403).json({
        success: false,
        message: '구독이 만료되었습니다'
      });
    }

    req.member = decoded;
    next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      message: '세션이 만료되었습니다. 다시 로그인하세요'
    });
  }
}


// ---------- 서버 토큰 인증 미들웨어 (activations 테이블 확인) ----------
async function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: '인증이 필요합니다' });
  }

  try {
    const token = auth.slice(7);
    const decoded = jwt.verify(token, LICENSE_SECRET);

    // ★ DB에 해당 토큰이 존재하는지 확인
    const [rows] = await pool.execute(
      `SELECT id FROM activations 
       WHERE user_id = UUID_TO_BIN(?) AND token = ?`,
      [decoded.userId, token]
    );

    if (!rows.length) {
      return res.status(401).json({
        success: false,
        message: '세션이 만료되었습니다. 다시 로그인하세요'
      });
    }

    req.auth = decoded;
    next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      message: '세션이 만료되었습니다. 다시 로그인하세요'
    });
  }
}

// ========== 페이지 인증 미들웨어 ==========

// 쿠키 또는 쿼리로 토큰을 받아 검증
async function requirePageAuth(req, res, next) {
  // 1순위: 쿠키, 2순위: Authorization 헤더
  const token = req.cookies?.token
    || req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.redirect('/login');
  }

  try {
    const decoded = jwt.verify(token, LICENSE_SECRET);

    const [rows] = await pool.execute(
      'SELECT id FROM activations WHERE user_id = UUID_TO_BIN(?) AND token = ?',
      [decoded.userId, token]
    );

    if (!rows.length) {
      res.clearCookie('token');
      return res.redirect('/login?message=세션이 종료되었습니다');
    }

    req.member = decoded;
    next();
  } catch (err) {
    res.clearCookie('token');
    return res.redirect('/login?message=세션이 만료되었습니다');
  }
}



// ---------- 공통 로그인 로직 ----------
async function authenticateUser(email, password, tokenExpiry = '24h') {
  const [rows] = await pool.execute(
    `SELECT BIN_TO_UUID(id) AS id, email, password, company_name, phone, 
            plan, max_users, grace_days, expires_at, is_active, created_at
     FROM users WHERE email = ?`,
    [email]
  );

  if (!rows.length) return { success: false, status: 401, message: '이메일 또는 비밀번호가 올바르지 않습니다' };

  const user = rows[0];
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return { success: false, status: 401, message: '이메일 또는 비밀번호가 올바르지 않습니다' };

  const token = jwt.sign(
    { userId: user.id, email: user.email, expiresAt: user.expires_at },
    LICENSE_SECRET,
    { expiresIn: tokenExpiry }
  );

  // 활성 세션: 기존 삭제 → 새로 생성
  await pool.execute(
    'DELETE FROM activations WHERE user_id = UUID_TO_BIN(?)',
    [user.id]
  );
  await pool.execute(
    `INSERT INTO activations (user_id, token, activated_at, last_check)
     VALUES (UUID_TO_BIN(?), ?, NOW(), NOW())`,
    [user.id, token]
  );

  return { success: true, user, token };
}


// ---------- 세션 검증 (홈페이지 네비게이션용, activations 기준) ----------
app.get('/api/member/session', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT BIN_TO_UUID(id) AS id, email, company_name, phone
       FROM users WHERE id = UUID_TO_BIN(?)`,
      [req.auth.userId]
    );
    if (!rows.length) {
      return res.status(401).json({ success: false, message: '회원 정보를 찾을 수 없습니다' });
    }
    res.json({ success: true, member: rows[0] });
  } catch (err) {
    console.error('❌ 세션 검증 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 내 정보 ----------
app.get('/api/member/me', requireMember, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT BIN_TO_UUID(id) AS id, email, company_name, phone, plan, max_users, expires_at, is_active, created_at
       FROM users WHERE id = UUID_TO_BIN(?)`,
      [req.member.userId]
    );
    if (!rows.length) {
      return res.status(404).json({ success: false, message: '회원 정보를 찾을 수 없습니다' });
    }
    res.json({ success: true, member: rows[0] });
  } catch (err) {
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 내 구독 정보 ----------
app.get('/api/member/subscription', requireMember, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT BIN_TO_UUID(id) AS id, plan, max_users, expires_at, is_active
       FROM users WHERE id = UUID_TO_BIN(?)`,
      [req.member.userId]
    );

    if (!rows.length) {
      return res.status(404).json({ success: false, message: '사용자를 찾을 수 없습니다' });
    }

    const user = rows[0];
    const isActive = user.is_active === 1
      && user.expires_at
      && new Date(user.expires_at) > new Date();

    res.json({
      success: true,
      hasActiveSubscription: isActive,
      subscription: {
        plan: user.plan,
        expires_at: user.expires_at,
        daysLeft: user.expires_at
          ? Math.ceil((new Date(user.expires_at) - new Date()) / (1000 * 60 * 60 * 24))
          : 0,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 구독 신청 ----------
app.post('/api/member/subscribe', requireMember, async (req, res) => {
  try {
    const { plan, paymentMethod } = req.body;

    const plans = {
      // basic:    { amount: 50000,  days: 30,  label: 'Basic (1개월)' },
      standard: { amount: 130000, days: 30, label: 'Standard (1개월)' },
      // premium:  { amount: 450000, days: 365, label: 'Premium (1년)' },
    };

    const selected = plans[plan];
    if (!selected) {
      return res.status(400).json({ success: false, message: '올바른 플랜을 선택하세요' });
    }

    const [rows] = await pool.execute(
      'SELECT expires_at FROM users WHERE id = UUID_TO_BIN(?)',
      [req.member.userId]
    );

    const now = new Date();
    const currentExpiry = rows[0]?.expires_at ? new Date(rows[0].expires_at) : now;
    const startDate = currentExpiry > now ? currentExpiry : now;
    const expiresDate = new Date(startDate);
    expiresDate.setDate(expiresDate.getDate() + selected.days);

    const startedAt = startDate.toISOString().slice(0, 19).replace('T', ' ');
    const expiresAt = expiresDate.toISOString().slice(0, 19).replace('T', ' ');

    // 결제 내역 저장
    await pool.execute(
      `INSERT INTO payments (user_id, plan, amount, payment_method, status, started_at, expires_at)
       VALUES (UUID_TO_BIN(?), ?, ?, ?, 'completed', ?, ?)`,
      [req.member.userId, plan, selected.amount, paymentMethod || 'bank_transfer', startedAt, expiresAt]
    );

    // users 구독 상태 갱신
    await pool.execute(
      'UPDATE users SET plan = ?, max_users = 80, expires_at = ?, is_active = 1 WHERE id = UUID_TO_BIN(?)',
      [plan, expiresAt, req.member.userId]
    );

    console.log(`💳 결제 완료: ${req.member.email} → ${selected.label} (${expiresAt})`);
    res.json({
      success: true,
      subscription: { plan, amount: selected.amount, startedAt, expiresAt },
    });
  } catch (err) {
    console.error('❌ 구독 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 결제 내역 조회 (사용자용) ----------
app.get('/api/member/payments', requireMember, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT id, plan, amount, payment_method, status, started_at, expires_at, created_at
       FROM payments
       WHERE user_id = UUID_TO_BIN(?)
       ORDER BY created_at DESC`,
      [req.member.userId]
    );

    const [[{ total }]] = await pool.execute(
      `SELECT IFNULL(SUM(amount), 0) AS total FROM payments
       WHERE user_id = UUID_TO_BIN(?) AND status = 'completed'`,
      [req.member.userId]
    );

    res.json({ success: true, payments: rows, totalAmount: total });
  } catch (err) {
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 다운로드 ----------
app.get('/api/member/download', requireMember, async (req, res) => {
  try {
    // 활성 구독 확인 (users 테이블에서 직접 확인)
    const [userRows] = await pool.execute(
      `SELECT is_active, expires_at FROM users
       WHERE id = UUID_TO_BIN(?) AND is_active = 1 AND expires_at > NOW()`,
      [req.member.userId]
    );

    if (!userRows.length) {
      return res.status(403).json({ success: false, message: '활성 구독이 필요합니다' });
    }

    const [files] = await pool.execute(
      "SELECT * FROM server_files WHERE category = 'server' AND is_active = 1 LIMIT 1"
    );

    if (!files.length) {
      return res.status(404).json({ success: false, message: '다운로드 가능한 파일이 없습니다.' });
    }

    const file = files[0];
    const filePath = path.join(uploadDir, file.stored_name);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ success: false, message: '파일이 서버에 존재하지 않습니다.' });
    }

    // server_files 다운로드 카운트 증가
    await pool.execute(
      'UPDATE server_files SET download_count = download_count + 1 WHERE id = ?',
      [file.id]
    );

    // 다운로드 기록 저장
    await pool.execute(
      'INSERT INTO downloads (user_id, version) VALUES (UUID_TO_BIN(?), ?)',
      [req.member.userId, file.version]
    );

    console.log(`📥 다운로드: ${req.member.email} - ${file.original_name} (v${file.version})`);

    // ★ 확장자별 Content-Type 매핑
    const extMap = {
      '.exe': 'application/x-msdownload',
      '.msi': 'application/x-msi',
      '.zip': 'application/zip',
    };
    const ext = path.extname(file.original_name).toLowerCase();
    const contentType = extMap[ext] || 'application/octet-stream';

    // ★ 다운로드 헤더 명시
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.original_name)}"`);
    res.setHeader('Content-Length', file.file_size);
    res.setHeader('X-Content-Type-Options', 'nosniff');




    // res.download(filePath, DOWNLOAD_FILE);
    // ★ DB의 원본 파일명으로 다운로드
    res.download(filePath, file.original_name);
  } catch (err) {
    console.error('❌ 다운로드 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 다운로드 이력 ----------
app.get('/api/member/downloads', requireMember, async (req, res) => {
  try {

    const [active] = await pool.execute(
      "SELECT version, description, file_size, uploaded_at FROM server_files WHERE category = 'server' AND is_active = 1 LIMIT 1"
    );

    const [history] = await pool.execute(
      `SELECT id, version, downloaded_at FROM downloads
       WHERE user_id = UUID_TO_BIN(?)
       ORDER BY downloaded_at DESC LIMIT 10`,
      [req.member.userId]
    );
    res.json({
      success: true,
      currentVersion: active.length ? active[0].version : '-',
      currentDescription: active.length ? active[0].description : '',
      currentFileSize: active.length ? active[0].file_size : 0,
      downloads: history,
    });
  } catch (err) {
    console.error('다운로드 정보 조회 실패:', err);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 공개 다운로드 (데스크탑 앱, 로그인 불필요) ----------
app.get('/api/public/files/desktop', async (req, res) => {
  try {
    const [files] = await pool.execute(
      `SELECT original_name, version, description, file_size FROM server_files
       WHERE category = 'desktop' AND is_active = 1
       ORDER BY uploaded_at DESC LIMIT 1`
    );

    if (!files.length) {
      return res.json({ success: false, message: '다운로드 가능한 파일이 없습니다.' });
    }

    const f = files[0];
    res.json({
      success: true,
      fileName: f.original_name,
      version: f.version,
      description: f.description,
      fileSize: f.file_size,
    });
  } catch (err) {
    console.error('공개 파일 정보 조회 실패:', err);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

app.get('/api/public/download/desktop', async (req, res) => {
  try {
    const [files] = await pool.execute(
      `SELECT * FROM server_files
       WHERE category = 'desktop' AND is_active = 1
       ORDER BY uploaded_at DESC LIMIT 1`
    );

    if (!files.length) {
      return res.status(404).json({ success: false, message: '다운로드 가능한 파일이 없습니다.' });
    }

    const file = files[0];
    const filePath = path.join(uploadDir, file.stored_name);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ success: false, message: '파일이 서버에 존재하지 않습니다.' });
    }

    // server_files 다운로드 카운트 증가 (공개 다운로드는 사용자 기록 없음)
    await pool.execute(
      'UPDATE server_files SET download_count = download_count + 1 WHERE id = ?',
      [file.id]
    );

    console.log(`📥 공개 다운로드: ${file.original_name} (v${file.version})`);

    // ★ 확장자별 Content-Type 매핑
    const extMap = {
      '.exe': 'application/x-msdownload',
      '.msi': 'application/x-msi',
      '.zip': 'application/zip',
    };
    const ext = path.extname(file.original_name).toLowerCase();
    const contentType = extMap[ext] || 'application/octet-stream';

    // ★ 다운로드 헤더 명시
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(file.original_name)}"`);
    res.setHeader('Content-Length', file.file_size);
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // ★ DB의 원본 파일명으로 다운로드
    res.download(filePath, file.original_name);
  } catch (err) {
    console.error('❌ 공개 다운로드 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ══════════════════════════════════════════════
//  서버(exe) 인증 API
// ══════════════════════════════════════════════

// ---------- 서버 로그인 (bcrypt 비교) ----------
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: '아이디와 비밀번호를 입력하세요' });
    }

    const result = await authenticateUser(email, password, '24h');

    if (!result.success) {
      return res.status(result.status).json({ success: false, message: result.message });
    }

    const user = result.user;
    const isExpired = !user.expires_at || new Date(user.expires_at) < new Date();

    if (user.is_active !== 1 || isExpired) {
      return res.json({
        success: true,
        subscription: { isActive: false },
        message: '구독이 만료되었습니다',
      });
    }

    console.log(`✅ 서버 로그인: ${email}`);
    res.json({
      success: true,
      token: result.token,
      subscription: {
        isActive: true,
        plan: user.plan,
        maxUsers: user.max_users,
        companyName: user.company_name,
        expiresAt: user.expires_at,
        graceDays: user.grace_days ?? 7,
      },
    });
  } catch (err) {
    console.error('❌ 서버 로그인 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 토큰 갱신 ----------
app.post('/api/auth/refresh', requireAuth, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ')
      ? authHeader.slice(7)
      : req.body?.token;

    if (!token) {
      return res.status(401).json({ success: false, message: 'Token required' });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, LICENSE_SECRET);
    } catch (jwtErr) {
      return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }

    // ★ 활성 세션에 해당 토큰이 있는지 확인
    const [activations] = await pool.execute(
      'SELECT id FROM activations WHERE user_id = UUID_TO_BIN(?) AND token = ?',
      [decoded.userId, token]
    );

    if (!activations.length) {
      return res.status(401).json({
        success: false,
        message: '세션이 만료되었습니다. 다시 로그인하세요'
      });
    }

    const [rows] = await pool.execute(
      `SELECT BIN_TO_UUID(id) AS id, email, plan, max_users, company_name, expires_at, is_active, grace_days
       FROM users
       WHERE id = UUID_TO_BIN(?) AND is_active = 1`,
      [decoded.userId]
    );

    if (!rows.length || !rows[0].expires_at || new Date(rows[0].expires_at) < new Date()) {
      return res.status(403).json({ success: false, message: '구독이 만료되었습니다' });
    }

    const user = rows[0];
    const newToken = jwt.sign(
      { userId: user.id, email: user.email, expiresAt: user.expires_at },
      LICENSE_SECRET,
      { expiresIn: '24h' }
    );

    // ★ 기존 토큰을 새 토큰으로 교체
    await pool.execute(
      'UPDATE activations SET token = ?, last_check = NOW() WHERE user_id = UUID_TO_BIN(?) AND token = ?',
      [newToken, user.id, token]
    );

    res.json({
      success: true,
      token: newToken,
      subscription: {
        isActive: true,
        plan: user.plan,
        maxUsers: user.max_users,
        companyName: user.company_name,
        expiresAt: user.expires_at,
        graceDays: user.grace_days ?? 7,
      },
    });
  } catch (err) {
    console.error('❌ 토큰 갱신 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 서버 로그아웃 ----------
app.post('/api/auth/logout', requireAuth, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (token) {
      try {
        const decoded = jwt.verify(token, LICENSE_SECRET);
        await pool.execute(
          'DELETE FROM activations WHERE user_id = UUID_TO_BIN(?)',
          [decoded.userId]
        );
        console.log(`👋 서버 로그아웃: ${decoded.email}`);
      } catch (jwtErr) {
        console.log('⚠️ 만료된 토큰으로 로그아웃 시도');
      }
    }

    res.clearCookie('token');
    res.json({ success: true });
  } catch (err) {
    console.error('❌ 로그아웃 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ══════════════════════════════════════════════
//  관리자 페이지 & API
// ══════════════════════════════════════════════

// ---------- 관리자 API 인증 미들웨어 (JWT Bearer) ----------
async function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: '로그인이 필요합니다' });
  }

  try {
    const token = authHeader.slice(7);
    const decoded = jwt.verify(token, LICENSE_SECRET);

    const [rows] = await pool.execute(
      'SELECT BIN_TO_UUID(id) AS id, email, role, is_active FROM admins WHERE id = UUID_TO_BIN(?)',
      [decoded.adminId]
    );

    if (!rows.length || !rows[0].is_active) {
      return res.status(403).json({ success: false, message: '권한이 없습니다' });
    }

    req.admin = rows[0];
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: '세션이 만료되었습니다' });
  }
}

// ---------- 관리자 페이지 인증 미들웨어 (쿠키) ----------
async function requireAdminPage(req, res, next) {
  const token = req.cookies?.adminToken;

  if (!token) {
    return res.redirect('/admin/login');
  }

  try {
    const decoded = jwt.verify(token, LICENSE_SECRET);

    const [rows] = await pool.execute(
      'SELECT BIN_TO_UUID(id) AS id, email, role, is_active FROM admins WHERE id = UUID_TO_BIN(?)',
      [decoded.adminId]
    );

    if (!rows.length || !rows[0].is_active) {
      res.clearCookie('adminToken');
      return res.redirect('/admin/login');
    }

    req.admin = rows[0];
    next();
  } catch (err) {
    res.clearCookie('adminToken');
    return res.redirect('/admin/login');
  }
}

// ---------- 관리자 로그인 ----------
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: '이메일과 비밀번호를 입력하세요' });
    }

    const [rows] = await pool.execute(
      'SELECT BIN_TO_UUID(id) AS id, email, password, role, is_active FROM admins WHERE email = ?',
      [email]
    );

    if (!rows.length) {
      return res.status(401).json({ success: false, message: '관리자 인증 실패' });
    }

    const admin = rows[0];
    if (!admin.is_active) {
      return res.status(403).json({ success: false, message: '비활성화된 계정입니다' });
    }

    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: '관리자 인증 실패' });
    }

    const token = jwt.sign(
      { adminId: admin.id, email: admin.email, role: admin.role },
      LICENSE_SECRET,
      { expiresIn: '24h' }
    );

    res.cookie('adminToken', token, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000,
    });

    console.log(`✅ 관리자 로그인: ${email}`);
    res.json({ success: true, token });
  } catch (err) {
    console.error('❌ 관리자 로그인 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 관리자 로그아웃 ----------
app.post('/api/admin/logout', (req, res) => {
  res.clearCookie('adminToken');
  res.json({ success: true });
});

// ---------- 관리자 목록 (CRUD) ----------
app.get('/api/admin/admins', requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT BIN_TO_UUID(id) AS id, email, role, is_active, last_login_at, created_at
       FROM admins ORDER BY created_at ASC`
    );
    res.json({ success: true, admins: rows });
  } catch (err) {
    console.error('❌ 관리자 목록 조회 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

app.post('/api/admin/admins', requireAdmin, async (req, res) => {
  try {
    const { email, password, role } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: '이메일과 비밀번호를 입력하세요' });
    }

    const [existing] = await pool.execute(
      'SELECT id FROM admins WHERE email = ?', [email]
    );
    if (existing.length) {
      return res.status(409).json({ success: false, message: '이미 존재하는 이메일입니다' });
    }

    const id = crypto.randomUUID();
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.execute(
      `INSERT INTO admins (id, email, password, role, is_active)
       VALUES (UUID_TO_BIN(?), ?, ?, ?, 1)`,
      [id, email, hashedPassword, role || 'admin']
    );

    console.log(`➕ 관리자 생성: ${email}`);
    res.json({ success: true, adminId: id });
  } catch (err) {
    console.error('❌ 관리자 생성 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

app.put('/api/admin/admins/:id', requireAdmin, async (req, res) => {
  try {
    const adminId = req.params.id;
    const { password, role, isActive } = req.body;

    const [rows] = await pool.execute(
      'SELECT email FROM admins WHERE id = UUID_TO_BIN(?)', [adminId]
    );
    if (!rows.length) {
      return res.status(404).json({ success: false, message: '관리자를 찾을 수 없습니다' });
    }

    const updates = [];
    const params = [];

    if (password) {
      const hashed = await bcrypt.hash(password, 10);
      updates.push('password = ?');
      params.push(hashed);
    }
    if (role !== undefined) {
      updates.push('role = ?');
      params.push(role);
    }
    if (isActive !== undefined) {
      updates.push('is_active = ?');
      params.push(isActive ? 1 : 0);
    }

    if (updates.length) {
      params.push(adminId);
      await pool.execute(
        `UPDATE admins SET ${updates.join(', ')} WHERE id = UUID_TO_BIN(?)`,
        params
      );
    }

    console.log(`✏️ 관리자 수정: ${rows[0].email}`);
    res.json({ success: true });
  } catch (err) {
    console.error('❌ 관리자 수정 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

app.delete('/api/admin/admins/:id', requireAdmin, async (req, res) => {
  try {
    const adminId = req.params.id;

    const [rows] = await pool.execute(
      'SELECT email FROM admins WHERE id = UUID_TO_BIN(?)', [adminId]
    );
    if (!rows.length) {
      return res.status(404).json({ success: false, message: '관리자를 찾을 수 없습니다' });
    }

    await pool.execute('DELETE FROM admins WHERE id = UUID_TO_BIN(?)', [adminId]);

    console.log(`🗑️ 관리자 삭제: ${rows[0].email}`);
    res.json({ success: true });
  } catch (err) {
    console.error('❌ 관리자 삭제 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 사용자 목록 ----------
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const [users] = await pool.execute(`
      SELECT
        BIN_TO_UUID(u.id) AS id,
        u.email,
        u.company_name,
        u.phone,
        u.plan,
        u.max_users,
        u.grace_days,
        u.expires_at,
        u.is_active,
        u.created_at,
        (SELECT COUNT(*) FROM activations a WHERE a.user_id = u.id) AS activation_count,
        (SELECT MAX(a.last_check) FROM activations a WHERE a.user_id = u.id) AS last_active
      FROM users u
      ORDER BY u.created_at DESC
    `);

    console.log(`👥 사용자 목록 조회: ${users}`);

    const enriched = users.map((u) => ({
      ...u,
      isExpired: !u.expires_at || new Date(u.expires_at) < new Date(),
      daysLeft: u.expires_at
        ? Math.ceil((new Date(u.expires_at) - new Date()) / (1000 * 60 * 60 * 24))
        : 0,
    }));

    res.json({ success: true, users: enriched });
  } catch (err) {
    console.error('❌ 사용자 목록 조회 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 사용자 생성 ----------
app.post('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const { email, password, companyName, phone, maxUsers, graceDays, expiresAt } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: '이메일과 비밀번호를 입력하세요' });
    }

    const [existing] = await pool.execute(
      'SELECT BIN_TO_UUID(id) AS id FROM users WHERE email = ?',
      [email]
    );
    if (existing.length) {
      return res.status(409).json({ success: false, message: '이미 존재하는 이메일입니다' });
    }

    const id = crypto.randomUUID();
    const hashedPassword = await bcrypt.hash(password, 10);
    const expiresAtFormatted = expiresAt
      ? new Date(expiresAt).toISOString().slice(0, 19).replace('T', ' ')
      : null;

    await pool.execute(
      `INSERT INTO users (id, email, password, company_name, phone, max_users, grace_days, expires_at, is_active)
       VALUES (UUID_TO_BIN(?), ?, ?, ?, ?, ?, ?, ?, 1)`,
      [id, email, hashedPassword, companyName || '', phone || '', maxUsers || 80, graceDays ?? 7, expiresAtFormatted]
    );

    console.log(`➕ 사용자 생성: ${email}`);
    res.json({ success: true, userId: id });
  } catch (err) {
    console.error('❌ 사용자 생성 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 사용자 수정 ----------
app.put('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const { password, expiresAt, isActive, graceDays } = req.body;

    const [rows] = await pool.execute(
      `SELECT BIN_TO_UUID(id) AS id, email, password, grace_days, expires_at, is_active
       FROM users WHERE id = UUID_TO_BIN(?)`,
      [userId]
    );

    if (!rows.length) {
      return res.status(404).json({ success: false, message: '사용자를 찾을 수 없습니다' });
    }

    const user = rows[0];
    const newPassword = password ? await bcrypt.hash(password, 10) : user.password;
    const newExpiresAt = expiresAt
      ? new Date(expiresAt).toISOString().slice(0, 19).replace('T', ' ')
      : user.expires_at;
    const newIsActive = isActive !== undefined ? (isActive ? 1 : 0) : user.is_active;
    const newGraceDays = graceDays !== undefined ? graceDays : user.grace_days;

    await pool.execute(
      'UPDATE users SET password = ?, grace_days = ?, expires_at = ?, is_active = ? WHERE id = UUID_TO_BIN(?)',
      [newPassword, newGraceDays, newExpiresAt, newIsActive, userId]
    );

    console.log(`✏️ 사용자 수정: ${user.email}`);
    res.json({ success: true });
  } catch (err) {
    console.error('❌ 사용자 수정 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 사용자 삭제 ----------
app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;

    const [rows] = await pool.execute(
      'SELECT email FROM users WHERE id = UUID_TO_BIN(?)',
      [userId]
    );
    if (!rows.length) {
      return res.status(404).json({ success: false, message: '사용자를 찾을 수 없습니다' });
    }

    await pool.execute('DELETE FROM activations WHERE user_id = UUID_TO_BIN(?)', [userId]);
    await pool.execute('DELETE FROM users WHERE id = UUID_TO_BIN(?)', [userId]);

    console.log(`🗑️ 사용자 삭제: ${rows[0].email}`);
    res.json({ success: true });
  } catch (err) {
    console.error('❌ 사용자 삭제 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 구독 연장 ----------
app.post('/api/admin/users/:id/extend', requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const { days } = req.body;

    const [rows] = await pool.execute(
      'SELECT BIN_TO_UUID(id) AS id, email, expires_at FROM users WHERE id = UUID_TO_BIN(?)',
      [userId]
    );
    if (!rows.length) {
      return res.status(404).json({ success: false, message: '사용자를 찾을 수 없습니다' });
    }

    const user = rows[0];
    const now = new Date();
    const currentExpiry = user.expires_at ? new Date(user.expires_at) : now;
    const base = currentExpiry > now ? currentExpiry : now;
    base.setDate(base.getDate() + (days || 30));
    const newExpires = base.toISOString().slice(0, 19).replace('T', ' ');

    await pool.execute(
      'UPDATE users SET expires_at = ?, is_active = 1 WHERE id = UUID_TO_BIN(?)',
      [newExpires, userId]
    );

    console.log(`📅 구독 연장: ${user.email} → ${newExpires}`);
    res.json({ success: true, expiresAt: newExpires });
  } catch (err) {
    console.error('❌ 구독 연장 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 전체 결제 내역 ----------
app.get('/api/admin/payments', requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT p.id, u.email, p.plan, p.amount, p.payment_method, p.status,
             p.started_at, p.expires_at, p.memo, p.created_at
      FROM payments p
      JOIN users u ON p.user_id = u.id
      ORDER BY p.created_at DESC
    `);
    res.json({ success: true, payments: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 결제 상태 변경 (환불 처리 등) ----------
app.put('/api/admin/payments/:id', requireAdmin, async (req, res) => {
  try {
    const paymentId = req.params.id;
    const { status, memo } = req.body;

    const [rows] = await pool.execute(
      `SELECT p.id, p.status, p.plan, p.amount, p.expires_at,
              BIN_TO_UUID(p.user_id) AS user_id, u.email
       FROM payments p
       JOIN users u ON p.user_id = u.id
       WHERE p.id = ?`,
      [paymentId]
    );

    if (!rows.length) {
      return res.status(404).json({ success: false, message: '결제 내역을 찾을 수 없습니다' });
    }

    const payment = rows[0];

    await pool.execute(
      'UPDATE payments SET status = ?, memo = ? WHERE id = ?',
      [status || payment.status, memo !== undefined ? memo : payment.memo, paymentId]
    );

    if (status === 'refunded') {
      const [validPayments] = await pool.execute(
        `SELECT MAX(expires_at) AS latest_expires
         FROM payments
         WHERE user_id = UUID_TO_BIN(?) AND status = 'completed' AND expires_at > NOW()`,
        [payment.user_id]
      );

      const latestExpires = validPayments[0]?.latest_expires;
      if (latestExpires) {
        const formatted = new Date(latestExpires).toISOString().slice(0, 19).replace('T', ' ');
        await pool.execute(
          'UPDATE users SET expires_at = ? WHERE id = UUID_TO_BIN(?)',
          [formatted, payment.user_id]
        );
      } else {
        await pool.execute(
          'UPDATE users SET expires_at = NULL, plan = NULL, is_active = 0 WHERE id = UUID_TO_BIN(?)',
          [payment.user_id]
        );
      }

      console.log(`💰 환불 처리: ${payment.email} (${payment.plan}, ₩${payment.amount})`);
    }

    res.json({ success: true });
  } catch (err) {
    console.error('❌ 결제 상태 변경 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 결제 통계 ----------
app.get('/api/admin/payment-stats', requireAdmin, async (req, res) => {
  try {
    const [[{ total }]] = await pool.execute(
      "SELECT IFNULL(SUM(amount), 0) AS total FROM payments WHERE status = 'completed'"
    );
    const [[{ monthly }]] = await pool.execute(
      `SELECT IFNULL(SUM(amount), 0) AS monthly FROM payments
       WHERE status = 'completed'
       AND YEAR(created_at) = YEAR(NOW()) AND MONTH(created_at) = MONTH(NOW())`
    );
    const [[{ refunded }]] = await pool.execute(
      "SELECT IFNULL(SUM(amount), 0) AS refunded FROM payments WHERE status = 'refunded'"
    );
    const [byPlan] = await pool.execute(
      `SELECT plan, COUNT(*) AS count, SUM(amount) AS total
       FROM payments WHERE status = 'completed'
       GROUP BY plan`
    );
    const [monthlyTrend] = await pool.execute(
      `SELECT DATE_FORMAT(created_at, '%Y-%m') AS month,
              COUNT(*) AS count, SUM(amount) AS total
       FROM payments WHERE status = 'completed'
       GROUP BY month ORDER BY month DESC LIMIT 12`
    );

    res.json({
      success: true,
      stats: { totalRevenue: total, monthlyRevenue: monthly, totalRefunded: refunded, byPlan, monthlyTrend },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 활성 세션 목록 ----------
app.get('/api/admin/activations', requireAdmin, async (req, res) => {
  try {
    const [activations] = await pool.execute(`
      SELECT
        a.id,
        BIN_TO_UUID(a.user_id) AS user_id,
        a.activated_at,
        a.last_check,
        u.email
      FROM activations a
      JOIN users u ON a.user_id = u.id
      ORDER BY a.last_check DESC
    `);
    res.json({ success: true, activations });
  } catch (err) {
    console.error('❌ 활성 세션 조회 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 강제 로그아웃 ----------
app.post('/api/admin/users/:id/kick', requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;

    const [rows] = await pool.execute(
      'SELECT email FROM users WHERE id = UUID_TO_BIN(?)',
      [userId]
    );

    await pool.execute(
      'DELETE FROM activations WHERE user_id = UUID_TO_BIN(?)',
      [userId]
    );

    const email = rows.length ? rows[0].email : userId;
    console.log(`🔌 강제 로그아웃: ${email}`);
    res.json({ success: true });
  } catch (err) {
    console.error('❌ 강제 로그아웃 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ---------- 대시보드 통계 ----------
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const [[{ count: totalUsers }]] = await pool.execute(
      'SELECT COUNT(*) AS count FROM users'
    );
    const [[{ count: activeUsers }]] = await pool.execute(
      'SELECT COUNT(*) AS count FROM users WHERE is_active = 1 AND expires_at > NOW()'
    );
    const [[{ count: expiredUsers }]] = await pool.execute(
      'SELECT COUNT(*) AS count FROM users WHERE expires_at IS NULL OR expires_at <= NOW()'
    );
    const [[{ count: activeSessions }]] = await pool.execute(
      'SELECT COUNT(*) AS count FROM activations'
    );
    const [[{ count: expiringIn7Days }]] = await pool.execute(
      `SELECT COUNT(*) AS count FROM users
       WHERE is_active = 1 AND expires_at > NOW()
       AND expires_at <= DATE_ADD(NOW(), INTERVAL 7 DAY)`
    );

    res.json({
      success: true,
      stats: { totalUsers, activeUsers, expiredUsers, activeSessions, expiringIn7Days },
    });
  } catch (err) {
    console.error('❌ 통계 조회 오류:', err.message);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ===== 관리자: 파일 목록 =====
app.get('/api/admin/files', requireAdmin, async (req, res) => {
  try {
    const [files] = await pool.execute(
      'SELECT * FROM server_files ORDER BY uploaded_at DESC'
    );

    const result = files.map(f => ({
      ...f,
      file_size_mb: (f.file_size / (1024 * 1024)).toFixed(1),
      file_exists: fs.existsSync(path.join(uploadDir, f.stored_name)),
    }));

    res.json({ success: true, files: result });
  } catch (err) {
    console.error('파일 목록 조회 실패:', err);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ===== 관리자: 파일 업로드 =====
app.post('/api/admin/files', requireAdmin, (req, res) => {
  console.log('📦 파일 업로드 요청 수신');  // ★ 디버그

  upload.single('file')(req, res, async (err) => {
    console.log('📦 multer 처리 완료, err:', err);  // ★ 디버그

    if (err) {
      if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ success: false, message: '파일 크기는 500MB 이하만 가능합니다.' });
      }
      return res.status(400).json({ success: false, message: err.message });
    }

    if (!req.file) {
      return res.status(400).json({ success: false, message: '파일이 없습니다.' });
    }

    const version = req.body.version || '1.0.0';
    const description = req.body.description || '';
    const category = req.body.category === 'desktop' ? 'desktop' : 'server';
    const originalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8');

    try {
      const [result] = await pool.execute(
        `INSERT INTO server_files (original_name, stored_name, file_size, version, description, category)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [originalName, req.file.filename, req.file.size, version, description, category]
      );

      res.json({
        success: true,
        file: {
          id: result.insertId,
          original_name: originalName,
          file_size: req.file.size,
          version,
          category,
        },
      });
    } catch (err) {
      fs.unlinkSync(req.file.path);
      console.error('파일 업로드 DB 저장 실패:', err);
      res.status(500).json({ success: false, message: '서버 오류' });
    }
  });
});

// ===== 관리자: 파일 삭제 =====
app.delete('/api/admin/files/:id', requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM server_files WHERE id = ?', [req.params.id]);
    if (!rows.length) {
      return res.status(404).json({ success: false, message: '파일을 찾을 수 없습니다.' });
    }

    const file = rows[0];
    const filePath = path.join(uploadDir, file.stored_name);

    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    await pool.execute('DELETE FROM server_files WHERE id = ?', [req.params.id]);

    res.json({ success: true });
  } catch (err) {
    console.error('파일 삭제 실패:', err);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ===== 관리자: 활성 파일 변경 (카테고리별) =====
app.put('/api/admin/files/:id/activate', requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT category FROM server_files WHERE id = ?', [req.params.id]);
    if (!rows.length) {
      return res.status(404).json({ success: false, message: '파일을 찾을 수 없습니다.' });
    }

    const { category } = rows[0];
    await pool.execute('UPDATE server_files SET is_active = 0 WHERE category = ?', [category]);
    await pool.execute('UPDATE server_files SET is_active = 1 WHERE id = ?', [req.params.id]);

    res.json({ success: true });
  } catch (err) {
    console.error('활성화 변경 실패:', err);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});

// ===== 관리자: 파일 정보 수정 =====
app.put('/api/admin/files/:id', requireAdmin, async (req, res) => {
  const { version, description } = req.body;
  const category = req.body.category === 'desktop' ? 'desktop' : 'server';
  try {
    await pool.execute(
      'UPDATE server_files SET version = ?, description = ?, category = ? WHERE id = ?',
      [version, description, category, req.params.id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error('파일 정보 수정 실패:', err);
    res.status(500).json({ success: false, message: '서버 오류' });
  }
});


// ========== 에러 핸들링 ==========
process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err);
});
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});
process.on('SIGINT', async () => {
  console.log('\n🛑 서버 종료 중...');
  await pool.end();
  console.log('✅ DB 연결 종료');
  process.exit(0);
});

// ========== Super Admin 시드 ==========
async function seedSuperAdmin() {
  try {
    const [rows] = await pool.execute('SELECT id FROM admins LIMIT 1');
    if (rows.length) return;

    const id = crypto.randomUUID();
    const hashedPassword = await bcrypt.hash(SUPER_ADMIN_PW, 10);

    await pool.execute(
      `INSERT INTO admins (id, email, password, role, is_active)
       VALUES (UUID_TO_BIN(?), ?, ?, 'super', 1)`,
      [id, SUPER_ADMIN_EMAIL, hashedPassword]
    );

    console.log(`🌱 Super Admin 생성: ${SUPER_ADMIN_EMAIL}`);
  } catch (err) {
    console.error('❌ Super Admin 시드 오류:', err.message);
  }
}

// ========== 서버 시작 ==========

app.listen(port, async () => {
  await seedSuperAdmin();
  console.log(`🔑 QuePilot License Server listening on port ${port}`);
});

