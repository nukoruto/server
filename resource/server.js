/**
 * プレ版 Web セッションロガー
 * -----------------------------------------
 * - Node.js v20.x 推奨
 * - express / jsonwebtoken / body-parser
 * - CSV ログ: timestamp, user_id, endpoint, use_case, type, jwt, label
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');

const SECRET   = 'change_this_to_env_secret'; // 本運用では環境変数へ
const PORT     = 3000;
const LOG_DIR  = path.join(__dirname, 'logs');
const LOG_FILE = path.join(LOG_DIR, 'operation_log.csv');

// ── 1. 抽象化マッピングテーブル ─────────────────────────
//   endpoint        → use_case (レイヤ2) → type (レイヤ3)
const MAP = {
  '/login':  { use_case: 'Login',       type: 'AUTH'   },
  '/logout': { use_case: 'Logout',      type: 'AUTH'   },
  '/browse': { use_case: 'ViewPage',    type: 'READ'   },
  '/edit':   { use_case: 'EditContent', type: 'UPDATE' }
};
// ──────────────────────────────────────────────────────

const app = express();
app.use(bodyParser.json());

// ── 2. ログファイル準備 ───────────────────────────────
if (!fs.existsSync(LOG_DIR))  fs.mkdirSync(LOG_DIR);
if (!fs.existsSync(LOG_FILE)) fs.writeFileSync(
  LOG_FILE,
  'timestamp,user_id,endpoint,use_case,type,jwt_payload,label\n',
  'utf8'
);

const stringify = obj => JSON.stringify(obj).replace(/,/g, ';'); // CSV用にカンマ潰し

function writeLog({
  userId = 'unknown',
  endpoint,
  payload = 'none',
  label = 'unknown'
}) {
  const { use_case = 'unknown', type = 'unknown' } = MAP[endpoint] || {};
  const line = [
    new Date().toISOString(),
    userId,
    endpoint,
    use_case,
    type,
    typeof payload === 'object' ? stringify(payload) : payload,
    label
  ].join(',') + '\n';

  fs.appendFile(LOG_FILE, line, err => {
    if (err) console.error('Log write error:', err);
  });
}

// ── 3. JWT 認証ミドルウェア ───────────────────────────
function auth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    writeLog({ endpoint: req.path, label: 'no_token' });
    return res.status(401).json({ error: 'No token supplied' });
  }
  const token = authHeader.split(' ')[1];
  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) {
      writeLog({ endpoint: req.path, token, label: 'invalid_token' });
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user  = decoded;  // { user_id }
    req.token = token;
    next();
  });
}

// ── 4. エンドポイント実装 ─────────────────────────────
// POST /login : JWT 発行
app.post('/login', (req, res) => {
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: 'user_id is required' });
  const payload = { user_id, iat: Date.now() };
  const token = jwt.sign(payload, SECRET, { expiresIn: '1h' });
  writeLog({ userId: user_id, endpoint: '/login', payload, label: 'normal' });
  res.json({ token });
});

// GET /browse : 認証必須
app.get('/browse', auth, (req, res) => {
  writeLog({
    userId: req.user.user_id,
    endpoint: '/browse',
    payload: req.user,
    label: 'normal'
  });
  res.json({ message: `Welcome, ${req.user.user_id}!` });
});

// POST /edit : 認証必須
app.post('/edit', auth, (req, res) => {
  writeLog({
    userId: req.user.user_id,
    endpoint: '/edit',
    payload: req.user,
    label: 'normal'
  });
  res.json({ message: 'Edit completed (dummy).' });
});

// POST /logout : 認証必須
app.post('/logout', auth, (req, res) => {
  writeLog({
    userId: req.user.user_id,
    endpoint: '/logout',
    payload: req.user,
    label: 'normal'
  });
  res.json({ message: 'Logged out.' });
});

// ── 5. サーバ起動 ────────────────────────────────────
app.listen(PORT, () =>
  console.log(`プレ版サーバ起動 → http://localhost:${PORT}`)
);
