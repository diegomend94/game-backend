// server.js
// Backend de cuentas para tu juego (Express + SQLite + Nodemailer + JWT)

const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const sqlite3 = require('sqlite3').verbose();

dotenv.config();
const app = express();
app.use(express.json());

// ===== CORS (permite SOLO tu Shopify) =====
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || '').split(',').map(s=>s.trim()).filter(Boolean);
app.use(cors({ origin: (origin, cb)=>{
  if(!origin) return cb(null, true);                 // permite herramientas locales (Postman)
  if(ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
  return cb(new Error('Not allowed by CORS: '+origin));
}}));

// ===== Base de datos (SQLite) =====
const DB_PATH = process.env.DATABASE_URL || './choco.db';
const db = new sqlite3.Database(DB_PATH);

// Promesas helper
const run = (sql, params=[]) => new Promise((res, rej)=> db.run(sql, params, function(err){ err?rej(err):res(this); }));
const get = (sql, params=[]) => new Promise((res, rej)=> db.get(sql, params, (err,row)=> err?rej(err):res(row)));
const all = (sql, params=[]) => new Promise((res, rej)=> db.all(sql, params, (err,rows)=> err?rej(err):res(rows)));

// Crear tabla si no existe
db.serialize(()=>{
  db.run(`CREATE TABLE IF NOT EXISTS accounts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    passhash TEXT NOT NULL,
    full_name TEXT,
    birth_date TEXT,             -- YYYY-MM-DD
    is_verified INTEGER NOT NULL DEFAULT 0,
    verify_token TEXT,
    created_at INTEGER NOT NULL
  );`);
});

// ===== Email (Nodemailer) =====
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});

// ===== Validaciones =====
const USER_RE = /^[A-Za-z0-9]{3,15}$/;                                // 3–15, solo letras/números
const PW_RE   = /^(?=.[a-z])(?=.[A-Z])(?=.\d)(?=.[^A-Za-z0-9]).{10,}$/; // 10+, 1 min, 1 may, 1 num, 1 símbolo
const BAD_WORDS = ['fuck','shit','bitch','cunt','asshole'];            // amplía tu lista

function hasInsult(s){ const l=(s||'').toLowerCase(); return BAD_WORDS.some(w=>l.includes(w)); }
function containsFiveSeqFromUsername(password, username){
  const u=(username||'').toLowerCase(), p=(password||'').toLowerCase();
  if(u.length<5) return false;
  for(let i=0;i<=u.length-5;i++){ if(p.includes(u.slice(i, i+5))) return true; }
  return false;
}

async function sendVerificationEmail(toEmail, username, token){
  const base = process.env.PUBLIC_VERIFY_URL || 'https://game-backend.onrender.com';
  const link = ${base.replace(/\/$/,'')}/api/verify?token=${encodeURIComponent(token)};
  const html = `
    <div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu">
      <h2>Confirm your game account</h2>
      <p>Hi ${username}, please verify your account by clicking the link below:</p>
      <p><a href="${link}" style="display:inline-block;padding:10px 16px;border-radius:6px;background:#0a7cff;color:#fff;text-decoration:none">Verify my account</a></p>
      <p>If you didn’t create this account, ignore this email.</p>
    </div>`;
  await transporter.sendMail({
    from: process.env.MAIL_FROM || process.env.SMTP_USER,
    to: toEmail,
    subject: 'Verify your ChocoValley game account',
    html
  });
}

// ===== RUTAS =====

// Salud
app.get('/', (_req,res)=> res.send('Auth API is running.'));

// Registro con verificación por email
app.post('/api/register', async (req,res)=>{
  try{
    const { username, email, password, fullName, birthDate } = req.body || {};

    // Validaciones
    if(!username || !email || !password) return res.json({ success:false, message:'Missing fields' });
    if(!USER_RE.test(username))          return res.json({ success:false, message:'Invalid username (3–15 letters/numbers).' });
    if(hasInsult(username))              return res.json({ success:false, message:'Username not allowed.' });
    if(!PW_RE.test(password))            return res.json({ success:false, message:'Weak password.' });
    if(containsFiveSeqFromUsername(password, username))
      return res.json({ success:false, message:'Password cannot contain 5+ consecutive characters from username.' });

    const passhash = await bcrypt.hash(password, 11);
    const token = crypto.randomBytes(24).toString('hex');
    const now = Date.now();

    await run(
      `INSERT INTO accounts(username,email,passhash,full_name,birth_date,is_verified,verify_token,created_at)
       VALUES(?,?,?,?,?,0,?,?)`,
      [username.trim(), email.trim().toLowerCase(), passhash, (fullName||'').trim(), birthDate || null, token, now]
    );

    await sendVerificationEmail(email.trim(), username.trim(), token);
    return res.json({ success:true, message:'Account created. Check your email to verify.' });
  }catch(e){
    if(String(e).includes('UNIQUE')) return res.json({ success:false, message:'Username or Email already in use.' });
    console.error(e);
    return res.json({ success:false, message:'Server error' });
  }
});

// Enlace de verificación
app.get('/api/verify', async (req,res)=>{
  try{
    const { token } = req.query;
    if(!token) return res.status(400).send('Missing token');
    const row = await get('SELECT id,is_verified FROM accounts WHERE verify_token=?', [token]);
    if(!row) return res.status(400).send('Invalid token');
    if(row.is_verified===1) return res.send(verifyHtml('Your account is already verified. You can login now.'));
    await run('UPDATE accounts SET is_verified=1, verify_token=NULL WHERE id=?', [row.id]);
    return res.send(verifyHtml('Account verified! You can now login in the game.'));
  }catch(err){
    console.error(err); return res.status(500).send('Server error');
  }
});
function verifyHtml(text){
  return <!doctype html><meta charset="utf-8"><div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu;max-width:560px;margin:40px auto"><h2>${text}</h2><p><a href="https://www.chocovalley.ca" style="text-decoration:none;padding:10px 16px;border-radius:6px;background:#0a7cff;color:#fff">Go to website</a></p></div>;
}

// Login (solo verificados)
app.post('/api/login', async (req,res)=>{
  try{
    const { username, password } = req.body || {};
    if(!username || !password) return res.json({ success:false, message:'Missing credentials' });
    const row = await get('SELECT * FROM accounts WHERE username=?', [username.trim()]);
    if(!row) return res.json({ success:false, message:'Invalid credentials' });

    const ok = await bcrypt.compare(password, row.passhash);
    if(!ok) return res.json({ success:false, message:'Invalid credentials' });
    if(row.is_verified!==1) return res.json({ success:false, message:'Please verify your email before login.' });

    const accountId = String(row.id);
    const token = jwt.sign({ sub: accountId, u: row.username }, process.env.JWT_SECRET || 'changeme', { expiresIn: '7d' });
    return res.json({ success:true, token, accountId });
  }catch(e){
    console.error(e); return res.json({ success:false, message:'Server error' });
  }
});

// Validar token (para autologin opcional)
app.get('/api/validate-token', (req,res)=>{
  try{
    const auth = req.headers.authorization || '';
    const t = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if(!t) return res.json({ valid:false });
    const dec = jwt.verify(t, process.env.JWT_SECRET || 'changeme');
    return res.json({ valid:true, accountId: dec.sub, username: dec.u });
  }catch(_){ return res.json({ valid:false }); }
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log('Auth API on http://localhost:'+PORT));