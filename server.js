const express    = require('express');
const multer     = require('multer');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const speakeasy  = require('speakeasy');
const QRCode     = require('qrcode');
const nodemailer = require('nodemailer');
const CryptoJS   = require('crypto-js');
const { v4: uuidv4 } = require('uuid');
const cors       = require('cors');
const fs         = require('fs');
const path       = require('path');
const session    = require('express-session');
const XLSX       = require('xlsx');
const { parse: parseCsv } = require('csv-parse/sync');

const app  = express();
const PORT     = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const JWT_SECRET     = process.env.JWT_SECRET     || 'docuvault-super-secret-jwt-key-2024';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'docuvault-encryption-key-32chars!!';

// Helper — always returns the correct base URL even if env var not set
// Admin can override by setting siteUrl in config via the admin panel
function getSiteUrl() {
  try {
    const cfg = loadConfig();
    if (cfg.siteUrl && cfg.siteUrl.startsWith('http')) return cfg.siteUrl.replace(/\/$/, '');
  } catch(e) {}
  return BASE_URL;
}
const DATA_FILE      = path.join(__dirname, 'data', 'users.json');
const CONFIG_FILE    = path.join(__dirname, 'data', 'config.json');
const UPLOADS_DIR    = path.join(__dirname, 'uploads');
const LOGO_PATH      = path.join(__dirname, 'public', 'logo.png');

let adminSseClients = [];
let customerSseClients = {};   // userId -> [res, res, ...]

fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
fs.mkdirSync(UPLOADS_DIR,                  { recursive: true });

// ─── IP helper — strips IPv6 wrapper from ::ffff:x.x.x.x and normalizes ::1 ─
function getClientIp(req) {
  let raw = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
         || req.ip
         || req.socket?.remoteAddress
         || req.connection?.remoteAddress
         || 'Unknown';
  raw = raw.replace(/^::ffff:/, '');
  if (raw === '::1') raw = '127.0.0.1';   // IPv6 loopback → IPv4 loopback
  return raw;
}

// ─── Config ───────────────────────────────────────────────────────────────
function defaultBranding() {
  return {
    corpName:    'Fast Professional Services Inc.',
    website:     'https://fastprofessional.com',
    email:       'admin@fastprofessional.com',
    phone:       '',
    cell:        '',
    address:     '',
    tagline:     'Secure Client Document Portal',
    welcomeMsg:  'Upload your documents safely and securely.',
    footerText:  '© 2025 Fast Professional Services Inc. All rights reserved.',
    primaryColor:'#1a56db',
    accentColor: '#f59e0b',
    textColor:   '#0f172a',
    bgColor:     '#f8fafc',
  };
}

function loadConfig() {
  if (!fs.existsSync(CONFIG_FILE)) {
    const d = {
      adminEmail:    'wajahat@fastprofessional.com',
      adminPassword: 'Admin@1234',
      siteUrl:       'https://portal.fastpro.tax',
      smtp: { host:'smtp-relay.brevo.com', port:587, user:'admin@fastpro.tax', pass:'' },
      branding: defaultBranding(),
      autoDeleteHours: 72,
      agreementText: fs.existsSync(path.join(__dirname,'data','agreement_backup.txt'))
        ? fs.readFileSync(path.join(__dirname,'data','agreement_backup.txt'),'utf8')
        : 'Agreement text not set. Please configure in Admin → Settings.'
    };
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(d, null, 2));
    return d;
  }
  const cfg = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  if (!cfg.branding) cfg.branding = defaultBranding();
  if (cfg.autoDeleteHours === undefined) cfg.autoDeleteHours = 72;
  // Always ensure siteUrl is set — never fall back to localhost in production
  if (!cfg.siteUrl || cfg.siteUrl.includes('localhost')) cfg.siteUrl = 'https://portal.fastpro.tax';
  return cfg;
}
function saveConfig(cfg) { fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2)); }

// ─── Admin accounts ───────────────────────────────────────────────────────
const ADMINS_FILE = path.join(__dirname, 'data', 'admins.json');

// Roles:
//   super_admin   — full access to everything, including managing other admins and branding/colors
//   admin         — full access EXCEPT changing color scheme (branding colors)
//   limited_admin — can only: view/download documents, send messages, manage document checklist/requests
const ROLE_LABELS = { super_admin:'Super Admin', admin:'Admin', limited_admin:'Limited Admin' };

async function loadAdmins() {
  if (!fs.existsSync(ADMINS_FILE)) {
    // Bootstrap: migrate the old single adminPassword (if any) into a Super Admin account
    const cfg = loadConfig();
    const hashedPw = await bcrypt.hash(cfg.adminPassword || 'Admin@1234', 12);
    const admins = {
      'super-admin-default': {
        id: 'super-admin-default',
        name: 'Super Admin',
        password: hashedPw,
        role: 'super_admin',
        createdAt: new Date().toISOString(),
        active: true
      }
    };
    fs.writeFileSync(ADMINS_FILE, JSON.stringify(admins, null, 2));
    return admins;
  }
  try { return JSON.parse(fs.readFileSync(ADMINS_FILE, 'utf8')); } catch { return {}; }
}
function saveAdmins(a) { fs.writeFileSync(ADMINS_FILE, JSON.stringify(a, null, 2)); }

// Permission checks per role
function canManageAdmins(role)   { return role === 'super_admin'; }
function canEditBranding(role)   { return role === 'super_admin'; }   // colors + company info reserved for Super Admin
function canEditColors(role)     { return role === 'super_admin'; }
function canEditAgreement(role)  { return role === 'super_admin' || role === 'admin'; }
function canEditEmailConfig(role){ return role === 'super_admin' || role === 'admin'; }
function canManageClients(role)  { return role === 'super_admin' || role === 'admin'; }   // create/invite/remove clients
function canDeleteDocuments(role){ return role === 'super_admin' || role === 'admin'; }
function canViewAuditLog(role)   { return role === 'super_admin' || role === 'admin'; }
// All roles (including limited_admin) can: view/download documents, message clients, manage checklist/requests, set doc status

// ─── Document category presets ─────────────────────────────────────────────
const DOC_CATEGORIES = [
  'Government ID', 'Social Security / ITIN', 'Tax Return', 'W-2', '1099',
  'Bank Statement', 'Pay Stub', 'Proof of Address', 'Insurance Document',
  'Business License', 'Financial Statement', 'Others'
];

// ─── Audit log ──────────────────────────────────────────────────────────────
const AUDIT_FILE = path.join(__dirname, 'data', 'audit_log.json');
function loadAudit() {
  if (!fs.existsSync(AUDIT_FILE)) return [];
  try { return JSON.parse(fs.readFileSync(AUDIT_FILE, 'utf8')); } catch { return []; }
}
function logAudit(entry) {
  const log = loadAudit();
  log.unshift({ id: uuidv4(), at: new Date().toISOString(), ...entry });
  // Keep the most recent 5000 entries so the file doesn't grow forever
  if (log.length > 5000) log.length = 5000;
  fs.writeFileSync(AUDIT_FILE, JSON.stringify(log, null, 2));
}

// ─── Auto-delete old documents ──────────────────────────────────────────────
// Runs periodically; deletes documents (file + record) older than cfg.autoDeleteHours.
// Set autoDeleteHours to 0 in config to disable entirely.
function runAutoDeleteSweep() {
  const cfg = loadConfig();
  const hours = cfg.autoDeleteHours;
  if (!hours || hours <= 0) return;   // disabled

  const cutoff = Date.now() - hours*60*60*1000;
  const users = loadUsers();
  let totalDeleted = 0;

  Object.values(users).forEach(user => {
    if (!user.documents || !user.documents.length) return;
    const keep = [];
    user.documents.forEach(doc => {
      const uploadedAt = new Date(doc.uploadedAt).getTime();
      if (uploadedAt <= cutoff) {
        const fp = path.join(UPLOADS_DIR, user.folderName, doc.storedName);
        if (fs.existsSync(fp)) { try { fs.unlinkSync(fp); } catch(e) { console.error('Auto-delete failed:', e.message); } }
        totalDeleted++;
        logAudit({ userId:user.id, customerName:`${user.firstName} ${user.lastName}`, actor:'system', action:'document_auto_deleted', detail:`${doc.originalName} (uploaded ${doc.uploadedAt}, retention: ${hours}h)` });
      } else {
        keep.push(doc);
      }
    });
    if (keep.length !== user.documents.length) user.documents = keep;
  });

  if (totalDeleted > 0) {
    saveUsers(users);
    console.log(`🧹 Auto-delete sweep: removed ${totalDeleted} document(s) older than ${hours}h`);
    pushAdmin({ type:'auto_delete', count: totalDeleted, hours });
  }
}

// ─── Users ────────────────────────────────────────────────────────────────
function loadUsers() {
  if (!fs.existsSync(DATA_FILE)) return {};
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch { return {}; }
}
function saveUsers(u) { fs.writeFileSync(DATA_FILE, JSON.stringify(u, null, 2)); }

// ─── Email ────────────────────────────────────────────────────────────────
// ─── Email via Brevo HTTP API (bypasses GoDaddy SMTP port blocking) ──────────
// Falls back to nodemailer SMTP if brevo API key not detected
async function sendMail(to, subject, html) {
  const cfg = loadConfig();
  if (!cfg.smtp?.pass) return { success:false, error:'Email not configured' };

  const isBrevo = cfg.smtp.host && cfg.smtp.host.includes('brevo');

  if (isBrevo) {
    // Use Brevo HTTP API on port 443 — GoDaddy cannot block this
    // Brevo API key is stored in cfg.smtp.apiKey (set from admin panel)
    // Falls back to cfg.smtp.pass if apiKey not set
    const apiKey = cfg.smtp.apiKey || cfg.smtp.pass;
    try {
      const https = require('https');
      const body = JSON.stringify({
        sender: { name: cfg.branding.corpName, email: cfg.smtp.user },
        to: [{ email: to }],
        subject,
        htmlContent: html
      });
      return await new Promise((resolve) => {
        const req = https.request({
          hostname: 'api.brevo.com',
          port: 443,
          path: '/v3/smtp/email',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'api-key': apiKey,
            'Content-Length': Buffer.byteLength(body)
          }
        }, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            if (res.statusCode >= 200 && res.statusCode < 300) {
              console.log(`✅ Email sent via Brevo API → ${to}`);
              resolve({ success:true });
            } else {
              console.error('❌ Brevo API error:', res.statusCode, data);
              resolve({ success:false, error:`Brevo API error ${res.statusCode}: ${data}` });
            }
          });
        });
        req.on('error', e => { console.error('❌ Brevo request error:', e.message); resolve({ success:false, error:e.message }); });
        req.write(body);
        req.end();
      });
    } catch(e) {
      console.error('❌ Brevo error:', e.message);
      return { success:false, error:e.message };
    }
  }

  // Standard SMTP fallback (for non-Brevo servers)
  try {
    const nodemailer = require('nodemailer');
    const t = nodemailer.createTransport({
      host: cfg.smtp.host, port: cfg.smtp.port,
      secure: cfg.smtp.port === 465,
      auth: { user: cfg.smtp.user, pass: cfg.smtp.pass },
      tls: { rejectUnauthorized: false }
    });
    await t.verify();
    await t.sendMail({ from:`"${cfg.branding.corpName}" <${cfg.smtp.user}>`, to, subject, html });
    console.log(`✅ Email → ${to}: ${subject}`);
    return { success:true };
  } catch(e) {
    console.error('❌ Email error:', e.message);
    return { success:false, error:e.message };
  }
}

function emailWrap(content) {
  const cfg = loadConfig();
  const b   = cfg.branding;
  return `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;">
    <div style="background:${b.primaryColor};padding:20px 28px;">
      <h1 style="color:white;margin:0;font-size:20px;font-weight:700;">${b.corpName}</h1>
      <p style="color:rgba(255,255,255,.7);margin:4px 0 0;font-size:12px;">${b.tagline}</p>
    </div>
    <div style="padding:28px;">${content}</div>
    <div style="padding:14px 28px;background:#f9fafb;border-top:1px solid #e5e7eb;font-size:12px;color:#9ca3af;">
      ${b.corpName} &nbsp;|&nbsp; ${b.website} &nbsp;|&nbsp; ${b.email}
      ${b.phone ? '&nbsp;|&nbsp; '+b.phone : ''}
    </div>
  </div>`;
}

async function sendInvitationEmail(user) {
  const cfg  = loadConfig();
  const b    = cfg.branding;
  const link = `${getSiteUrl()}/accept.html?token=${user.inviteToken}`;
  const html = emailWrap(`
    <h2 style="color:${b.primaryColor};margin:0 0 8px;">You've been invited to our Secure Client Portal</h2>
    <p style="color:#374151;margin:0 0 16px;">Hello <strong>${user.firstName}</strong>,</p>
    <p style="color:#374151;margin:0 0 16px;">
      <strong>${b.corpName}</strong> has created a secure document vault for you.
      Please click the button below to review and accept your client agreement, then set your password.
    </p>
    <div style="background:#fff8e1;border-left:4px solid ${b.accentColor};padding:12px 16px;border-radius:6px;margin:0 0 22px;">
      <strong style="color:#92400e;">⏰ This invitation expires in 48 hours.</strong>
    </div>
    <a href="${link}" style="display:inline-block;background:${b.primaryColor};color:white;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:600;font-size:15px;">
      Review &amp; Accept Agreement →
    </a>
    <p style="color:#9ca3af;font-size:12px;margin:20px 0 0;">Or copy this link:<br/><span style="color:${b.primaryColor};">${link}</span></p>
  `);
  return sendMail(user.email, `Your Secure Portal Invitation — ${b.corpName}`, html);
}

async function sendPasswordResetEmail(user) {
  const cfg  = loadConfig();
  const b    = cfg.branding;
  const link = `${getSiteUrl()}/reset-password.html?token=${user.resetToken}`;
  const html = emailWrap(`
    <h2 style="color:${b.primaryColor};margin:0 0 8px;">Reset Your Password</h2>
    <p style="color:#374151;margin:0 0 16px;">Hello <strong>${user.firstName}</strong>,</p>
    <p style="color:#374151;margin:0 0 16px;">
      We received a request to reset the password for your <strong>${b.corpName}</strong> secure portal account.
      Click the button below to choose a new password.
    </p>
    <div style="background:#fff8e1;border-left:4px solid ${b.accentColor};padding:12px 16px;border-radius:6px;margin:0 0 22px;">
      <strong style="color:#92400e;">⏰ This link expires in 1 hour.</strong>
    </div>
    <a href="${link}" style="display:inline-block;background:${b.primaryColor};color:white;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:600;font-size:15px;">
      Reset My Password →
    </a>
    <p style="color:#9ca3af;font-size:12px;margin:20px 0 0;">Or copy this link:<br/><span style="color:${b.primaryColor};">${link}</span></p>
    <p style="color:#9ca3af;font-size:12px;margin:16px 0 0;">If you didn't request this, you can safely ignore this email — your password will not be changed.</p>
  `);
  return sendMail(user.email, `Reset Your Password — ${b.corpName}`, html);
}

async function sendUploadNotification(user, fileName, uploadIp) {
  const cfg = loadConfig();
  const b   = cfg.branding;
  const html = emailWrap(`
    <h2 style="color:${b.primaryColor};margin:0 0 16px;">New Document Uploaded</h2>
    <table style="width:100%;border-collapse:collapse;background:#f9fafb;border-radius:8px;overflow:hidden;">
      <tr style="border-bottom:1px solid #e5e7eb;"><td style="padding:10px 14px;color:#6b7280;font-weight:600;width:130px;">Client Name</td><td style="padding:10px 14px;color:#111827;">${user.firstName} ${user.lastName}</td></tr>
      <tr style="border-bottom:1px solid #e5e7eb;"><td style="padding:10px 14px;color:#6b7280;font-weight:600;">Email</td><td style="padding:10px 14px;color:#111827;">${user.email}</td></tr>
      <tr style="border-bottom:1px solid #e5e7eb;"><td style="padding:10px 14px;color:#6b7280;font-weight:600;">Folder</td><td style="padding:10px 14px;color:#111827;font-family:monospace;">${user.folderName}</td></tr>
      <tr style="border-bottom:1px solid #e5e7eb;"><td style="padding:10px 14px;color:#6b7280;font-weight:600;">File</td><td style="padding:10px 14px;color:${b.primaryColor};font-weight:600;">📄 ${fileName}</td></tr>
      <tr style="border-bottom:1px solid #e5e7eb;"><td style="padding:10px 14px;color:#6b7280;font-weight:600;">Uploaded At</td><td style="padding:10px 14px;color:#111827;">${new Date().toLocaleString('en-GB')}</td></tr>
      <tr><td style="padding:10px 14px;color:#6b7280;font-weight:600;">Upload IP</td><td style="padding:10px 14px;color:#111827;font-family:monospace;">${uploadIp}</td></tr>
    </table>
    <p style="margin-top:18px;padding:12px 14px;background:#eff4ff;border-radius:8px;color:${b.primaryColor};font-size:13px;">
      Log in to the admin panel to review: <strong>${getSiteUrl()}/admin.html</strong>
    </p>
  `);
  return sendMail(cfg.adminEmail, `New Upload — ${user.firstName} ${user.lastName} — ${fileName}`, html);
}

async function sendMessageNotification(user, messageText, fromAdmin) {
  const cfg = loadConfig();
  const b   = cfg.branding;
  const html = emailWrap(`
    <h2 style="color:${b.primaryColor};margin:0 0 14px;">${fromAdmin ? 'New Message from ' + b.corpName : 'New Message from ' + user.firstName + ' ' + user.lastName}</h2>
    <div style="background:#f9fafb;border-left:4px solid ${b.primaryColor};padding:14px 18px;border-radius:6px;margin:0 0 20px;color:#374151;font-size:14px;line-height:1.6;">
      ${esc(messageText).replace(/\n/g,'<br/>')}
    </div>
    <p style="margin-top:18px;padding:12px 14px;background:#eff4ff;border-radius:8px;color:${b.primaryColor};font-size:13px;">
      ${fromAdmin
        ? `Log in to your secure portal to view and reply: <strong>${getSiteUrl()}</strong>`
        : `Log in to the admin panel to view and reply: <strong>${getSiteUrl()}/admin.html</strong>`}
    </p>
  `);
  const to = fromAdmin ? user.email : cfg.adminEmail;
  const subject = fromAdmin ? `New Message from ${b.corpName}` : `New Message from ${user.firstName} ${user.lastName}`;
  return sendMail(to, subject, html);
}
function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// ─── SSE push ─────────────────────────────────────────────────────────────
function pushAdmin(data) {
  const payload = `data: ${JSON.stringify(data)}\n\n`;
  adminSseClients = adminSseClients.filter(r => { try { r.write(payload); return true; } catch { return false; } });
}
function pushCustomer(userId, data) {
  const payload = `data: ${JSON.stringify(data)}\n\n`;
  const clients = customerSseClients[userId] || [];
  customerSseClients[userId] = clients.filter(r => { try { r.write(payload); return true; } catch { return false; } });
}

// ─── Middleware ───────────────────────────────────────────────────────────
app.set('trust proxy', true);   // ← must be set before routes/middleware that read req.ip
app.use(cors());
app.use(express.json({ limit:'10mb' }));
app.use(express.urlencoded({ extended:true, limit:'10mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({ secret:'dv-sess-secret', resave:false, saveUninitialized:false }));

function requireAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error:'Not authenticated' });
  try {
    const d = jwt.verify(token, JWT_SECRET);
    req.userId    = d.userId;
    req.isAdmin   = d.isAdmin || false;
    req.adminId   = d.adminId || null;
    req.adminName = d.adminName || null;
    req.adminRole = d.role || null;
    next();
  } catch { res.status(401).json({ error:'Session expired' }); }
}
function requireAdmin(req, res, next) {
  if (!req.isAdmin) return res.status(403).json({ error:'Admin only' });
  next();
}
function requireRole(checkFn) {
  return (req, res, next) => {
    if (!req.isAdmin) return res.status(403).json({ error:'Admin only' });
    if (!checkFn(req.adminRole)) return res.status(403).json({ error:'You do not have permission to perform this action.' });
    next();
  };
}

// ─── Multer ───────────────────────────────────────────────────────────────
const docStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const users  = loadUsers();
    const user   = users[req.userId];
    const folder = path.join(UPLOADS_DIR, user ? user.folderName : req.userId);
    fs.mkdirSync(folder, { recursive:true });
    cb(null, folder);
  },
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload     = multer({ storage: docStorage, limits:{ fileSize: 50*1024*1024 } });
const logoUpload = multer({ dest: path.join(__dirname,'public'), limits:{ fileSize: 2*1024*1024 } });
const importUpload = multer({ storage: multer.memoryStorage(), limits:{ fileSize: 5*1024*1024 } });

// ══════════════════════════════════════════════════════════
//  PUBLIC — BRANDING (used by all pages on load)
// ══════════════════════════════════════════════════════════
app.get('/api/branding', (req, res) => {
  const cfg = loadConfig();
  res.json(cfg.branding || defaultBranding());
});

app.get('/api/doc-categories', (req, res) => {
  res.json({ categories: DOC_CATEGORIES });
});

// ══════════════════════════════════════════════════════════
//  PUBLIC — INVITATION FLOW
// ══════════════════════════════════════════════════════════
app.get('/api/invite/:token', (req, res) => {
  const users = loadUsers();
  const user  = Object.values(users).find(u => u.inviteToken === req.params.token);
  if (!user)                     return res.status(404).json({ error:'Invitation not found or already used.' });
  if (user.status === 'active')  return res.status(400).json({ error:'This invitation has already been accepted.' });
  if (new Date() > new Date(user.inviteExpires))
    return res.status(410).json({ error:'This invitation link has expired. Please contact us for a new one.' });
  const cfg = loadConfig();
  res.json({ firstName:user.firstName, lastName:user.lastName, email:user.email, agreementText:cfg.agreementText });
});

app.post('/api/invite/:token/accept', async (req, res) => {
  const { password } = req.body;
  if (!password)                           return res.status(400).json({ error:'Password is required.' });
  if (password.length < 8)                 return res.status(400).json({ error:'Password must be at least 8 characters.' });
  if (!/[0-9]/.test(password))             return res.status(400).json({ error:'Password must contain at least one number.' });
  if (!/[^A-Za-z0-9]/.test(password))     return res.status(400).json({ error:'Password must contain at least one special character.' });

  const users = loadUsers();
  const user  = Object.values(users).find(u => u.inviteToken === req.params.token);
  if (!user)                               return res.status(404).json({ error:'Invalid invitation.' });
  if (user.status === 'active')            return res.status(400).json({ error:'Already accepted.' });
  if (new Date() > new Date(user.inviteExpires)) return res.status(410).json({ error:'Invitation expired.' });

  const secret = speakeasy.generateSecret({ name:`${loadConfig().branding.corpName} (${user.email})` });
  users[user.id].password          = await bcrypt.hash(password, 12);
  users[user.id].twoFactorSecret   = secret.base32;
  users[user.id].twoFactorEnabled  = false;
  users[user.id].status            = 'pending_2fa';
  users[user.id].agreementAccepted = new Date().toISOString();
  users[user.id].agreementIp       = getClientIp(req);   // ← fixed IP
  users[user.id].inviteToken       = null;
  saveUsers(users);
  logAudit({ userId:user.id, customerName:`${user.firstName} ${user.lastName}`, actor:'customer', action:'agreement_accepted', detail:'Client agreement accepted', ip:users[user.id].agreementIp });
  res.json({ success:true, userId: user.id, qrCode: await QRCode.toDataURL(secret.otpauth_url) });
});

app.post('/api/invite/verify-2fa', (req, res) => {
  const { userId, token } = req.body;
  const users = loadUsers();
  const user  = users[userId];
  if (!user) return res.status(404).json({ error:'User not found.' });
  const ok = speakeasy.totp.verify({ secret:user.twoFactorSecret, encoding:'base32', token, window:2 });
  if (!ok) return res.status(400).json({ error:'Invalid code. Try again.' });
  users[userId].twoFactorEnabled = true;
  users[userId].status = 'active';
  saveUsers(users);
  res.json({ success:true });
});

// ══════════════════════════════════════════════════════════
//  CUSTOMER ROUTES
// ══════════════════════════════════════════════════════════
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const users = loadUsers();
  const user  = Object.values(users).find(u => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.password || ''))) {
    logAudit({ userId:user?.id||null, customerName:user?`${user.firstName} ${user.lastName}`:email, actor:'customer', action:'login_failed', detail:'Invalid credentials', ip:getClientIp(req) });
    return res.status(401).json({ error:'Invalid email or password.' });
  }
  if (user.status !== 'active')
    return res.status(403).json({ error:'Account not yet activated. Please complete your invitation.' });
  res.json({ success:true, userId:user.id, requires2FA:user.twoFactorEnabled });
});

app.post('/api/login-2fa', (req, res) => {
  const { userId, token } = req.body;
  const users = loadUsers();
  const user  = users[userId];
  if (!user) return res.status(404).json({ error:'User not found.' });
  const ok = speakeasy.totp.verify({ secret:user.twoFactorSecret, encoding:'base32', token, window:2 });
  if (!ok) {
    logAudit({ userId, customerName:`${user.firstName} ${user.lastName}`, actor:'customer', action:'login_2fa_failed', detail:'Invalid 2FA code', ip:getClientIp(req) });
    return res.status(400).json({ error:'Invalid 2FA code.' });
  }
  const jwtToken = jwt.sign({ userId:user.id, email:user.email, name:`${user.firstName} ${user.lastName}`, isAdmin:false }, JWT_SECRET, { expiresIn:'8h' });
  logAudit({ userId, customerName:`${user.firstName} ${user.lastName}`, actor:'customer', action:'login_success', detail:'Logged in', ip:getClientIp(req) });
  res.json({ success:true, token:jwtToken, name:`${user.firstName} ${user.lastName}`, email:user.email });
});

// ══════════════════════════════════════════════════════════
//  PASSWORD RESET — self-service, customer accounts only
// ══════════════════════════════════════════════════════════
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error:'Email is required.' });
  const users = loadUsers();
  const user  = Object.values(users).find(u => u.email === email && u.status === 'active');
  if (user) {
    users[user.id].resetToken   = uuidv4();
    users[user.id].resetExpires = new Date(Date.now()+60*60*1000).toISOString(); // 1 hour
    saveUsers(users);
    await sendPasswordResetEmail(users[user.id]);
    logAudit({ userId:user.id, customerName:`${user.firstName} ${user.lastName}`, actor:'customer', action:'password_reset_requested', detail:'Password reset email sent', ip:getClientIp(req) });
  }
  // Always the same response, whether or not the email exists — avoids leaking which emails are registered.
  res.json({ success:true });
});

app.get('/api/reset-password/:token', (req, res) => {
  const users = loadUsers();
  const user  = Object.values(users).find(u => u.resetToken === req.params.token);
  if (!user) return res.status(404).json({ error:'This link is invalid or has already been used.' });
  if (new Date() > new Date(user.resetExpires))
    return res.status(410).json({ error:'This link has expired. Please request a new one.' });
  res.json({ firstName:user.firstName, lastName:user.lastName });
});

app.post('/api/reset-password/:token', async (req, res) => {
  const { password } = req.body;
  if (!password)                       return res.status(400).json({ error:'Password is required.' });
  if (password.length < 8)             return res.status(400).json({ error:'Password must be at least 8 characters.' });
  if (!/[0-9]/.test(password))         return res.status(400).json({ error:'Password must contain at least one number.' });
  if (!/[^A-Za-z0-9]/.test(password)) return res.status(400).json({ error:'Password must contain at least one special character.' });

  const users = loadUsers();
  const user  = Object.values(users).find(u => u.resetToken === req.params.token);
  if (!user) return res.status(404).json({ error:'This link is invalid or has already been used.' });
  if (new Date() > new Date(user.resetExpires))
    return res.status(410).json({ error:'This link has expired. Please request a new one.' });

  users[user.id].password     = await bcrypt.hash(password, 12);
  users[user.id].resetToken   = null;
  users[user.id].resetExpires = null;
  saveUsers(users);
  logAudit({ userId:user.id, customerName:`${user.firstName} ${user.lastName}`, actor:'customer', action:'password_reset_completed', detail:'Password reset via email link', ip:getClientIp(req) });
  res.json({ success:true });
});

app.post('/api/upload', requireAuth, upload.single('document'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error:'No file uploaded.' });
  const users    = loadUsers();
  const user     = users[req.userId];
  if (!user)     return res.status(404).json({ error:'User not found.' });
  const uploadIp = getClientIp(req);
  const category = (req.body.category && DOC_CATEGORIES.includes(req.body.category)) ? req.body.category : 'Others';
  const checklistItemId = req.body.checklistItemId || null;   // optional link to a requested item

  // Versioning: if a checklist item or matching category+name already has documents, link as a new version
  const existingForName = (user.documents||[]).filter(d => d.originalName === req.file.originalname);
  const versionGroupId  = existingForName.length ? (existingForName[0].versionGroupId || existingForName[0].id) : uuidv4();
  const versionNumber   = existingForName.length + 1;

  const docRecord = {
    id: uuidv4(),
    originalName:  req.file.originalname,
    encryptedName: CryptoJS.AES.encrypt(req.file.originalname, ENCRYPTION_KEY).toString(),
    storedName:    req.file.filename,
    size:          req.file.size,
    mimetype:      req.file.mimetype,
    uploadedAt:    new Date().toISOString(),
    uploadIp,
    category,
    checklistItemId,
    versionGroupId,
    versionNumber,
    status: 'pending',          // pending | reviewed | needs_resubmission
    statusNote: '',
    statusUpdatedAt: null
  };
  users[req.userId].documents.push(docRecord);

  // If this upload fulfills a checklist item, mark it received
  if (checklistItemId && users[req.userId].checklist) {
    const item = users[req.userId].checklist.find(c => c.id === checklistItemId);
    if (item) { item.status = 'received'; item.receivedDocId = docRecord.id; }
  }
  saveUsers(users);

  logAudit({ userId:req.userId, customerName:`${user.firstName} ${user.lastName}`, actor:'customer', action:'document_uploaded', detail:`${req.file.originalname} (${category})${versionNumber>1?' — v'+versionNumber:''}`, ip:uploadIp });

  sendUploadNotification(user, req.file.originalname, uploadIp);
  pushAdmin({ type:'upload', customerName:`${user.firstName} ${user.lastName}`, customerEmail:user.email, fileName:req.file.originalname, fileSize:req.file.size, uploadedAt:docRecord.uploadedAt, uploadIp });
  res.json({ success:true, document:docRecord });
});

app.get('/api/documents', requireAuth, (req, res) => {
  const users = loadUsers();
  const user  = users[req.userId];
  if (!user) return res.status(404).json({ error:'User not found.' });
  res.json({ documents: user.documents||[], checklist: user.checklist||[], name:`${user.firstName} ${user.lastName}` });
});

app.delete('/api/documents/:docId', requireAuth, (req, res) => {
  const users = loadUsers();
  const user  = users[req.userId];
  const doc   = (user.documents||[]).find(d => d.id === req.params.docId);
  if (!doc) return res.status(404).json({ error:'Not found.' });
  const fp = path.join(UPLOADS_DIR, user.folderName, doc.storedName);
  if (fs.existsSync(fp)) fs.unlinkSync(fp);
  users[req.userId].documents = user.documents.filter(d => d.id !== req.params.docId);
  saveUsers(users);
  logAudit({ userId:req.userId, customerName:`${user.firstName} ${user.lastName}`, actor:'customer', action:'document_deleted', detail:doc.originalName, ip:getClientIp(req) });
  res.json({ success:true });
});

// ══════════════════════════════════════════════════════════
//  MESSAGING — customer side
// ══════════════════════════════════════════════════════════

// Customer's live message stream (so they see admin messages instantly)
app.get('/api/messages/events', (req, res) => {
  const token = req.query.token;
  let userId;
  try { const d = jwt.verify(token, JWT_SECRET); if (d.isAdmin) throw 0; userId = d.userId; }
  catch { return res.status(401).end(); }
  res.setHeader('Content-Type','text/event-stream');
  res.setHeader('Cache-Control','no-cache');
  res.setHeader('Connection','keep-alive');
  res.flushHeaders();
  const hb = setInterval(() => { try { res.write('data:{"type":"ping"}\n\n'); } catch { clearInterval(hb); } }, 25000);
  if (!customerSseClients[userId]) customerSseClients[userId] = [];
  customerSseClients[userId].push(res);
  req.on('close', () => { clearInterval(hb); customerSseClients[userId] = (customerSseClients[userId]||[]).filter(c=>c!==res); });
});

// Get my message thread
app.get('/api/messages', requireAuth, (req, res) => {
  if (req.isAdmin) return res.status(403).json({ error:'Use /api/admin/messages/:userId instead.' });
  const users = loadUsers();
  const user  = users[req.userId];
  if (!user) return res.status(404).json({ error:'User not found.' });
  const msgs = user.messages || [];
  // mark admin messages as read by customer
  let changed = false;
  msgs.forEach(m => { if (m.from === 'admin' && !m.readByCustomer) { m.readByCustomer = true; changed = true; } });
  if (changed) saveUsers(users);
  res.json({ messages: msgs });
});

// Customer sends a message to admin
app.post('/api/messages', requireAuth, async (req, res) => {
  if (req.isAdmin) return res.status(403).json({ error:'Use /api/admin/messages/:userId instead.' });
  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error:'Message cannot be empty.' });
  const users = loadUsers();
  const user  = users[req.userId];
  if (!user) return res.status(404).json({ error:'User not found.' });
  if (!user.messages) user.messages = [];
  const msg = { id: uuidv4(), from:'customer', text: text.trim(), sentAt: new Date().toISOString(), readByAdmin:false, readByCustomer:true };
  user.messages.push(msg);
  saveUsers(users);

  sendMessageNotification(user, text.trim(), false);
  pushAdmin({ type:'message', customerId:user.id, customerName:`${user.firstName} ${user.lastName}`, customerEmail:user.email, text: text.trim(), sentAt: msg.sentAt });

  res.json({ success:true, message: msg });
});

// ══════════════════════════════════════════════════════════
//  MESSAGING — admin side
// ══════════════════════════════════════════════════════════

// Get message thread for a specific customer (admin)
app.get('/api/admin/messages/:userId', requireAuth, requireAdmin, (req, res) => {
  const users = loadUsers();
  const user  = users[req.params.userId];
  if (!user) return res.status(404).json({ error:'Customer not found.' });
  const msgs = user.messages || [];
  let changed = false;
  msgs.forEach(m => { if (m.from === 'customer' && !m.readByAdmin) { m.readByAdmin = true; changed = true; } });
  if (changed) saveUsers(users);
  res.json({ messages: msgs, customerName:`${user.firstName} ${user.lastName}`, customerEmail:user.email });
});

// Admin sends a message to a customer
app.post('/api/admin/messages/:userId', requireAuth, requireAdmin, async (req, res) => {
  const { text } = req.body;
  if (!text || !text.trim()) return res.status(400).json({ error:'Message cannot be empty.' });
  const users = loadUsers();
  const user  = users[req.params.userId];
  if (!user) return res.status(404).json({ error:'Customer not found.' });
  if (!user.messages) user.messages = [];
  const msg = { id: uuidv4(), from:'admin', text: text.trim(), sentAt: new Date().toISOString(), readByAdmin:true, readByCustomer:false };
  user.messages.push(msg);
  saveUsers(users);

  sendMessageNotification(user, text.trim(), true);
  pushCustomer(user.id, { type:'message', text: text.trim(), sentAt: msg.sentAt });

  res.json({ success:true, message: msg });
});

// Quick-send "documents received" templated message
app.post('/api/admin/messages/:userId/quick-received', requireAuth, requireAdmin, async (req, res) => {
  const users = loadUsers();
  const user  = users[req.params.userId];
  if (!user) return res.status(404).json({ error:'Customer not found.' });
  const { docNames } = req.body;   // optional array of doc names to mention
  const text = docNames && docNames.length
    ? `We have received your document(s): ${docNames.join(', ')}. Thank you — our team will review them shortly.`
    : `We have received your document(s). Thank you — our team will review them shortly.`;
  if (!user.messages) user.messages = [];
  const msg = { id: uuidv4(), from:'admin', text, sentAt: new Date().toISOString(), readByAdmin:true, readByCustomer:false };
  user.messages.push(msg);
  saveUsers(users);

  sendMessageNotification(user, text, true);
  pushCustomer(user.id, { type:'message', text, sentAt: msg.sentAt });

  res.json({ success:true, message: msg });
});

// Unread counts for all customers (for admin badge)
app.get('/api/admin/messages-summary', requireAuth, requireAdmin, (req, res) => {
  const users = loadUsers();
  const summary = {};
  Object.values(users).forEach(u => {
    const unread = (u.messages||[]).filter(m => m.from==='customer' && !m.readByAdmin).length;
    if (unread > 0) summary[u.id] = unread;
  });
  res.json({ summary });
});

// ══════════════════════════════════════════════════════════
//  CHECKLIST — requested documents (all optional, never blocking)
// ══════════════════════════════════════════════════════════

// Admin: add a checklist item for a client (preset or custom label)
app.post('/api/admin/customers/:userId/checklist', requireAuth, requireAdmin, (req, res) => {
  const { label, category } = req.body;
  if (!label || !label.trim()) return res.status(400).json({ error:'A label is required.' });
  const users = loadUsers();
  const user  = users[req.params.userId];
  if (!user) return res.status(404).json({ error:'Customer not found.' });
  if (!user.checklist) user.checklist = [];
  const item = { id:uuidv4(), label:label.trim(), category: category||'Others', status:'requested', receivedDocId:null, addedAt:new Date().toISOString() };
  user.checklist.push(item);
  saveUsers(users);
  logAudit({ userId:user.id, customerName:`${user.firstName} ${user.lastName}`, actor:'admin', action:'checklist_item_added', detail:item.label });
  res.json({ success:true, item });
});

// Admin: remove a checklist item (it's just a suggestion, can be removed anytime — non-blocking)
app.delete('/api/admin/customers/:userId/checklist/:itemId', requireAuth, requireAdmin, (req, res) => {
  const users = loadUsers();
  const user  = users[req.params.userId];
  if (!user) return res.status(404).json({ error:'Customer not found.' });
  user.checklist = (user.checklist||[]).filter(c => c.id !== req.params.itemId);
  saveUsers(users);
  res.json({ success:true });
});

// Admin: mark a checklist item as waived/not needed (still never blocking — purely informational)
app.post('/api/admin/customers/:userId/checklist/:itemId/waive', requireAuth, requireAdmin, (req, res) => {
  const users = loadUsers();
  const user  = users[req.params.userId];
  if (!user) return res.status(404).json({ error:'Customer not found.' });
  const item = (user.checklist||[]).find(c => c.id === req.params.itemId);
  if (!item) return res.status(404).json({ error:'Item not found.' });
  item.status = 'waived';
  saveUsers(users);
  res.json({ success:true });
});

// ══════════════════════════════════════════════════════════
//  DOCUMENT STATUS FLAGS — visible to both admin and client
// ══════════════════════════════════════════════════════════
app.post('/api/admin/customers/:userId/documents/:docId/status', requireAuth, requireAdmin, async (req, res) => {
  const { status, note } = req.body;   // status: pending | reviewed | needs_resubmission
  if (!['pending','reviewed','needs_resubmission'].includes(status))
    return res.status(400).json({ error:'Invalid status.' });
  const users = loadUsers();
  const user  = users[req.params.userId];
  if (!user) return res.status(404).json({ error:'Customer not found.' });
  const doc = (user.documents||[]).find(d => d.id === req.params.docId);
  if (!doc) return res.status(404).json({ error:'Document not found.' });
  doc.status = status;
  doc.statusNote = note || '';
  doc.statusUpdatedAt = new Date().toISOString();
  saveUsers(users);

  logAudit({ userId:user.id, customerName:`${user.firstName} ${user.lastName}`, actor:'admin', action:'document_status_changed', detail:`${doc.originalName} → ${status}${note?' ('+note+')':''}` });

  const statusLabel = status==='reviewed' ? 'Reviewed ✅' : status==='needs_resubmission' ? 'Needs Resubmission ⚠️' : 'Pending Review';
  const msgText = `Document update: "${doc.originalName}" is now marked as ${statusLabel}.${note ? ' Note: '+note : ''}`;
  if (!user.messages) user.messages = [];
  const msg = { id: uuidv4(), from:'admin', text: msgText, sentAt: new Date().toISOString(), readByAdmin:true, readByCustomer:false, isStatusUpdate:true };
  user.messages.push(msg);
  saveUsers(users);
  pushCustomer(user.id, { type:'message', text: msgText, sentAt: msg.sentAt });
  pushCustomer(user.id, { type:'doc_status', docId: doc.id, status, note });

  res.json({ success:true, document: doc });
});

// ══════════════════════════════════════════════════════════
//  AUDIT LOG
// ══════════════════════════════════════════════════════════
app.get('/api/admin/audit-log', requireAuth, requireRole(r=>r==='super_admin'||r==='admin'), (req, res) => {
  const { userId, limit } = req.query;
  let log = loadAudit();
  if (userId) log = log.filter(e => e.userId === userId);
  res.json({ entries: log.slice(0, parseInt(limit)||200) });
});

// ══════════════════════════════════════════════════════════
//  ADMIN ROUTES
// ══════════════════════════════════════════════════════════
app.post('/api/admin/login', async (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(401).json({ error:'Name and password are required.' });
  const admins = await loadAdmins();
  const admin  = Object.values(admins).find(a => a.name.toLowerCase() === name.trim().toLowerCase() && a.active);
  if (!admin || !(await bcrypt.compare(password, admin.password))) {
    logAudit({ userId:null, customerName:'Admin', actor:'admin', action:'admin_login_failed', detail:`Attempted login as "${name}"`, ip:getClientIp(req) });
    return res.status(401).json({ error:'Invalid name or password.' });
  }
  // If 2FA is enabled, return a temporary pre-auth token — full token issued after TOTP verified
  if (admin.twoFactorEnabled && admin.twoFactorSecret) {
    const preToken = jwt.sign({ preAuth:true, adminId:admin.id }, JWT_SECRET, { expiresIn:'5m' });
    return res.json({ success:true, requires2FA:true, preToken, name:admin.name });
  }
  const token = jwt.sign({ isAdmin:true, adminId:admin.id, adminName:admin.name, role:admin.role, userId:'admin' }, JWT_SECRET, { expiresIn:'8h' });
  logAudit({ userId:null, customerName:admin.name, actor:'admin', action:'admin_login_success', detail:`Logged in as ${ROLE_LABELS[admin.role]}`, ip:getClientIp(req) });
  res.json({ success:true, requires2FA:false, token, name:admin.name, role:admin.role, roleLabel:ROLE_LABELS[admin.role] });
});

// Admin 2FA verify — called after password step when admin has 2FA enabled
app.post('/api/admin/login-2fa', async (req, res) => {
  const { preToken, token: totpCode } = req.body;
  if (!preToken || !totpCode) return res.status(400).json({ error:'Missing token or code.' });
  let payload;
  try { payload = jwt.verify(preToken, JWT_SECRET); } catch { return res.status(401).json({ error:'Session expired. Please log in again.' }); }
  if (!payload.preAuth) return res.status(401).json({ error:'Invalid pre-auth token.' });
  const admins = await loadAdmins();
  const admin  = admins[payload.adminId];
  if (!admin) return res.status(404).json({ error:'Admin not found.' });
  const ok = speakeasy.totp.verify({ secret:admin.twoFactorSecret, encoding:'base32', token:totpCode, window:2 });
  if (!ok) {
    logAudit({ userId:null, customerName:admin.name, actor:'admin', action:'admin_2fa_failed', detail:'Invalid 2FA code', ip:getClientIp(req) });
    return res.status(400).json({ error:'Invalid 2FA code. Please try again.' });
  }
  const fullToken = jwt.sign({ isAdmin:true, adminId:admin.id, adminName:admin.name, role:admin.role, userId:'admin' }, JWT_SECRET, { expiresIn:'8h' });
  logAudit({ userId:null, customerName:admin.name, actor:'admin', action:'admin_login_success', detail:`Logged in as ${ROLE_LABELS[admin.role]} (2FA verified)`, ip:getClientIp(req) });
  res.json({ success:true, token:fullToken, name:admin.name, role:admin.role, roleLabel:ROLE_LABELS[admin.role] });
});

// Admin setup 2FA — generates QR code for scanning in Google Authenticator
app.post('/api/admin/setup-2fa', requireAuth, requireAdmin, async (req, res) => {
  const admins = await loadAdmins();
  const admin  = admins[req.adminId];
  if (!admin) return res.status(404).json({ error:'Admin not found.' });
  const cfg    = loadConfig();
  const secret = speakeasy.generateSecret({ name:`${cfg.branding.corpName} Admin (${admin.name})` });
  admins[req.adminId].twoFactorSecret  = secret.base32;
  admins[req.adminId].twoFactorEnabled = false;   // not enabled until verified
  saveAdmins(admins);
  const qrCode = await QRCode.toDataURL(secret.otpauth_url);
  res.json({ success:true, qrCode, secret:secret.base32 });
});

// Admin verify 2FA setup — confirms code matches before enabling
app.post('/api/admin/verify-2fa', requireAuth, requireAdmin, async (req, res) => {
  const { token: totpCode } = req.body;
  const admins = await loadAdmins();
  const admin  = admins[req.adminId];
  if (!admin || !admin.twoFactorSecret) return res.status(400).json({ error:'2FA not set up yet.' });
  const ok = speakeasy.totp.verify({ secret:admin.twoFactorSecret, encoding:'base32', token:totpCode, window:2 });
  if (!ok) return res.status(400).json({ error:'Invalid code. Please scan the QR code again and retry.' });
  admins[req.adminId].twoFactorEnabled = true;
  saveAdmins(admins);
  logAudit({ userId:null, customerName:admin.name, actor:'admin', action:'admin_2fa_enabled', detail:'Two-factor authentication enabled' });
  res.json({ success:true });
});

// Admin disable 2FA (requires current password confirmation)
app.post('/api/admin/disable-2fa', requireAuth, requireAdmin, async (req, res) => {
  const { password } = req.body;
  const admins = await loadAdmins();
  const admin  = admins[req.adminId];
  if (!admin) return res.status(404).json({ error:'Admin not found.' });
  if (!await bcrypt.compare(password, admin.password)) return res.status(401).json({ error:'Incorrect password.' });
  admins[req.adminId].twoFactorEnabled = false;
  admins[req.adminId].twoFactorSecret  = null;
  saveAdmins(admins);
  logAudit({ userId:null, customerName:admin.name, actor:'admin', action:'admin_2fa_disabled', detail:'Two-factor authentication disabled' });
  res.json({ success:true });
});

// Get current admin's own profile (used by UI to know permissions)
app.get('/api/admin/me', requireAuth, requireAdmin, (req, res) => {
  res.json({ name:req.adminName, role:req.adminRole, roleLabel:ROLE_LABELS[req.adminRole],
    permissions: {
      manageAdmins:   canManageAdmins(req.adminRole),
      editBranding:   canEditBranding(req.adminRole),
      editColors:     canEditColors(req.adminRole),
      editAgreement:  canEditAgreement(req.adminRole),
      editEmailConfig:canEditEmailConfig(req.adminRole),
      manageClients:  canManageClients(req.adminRole),
      deleteDocuments:canDeleteDocuments(req.adminRole),
      viewAuditLog:   canViewAuditLog(req.adminRole)
    }
  });
});

// ══════════════════════════════════════════════════════════
//  ADMIN ACCOUNT MANAGEMENT — Super Admin only
// ══════════════════════════════════════════════════════════
app.get('/api/admin/admins', requireAuth, requireRole(r=>r==='super_admin'), async (req, res) => {
  const admins = await loadAdmins();
  const list = Object.values(admins).map(a => ({ id:a.id, name:a.name, role:a.role, roleLabel:ROLE_LABELS[a.role], active:a.active, createdAt:a.createdAt }));
  res.json({ admins: list, roles: ROLE_LABELS });
});

app.post('/api/admin/admins', requireAuth, requireRole(r=>r==='super_admin'), async (req, res) => {
  const { name, password, role } = req.body;
  if (!name || !name.trim())  return res.status(400).json({ error:'Name is required.' });
  if (!password || password.length < 8) return res.status(400).json({ error:'Password must be at least 8 characters.' });
  if (!ROLE_LABELS[role]) return res.status(400).json({ error:'Invalid role.' });
  const admins = await loadAdmins();
  if (Object.values(admins).find(a => a.name.toLowerCase() === name.trim().toLowerCase()))
    return res.status(400).json({ error:'An admin with this name already exists.' });
  const id = uuidv4();
  admins[id] = { id, name:name.trim(), password: await bcrypt.hash(password, 12), role, createdAt:new Date().toISOString(), active:true };
  saveAdmins(admins);
  logAudit({ userId:null, customerName:req.adminName, actor:'admin', action:'admin_account_created', detail:`Created "${name.trim()}" as ${ROLE_LABELS[role]}` });
  res.json({ success:true, id });
});

app.post('/api/admin/admins/:id/password', requireAuth, requireRole(r=>r==='super_admin'), async (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 8) return res.status(400).json({ error:'Password must be at least 8 characters.' });
  const admins = await loadAdmins();
  if (!admins[req.params.id]) return res.status(404).json({ error:'Admin not found.' });
  admins[req.params.id].password = await bcrypt.hash(password, 12);
  saveAdmins(admins);
  logAudit({ userId:null, customerName:req.adminName, actor:'admin', action:'admin_password_changed', detail:`Reset password for "${admins[req.params.id].name}"` });
  res.json({ success:true });
});

app.post('/api/admin/admins/:id/role', requireAuth, requireRole(r=>r==='super_admin'), async (req, res) => {
  const { role } = req.body;
  if (!ROLE_LABELS[role]) return res.status(400).json({ error:'Invalid role.' });
  const admins = await loadAdmins();
  if (!admins[req.params.id]) return res.status(404).json({ error:'Admin not found.' });
  admins[req.params.id].role = role;
  saveAdmins(admins);
  res.json({ success:true });
});

app.delete('/api/admin/admins/:id', requireAuth, requireRole(r=>r==='super_admin'), async (req, res) => {
  const admins = await loadAdmins();
  if (!admins[req.params.id]) return res.status(404).json({ error:'Admin not found.' });
  if (req.params.id === req.adminId) return res.status(400).json({ error:'You cannot remove your own account.' });
  const remainingSupers = Object.values(admins).filter(a => a.role==='super_admin' && a.id!==req.params.id && a.active);
  if (admins[req.params.id].role === 'super_admin' && remainingSupers.length === 0)
    return res.status(400).json({ error:'Cannot remove the last Super Admin account.' });
  const name = admins[req.params.id].name;
  delete admins[req.params.id];
  saveAdmins(admins);
  logAudit({ userId:null, customerName:req.adminName, actor:'admin', action:'admin_account_removed', detail:`Removed "${name}"` });
  res.json({ success:true });
});

app.get('/api/admin/events', (req, res) => {
  try { const d = jwt.verify(req.query.token, JWT_SECRET); if (!d.isAdmin) throw 0; } catch { return res.status(401).end(); }
  res.setHeader('Content-Type','text/event-stream');
  res.setHeader('Cache-Control','no-cache');
  res.setHeader('Connection','keep-alive');
  res.flushHeaders();
  const hb = setInterval(() => { try { res.write('data:{"type":"ping"}\n\n'); } catch { clearInterval(hb); } }, 25000);
  adminSseClients.push(res);
  req.on('close', () => { clearInterval(hb); adminSseClients = adminSseClients.filter(c=>c!==res); });
});

// Shared logic for creating a single client record (used by both single-add and bulk import)
function createCustomerRecord(firstName, lastName, email, ssn4) {
  const userId        = uuidv4();
  const folderName    = `${firstName}_${lastName}_${ssn4}`.replace(/\s+/g,'_');
  const inviteToken   = uuidv4();
  const inviteExpires = new Date(Date.now()+48*60*60*1000).toISOString();
  return {
    id:userId, firstName, lastName, name:`${firstName} ${lastName}`, email, ssn4, folderName,
    status:'invited', inviteToken, inviteExpires, inviteSentAt:new Date().toISOString(),
    agreementAccepted:null, agreementIp:null, password:null, twoFactorSecret:null, twoFactorEnabled:false,
    createdAt:new Date().toISOString(), documents:[], messages:[], checklist:[]
  };
}

app.post('/api/admin/customers', requireAuth, requireRole(r=>r==='super_admin'||r==='admin'), async (req, res) => {
  const { firstName, lastName, email, ssn4 } = req.body;
  if (!firstName||!lastName||!email||!ssn4) return res.status(400).json({ error:'All fields are required.' });
  if (!/^\d{4}$/.test(ssn4))               return res.status(400).json({ error:'SSN must be exactly 4 digits.' });
  const users = loadUsers();
  if (Object.values(users).find(u => u.email === email)) return res.status(400).json({ error:'Email already exists.' });
  const record = createCustomerRecord(firstName, lastName, email, ssn4);
  users[record.id] = record;
  saveUsers(users);
  fs.mkdirSync(path.join(UPLOADS_DIR, record.folderName), { recursive:true });
  logAudit({ userId:record.id, customerName:`${firstName} ${lastName}`, actor:'admin', action:'client_created', detail:`Folder: ${record.folderName}` });
  res.json({ success:true, userId:record.id, folderName:record.folderName });
});

// ══════════════════════════════════════════════════════════
//  BULK IMPORT — CSV / Excel
// ══════════════════════════════════════════════════════════

// Download a starter template
app.get('/api/admin/customers/import-template', (req, res) => {
  const token = req.query.token || req.headers.authorization?.split(' ')[1];
  try {
    const d = jwt.verify(token, JWT_SECRET);
    if (!d.isAdmin || !(d.role==='super_admin'||d.role==='admin')) throw 0;
  } catch { return res.status(401).end(); }

  const format = req.query.format === 'xlsx' ? 'xlsx' : 'csv';
  const rows = [
    ['First Name','Last Name','Email','SSN Last 4'],
    ['Jane','Smith','jane.smith@example.com','1234'],
    ['John','Doe','john.doe@example.com','5678']
  ];
  if (format === 'xlsx') {
    const ws = XLSX.utils.aoa_to_sheet(rows);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Clients');
    const buf = XLSX.write(wb, { type:'buffer', bookType:'xlsx' });
    res.setHeader('Content-Disposition', 'attachment; filename="client_import_template.xlsx"');
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buf);
  } else {
    const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g,'""')}"`).join(',')).join('\r\n');
    res.setHeader('Content-Disposition', 'attachment; filename="client_import_template.csv"');
    res.setHeader('Content-Type', 'text/csv');
    res.send(csv);
  }
});

// Parse uploaded file and return a preview (does NOT create accounts yet)
app.post('/api/admin/customers/import-preview', requireAuth, requireRole(r=>r==='super_admin'||r==='admin'), importUpload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error:'No file uploaded.' });
  let rows;
  try {
    const name = req.file.originalname.toLowerCase();
    if (name.endsWith('.csv')) {
      rows = parseCsv(req.file.buffer, { columns:false, skip_empty_lines:true, trim:true });
    } else {
      const wb = XLSX.read(req.file.buffer, { type:'buffer' });
      const sheet = wb.Sheets[wb.SheetNames[0]];
      rows = XLSX.utils.sheet_to_json(sheet, { header:1, defval:'' });
    }
  } catch (e) {
    return res.status(400).json({ error:'Could not read the file. Make sure it is a valid CSV or Excel file.' });
  }
  if (!rows.length) return res.status(400).json({ error:'The file appears to be empty.' });

  // Detect and skip a header row if present
  const headerLike = rows[0].map(c => String(c).toLowerCase());
  const looksLikeHeader = headerLike.some(c => c.includes('first') || c.includes('email') || c.includes('last'));
  const dataRows = looksLikeHeader ? rows.slice(1) : rows;

  const users = loadUsers();
  const existingEmails = new Set(Object.values(users).map(u => u.email.toLowerCase()));
  const seenInFile = new Set();

  const preview = dataRows.map((row, i) => {
    const firstName = String(row[0]||'').trim();
    const lastName  = String(row[1]||'').trim();
    const email     = String(row[2]||'').trim();
    const ssn4Raw   = String(row[3]||'').trim();
    const ssn4      = ssn4Raw.padStart(4,'0').slice(-4);

    const errors = [];
    if (!firstName) errors.push('Missing first name');
    if (!lastName)  errors.push('Missing last name');
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.push('Invalid or missing email');
    if (!/^\d{1,4}$/.test(ssn4Raw)) errors.push('SSN last 4 must be digits');
    if (email && existingEmails.has(email.toLowerCase())) errors.push('Email already exists in system');
    if (email && seenInFile.has(email.toLowerCase())) errors.push('Duplicate email in this file');
    if (email) seenInFile.add(email.toLowerCase());

    return { row:i+1, firstName, lastName, email, ssn4, valid:errors.length===0, errors };
  });

  const validCount = preview.filter(p => p.valid).length;
  res.json({ preview, total:preview.length, validCount, invalidCount:preview.length-validCount });
});

// Actually create the accounts from a confirmed, validated list
app.post('/api/admin/customers/import-confirm', requireAuth, requireRole(r=>r==='super_admin'||r==='admin'), async (req, res) => {
  const { rows, sendInvites } = req.body;   // rows: [{firstName,lastName,email,ssn4}]
  if (!Array.isArray(rows) || !rows.length) return res.status(400).json({ error:'No rows provided.' });

  const users = loadUsers();
  const created = [];
  const skipped = [];

  for (const r of rows) {
    const firstName = String(r.firstName||'').trim();
    const lastName  = String(r.lastName||'').trim();
    const email      = String(r.email||'').trim();
    const ssn4       = String(r.ssn4||'').trim();
    if (!firstName || !lastName || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^\d{4}$/.test(ssn4)) {
      skipped.push({ email, reason:'Invalid data' }); continue;
    }
    if (Object.values(users).find(u => u.email.toLowerCase() === email.toLowerCase())) {
      skipped.push({ email, reason:'Already exists' }); continue;
    }
    const record = createCustomerRecord(firstName, lastName, email, ssn4);
    users[record.id] = record;
    fs.mkdirSync(path.join(UPLOADS_DIR, record.folderName), { recursive:true });
    created.push(record);
  }
  saveUsers(users);
  logAudit({ userId:null, customerName:req.adminName||'Admin', actor:'admin', action:'bulk_import', detail:`Imported ${created.length} client(s), skipped ${skipped.length}` });

  // Optionally fire off invitation emails (sequentially to avoid SMTP rate issues)
  if (sendInvites) {
    for (const u of created) { await sendInvitationEmail(u); }
  }

  res.json({ success:true, createdCount:created.length, skipped });
});

app.post('/api/admin/customers/:userId/invite', requireAuth, requireRole(r=>r==='super_admin'||r==='admin'), async (req, res) => {
  const users = loadUsers();
  const user  = users[req.params.userId];
  if (!user)               return res.status(404).json({ error:'Customer not found.' });
  if (user.status==='active') return res.status(400).json({ error:'Customer is already active.' });
  users[req.params.userId].inviteToken   = uuidv4();
  users[req.params.userId].inviteExpires = new Date(Date.now()+48*60*60*1000).toISOString();
  users[req.params.userId].inviteSentAt  = new Date().toISOString();
  users[req.params.userId].status        = 'invited';
  saveUsers(users);
  res.json(await sendInvitationEmail(users[req.params.userId]));
});

app.get('/api/admin/customers', requireAuth, requireAdmin, (req, res) => {
  const users = loadUsers();
  const list  = Object.values(users)
    .sort((a,b)=>a.firstName.localeCompare(b.firstName))
    .map(u=>({
      id:u.id, firstName:u.firstName, lastName:u.lastName, email:u.email, ssn4:u.ssn4,
      folderName:u.folderName, status:u.status, createdAt:u.createdAt,
      inviteSentAt:u.inviteSentAt, inviteExpires:u.inviteExpires,
      agreementAccepted:u.agreementAccepted, agreementIp:u.agreementIp,
      twoFactorEnabled:u.twoFactorEnabled, documentCount:(u.documents||[]).length,
      unreadMessages:(u.messages||[]).filter(m=>m.from==='customer'&&!m.readByAdmin).length,
      messageCount:(u.messages||[]).length,
      checklist:(u.checklist||[]),
      documents:(u.documents||[]).map(d=>({
        id:d.id, originalName:d.originalName, size:d.size, uploadedAt:d.uploadedAt,
        storedName:d.storedName, uploadIp:d.uploadIp||'—',
        category:d.category||'Others', status:d.status||'pending', statusNote:d.statusNote||'',
        statusUpdatedAt:d.statusUpdatedAt||null, versionGroupId:d.versionGroupId||d.id, versionNumber:d.versionNumber||1
      }))
    }));
  res.json({ customers:list });
});

app.get('/api/admin/download/:userId/:docId', (req, res) => {
  try { const d=jwt.verify(req.query.token,JWT_SECRET); if(!d.isAdmin) throw 0; } catch { return res.status(401).end(); }
  const users=loadUsers(); const user=users[req.params.userId];
  if(!user) return res.status(404).end();
  const doc=(user.documents||[]).find(d=>d.id===req.params.docId);
  if(!doc)  return res.status(404).end();
  const fp=path.join(UPLOADS_DIR,user.folderName,doc.storedName);
  if(!fs.existsSync(fp)) return res.status(404).json({ error:'File not on disk.' });
  res.download(fp, doc.originalName);
});

app.delete('/api/admin/customers/:userId/documents/:docId', requireAuth, requireRole(r=>r==='super_admin'||r==='admin'), (req, res) => {
  const users=loadUsers(); const user=users[req.params.userId];
  if(!user) return res.status(404).json({ error:'Not found.' });
  const doc=(user.documents||[]).find(d=>d.id===req.params.docId);
  if(!doc)  return res.status(404).json({ error:'Not found.' });
  const fp=path.join(UPLOADS_DIR,user.folderName,doc.storedName);
  if(fs.existsSync(fp)) fs.unlinkSync(fp);
  users[req.params.userId].documents=user.documents.filter(d=>d.id!==req.params.docId);
  saveUsers(users); res.json({ success:true });
});

app.delete('/api/admin/customers/:userId', requireAuth, requireRole(r=>r==='super_admin'||r==='admin'), (req, res) => {
  const users=loadUsers(); const user=users[req.params.userId];
  if(!user) return res.status(404).json({ error:'Not found.' });
  const folder=path.join(UPLOADS_DIR,user.folderName);
  if(fs.existsSync(folder)) fs.rmSync(folder,{ recursive:true });
  delete users[req.params.userId]; saveUsers(users); res.json({ success:true });
});

// GET CONFIG (full, for admin)
app.get('/api/admin/config', requireAuth, requireAdmin, (req, res) => {
  const cfg = loadConfig();
  res.json({
    adminEmail:cfg.adminEmail, smtpHost:cfg.smtp?.host, smtpUser:cfg.smtp?.user,
    smtpPort:cfg.smtp?.port, smtpConfigured:!!(cfg.smtp?.pass),
    agreementText:cfg.agreementText, branding: cfg.branding,
    autoDeleteHours: cfg.autoDeleteHours,
    siteUrl: cfg.siteUrl || getSiteUrl()
  });
});

// UPDATE SITE URL
app.post('/api/admin/config/siteurl', requireAuth, requireRole(r=>r==='super_admin'||r==='admin'), (req, res) => {
  const { siteUrl } = req.body;
  if (!siteUrl || !siteUrl.startsWith('http')) return res.status(400).json({ error:'Must be a valid URL starting with http/https' });
  const cfg = loadConfig();
  cfg.siteUrl = siteUrl.replace(/\/$/, '');
  saveConfig(cfg);
  res.json({ success:true, siteUrl: cfg.siteUrl });
});

// UPDATE EMAIL
app.post('/api/admin/config/email', requireAuth, requireRole(r=>r==='super_admin'||r==='admin'), (req, res) => {
  const { adminEmail, smtpHost, smtpPort, smtpUser, smtpPass, smtpApiKey } = req.body;
  const cfg = loadConfig();
  cfg.adminEmail = adminEmail;
  cfg.smtp = { host:smtpHost, port:parseInt(smtpPort)||587, user:smtpUser, pass:smtpPass };
  if (smtpApiKey) cfg.smtp.apiKey = smtpApiKey;   // Brevo API key stored separately
  saveConfig(cfg); res.json({ success:true });
});

// UPDATE AGREEMENT
app.post('/api/admin/config/agreement', requireAuth, requireRole(r=>r==='super_admin'||r==='admin'), (req, res) => {
  const cfg = loadConfig();
  cfg.agreementText = req.body.agreementText;
  saveConfig(cfg); res.json({ success:true });
});

// UPDATE BRANDING
app.post('/api/admin/config/branding', requireAuth, requireRole(r=>r==='super_admin'), (req, res) => {
  const cfg = loadConfig();
  cfg.branding = { ...defaultBranding(), ...req.body };
  saveConfig(cfg);
  res.json({ success:true, branding: cfg.branding });
});

// UPLOAD LOGO
app.post('/api/admin/config/logo', requireAuth, requireRole(r=>r==='super_admin'), logoUpload.single('logo'), (req, res) => {
  if (!req.file) return res.status(400).json({ error:'No file uploaded.' });
  const ext  = path.extname(req.file.originalname).toLowerCase() || '.png';
  const dest = path.join(__dirname, 'public', `logo${ext}`);
  fs.renameSync(req.file.path, dest);
  res.json({ success:true, logoUrl: `/logo${ext}?t=${Date.now()}` });
});

// TEST EMAIL
app.post('/api/admin/test-email', requireAuth, requireRole(r=>r==='super_admin'||r==='admin'), async (req, res) => {
  res.json(await sendMail(loadConfig().adminEmail, 'Test Email — Configuration OK', emailWrap('<h2 style="color:#059669;">✅ Email is working!</h2><p>Your SMTP configuration is correct.</p>')));
});

// DOCUMENT RETENTION SETTINGS
app.get('/api/admin/config/retention', requireAuth, requireRole(r=>r==='super_admin'||r==='admin'), (req, res) => {
  const cfg = loadConfig();
  res.json({ autoDeleteHours: cfg.autoDeleteHours });
});
app.post('/api/admin/config/retention', requireAuth, requireRole(r=>r==='super_admin'||r==='admin'), (req, res) => {
  const hours = parseInt(req.body.autoDeleteHours);
  if (isNaN(hours) || hours < 0) return res.status(400).json({ error:'Invalid retention period.' });
  const cfg = loadConfig();
  cfg.autoDeleteHours = hours;
  saveConfig(cfg);
  logAudit({ userId:null, customerName:req.adminName||'Admin', actor:'admin', action:'retention_setting_changed', detail: hours===0 ? 'Auto-delete disabled' : `Auto-delete set to ${hours} hours` });
  res.json({ success:true });
});

// Manually trigger a sweep on demand (useful for testing / immediate cleanup)
app.post('/api/admin/run-auto-delete', requireAuth, requireRole(r=>r==='super_admin'||r==='admin'), (req, res) => {
  runAutoDeleteSweep();
  res.json({ success:true });
});

// ─── Start ────────────────────────────────────────────────────────────────
const cfg = loadConfig();
app.listen(PORT, () => {
  console.log(`\n🚀 ${cfg.branding.corpName}`);
  console.log(`   Portal  → ${BASE_URL}`);
  console.log(`   Admin   → ${BASE_URL}/admin.html`);
  console.log(`   Notify  → ${cfg.adminEmail}`);
  console.log(cfg.smtp?.pass ? `   Email  ✅ via ${cfg.smtp.user}` : `   Email  ⚠️  SMTP password not set`);
  console.log(cfg.autoDeleteHours > 0 ? `   Retention  🧹 Auto-delete after ${cfg.autoDeleteHours}h` : `   Retention  ⚪ Auto-delete disabled`);
  console.log('');

  // Run an initial sweep shortly after boot, then every hour
  setTimeout(runAutoDeleteSweep, 10000);
  setInterval(runAutoDeleteSweep, 60*60*1000);
});
