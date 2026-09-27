const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const multer = require('multer');
const AdmZip = require('adm-zip');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const whatsapp = require('./whatsapp');
const configuredPort = process.env.PORT?.trim();
const port = configuredPort ? Number(configuredPort) : 5050;
if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error('PORT must be an integer between 0 and 65535');
}
const JWT_SECRET = process.env.JWT_SECRET || (
    process.env.NODE_ENV === 'production' ? null : 'assudani-super-secret-key'
);
if (!JWT_SECRET) {
    throw new Error('JWT_SECRET must be configured when NODE_ENV=production');
}
if (process.env.NODE_ENV === 'production' && JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must contain at least 32 characters when NODE_ENV=production');
}
const allowedOrigins = new Set(
    (process.env.CORS_ORIGINS || (process.env.NODE_ENV === 'production' ? '' : 'http://localhost:5173,http://localhost:5174'))
        .split(',')
        .map((origin) => origin.trim())
        .filter(Boolean)
);
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || null;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || null;
if (process.env.NODE_ENV === 'production') {
    const hasThreeCharacterClasses = typeof ADMIN_PASSWORD === 'string' &&
        [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((pattern) => pattern.test(ADMIN_PASSWORD)).length >= 3;
    if (!ADMIN_USERNAME || ADMIN_USERNAME.length < 3 || !ADMIN_PASSWORD ||
        ADMIN_PASSWORD.length < 24 || !hasThreeCharacterClasses) {
        throw new Error('Production admin authentication requires ADMIN_USERNAME (3+ characters) and ADMIN_PASSWORD (24+ characters with at least three character classes)');
    }
}
const db = require('./database');

function generateInvoicePDF(payment, invoiceNumber, date) {
    const subtotal = payment.amount || 0;
    const serviceTax = payment.serviceTax || 0;
    const dashboardTax = payment.dashboardTax || 0;
    const total = subtotal + serviceTax + dashboardTax;
    const planName = payment.plan_name || 'Hosting Plan';
    const customerName = payment.name || 'Customer';
    const customerEmail = payment.email || '';
    const customerPhone = payment.whatsapp_number || '';
    const address = [payment.address_line1, payment.address_line2, payment.city, payment.state, payment.postal_code, payment.country]
        .filter(Boolean).join(', ') || 'Not provided';
    
    return `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length 2000 >>
stream
BT
/F1 24 Tf
50 750 Td
(Assudani Hosting - Invoice) Tj
0 -30 Td
/F1 12 Tf
(Invoice #: ${invoiceNumber}) Tj
0 -20 Td
(Date: ${date}) Tj
0 -40 Td
/F1 14 Tf
(Bill To:) Tj
0 -20 Td
/F1 12 Tf
(${customerName}) Tj
0 -18 Td
(${customerEmail}) Tj
0 -18 Td
(${customerPhone}) Tj
0 -18 Td
(${address}) Tj
0 -40 Td
/F1 14 Tf
(Plan: ${planName}) Tj
0 -30 Td
/F1 12 Tf
(Description) Tj
150 0 Td
(Amount) Tj
0 -20 Td
(${planName} - Hosting Service) Tj
150 0 Td
(₹${subtotal.toFixed(2)}) Tj
0 -20 Td
(Service Tax (3%)) Tj
150 0 Td
(₹${serviceTax.toFixed(2)}) Tj
0 -20 Td
(Dashboard Tax (3%)) Tj
150 0 Td
(₹${dashboardTax.toFixed(2)}) Tj
0 -30 Td
/F1 14 Tf
(Total) Tj
150 0 Td
(₹${total.toFixed(2)}) Tj
ET
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>
endobj
xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000060 00000 n
0000000117 00000 n
0000000238 00000 n
000002100 00000 n
trailer
<< /Size 6 /Root 1 0 R >>
startxref
2200
%%EOF`;
}

const app = express();

const authRateLimits = new Map();
function checkAuthRateLimit(req, maxAttempts = 5, windowMs = 15 * 60 * 1000) {
    const ipHash = getHashedClientAddress(req);
    const now = Date.now();
    const limit = authRateLimits.get(ipHash) || { attempts: 0, windowStart: now };
    if (now - limit.windowStart > windowMs) {
        limit.attempts = 0;
        limit.windowStart = now;
    }
    limit.attempts++;
    authRateLimits.set(ipHash, limit);
    if (limit.attempts > maxAttempts) {
        return false;
    }
    return true;
}

const HOSTING_DIR = path.resolve(process.env.HOSTING_DIR || path.resolve(__dirname, '../public_hosting'));
const OFFLINE_DIR = path.resolve(process.env.OFFLINE_HOSTING_DIR ||
    path.resolve(path.dirname(HOSTING_DIR), 'private_hosting_offline'));
const PAYMENT_SCREENSHOTS_DIR = path.resolve(process.env.PAYMENT_SCREENSHOTS_DIR ||
    path.resolve(__dirname, 'payment-screenshots'));
const MAX_DEPLOYMENT_BYTES = 500 * 1024 * 1024;
const MAX_WEBSITE_STORAGE_BYTES = 15 * 1024 * 1024;

app.use(cors({
    origin(origin, callback) {
        callback(null, !origin || allowedOrigins.has(origin));
    }
}));
app.use(express.json());

// Security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    const csp = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data: https:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'"
    ].join('; ');
    res.setHeader('Content-Security-Policy', csp);
    next();
});

if (!fs.existsSync(HOSTING_DIR)) {
  fs.mkdirSync(HOSTING_DIR, { recursive: true });
}
if (!fs.existsSync(OFFLINE_DIR)) {
  fs.mkdirSync(OFFLINE_DIR, { recursive: true });
}
if (!fs.existsSync(PAYMENT_SCREENSHOTS_DIR)) {
  fs.mkdirSync(PAYMENT_SCREENSHOTS_DIR, { recursive: true });
}
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 }
});
const paymentUpload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, callback) => {
        if (!['image/jpeg', 'image/png', 'image/webp', 'image/gif'].includes(file.mimetype)) {
            return callback(new Error('Screenshot must be a JPEG, PNG, WebP, or GIF image'));
        }
        callback(null, true);
    }
});

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (token == null) return res.status(401).json({ error: "Unauthorized" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(401).json({ error: "Unauthorized" });
        if (!user || user.role === 'admin' || !Number.isInteger(Number(user.id))) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        db.get(`SELECT account_status, terms_accepted_at, privacy_acknowledged_at
                FROM users WHERE id = ?`, [user.id], (userError, account) => {
            if (userError) return res.status(503).json({ error: 'Unable to validate customer account status' });
            if (!account) return res.status(401).json({ error: 'Customer account no longer exists' });
            if (account.account_status !== 'Active') return res.status(403).json({ error: 'Customer account is suspended' });
            const legalAcceptanceRoute = req.originalUrl.split('?')[0] === '/api/user/onboarding/accept-legal';
            if ((!account.terms_accepted_at || !account.privacy_acknowledged_at) && !legalAcceptanceRoute) {
                return res.status(403).json({ error: 'Accept the Terms of Service and Privacy Notice before using customer features' });
            }
            req.user = user;
            next();
        });
    });
};

function safeCredentialMatch(expected, supplied) {
    const expectedDigest = crypto.createHash('sha256').update(expected).digest();
    const suppliedDigest = crypto.createHash('sha256').update(supplied).digest();
    return crypto.timingSafeEqual(expectedDigest, suppliedDigest);
}

function getHashedClientAddress(req) {
    const address = req.socket.remoteAddress || 'unknown';
    return crypto.createHash('sha256').update(address).digest('hex');
}

function recordAudit(actor, action, method, route, statusCode, requestId) {
    db.run(`INSERT INTO audit_logs (actor, action, method, route, status_code, request_id)
            VALUES (?, ?, ?, ?, ?, ?)`,
        [actor, action, method, route, statusCode, requestId],
        (error) => {
            if (error) console.error('Admin audit log write failed:', error.message);
        });
}

function databaseGet(sql, params = []) {
    return new Promise((resolve, reject) => db.get(sql, params, (error, row) => error ? reject(error) : resolve(row)));
}

function databaseAll(sql, params = []) {
    return new Promise((resolve, reject) => db.all(sql, params, (error, rows) => error ? reject(error) : resolve(rows)));
}

function databaseRun(sql, params = []) {
    return new Promise((resolve, reject) => db.run(sql, params, function(error) {
        if (error) reject(error);
        else resolve({ changes: this.changes, lastID: this.lastID });
    }));
}

app.post('/api/admin/login', (req, res) => {
    if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
        return res.status(503).json({ error: 'Admin authentication is not configured' });
    }
    const username = typeof req.body.username === 'string' && req.body.username.length <= 256
        ? req.body.username : '';
    const password = typeof req.body.password === 'string' && req.body.password.length <= 1024
        ? req.body.password : '';
    const ipHash = getHashedClientAddress(req);
    db.get('SELECT window_started_at, attempts, locked_until FROM admin_login_limits WHERE ip_hash = ?',
        [ipHash], (limitError, loginLimit) => {
        if (limitError) return res.status(503).json({ error: 'Admin login is temporarily unavailable' });
        if (loginLimit?.locked_until && Date.parse(loginLimit.locked_until) > Date.now()) {
            return res.status(429).json({ error: 'Too many failed admin login attempts; try again later' });
        }
    const usernameMatches = safeCredentialMatch(ADMIN_USERNAME, username);
    const passwordMatches = safeCredentialMatch(ADMIN_PASSWORD, password);
    if (!usernameMatches || !passwordMatches) {
        const now = Date.now();
        const sameWindow = loginLimit && now - Date.parse(loginLimit.window_started_at) < 15 * 60 * 1000;
        const attempts = sameWindow ? loginLimit.attempts + 1 : 1;
        const windowStarted = sameWindow ? loginLimit.window_started_at : new Date(now).toISOString();
        const lockedUntil = attempts >= 5 ? new Date(now + 15 * 60 * 1000).toISOString() : null;
        return db.run(`INSERT INTO admin_login_limits (ip_hash, window_started_at, attempts, locked_until)
                       VALUES (?, ?, ?, ?)
                       ON CONFLICT(ip_hash) DO UPDATE SET window_started_at = excluded.window_started_at,
                         attempts = excluded.attempts, locked_until = excluded.locked_until`,
            [ipHash, windowStarted, attempts, lockedUntil], (saveError) => {
                if (saveError) return res.status(503).json({ error: 'Admin login is temporarily unavailable' });
                recordAudit('unknown', 'admin_login_failed', req.method, '/api/admin/login', 401, crypto.randomUUID());
                res.status(401).json({ error: 'Invalid admin credentials' });
            });
    }
    db.run('DELETE FROM admin_login_limits WHERE ip_hash = ?', [ipHash], (clearError) => {
        if (clearError) return res.status(503).json({ error: 'Admin login is temporarily unavailable' });
    const token = jwt.sign(
        { role: 'admin', username: ADMIN_USERNAME },
        JWT_SECRET,
        { expiresIn: '8h', issuer: 'hosting-dashboard', audience: 'hosting-dashboard-admin' }
    );
    recordAudit(ADMIN_USERNAME, 'admin_login', req.method, '/api/admin/login', 200, crypto.randomUUID());
    res.json({ token, admin: { username: ADMIN_USERNAME, role: 'admin' } });
    });
    });
});

app.use('/api/admin', (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    jwt.verify(token, JWT_SECRET, {
        issuer: 'hosting-dashboard',
        audience: 'hosting-dashboard-admin'
    }, (error, claims) => {
        if (error || !claims || claims.role !== 'admin' || claims.username !== ADMIN_USERNAME) {
            recordAudit('unknown', 'admin_access_denied', req.method, req.path, 401, crypto.randomUUID());
            return res.status(401).json({ error: 'Unauthorized' });
        }
        req.admin = claims;
        const requestId = crypto.randomUUID();
        res.on('finish', () => {
            recordAudit(claims.username, 'admin_api_request', req.method, req.path, res.statusCode, requestId);
        });
        next();
    });
});

function getFolderSize(dirPath) {
    let size = 0;
    const files = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const file of files) {
        const filePath = path.join(dirPath, file.name);
        size += file.isDirectory() ? getFolderSize(filePath) : fs.statSync(filePath).size;
    }
    return size;
}

function validSubdomain(value) {
    return typeof value === 'string' && value.length <= 63 &&
        /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(value);
}

const prohibitedExtensions = new Set([
    '.exe', '.dll', '.so', '.dylib', '.bat', '.cmd', '.com', '.msi',
    '.ps1', '.sh', '.php', '.phtml', '.phar', '.cgi', '.pl', '.py',
    '.rb', '.jar', '.war', '.class', '.asp', '.aspx', '.jsp', '.jspx',
    '.vbs', '.vbe', '.wsf', '.hta', '.node', '.bin', '.elf', '.app',
    '.command', '.zsh', '.fish', '.psm1', '.psd1'
]);

function prohibitedContent(buffer) {
    if (buffer.length >= 2 && buffer.toString('ascii', 0, 2) === 'MZ') return true;
    if (buffer.length >= 4 && buffer.toString('hex', 0, 4) === '7f454c46') return true;
    if (buffer.length >= 4 && ['feedface', 'feedfacf', 'cefaedfe', 'cffaedfe'].includes(buffer.toString('hex', 0, 4))) return true;
    return buffer.length >= 2 && buffer[0] === 0x23 && buffer[1] === 0x21;
}

function safeUploadPath(root, name) {
    if (typeof name !== 'string' || !name || name.includes('\\') || name.includes('\0') ||
        path.posix.isAbsolute(name) || /^[a-zA-Z]:/.test(name)) {
        return null;
    }
    const segments = name.split('/');
    if (segments.some((segment) => !segment || segment === '.' || segment === '..')) return null;
    if (prohibitedExtensions.has(path.extname(name).toLowerCase())) return null;
    const destination = path.resolve(root, ...segments);
    return destination.startsWith(`${root}${path.sep}`) ? destination : null;
}

function ownedSitePath(root, subdomain) {
    if (!validSubdomain(subdomain)) return null;
    const resolvedRoot = path.resolve(root);
    const sitePath = path.resolve(resolvedRoot, subdomain);
    return path.dirname(sitePath) === resolvedRoot ? sitePath : null;
}

function inspectPaymentImage(buffer) {
    if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return '.jpg';
    if (buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) return '.png';
    if (buffer.length >= 12 && buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WEBP') return '.webp';
    if (buffer.length >= 6 && ['GIF87a', 'GIF89a'].includes(buffer.toString('ascii', 0, 6))) return '.gif';
    return null;
}

function checkDeploymentCapacity(userId, uploadBytes, callback) {
    const sql = `SELECT u.plan_status, u.storage_used, u.subscription_expires_at, p.is_active AS plan_active,
                    p.storage_limit_mb, COALESCE(u.subscription_max_websites, p.max_websites) AS max_websites,
                    COUNT(w.id) AS website_count,
                    COALESCE(SUM(w.size_mb), 0) AS website_storage_mb
                 FROM users u
                 LEFT JOIN plans p ON p.id = u.plan_id
                 LEFT JOIN websites w ON w.user_id = u.id
                 WHERE u.id = ?
                 GROUP BY u.id`;
    db.get(sql, [userId], (err, row) => {
        if (err) return callback(err);
        if (!row) return callback(null, { status: 404, error: 'User not found' });
        if (row.plan_status !== 'Active' || !row.plan_active) {
            return callback(null, { status: 403, error: 'An active plan is required to deploy a website' });
        }
        if (row.subscription_expires_at && Date.parse(row.subscription_expires_at) <= Date.now()) {
            return callback(null, { status: 403, error: 'The active subscription has expired' });
        }
        if (row.website_count >= row.max_websites) {
            return callback(null, { status: 403, error: 'Website limit for the active plan has been reached' });
        }
        const usedMb = Math.max(Number(row.storage_used) || 0, Number(row.website_storage_mb) || 0);
        const limitBytes = Number(row.max_websites) * MAX_WEBSITE_STORAGE_BYTES;
        const availableBytes = Math.min(
            MAX_DEPLOYMENT_BYTES,
            MAX_WEBSITE_STORAGE_BYTES,
            Math.max(0, limitBytes - usedMb * 1024 * 1024)
        );
        if (!Number.isFinite(limitBytes) || uploadBytes > availableBytes) {
            return callback(null, { status: 413, error: 'Deployment exceeds the 15 MB per-website limit or the active plan storage quota' });
        }
        callback(null, { plan: row, maxUploadBytes: availableBytes });
    });
}

function cleanText(value) {
    return typeof value === 'string' ? value.trim() : '';
}

function optionalBillingAddress(body) {
    const limits = {
          address_line1: 200,
          address_line2: 200,
          city: 100,
          state: 100,
          postal_code: 32,
          country: 100
    };
    const address = {
        address_line1: cleanText(body.address_line1),
        address_line2: cleanText(body.address_line2),
        city: cleanText(body.city),
        state: cleanText(body.state),
        postal_code: cleanText(body.postal_code),
        country: cleanText(body.country)
    };
    if (Object.entries(limits).some(([key, limit]) =>
          (body[key] != null && typeof body[key] !== 'string') || address[key].length > limit
    )) {
          return null;
    }
    return address;
}

function hashOtp(userId, otp) {
    return crypto.createHmac('sha256', JWT_SECRET).update(`${userId}:${otp}`).digest('hex');
}

function validWhatsappNumber(value) {
    if (typeof value !== 'string') return false;
    const digits = value.replace(/\D/g, '');
    return digits.length >= 10 && digits.length <= 15;
}

function checkOtpIpRateLimit(req, callback) {
    const address = req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
    const ipHash = crypto.createHmac('sha256', JWT_SECRET).update(address).digest('hex');
    db.run(`DELETE FROM password_reset_otp_ip_limits
            WHERE datetime(window_started_at) <= datetime('now', '-1 hour')`, (cleanupError) => {
        if (cleanupError) return callback(cleanupError);
        db.run(`INSERT INTO password_reset_otp_ip_limits (ip_hash, window_started_at, request_count)
            VALUES (?, CURRENT_TIMESTAMP, 1)
            ON CONFLICT(ip_hash) DO UPDATE SET
              request_count = CASE
                WHEN datetime(password_reset_otp_ip_limits.window_started_at) <= datetime('now', '-1 hour')
                  THEN 1
                ELSE password_reset_otp_ip_limits.request_count + 1
              END,
              window_started_at = CASE
                WHEN datetime(password_reset_otp_ip_limits.window_started_at) <= datetime('now', '-1 hour')
                  THEN CURRENT_TIMESTAMP
                ELSE password_reset_otp_ip_limits.window_started_at
              END`, [ipHash], (updateError) => {
            if (updateError) return callback(updateError);
            db.get('SELECT request_count FROM password_reset_otp_ip_limits WHERE ip_hash = ?', [ipHash], (queryError, row) => {
                if (queryError) return callback(queryError);
                callback(null, row.request_count <= 20);
            });
        });
    });
}

function addMonths(dateValue, months) {
    const date = new Date(dateValue);
    const day = date.getUTCDate();
    date.setUTCDate(1);
    date.setUTCMonth(date.getUTCMonth() + months);
    const lastDay = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 0)).getUTCDate();
    date.setUTCDate(Math.min(day, lastDay));
    return date;
}

const deployingUsers = new Set();

function beginDeployment(userId, subdomain, estimatedBytes, res, callback) {
    if (!validSubdomain(subdomain)) {
        return res.status(400).json({ error: 'Subdomain must contain only lowercase letters, numbers, and internal hyphens' });
    }
    if (deployingUsers.has(userId)) {
        return res.status(409).json({ error: 'A deployment for this account is already in progress' });
    }
    deployingUsers.add(userId);
    db.get('SELECT id FROM websites WHERE subdomain = ?', [subdomain], (err, existing) => {
        if (err) {
            deployingUsers.delete(userId);
            return res.status(500).json({ error: `Database error checking subdomain: ${err.message}` });
        }
        if (existing) {
            deployingUsers.delete(userId);
            return res.status(400).json({ error: 'Subdomain taken' });
        }
        if (fs.existsSync(path.join(HOSTING_DIR, subdomain))) {
            deployingUsers.delete(userId);
            return res.status(409).json({ error: 'Deployment path already exists' });
        }
        checkDeploymentCapacity(userId, estimatedBytes, (capacityError, result) => {
            if (capacityError) {
                deployingUsers.delete(userId);
                return res.status(500).json({ error: `Database error checking plan limits: ${capacityError.message}` });
            }
            if (result.error) {
                deployingUsers.delete(userId);
                return res.status(result.status).json({ error: result.error });
            }
            callback(path.join(HOSTING_DIR, subdomain), result.maxUploadBytes);
        });
    });
}

function finishDeployment(userId, subdomain, sitePath, res) {
    let actualBytes;
    try {
        actualBytes = getFolderSize(sitePath);
    } catch (error) {
        deployingUsers.delete(userId);
        return fs.rm(sitePath, { recursive: true, force: true }, (cleanupError) => {
            res.status(500).json({ error: cleanupError
                ? `Filesystem error measuring deployment: ${error.message}; cleanup failed: ${cleanupError.message}`
                : `Filesystem error measuring deployment: ${error.message}` });
        });
    }
    if (actualBytes > MAX_DEPLOYMENT_BYTES) {
        deployingUsers.delete(userId);
        return fs.rm(sitePath, { recursive: true, force: true }, (cleanupError) => {
            res.status(413).json({ error: cleanupError
                ? `Deployment exceeds the maximum size and cleanup failed: ${cleanupError.message}`
                : 'Deployment exceeds the maximum permitted extracted size' });
        });
    }
    checkDeploymentCapacity(userId, actualBytes, (capacityError, result) => {
        if (capacityError || result.error) {
            deployingUsers.delete(userId);
            return fs.rm(sitePath, { recursive: true, force: true }, (cleanupError) => {
                if (capacityError) return res.status(500).json({ error: cleanupError
                    ? `Database error verifying deployment quota: ${capacityError.message}; cleanup failed: ${cleanupError.message}`
                    : `Database error verifying deployment quota: ${capacityError.message}` });
                const message = cleanupError ? `${result.error}; cleanup failed: ${cleanupError.message}` : result.error;
                res.status(result.status).json({ error: message });
            });
        }
        const sizeMb = Math.ceil((actualBytes / (1024 * 1024)) * 1000) / 1000;
        db.run(`INSERT INTO websites (user_id, subdomain, status, folder_path, size_mb)
                VALUES (?, ?, 'Live', ?, ?)`,
            [userId, subdomain, sitePath, sizeMb], function(insertError) {
                if (insertError) {
                    deployingUsers.delete(userId);
                    return fs.rm(sitePath, { recursive: true, force: true }, (cleanupError) => {
                        res.status(500).json({ error: cleanupError
                            ? `Database error saving deployment: ${insertError.message}; cleanup failed: ${cleanupError.message}`
                            : `Database error saving deployment: ${insertError.message}` });
                    });
                }
                db.run('UPDATE users SET storage_used = COALESCE(storage_used, 0) + ? WHERE id = ?',
                    [sizeMb, userId], function(updateError) {
                        deployingUsers.delete(userId);
                        if (updateError) {
                            db.run('DELETE FROM websites WHERE user_id = ? AND subdomain = ?', [userId, subdomain]);
                            return fs.rm(sitePath, { recursive: true, force: true }, (cleanupError) => {
                                res.status(500).json({ error: cleanupError
                                    ? `Database error updating storage usage: ${updateError.message}; cleanup failed: ${cleanupError.message}`
                                    : `Database error updating storage usage: ${updateError.message}` });
                            });
                        }
                        res.json({ message: 'Website deployed successfully!', subdomain });
                    });
            });
    });
}

// --- ROUTES ---

function getPaymentSettings(callback) {
    db.all("SELECT key, value FROM admin_settings WHERE key IN ('upi_id', 'upi_qr_url')", [], (error, rows) => {
        if (error) return callback(error);
        const settings = Object.fromEntries(rows.map(({ key, value }) => [key, value]));
        callback(null, {
            upiId: (process.env.UPI_ID || settings.upi_id || '').trim(),
            qrImageUrl: (process.env.UPI_QR_IMAGE_URL || settings.upi_qr_url || '').trim()
        });
    });
}

function requirePaymentConfiguration(req, res, next) {
    getPaymentSettings((error, settings) => {
        if (error) return res.status(500).json({ error: 'Could not verify payment instructions' });
        if (!settings.upiId) {
            return res.status(503).json({ error: 'Payment instructions are not configured. Please contact support.' });
        }
        next();
    });
}

app.get('/api/public/payment-settings', (req, res) => {
    getPaymentSettings((error, settings) => {
        if (error) return res.status(500).json({ error: `Database error loading payment instructions: ${error.message}` });
        res.json(settings);
    });
});

app.get('/api/csrf-token', authenticateToken, (req, res) => {
    const token = crypto.randomBytes(32).toString('hex');
    req.session = req.session || {};
    req.session.csrfToken = token;
    res.json({ csrfToken: token });
});

const csrfTokens = new Map();
function validateCsrfToken(req, res, next) {
    const token = req.headers['x-csrf-token'] || req.body._csrf;
    if (!token) {
        return res.status(403).json({ error: 'CSRF token required' });
    }
    const userId = req.user?.id;
    if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const userTokens = csrfTokens.get(userId) || [];
    if (!userTokens.includes(token)) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    next();
}

app.get('/api/plans', (req, res) => {
    db.all(`SELECT id, name, price, monthly_price, term_price, duration_months,
                   max_websites, max_websites * 15 AS storage_limit_mb, is_active
            FROM plans WHERE is_active = 1`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ plans: rows });
    });
});

app.post('/api/auth/signup', async (req, res) => {
    if (!checkAuthRateLimit(req)) {
        return res.status(429).json({ error: 'Too many signup attempts. Please try again later.' });
    }
    const { name, email, whatsapp_number, password, termsAccepted, privacyAcknowledged } = req.body;
    const cleanName = typeof name === 'string' ? name.trim() : '';
    const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
    const cleanPhone = typeof whatsapp_number === 'string' ? whatsapp_number.trim() : '';
    const address = optionalBillingAddress(req.body);
    if (!cleanName || cleanName.length > 100) {
        return res.status(400).json({ error: 'A name of 1 to 100 characters is required' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail) || cleanEmail.length > 254) {
        return res.status(400).json({ error: 'A valid email address is required' });
    }
    if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
        return res.status(400).json({ error: 'Password must be between 8 and 128 characters' });
    }
    if (!validWhatsappNumber(whatsapp_number)) {
        return res.status(400).json({ error: 'A valid WhatsApp number is required' });
    }
    if (!address) return res.status(400).json({ error: 'Address fields must be valid text values' });
    const termsVersion = typeof req.body.termsVersion === 'string' ? req.body.termsVersion.trim() : '';
    const privacyVersion = typeof req.body.privacyVersion === 'string' ? req.body.privacyVersion.trim() : '';
    if (termsAccepted !== true || privacyAcknowledged !== true) {
        return res.status(400).json({ error: 'Terms acceptance and Privacy notice acknowledgement are required' });
    }
    if (termsVersion.length > 100 || privacyVersion.length > 100) {
        return res.status(400).json({ error: 'Acceptance versions must be 100 characters or fewer' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = `INSERT INTO users
            (name, email, whatsapp_number, password_hash, terms_accepted_at, terms_version,
             privacy_acknowledged_at, privacy_version, address_line1, address_line2, city, state,
             postal_code, country)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?)`;
        db.run(sql, [cleanName, cleanEmail, cleanPhone, hashedPassword, termsVersion || null, privacyVersion || null,
            address.address_line1 || null, address.address_line2 || null, address.city || null, address.state || null,
            address.postal_code || null, address.country || null], function(err) {
            if (err) {
                if (err.code === 'SQLITE_CONSTRAINT') return res.status(409).json({ error: 'An account with this email already exists' });
                return res.status(500).json({ error: `Database error creating account: ${err.message}` });
            }
            const userId = this.lastID;
            const token = jwt.sign({ id: userId, email: cleanEmail, role: 'customer' }, JWT_SECRET, { expiresIn: '30d' });
            res.json({
                message: 'Account created successfully',
                userId,
                token,
                user: { id: userId, name: cleanName, email: cleanEmail, plan_status: 'Inactive' }
            });
        });
    } catch (err) {
        res.status(500).json({ error: "Internal server error" });
    }
});

function parseUserAgent(userAgent) {
    const ua = userAgent || '';
    let browser = 'Unknown';
    let os = 'Unknown';
    if (ua.includes('Edg/')) browser = 'Edge';
    else if (ua.includes('Chrome/')) browser = 'Chrome';
    else if (ua.includes('Firefox/')) browser = 'Firefox';
    else if (ua.includes('Safari/')) browser = 'Safari';
    if (ua.includes('Windows')) os = 'Windows';
    else if (ua.includes('Mac OS X') || ua.includes('macOS')) os = 'macOS';
    else if (ua.includes('Linux')) os = 'Linux';
    else if (ua.includes('Android')) os = 'Android';
    else if (ua.includes('iOS') || ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';
    return { browser, os };
}

function createUserSession(userId, req, callback) {
    const deviceId = crypto.randomUUID();
    const userAgent = req.headers['user-agent'] || '';
    const { browser, os } = parseUserAgent(userAgent);
    const ipHash = getHashedClientAddress(req);
    const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    db.run('UPDATE user_sessions SET is_current = 0 WHERE user_id = ?', [userId], (updateErr) => {
        if (updateErr) console.error('Failed to mark old sessions as not current:', updateErr.message);
        db.run(`INSERT INTO user_sessions (user_id, device_id, device_name, browser, os, ip_hash, user_agent, is_current, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)`,
            [userId, deviceId, `${browser} on ${os}`, browser, os, ipHash, userAgent, expiresAt],
            function(err) {
                callback(err, deviceId);
            });
    });
}

app.post('/api/auth/login', (req, res) => {
    if (!checkAuthRateLimit(req)) {
        return res.status(429).json({ error: 'Too many login attempts. Please try again later.' });
    }
    const { identifier, password } = req.body;
    const cleanIdentifier = typeof identifier === 'string' ? identifier.trim() : '';
    if (!cleanIdentifier || typeof password !== 'string') {
        return res.status(400).json({ error: 'Username/Email/Mobile and password are required' });
    }
    const isEmail = cleanIdentifier.includes('@');
    const isMobile = /^\d{10,15}$/.test(cleanIdentifier.replace(/\D/g, ''));
    let whereClause = 'email = ? COLLATE NOCASE';
    let params = [cleanIdentifier];
    if (isMobile) {
        whereClause = 'whatsapp_number = ?';
        params = [cleanIdentifier.replace(/\D/g, '')];
    } else if (!isEmail) {
        whereClause = 'name = ? COLLATE NOCASE';
    }
    db.get(`SELECT * FROM users WHERE ${whereClause}`, params, async (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(400).json({ error: "Invalid credentials" });

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) return res.status(400).json({ error: "Invalid credentials" });
        if (user.account_status !== 'Active') {
            return res.status(403).json({ error: 'This customer account is suspended. Contact support.' });
        }

        const token = jwt.sign({ id: user.id, email: user.email, role: 'customer' }, JWT_SECRET, { expiresIn: '30d' });
        createUserSession(user.id, req, (sessionErr, deviceId) => {
            if (sessionErr) console.error('Session creation failed:', sessionErr.message);
        });
        res.json({
            token,
            requiresLegalAcceptance: !user.terms_accepted_at || !user.privacy_acknowledged_at,
            user: { id: user.id, name: user.name, email: user.email, plan_status: user.plan_status }
        });
    });
});

app.post('/api/auth/forgot-password', (req, res) => {
    if (process.env.WHATSAPP_ENABLED !== 'true') {
        return res.status(503).json({ error: 'WhatsApp service not configured. Contact support.' });
    }
    const mobile = typeof req.body.mobile === 'string' ? req.body.mobile.trim().replace(/\D/g, '') : '';
    if (!mobile || mobile.length < 10 || mobile.length > 15) {
        return res.status(400).json({ error: 'A valid mobile number (10-15 digits) is required' });
    }
    checkOtpIpRateLimit(req, (limitError, allowed) => {
        if (limitError) return res.status(500).json({ error: `Database error checking OTP rate limit: ${limitError.message}` });
        if (!allowed) return res.status(429).json({ error: 'Password recovery request limit reached; try again later' });
    db.get('SELECT id, whatsapp_number FROM users WHERE whatsapp_number = ?', [mobile], (queryError, user) => {
        if (queryError) return res.status(500).json({ error: `Database error preparing OTP: ${queryError.message}` });
        if (!user) return res.json({ message: 'If an account exists for that mobile number, a WhatsApp verification code will be sent.' });
        db.get('SELECT * FROM password_reset_otps WHERE user_id = ?', [user.id], (otpQueryError, previous) => {
            if (otpQueryError) return res.status(500).json({ error: `Database error checking OTP rate limits: ${otpQueryError.message}` });
            const now = Date.now();
            const windowActive = previous && now - Date.parse(previous.request_window_started_at) < 60 * 60 * 1000;
            if (previous && Date.parse(previous.resend_after) > now) {
                return res.status(429).json({ error: 'Please wait before requesting another code' });
            }
            if (windowActive && previous.request_count >= 5) {
                return res.status(429).json({ error: 'Password recovery request limit reached; try again later' });
            }
            const otp = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
            const otpHash = hashOtp(user.id, otp);
            const windowStarted = windowActive ? previous.request_window_started_at : new Date(now).toISOString();
            const requestCount = windowActive ? previous.request_count + 1 : 1;
            const expiresAt = new Date(now + 5 * 60 * 1000).toISOString();
            const resendAfter = new Date(now + 60 * 1000).toISOString();
            db.run(`INSERT INTO password_reset_otps
                    (user_id, otp_hash, expires_at, resend_after, attempts, request_window_started_at, request_count, used_at)
                    VALUES (?, ?, ?, ?, 0, ?, ?, NULL)
                    ON CONFLICT(user_id) DO UPDATE SET otp_hash = excluded.otp_hash,
                      expires_at = excluded.expires_at, resend_after = excluded.resend_after,
                      attempts = 0, request_window_started_at = excluded.request_window_started_at,
                      request_count = excluded.request_count, used_at = NULL
                    WHERE datetime(password_reset_otps.resend_after) <= CURRENT_TIMESTAMP`,
                [user.id, otpHash, expiresAt, resendAfter, windowStarted, requestCount], async function(insertError) {
                    if (insertError) return res.status(500).json({ error: `Database error creating OTP: ${insertError.message}` });
                    if (this.changes !== 1) return res.status(429).json({ error: 'A code was just requested; wait before retrying' });
                    try {
                        await whatsapp.sendOTP(user.whatsapp_number, otp);
                        res.json({ message: 'A verification code has been sent to the WhatsApp number registered to this account.' });
                    } catch (sendError) {
                        db.run(`UPDATE password_reset_otps SET otp_hash = '', used_at = CURRENT_TIMESTAMP
                                WHERE user_id = ? AND otp_hash = ?`, [user.id, otpHash], (invalidateError) => {
                            if (invalidateError) {
                                console.error('Failed to invalidate an undelivered WhatsApp OTP:', invalidateError.message);
                                return res.status(500).json({
                                    error: 'WhatsApp delivery failed and the verification code could not be invalidated; contact support before retrying.'
                                });
                            }
                            res.status(502).json({ error: 'Unable to send the verification code. Please try again later.' });
                        });
                    }
                });
        });
        });
    });
});

app.post('/api/auth/reset-password', (req, res) => {
    if (!checkAuthRateLimit(req)) {
        return res.status(429).json({ error: 'Too many password reset attempts. Please try again later.' });
    }
    const mobile = typeof req.body.mobile === 'string' ? req.body.mobile.trim().replace(/\D/g, '') : '';
    const otp = typeof req.body.otp === 'string' ? req.body.otp.trim() : '';
    const newPassword = req.body.newPassword;
    if (!mobile || mobile.length < 10 || mobile.length > 15 || !/^\d{6}$/.test(otp)) {
        return res.status(400).json({ error: 'Mobile number or verification code is invalid or expired' });
    }
    if (typeof newPassword !== 'string' || newPassword.length < 8 || newPassword.length > 128) {
        return res.status(400).json({ error: 'New password must be between 8 and 128 characters' });
    }
    db.run('BEGIN IMMEDIATE', (beginError) => {
        if (beginError) return res.status(500).json({ error: `Database error starting password reset: ${beginError.message}` });
        db.get(`SELECT u.id, o.otp_hash, o.expires_at, o.attempts, o.used_at
                FROM users u LEFT JOIN password_reset_otps o ON o.user_id = u.id
                WHERE u.whatsapp_number = ?`, [mobile], (queryError, row) => {
            if (queryError) return db.run('ROLLBACK', () =>
                res.status(500).json({ error: `Database error validating OTP: ${queryError.message}` }));
            const invalid = !row || !row.otp_hash || row.used_at ||
                Date.parse(row.expires_at) <= Date.now() || row.attempts >= 5 ||
                !/^[a-f0-9]{64}$/.test(row.otp_hash) ||
                !crypto.timingSafeEqual(Buffer.from(hashOtp(row.id, otp), 'hex'), Buffer.from(row.otp_hash, 'hex'));
            if (invalid) {
                const finishInvalid = (attemptError) => {
                    if (attemptError) return db.run('ROLLBACK', () =>
                        res.status(500).json({ error: `Database error recording OTP attempt: ${attemptError.message}` }));
                    db.run('COMMIT', (commitError) => {
                    if (commitError) return res.status(500).json({ error: `Database error recording OTP attempt: ${commitError.message}` });
                    res.status(400).json({ error: 'Mobile number or verification code is invalid or expired' });
                    });
                };
                if (row && !row.used_at && Date.parse(row.expires_at) > Date.now() && row.attempts < 5) {
                    return db.run('UPDATE password_reset_otps SET attempts = attempts + 1 WHERE user_id = ?', [row.id], finishInvalid);
                }
                return finishInvalid();
            }
            bcrypt.hash(newPassword, 10).then((passwordHash) => {
                db.run('UPDATE users SET password_hash = ? WHERE id = ?', [passwordHash, row.id], function(updateError) {
                    if (updateError || this.changes !== 1) {
                        const errorMessage = updateError ? updateError.message : 'User not found';
                        return db.run('ROLLBACK', () => res.status(500).json({ error: `Database error updating password: ${errorMessage}` }));
                    }
                    db.run('UPDATE password_reset_otps SET used_at = CURRENT_TIMESTAMP WHERE user_id = ?', [row.id], (consumeError) => {
                        if (consumeError) return db.run('ROLLBACK', () =>
                            res.status(500).json({ error: `Database error consuming OTP: ${consumeError.message}` }));
                        db.run('COMMIT', (commitError) => {
                            if (commitError) return db.run('ROLLBACK', () =>
                                res.status(500).json({ error: `Database error saving password reset: ${commitError.message}` }));
                            res.json({ message: 'Password reset successfully' });
                        });
                    });
                });
            }).catch(() => db.run('ROLLBACK', () =>
                res.status(500).json({ error: 'Unable to reset password' })));
        });
    });
});

function submitPayment(userId, planId, utrNumber, screenshotUrl, termsVersion, options, res) {
    const removeScreenshot = () => {
        if (screenshotUrl) fs.unlink(path.join(PAYMENT_SCREENSHOTS_DIR, path.basename(screenshotUrl)), () => {});
    };
    const planIdNumber = Number(planId);
    if (!Number.isInteger(planIdNumber) || planIdNumber <= 0) {
        removeScreenshot();
        return res.status(400).json({ error: 'A valid active plan is required' });
    }
    db.get('SELECT * FROM plans WHERE id = ? AND is_active = 1', [planIdNumber], (planError, plan) => {
        if (planError) {
            removeScreenshot();
            return res.status(500).json({ error: `Database error validating plan: ${planError.message}` });
        }
        if (!plan) {
            removeScreenshot();
            return res.status(400).json({ error: 'A valid active plan is required' });
        }
        const durationMonths = options.durationMonths == null ? Number(plan.duration_months) : Number(options.durationMonths);
        const quantity = options.quantity == null ? 1 : Number(options.quantity);
        const firstPurchasePromo = options.firstPurchasePromo === true;
        if (!Number.isInteger(durationMonths) || durationMonths < 1 || durationMonths > 3 ||
            !Number.isInteger(Number(plan.duration_months)) || Number(plan.duration_months) < 1 ||
            Number(plan.duration_months) > 3 || !Number.isInteger(quantity) || quantity < 1 ||
            quantity > Math.max(1, Number(plan.max_websites)) ||
            (firstPurchasePromo && (durationMonths !== 1 || quantity !== 1))) {
            removeScreenshot();
            return res.status(400).json({ error: 'Plan duration or quantity is invalid' });
        }
        db.get(`SELECT u.first_purchase_promo_used, u.first_paid_at, u.plan_id, u.plan_status,
                       EXISTS(SELECT 1 FROM payments WHERE user_id = u.id AND status = 'Approved') AS has_approved_payment,
                       EXISTS(SELECT 1 FROM payments WHERE user_id = u.id AND status = 'Pending') AS has_pending_payment
                FROM users u WHERE u.id = ?`, [userId], (userError, user) => {
            if (userError) {
                removeScreenshot();
                return res.status(500).json({ error: `Database error checking payment eligibility: ${userError.message}` });
            }
            if (!user) {
                removeScreenshot();
                return res.status(404).json({ error: 'User not found' });
            }
            if (firstPurchasePromo && (user.first_purchase_promo_used || user.first_paid_at ||
                user.has_approved_payment || user.has_pending_payment ||
                (user.plan_id && user.plan_status !== 'Pending'))) {
                removeScreenshot();
                return res.status(409).json({ error: 'The first-purchase promotion is not available for this account' });
            }
            const monthlyPrice = Number(plan.monthly_price ?? plan.price);
            const termPrice = Number(plan.term_price ?? plan.price);
            const standardAmount = durationMonths === Number(plan.duration_months)
                ? termPrice
                : monthlyPrice * durationMonths;
            const subtotal = firstPurchasePromo ? 99 : standardAmount * quantity;
            if (!Number.isFinite(subtotal) || subtotal <= 0) {
                removeScreenshot();
                return res.status(400).json({ error: 'Plan pricing is not configured correctly' });
            }
            resolveCouponQuote(userId, options.couponCode, planIdNumber, subtotal, firstPurchasePromo, (couponError, quote) => {
                if (couponError) {
                    removeScreenshot();
                    return res.status(couponError.status).json({ error: couponError.message });
                }
                const amount = quote.amount;
                if (!Number.isFinite(amount) || amount <= 0) {
                    removeScreenshot();
                    return res.status(400).json({ error: 'Plan pricing is not configured correctly' });
                }
        db.run(
            `INSERT INTO payments
             (user_id, plan_id, utr_number, screenshot_url, status, terms_accepted_at, terms_version,
              quantity, duration_months, amount, is_first_purchase_promo, coupon_id, coupon_code,
              coupon_discount, plan_name,
              plan_monthly_price, plan_term_price, max_websites, storage_limit_mb)
             VALUES (?, ?, ?, ?, 'Pending', CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [userId, planIdNumber, utrNumber || '', screenshotUrl, termsVersion || null, quantity,
                durationMonths, amount, firstPurchasePromo ? 1 : 0, quote.coupon?.id || null,
                quote.coupon?.code || null, quote.discount, plan.name,
                monthlyPrice, termPrice, plan.max_websites, plan.storage_limit_mb],
            function(insertError) {
                if (insertError) {
                    removeScreenshot();
                    return res.status(500).json({ error: `Database error saving payment: ${insertError.message}` });
                }
                const paymentId = this.lastID;
                const saveCustomerPaymentState = () => db.run(
                    `UPDATE users SET utr_number = ?, payment_screenshot_url = ?,
                     plan_status = CASE
                       WHEN plan_status = 'Active' AND datetime(subscription_expires_at) > CURRENT_TIMESTAMP THEN plan_status
                       ELSE 'Pending' END
                     WHERE id = ?`,
                    [utrNumber || null, screenshotUrl, userId],
                    function(updateError) {
                        if (updateError || this.changes === 0) {
                            const errorMessage = updateError ? updateError.message : 'User not found';
                            db.run('DELETE FROM payments WHERE id = ?', [paymentId]);
                            removeScreenshot();
                            return res.status(updateError ? 500 : 404).json({
                                error: updateError ? `Database error updating payment status: ${errorMessage}` : errorMessage
                            });
                        }
                        res.json({ message: 'Payment submitted, waiting for admin approval' });
                    }
                );
                if (!quote.coupon) return saveCustomerPaymentState();
                db.run(`INSERT INTO coupon_redemptions
                        (coupon_id, user_id, payment_id, status, discount_amount)
                        SELECT ?, ?, ?, 'Pending', ?
                        WHERE EXISTS (
                          SELECT 1 FROM coupons c
                          WHERE c.id = ?
                            AND c.is_active = 1
                            AND (c.plan_id IS NULL OR c.plan_id = ?)
                            AND (c.starts_at IS NULL OR datetime(c.starts_at) <= CURRENT_TIMESTAMP)
                            AND (c.expires_at IS NULL OR datetime(c.expires_at) > CURRENT_TIMESTAMP)
                            AND (c.max_redemptions IS NULL OR
                              (SELECT COUNT(*) FROM coupon_redemptions r
                               WHERE r.coupon_id = c.id AND r.status IN ('Pending', 'Approved')) < c.max_redemptions)
                            AND (SELECT COUNT(*) FROM coupon_redemptions r
                                 WHERE r.coupon_id = c.id AND r.user_id = ?
                                   AND r.status IN ('Pending', 'Approved')) < c.per_user_limit
                        )`,
                    [quote.coupon.id, userId, paymentId, quote.discount,
                        quote.coupon.id, planIdNumber, userId],
                    function(redemptionError) {
                        if (redemptionError || this.changes !== 1) {
                            const message = redemptionError
                                ? `Database error reserving coupon: ${redemptionError.message}`
                                : 'Coupon has reached its redemption limit or expired';
                            return db.run('DELETE FROM payments WHERE id = ?', [paymentId], (deleteError) => {
                                if (deleteError) {
                                    console.error('Failed to roll back payment after coupon reservation error:', deleteError.message);
                                    return res.status(500).json({ error: 'Unable to reserve coupon or roll back payment' });
                                }
                                removeScreenshot();
                                res.status(redemptionError ? 500 : 409).json({ error: message });
                            });
                        }
                        saveCustomerPaymentState();
                    });
            }
        );
            });
        });
    });
}

function getTaxSettings(callback) {
    db.get(`SELECT 
                COALESCE((SELECT value FROM admin_settings WHERE key = 'service_tax_percent'), '3') AS service_tax,
                COALESCE((SELECT value FROM admin_settings WHERE key = 'dashboard_tax_percent'), '3') AS dashboard_tax
            `, [], (err, row) => {
        if (err) return callback(err);
        callback(null, {
            serviceTaxPercent: parseFloat(row.service_tax) || 3,
            dashboardTaxPercent: parseFloat(row.dashboard_tax) || 3
        });
    });
}

function calculatePaymentBreakdown(baseAmount, serviceTaxPercent, dashboardTaxPercent) {
    const serviceTax = Math.round(baseAmount * serviceTaxPercent / 100 * 100) / 100;
    const dashboardTax = Math.round(baseAmount * dashboardTaxPercent / 100 * 100) / 100;
    const total = Math.round((baseAmount + serviceTax + dashboardTax) * 100) / 100;
    return {
        baseAmount: Math.round(baseAmount * 100) / 100,
        serviceTax,
        dashboardTax,
        total
    };
}

function resolveCouponQuote(userId, rawCode, planId, subtotal, firstPurchasePromo, callback) {
    const code = typeof rawCode === 'string' ? rawCode.trim().toUpperCase() : '';
    if (!code) return callback(null, { amount: subtotal, discount: 0, coupon: null });
    if (firstPurchasePromo) {
        return callback({ status: 400, message: 'A coupon cannot be combined with the first-purchase offer' });
    }
    if (!/^[A-Z0-9_-]{3,40}$/.test(code)) {
        return callback({ status: 400, message: 'Coupon code is invalid' });
    }
    db.get(`SELECT id, code, discount_type, discount_value, max_discount, max_redemptions, per_user_limit, plan_id
            FROM coupons
            WHERE code = ? COLLATE NOCASE AND is_active = 1
              AND (starts_at IS NULL OR datetime(starts_at) <= CURRENT_TIMESTAMP)
              AND (expires_at IS NULL OR datetime(expires_at) > CURRENT_TIMESTAMP)`,
        [code], (couponError, coupon) => {
            if (couponError) return callback({ status: 500, message: `Database error validating coupon: ${couponError.message}` });
            if (!coupon) return callback({ status: 400, message: 'Coupon is invalid, inactive, or expired' });
            if (coupon.plan_id != null && Number(coupon.plan_id) !== Number(planId)) {
                return callback({ status: 400, message: 'Coupon is not valid for the selected plan' });
            }
            db.get(`SELECT
                      SUM(CASE WHEN status IN ('Pending', 'Approved') THEN 1 ELSE 0 END) AS total_uses,
                      SUM(CASE WHEN user_id = ? AND status IN ('Pending', 'Approved') THEN 1 ELSE 0 END) AS user_uses
                    FROM coupon_redemptions WHERE coupon_id = ?`,
                [userId, coupon.id], (usageError, usage) => {
                    if (usageError) return callback({ status: 500, message: `Database error checking coupon usage: ${usageError.message}` });
                    if (coupon.max_redemptions != null && Number(usage.total_uses || 0) >= Number(coupon.max_redemptions)) {
                        return callback({ status: 409, message: 'Coupon has reached its redemption limit' });
                    }
                    if (Number(usage.user_uses || 0) >= Number(coupon.per_user_limit)) {
                        return callback({ status: 409, message: 'This account has already used this coupon' });
                    }
                    const rawDiscount = coupon.discount_type === 'percent'
                        ? subtotal * Number(coupon.discount_value) / 100
                        : Number(coupon.discount_value);
                    const cappedDiscount = coupon.max_discount == null
                        ? rawDiscount
                        : Math.min(rawDiscount, Number(coupon.max_discount));
                    const discount = Math.min(subtotal, Math.round(cappedDiscount * 100) / 100);
                    if (!Number.isFinite(discount) || discount <= 0) {
                        return callback({ status: 400, message: 'Coupon discount is not configured correctly' });
                    }
                    callback(null, {
                        amount: Math.max(0, Math.round((subtotal - discount) * 100) / 100),
                        discount,
                        coupon: { id: coupon.id, code: coupon.code, planId }
                    });
                });
        });
}

app.get('/api/user/payments', authenticateToken, (req, res) => {
    const sql = `SELECT pay.id, pay.plan_id, COALESCE(pay.plan_name, p.name) AS plan_name,
                    COALESCE(pay.plan_term_price, p.term_price, p.price) AS plan_price,
                    NULLIF(pay.utr_number, '') AS utr_number, pay.status,
                    pay.quantity, pay.duration_months, pay.amount, pay.is_first_purchase_promo AS first_purchase_promo,
                    pay.coupon_code, pay.coupon_discount,
                    pay.created_at
                 FROM payments pay
                 LEFT JOIN plans p ON p.id = pay.plan_id
                 WHERE pay.user_id = ?
                 ORDER BY pay.created_at DESC, pay.id DESC`;
    db.all(sql, [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: `Database error loading payment history: ${err.message}` });
        res.json({ payments: rows });
    });
});

app.post('/api/user/payments', authenticateToken, paymentUpload.single('screenshot'), requirePaymentConfiguration, (req, res) => {
    const { planId, utrNumber, termsAccepted } = req.body;
    const termsVersion = typeof req.body.termsVersion === 'string' ? req.body.termsVersion.trim() : '';
    if (termsAccepted !== 'true') {
        return res.status(400).json({ error: 'Acceptance of Terms and Payments/Refunds is required' });
    }
    if (termsVersion.length > 100) {
        return res.status(400).json({ error: 'Terms version must be 100 characters or fewer' });
    }
    if (!req.file) return res.status(400).json({ error: 'A payment screenshot is required' });
    const cleanUtr = typeof utrNumber === 'string' ? utrNumber.trim() : '';
    if (!/^\d+$/.test(String(planId || '')) || (cleanUtr && !/^\d{12}$/.test(cleanUtr))) {
        return res.status(400).json({ error: 'A valid planId and optional 12-digit UTR number are required' });
    }
    const extension = inspectPaymentImage(req.file.buffer);
    if (!extension) return res.status(400).json({ error: 'Screenshot contents are not a supported image' });
    const filename = `${crypto.randomUUID()}${extension}`;
    const screenshotUrl = `/uploads/payment-screenshots/${filename}`;
    const screenshotPath = path.join(PAYMENT_SCREENSHOTS_DIR, filename);
    fs.writeFile(screenshotPath, req.file.buffer, (writeError) => {
        if (writeError) return res.status(500).json({ error: `Filesystem error saving payment screenshot: ${writeError.message}` });
        submitPayment(req.user.id, planId, cleanUtr || null, screenshotUrl, termsVersion, {
            durationMonths: req.body.durationMonths,
            quantity: req.body.quantity,
            firstPurchasePromo: req.body.firstPurchasePromo === 'true' || req.body.promo === 'true',
            couponCode: req.body.couponCode
        }, res);
    });
});

// Retain the original JSON endpoint for existing clients.
app.post('/api/user/payment', authenticateToken, requirePaymentConfiguration, (req, res) => {
    const { planId, utrNumber, termsAccepted } = req.body;
    const termsVersion = typeof req.body.termsVersion === 'string' ? req.body.termsVersion.trim() : '';
    if (termsAccepted !== true) {
        return res.status(400).json({ error: 'Acceptance of Terms and Payments/Refunds is required' });
    }
    if (termsVersion.length > 100) {
        return res.status(400).json({ error: 'Terms version must be 100 characters or fewer' });
    }
    if (!/^\d+$/.test(String(planId || '')) || !/^\d{12}$/.test(String(utrNumber || '').trim())) {
        return res.status(400).json({ error: 'A valid planId and 12-digit UTR number are required' });
    }
    submitPayment(req.user.id, planId, String(utrNumber).trim(), null, termsVersion, {
        durationMonths: req.body.durationMonths,
        quantity: req.body.quantity,
        firstPurchasePromo: req.body.firstPurchasePromo === true || req.body.promo === true,
        couponCode: req.body.couponCode
    }, res);
});

app.post('/api/user/coupons/validate', authenticateToken, (req, res) => {
    const planId = Number(req.body.planId);
    const durationMonths = Number(req.body.durationMonths);
    const quantity = req.body.quantity == null ? 1 : Number(req.body.quantity);
    const couponCode = typeof req.body.couponCode === 'string' ? req.body.couponCode.trim() : '';
    if (!Number.isInteger(planId) || planId <= 0 || !Number.isInteger(durationMonths) ||
        durationMonths < 1 || durationMonths > 3 || !Number.isInteger(quantity) || quantity < 1) {
        return res.status(400).json({ error: 'A valid plan, duration, and website count are required' });
    }
    db.get('SELECT * FROM plans WHERE id = ? AND is_active = 1', [planId], (planError, plan) => {
        if (planError) return res.status(500).json({ error: `Database error validating plan: ${planError.message}` });
        if (!plan || quantity > Number(plan.max_websites)) return res.status(400).json({ error: 'Plan or website count is invalid' });
        const unitPrice = durationMonths === Number(plan.duration_months)
            ? Number(plan.term_price ?? plan.price)
            : Number(plan.monthly_price ?? plan.price) * durationMonths;
        const subtotal = unitPrice * quantity;
        if (!Number.isFinite(subtotal) || subtotal <= 0) return res.status(400).json({ error: 'Plan pricing is not configured correctly' });
        resolveCouponQuote(req.user.id, couponCode, planId, subtotal, false, (couponError, quote) => {
            if (couponError) return res.status(couponError.status).json({ error: couponError.message });
            getTaxSettings((taxErr, taxes) => {
                if (taxErr) return res.status(500).json({ error: 'Could not load tax settings' });
                const breakdown = calculatePaymentBreakdown(quote.amount, taxes.serviceTaxPercent, taxes.dashboardTaxPercent);
                res.json({
                    code: quote.coupon?.code || null,
                    subtotal,
                    discount: quote.discount,
                    amount: quote.amount,
                    ...breakdown,
                    serviceTaxPercent: taxes.serviceTaxPercent,
                    dashboardTaxPercent: taxes.dashboardTaxPercent
                });
            });
        });
    });
});

app.post('/api/user/payment/calculate', authenticateToken, (req, res) => {
    const planId = Number(req.body.planId);
    const durationMonths = Number(req.body.durationMonths);
    const quantity = req.body.quantity == null ? 1 : Number(req.body.quantity);
    const couponCode = typeof req.body.couponCode === 'string' ? req.body.couponCode.trim() : '';
    const firstPurchasePromo = req.body.firstPurchasePromo === true;
    if (!Number.isInteger(planId) || planId <= 0 || !Number.isInteger(durationMonths) ||
        durationMonths < 1 || durationMonths > 3 || !Number.isInteger(quantity) || quantity < 1) {
        return res.status(400).json({ error: 'A valid plan, duration, and website count are required' });
    }
    db.get('SELECT * FROM plans WHERE id = ? AND is_active = 1', [planId], (planError, plan) => {
        if (planError) return res.status(500).json({ error: `Database error validating plan: ${planError.message}` });
        if (!plan || quantity > Number(plan.max_websites)) return res.status(400).json({ error: 'Plan or website count is invalid' });
        const unitPrice = durationMonths === Number(plan.duration_months)
            ? Number(plan.term_price ?? plan.price)
            : Number(plan.monthly_price ?? plan.price) * durationMonths;
        const subtotal = unitPrice * quantity;
        if (!Number.isFinite(subtotal) || subtotal <= 0) return res.status(400).json({ error: 'Plan pricing is not configured correctly' });
        getTaxSettings((taxErr, taxes) => {
            if (taxErr) return res.status(500).json({ error: 'Could not load tax settings' });
            if (!couponCode && !firstPurchasePromo) {
                const breakdown = calculatePaymentBreakdown(subtotal, taxes.serviceTaxPercent, taxes.dashboardTaxPercent);
                return res.json({
                    subtotal,
                    discount: 0,
                    amount: subtotal,
                    ...breakdown,
                    serviceTaxPercent: taxes.serviceTaxPercent,
                    dashboardTaxPercent: taxes.dashboardTaxPercent,
                    plan: { id: plan.id, name: plan.name, duration_months: plan.duration_months, max_websites: plan.max_websites }
                });
            }
            resolveCouponQuote(req.user.id, couponCode, planId, subtotal, firstPurchasePromo, (couponError, quote) => {
                if (couponError) return res.status(couponError.status).json({ error: couponError.message });
                const breakdown = calculatePaymentBreakdown(quote.amount, taxes.serviceTaxPercent, taxes.dashboardTaxPercent);
                res.json({
                    subtotal,
                    discount: quote.discount,
                    amount: quote.amount,
                    ...breakdown,
                    serviceTaxPercent: taxes.serviceTaxPercent,
                    dashboardTaxPercent: taxes.dashboardTaxPercent,
                    coupon: quote.coupon ? { code: quote.coupon.code } : null,
                    firstPurchasePromo,
                    plan: { id: plan.id, name: plan.name, duration_months: plan.duration_months, max_websites: plan.max_websites }
                });
            });
        });
    });
});

app.post('/api/user/onboarding/accept-legal', authenticateToken, (req, res) => {
    const { termsAccepted, privacyAcknowledged } = req.body;
    const termsVersion = typeof req.body.termsVersion === 'string' ? req.body.termsVersion.trim() : '';
    const privacyVersion = typeof req.body.privacyVersion === 'string' ? req.body.privacyVersion.trim() : '';
    if (termsAccepted !== true || privacyAcknowledged !== true) {
        return res.status(400).json({ error: 'Accept the Terms of Service and acknowledge the Privacy Notice to continue' });
    }
    if (!termsVersion || termsVersion.length > 100 || !privacyVersion || privacyVersion.length > 100) {
        return res.status(400).json({ error: 'Valid policy versions are required' });
    }
    db.run(`UPDATE users SET terms_accepted_at = COALESCE(terms_accepted_at, CURRENT_TIMESTAMP),
            terms_version = COALESCE(terms_version, ?),
            privacy_acknowledged_at = COALESCE(privacy_acknowledged_at, CURRENT_TIMESTAMP),
            privacy_version = COALESCE(privacy_version, ?)
            WHERE id = ?`,
        [termsVersion, privacyVersion, req.user.id], function(error) {
            if (error) return res.status(500).json({ error: `Database error saving policy acceptance: ${error.message}` });
            if (this.changes !== 1) return res.status(404).json({ error: 'Customer account not found' });
            res.json({ message: 'Policy acceptance saved' });
        });
});

app.get('/api/user/profile', authenticateToken, (req, res) => {
    const sql = `SELECT u.id, u.name, u.email, u.whatsapp_number, u.plan_id, u.plan_status, u.storage_used,
                 u.address_line1, u.address_line2, u.city, u.state, u.postal_code, u.country,
                 u.customer_type, u.student_institute, u.student_course,
                 u.occupation, u.organization, u.hosting_purpose, u.referral_source, u.referral_details,
                 u.onboarding_step, u.onboarding_completed_at,
                 u.subscription_expires_at,
                 p.name as plan_name, p.price as plan_price,
                 COALESCE(p.monthly_price, p.price) AS plan_monthly_price, p.storage_limit_mb,
                 COALESCE(u.subscription_max_websites, p.max_websites) AS max_websites
                 FROM users u LEFT JOIN plans p ON u.plan_id = p.id WHERE u.id = ?`;
    db.get(sql, [req.user.id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ user: row });
    });
});

app.get('/api/user/sessions', authenticateToken, (req, res) => {
    db.all(`SELECT id, device_id, device_name, browser, os, ip_hash, is_current, created_at, last_activity_at, expires_at
            FROM user_sessions WHERE user_id = ? ORDER BY is_current DESC, last_activity_at DESC`,
        [req.user.id], (err, rows) => {
            if (err) return res.status(500).json({ error: `Database error loading sessions: ${err.message}` });
            res.json({ sessions: rows });
        });
});

app.delete('/api/user/sessions/:sessionId', authenticateToken, (req, res) => {
    const sessionId = Number(req.params.sessionId);
    if (!Number.isInteger(sessionId) || sessionId <= 0) return res.status(400).json({ error: 'Invalid session ID' });
    db.get('SELECT id, is_current FROM user_sessions WHERE id = ? AND user_id = ?', [sessionId, req.user.id], (err, session) => {
        if (err) return res.status(500).json({ error: `Database error loading session: ${err.message}` });
        if (!session) return res.status(404).json({ error: 'Session not found' });
        if (session.is_current) return res.status(400).json({ error: 'Cannot revoke current session' });
        db.run('DELETE FROM user_sessions WHERE id = ? AND user_id = ?', [sessionId, req.user.id], function(deleteError) {
            if (deleteError) return res.status(500).json({ error: `Database error revoking session: ${deleteError.message}` });
            res.json({ message: 'Session revoked successfully' });
        });
    });
});

app.delete('/api/user/sessions', authenticateToken, (req, res) => {
    db.run('DELETE FROM user_sessions WHERE user_id = ? AND is_current = 0', [req.user.id], function(err) {
        if (err) return res.status(500).json({ error: `Database error revoking sessions: ${err.message}` });
        res.json({ message: 'All other sessions revoked', revokedCount: this.changes });
    });
});

app.patch('/api/user/profile', authenticateToken, (req, res) => {
        const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
        const whatsappNumber = typeof req.body.whatsapp_number === 'string' ? req.body.whatsapp_number.trim() : '';
        const address = optionalBillingAddress(req.body);
        if (!name || name.length > 100 || whatsappNumber.length > 32 || !validWhatsappNumber(whatsappNumber)) {
            return res.status(400).json({ error: 'Name and WhatsApp number are required and must be valid' });
        }
        if (!address) return res.status(400).json({ error: 'Address fields must be valid text values' });
        db.run(`UPDATE users SET name = ?, whatsapp_number = ?, address_line1 = ?, address_line2 = ?,
                city = ?, state = ?, postal_code = ?, country = ? WHERE id = ?`,
            [name, whatsappNumber, address.address_line1 || null, address.address_line2 || null,
                address.city || null, address.state || null, address.postal_code || null,
                address.country || null, req.user.id], function(err) {
                if (err) return res.status(500).json({ error: `Database error updating profile: ${err.message}` });
                if (!this.changes) return res.status(404).json({ error: 'User not found' });
                db.get(`SELECT u.id, u.name, u.email, u.whatsapp_number, u.plan_id, u.plan_status, u.storage_used,
                            u.address_line1, u.address_line2, u.city, u.state, u.postal_code, u.country,
                            u.customer_type, u.student_institute, u.student_course,
                            u.occupation, u.organization, u.hosting_purpose, u.referral_source, u.referral_details,
                            u.onboarding_step, u.onboarding_completed_at,
                            u.subscription_expires_at,
                            p.name AS plan_name, p.price AS plan_price,
                            COALESCE(p.monthly_price, p.price) AS plan_monthly_price, p.storage_limit_mb,
                            COALESCE(u.subscription_max_websites, p.max_websites) AS max_websites
                        FROM users u LEFT JOIN plans p ON p.id = u.plan_id WHERE u.id = ?`,
                    [req.user.id], (queryError, user) => {
                    if (queryError) return res.status(500).json({ error: `Database error loading profile: ${queryError.message}` });
                    res.json({ user });
                });
            });
    });

app.patch('/api/user/onboarding', authenticateToken, (req, res) => {
    const step = Number(req.body.step);
    const skip = req.body.skip === true;
    if (!Number.isInteger(step) || step < 1 || step > 3 || (req.body.skip != null && typeof req.body.skip !== 'boolean')) {
        return res.status(400).json({ error: 'A valid onboarding step is required' });
    }
    const textField = (key, limit) => {
        if (req.body[key] == null) return '';
        if (typeof req.body[key] !== 'string' || req.body[key].trim().length > limit) return null;
        return req.body[key].trim();
    };
    const updates = [];
    const params = [];
    const addField = (key, limit) => {
        const value = textField(key, limit);
        if (value === null) return false;
        updates.push(`${key} = ?`);
        params.push(value || null);
        return true;
    };
    if (!skip && step === 1) {
        for (const [key, limit] of [
            ['address_line1', 200], ['address_line2', 200], ['city', 100],
            ['state', 100], ['postal_code', 32], ['country', 100]
        ]) {
            if (!addField(key, limit)) return res.status(400).json({ error: `The ${key.replaceAll('_', ' ')} value is invalid` });
        }
    }
    if (!skip && step === 2) {
        for (const [key, limit] of [
            ['occupation', 100], ['organization', 160], ['hosting_purpose', 160],
            ['student_institute', 160], ['student_course', 160]
        ]) {
            if (!addField(key, limit)) return res.status(400).json({ error: `The ${key.replaceAll('_', ' ')} value is invalid` });
        }
        const occupation = textField('occupation', 100);
        if (occupation) {
            updates.push('customer_type = ?');
            params.push(occupation === 'Student' ? 'Student' : 'Customer');
        }
    }
    if (!skip && step === 3) {
        const allowedSources = new Set([
            'Search engine', 'Social media', 'Friend or colleague', 'School or college',
            'Online community', 'Other'
        ]);
        const source = textField('referral_source', 100);
        if (source === null || (source && !allowedSources.has(source))) {
            return res.status(400).json({ error: 'Select a valid option for where you heard about us' });
        }
        const details = textField('referral_details', 200);
        if (details === null) return res.status(400).json({ error: 'Referral details must be 200 characters or fewer' });
        updates.push('referral_source = ?', 'referral_details = ?');
        params.push(source || null, details || null);
    }
    updates.push('onboarding_step = MAX(onboarding_step, ?)');
    params.push(step);
    if (step === 3) updates.push('onboarding_completed_at = COALESCE(onboarding_completed_at, CURRENT_TIMESTAMP)');
    params.push(req.user.id);
    db.run(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params, function(error) {
        if (error) return res.status(500).json({ error: `Database error saving onboarding details: ${error.message}` });
        if (this.changes !== 1) return res.status(404).json({ error: 'User not found' });
        res.json({ message: 'Onboarding step saved', step, completed: step === 3 });
    });
});

app.post('/api/user/password', authenticateToken, (req, res) => {
        const { currentPassword, newPassword } = req.body;
        if (typeof currentPassword !== 'string' || typeof newPassword !== 'string' ||
            newPassword.length < 8 || newPassword.length > 128) {
            return res.status(400).json({ error: 'Current password and a new password of at least 8 characters are required' });
        }
        db.get('SELECT password_hash FROM users WHERE id = ?', [req.user.id], async (err, user) => {
            if (err) return res.status(500).json({ error: `Database error verifying password: ${err.message}` });
            if (!user) return res.status(404).json({ error: 'User not found' });
            try {
                if (!await bcrypt.compare(currentPassword, user.password_hash)) {
                    return res.status(400).json({ error: 'Current password is incorrect' });
                }
                const passwordHash = await bcrypt.hash(newPassword, 10);
                db.run('UPDATE users SET password_hash = ? WHERE id = ?', [passwordHash, req.user.id], function(updateError) {
                    if (updateError) return res.status(500).json({ error: `Database error updating password: ${updateError.message}` });
                    res.json({ message: 'Password updated successfully' });
                });
            } catch (hashError) {
                res.status(500).json({ error: 'Unable to update password' });
            }
        });
    });

app.get('/api/user/support-tickets', authenticateToken, (req, res) => {
        db.all(`SELECT id, type, subject, message, category, status, created_at
                FROM support_tickets WHERE user_id = ? ORDER BY created_at DESC, id DESC`,
            [req.user.id], (err, rows) => {
                if (err) return res.status(500).json({ error: `Database error loading support requests: ${err.message}` });
                res.json({ tickets: rows });
            });
    });

app.post('/api/user/support-tickets', authenticateToken, (req, res) => {
        const { type, category } = req.body;
        const subject = typeof req.body.subject === 'string' ? req.body.subject.trim() : '';
        const message = typeof req.body.message === 'string' ? req.body.message.trim() : '';
        const normalizedCategory = typeof category === 'string' ? category.trim() : '';
        if (!['issue', 'feedback'].includes(type) || !subject || subject.length > 200 ||
            !message || message.length > 10000 || normalizedCategory.length > 100 ||
            (category != null && typeof category !== 'string')) {
            return res.status(400).json({ error: 'A valid type, subject, and message are required' });
        }
        db.run(`INSERT INTO support_tickets (user_id, type, subject, message, category)
                VALUES (?, ?, ?, ?, ?)`,
            [req.user.id, type, subject, message, normalizedCategory || null], function(err) {
                if (err) return res.status(500).json({ error: `Database error saving support request: ${err.message}` });
                db.get(`SELECT id, type, subject, message, category, status, created_at
                        FROM support_tickets WHERE id = ? AND user_id = ?`,
                    [this.lastID, req.user.id], (queryError, ticket) => {
                        if (queryError) return res.status(500).json({ error: `Database error loading support request: ${queryError.message}` });
                        res.status(201).json({ ticket });
            });
    });
});

app.get('/api/user/announcements', authenticateToken, (req, res) => {
    db.all(`SELECT a.id, a.type, a.severity, a.title, a.message, a.link_url,
                   a.starts_at, a.expires_at, a.created_at,
                   CASE WHEN r.announcement_id IS NULL THEN 0 ELSE 1 END AS is_read
            FROM announcements a
            LEFT JOIN announcement_reads r ON r.announcement_id = a.id AND r.user_id = ?
            WHERE a.is_active = 1
              AND (a.starts_at IS NULL OR datetime(a.starts_at) <= CURRENT_TIMESTAMP)
              AND (a.expires_at IS NULL OR datetime(a.expires_at) > CURRENT_TIMESTAMP)
              AND a.type IN ('notification', 'both')
            ORDER BY a.created_at DESC, a.id DESC`,
        [req.user.id], (error, rows) => {
            if (error) return res.status(500).json({ error: `Database error loading notifications: ${error.message}` });
            res.json({ announcements: rows });
        });
});

app.get('/api/user/banners', authenticateToken, (req, res) => {
    db.all(`SELECT id, severity, title, message, link_url, starts_at, expires_at, created_at
            FROM announcements
            WHERE is_active = 1
              AND (starts_at IS NULL OR datetime(starts_at) <= CURRENT_TIMESTAMP)
              AND (expires_at IS NULL OR datetime(expires_at) > CURRENT_TIMESTAMP)
              AND type IN ('banner', 'both')
            ORDER BY created_at DESC, id DESC`,
        [], (error, rows) => {
            if (error) return res.status(500).json({ error: `Database error loading banners: ${error.message}` });
            res.json({ banners: rows });
        });
});

app.post('/api/user/announcements/:id/read', authenticateToken, (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid notification ID' });
    db.get(`SELECT id FROM announcements WHERE id = ? AND is_active = 1
            AND type IN ('notification', 'both')
            AND (starts_at IS NULL OR datetime(starts_at) <= CURRENT_TIMESTAMP)
            AND (expires_at IS NULL OR datetime(expires_at) > CURRENT_TIMESTAMP)`,
        [id], (queryError, announcement) => {
            if (queryError) return res.status(500).json({ error: `Database error validating notification: ${queryError.message}` });
            if (!announcement) return res.status(404).json({ error: 'Notification not found' });
            db.run(`INSERT OR IGNORE INTO announcement_reads (announcement_id, user_id)
                    VALUES (?, ?)`, [id, req.user.id], (insertError) => {
                if (insertError) return res.status(500).json({ error: `Database error marking notification read: ${insertError.message}` });
                res.json({ message: 'Notification marked as read' });
            });
        });
});

app.get('/api/user/dashboard', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const profileSql = `SELECT u.id, u.name, u.email, u.whatsapp_number, u.plan_id, u.plan_status, u.storage_used,
                         p.name as plan_name, p.price as plan_price,
                         COALESCE(p.monthly_price, p.price) AS plan_monthly_price, p.storage_limit_mb,
                         COALESCE(u.subscription_max_websites, p.max_websites) AS max_websites,
                         u.subscription_expires_at
                         FROM users u LEFT JOIN plans p ON u.plan_id = p.id WHERE u.id = ?`;
    
    db.get(profileSql, [userId], (err, profile) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!profile) return res.status(404).json({ error: "User not found" });

        db.all("SELECT * FROM websites WHERE user_id = ? ORDER BY created_at DESC", [userId], (err, websites) => {
            if (err) return res.status(500).json({ error: err.message });
            
            let totalSizeMb = 0;
            websites.forEach(w => { totalSizeMb += w.size_mb || 0; });

            const activeWebsites = websites.filter(w => w.status === 'Live').length;
            const inactiveWebsites = websites.filter(w => w.status !== 'Live').length;
            const storageLimit = profile.storage_limit_mb || 0;
            const remaining = Math.max(storageLimit - totalSizeMb, 0);

            if (Math.abs(totalSizeMb - (profile.storage_used || 0)) > 0.1) {
                db.run("UPDATE users SET storage_used = ? WHERE id = ?", [totalSizeMb, userId]);
            }

            res.json({
                profile: {
                    ...profile,
                    storage_used: totalSizeMb
                },
                websites,
                stats: {
                    storage_used_mb: parseFloat(totalSizeMb.toFixed(1)),
                    storage_limit_mb: storageLimit,
                    storage_percent: storageLimit > 0 ? parseFloat(((totalSizeMb / storageLimit) * 100).toFixed(0)) : 0,
                    storage_remaining_mb: parseFloat(remaining.toFixed(1)),
                    total_websites: websites.length,
                    active_websites: activeWebsites,
                    inactive_websites: inactiveWebsites,
                    max_websites: profile.max_websites || 0,
                    remaining_websites: Math.max((profile.max_websites || 0) - websites.length, 0),
                    websites_percent: profile.max_websites > 0 ? parseFloat(((websites.length / profile.max_websites) * 100).toFixed(0)) : 0
                }
            });
        });
    });
});

app.get('/api/user/websites', authenticateToken, (req, res) => {
    db.all("SELECT * FROM websites WHERE user_id = ? ORDER BY created_at DESC", [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ websites: rows });
    });
});

app.post('/api/user/check-subdomain', authenticateToken, (req, res) => {
    const { subdomain } = req.body;
    if (!validSubdomain(subdomain)) return res.status(400).json({ error: 'Invalid subdomain' });
    db.get("SELECT id FROM websites WHERE subdomain = ?", [subdomain], (err, row) => {
        if (err) return res.status(500).json({ error: `Database error checking subdomain: ${err.message}` });
        if (row) return res.json({ available: false });
        res.json({ available: true });
    });
});

app.post('/api/user/upload-zip', authenticateToken, upload.single('file'), (req, res) => {
    const { subdomain } = req.body;
    if (!req.file || !subdomain) {
        return res.status(400).json({ error: "Missing file or subdomain" });
    }
    let entries;
    let totalBytes = 0;
    try {
        const zip = new AdmZip(req.file.buffer);
        entries = zip.getEntries();
        if (!entries.length || entries.length > 10000) throw new Error('ZIP must contain between 1 and 10,000 entries');
        for (const entry of entries) {
            const entryName = entry.entryName.replace(/\/$/, '');
            if (!entryName) continue;
            if (!safeUploadPath(HOSTING_DIR, entryName)) throw new Error(`Unsafe or prohibited ZIP entry: ${entry.entryName}`);
            const unixMode = (entry.header.attr >>> 16) & 0xf000;
            if (unixMode === 0xa000) throw new Error(`Symbolic links are not allowed: ${entry.entryName}`);
            if (!entry.isDirectory) {
                const size = Number(entry.header.size);
                if (!Number.isSafeInteger(size) || size < 0) throw new Error(`Invalid ZIP entry size: ${entry.entryName}`);
                totalBytes += size;
                if (totalBytes > MAX_DEPLOYMENT_BYTES) throw new Error('ZIP extracted size exceeds the maximum permitted size');
            }
        }
    } catch (error) {
        return res.status(400).json({ error: `Invalid ZIP archive: ${error.message}` });
    }

    beginDeployment(req.user.id, subdomain, totalBytes, res, (userSitePath, maxUploadBytes) => {
        let created = false;
        try {
            fs.mkdirSync(userSitePath, { recursive: false });
            created = true;
            let extractedBytes = 0;
            for (const entry of entries) {
                const name = entry.entryName.replace(/\/$/, '');
                if (!name) continue;
                const destination = safeUploadPath(userSitePath, name);
                if (!destination) throw new Error(`Unsafe ZIP entry: ${entry.entryName}`);
                if (entry.isDirectory) {
                    fs.mkdirSync(destination, { recursive: true });
                    continue;
                }
                const content = entry.getData();
                if (content.length !== Number(entry.header.size) || content.length > MAX_DEPLOYMENT_BYTES) {
                    throw new Error(`Invalid extracted ZIP entry: ${entry.entryName}`);
                }
                if (prohibitedContent(content)) throw new Error(`Executable or script content is not allowed: ${entry.entryName}`);
                extractedBytes += content.length;
                if (extractedBytes > maxUploadBytes) {
                    throw new Error('Extracted ZIP size exceeds the active plan storage quota');
                }
                fs.mkdirSync(path.dirname(destination), { recursive: true });
                fs.writeFileSync(destination, content, { flag: 'wx' });
            }
            finishDeployment(req.user.id, subdomain, userSitePath, res);
        } catch (error) {
            deployingUsers.delete(req.user.id);
            if (!created) return res.status(500).json({ error: `Filesystem error creating deployment: ${error.message}` });
            fs.rm(userSitePath, { recursive: true, force: true }, (cleanupError) => {
                res.status(400).json({ error: cleanupError
                    ? `Failed to extract ZIP: ${error.message}; cleanup failed: ${cleanupError.message}`
                    : `Failed to extract ZIP: ${error.message}` });
            });
        }
    });
});

app.post('/api/user/upload-folder', authenticateToken, upload.array('files', 500), (req, res) => {
    const { subdomain } = req.body;
    if (!req.files || req.files.length === 0 || !subdomain) {
        return res.status(400).json({ error: "Missing files or subdomain" });
    }
    let totalBytes = 0;
    const normalizedFiles = [];
    const seenPaths = new Set();
    for (const file of req.files) {
        const relativePath = file.originalname;
        const destination = safeUploadPath(HOSTING_DIR, relativePath);
        if (!destination || seenPaths.has(relativePath)) {
            return res.status(400).json({ error: `Unsafe, prohibited, or duplicate upload path: ${relativePath}` });
        }
        if (prohibitedContent(file.buffer)) {
            return res.status(400).json({ error: `Executable or script content is not allowed: ${relativePath}` });
        }
        seenPaths.add(relativePath);
        totalBytes += file.size;
        normalizedFiles.push({ relativePath, buffer: file.buffer });
    }
    if (totalBytes > MAX_DEPLOYMENT_BYTES) {
        return res.status(413).json({ error: 'Upload exceeds the maximum permitted deployment size' });
    }
    beginDeployment(req.user.id, subdomain, totalBytes, res, (userSitePath) => {
        let created = false;
        try {
            fs.mkdirSync(userSitePath, { recursive: false });
            created = true;
            for (const file of normalizedFiles) {
                const destination = safeUploadPath(userSitePath, file.relativePath);
                if (!destination) throw new Error(`Unsafe upload path: ${file.relativePath}`);
                fs.mkdirSync(path.dirname(destination), { recursive: true });
                fs.writeFileSync(destination, file.buffer, { flag: 'wx' });
            }
            finishDeployment(req.user.id, subdomain, userSitePath, res);
        } catch (error) {
            deployingUsers.delete(req.user.id);
            if (!created) return res.status(500).json({ error: `Filesystem error creating deployment: ${error.message}` });
            fs.rm(userSitePath, { recursive: true, force: true }, (cleanupError) => {
                res.status(500).json({ error: cleanupError
                    ? `Filesystem error processing upload: ${error.message}; cleanup failed: ${cleanupError.message}`
                    : `Filesystem error processing upload: ${error.message}` });
            });
        }
    });
});

app.post('/api/user/toggle-website', authenticateToken, (req, res) => {
    const { websiteId } = req.body;
    db.get("SELECT * FROM websites WHERE id = ? AND user_id = ?", [websiteId, req.user.id], (err, site) => {
        if (err) return res.status(500).json({ error: `Database error loading website: ${err.message}` });
        if (!site) return res.status(404).json({ error: "Website not found" });
        const newStatus = site.status === 'Live' ? 'Offline' : 'Live';
        const livePath = ownedSitePath(HOSTING_DIR, site.subdomain);
        const offlinePath = ownedSitePath(OFFLINE_DIR, site.subdomain);
        if (!livePath || !offlinePath) return res.status(400).json({ error: 'Website path is invalid' });
        const sourcePath = newStatus === 'Offline'
            ? (fs.existsSync(livePath) ? livePath : null)
            : (fs.existsSync(offlinePath) ? offlinePath : null);
        const destinationPath = newStatus === 'Offline' ? offlinePath : livePath;
        const alreadyAtDestination = newStatus === 'Offline'
            ? (!sourcePath && fs.existsSync(offlinePath))
            : (!sourcePath && fs.existsSync(livePath));
        if (!sourcePath && !alreadyAtDestination) {
            return res.status(500).json({ error: 'Filesystem error: website directory is missing from both hosting locations' });
        }
        const savePublicationState = (rollbackPath) => {
            db.run("UPDATE websites SET status = ?, folder_path = ? WHERE id = ? AND user_id = ?",
                [newStatus, destinationPath, websiteId, req.user.id], function(updateError) {
                    if (updateError || this.changes !== 1) {
                        const databaseError = updateError
                            ? updateError.message
                            : 'Website record changed before publication state could be saved';
                        const respond = (rollbackError) => {
                            const rollbackMessage = rollbackError
                                ? `; filesystem rollback failed: ${rollbackError.message}`
                                : '';
                            res.status(updateError ? 500 : 409).json({
                                error: `Database error updating website publication: ${databaseError}${rollbackMessage}`
                            });
                        };
                        if (!rollbackPath) return respond(null);
                        return fs.rename(destinationPath, rollbackPath, respond);
                    }
                    res.json({ message: `Website is now ${newStatus}`, status: newStatus });
                });
        };
        if (alreadyAtDestination) {
            return savePublicationState(null);
        }
        fs.access(destinationPath, fs.constants.F_OK, (destinationError) => {
            if (!destinationError) return res.status(409).json({ error: 'Website destination path already exists' });
            if (destinationError.code !== 'ENOENT') {
                return res.status(500).json({ error: `Filesystem error checking website destination: ${destinationError.message}` });
            }
            fs.rename(sourcePath, destinationPath, (moveError) => {
                    if (moveError) return res.status(500).json({ error: `Filesystem error changing website publication: ${moveError.message}` });
                    savePublicationState(sourcePath);
            });
        });
    });
});

app.delete('/api/user/websites/:id', authenticateToken, (req, res) => {
    db.get("SELECT * FROM websites WHERE id = ? AND user_id = ?", [req.params.id, req.user.id], (err, site) => {
        if (err) return res.status(500).json({ error: `Database error loading website: ${err.message}` });
        if (!site) return res.status(404).json({ error: "Website not found" });
        const livePath = ownedSitePath(HOSTING_DIR, site.subdomain);
        const offlinePath = ownedSitePath(OFFLINE_DIR, site.subdomain);
        if (!livePath || !offlinePath ||
            ![livePath, offlinePath].includes(path.resolve(site.folder_path))) {
            return res.status(400).json({ error: 'Website path is invalid' });
        }
        Promise.all([livePath, offlinePath].map((sitePath) =>
            fs.promises.rm(sitePath, { recursive: true, force: true })
        )).then(() => {
            const sizeMb = site.size_mb || 0;
            db.run("DELETE FROM websites WHERE id = ? AND user_id = ?", [req.params.id, req.user.id], function(deleteError) {
                if (deleteError || this.changes !== 1) {
                    return res.status(deleteError ? 500 : 409).json({
                        error: deleteError
                            ? `Database error deleting website: ${deleteError.message}`
                            : 'Website record changed before deletion'
                    });
                }
                db.run("UPDATE users SET storage_used = MAX(storage_used - ?, 0) WHERE id = ?",
                    [sizeMb, req.user.id], function(storageError) {
                        if (storageError) return res.status(500).json({ error: `Database error updating storage usage: ${storageError.message}` });
                        res.json({ message: "Website deleted" });
                    });
            });
        }).catch((filesystemError) => {
            res.status(500).json({ error: `Filesystem error deleting website: ${filesystemError.message}` });
        });
    });
});

// --- ADMIN ROUTES ---

app.get('/api/admin/pending-payments', (req, res) => {
    const sql = `SELECT u.id, u.id AS user_id, pay.id AS payment_id, u.name, u.email,
                    u.whatsapp_number, u.address_line1, u.address_line2, u.city, u.state,
                    u.postal_code, u.country, pay.utr_number,
                    pay.screenshot_url AS payment_screenshot_url, pay.screenshot_url,
                    COALESCE(pay.plan_name, p.name) AS plan_name,
                    COALESCE(pay.amount, p.term_price, p.price) AS amount,
                    COALESCE(pay.amount, p.term_price, p.price) AS price,
                    pay.quantity, pay.duration_months,
                    pay.is_first_purchase_promo AS first_purchase_promo,
                    pay.coupon_code, pay.coupon_discount,
                    pay.created_at
                 FROM payments pay
                 JOIN users u ON u.id = pay.user_id
                 LEFT JOIN plans p ON p.id = pay.plan_id
                 WHERE pay.status = 'Pending'
                 ORDER BY pay.created_at ASC, pay.id ASC`;
    db.all(sql, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ pendingUsers: rows });
    });
});

app.get('/api/admin/payments/:paymentId/screenshot', (req, res) => {
        const paymentId = Number(req.params.paymentId);
        if (!Number.isInteger(paymentId) || paymentId <= 0) return res.status(400).json({ error: 'Invalid payment ID' });
        db.get('SELECT screenshot_url FROM payments WHERE id = ?', [paymentId], (queryError, payment) => {
            if (queryError) return res.status(500).json({ error: `Database error loading payment screenshot: ${queryError.message}` });
            if (!payment?.screenshot_url) return res.status(404).json({ error: 'Payment screenshot not found' });
            const filename = path.basename(payment.screenshot_url);
            if (filename !== payment.screenshot_url.split('/').pop() ||
                !/^[a-f0-9-]+\.(?:jpg|png|webp|gif)$/i.test(filename)) {
                return res.status(400).json({ error: 'Payment screenshot reference is invalid' });
            }
            const screenshotPath = path.resolve(PAYMENT_SCREENSHOTS_DIR, filename);
            if (path.dirname(screenshotPath) !== PAYMENT_SCREENSHOTS_DIR) {
                return res.status(400).json({ error: 'Payment screenshot reference is invalid' });
            }
            fs.access(screenshotPath, fs.constants.R_OK, (accessError) => {
                if (accessError) return res.status(accessError.code === 'ENOENT' ? 404 : 500).json({
                    error: accessError.code === 'ENOENT' ? 'Payment screenshot not found' : 'Payment screenshot is unavailable'
                });
                res.sendFile(screenshotPath, { dotfiles: 'deny' }, (sendError) => {
                    if (sendError) {
                        console.error('Admin payment screenshot delivery failed:', sendError.message);
                        if (!res.headersSent) res.status(500).json({ error: 'Unable to send payment screenshot' });
                    }
                });
        });
    });
});

function finishPayment(paymentId, status, res) {
    db.run('BEGIN IMMEDIATE', (beginError) => {
        if (beginError) return res.status(500).json({ error: `Database error starting payment review: ${beginError.message}` });
        db.get(`SELECT pay.*, u.name, u.whatsapp_number, u.subscription_expires_at,
                       u.plan_id AS current_plan_id, u.plan_status AS current_plan_status,
                       u.first_paid_at, u.first_purchase_promo_used,
                       EXISTS(SELECT 1 FROM payments prior
                              WHERE prior.user_id = pay.user_id AND prior.status = 'Approved') AS has_prior_approved
                FROM payments pay JOIN users u ON u.id = pay.user_id
                WHERE pay.id = ? AND pay.status = 'Pending'`, [paymentId], (queryError, payment) => {
            if (queryError) return db.run('ROLLBACK', () =>
                res.status(500).json({ error: `Database error loading payment: ${queryError.message}` }));
            if (!payment) return db.run('ROLLBACK', () =>
                res.status(404).json({ error: 'Pending payment not found' }));
            const finish = (error, response) => db.run(error ? 'ROLLBACK' : 'COMMIT', (transactionError) => {
                if (transactionError) return res.status(500).json({ error: `Database error saving payment review: ${transactionError.message}` });
                if (error) return res.status(error.status || 500).json({ error: error.message });
                if (status === 'Approved') {
                    whatsapp.sendMessage(payment.whatsapp_number,
                        `Hey ${payment.name}, your hosting subscription has been activated.`);
                }
                res.json(response);
            });

            if (status === 'Approved' && payment.is_first_purchase_promo &&
                (payment.first_purchase_promo_used || payment.first_paid_at || payment.has_prior_approved ||
                    (payment.current_plan_id && payment.current_plan_status === 'Active'))) {
                return finish({ status: 409, message: 'First-purchase offer is no longer eligible for this customer' });
            }

            if (status === 'Rejected') {
                db.run("UPDATE payments SET status = 'Rejected', rejected_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'Pending'",
                    [paymentId], function(rejectError) {
                        if (rejectError) return finish({ message: `Database error rejecting payment: ${rejectError.message}` });
                        if (this.changes !== 1) return finish({ status: 409, message: 'Payment is no longer pending' });
                        db.run(`UPDATE coupon_redemptions SET status = 'Rejected' WHERE payment_id = ?`,
                            [paymentId], (couponError) => {
                                if (couponError) return finish({ message: `Database error releasing coupon: ${couponError.message}` });
                                db.get(`SELECT COUNT(*) AS count FROM payments WHERE user_id = ? AND status = 'Pending'`,
                                    [payment.user_id], (pendingError, pending) => {
                                        if (pendingError) return finish({ message: `Database error checking pending payments: ${pendingError.message}` });
                                        if (pending.count > 0) return finish(null, { message: 'Payment rejected' });
                                        db.run(`UPDATE users SET plan_status = CASE
                                            WHEN datetime(subscription_expires_at) > CURRENT_TIMESTAMP THEN 'Active' ELSE 'Inactive' END,
                                            utr_number = NULL, payment_screenshot_url = NULL
                                            WHERE id = ?`, [payment.user_id], (userError) => {
                                            if (userError) return finish({ message: `Database error updating customer payment status: ${userError.message}` });
                                            finish(null, { message: 'Payment rejected' });
                                        });
                                    });
                            });
                    });
                return;
            }

            const now = new Date();
            const expiry = payment.subscription_expires_at && Date.parse(payment.subscription_expires_at) > now.getTime()
                ? new Date(payment.subscription_expires_at)
                : now;
            const newExpiry = addMonths(expiry, Math.min(3, Math.max(1, Number(payment.duration_months) || 1))).toISOString();
            db.run("UPDATE payments SET status = 'Approved', approved_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'Pending'",
                [paymentId], function(approveError) {
                    if (approveError) return finish({ message: `Database error approving payment: ${approveError.message}` });
                    if (this.changes !== 1) return finish({ status: 409, message: 'Payment is no longer pending' });
                    db.run(`UPDATE users SET plan_id = ?, plan_status = 'Active',
                        subscription_expires_at = ?, paid_at = CURRENT_TIMESTAMP,
                        first_paid_at = COALESCE(first_paid_at, CURRENT_TIMESTAMP),
                        first_purchase_promo_used = CASE WHEN ? = 1 THEN 1 ELSE first_purchase_promo_used END,
                        subscription_max_websites = CASE WHEN ? = 1 THEN 1 ELSE NULL END,
                        utr_number = ?, payment_screenshot_url = ?
                        WHERE id = ?`,
                    [payment.plan_id, newExpiry, payment.is_first_purchase_promo,
                        payment.is_first_purchase_promo, payment.utr_number,
                        payment.screenshot_url, payment.user_id], function(userError) {
                            if (userError) return finish({ message: `Database error activating subscription: ${userError.message}` });
                            if (this.changes !== 1) return finish({ status: 404, message: 'Customer not found' });
                            db.run(`UPDATE coupon_redemptions SET status = 'Approved' WHERE payment_id = ?`,
                                [paymentId], (couponError) => {
                                    if (couponError) return finish({ message: `Database error confirming coupon redemption: ${couponError.message}` });
                                    finish(null, { message: 'Payment approved successfully', expiresAt: newExpiry });
                                });
                    });
                });
        });
    });
}

function resolvePaymentId(body, callback) {
    if (body.paymentId != null) {
        const id = Number(body.paymentId);
        if (!Number.isInteger(id) || id <= 0) return callback(null, null);
        return callback(null, id);
    }
    if (body.userId == null) return callback(null, null);
    db.get("SELECT id FROM payments WHERE user_id = ? AND status = 'Pending' ORDER BY created_at DESC, id DESC LIMIT 1",
        [body.userId], (err, payment) => callback(err, payment ? payment.id : null));
}

app.post('/api/admin/payments/:paymentId/approve', (req, res) => {
    const id = Number(req.params.paymentId);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid payment ID' });
    finishPayment(id, 'Approved', res);
});

app.post('/api/admin/payments/:paymentId/reject', (req, res) => {
    const id = Number(req.params.paymentId);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid payment ID' });
    finishPayment(id, 'Rejected', res);
});

app.post('/api/admin/approve-payment', (req, res) => {
    resolvePaymentId(req.body, (err, paymentId) => {
        if (err) return res.status(500).json({ error: `Database error locating pending payment: ${err.message}` });
        if (!paymentId) return res.status(404).json({ error: 'Pending payment not found' });
        finishPayment(paymentId, 'Approved', res);
    });
});

app.post('/api/admin/reject-payment', (req, res) => {
    resolvePaymentId(req.body, (err, paymentId) => {
        if (err) return res.status(500).json({ error: `Database error locating pending payment: ${err.message}` });
        if (!paymentId) return res.status(404).json({ error: 'Pending payment not found' });
        finishPayment(paymentId, 'Rejected', res);
    });
});

app.get('/api/admin/stats', (req, res) => {
    Promise.all([
        new Promise((resolve, reject) => db.get(`SELECT
            (SELECT COUNT(*) FROM users) AS totalUsers,
            (SELECT COUNT(*) FROM users WHERE plan_status = 'Active' AND datetime(subscription_expires_at) > CURRENT_TIMESTAMP) AS activeUsers,
            (SELECT COUNT(*) FROM users WHERE customer_type = 'Student') AS studentUsers,
            (SELECT COUNT(DISTINCT user_id) FROM admin_access_grants
             WHERE status = 'Active' AND datetime(expires_at) > CURRENT_TIMESTAMP) AS complimentaryUsers,
            (SELECT COUNT(*) FROM websites WHERE status = 'Live') AS liveWebsites,
            (SELECT COUNT(*) FROM payments WHERE status = 'Pending') AS pendingPayments,
            (SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status = 'Approved') AS totalRevenue,
            (SELECT COALESCE(SUM(size_mb), 0) FROM websites) AS storageUsedMb,
            (SELECT COALESCE(SUM(p.storage_limit_mb), 0) FROM users u JOIN plans p ON p.id = u.plan_id WHERE u.plan_status = 'Active') AS storageLimitMb`,
        (error, row) => error ? reject(error) : resolve(row))),
        new Promise((resolve, reject) => db.all(`SELECT date(created_at) AS day, SUM(amount) AS amount
            FROM payments WHERE status = 'Approved'
              AND date(created_at) >= date('now', '-6 days')
            GROUP BY date(created_at) ORDER BY day`,
        (error, rows) => error ? reject(error) : resolve(rows))),
        new Promise((resolve, reject) => db.all(`SELECT COALESCE(p.name, 'No plan') AS name, COUNT(*) AS users
            FROM users u LEFT JOIN plans p ON p.id = u.plan_id
            GROUP BY p.id, p.name ORDER BY users DESC`,
        (error, rows) => error ? reject(error) : resolve(rows))),
        new Promise((resolve, reject) => db.all(`SELECT id, name, email, created_at FROM users
            ORDER BY created_at DESC, id DESC LIMIT 5`,
        (error, rows) => error ? reject(error) : resolve(rows))),
        new Promise((resolve, reject) => db.all(`SELECT w.id, w.subdomain, w.status, w.size_mb, w.created_at,
                u.name AS user_name, u.email AS user_email, p.name AS plan_name
            FROM websites w JOIN users u ON u.id = w.user_id
            LEFT JOIN plans p ON p.id = u.plan_id
            ORDER BY w.created_at DESC, w.id DESC LIMIT 5`,
        (error, rows) => error ? reject(error) : resolve(rows)))
    ]).then(([stats, revenueRows, planUsage, recentUsers, recentWebsites]) => {
        const revenueByDay = new Map(revenueRows.map((row) => [row.day, Number(row.amount) || 0]));
        const revenue = Array.from({ length: 7 }, (_, index) => {
            const date = new Date();
            date.setUTCHours(0, 0, 0, 0);
            date.setUTCDate(date.getUTCDate() - (6 - index));
            const day = date.toISOString().slice(0, 10);
            return { day, amount: revenueByDay.get(day) || 0 };
        });
        res.json({ ...stats, revenue, planUsage, recentUsers, recentWebsites });
    }).catch((error) => {
        console.error('Admin overview query failed:', error.message);
        res.status(500).json({ error: 'Could not load admin overview data' });
    });
});

app.get('/api/admin/system-status', async (req, res) => {
    try {
        await new Promise((resolve, reject) => db.get('SELECT 1 AS connected', (error, row) => {
            if (error) reject(error);
            else if (!row?.connected) reject(new Error('Database health query returned no result'));
            else resolve();
        }));
        const [hostingWritable, screenshotsWritable] = await Promise.all([
            fs.promises.access(HOSTING_DIR, fs.constants.R_OK | fs.constants.W_OK).then(() => true, () => false),
            fs.promises.access(PAYMENT_SCREENSHOTS_DIR, fs.constants.R_OK | fs.constants.W_OK).then(() => true, () => false)
        ]);
        const whatsappStatus = whatsapp.getStatus();
        res.json({
            services: {
                api: 'operational',
                database: 'operational',
                hostingStorage: hostingWritable ? 'operational' : 'degraded',
                paymentStorage: screenshotsWritable ? 'operational' : 'degraded',
                whatsapp: whatsappStatus.ready ? 'operational' : 'not-connected'
            },
            process: {
                uptimeSeconds: Math.floor(process.uptime()),
                memoryRssBytes: process.memoryUsage().rss,
                nodeVersion: process.version,
                platform: os.platform(),
                loadAverage: os.loadavg()
            }
        });
    } catch (error) {
        console.error('Admin system status failed:', error.message);
        res.status(503).json({ error: 'Could not verify system status' });
    }
});

app.get('/api/admin/system-settings', (req, res) => {
    const whatsappStatus = whatsapp.getStatus();
    getPaymentSettings((error, settings) => {
        if (error) return res.status(500).json({ error: 'Could not verify system settings' });
        res.json({
            paymentUpiConfigured: Boolean(settings.upiId),
            paymentQrConfigured: Boolean(settings.qrImageUrl),
            adminAuthConfigured: Boolean(ADMIN_USERNAME && ADMIN_PASSWORD && JWT_SECRET),
            whatsappEnabled: process.env.WHATSAPP_ENABLED === 'true',
            whatsappReady: whatsappStatus.ready
        });
    });
});

app.get('/api/admin/notes', (req, res) => {
    db.all(`SELECT * FROM admin_notes ORDER BY updated_at DESC, id DESC`, [], (error, notes) => {
        if (error) return res.status(500).json({ error: `Database error loading notes: ${error.message}` });
        res.json({ notes });
    });
});

app.post('/api/admin/notes', (req, res) => {
    const title = typeof req.body.title === 'string' ? req.body.title.trim() : '';
    const content = typeof req.body.content === 'string' ? req.body.content.trim() : '';
    const category = typeof req.body.category === 'string' ? req.body.category.trim() : '';
    if (!title || title.length > 200 || !content || content.length > 10000 || category.length > 100) {
        return res.status(400).json({ error: 'Title (max 200), content (max 10000), and category (max 100) are required' });
    }
    db.run(`INSERT INTO admin_notes (title, content, category, created_by) VALUES (?, ?, ?, ?)`,
        [title, content, category || null, req.admin.username], function(error) {
            if (error) return res.status(500).json({ error: `Database error creating note: ${error.message}` });
            res.status(201).json({ noteId: this.lastID, message: 'Note created' });
        });
});

app.put('/api/admin/notes/:id', (req, res) => {
    const id = Number(req.params.id);
    const title = typeof req.body.title === 'string' ? req.body.title.trim() : '';
    const content = typeof req.body.content === 'string' ? req.body.content.trim() : '';
    const category = typeof req.body.category === 'string' ? req.body.category.trim() : '';
    if (!Number.isInteger(id) || id <= 0 || !title || title.length > 200 || !content || content.length > 10000 || category.length > 100) {
        return res.status(400).json({ error: 'Valid note ID and fields are required' });
    }
    db.run(`UPDATE admin_notes SET title = ?, content = ?, category = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
        [title, content, category || null, id], function(error) {
            if (error) return res.status(500).json({ error: `Database error updating note: ${error.message}` });
            if (!this.changes) return res.status(404).json({ error: 'Note not found' });
            res.json({ message: 'Note updated' });
        });
});

app.delete('/api/admin/notes/:id', (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid note ID' });
    db.run('DELETE FROM admin_notes WHERE id = ?', [id], function(error) {
        if (error) return res.status(500).json({ error: `Database error deleting note: ${error.message}` });
        if (!this.changes) return res.status(404).json({ error: 'Note not found' });
        res.json({ message: 'Note deleted' });
    });
});

app.get('/api/admin/settings', (req, res) => {
    db.all('SELECT key, value, description FROM admin_settings ORDER BY key', [], (error, rows) => {
        if (error) return res.status(500).json({ error: `Database error loading settings: ${error.message}` });
        const settings = {};
        rows.forEach(row => { settings[row.key] = { value: row.value, description: row.description }; });
        res.json({ settings });
    });
});

app.put('/api/admin/settings', (req, res) => {
    const updates = req.body;
    if (!updates || typeof updates !== 'object') return res.status(400).json({ error: 'Settings object required' });
    const allowedKeys = ['upi_id', 'upi_qr_url', 'support_email', 'support_phone', 'support_website', 
                         'github_url', 'linkedin_url', 'service_tax_percent', 'dashboard_tax_percent',
                         'banner_message', 'banner_enabled'];
    const stmt = db.prepare('UPDATE admin_settings SET value = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ?');
    let updated = 0;
    db.run('BEGIN IMMEDIATE');
    for (const [key, value] of Object.entries(updates)) {
        if (!allowedKeys.includes(key)) continue;
        stmt.run(String(value), req.admin.username, key, (err) => { if (!err) updated++; });
    }
    stmt.finalize();
    db.run('COMMIT', (err) => {
        if (err) return res.status(500).json({ error: `Database error saving settings: ${err.message}` });
        res.json({ message: 'Settings updated', updated });
    });
});

app.get('/api/admin/plans', (req, res) => {
    db.all("SELECT * FROM plans", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ plans: rows });
    });
});

app.get('/api/admin/coupons', (req, res) => {
    db.all(`SELECT c.*, p.name AS plan_name,
                   (SELECT COUNT(*) FROM coupon_redemptions r
                    WHERE r.coupon_id = c.id AND r.status IN ('Pending', 'Approved')) AS reserved_or_approved_uses
            FROM coupons c LEFT JOIN plans p ON p.id = c.plan_id
            ORDER BY c.created_at DESC, c.id DESC`,
        [], (error, coupons) => {
            if (error) return res.status(500).json({ error: `Database error loading coupons: ${error.message}` });
            res.json({ coupons });
        });
});

app.post('/api/admin/coupons', (req, res) => {
    const code = typeof req.body.code === 'string' ? req.body.code.trim().toUpperCase() : '';
    const description = typeof req.body.description === 'string' ? req.body.description.trim() : '';
    const discountType = req.body.discount_type;
    const discountValue = Number(req.body.discount_value);
    const maxDiscount = req.body.max_discount == null || req.body.max_discount === '' ? null : Number(req.body.max_discount);
    const maxRedemptions = req.body.max_redemptions == null || req.body.max_redemptions === '' ? null : Number(req.body.max_redemptions);
    const perUserLimit = req.body.per_user_limit == null ? 1 : Number(req.body.per_user_limit);
    const planId = req.body.plan_id == null || req.body.plan_id === '' ? null : Number(req.body.plan_id);
    const startsAt = req.body.starts_at || null;
    const expiresAt = req.body.expires_at || null;
    const validDate = (value) => value == null || (typeof value === 'string' && Number.isFinite(Date.parse(value)));
    if (!/^[A-Z0-9_-]{3,40}$/.test(code) || description.length > 500 ||
        !['percent', 'fixed'].includes(discountType) || !Number.isFinite(discountValue) ||
        discountValue <= 0 || (discountType === 'percent' && discountValue > 100) ||
        (maxDiscount != null && (!Number.isFinite(maxDiscount) || maxDiscount <= 0)) ||
        (maxRedemptions != null && (!Number.isInteger(maxRedemptions) || maxRedemptions < 1)) ||
        !Number.isInteger(perUserLimit) || perUserLimit < 1 || perUserLimit > 100 ||
        (planId != null && (!Number.isInteger(planId) || planId <= 0)) ||
        !validDate(startsAt) || !validDate(expiresAt) ||
        (startsAt && expiresAt && Date.parse(startsAt) >= Date.parse(expiresAt))) {
        return res.status(400).json({ error: 'Coupon fields, discount, limits, and validity dates must be valid' });
    }
    const createCoupon = () => db.run(`INSERT INTO coupons
        (code, description, discount_type, discount_value, max_discount, max_redemptions,
         per_user_limit, plan_id, starts_at, expires_at, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [code, description || null, discountType, discountValue, maxDiscount, maxRedemptions,
            perUserLimit, planId, startsAt, expiresAt, req.admin.username], function(error) {
            if (error?.code === 'SQLITE_CONSTRAINT') return res.status(409).json({ error: 'Coupon code already exists' });
            if (error) return res.status(500).json({ error: `Database error creating coupon: ${error.message}` });
            res.status(201).json({ couponId: this.lastID, message: 'Coupon created' });
        });
    if (planId == null) return createCoupon();
    db.get('SELECT id FROM plans WHERE id = ?', [planId], (error, plan) => {
        if (error) return res.status(500).json({ error: `Database error validating coupon plan: ${error.message}` });
        if (!plan) return res.status(400).json({ error: 'Coupon plan does not exist' });
        createCoupon();
    });
});

app.patch('/api/admin/coupons/:id', (req, res) => {
    const id = Number(req.params.id);
    const { is_active: isActive } = req.body;
    if (!Number.isInteger(id) || id <= 0 || ![0, 1, true, false].includes(isActive)) {
        return res.status(400).json({ error: 'A valid coupon ID and active state are required' });
    }
    db.run('UPDATE coupons SET is_active = ? WHERE id = ?', [isActive ? 1 : 0, id], function(error) {
        if (error) return res.status(500).json({ error: `Database error updating coupon: ${error.message}` });
        if (!this.changes) return res.status(404).json({ error: 'Coupon not found' });
        res.json({ message: 'Coupon updated', is_active: isActive ? 1 : 0 });
    });
});

app.get('/api/admin/announcements', (req, res) => {
    db.all('SELECT * FROM announcements ORDER BY created_at DESC, id DESC',
        [], (error, announcements) => {
            if (error) return res.status(500).json({ error: `Database error loading announcements: ${error.message}` });
            res.json({ announcements });
        });
});

app.post('/api/admin/announcements', (req, res) => {
    const { type, severity } = req.body;
    const title = typeof req.body.title === 'string' ? req.body.title.trim() : '';
    const message = typeof req.body.message === 'string' ? req.body.message.trim() : '';
    const linkUrl = typeof req.body.link_url === 'string' ? req.body.link_url.trim() : '';
    const startsAt = req.body.starts_at || null;
    const expiresAt = req.body.expires_at || null;
    const validDate = (value) => value == null || (typeof value === 'string' && Number.isFinite(Date.parse(value)));
    if (!['banner', 'notification', 'both'].includes(type) ||
        !['info', 'success', 'warning'].includes(severity || 'info') ||
        !title || title.length > 120 || !message || message.length > 2000 ||
        linkUrl.length > 300 || (linkUrl && !/^\/dashboard(?:\/[a-z0-9/-]*)?(?:#[a-z0-9_-]+)?$/i.test(linkUrl)) ||
        !validDate(startsAt) || !validDate(expiresAt) ||
        (startsAt && expiresAt && Date.parse(startsAt) >= Date.parse(expiresAt))) {
        return res.status(400).json({ error: 'Announcement content, type, severity, link, or schedule is invalid' });
    }
    db.run(`INSERT INTO announcements
        (type, severity, title, message, link_url, starts_at, expires_at, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [type, severity || 'info', title, message, linkUrl || null, startsAt, expiresAt, req.admin.username],
        function(error) {
            if (error) return res.status(500).json({ error: `Database error publishing announcement: ${error.message}` });
            res.status(201).json({ announcementId: this.lastID, message: 'Announcement published' });
        });
});

app.patch('/api/admin/announcements/:id', (req, res) => {
    const id = Number(req.params.id);
    const isActive = req.body.is_active;
    if (!Number.isInteger(id) || id <= 0 || ![0, 1, true, false].includes(isActive)) {
        return res.status(400).json({ error: 'A valid announcement ID and active state are required' });
    }
    db.run('UPDATE announcements SET is_active = ? WHERE id = ?', [isActive ? 1 : 0, id], function(error) {
        if (error) return res.status(500).json({ error: `Database error updating announcement: ${error.message}` });
        if (!this.changes) return res.status(404).json({ error: 'Announcement not found' });
        res.json({ message: 'Announcement status updated', is_active: isActive ? 1 : 0 });
    });
});

app.post('/api/admin/plans', (req, res) => {
    const { name, price, storage_limit_mb, max_websites } = req.body;
    const maxWebsites = Number(max_websites);
    const durationMonths = req.body.duration_months == null ? 1 : Number(req.body.duration_months);
    const monthlyPrice = req.body.monthly_price == null ? Number(price) : Number(req.body.monthly_price);
    const termPrice = req.body.term_price == null ? Number(price) : Number(req.body.term_price);
    if (typeof name !== 'string' || !name.trim() || name.trim().length > 100 ||
        !Number.isFinite(monthlyPrice) || monthlyPrice <= 0 || !Number.isFinite(termPrice) || termPrice <= 0 ||
        !Number.isInteger(durationMonths) || durationMonths < 1 || durationMonths > 3 ||
        !Number.isInteger(Number(storage_limit_mb)) || Number(storage_limit_mb) < 1 ||
        !Number.isInteger(maxWebsites) || maxWebsites < 1) {
        return res.status(400).json({ error: 'Plan name, prices, duration (1-3 months), and limits must be valid' });
    }
    db.run(`INSERT INTO plans
        (name, price, storage_limit_mb, max_websites, duration_months, monthly_price, term_price)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [name.trim(), termPrice, maxWebsites * 15, maxWebsites,
            durationMonths, monthlyPrice, termPrice], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Plan created", planId: this.lastID });
    });
});

app.put('/api/admin/plans/:id', (req, res) => {
    db.get('SELECT * FROM plans WHERE id = ?', [req.params.id], (queryError, current) => {
        if (queryError) return res.status(500).json({ error: queryError.message });
        if (!current) return res.status(404).json({ error: 'Plan not found' });
        const name = req.body.name == null ? current.name : req.body.name;
        const maxWebsites = req.body.max_websites == null ? current.max_websites : Number(req.body.max_websites);
        const durationMonths = req.body.duration_months == null
            ? Number(current.duration_months || 1)
            : Number(req.body.duration_months);
        const legacyPrice = req.body.price == null ? Number(current.price) : Number(req.body.price);
        const monthlyPrice = req.body.monthly_price == null
            ? Number(current.monthly_price ?? current.price)
            : Number(req.body.monthly_price);
        const termPrice = req.body.term_price == null
            ? (req.body.price == null ? Number(current.term_price ?? current.price) : legacyPrice)
            : Number(req.body.term_price);
        const isActive = req.body.is_active == null ? current.is_active : req.body.is_active;
        if (typeof name !== 'string' || !name.trim() || name.trim().length > 100 ||
            !Number.isFinite(monthlyPrice) || monthlyPrice <= 0 || !Number.isFinite(termPrice) || termPrice <= 0 ||
            !Number.isInteger(durationMonths) || durationMonths < 1 || durationMonths > 3 ||
            !Number.isInteger(maxWebsites) || maxWebsites < 1 ||
            ![0, 1, true, false].includes(isActive)) {
            return res.status(400).json({ error: 'Plan name, prices, duration (1-3 months), and limits must be valid' });
        }
        db.run(`UPDATE plans SET name=?, price=?, storage_limit_mb=?, max_websites=?, is_active=?,
            duration_months=?, monthly_price=?, term_price=? WHERE id=?`,
            [name.trim(), termPrice, maxWebsites * 15, maxWebsites, isActive ? 1 : 0,
                durationMonths, monthlyPrice, termPrice, req.params.id], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: "Plan updated" });
        });
    });
});

app.get('/api/admin/users', (req, res) => {
    const sql = `SELECT u.id, u.name, u.email, u.whatsapp_number, u.customer_type,
                    u.student_institute, u.student_course, u.plan_status, u.account_status,
                    u.storage_used, u.subscription_expires_at, p.id AS plan_id,
                    p.name AS plan_name, p.storage_limit_mb, p.max_websites,
                    EXISTS(SELECT 1 FROM admin_access_grants g
                           WHERE g.user_id = u.id AND g.status = 'Active'
                                 AND datetime(g.expires_at) > CURRENT_TIMESTAMP) AS complimentary_access
                 FROM users u LEFT JOIN plans p ON u.plan_id = p.id
                 ORDER BY CASE WHEN u.customer_type = 'Student' THEN 0 ELSE 1 END, u.created_at DESC`;
    db.all(sql, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ users: rows });
    });
});

app.get('/api/admin/users/:userId/sessions', (req, res) => {
    const userId = Number(req.params.userId);
    if (!Number.isInteger(userId) || userId <= 0) return res.status(400).json({ error: 'Invalid user ID' });
    db.all(`SELECT id, device_id, device_name, browser, os, ip_hash, is_current, created_at, last_activity_at, expires_at
            FROM user_sessions WHERE user_id = ? ORDER BY is_current DESC, last_activity_at DESC`,
        [userId], (err, rows) => {
            if (err) return res.status(500).json({ error: `Database error loading sessions: ${err.message}` });
            res.json({ sessions: rows });
        });
});

app.delete('/api/admin/users/:userId/sessions/:sessionId', (req, res) => {
    const userId = Number(req.params.userId);
    const sessionId = Number(req.params.sessionId);
    if (!Number.isInteger(userId) || userId <= 0 || !Number.isInteger(sessionId) || sessionId <= 0) {
        return res.status(400).json({ error: 'Invalid user ID or session ID' });
    }
    db.get('SELECT id, is_current FROM user_sessions WHERE id = ? AND user_id = ?', [sessionId, userId], (err, session) => {
        if (err) return res.status(500).json({ error: `Database error loading session: ${err.message}` });
        if (!session) return res.status(404).json({ error: 'Session not found' });
        if (session.is_current) return res.status(400).json({ error: 'Cannot revoke current session via admin' });
        db.run('DELETE FROM user_sessions WHERE id = ? AND user_id = ?', [sessionId, userId], function(deleteError) {
            if (deleteError) return res.status(500).json({ error: `Database error revoking session: ${deleteError.message}` });
            res.json({ message: 'Session revoked successfully' });
        });
    });
});

app.post('/api/admin/customers', async (req, res) => {
    const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const phone = typeof req.body.whatsapp_number === 'string' ? req.body.whatsapp_number.trim() : '';
    const customerType = req.body.customer_type === 'Student' ? 'Student' : req.body.customer_type === 'Customer' ? 'Customer' : '';
    const institute = typeof req.body.student_institute === 'string' ? req.body.student_institute.trim() : '';
    const course = typeof req.body.student_course === 'string' ? req.body.student_course.trim() : '';
    if (!name || name.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        email.length > 254 || !validWhatsappNumber(phone) || !customerType ||
        institute.length > 160 || course.length > 160) {
        return res.status(400).json({ error: 'Name, valid email, mobile number, customer type, and optional student details must be valid' });
    }
    const temporaryPassword = crypto.randomBytes(18).toString('base64url');
    try {
        const passwordHash = await bcrypt.hash(temporaryPassword, 12);
        db.run(`INSERT INTO users
            (name, email, whatsapp_number, password_hash, customer_type, student_institute, student_course)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [name, email, phone, passwordHash, customerType, institute || null, course || null],
            function(error) {
                if (error?.code === 'SQLITE_CONSTRAINT') {
                    return res.status(409).json({ error: 'An account with this email already exists' });
                }
                if (error) return res.status(500).json({ error: `Database error creating customer: ${error.message}` });
                res.status(201).json({
                    customer: { id: this.lastID, name, email, whatsapp_number: phone, customer_type: customerType },
                    temporaryPassword
                });
            });
    } catch (error) {
        console.error('Admin customer creation failed:', error.message);
        res.status(500).json({ error: 'Could not create customer account' });
    }
});

app.post('/api/admin/customers/:id/complimentary-access', (req, res) => {
    const userId = Number(req.params.id);
    const planId = Number(req.body.plan_id);
    const durationMonths = Number(req.body.duration_months);
    const reason = typeof req.body.reason === 'string' ? req.body.reason.trim() : '';
    if (!Number.isInteger(userId) || userId <= 0 || !Number.isInteger(planId) || planId <= 0 ||
        !Number.isInteger(durationMonths) || durationMonths < 1 || durationMonths > 3 ||
        reason.length < 3 || reason.length > 500) {
        return res.status(400).json({ error: 'Customer, plan, duration (1–3 months), and a reason of 3–500 characters are required' });
    }
    db.get('SELECT id, is_active FROM plans WHERE id = ?', [planId], (planError, plan) => {
        if (planError) return res.status(500).json({ error: `Database error validating plan: ${planError.message}` });
        if (!plan || !plan.is_active) return res.status(400).json({ error: 'Select an active plan' });
        db.run('BEGIN IMMEDIATE', (beginError) => {
            if (beginError) return res.status(500).json({ error: `Database error starting access grant: ${beginError.message}` });
            db.get(`SELECT id, account_status, plan_status, subscription_expires_at
                    FROM users WHERE id = ?`, [userId], (userError, user) => {
                if (userError || !user || user.account_status !== 'Active') {
                    return db.run('ROLLBACK', () => res.status(userError ? 500 : 404).json({
                        error: userError ? `Database error loading customer: ${userError.message}` :
                            !user ? 'Customer not found' : 'Reactivate the suspended customer before granting access'
                    }));
                }
                const now = new Date();
                const currentExpiry = user.subscription_expires_at && Date.parse(user.subscription_expires_at) > now.getTime()
                    ? new Date(user.subscription_expires_at)
                    : now;
                const startsAt = now;
                const expiresAt = addMonths(currentExpiry, durationMonths).toISOString();
                db.run(`INSERT INTO admin_access_grants
                    (user_id, plan_id, duration_months, reason, granted_by, starts_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [userId, planId, durationMonths, reason, req.admin.username, startsAt.toISOString(), expiresAt],
                    function(insertError) {
                        if (insertError) return db.run('ROLLBACK', () => res.status(500).json({
                            error: `Database error recording complimentary access: ${insertError.message}`
                        }));
                        const grantId = this.lastID;
                        db.run(`UPDATE users SET plan_id = ?, plan_status = 'Active',
                                subscription_expires_at = ?, subscription_max_websites = NULL
                                WHERE id = ? AND account_status = 'Active'`,
                            [planId, expiresAt, userId], function(updateError) {
                                if (updateError || this.changes !== 1) {
                                    return db.run('ROLLBACK', () => res.status(updateError ? 500 : 409).json({
                                        error: updateError
                                            ? `Database error assigning complimentary plan: ${updateError.message}`
                                            : 'Customer status changed before the complimentary plan could be assigned'
                                    }));
                                }
                                db.run('COMMIT', (commitError) => {
                                    if (commitError) return db.run('ROLLBACK', () => res.status(500).json({
                                        error: `Database error saving complimentary access: ${commitError.message}`
                                    }));
                                    res.status(201).json({
                                        message: 'Complimentary hosting access granted',
                                        grantId,
                                        startsAt: startsAt.toISOString(),
                                        expiresAt
                                    });
                                });
                            });
                    });
            });
        });
    });
});

app.patch('/api/admin/customers/:id/classification', (req, res) => {
    const userId = Number(req.params.id);
    const customerType = req.body.customer_type;
    const institute = typeof req.body.student_institute === 'string' ? req.body.student_institute.trim() : '';
    const course = typeof req.body.student_course === 'string' ? req.body.student_course.trim() : '';
    if (!Number.isInteger(userId) || userId <= 0 || !['Student', 'Customer'].includes(customerType) ||
        institute.length > 160 || course.length > 160) {
        return res.status(400).json({ error: 'Customer type and student details must be valid' });
    }
    db.run(`UPDATE users SET customer_type = ?, student_institute = ?, student_course = ?
            WHERE id = ?`,
        [customerType, customerType === 'Student' ? institute || null : null,
            customerType === 'Student' ? course || null : null, userId],
        function(error) {
            if (error) return res.status(500).json({ error: `Database error updating customer classification: ${error.message}` });
            if (this.changes !== 1) return res.status(404).json({ error: 'Customer not found' });
            res.json({ message: 'Customer classification updated', customer_type: customerType });
        });
});

app.get('/api/admin/support-tickets', (req, res) => {
    db.all(`SELECT t.id, t.user_id, t.type, t.subject, t.message, t.category, t.status, t.created_at,
                   u.name AS customer_name, u.email AS customer_email, u.whatsapp_number
            FROM support_tickets t
            JOIN users u ON u.id = t.user_id
            ORDER BY CASE WHEN t.status IN ('Open', 'In Progress') THEN 0 ELSE 1 END,
                     t.created_at DESC, t.id DESC`,
        [], (err, rows) => {
            if (err) return res.status(500).json({ error: `Database error loading support tickets: ${err.message}` });
            res.json({ tickets: rows });
        });
});

app.patch('/api/admin/support-tickets/:id', (req, res) => {
    const id = Number(req.params.id);
    const { status } = req.body;
    if (!Number.isInteger(id) || id <= 0 ||
        !['Open', 'In Progress', 'Resolved', 'Closed'].includes(status)) {
        return res.status(400).json({ error: 'A valid support ticket ID and status are required' });
    }
    db.run('UPDATE support_tickets SET status = ? WHERE id = ?', [status, id], function(err) {
        if (err) return res.status(500).json({ error: `Database error updating support ticket: ${err.message}` });
        if (this.changes !== 1) return res.status(404).json({ error: 'Support ticket not found' });
        res.json({ message: 'Support ticket status updated', status });
    });
});

app.get('/api/admin/audit-logs', (req, res) => {
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 50));
    db.all(`SELECT id, actor, action, method, route, status_code, request_id, created_at
            FROM audit_logs ORDER BY id DESC LIMIT ?`,
        [limit], (error, rows) => {
            if (error) return res.status(500).json({ error: `Database error loading audit history: ${error.message}` });
            res.json({ logs: rows });
        });
});

app.get('/api/admin/search', (req, res) => {
    const query = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 100) : '';
    if (query.length < 2) return res.status(400).json({ error: 'Search query must contain at least two characters' });
    const pattern = `%${query.replace(/[\\%_]/g, '\\$&')}%`;
    Promise.all([
        new Promise((resolve, reject) => db.all(`SELECT id, name, email, plan_status FROM users
            WHERE name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\'
            ORDER BY created_at DESC LIMIT 10`, [pattern, pattern],
        (error, rows) => error ? reject(error) : resolve(rows))),
        new Promise((resolve, reject) => db.all(`SELECT id, subdomain, status, user_id FROM websites
            WHERE subdomain LIKE ? ESCAPE '\\' ORDER BY created_at DESC LIMIT 10`,
        [pattern], (error, rows) => error ? reject(error) : resolve(rows))),
        new Promise((resolve, reject) => db.all(`SELECT p.id, p.user_id, p.status, p.amount, p.utr_number, u.name, u.email
            FROM payments p JOIN users u ON u.id = p.user_id
            WHERE u.name LIKE ? ESCAPE '\\' OR u.email LIKE ? ESCAPE '\\' OR p.utr_number LIKE ? ESCAPE '\\'
            ORDER BY p.created_at DESC LIMIT 10`, [pattern, pattern, pattern],
        (error, rows) => error ? reject(error) : resolve(rows)))
    ]).then(([users, websites, payments]) => res.json({ users, websites, payments }))
        .catch((error) => {
            console.error('Admin search failed:', error.message);
            res.status(500).json({ error: 'Could not complete admin search' });
        });
});

app.get('/api/admin/websites/:id/files', async (req, res) => {
    const websiteId = Number(req.params.id);
    const relativePath = typeof req.query.path === 'string' ? req.query.path : '';
    if (!Number.isInteger(websiteId) || websiteId <= 0 || relativePath.includes('\\') ||
        relativePath.includes('\0') || path.posix.isAbsolute(relativePath) ||
        relativePath.split('/').some((segment) => segment === '..' || segment === '.')) {
        return res.status(400).json({ error: 'Website or relative path is invalid' });
    }
    try {
        const site = await new Promise((resolve, reject) => db.get(
            'SELECT id, subdomain, status, folder_path FROM websites WHERE id = ?',
            [websiteId], (error, row) => error ? reject(error) : resolve(row)
        ));
        if (!site) return res.status(404).json({ error: 'Website not found' });
        const liveRoot = ownedSitePath(HOSTING_DIR, site.subdomain);
        const offlineRoot = ownedSitePath(OFFLINE_DIR, site.subdomain);
        const siteRoot = path.resolve(site.folder_path);
        if (!liveRoot || !offlineRoot || ![liveRoot, offlineRoot].includes(siteRoot)) {
            return res.status(400).json({ error: 'Website path is outside configured hosting storage' });
        }
        const folder = path.resolve(siteRoot, relativePath);
        if (folder !== siteRoot && !folder.startsWith(`${siteRoot}${path.sep}`)) {
            return res.status(400).json({ error: 'Requested path is outside this website' });
        }
        const stats = await fs.promises.lstat(folder);
        if (!stats.isDirectory() || stats.isSymbolicLink()) {
            return res.status(400).json({ error: 'Requested path is not a safe directory' });
        }
        const directoryEntries = await fs.promises.readdir(folder, { withFileTypes: true });
        const entries = await Promise.all(directoryEntries.slice(0, 300).map(async (entry) => {
            const entryPath = path.join(folder, entry.name);
            const details = await fs.promises.lstat(entryPath);
            return {
                name: entry.name,
                type: details.isSymbolicLink() ? 'link' : details.isDirectory() ? 'directory' : 'file',
                sizeBytes: details.isFile() ? details.size : null,
                relativePath: path.posix.join(relativePath, entry.name)
            };
        }));
        res.json({
            website: { id: site.id, subdomain: site.subdomain, status: site.status },
            path: relativePath,
            entries: entries.sort((left, right) => left.type.localeCompare(right.type) || left.name.localeCompare(right.name)),
            truncated: directoryEntries.length > 300
        });
    } catch (error) {
        const notFound = error.code === 'ENOENT';
        if (!notFound) console.error('Admin file manager request failed:', error.message);
        res.status(notFound ? 404 : 500).json({ error: notFound ? 'Website folder not found' : 'Could not read website folder' });
    }
});

app.get('/api/admin/websites', (req, res) => {
    const sql = `SELECT w.*, u.name as user_name, u.email as user_email 
                 FROM websites w JOIN users u ON w.user_id = u.id`;
    db.all(sql, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ websites: rows });
    });
});

async function setCustomerSuspendedState(userId, suspended) {
    const user = await databaseGet('SELECT id, account_status FROM users WHERE id = ?', [userId]);
    if (!user) {
        const error = new Error('Customer not found');
        error.status = 404;
        throw error;
    }
    const websites = await databaseAll('SELECT id, subdomain, status, folder_path FROM websites WHERE user_id = ?', [userId]);
    const paths = websites.map((site) => {
        const live = ownedSitePath(HOSTING_DIR, site.subdomain);
        const offline = ownedSitePath(OFFLINE_DIR, site.subdomain);
        if (!live || !offline || ![live, offline].includes(path.resolve(site.folder_path))) {
            throw new Error(`Website ${site.subdomain} has an unsafe hosting path`);
        }
        return { site, live, offline, previousStatus: site.status, previousPath: site.folder_path };
    });
    if (suspended) await databaseRun("UPDATE users SET account_status = 'Suspended' WHERE id = ?", [userId]);
    const moved = [];
    try {
        for (const item of paths) {
            const liveExists = fs.existsSync(item.live);
            const offlineExists = fs.existsSync(item.offline);
            if (liveExists && offlineExists) throw new Error(`Both live and private copies exist for ${item.site.subdomain}`);
            if (liveExists) {
                await fs.promises.rename(item.live, item.offline);
                moved.push(item);
            }
        }
        for (const item of paths) {
            const state = await databaseRun(
                'UPDATE websites SET status = ?, folder_path = ? WHERE id = ? AND user_id = ?',
                [suspended ? 'Suspended' : 'Offline', item.offline, item.site.id, userId]
            );
            if (state.changes !== 1) throw new Error(`Website ${item.site.subdomain} changed during account status update`);
        }
        const userUpdate = await databaseRun(
            `UPDATE users SET account_status = ?, plan_status = CASE WHEN ? = 1 THEN 'Inactive' ELSE plan_status END
             WHERE id = ?`,
            [suspended ? 'Suspended' : 'Active', suspended ? 1 : 0, userId]
        );
        if (userUpdate.changes !== 1) throw new Error('Customer changed during account status update');
        return { accountStatus: suspended ? 'Suspended' : 'Active', websitesUpdated: paths.length };
    } catch (error) {
        const restoreErrors = [];
        for (const item of [...moved].reverse()) {
            try { await fs.promises.rename(item.offline, item.live); }
            catch (restoreError) { restoreErrors.push(restoreError.message); }
        }
        for (const item of paths) {
            try {
                await databaseRun('UPDATE websites SET status = ?, folder_path = ? WHERE id = ?',
                    [item.previousStatus, item.previousPath, item.site.id]);
            } catch (restoreError) { restoreErrors.push(restoreError.message); }
        }
        try {
            await databaseRun('UPDATE users SET account_status = ? WHERE id = ?',
                [user.account_status, userId]);
        } catch (restoreError) { restoreErrors.push(restoreError.message); }
        if (restoreErrors.length) {
            throw new Error(`${error.message}; rollback errors: ${restoreErrors.join('; ')}`);
        }
        throw error;
    }
}

app.post('/api/admin/suspend-user', async (req, res) => {
    const userId = Number(req.body.userId);
    if (!Number.isInteger(userId) || userId <= 0) return res.status(400).json({ error: 'A valid customer ID is required' });
    try {
        const result = await setCustomerSuspendedState(userId, true);
        res.json({ message: 'Customer suspended; hosted sites moved out of public hosting', ...result });
    } catch (error) {
        console.error('Admin customer suspension failed:', error.message);
        res.status(error.status || 500).json({ error: error.message });
    }
});

app.post('/api/admin/unsuspend-user', async (req, res) => {
    const userId = Number(req.body.userId);
    if (!Number.isInteger(userId) || userId <= 0) return res.status(400).json({ error: 'A valid customer ID is required' });
    try {
        const result = await setCustomerSuspendedState(userId, false);
        res.json({ message: 'Customer reactivated; websites remain private until republished', ...result });
    } catch (error) {
        console.error('Admin customer reactivation failed:', error.message);
        res.status(error.status || 500).json({ error: error.message });
    }
});

app.delete('/api/admin/websites/:id', (req, res) => {
    db.get("SELECT * FROM websites WHERE id = ?", [req.params.id], (err, site) => {
        if (err || !site) return res.status(404).json({ error: "Website not found" });
        const livePath = ownedSitePath(HOSTING_DIR, site.subdomain);
        const offlinePath = ownedSitePath(OFFLINE_DIR, site.subdomain);
        const sitePath = path.resolve(site.folder_path);
        if (!livePath || !offlinePath || ![livePath, offlinePath].includes(sitePath)) {
            return res.status(400).json({ error: 'Website path is outside configured hosting storage' });
        }
        Promise.all([livePath, offlinePath].map((knownPath) => fs.promises.rm(knownPath, { recursive: true, force: true })))
            .then(() => db.run("DELETE FROM websites WHERE id = ?", [req.params.id], function(deleteError) {
                if (deleteError) return res.status(500).json({ error: `Database error deleting website: ${deleteError.message}` });
                if (this.changes !== 1) return res.status(409).json({ error: 'Website record changed before deletion' });
                db.run("UPDATE users SET storage_used = MAX(storage_used - ?, 0) WHERE id = ?",
                    [site.size_mb || 0, site.user_id], (storageError) => {
                        if (storageError) return res.status(500).json({ error: `Database error updating storage usage: ${storageError.message}` });
                        res.json({ message: "Website deleted" });
                    });
            }))
            .catch((filesystemError) => {
                res.status(500).json({ error: `Filesystem error deleting website: ${filesystemError.message}` });
            });
    });
});

app.post('/api/admin/broadcast', (req, res) => {
    const message = typeof req.body.message === 'string' ? req.body.message.trim() : '';
    if (!message || message.length > 2000) {
        return res.status(400).json({ error: 'A message of 1–2,000 characters is required' });
    }
    db.all("SELECT whatsapp_number FROM users WHERE plan_status = 'Active'", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        Promise.all(rows.map((user) => whatsapp.sendMessage(user.whatsapp_number, message)))
            .then((results) => {
                const sent = results.filter(Boolean).length;
                const failed = results.length - sent;
                const statusCode = failed ? 207 : 200;
                res.status(statusCode).json({
                    message: failed
                        ? `Broadcast partially delivered: ${sent} sent, ${failed} failed`
                        : `Broadcast sent to ${sent} users`,
                    total: results.length,
                    sent,
                    failed
                });
            })
            .catch((sendError) => {
                console.error('WhatsApp broadcast failed:', sendError.message);
                res.status(502).json({ error: 'WhatsApp broadcast could not be completed' });
            });
    });
});

app.post('/api/admin/broadcast', (req, res) => {
    const message = typeof req.body.message === 'string' ? req.body.message.trim() : '';
    if (!message || message.length > 2000) {
        return res.status(400).json({ error: 'A message of 1–2,000 characters is required' });
    }
    db.all("SELECT whatsapp_number FROM users WHERE plan_status = 'Active'", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        Promise.all(rows.map((user) => whatsapp.sendMessage(user.whatsapp_number, message)))
            .then((results) => {
                const sent = results.filter(Boolean).length;
                const failed = results.length - sent;
                const statusCode = failed ? 207 : 200;
                res.status(statusCode).json({
                    message: failed
                        ? `Broadcast partially delivered: ${sent} sent, ${failed} failed`
                        : `Broadcast sent to ${sent} users`,
                    total: results.length,
                    sent,
                    failed
                });
            })
            .catch((sendError) => {
                console.error('WhatsApp broadcast failed:', sendError.message);
                res.status(502).json({ error: 'WhatsApp broadcast could not be completed' });
            });
    });
});

app.get('/robots.txt', (req, res) => {
    const baseUrl = process.env.BASE_URL || 'https://piyushassudani.in';
    const robots = `User-agent: *
Allow: /
Disallow: /dashboard/
Disallow: /api/
Disallow: /login
Disallow: /signup
Disallow: /forgot-password
Disallow: /reset-password
Disallow: /onboarding/
Disallow: /policies/

Sitemap: ${baseUrl}/sitemap.xml
`;
    res.set('Content-Type', 'text/plain');
    res.send(robots);
});

app.get('/sitemap.xml', (req, res) => {
    const baseUrl = process.env.BASE_URL || 'https://piyushassudani.in';
    const today = new Date().toISOString().split('T')[0];
    const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>${baseUrl}/</loc>
        <lastmod>${today}</lastmod>
        <changefreq>weekly</changefreq>
        <priority>1.0</priority>
    </url>
    <url>
        <loc>${baseUrl}/login</loc>
        <lastmod>${today}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.8</priority>
    </url>
    <url>
        <loc>${baseUrl}/signup</loc>
        <lastmod>${today}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.8</priority>
    </url>
    <url>
        <loc>${baseUrl}/pricing</loc>
        <lastmod>${today}</lastmod>
        <changefreq>weekly</changefreq>
        <priority>0.9</priority>
    </url>
    <url>
        <loc>${baseUrl}/features</loc>
        <lastmod>${today}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.7</priority>
    </url>
    <url>
        <loc>${baseUrl}/contact</loc>
        <lastmod>${today}</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.6</priority>
    </url>
    <url>
        <loc>${baseUrl}/policies/terms</loc>
        <lastmod>${today}</lastmod>
        <changefreq>yearly</changefreq>
        <priority>0.5</priority>
    </url>
    <url>
        <loc>${baseUrl}/policies/privacy</loc>
        <lastmod>${today}</lastmod>
        <changefreq>yearly</changefreq>
        <priority>0.5</priority>
    </url>
    <url>
        <loc>${baseUrl}/policies/refunds</loc>
        <lastmod>${today}</lastmod>
        <changefreq>yearly</changefreq>
        <priority>0.5</priority>
    </url>
    <url>
        <loc>${baseUrl}/policies/acceptable-use</loc>
        <lastmod>${today}</lastmod>
        <changefreq>yearly</changefreq>
        <priority>0.5</priority>
    </url>
</urlset>`;
    res.set('Content-Type', 'application/xml');
    res.send(sitemap);
});

// Invoice PDF generation endpoint
app.get('/api/admin/invoices/:paymentId/pdf', (req, res) => {
    const paymentId = Number(req.params.paymentId);
    if (!Number.isInteger(paymentId) || paymentId <= 0) {
        return res.status(400).json({ error: 'Invalid payment ID' });
    }
    db.get(`SELECT p.*, u.name, u.email, u.whatsapp_number, u.address_line1, u.address_line2, u.city, u.state, u.postal_code, u.country
            FROM payments p JOIN users u ON u.id = p.user_id
            WHERE p.id = ?`, [paymentId], (err, payment) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!payment) return res.status(404).json({ error: 'Payment not found' });
        
        const invoiceNumber = `INV-${payment.id.toString().padStart(6, '0')}`;
        const date = new Date(payment.created_at).toLocaleDateString();
        const pdfContent = generateInvoicePDF(payment, invoiceNumber, date);
        
        // Save invoice record
        db.run(`INSERT OR REPLACE INTO invoices (payment_id, user_id, invoice_number, amount, service_tax, dashboard_tax, total_amount, status, pdf_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'Generated', ?)`,
            [payment.id, payment.user_id, invoiceNumber, payment.amount, payment.serviceTax || 0, payment.dashboardTax || 0, 
             (payment.amount + (payment.serviceTax || 0) + (payment.dashboardTax || 0)), invoiceNumber + '.pdf'],
            function(err) {
                if (err) console.error('Invoice record error:', err.message);
            });
        
        res.set('Content-Type', 'application/pdf');
        res.set('Content-Disposition', `attachment; filename="${invoiceNumber}.pdf"`);
        res.send(pdfContent);
    });
});

// Admin password rotation policy
app.get('/api/admin/password-policy', (req, res) => {
    db.get('SELECT * FROM admin_settings WHERE key = ?', ['admin_password_policy'], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        const policy = row ? JSON.parse(row.value) : {
            maxAgeDays: 90,
            minLength: 24,
            requireUppercase: true,
            requireLowercase: true,
            requireNumbers: true,
            requireSpecial: true,
            historyCount: 5
        };
        res.json({ policy });
    });
});

app.put('/api/admin/password-policy', (req, res) => {
    const policy = req.body;
    if (!policy || typeof policy.maxAgeDays !== 'number' || policy.maxAgeDays < 30 || policy.maxAgeDays > 365) {
        return res.status(400).json({ error: 'Invalid policy: maxAgeDays must be 30-365' });
    }
    db.run(`INSERT OR REPLACE INTO admin_settings (key, value, description, updated_by, updated_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`,
        ['admin_password_policy', JSON.stringify(policy), 'Admin password rotation policy', req.admin.username],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Password policy updated', policy });
        });
});

// Admin password change with history
app.post('/api/admin/change-password', async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: 'Current and new password required' });
    }
    db.get('SELECT password_hash FROM admin_password_history WHERE admin_username = ? ORDER BY changed_at DESC LIMIT 1',
        [req.admin.username], async (err, row) => {
            if (err) return res.status(500).json({ error: err.message });
            const valid = row && await bcrypt.compare(currentPassword, row.password_hash);
            if (!valid) return res.status(401).json({ error: 'Current password incorrect' });
            
            // Check password policy
            db.get('SELECT value FROM admin_settings WHERE key = ?', ['admin_password_policy'], async (err, policyRow) => {
                if (err) return res.status(500).json({ error: err.message });
                const policy = policyRow ? JSON.parse(policyRow.value) : { minLength: 24, requireUppercase: true, requireLowercase: true, requireNumbers: true, requireSpecial: true, historyCount: 5 };
                
                if (newPassword.length < policy.minLength) return res.status(400).json({ error: `Password must be at least ${policy.minLength} characters` });
                if (policy.requireUppercase && !/[A-Z]/.test(newPassword)) return res.status(400).json({ error: 'Password must contain uppercase letter' });
                if (policy.requireLowercase && !/[a-z]/.test(newPassword)) return res.status(400).json({ error: 'Password must contain lowercase letter' });
                if (policy.requireNumbers && !/\d/.test(newPassword)) return res.status(400).json({ error: 'Password must contain number' });
                if (policy.requireSpecial && !/[^A-Za-z0-9]/.test(newPassword)) return res.status(400).json({ error: 'Password must contain special character' });
                
                // Check history
                db.all('SELECT password_hash FROM admin_password_history WHERE admin_username = ? ORDER BY changed_at DESC LIMIT ?',
                    [req.admin.username, policy.historyCount || 5], async (err, history) => {
                        if (err) return res.status(500).json({ error: err.message });
                        for (const h of history) {
                            if (await bcrypt.compare(newPassword, h.password_hash)) {
                                return res.status(400).json({ error: 'Password cannot be reused from recent history' });
                            }
                        }
                        
                        const hash = await bcrypt.hash(newPassword, 12);
                        db.run('INSERT INTO admin_password_history (admin_username, password_hash) VALUES (?, ?)',
                            [req.admin.username, hash], function(err) {
                                if (err) return res.status(500).json({ error: err.message });
                                res.json({ message: 'Password changed successfully' });
                            });
                    });
            });
        });
});

// Audit log retention policy
app.get('/api/admin/audit-retention', (req, res) => {
    db.get('SELECT * FROM audit_log_retention LIMIT 1', (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        const retention = row || { retention_days: 365, last_cleanup: null, auto_cleanup: 1 };
        res.json({ retention });
    });
});

app.put('/api/admin/audit-retention', (req, res) => {
    const { retention_days, auto_cleanup } = req.body;
    if (!Number.isInteger(retention_days) || retention_days < 30 || retention_days > 2555) {
        return res.status(400).json({ error: 'retention_days must be 30-2555' });
    }
    db.run(`INSERT OR REPLACE INTO audit_log_retention (retention_days, auto_cleanup) VALUES (?, ?)`,
        [retention_days, auto_cleanup ? 1 : 0], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Audit log retention policy updated', retention_days, auto_cleanup });
        });
});

// Manual audit log cleanup
app.post('/api/admin/audit-cleanup', (req, res) => {
    db.get('SELECT retention_days FROM audit_log_retention LIMIT 1', (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        const retentionDays = row?.retention_days || 365;
        const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
        db.run('DELETE FROM audit_logs WHERE created_at < ?', [cutoff], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            db.run('UPDATE audit_log_retention SET last_cleanup = CURRENT_TIMESTAMP');
            res.json({ message: `Cleaned up ${this.changes} old audit logs`, deleted: this.changes });
        });
    });
});

// Subscription renewal reminder via WhatsApp
app.post('/api/admin/send-renewal-reminders', (req, res) => {
    const daysBefore = req.body.days_before || 3;
    const reminderDate = new Date(Date.now() + daysBefore * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    db.all(`SELECT u.id, u.name, u.whatsapp_number, u.subscription_expires_at, p.name as plan_name
            FROM users u JOIN plans p ON p.id = u.plan_id
            WHERE u.plan_status = 'Active' AND date(u.subscription_expires_at) = ?`, [reminderDate], (err, users) => {
        if (err) return res.status(500).json({ error: err.message });
        
        const promises = users.map(user => {
            const message = `Hi ${user.name}, your ${user.plan_name} plan expires in ${daysBefore} days (${user.subscription_expires_at}). Please renew to avoid service interruption. Reply RENEW or visit dashboard.`;
            return whatsapp.sendMessage(user.whatsapp_number, message)
                .then(() => {
                    db.run('INSERT INTO subscription_reminders (user_id, reminder_type, expires_at) VALUES (?, ?, ?)',
                        [user.id, 'renewal', user.subscription_expires_at]);
                    return { user: user.name, sent: true };
                })
                .catch(err => ({ user: user.name, sent: false, error: err.message }));
        });
        
        Promise.all(promises).then(results => {
            const sent = results.filter(r => r.sent).length;
            res.json({ message: `Sent ${sent} of ${users.length} renewal reminders`, results });
        });
    });
});

// DDoS/WAF protection middleware
const suspiciousPatterns = [
    /<script/i, /javascript:/i, /onload=/i, /onerror=/i, /onclick=/i,
    /union.*select/i, /drop.*table/i, /insert.*into/i, /delete.*from/i,
    /\.\.\//, /etc\/passwd/, /proc\/self/, /\.env/, /wp-admin/, /phpmyadmin/
];

app.use((req, res, next) => {
    // Skip for health checks
    if (req.path === '/' || req.path === '/robots.txt' || req.path === '/sitemap.xml') return next();
    
    // Check for suspicious patterns in query params, body, and URL
    const checkValue = (val) => {
        if (typeof val !== 'string') return false;
        return suspiciousPatterns.some(p => p.test(val));
    };
    
    const suspicious = checkValue(req.url) || 
        (req.body && Object.values(req.body).some(checkValue)) ||
        (req.query && Object.values(req.query).some(checkValue));
    
    if (suspicious) {
        const ip = req.socket.remoteAddress;
        console.warn(`WAF blocked suspicious request from ${ip}: ${req.method} ${req.url}`);
        return res.status(403).json({ error: 'Request blocked by security policy' });
    }
    next();
});

// Per-site analytics endpoint
app.get('/api/user/analytics/:websiteId', authenticateToken, (req, res) => {
    const websiteId = Number(req.params.websiteId);
    const days = Number(req.query.days) || 30;
    if (!Number.isInteger(websiteId) || websiteId <= 0) {
        return res.status(400).json({ error: 'Invalid website ID' });
    }
    db.get('SELECT id FROM websites WHERE id = ? AND user_id = ?', [websiteId, req.user.id], (err, site) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!site) return res.status(404).json({ error: 'Website not found' });
        
        const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
        db.all(`SELECT date, visits, unique_visitors, page_views, bandwidth_bytes, avg_response_time_ms
                FROM per_site_analytics WHERE website_id = ? AND date >= ? ORDER BY date`,
            [websiteId, startDate], (err, rows) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ analytics: rows });
            });
    });
});

// Admin per-site analytics
app.get('/api/admin/analytics/:websiteId', (req, res) => {
    const websiteId = Number(req.params.websiteId);
    const days = Number(req.query.days) || 30;
    if (!Number.isInteger(websiteId) || websiteId <= 0) {
        return res.status(400).json({ error: 'Invalid website ID' });
    }
    const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    db.all(`SELECT a.*, w.subdomain, u.name as owner
            FROM per_site_analytics a
            JOIN websites w ON w.id = a.website_id
            JOIN users u ON u.id = w.user_id
            WHERE a.website_id = ? AND a.date >= ? ORDER BY a.date`,
        [websiteId, startDate], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ analytics: rows });
        });
});

// WhatsApp QR verification status
app.get('/api/admin/whatsapp/qr-status', (req, res) => {
    const status = whatsapp.getStatus();
    res.json({ 
        ready: status.ready,
        qrCode: status.qrCode,
        authenticated: status.authenticated
    });
});

app.get('/', (req, res) => {
  res.send('Assudani Hosting API is running');
});

app.use('/api', (req, res) => {
    res.status(404).json({ error: `API route not found: ${req.method} ${req.path}` });
});

app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    if (error instanceof multer.MulterError) {
        const tooLarge = error.code === 'LIMIT_FILE_SIZE';
        return res.status(tooLarge ? 413 : 400).json({
            error: tooLarge ? 'Uploaded file exceeds the permitted size limit' : `Upload error: ${error.message}`
        });
    }
    if (error && error.message === 'Screenshot must be a JPEG, PNG, WebP, or GIF image') {
        return res.status(400).json({ error: error.message });
    }
    res.status(500).json({ error: `Request processing error: ${error.message}` });
});

if (require.main === module) {
    const server = app.listen(port);
    server.on('error', (error) => {
        if (error.code === 'EADDRINUSE') {
            console.error(`Unable to start API: port ${port} is already in use. Stop the existing backend process or set PORT to another available port.`);
        } else {
            console.error(`Unable to start API: ${error.message}`);
        }
        process.exitCode = 1;
    });
    server.once('listening', () => {
        const address = server.address();
        if (!address) {
            console.error('Unable to start API: listener reported ready without a bound address.');
            process.exitCode = 1;
            return server.close();
        }
        const listeningOn = typeof address === 'string' ? address : address.port;
        console.log(`Server is running on ${typeof address === 'string' ? address : `port ${listeningOn}`}`);
        if (process.env.WHATSAPP_ENABLED === 'true') {
            whatsapp.initialize().catch((error) => {
                console.error(`WhatsApp initialization failed: ${error.message}`);
            });
        }
    });
    module.exports = { app, server };
} else {
    module.exports = { app };
}
