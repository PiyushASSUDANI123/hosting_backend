const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const dbPath = process.env.DATABASE_PATH
  ? path.resolve(process.env.DATABASE_PATH)
  : path.resolve(__dirname, 'hosting.db');
try {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
} catch (err) {
  throw new Error(`Unable to create database directory: ${err.message}`);
}

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
    return;
  }

  console.log('Connected to the SQLite database.');
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS plans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      price REAL NOT NULL,
      storage_limit_mb INTEGER NOT NULL,
      max_websites INTEGER NOT NULL,
      duration_months INTEGER NOT NULL DEFAULT 1,
      monthly_price REAL,
      term_price REAL,
      is_active BOOLEAN DEFAULT 1
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      whatsapp_number TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      plan_id INTEGER,
      plan_status TEXT DEFAULT 'Inactive',
      payment_screenshot_url TEXT,
      utr_number TEXT,
      storage_used REAL DEFAULT 0,
      address_line1 TEXT,
      address_line2 TEXT,
      city TEXT,
      state TEXT,
      postal_code TEXT,
      country TEXT,
      customer_type TEXT NOT NULL DEFAULT 'Customer',
      student_institute TEXT,
      student_course TEXT,
      subscription_expires_at DATETIME,
      paid_at DATETIME,
      first_paid_at DATETIME,
      first_purchase_promo_used BOOLEAN NOT NULL DEFAULT 0,
      subscription_max_websites INTEGER,
      account_status TEXT NOT NULL DEFAULT 'Active' CHECK (account_status IN ('Active', 'Suspended')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (plan_id) REFERENCES plans (id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS websites (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      subdomain TEXT UNIQUE NOT NULL,
      status TEXT DEFAULT 'Offline',
      folder_path TEXT NOT NULL,
      size_mb REAL DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    const ensureColumns = (table, definitions, onComplete) => {
      db.all(`PRAGMA table_info(${table})`, (err, columns) => {
        if (err) {
          console.error(`Database migration failed while reading ${table}:`, err.message);
          if (onComplete) onComplete(err);
          return;
        }
        const existing = new Set(columns.map((column) => column.name));
        const missingDefinitions = definitions.filter(([name]) => !existing.has(name));
        if (!missingDefinitions.length) {
          if (onComplete) onComplete(null);
          return;
        }
        let pending = missingDefinitions.length;
        let migrationError = null;
        const finish = () => {
          pending -= 1;
          if (pending === 0 && onComplete) onComplete(migrationError);
        };
        missingDefinitions.forEach(([name, definition]) => {
            const timestampDefault = name === 'created_at' && /DEFAULT CURRENT_TIMESTAMP/i.test(definition);
            const columnDefinition = timestampDefault ? 'DATETIME' : definition;
            db.run(`ALTER TABLE ${table} ADD COLUMN ${name} ${columnDefinition}`, (alterError) => {
              if (alterError) {
                console.error(`Database migration failed adding ${table}.${name}:`, alterError.message);
                migrationError = alterError;
                return finish();
              }
              if (timestampDefault) {
                db.run(`UPDATE ${table} SET ${name} = CURRENT_TIMESTAMP WHERE ${name} IS NULL`);
                db.run(`CREATE TRIGGER IF NOT EXISTS set_${table}_${name}_default
                        AFTER INSERT ON ${table}
                        WHEN NEW.${name} IS NULL
                        BEGIN
                          UPDATE ${table} SET ${name} = CURRENT_TIMESTAMP WHERE rowid = NEW.rowid;
                        END`, (triggerError) => {
                  if (triggerError) console.error(`Database migration failed creating ${table}.${name} default:`, triggerError.message);
                });
              }
              finish();
            });
        });
      });
    };

    ensureColumns('websites', [
      ['size_mb', 'REAL DEFAULT 0'],
      ['created_at', 'DATETIME DEFAULT CURRENT_TIMESTAMP']
    ]);
    ensureColumns('users', [
      ['created_at', 'DATETIME DEFAULT CURRENT_TIMESTAMP'],
      ['terms_accepted_at', 'DATETIME'],
      ['terms_version', 'TEXT'],
      ['privacy_acknowledged_at', 'DATETIME'],
      ['privacy_version', 'TEXT'],
      ['address_line1', 'TEXT'],
      ['address_line2', 'TEXT'],
      ['city', 'TEXT'],
      ['state', 'TEXT'],
      ['postal_code', 'TEXT'],
      ['country', 'TEXT'],
      ['customer_type', "TEXT NOT NULL DEFAULT 'Customer'"],
      ['student_institute', 'TEXT'],
      ['student_course', 'TEXT'],
      ['occupation', 'TEXT'],
      ['organization', 'TEXT'],
      ['hosting_purpose', 'TEXT'],
      ['referral_source', 'TEXT'],
      ['referral_details', 'TEXT'],
      ['onboarding_step', 'INTEGER NOT NULL DEFAULT 0'],
      ['onboarding_completed_at', 'DATETIME'],
      ['subscription_expires_at', 'DATETIME'],
      ['paid_at', 'DATETIME'],
      ['first_paid_at', 'DATETIME'],
      ['first_purchase_promo_used', 'BOOLEAN NOT NULL DEFAULT 0'],
      ['subscription_max_websites', 'INTEGER'],
      ['account_status', "TEXT NOT NULL DEFAULT 'Active'"]
    ], (migrationError) => {
      if (migrationError) return;
      db.run(`UPDATE users SET first_paid_at = COALESCE(paid_at, created_at, CURRENT_TIMESTAMP)
              WHERE first_paid_at IS NULL AND plan_id IS NOT NULL AND plan_status = 'Active'
                AND NOT EXISTS (SELECT 1 FROM admin_access_grants g WHERE g.user_id = users.id)`);
    });

    ensureColumns('plans', [
      ['duration_months', 'INTEGER NOT NULL DEFAULT 1'],
      ['monthly_price', 'REAL'],
      ['term_price', 'REAL']
    ], (migrationError) => {
      if (migrationError) return;
      db.run('UPDATE plans SET monthly_price = price WHERE monthly_price IS NULL', (monthlyError) => {
        if (monthlyError) {
          console.error('Database migration failed updating monthly plan prices:', monthlyError.message);
          return;
        }
        db.run('UPDATE plans SET term_price = price WHERE term_price IS NULL', (termError) => {
          if (termError) {
            console.error('Database migration failed updating plan term prices:', termError.message);
            return;
          }
          db.run(`WITH catalog(name, monthly_price, term_price, duration_months, storage_limit_mb, max_websites) AS (
                    VALUES
                        ('Launch', 199, 549, 3, 15, 1),
                        ('Creator', 299, 799, 3, 45, 3),
                        ('Growth', 499, 1299, 3, 150, 10)
                  )
                  INSERT INTO plans (name, price, monthly_price, term_price, duration_months, storage_limit_mb, max_websites)
                  SELECT name, term_price, monthly_price, term_price, duration_months, storage_limit_mb, max_websites
                  FROM catalog
                  WHERE NOT EXISTS (SELECT 1 FROM plans)`,
            (seedError) => {
              if (seedError) {
                console.error('Database migration failed seeding default plans:', seedError.message);
                return;
              }
              db.run('UPDATE plans SET storage_limit_mb = max_websites * 15 WHERE max_websites > 0',
                (storageError) => {
                  if (storageError) console.error('Database migration failed updating per-website storage quotas:', storageError.message);
                });
            });
        });
      });
    });

    db.run(`CREATE TABLE IF NOT EXISTS admin_access_grants (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      plan_id INTEGER NOT NULL,
      duration_months INTEGER NOT NULL CHECK (duration_months BETWEEN 1 AND 3),
      reason TEXT NOT NULL,
      granted_by TEXT NOT NULL,
      starts_at DATETIME NOT NULL,
      expires_at DATETIME NOT NULL,
      status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Expired', 'Revoked')),
      created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id),
      FOREIGN KEY (plan_id) REFERENCES plans (id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS coupons (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT NOT NULL COLLATE NOCASE UNIQUE,
      description TEXT,
      discount_type TEXT NOT NULL CHECK (discount_type IN ('percent', 'fixed')),
      discount_value REAL NOT NULL,
      max_discount REAL,
      max_redemptions INTEGER,
      per_user_limit INTEGER NOT NULL DEFAULT 1,
      plan_id INTEGER,
      starts_at DATETIME,
      expires_at DATETIME,
      is_active BOOLEAN NOT NULL DEFAULT 1,
      created_by TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (plan_id) REFERENCES plans (id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS announcements (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL CHECK (type IN ('banner', 'notification', 'both')),
      severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'success', 'warning')),
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      link_url TEXT,
      starts_at DATETIME,
      expires_at DATETIME,
      is_active BOOLEAN NOT NULL DEFAULT 1,
      created_by TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS announcement_reads (
      announcement_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      read_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (announcement_id, user_id),
      FOREIGN KEY (announcement_id) REFERENCES announcements (id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor TEXT NOT NULL,
      action TEXT NOT NULL,
      method TEXT NOT NULL,
      route TEXT NOT NULL,
      status_code INTEGER NOT NULL,
      request_id TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS admin_login_limits (
      ip_hash TEXT PRIMARY KEY,
      window_started_at DATETIME NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      locked_until DATETIME
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      plan_id INTEGER NOT NULL,
      utr_number TEXT,
      screenshot_url TEXT,
      status TEXT NOT NULL DEFAULT 'Pending',
      quantity INTEGER NOT NULL DEFAULT 1,
      duration_months INTEGER NOT NULL DEFAULT 1,
      amount REAL NOT NULL DEFAULT 0,
      is_first_purchase_promo BOOLEAN NOT NULL DEFAULT 0,
      plan_name TEXT,
      plan_monthly_price REAL,
      plan_term_price REAL,
      max_websites INTEGER,
      storage_limit_mb INTEGER,
      approved_at DATETIME,
      rejected_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id),
      FOREIGN KEY (plan_id) REFERENCES plans (id)
    )`, (err) => {
      if (err) {
        console.error('Database migration failed creating payments:', err.message);
      } else {
        ensureColumns('payments', [
          ['user_id', 'INTEGER'],
          ['plan_id', 'INTEGER'],
          ['utr_number', "TEXT NOT NULL DEFAULT ''"],
          ['screenshot_url', 'TEXT'],
          ['status', "TEXT NOT NULL DEFAULT 'Pending'"],
          ['quantity', 'INTEGER NOT NULL DEFAULT 1'],
          ['duration_months', 'INTEGER NOT NULL DEFAULT 1'],
          ['amount', 'REAL NOT NULL DEFAULT 0'],
          ['is_first_purchase_promo', 'BOOLEAN NOT NULL DEFAULT 0'],
          ['coupon_id', 'INTEGER'],
          ['coupon_code', 'TEXT'],
          ['coupon_discount', 'REAL NOT NULL DEFAULT 0'],
          ['plan_name', 'TEXT'],
          ['plan_monthly_price', 'REAL'],
          ['plan_term_price', 'REAL'],
          ['max_websites', 'INTEGER'],
          ['storage_limit_mb', 'INTEGER'],
          ['approved_at', 'DATETIME'],
          ['rejected_at', 'DATETIME'],
          ['terms_accepted_at', 'DATETIME'],
          ['terms_version', 'TEXT'],
          ['created_at', 'DATETIME DEFAULT CURRENT_TIMESTAMP']
        ], (migrationError) => {
          if (migrationError) return;
          db.run(`INSERT INTO payments
            (user_id, plan_id, utr_number, screenshot_url, status, quantity, duration_months,
             amount, plan_name, plan_monthly_price, plan_term_price, max_websites, storage_limit_mb)
            SELECT u.id, u.plan_id, COALESCE(u.utr_number, ''), u.payment_screenshot_url, 'Pending',
                   1, COALESCE(p.duration_months, 1), COALESCE(p.term_price, p.price, 0),
                   p.name, COALESCE(p.monthly_price, p.price), COALESCE(p.term_price, p.price),
                   p.max_websites, p.storage_limit_mb
            FROM users u JOIN plans p ON p.id = u.plan_id
            WHERE u.plan_status = 'Pending'
              AND NOT EXISTS (
                SELECT 1 FROM payments pay
                WHERE pay.user_id = u.id AND pay.status = 'Pending' AND pay.plan_id = u.plan_id
              )`, (seedError) => {
            if (seedError) console.error('Database migration failed importing pending payments:', seedError.message);
          });

          db.run(`CREATE TABLE IF NOT EXISTS coupon_redemptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            coupon_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            payment_id INTEGER NOT NULL UNIQUE,
            status TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'Approved', 'Rejected')),
            discount_amount REAL NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (coupon_id) REFERENCES coupons (id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (payment_id) REFERENCES payments (id) ON DELETE CASCADE
          )`);
        });
      }
    });

    db.run(`CREATE TABLE IF NOT EXISTS support_tickets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL CHECK (type IN ('issue', 'feedback')),
      subject TEXT NOT NULL,
      message TEXT NOT NULL,
      category TEXT,
      status TEXT NOT NULL DEFAULT 'Open',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`, (err) => {
      if (err) {
        console.error('Database migration failed creating support_tickets:', err.message);
      } else {
        ensureColumns('support_tickets', [
          ['user_id', 'INTEGER'],
          ['type', "TEXT NOT NULL DEFAULT 'issue'"],
          ['subject', "TEXT NOT NULL DEFAULT ''"],
          ['message', "TEXT NOT NULL DEFAULT ''"],
          ['category', 'TEXT'],
          ['status', "TEXT NOT NULL DEFAULT 'Open'"],
          ['created_at', 'DATETIME DEFAULT CURRENT_TIMESTAMP']
        ]);
      }
    });

    db.run(`CREATE TABLE IF NOT EXISTS password_reset_tokens (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at DATETIME NOT NULL,
      used_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`, (err) => {
      if (err) console.error('Database migration failed creating password_reset_tokens:', err.message);
    });

    db.run(`CREATE TABLE IF NOT EXISTS password_reset_otps (
      user_id INTEGER PRIMARY KEY,
      otp_hash TEXT NOT NULL,
      expires_at DATETIME NOT NULL,
      resend_after DATETIME NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      request_window_started_at DATETIME NOT NULL,
      request_count INTEGER NOT NULL DEFAULT 1,
      used_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS password_reset_otp_ip_limits (
      ip_hash TEXT PRIMARY KEY,
      window_started_at DATETIME NOT NULL,
      request_count INTEGER NOT NULL DEFAULT 1
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS user_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      device_id TEXT NOT NULL,
      device_name TEXT,
      browser TEXT,
      os TEXT,
      ip_hash TEXT,
      user_agent TEXT,
      is_current BOOLEAN NOT NULL DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_activity_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS admin_notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      category TEXT,
      created_by TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS admin_settings (
      key TEXT PRIMARY KEY,
      value TEXT,
      description TEXT,
      updated_by TEXT,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS admin_password_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      admin_username TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      changed_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS audit_log_retention (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      retention_days INTEGER NOT NULL DEFAULT 365,
      last_cleanup DATETIME,
      auto_cleanup BOOLEAN NOT NULL DEFAULT 1
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS invoices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      payment_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      invoice_number TEXT NOT NULL UNIQUE,
      amount REAL NOT NULL,
      service_tax REAL NOT NULL,
      dashboard_tax REAL NOT NULL,
      total_amount REAL NOT NULL,
      status TEXT NOT NULL DEFAULT 'Pending',
      pdf_path TEXT,
      generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (payment_id) REFERENCES payments (id),
      FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS subscription_reminders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      reminder_type TEXT NOT NULL,
      sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS per_site_analytics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      website_id INTEGER NOT NULL,
      date DATE NOT NULL,
      visits INTEGER NOT NULL DEFAULT 0,
      unique_visitors INTEGER NOT NULL DEFAULT 0,
      page_views INTEGER NOT NULL DEFAULT 0,
      bandwidth_bytes INTEGER NOT NULL DEFAULT 0,
      avg_response_time_ms INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (website_id) REFERENCES websites (id) ON DELETE CASCADE,
      UNIQUE(website_id, date)
    )`);

    const defaultSettings = [
      ['upi_id', 'piyushassudani@yespop', 'UPI ID for payments'],
      ['upi_qr_url', '', 'UPI QR code image URL'],
      ['support_email', 'piyushassudani96@gmail.com', 'Support email address'],
      ['support_phone', '+91 9413879444', 'Support phone number'],
      ['support_website', 'https://piyushassudani.in', 'Support website URL'],
      ['github_url', 'https://github.com/PiyushASSUDANI123', 'GitHub profile URL'],
      ['linkedin_url', 'https://www.linkedin.com/in/piyush-assudani96/', 'LinkedIn profile URL'],
      ['service_tax_percent', '3', 'Service tax percentage'],
      ['dashboard_tax_percent', '3', 'Dashboard tax percentage'],
      ['banner_message', '', 'Sidebar banner message (optional)'],
      ['banner_enabled', '0', 'Enable sidebar banner (0/1)'],
    ];
    defaultSettings.forEach(([key, value, description]) => {
      db.run(`INSERT OR IGNORE INTO admin_settings (key, value, description) VALUES (?, ?, ?)`, [key, value, description]);
    });

    // --- Developer Plan & Owner Account Setup ---
    // Hidden plan (is_active=0) with unlimited resources for the developer/owner
    db.run(`INSERT OR IGNORE INTO plans (name, price, storage_limit_mb, max_websites, duration_months, monthly_price, term_price, is_active)
            VALUES ('Developer', 0, 999999, 9999, 12, 0, 0, 0)`, function(planErr) {
      if (planErr && !planErr.message.includes('UNIQUE')) {
        console.error('Developer plan seed error:', planErr.message);
        return;
      }
      db.get(`SELECT id FROM plans WHERE name = 'Developer' LIMIT 1`, (err, devPlan) => {
        if (err || !devPlan) return;
        const devEmail = 'piyushassudani96@gmail.com';
        const devPassword = 'piyushassudani@300609';
        const bcrypt = require('bcrypt');
        bcrypt.hash(devPassword, 10).then(hash => {
          // Check if account exists
          db.get(`SELECT id FROM users WHERE email = ?`, [devEmail], (userErr, existingUser) => {
            if (userErr) return;
            if (existingUser) {
              // Update existing account to developer
              db.run(`UPDATE users SET
                password_hash = ?,
                plan_id = ?,
                plan_status = 'Active',
                subscription_expires_at = '2099-12-31T23:59:59.000Z',
                subscription_max_websites = 9999,
                terms_accepted_at = COALESCE(terms_accepted_at, datetime('now')),
                privacy_acknowledged_at = COALESCE(privacy_acknowledged_at, datetime('now'))
                WHERE email = ?`, [hash, devPlan.id, devEmail], function(updateErr) {
                if (updateErr) console.error('Developer account update error:', updateErr.message);
                else console.log('Developer account ready:', devEmail);
              });
            } else {
              // Create fresh developer account
              db.run(`INSERT INTO users (name, email, whatsapp_number, password_hash, plan_id, plan_status,
                      subscription_expires_at, subscription_max_websites, customer_type,
                      terms_accepted_at, privacy_acknowledged_at)
                      VALUES ('Piyush Assudani', ?, '+919413879444', ?, ?, 'Active',
                      '2099-12-31T23:59:59.000Z', 9999, 'Customer',
                      datetime('now'), datetime('now'))`, [devEmail, hash, devPlan.id], function(insertErr) {
                if (insertErr) console.error('Developer account creation error:', insertErr.message);
                else console.log('Developer account created:', devEmail);
              });
            }
          });
        }).catch(err => console.error('Developer account bcrypt error:', err.message));
      });
    });

  });
});

module.exports = db;
