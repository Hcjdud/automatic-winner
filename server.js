const express = require('express');
const nodemailer = require('nodemailer');
const sqlite3 = require('sqlite3').verbose();
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const compression = require('compression');
const crypto = require('crypto');
const path = require('path');
const axios = require('axios');
const session = require('express-session');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ===== ЗАЩИТА =====
app.use(helmet({
  contentSecurityPolicy: false,
}));
app.use(compression());

// Куки и сессии для запоминания пользователей
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'wtf-mail-secret-key-2026',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: false,
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
}));

// Глобальный лимитер
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Слишком много запросов' }
});
app.use(globalLimiter);

// Лимитер для API
const apiLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: { error: 'Слишком много попыток. Попробуйте через час.' },
  keyGenerator: (req) => req.body.email || req.ip
});

const resendLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 1,
  message: { error: 'Подождите минуту перед повторной отправкой' }
});

// Middleware
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ===== БАЗА ДАННЫХ =====
const db = new sqlite3.Database('./database.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    surname TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    status TEXT DEFAULT 'pending',
    ip_address TEXT,
    country TEXT,
    city TEXT,
    user_agent TEXT,
    registered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    confirmed_at DATETIME,
    last_login DATETIME
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    code TEXT NOT NULL,
    attempts INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT NOT NULL,
    user_name TEXT NOT NULL,
    user_surname TEXT NOT NULL,
    message_text TEXT NOT NULL,
    sent_to_admin TEXT DEFAULT 'anaevgrafova6@gmail.com',
    sent_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  console.log('✅ База данных готова');
});

// ===== НАСТРОЙКА ПОЧТЫ =====
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: true,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

transporter.verify((error, success) => {
  if (error) {
    console.log('❌ Ошибка почты. Проверьте .env файл');
  } else {
    console.log('✅ Почта готова к отправке');
  }
});

// ===== ФУНКЦИИ =====

function generateCode() {
  return crypto.randomInt(100000, 999999).toString();
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const ip = forwarded ? forwarded.split(',')[0] : req.socket.remoteAddress;
  return ip === '::1' ? '127.0.0.1' : ip || 'unknown';
}

async function getGeoInfo(ip) {
  if (ip === '127.0.0.1' || ip === 'localhost' || ip.startsWith('192.168.') || ip.startsWith('10.')) {
    return {
      country: 'Локальная сеть',
      city: 'Локальный IP'
    };
  }

  try {
    const response = await axios.get(`http://ip-api.com/json/${ip}?fields=status,country,city,query`, {
      timeout: 3000
    });
    
    if (response.data.status === 'success') {
      return {
        country: response.data.country || 'Неизвестно',
        city: response.data.city || 'Неизвестно'
      };
    }
  } catch (error) {
    console.log('⚠️ Не удалось получить геолокацию для IP:', ip);
  }
  
  return {
    country: 'Не удалось определить',
    city: 'Не удалось определить'
  };
}

// Middleware для проверки авторизации
function isAuthenticated(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.status(401).json({ error: 'Не авторизован' });
  }
}

async function sendVerificationEmail(email, name, surname, code) {
  const mailOptions = {
    from: `"WTF Mail" <${process.env.SMTP_USER}>`,
    to: email,
    subject: 'Verify your email',
    html: `
      <!DOCTYPE html>
      <html>
      <head><meta charset="UTF-8"></head>
      <body style="font-family:Arial; background:#f4f4f4; padding:20px;">
        <div style="max-width:600px; margin:0 auto; background:white; border-radius:10px; padding:30px;">
          <h2 style="color:#333; text-align:center;">Verify your email</h2>
          <p>Hi <strong>${name} ${surname}</strong>,</p>
          <p>Enter the code below:</p>
          <div style="font-size:36px; letter-spacing:10px; text-align:center; background:#f0f0f0; padding:20px;">${code}</div>
          <p>Expires in ${process.env.CODE_EXPIRY_MINUTES} minutes</p>
          <p style="margin-top:30px;">WTF</p>
          <p style="color:#999; font-size:12px;">Sent from ${process.env.SMTP_USER}</p>
        </div>
      </body>
      </html>
    `
  };
  return await transporter.sendMail(mailOptions);
}

async function sendAdminNotification(userData, ip, geoInfo) {
  const mailOptions = {
    from: `"WTF Mail Admin" <${process.env.SMTP_USER}>`,
    to: process.env.ADMIN_EMAIL,
    subject: '✅ НОВАЯ РЕГИСТРАЦИЯ',
    html: `
      <h2>✅ НОВАЯ РЕГИСТРАЦИЯ</h2>
      <p><strong>Имя:</strong> ${userData.name} ${userData.surname}</p>
      <p><strong>Email:</strong> ${userData.email}</p>
      <p><strong>IP:</strong> ${ip}</p>
      <p><strong>Страна:</strong> ${geoInfo.country}</p>
      <p><strong>Город:</strong> ${geoInfo.city}</p>
      <p><strong>Дата:</strong> ${new Date().toLocaleString('ru-RU')}</p>
      <p style="margin-top:30px;">WTF</p>
    `
  };
  return await transporter.sendMail(mailOptions);
}

async function sendUserMessageToAdmin(userData, messageText) {
  const mailOptions = {
    from: `"WTF Mail User" <${process.env.SMTP_USER}>`,
    to: process.env.ADMIN_EMAIL,
    subject: `📨 Сообщение от ${userData.name} ${userData.surname}`,
    html: `
      <h2>📨 НОВОЕ СООБЩЕНИЕ</h2>
      <p><strong>От:</strong> ${userData.name} ${userData.surname} (${userData.email})</p>
      <p><strong>Сообщение:</strong></p>
      <div style="background:#f0f0f0; padding:15px; border-radius:5px;">${messageText}</div>
      <p><strong>Дата:</strong> ${new Date().toLocaleString('ru-RU')}</p>
      <p style="margin-top:30px;">WTF</p>
    `
  };
  return await transporter.sendMail(mailOptions);
}

// Очистка старых кодов
function cleanupOldCodes() {
  db.run(`DELETE FROM codes WHERE datetime(created_at) < datetime('now', '-${process.env.CODE_EXPIRY_MINUTES} minutes')`);
}
setInterval(cleanupOldCodes, 5 * 60 * 1000);
cleanupOldCodes();

// ===== API =====

// Проверка авторизации
app.get('/api/check-auth', (req, res) => {
  if (req.session.user) {
    res.json({ 
      authenticated: true, 
      user: {
        name: req.session.user.name,
        surname: req.session.user.surname,
        email: req.session.user.email
      }
    });
  } else {
    res.json({ authenticated: false });
  }
});

// Регистрация
app.post('/api/register', apiLimiter, [
  body('name').trim().isLength({ min: 2, max: 50 }),
  body('surname').trim().isLength({ min: 2, max: 50 }),
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Проверьте правильность введенных данных' });
    }

    const { name, surname, email } = req.body;
    const ip = getClientIp(req);
    const userAgent = req.headers['user-agent'];

    const userExists = await new Promise((resolve) => {
      db.get('SELECT email FROM users WHERE email = ?', [email], (err, row) => resolve(row));
    });

    if (userExists) {
      return res.status(400).json({ error: 'Email уже зарегистрирован' });
    }

    const code = generateCode();
    const expiresAt = new Date(Date.now() + process.env.CODE_EXPIRY_MINUTES * 60 * 1000).toISOString();

    await new Promise((resolve, reject) => {
      db.serialize(() => {
        db.run('BEGIN TRANSACTION');
        
        db.run(
          'INSERT INTO users (name, surname, email, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)',
          [name, surname, email, ip, userAgent],
          function(err) {
            if (err) {
              db.run('ROLLBACK');
              reject(err);
              return;
            }
            
            db.run(
              'INSERT INTO codes (email, code, expires_at) VALUES (?, ?, ?)',
              [email, code, expiresAt],
              (err) => {
                if (err) {
                  db.run('ROLLBACK');
                  reject(err);
                  return;
                }
                
                db.run('COMMIT', resolve);
              }
            );
          }
        );
      });
    });

    await sendVerificationEmail(email, name, surname, code);
    res.json({ success: true, email });

  } catch (error) {
    console.error('Ошибка регистрации:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Проверка кода
app.post('/api/verify', apiLimiter, [
  body('email').isEmail().normalizeEmail(),
  body('code').isLength({ min: 6, max: 6 }).isNumeric()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Неверный формат' });
    }

    const { email, code } = req.body;
    const ip = getClientIp(req);

    const codeData = await new Promise((resolve) => {
      db.get(
        'SELECT * FROM codes WHERE email = ? ORDER BY created_at DESC LIMIT 1',
        [email],
        (err, row) => resolve(row)
      );
    });

    if (!codeData) {
      return res.status(400).json({ error: 'Код не найден' });
    }

    if (new Date() > new Date(codeData.expires_at)) {
      db.run('DELETE FROM codes WHERE id = ?', [codeData.id]);
      return res.status(400).json({ error: 'Код истек' });
    }

    if (codeData.attempts >= process.env.MAX_ATTEMPTS) {
      return res.status(400).json({ error: 'Слишком много попыток' });
    }

    if (codeData.code !== code) {
      db.run('UPDATE codes SET attempts = attempts + 1 WHERE id = ?', [codeData.id]);
      const attemptsLeft = process.env.MAX_ATTEMPTS - (codeData.attempts + 1);
      return res.status(400).json({ error: `Неверный код. Осталось попыток: ${attemptsLeft}` });
    }

    const userData = await new Promise((resolve) => {
      db.get(
        'SELECT name, surname, email, ip_address, user_agent FROM users WHERE email = ?',
        [email],
        (err, row) => resolve(row)
      );
    });

    const geoInfo = await getGeoInfo(ip);

    db.run(
      'UPDATE users SET country = ?, city = ?, status = ?, confirmed_at = CURRENT_TIMESTAMP, last_login = CURRENT_TIMESTAMP WHERE email = ?',
      [geoInfo.country, geoInfo.city, 'confirmed', email]
    );
    
    db.run('DELETE FROM codes WHERE email = ?', [email]);

    req.session.user = {
      name: userData.name,
      surname: userData.surname,
      email: userData.email
    };

    await sendAdminNotification(userData, ip, geoInfo);

    res.json({ 
      success: true, 
      name: userData.name, 
      surname: userData.surname 
    });

  } catch (error) {
    console.error('Ошибка проверки кода:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Отправка сообщения
app.post('/api/send-message', isAuthenticated, [
  body('message').trim().isLength({ min: 1, max: 1000 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Сообщение не может быть пустым' });
    }

    const { message } = req.body;
    const userEmail = req.session.user.email;

    const userData = await new Promise((resolve) => {
      db.get(
        'SELECT name, surname, email FROM users WHERE email = ?',
        [userEmail],
        (err, row) => resolve(row)
      );
    });

    if (!userData) {
      return res.status(400).json({ error: 'Пользователь не найден' });
    }

    await new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO messages (user_email, user_name, user_surname, message_text) VALUES (?, ?, ?, ?)',
        [userEmail, userData.name, userData.surname, message],
        function(err) {
          if (err) reject(err);
          resolve();
        }
      );
    });

    await sendUserMessageToAdmin(userData, message);
    res.json({ success: true, message: 'Сообщение отправлено' });

  } catch (error) {
    console.error('Ошибка отправки сообщения:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Выход
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Повторная отправка кода
app.post('/api/resend', resendLimiter, [
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Неверный email' });
    }

    const { email } = req.body;

    const userData = await new Promise((resolve) => {
      db.get(
        'SELECT name, surname FROM users WHERE email = ? AND status = "pending"',
        [email],
        (err, row) => resolve(row)
      );
    });

    if (!userData) {
      return res.status(400).json({ error: 'Пользователь не найден' });
    }

    const code = generateCode();
    const expiresAt = new Date(Date.now() + process.env.CODE_EXPIRY_MINUTES * 60 * 1000).toISOString();

    db.run(
      'INSERT INTO codes (email, code, expires_at) VALUES (?, ?, ?)',
      [email, code, expiresAt]
    );

    await sendVerificationEmail(email, userData.name, userData.surname, code);
    res.json({ success: true, message: 'Новый код отправлен' });

  } catch (error) {
    console.error('Ошибка повторной отправки:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Получение оставшегося времени
app.get('/api/time-left', (req, res) => {
  const { email } = req.query;

  db.get(
    'SELECT expires_at FROM codes WHERE email = ? ORDER BY created_at DESC LIMIT 1',
    [email],
    (err, row) => {
      if (err || !row) {
        return res.json({ timeLeft: 0 });
      }

      const timeLeft = Math.max(0, (new Date(row.expires_at) - new Date()) / 1000);
      res.json({ timeLeft });
    }
  );
});

// Статистика
app.get('/api/stats', (req, res) => {
  db.get(
    'SELECT COUNT(*) as total, SUM(CASE WHEN status = "confirmed" THEN 1 ELSE 0 END) as confirmed FROM users',
    (err, row) => {
      res.json(row || { total: 0, confirmed: 0 });
    }
  );
});

// ===== ЗАПУСК =====
app.listen(PORT, '0.0.0.0', () => {
  console.log('=' .repeat(60));
  console.log(`🚀 СЕРВЕР ЗАПУЩЕН НА ПОРТУ ${PORT}`);
  console.log('=' .repeat(60));
  console.log(`📧 Отправка писем с: ${process.env.SMTP_USER}`);
  console.log(`📨 Уведомления админу: ${process.env.ADMIN_EMAIL}`);
  console.log('=' .repeat(60));
});
