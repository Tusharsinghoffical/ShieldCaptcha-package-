/**
 * ShieldCaptcha Standalone Demo Server
 * Zero-dependency demonstration of full client + server integration.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const { ShieldCaptcha } = require('../index');

// Try loading local .env
function loadEnv() {
  const envPath = path.resolve(process.cwd(), '.env');
  if (fs.existsSync(envPath)) {
    try {
      const content = fs.readFileSync(envPath, 'utf8');
      content.split('\n').forEach(line => {
        const match = line.match(/^\s*([\w.-]+)\s*=\s*(.*)?\s*$/);
        if (match) {
          const key = match[1];
          let val = (match[2] || '').trim();
          if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1);
          if (val.startsWith("'") && val.endsWith("'")) val = val.slice(1, -1);
          if (!process.env[key]) process.env[key] = val;
        }
      });
    } catch {}
  }
}

loadEnv();

const siteKey = process.env.SHIELDCAPTCHA_SITE_KEY || process.env.NEXT_PUBLIC_SITE_KEY || 'pub_shield_live_demo_sitekey';
const secretKey = process.env.SHIELDCAPTCHA_SECRET_KEY || process.env.SITE_SECRET || 'sec_shield_live_demo_secretkey';
const apiUrl = process.env.SHIELDCAPTCHA_API_URL || process.env.NEXT_PUBLIC_CAPTCHA_API || 'https://shieldcaptcha.vercel.app';
const port = parseInt(process.env.PORT || '4000', 10);

const captcha = new ShieldCaptcha({ siteKey, secretKey, apiUrl });

const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
  const pathname = parsedUrl.pathname;

  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Site-Secret');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  // 1. Serve client-side demo HTML
  if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
    const htmlPath = path.join(__dirname, 'public', 'index.html');
    if (fs.existsSync(htmlPath)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(htmlPath));
    }
  }

  // 2. Serve bundled captcha.js
  if (req.method === 'GET' && pathname === '/captcha.js') {
    const jsPath = path.join(__dirname, '..', 'client', 'captcha.js');
    if (fs.existsSync(jsPath)) {
      res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
      return res.end(fs.readFileSync(jsPath));
    }
  }

  // 3. API Config for frontend widget
  if (req.method === 'GET' && pathname === '/api/config') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      siteKey,
      apiUrl,
      hasSecretKey: Boolean(secretKey)
    }));
  }

  // 4. Server-Side Verification Endpoint
  if (req.method === 'POST' && pathname === '/api/login') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', async () => {
      try {
        const data = JSON.parse(body);
        const token = data.token || data.captcha_token;
        const email = data.email || 'user@example.com';
        const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress;

        // Verify with ShieldCaptcha SDK
        const verification = await captcha.verify({ token, remoteIp: clientIp });

        if (verification.success) {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            success: true,
            message: `Authentication approved for ${email}!`,
            score: verification.score || 95,
            mode: verification.mode || 'adaptive',
            challenge_ts: verification.challenge_ts || new Date().toISOString()
          }));
        } else {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            success: false,
            error: verification.error || 'verification_failed',
            message: verification.message || 'Captcha token rejected or expired.'
          }));
        }
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: err.message }));
      }
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

server.listen(port, () => {
  console.log('\n\x1b[36m%s\x1b[0m', '=======================================================');
  console.log('\x1b[1m\x1b[35m%s\x1b[0m', '   🛡️  SHIELDCAPTCHA LOCAL DEMO SERVER RUNNING');
  console.log('\x1b[36m%s\x1b[0m', '=======================================================');
  console.log(`  🌐 URL:        \x1b[1m\x1b[32mhttp://localhost:${port}\x1b[0m`);
  console.log(`  🔑 Site Key:   \x1b[33m${siteKey}\x1b[0m`);
  console.log(`  🔒 API Target: \x1b[36m${apiUrl}\x1b[0m`);
  console.log('-------------------------------------------------------');
  console.log('  Open the URL in your browser to test the captcha widget');
  console.log('  and live server-side verification with your API key!');
  console.log('=======================================================\n');
});
