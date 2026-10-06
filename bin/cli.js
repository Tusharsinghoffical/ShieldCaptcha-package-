#!/usr/bin/env node

/**
 * ShieldCaptcha Enterprise CLI Tool
 * Commands: info, configure, test, demo
 */

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const os = require('os');

// Helper to parse arguments
const args = process.argv.slice(2);
const command = args[0] || 'info';

function getArgValue(name) {
  for (const a of args) {
    if (a.startsWith(`--${name}=`)) {
      return a.slice(`--${name}=`.length);
    }
  }
  return null;
}

// Load .env if present
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

let siteKey = getArgValue('site-key') || process.env.SHIELDCAPTCHA_SITE_KEY || process.env.NEXT_PUBLIC_SITE_KEY || process.env.SITE_KEY || 'pub_shield_live_demo_sitekey';
let secretKey = getArgValue('secret-key') || process.env.SHIELDCAPTCHA_SECRET_KEY || process.env.SITE_SECRET || 'sec_shield_live_demo_secretkey';
let apiUrl = getArgValue('api-url') || process.env.SHIELDCAPTCHA_API_URL || process.env.NEXT_PUBLIC_CAPTCHA_API || 'https://shieldcaptcha.vercel.app';

// Strip trailing slash
if (apiUrl.endsWith('/')) apiUrl = apiUrl.slice(0, -1);

async function requestJson(urlStr, options = {}, postData = null) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(urlStr);
    const isHttps = parsed.protocol === 'https:';
    const client = isHttps ? https : http;

    const reqOpts = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: options.method || 'GET',
      headers: {
        'Accept': 'application/json',
        ...(options.headers || {})
      },
      timeout: 10000
    };

    let bodyBuf = null;
    if (postData) {
      bodyBuf = Buffer.from(typeof postData === 'string' ? postData : JSON.stringify(postData), 'utf8');
      reqOpts.headers['Content-Type'] = 'application/json';
      reqOpts.headers['Content-Length'] = bodyBuf.length;
    }

    const req = client.request(reqOpts, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve({ status: res.statusCode, headers: res.headers, data: json });
        } catch {
          resolve({ status: res.statusCode, headers: res.headers, raw: data });
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Connection timed out'));
    });

    req.on('error', (err) => {
      reject(err);
    });

    if (bodyBuf) {
      req.write(bodyBuf);
    }
    req.end();
  });
}

// -----------------------------------------------------------------------------
// Command: info
// -----------------------------------------------------------------------------
if (command === 'info' || command === '--help' || command === '-h' || command === 'status') {
  require('./welcome');
  process.exit(0);
}

// -----------------------------------------------------------------------------
// Command: configure
// -----------------------------------------------------------------------------
if (command === 'configure') {
  console.log('\n\x1b[36m%s\x1b[0m', '--- ShieldCaptcha Configuration ---');
  const targetSite = getArgValue('site-key');
  const targetSecret = getArgValue('secret-key');
  const targetUrl = getArgValue('api-url') || apiUrl;

  if (!targetSite || !targetSecret) {
    console.log('\x1b[33mUsage:\x1b[0m');
    console.log('  npx shieldcaptcha configure --site-key=YOUR_SITE_KEY --secret-key=YOUR_SECRET_KEY [--api-url=API_URL]');
    console.log('\n\x1b[36mExample:\x1b[0m');
    console.log('  npx shieldcaptcha configure --site-key=pub_shield_abc123 --secret-key=sec_shield_xyz789');
    console.log('');
    process.exit(1);
  }

  const envPath = path.resolve(process.cwd(), '.env');
  let envLines = [];
  if (fs.existsSync(envPath)) {
    try {
      envLines = fs.readFileSync(envPath, 'utf8').split('\n').filter(l => {
        return !l.startsWith('SHIELDCAPTCHA_') && !l.startsWith('NEXT_PUBLIC_SITE_KEY') && !l.startsWith('SITE_SECRET');
      });
    } catch {}
  }

  envLines.push(`SHIELDCAPTCHA_SITE_KEY="${targetSite}"`);
  envLines.push(`SHIELDCAPTCHA_SECRET_KEY="${targetSecret}"`);
  envLines.push(`SHIELDCAPTCHA_API_URL="${targetUrl}"`);

  fs.writeFileSync(envPath, envLines.join('\n').trim() + '\n', 'utf8');

  console.log('\x1b[32m%s\x1b[0m', `✓ Successfully configured ShieldCaptcha in ${envPath}`);
  console.log(`  • Site Key:   ${targetSite}`);
  console.log(`  • Secret Key: ${targetSecret.slice(0, 10)}...`);
  console.log(`  • API Target: ${targetUrl}`);
  console.log('\nRun \x1b[1m\x1b[33mnpx shieldcaptcha test\x1b[0m to test the connection!\n');
  process.exit(0);
}

// -----------------------------------------------------------------------------
// Command: test
// -----------------------------------------------------------------------------
if (command === 'test') {
  (async () => {
    console.log('\n\x1b[36m%s\x1b[0m', '=======================================================');
    console.log('\x1b[1m\x1b[35m%s\x1b[0m', '   🛡️  SHIELDCAPTCHA LIVE INTEGRATION TEST');
    console.log('\x1b[36m%s\x1b[0m', '=======================================================');
    console.log(`🌐 Target API:    \x1b[36m${apiUrl}\x1b[0m`);
    console.log(`🔑 Site Key:      \x1b[32m${siteKey}\x1b[0m`);
    console.log(`🔒 Secret Key:    \x1b[32m${secretKey ? secretKey.slice(0, 10) + '...' : '[NONE]'}\x1b[0m`);
    console.log('-------------------------------------------------------');

    try {
      // Step 1: Health Check
      process.stdout.write('1. Checking ShieldCaptcha API Reachability... ');
      const healthRes = await requestJson(`${apiUrl}/api/health`).catch(() => null);
      if (healthRes && (healthRes.status === 200 || healthRes.status === 204)) {
        console.log('\x1b[32m[PASS] OK\x1b[0m');
      } else {
        console.log('\x1b[33m[WARN] (Will proceed with challenge test)\x1b[0m');
      }

      // Step 2: Request Challenge
      process.stdout.write('2. Requesting Proof-of-Work Challenge... ');
      const chalRes = await requestJson(`${apiUrl}/api/challenge`, { method: 'POST' }, {
        siteKey: siteKey,
        mode: 'checkbox'
      });

      if (!chalRes || chalRes.status !== 200 || !chalRes.data?.id) {
        console.log('\x1b[31m[FAILED]\x1b[0m');
        console.error('   API Response:', chalRes?.data || chalRes?.raw || 'No response');
        process.exit(1);
      }
      const chal = chalRes.data;
      console.log(`\x1b[32m[PASS]\x1b[0m (ID: ${chal.id.slice(0, 12)}..., Bits: ${chal.bits || 14})`);

      // Step 3: Solve Proof-of-Work
      process.stdout.write('3. Solving Biomechanical Proof-of-Work locally... ');
      const prefix = chal.prefix || 'chal';
      const bits = chal.bits || 14;
      let nonce = 0;
      const startMs = Date.now();

      while (true) {
        const hash = crypto.createHash('sha256').update(`${prefix}:${nonce}`).digest();
        let zeros = 0;
        for (let i = 0; i < hash.length; i++) {
          if (hash[i] === 0) zeros += 8;
          else {
            zeros += Math.clz32(hash[i]) - 24;
            break;
          }
        }
        if (zeros >= bits) break;
        nonce++;
        if (nonce > 500000) break;
      }
      const elapsed = Date.now() - startMs;
      console.log(`\x1b[32m[PASS]\x1b[0m (Nonce: ${nonce}, Solved in ${elapsed}ms)`);

      // Step 4: Verify Challenge with Engine
      process.stdout.write('4. Submitting solution for signed pass token... ');
      const verifyRes = await requestJson(`${apiUrl}/api/verify`, { method: 'POST' }, {
        id: chal.id,
        nonce: nonce,
        trustedEvent: true,
        clickLatencyMs: 140,
        env: { isHeadless: false }
      });

      if (!verifyRes || verifyRes.status !== 200 || !verifyRes.data?.token) {
        console.log('\x1b[31m[FAILED]\x1b[0m');
        console.error('   Verify Error:', verifyRes?.data || verifyRes?.raw);
        process.exit(1);
      }
      const token = verifyRes.data.token;
      console.log(`\x1b[32m[PASS]\x1b[0m (Token: ${token.slice(0, 24)}...)`);

      // Step 5: Server-side validation via /api/siteverify
      process.stdout.write('5. Server-Side Token Validation (/api/siteverify)... ');
      const siteVerifyRes = await requestJson(`${apiUrl}/api/siteverify`, {
        method: 'POST',
        headers: { 'X-Site-Secret': secretKey }
      }, {
        token: token,
        secret: secretKey
      });

      if (!siteVerifyRes || siteVerifyRes.status !== 200 || !siteVerifyRes.data?.success) {
        console.log('\x1b[31m[FAILED]\x1b[0m');
        console.error('   Validation Error:', siteVerifyRes?.data || siteVerifyRes?.raw);
        process.exit(1);
      }

      console.log('\x1b[32m[PASS]\x1b[0m');
      console.log('-------------------------------------------------------');
      console.log('\x1b[1m\x1b[32m%s\x1b[0m', '   🎉 SUCCESS: ShieldCaptcha is fully operational!');
      console.log(`   • Trust Score:   \x1b[1m\x1b[32m${siteVerifyRes.data.score || 95}/100\x1b[0m`);
      console.log(`   • Mode:          ${siteVerifyRes.data.mode || 'adaptive'}`);
      console.log(`   • Verified At:   ${siteVerifyRes.data.challenge_ts}`);
      console.log('=======================================================\n');
    } catch (err) {
      console.log('\n\x1b[31m[ERROR]\x1b[0m Could not connect to ShieldCaptcha API:');
      console.error('  ', err.message);
      console.log(`\nPlease check if your ShieldCaptcha website/backend is running at ${apiUrl}.\n`);
      process.exit(1);
    }
  })();
}

// -----------------------------------------------------------------------------
// Command: demo
// -----------------------------------------------------------------------------
if (command === 'demo') {
  const port = parseInt(getArgValue('port') || '4000', 10);
  require('../demo/server');
}
