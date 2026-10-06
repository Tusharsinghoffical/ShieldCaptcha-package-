#!/usr/bin/env node

/**
 * ShieldCaptcha Enterprise - Package Installation & System Welcome Banner
 * Automatically displays host system information and API connection instructions.
 */

const os = require('os');
const path = require('path');
const fs = require('fs');

// Try loading local .env if available
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

const siteKey = process.env.SHIELDCAPTCHA_SITE_KEY || process.env.NEXT_PUBLIC_SITE_KEY || process.env.SITE_KEY || '';
const secretKey = process.env.SHIELDCAPTCHA_SECRET_KEY || process.env.SITE_SECRET || '';
const apiUrl = process.env.SHIELDCAPTCHA_API_URL || process.env.NEXT_PUBLIC_CAPTCHA_API || 'https://shieldcaptcha.vercel.app';

// Collect System Information
const totalMemMB = Math.round(os.totalmem() / (1024 * 1024));
const freeMemMB = Math.round(os.freemem() / (1024 * 1024));
const cpus = os.cpus() || [];
const cpuModel = cpus.length > 0 ? cpus[0].model.trim() : 'Unknown';

console.log('');
console.log('\x1b[36m%s\x1b[0m', '  ======================================================================');
console.log('\x1b[1m\x1b[35m%s\x1b[0m', '   🛡️  SHIELDCAPTCHA ENTERPRISE SDK v4.2.0 INSTALLED SUCCESSFULLY');
console.log('\x1b[36m%s\x1b[0m', '  ======================================================================');
console.log('');
console.log('\x1b[1m\x1b[33m%s\x1b[0m', '  💻 SYSTEM & ENVIRONMENT DETAILS (THIS MACHINE):');
console.log(`     • Device Hostname:   \x1b[32m${os.hostname()}\x1b[0m`);
console.log(`     • Platform / Arch:   \x1b[32m${os.platform()} (${os.arch()})\x1b[0m — ${os.type()} ${os.release()}`);
console.log(`     • CPU Architecture:  \x1b[32m${cpuModel} (${cpus.length} cores)\x1b[0m`);
console.log(`     • Memory (RAM):      \x1b[32m${freeMemMB} MB free / ${totalMemMB} MB total\x1b[0m`);
console.log(`     • Node.js Runtime:   \x1b[32m${process.version}\x1b[0m`);
console.log(`     • Working Directory: \x1b[32m${process.cwd()}\x1b[0m`);
console.log(`     • Local Timestamp:   \x1b[32${new Date().toISOString()}\x1b[0m`);
console.log('');
console.log('\x1b[1m\x1b[34m%s\x1b[0m', '  🔑 API KEYS CONFIGURATION STATUS:');
if (siteKey) {
  console.log(`     • Site Key:          \x1b[32m${siteKey}\x1b[0m (Active)`);
} else {
  console.log(`     • Site Key:          \x1b[31m[NOT CONFIGURED]\x1b[0m (Get from ShieldCaptcha Website)`);
}

if (secretKey) {
  const maskedSec = secretKey.length > 10 ? secretKey.slice(0, 10) + '...' + secretKey.slice(-4) : '***';
  console.log(`     • Secret Key:        \x1b[32m${maskedSec}\x1b[0m (Configured)`);
} else {
  console.log(`     • Secret Key:        \x1b[31m[NOT CONFIGURED]\x1b[0m (Get from ShieldCaptcha Website)`);
}

console.log(`     • API Endpoint:      \x1b[36m${apiUrl}\x1b[0m`);
console.log('');
console.log('\x1b[1m\x1b[32m%s\x1b[0m', '  🚀 HOW TO CONNECT WITH YOUR SHIELDCAPTCHA WEBSITE:');
console.log('     1. Open your ShieldCaptcha Website Dashboard:');
console.log(`        \x1b[4m${apiUrl}/api-keys\x1b[0m`);
console.log('     2. Copy your Site Key (pub_shield_...) and Secret Key (sec_shield_...)');
console.log('     3. On this system, configure your keys using the CLI:');
console.log('        \x1b[1m\x1b[33mnpx shieldcaptcha configure --site-key=YOUR_SITE_KEY --secret-key=YOUR_SECRET_KEY\x1b[0m');
console.log('        (Or create a .env file with SHIELDCAPTCHA_SITE_KEY and SHIELDCAPTCHA_SECRET_KEY)');
console.log('     4. Test your live connection:');
console.log('        \x1b[1m\x1b[33mnpx shieldcaptcha test\x1b[0m');
console.log('     5. Launch the instant local demo server:');
console.log('        \x1b[1m\x1b[33mnpx shieldcaptcha demo\x1b[0m  (Runs at http://localhost:4000)');
console.log('');
console.log('\x1b[36m%s\x1b[0m', '  ======================================================================');
console.log('');
