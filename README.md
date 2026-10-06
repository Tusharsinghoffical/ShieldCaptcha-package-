# ShieldCaptcha Enterprise SDK & Client Package

Official developer package for integrating **ShieldCaptcha Enterprise** into any Node.js, Express, Next.js, or HTML application.

---

## ⚡ Quick Start

### 1. Installation

Install via npm:
```bash
npm install shieldcaptcha
```
*Upon installation, system information and API connection status will automatically be displayed.*

Or run the interactive CLI directly:
```bash
npx shieldcaptcha
```

---

## 🔑 Configure API Keys

Get your **Site Key** and **Secret Key** from your ShieldCaptcha Website Dashboard (`/api-keys`).

Configure them on your system using the CLI:
```bash
npx shieldcaptcha configure --site-key=pub_shield_YOUR_KEY --secret-key=sec_shield_YOUR_SECRET
```
*(Or create a `.env` file with `SHIELDCAPTCHA_SITE_KEY` and `SHIELDCAPTCHA_SECRET_KEY`)*

---

## 🧪 Test API Connectivity

Run the live end-to-end integration test to ensure your API keys and the ShieldCaptcha server are communicating:
```bash
npx shieldcaptcha test
```

---

## 🚀 Run the Local Demo Server

Launch the zero-config demo playground on `http://localhost:4000`:
```bash
npx shieldcaptcha demo
```

---

## 💻 Server-Side Integration (Node.js / Express)

```javascript
const express = require('express');
const { ShieldCaptcha } = require('shieldcaptcha');

const app = express();
app.use(express.json());

// Initialize SDK with your keys
const captcha = new ShieldCaptcha({
  siteKey: process.env.SHIELDCAPTCHA_SITE_KEY,
  secretKey: process.env.SHIELDCAPTCHA_SECRET_KEY,
  apiUrl: 'https://shieldcaptcha.vercel.app'
});

// Protect your endpoint
app.post('/api/login', async (req, res) => {
  const { email, token } = req.body;

  // Verify single-use token with ShieldCaptcha engine
  const result = await captcha.verify({
    token: token,
    remoteIp: req.ip
  });

  if (!result.success) {
    return res.status(403).json({
      success: false,
      message: 'Captcha verification failed'
    });
  }

  // Token is valid! Proceed with login
  res.json({
    success: true,
    score: result.score,
    message: 'Login successful'
  });
});

app.listen(3000);
```

---

## 🌐 Client-Side Integration (HTML / React)

### HTML:
```html
<!-- 1. Include Script -->
<script src="https://shieldcaptcha.vercel.app/captcha.js"></script>

<!-- 2. Target Container -->
<div id="captcha-box"></div>

<!-- 3. Mount Widget -->
<script>
  ShieldCaptcha.mount('#captcha-box', {
    siteKey: 'pub_shield_YOUR_KEY',
    mode: 'checkbox', // 'checkbox' | 'jigsaw' | 'adaptive'
    onToken: (token, meta) => {
      console.log('Verified token:', token, 'Score:', meta.score);
      // Attach token to your form submission
    }
  });
</script>
```

---

## 📄 License
MIT © ShieldCaptcha Enterprise Team
