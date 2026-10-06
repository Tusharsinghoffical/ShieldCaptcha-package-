/**
 * ShieldCaptcha Enterprise Node.js / TypeScript SDK
 * Version: 4.2.0
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

class ShieldCaptcha {
  /**
   * @param {Object} options
   * @param {string} options.siteKey - ShieldCaptcha public site key (pub_shield_...)
   * @param {string} options.secretKey - ShieldCaptcha private secret key (sec_shield_...)
   * @param {string} [options.apiUrl] - Base URL of ShieldCaptcha engine (default: https://shieldcaptcha.vercel.app)
   * @param {number} [options.timeout] - Request timeout in ms (default: 5000)
   */
  constructor(options = {}) {
    this.siteKey = options.siteKey || process.env.SHIELDCAPTCHA_SITE_KEY || process.env.NEXT_PUBLIC_SITE_KEY || process.env.SITE_KEY || '';
    this.secretKey = options.secretKey || process.env.SHIELDCAPTCHA_SECRET_KEY || process.env.SITE_SECRET || '';
    this.apiUrl = (options.apiUrl || process.env.SHIELDCAPTCHA_API_URL || process.env.NEXT_PUBLIC_CAPTCHA_API || 'https://shieldcaptcha.vercel.app').replace(/\/+$/, '');
    this.timeout = options.timeout || 5000;
  }

  /**
   * Verify a captcha token submitted by the client
   * @param {Object} params
   * @param {string} params.token - Single-use pass token from client widget
   * @param {string} [params.remoteIp] - Client IP address for risk scoring
   * @returns {Promise<{success: boolean, score?: number, mode?: string, challenge_ts?: string, error?: string, message?: string}>}
   */
  async verify({ token, remoteIp } = {}) {
    if (!token || typeof token !== 'string') {
      return { success: false, error: 'missing_token', message: 'No captcha token provided' };
    }

    if (!this.secretKey) {
      return { success: false, error: 'missing_secret_key', message: 'ShieldCaptcha secret key is not configured' };
    }

    const payload = JSON.stringify({
      token,
      secret: this.secretKey,
      remoteip: remoteIp || ''
    });

    const targetUrl = new URL(`${this.apiUrl}/api/siteverify`);
    const isHttps = targetUrl.protocol === 'https:';
    const client = isHttps ? https : http;

    return new Promise((resolve) => {
      const req = client.request({
        hostname: targetUrl.hostname,
        port: targetUrl.port || (isHttps ? 443 : 80),
        path: targetUrl.pathname + targetUrl.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
          'X-Site-Secret': this.secretKey,
          'Accept': 'application/json'
        },
        timeout: this.timeout
      }, (res) => {
        let raw = '';
        res.on('data', chunk => { raw += chunk; });
        res.on('end', () => {
          try {
            const data = JSON.parse(raw);
            resolve(data);
          } catch {
            resolve({ success: false, error: 'invalid_response_format', details: raw });
          }
        });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({ success: false, error: 'verification_timeout', message: 'Request to ShieldCaptcha timed out' });
      });

      req.on('error', (err) => {
        resolve({ success: false, error: 'network_error', message: err.message });
      });

      req.write(payload);
      req.end();
    });
  }

  /**
   * Express / Connect middleware to protect any route
   * Looks for token in req.body.captcha_token or req.headers['x-captcha-token']
   * @param {Object} [opts]
   * @param {number} [opts.minScore=50] - Minimum trust score (0-100)
   * @param {string} [opts.tokenField='captcha_token']
   */
  middleware(opts = {}) {
    const minScore = opts.minScore || 50;
    const tokenField = opts.tokenField || 'captcha_token';

    return async (req, res, next) => {
      const token = (req.body && req.body[tokenField]) || req.headers['x-captcha-token'];
      const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress;

      const result = await this.verify({ token, remoteIp: clientIp });
      if (!result.success) {
        return res.status(403).json({
          success: false,
          error: 'captcha_verification_failed',
          details: result.error || 'Human verification required'
        });
      }

      if (typeof result.score === 'number' && result.score < minScore) {
        return res.status(403).json({
          success: false,
          error: 'low_trust_score',
          score: result.score
        });
      }

      req.shieldCaptcha = result;
      next();
    };
  }

  /**
   * Returns the standalone script tag URL for client-side embedding
   */
  getClientScriptUrl() {
    return `${this.apiUrl}/captcha.js`;
  }
}

/**
 * Convenience static verification function
 */
async function verifyToken(token, secretKey, apiUrl) {
  const instance = new ShieldCaptcha({ secretKey, apiUrl });
  return instance.verify({ token });
}

// Client-side helper for browser environments
const ShieldCaptchaClient = {
  render(target, options = {}) {
    if (typeof window !== 'undefined' && window.ShieldCaptcha) {
      return window.ShieldCaptcha.mount(target, options);
    }
    console.warn('[ShieldCaptcha] Global script not yet loaded. Ensure <script src="/captcha.js"> is included.');
  }
};

module.exports = {
  ShieldCaptcha,
  verifyToken,
  ShieldCaptchaClient
};
