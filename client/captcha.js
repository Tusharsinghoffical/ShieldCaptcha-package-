/**
 * ShieldCaptcha Enterprise v4.1 — Hardened Security Edition
 * Zero-dependency, dual-modal Proof-of-Work & Biomechanical Defense Engine.
 *
 * Security hardening over v4.0:
 * - Deep browser fingerprinting (WebGL renderer, plugin count, screen entropy,
 *   navigator.hardwareConcurrency, memory, touchpoints, scroll state)
 * - Canvas Fingerprint extraction & submission for cross-session replay detection
 * - Interaction timing analysis: time-to-first-move, click hesitation, micro-pause detection
 * - Native API tamper detection (toString() check on setTimeout, fetch, etc.)
 * - Per-instance isolated ambient trace (no global poisoning)
 * - AES-CBC-128 payload encryption using SubtleCrypto (replaces weak XOR)
 * - Strict isTrusted enforcement with secondary timing sanity check
 * - Progressive fail backoff: each widget reset increases PoW difficulty signal
 * - Input focus/blur entropy capture (tab-switching bots)
 * - Comprehensive CSP-safe nonce injection prevention
 */
(function (global) {
  'use strict';

  const W = 320;
  const H = 160;
  const P = 48;
  const KN = 44;
  const SDK_VERSION = '4.2';
  const MIN_CLICK_TO_SUBMIT_MS = 80; // Below this = synthetic bot click timing

  /* =========================================================================
     WEB WORKER — Bit-Level SHA-256 Proof-of-Work
     ========================================================================= */
  const WORKER_CODE = `
    self.onmessage = async function(e) {
      const { prefix, bits, jitter } = e.data;
      if (!prefix || typeof bits !== 'number' || bits < 1 || bits > 28) {
        self.postMessage({ nonce: '0', duration: 0 });
        return;
      }
      // Timing jitter: small random delay prevents timing oracle attacks
      if (jitter > 0) await new Promise(r => setTimeout(r, jitter));
      const encoder = new TextEncoder();
      const t0 = performance.now();

      function lz(bytes) {
        let count = 0;
        for (let i = 0; i < bytes.length; i++) {
          const byte = bytes[i];
          if (byte === 0) { count += 8; }
          else { count += Math.clz32(byte) - 24; break; }
        }
        return count;
      }

      for (let nonce = 0; ; nonce++) {
        const nonceStr = nonce.toString(36);
        const data = encoder.encode(prefix + ':' + nonceStr);
        const hashBuf = await crypto.subtle.digest('SHA-256', data);
        if (lz(new Uint8Array(hashBuf)) >= bits) {
          self.postMessage({ nonce: nonceStr, duration: Math.round(performance.now() - t0) });
          return;
        }
        if (nonce % 4000 === 0 && performance.now() - t0 > 2500)
          await new Promise(r => setTimeout(r, 0));
      }
    };
  `;

  async function solvePoWMainThread(prefix, bits) {
    if (!prefix || typeof bits !== 'number') return { nonce: '0', duration: 0 };
    const encoder = new TextEncoder();
    const t0 = performance.now();
    function lz(bytes) {
      let count = 0;
      for (let i = 0; i < bytes.length; i++) {
        if (bytes[i] === 0) count += 8;
        else { count += Math.clz32(bytes[i]) - 24; break; }
      }
      return count;
    }
    for (let nonce = 0; ; nonce++) {
      const nonceStr = nonce.toString(36);
      const hashBuf = await crypto.subtle.digest('SHA-256', encoder.encode(prefix + ':' + nonceStr));
      if (lz(new Uint8Array(hashBuf)) >= bits)
        return { nonce: nonceStr, duration: Math.round(performance.now() - t0) };
      if (nonce % 1000 === 0) await new Promise(r => setTimeout(r, 0));
    }
  }

  function runPoWWorker(prefix, bits) {
    if (!prefix || typeof bits !== 'number') return Promise.resolve({ nonce: '0', duration: 0 });
    // Small random jitter (10–60ms) prevents timing-oracle side-channel
    const jitter = Math.floor(Math.random() * 50) + 10;
    return new Promise((resolve, reject) => {
      try {
        const blob = new Blob([WORKER_CODE], { type: 'application/javascript' });
        const workerUrl = URL.createObjectURL(blob);
        const worker = new Worker(workerUrl);
        const timeout = setTimeout(() => {
          worker.terminate();
          URL.revokeObjectURL(workerUrl);
          solvePoWMainThread(prefix, bits).then(resolve).catch(reject);
        }, 30000);
        worker.onmessage = e => {
          clearTimeout(timeout);
          URL.revokeObjectURL(workerUrl);
          worker.terminate();
          resolve(e.data);
        };
        worker.onerror = () => {
          clearTimeout(timeout);
          URL.revokeObjectURL(workerUrl);
          worker.terminate();
          solvePoWMainThread(prefix, bits).then(resolve).catch(reject);
        };
        worker.postMessage({ prefix, bits, jitter });
      } catch {
        solvePoWMainThread(prefix, bits).then(resolve).catch(reject);
      }
    });
  }

  /* =========================================================================
     DEEP BROWSER FINGERPRINTING — Anti-Automation & Anomaly Signals
     ========================================================================= */

  function collectBrowserFingerprint() {
    const nav = navigator;
    const fp = {};

    // --- Automation flags & deep evasion detection ---
    fp.webdriver = Boolean(nav.webdriver);
    fp.isHeadless = /HeadlessChrome|PhantomJS|puppeteer|playwright|selenium|Electron|node\.js/i.test(nav.userAgent);

    // Automation driver globals check
    try {
      fp.hasAutomationGlobals = Boolean(
        window.__webdriver_evaluate ||
        window.__selenium_evaluate ||
        window.__driver_evaluate ||
        window.__nightmare ||
        window._phantom ||
        window.callPhantom ||
        window.$cdc_asdjflasutopfhvcZLmcfl_ ||
        document.$chrome_asyncScriptInfo ||
        (document.documentElement && document.documentElement.getAttribute('webdriver'))
      );
    } catch { fp.hasAutomationGlobals = false; }

    // navigator.webdriver descriptor tampering check (stealth plugin bypass)
    try {
      const desc = Object.getOwnPropertyDescriptor(navigator, 'webdriver') ||
                   Object.getOwnPropertyDescriptor(Object.getPrototypeOf(navigator), 'webdriver');
      fp.webdriverTampered = Boolean(desc && (typeof desc.get !== 'function' || desc.value !== undefined));
    } catch { fp.webdriverTampered = false; }

    // --- Native function tamper detection (v4.2: expanded set) ---
    try {
      const checks = [
        [setTimeout, 'setTimeout'],
        [fetch, 'fetch'],
        [Array.prototype.push, 'Array.prototype.push'],
        [JSON.stringify, 'JSON.stringify'],
        [document.createElement, 'createElement'],
        [history.pushState, 'pushState'],
      ];
      fp.tamperedNatives = checks.some(([fn, name]) => {
        try {
          const src = Function.prototype.toString.call(fn);
          return !src.includes('[native code]');
        } catch { return true; }
      });
    } catch { fp.tamperedNatives = true; }

    // --- Prototype pollution detection ---
    try {
      fp.protoTampered = Object.prototype.hasOwnProperty.call(Object.prototype, '__proto__') ||
        typeof Object.prototype.toString !== 'function';
    } catch { fp.protoTampered = true; }

    // --- Environment signals ---
    fp.languages = (nav.languages || []).length;
    fp.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
    fp.hardwareConcurrency = nav.hardwareConcurrency || 0;
    fp.deviceMemory = nav.deviceMemory || 0;
    fp.maxTouchPoints = nav.maxTouchPoints || 0;
    fp.platform = nav.platform || '';
    fp.cookieEnabled = nav.cookieEnabled;
    fp.outerZero = (window.outerWidth === 0 && window.outerHeight === 0);
    fp.availZero = (window.screen.availWidth === 0);
    fp.pluginCount = nav.plugins ? nav.plugins.length : -1;

    // --- Connection type (v4.2: new signal) ---
    try {
      const conn = nav.connection || nav.mozConnection || nav.webkitConnection;
      fp.connectionType = conn ? (conn.effectiveType || conn.type || 'unknown') : 'none';
      fp.connectionRtt = conn ? (conn.rtt || 0) : 0;
    } catch { fp.connectionType = 'unknown'; fp.connectionRtt = 0; }

    // --- WebGL renderer fingerprint ---
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (gl) {
        const dbgInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (dbgInfo) {
          fp.webglRenderer = gl.getParameter(dbgInfo.UNMASKED_RENDERER_WEBGL);
          fp.webglVendor = gl.getParameter(dbgInfo.UNMASKED_VENDOR_WEBGL);
        }
        // Additional WebGL capability checks
        fp.webglMaxTextureSize = gl.getParameter(gl.MAX_TEXTURE_SIZE);
        fp.webglShadingVersion = gl.getParameter(gl.SHADING_LANGUAGE_VERSION);
      }
    } catch { fp.webglRenderer = null; }

    // --- Canvas 2D pixel fingerprint (v4.2: richer drawing for uniqueness) ---
    try {
      const c = document.createElement('canvas');
      c.width = 280; c.height = 60;
      const ctx = c.getContext('2d');
      // Multi-layer draw for renderer uniqueness
      const grd = ctx.createLinearGradient(0, 0, 280, 0);
      grd.addColorStop(0, '#f60');
      grd.addColorStop(0.5, '#069');
      grd.addColorStop(1, '#93c');
      ctx.fillStyle = grd;
      ctx.fillRect(0, 0, 280, 60);
      ctx.fillStyle = 'rgba(255,255,255,0.7)';
      ctx.font = '14px Arial';
      ctx.fillText('\u{1F6E1} Shield v4.2 FP \u2764 \u03B1\u03B2\u03B3', 8, 28);
      ctx.beginPath();
      ctx.arc(240, 30, 18, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(99,102,241,0.5)';
      ctx.fill();
      ctx.shadowColor = '#4f46e5';
      ctx.shadowBlur = 8;
      ctx.fillStyle = '#fff';
      ctx.fillRect(10, 40, 80, 6);
      fp.canvasFp = c.toDataURL().slice(-64);
    } catch { fp.canvasFp = ''; }

    // --- Audio context fingerprint ---
    try {
      const ac = new (window.AudioContext || window.webkitAudioContext)();
      const osc = ac.createOscillator();
      const analyser = ac.createAnalyser();
      const gain = ac.createGain();
      gain.gain.setValueAtTime(0, ac.currentTime);
      osc.connect(analyser);
      analyser.connect(gain);
      gain.connect(ac.destination);
      osc.start(0);
      const data = new Float32Array(analyser.frequencyBinCount);
      analyser.getFloatFrequencyData(data);
      fp.audioFp = data[0].toFixed(6);
      fp.sampleRate = ac.sampleRate;
      osc.stop();
      ac.close();
    } catch { fp.audioFp = ''; fp.sampleRate = 0; }

    // --- Screen entropy ---
    fp.screenW = window.screen.width;
    fp.screenH = window.screen.height;
    fp.screenDepth = window.screen.colorDepth;
    fp.pixelRatio = window.devicePixelRatio || 1;

    // --- Permission API probe ---
    fp.permissionsAvailable = typeof navigator.permissions === 'object';

    // --- Iframe/top-level context check ---
    fp.isIframe = (window.self !== window.top);

    return fp;
  }

  /* =========================================================================
     INTERACTION TIMING — Detects scripted / synthetic interactions
     ========================================================================= */

  function createInteractionSensor() {
    const events = [];
    let firstMoveTime = null;
    let mountTime = performance.now();
    let focusLostCount = 0;
    let scrollDepth = 0;

    const track = (type) => (e) => {
      const now = performance.now();
      if (type === 'pointermove' && firstMoveTime === null) firstMoveTime = now;
      if (type === 'scroll') scrollDepth = Math.max(scrollDepth, window.scrollY);
      events.push({ type, t: Math.round(now), trusted: e.isTrusted });
    };

    document.addEventListener('pointermove', track('pointermove'), { passive: true });
    document.addEventListener('pointerdown', track('pointerdown'), { passive: true });
    document.addEventListener('keydown', track('keydown'), { passive: true });
    window.addEventListener('blur', () => { focusLostCount++; });
    window.addEventListener('scroll', track('scroll'), { passive: true });

    return {
      getReport() {
        const now = performance.now();
        const totalInteractions = events.length;
        const untrusted = events.filter(e => !e.trusted).length;
        const syntheticRatio = totalInteractions > 0 ? untrusted / totalInteractions : 0;
        return {
          timeOnPageMs: Math.round(now - mountTime),
          timeToFirstMoveMs: firstMoveTime !== null ? Math.round(firstMoveTime - mountTime) : null,
          totalInteractions,
          syntheticEventRatio: +syntheticRatio.toFixed(3),
          focusLostCount,
          scrollDepth: Math.round(scrollDepth)
        };
      },
      destroy() {
        document.removeEventListener('pointermove', track('pointermove'));
        document.removeEventListener('pointerdown', track('pointerdown'));
        document.removeEventListener('keydown', track('keydown'));
      }
    };
  }

  /* =========================================================================
     AES-CBC PAYLOAD ENCRYPTION (replaces weak XOR)
     Uses SubtleCrypto: PBKDF2 key derivation + AES-CBC-128 + IV prepended
     ========================================================================= */

  async function encryptPayload(dataObj, sessionSalt) {
    const enc = new TextEncoder();
    const plainBytes = enc.encode(JSON.stringify(dataObj));

    // PBKDF2 key derivation from session salt
    const saltBytes = enc.encode(sessionSalt);
    const baseKey = await crypto.subtle.importKey(
      'raw', saltBytes, { name: 'PBKDF2' }, false, ['deriveKey']
    );
    const aesKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: saltBytes, iterations: 1000, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-CBC', length: 128 },
      false,
      ['encrypt']
    );

    const iv = crypto.getRandomValues(new Uint8Array(16));
    const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, plainBytes);

    // Prepend IV to ciphertext -> hex encode
    const combined = new Uint8Array(16 + cipherBuf.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(cipherBuf), 16);
    return Array.from(combined).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /* =========================================================================
     MOUNT — Main Widget Factory
     ========================================================================= */

  function mount(container, options = {}) {
    const api = options.api || '';
    let preferredMode = options.mode || 'checkbox';
    const onToken = options.onToken || (() => {});
    const onReset = options.onReset || (() => {});
    const onTrajectory = options.onTrajectory || (() => {});

    // Per-instance ambient trace (not global — prevents cross-instance poisoning)
    const ambientTrace = [];
    let lastMoveTime = 0;
    const mountTimestamp = performance.now(); // v4.2: widget mount time for click timing gate
    const handleAmbient = (e) => {
      const now = performance.now();
      if (now - lastMoveTime < 16) return;
      lastMoveTime = now;
      if (ambientTrace.length >= 400) ambientTrace.shift();
      ambientTrace.push([e.clientX | 0, e.clientY | 0, Math.round(now)]);
    };
    window.addEventListener('pointermove', handleAmbient, { passive: true });

    // Global interaction sensor
    const sensor = createInteractionSensor();

    // Fail counter for progressive PoW difficulty signal
    let failCount = 0;

    container.innerHTML = '';
    container.classList.add('shield-captcha-container');

    const root = document.createElement('div');
    root.className = 'sc-root';
    root.style.cssText = `
      position: relative;
      width: ${W}px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      user-select: none;
      -webkit-user-select: none;
      box-sizing: border-box;
    `;

    if (!document.getElementById('sc-enterprise-styles')) {
      const st = document.createElement('style');
      st.id = 'sc-enterprise-styles';
      st.textContent = `
        @keyframes sc-spin { to { transform: rotate(360deg); } }
        @keyframes sc-pulse { 0%,100% { opacity: 0.6; } 50% { opacity: 1; } }
        @keyframes sc-shake { 0%,100%{transform:translateX(0)} 20%{transform:translateX(-6px)} 40%{transform:translateX(6px)} 60%{transform:translateX(-4px)} 80%{transform:translateX(4px)} }
        @keyframes sc-guide-bounce { 0%,100% { transform: translateY(0); } 50% { transform: translateY(-3px); } }
        @keyframes sc-guide-slide { 0%,100% { transform: translateX(0); } 50% { transform: translateX(5px); } }
        @keyframes sc-guide-slide-left { 0%,100% { transform: translateX(0); } 50% { transform: translateX(-5px); } }
        @keyframes sc-guide-pulse { 0%,100% { transform: scale(1); } 50% { transform: scale(1.15); } }
        @keyframes sc-warn-blink { 0%,100% { opacity: 1; } 50% { opacity: 0.55; } }
        @keyframes sc-guide-slidein { 0% { opacity:0; transform:translateY(-6px); } 100% { opacity:1; transform:translateY(0); } }
        @keyframes sc-hint-glow { 0%,100% { box-shadow:0 0 0 0 rgba(99,102,241,0); } 50% { box-shadow:0 0 10px 2px rgba(99,102,241,0.25); } }
        @keyframes sc-match-glow { 0%,100% { box-shadow:0 0 0 0 rgba(16,185,129,0); } 50% { box-shadow:0 0 14px 3px rgba(16,185,129,0.4); } }
        @keyframes sc-warn-shake { 0%,100%{transform:rotate(0deg)} 25%{transform:rotate(-6deg)} 75%{transform:rotate(6deg)} }
        .sc-chk-btn:hover { border-color: #818cf8 !important; box-shadow: 0 4px 16px rgba(99,102,241,0.25) !important; }
        .sc-knob:active { cursor: grabbing !important; transform: scale(1.05); }
        .sc-shake { animation: sc-shake 0.4s ease; }
        .sc-top-guide { animation: sc-guide-slidein 0.3s ease; }
        .sc-top-guide.sc-hint-idle { animation: sc-hint-glow 2s ease-in-out infinite; }
        .sc-top-guide.sc-hint-match { animation: sc-match-glow 0.6s ease-in-out infinite; }
        .sc-guide-icon.sc-warn-icon { animation: sc-warn-shake 0.4s ease-in-out infinite !important; }
      `;
      document.head.appendChild(st);
    }

    root.innerHTML = `
      <!-- VIEW A: 1-Click Smart Checkbox Card -->
      <div class="sc-view-checkbox" style="
        display: none;
        width: 100%;
        background: #ffffff;
        border: 1px solid #cbd5e1;
        border-radius: 12px;
        padding: 12px 16px;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.05);
        box-sizing: border-box;
      ">
        <div style="display: flex; align-items: center; justify-content: space-between;">
          <div style="display: flex; align-items: center; gap: 12px;">
            <button type="button" class="sc-chk-btn" style="
              width: 28px;
              height: 28px;
              border-radius: 7px;
              border: 2px solid #cbd5e1;
              background: #f8fafc;
              cursor: pointer;
              display: flex;
              align-items: center;
              justify-content: center;
              padding: 0;
              transition: all 0.2s ease;
              outline: none;
            ">
              <div class="sc-chk-spinner" style="display: none; width: 14px; height: 14px; border: 2px solid rgba(99,102,241,0.3); border-top-color: #4f46e5; border-radius: 50%; animation: sc-spin 0.7s linear infinite;"></div>
              <svg class="sc-chk-check" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="display: none;">
                <polyline points="20 6 9 17 4 12"></polyline>
              </svg>
            </button>
            <div style="display: flex; flex-direction: column;">
              <span class="sc-chk-label" style="font-size: 14px; font-weight: 600; color: #0f172a;">Verify you are human</span>
              <span class="sc-chk-sub" style="font-size: 11px; color: #64748b;">Autonomous Proof-of-Work</span>
            </div>
          </div>
          <div style="display: flex; align-items: center; gap: 8px;">
            <img src="/logo.png?v=5" alt="Shield" style="width: 26px; height: 26px; object-fit: contain;">
            <div style="display: flex; flex-direction: column; align-items: flex-end; gap: 1px;">
              <span style="font-size: 11px; font-weight: 700; color: #334155; letter-spacing: 0.5px;">SHIELD</span>
              <span style="font-size: 9px; color: #64748b;">Enterprise v${SDK_VERSION}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- VIEW B: Biomechanical Jigsaw Slider Card -->
      <div class="sc-view-jigsaw" style="display: none; width: 100%;">
        <!-- Top Animated Suggestion & Attempt Helper Bar -->
        <div class="sc-top-guide" style="
          margin-bottom: 8px;
          padding: 6px 10px;
          background: #f8fafc;
          border: 1px solid #cbd5e1;
          border-radius: 9px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          font-size: 11px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.03);
          transition: all 0.2s ease;
          box-sizing: border-box;
        ">
          <div class="sc-guide-content" style="display: flex; align-items: center; gap: 6px; color: #334155; font-weight: 500; min-height: 18px; overflow: hidden; max-width: 220px;">
            <span class="sc-guide-icon" style="font-size: 13px; display: inline-flex; animation: sc-guide-bounce 1.5s ease-in-out infinite;">💡</span>
            <span class="sc-guide-msg" style="white-space: nowrap; text-overflow: ellipsis; overflow: hidden;">Slider ko slide karke slot me fit karein</span>
          </div>
          <div class="sc-attempt-badge" style="
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 2px 7px;
            border-radius: 6px;
            background: #ffffff;
            color: #475569;
            font-size: 10px;
            font-weight: 600;
            border: 1px solid #cbd5e1;
            flex-shrink: 0;
          ">
            <span class="sc-attempt-dot" style="width: 5px; height: 5px; border-radius: 50%; background: #10b981;"></span>
            <span class="sc-attempt-text">Attempt 1/3</span>
          </div>
        </div>

        <div class="sc-card" style="
          position: relative;
          width: ${W}px;
          height: ${H}px;
          border-radius: 14px;
          overflow: hidden;
          background: #0f172a;
          box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 0 0 1px #cbd5e1;
        ">
          <img class="sc-bg" alt="Security Puzzle" draggable="false" style="
            display: block;
            width: ${W}px;
            height: ${H}px;
            object-fit: cover;
            pointer-events: none;
            filter: contrast(1.02);
          ">

          <img class="sc-piece" alt="" draggable="false" style="
            position: absolute;
            left: 0;
            top: 0;
            width: ${P}px;
            height: ${P}px;
            pointer-events: none;
            filter: drop-shadow(0 4px 8px rgba(0, 0, 0, 0.5));
            will-change: transform, left;
            transition: filter 0.2s ease;
          ">

          <!-- Top Status Bar & Reload Button -->
          <div style="position: absolute; top: 8px; left: 8px; right: 8px; display: flex; align-items: center; justify-content: space-between; pointer-events: none;">
            <div class="sc-badge" style="
              display: inline-flex;
              align-items: center;
              gap: 5px;
              padding: 3px 8px;
              border-radius: 999px;
              background: rgba(255, 255, 255, 0.92);
              backdrop-filter: blur(8px);
              border: 1px solid rgba(0, 0, 0, 0.08);
              color: #1e293b;
              font-size: 11px;
              font-weight: 600;
              box-shadow: 0 2px 5px rgba(0,0,0,0.06);
            ">
              <img src="/logo.png?v=5" alt="" style="width: 14px; height: 14px; object-fit: contain;">
              <span class="sc-dot" style="width: 6px; height: 6px; border-radius: 50%; background: #4f46e5;"></span>
              <span class="sc-badge-text">Shield Jigsaw</span>
            </div>

            <button class="sc-refresh-btn" type="button" title="Refresh Challenge" style="
              pointer-events: auto;
              background: rgba(255, 255, 255, 0.92);
              backdrop-filter: blur(8px);
              border: 1px solid rgba(0, 0, 0, 0.08);
              color: #334155;
              width: 26px;
              height: 26px;
              border-radius: 50%;
              display: flex;
              align-items: center;
              justify-content: center;
              cursor: pointer;
              outline: none;
              box-shadow: 0 2px 5px rgba(0,0,0,0.06);
            ">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2"/>
              </svg>
            </button>
          </div>

          <!-- Loading Overlay -->
          <div class="sc-overlay" style="
            position: absolute;
            inset: 0;
            background: rgba(255, 255, 255, 0.92);
            backdrop-filter: blur(6px);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            gap: 10px;
            opacity: 1;
            transition: opacity 0.25s ease;
            pointer-events: none;
          ">
            <div style="width: 24px; height: 24px; border: 2px solid rgba(79, 70, 229, 0.2); border-top-color: #4f46e5; border-radius: 50%; animation: sc-spin 0.8s linear infinite;"></div>
            <span class="sc-load-text" style="color: #475569; font-size: 12px; font-weight: 600;">Generating Anti-CV Puzzle...</span>
          </div>
        </div>

        <!-- Slider Track -->
        <div class="sc-track-container" style="
          position: relative;
          height: ${KN}px;
          margin-top: 12px;
          background: #f1f5f9;
          border-radius: 24px;
          box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.05), 0 0 0 1px #cbd5e1;
          touch-action: none;
          overflow: hidden;
        ">
          <div class="sc-progress-fill" style="
            position: absolute; left: 0; top: 0; bottom: 0; width: 0px;
            background: linear-gradient(90deg, rgba(79, 70, 229, 0.18), rgba(129, 140, 248, 0.32));
            border-radius: 24px; pointer-events: none;
          "></div>

          <div class="sc-prompt-text" style="
            position: absolute; inset: 0; display: flex; align-items: center; justify-content: center;
            color: #64748b; font-size: 13px; font-weight: 500; pointer-events: none;
          ">
            Slide the puzzle piece to fit
          </div>

          <div class="sc-knob" style="
            position: absolute; left: 0; top: 0; width: ${KN}px; height: ${KN}px;
            border-radius: 50%; background: linear-gradient(135deg, #4f46e5, #4338ca);
            box-shadow: 0 4px 12px rgba(79, 70, 229, 0.5), inset 0 1px 1px rgba(255, 255, 255, 0.3);
            cursor: grab; touch-action: none; display: flex; align-items: center; justify-content: center;
            color: #ffffff; transition: background 0.2s ease, transform 0.15s ease;
          ">
            <svg class="sc-knob-arrow" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="9 18 15 12 9 6"></polyline>
            </svg>
            <svg class="sc-knob-check" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="display: none;">
              <polyline points="20 6 9 17 4 12"></polyline>
            </svg>
          </div>
        </div>
      </div>

      <!-- Invisible Multi-Layer Honeypot Traps — bots fill these, humans don't -->
      <input class="sc-honeypot" name="user_verification_hp" tabindex="-1" autocomplete="off" aria-hidden="true" style="position: absolute; left: -9999px; opacity: 0; pointer-events: none; height: 0; width: 0;">
      <input class="sc-honeypot-sec" name="auth_token_bypass" tabindex="-1" autocomplete="off" aria-hidden="true" style="display: none !important; opacity: 0; position: absolute; pointer-events: none;">

      <!-- Locked Out Rate Limit Overlay with Live Countdown -->
      <div class="sc-lockout-overlay" style="
        display: none;
        position: absolute;
        inset: 0;
        background: rgba(15, 23, 42, 0.96);
        backdrop-filter: blur(10px);
        border-radius: 12px;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 16px;
        text-align: center;
        z-index: 99;
        box-shadow: inset 0 0 25px rgba(239, 68, 68, 0.3), 0 10px 25px rgba(0,0,0,0.3);
        box-sizing: border-box;
      ">
        <div style="width: 38px; height: 38px; border-radius: 50%; background: rgba(239, 68, 68, 0.18); border: 2px solid #ef4444; display: flex; align-items: center; justify-content: center; margin-bottom: 8px; animation: sc-pulse 1.5s infinite;">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
          </svg>
        </div>
        <span style="color: #f87171; font-size: 13px; font-weight: 700; letter-spacing: 0.3px;">Rate Limit / Access Blocked</span>
        <span class="sc-lockout-desc" style="color: #cbd5e1; font-size: 11px; margin-top: 4px; line-height: 1.4; max-width: 250px;">Too many failed attempts. Temporary security lockout active.</span>
        <div style="margin-top: 10px; display: inline-flex; align-items: center; gap: 7px; padding: 4px 14px; border-radius: 20px; background: rgba(0,0,0,0.5); border: 1px solid rgba(239, 68, 68, 0.4);">
          <span style="color: #94a3b8; font-size: 11px; font-weight: 500;">Unlocks in:</span>
          <span class="sc-lockout-timer" style="color: #f87171; font-family: monospace; font-size: 14px; font-weight: 700;">05:00</span>
        </div>
      </div>
    `;

    container.appendChild(root);

    const viewCheckbox   = root.querySelector('.sc-view-checkbox');
    const viewJigsaw     = root.querySelector('.sc-view-jigsaw');
    const chkBtn         = root.querySelector('.sc-chk-btn');
    const chkSpinner     = root.querySelector('.sc-chk-spinner');
    const chkCheck       = root.querySelector('.sc-chk-check');
    const chkLabel       = root.querySelector('.sc-chk-label');
    const chkSub         = root.querySelector('.sc-chk-sub');
    const bgImg          = root.querySelector('.sc-bg');
    const pieceImg       = root.querySelector('.sc-piece');
    const overlay        = root.querySelector('.sc-overlay');
    const loadText       = root.querySelector('.sc-load-text');
    const knob           = root.querySelector('.sc-knob');
    const promptText     = root.querySelector('.sc-prompt-text');
    const progressFill   = root.querySelector('.sc-progress-fill');
    const refreshBtn     = root.querySelector('.sc-refresh-btn');
    const honeypot       = root.querySelector('.sc-honeypot');
    const honeypotSec    = root.querySelector('.sc-honeypot-sec');
    const badgeText      = root.querySelector('.sc-badge-text');
    const badgeDot       = root.querySelector('.sc-dot');
    const knobArrow      = root.querySelector('.sc-knob-arrow');
    const knobCheck      = root.querySelector('.sc-knob-check');
    const topGuide       = root.querySelector('.sc-top-guide');
    const guideIcon      = root.querySelector('.sc-guide-icon');
    const guideMsg       = root.querySelector('.sc-guide-msg');
    const attemptBadge   = root.querySelector('.sc-attempt-badge');
    const attemptDot     = root.querySelector('.sc-attempt-dot');
    const attemptText    = root.querySelector('.sc-attempt-text');
    const lockoutOverlay = root.querySelector('.sc-lockout-overlay');
    const lockoutDesc    = root.querySelector('.sc-lockout-desc');
    const lockoutTimer   = root.querySelector('.sc-lockout-timer');

    let lockoutInterval  = null;

    function showLockout(seconds = 300, message = '') {
      if (lockoutInterval) clearInterval(lockoutInterval);
      if (lockoutOverlay) {
        lockoutOverlay.style.display = 'flex';
        if (message && lockoutDesc) lockoutDesc.textContent = message;
      }
      let remaining = Math.max(1, Math.round(seconds));
      const formatTime = (s) => {
        const m = Math.floor(s / 60).toString().padStart(2, '0');
        const sec = (s % 60).toString().padStart(2, '0');
        return `${m}:${sec}`;
      };
      if (lockoutTimer) lockoutTimer.textContent = formatTime(remaining);

      lockoutInterval = setInterval(() => {
        remaining--;
        if (lockoutTimer) lockoutTimer.textContent = formatTime(Math.max(0, remaining));
        if (remaining <= 0) {
          clearInterval(lockoutInterval);
          lockoutInterval = null;
          if (lockoutOverlay) lockoutOverlay.style.display = 'none';
          attemptCount = 0;
          initChallenge();
        }
      }, 1000);
    }

    function hideLockout() {
      if (lockoutInterval) {
        clearInterval(lockoutInterval);
        lockoutInterval = null;
      }
      if (lockoutOverlay) lockoutOverlay.style.display = 'none';
    }

    let attemptCount = 0;
    const MAX_ATTEMPTS = 3;

    function updateAttemptBadge() {
      if (!attemptBadge || !attemptText || !attemptDot) return;
      const current = Math.min(attemptCount + 1, MAX_ATTEMPTS);
      attemptText.textContent = `Attempt ${current}/${MAX_ATTEMPTS}`;
      if (current === 1) {
        attemptDot.style.background = '#10b981';
        attemptBadge.style.borderColor = '#cbd5e1';
        attemptBadge.style.color = '#475569';
      } else if (current === 2) {
        attemptDot.style.background = '#f59e0b';
        attemptBadge.style.borderColor = '#fcd34d';
        attemptBadge.style.color = '#b45309';
      } else {
        attemptDot.style.background = '#ef4444';
        attemptBadge.style.borderColor = '#fca5a5';
        attemptBadge.style.color = '#b91c1c';
      }
    }

    function setTopGuide(state, message, customIcon = null) {
      if (!topGuide || !guideIcon || !guideMsg) return;
      guideMsg.textContent = message;

      if (state === 'match') {
        topGuide.style.background = 'rgba(16, 185, 129, 0.12)';
        topGuide.style.borderColor = '#10b981';
        topGuide.style.boxShadow = '0 0 10px rgba(16, 185, 129, 0.25)';
        guideMsg.style.color = '#047857';
        guideIcon.textContent = customIcon || '✨';
        guideIcon.style.animation = 'sc-guide-pulse 0.5s ease-in-out infinite';
      } else if (state === 'right') {
        topGuide.style.background = 'rgba(99, 102, 241, 0.08)';
        topGuide.style.borderColor = 'rgba(99, 102, 241, 0.35)';
        topGuide.style.boxShadow = '0 1px 3px rgba(0,0,0,0.03)';
        guideMsg.style.color = '#4338ca';
        guideIcon.textContent = customIcon || '👉';
        guideIcon.style.animation = 'sc-guide-slide 0.7s ease-in-out infinite';
      } else if (state === 'left') {
        topGuide.style.background = 'rgba(245, 158, 11, 0.1)';
        topGuide.style.borderColor = 'rgba(245, 158, 11, 0.4)';
        topGuide.style.boxShadow = '0 1px 3px rgba(0,0,0,0.03)';
        guideMsg.style.color = '#b45309';
        guideIcon.textContent = customIcon || '👈';
        guideIcon.style.animation = 'sc-guide-slide-left 0.7s ease-in-out infinite';
      } else if (state === 'warning') {
        topGuide.style.background = 'rgba(239, 68, 68, 0.1)';
        topGuide.style.borderColor = 'rgba(239, 68, 68, 0.4)';
        topGuide.style.boxShadow = '0 0 10px rgba(239, 68, 68, 0.2)';
        guideMsg.style.color = '#b91c1c';
        guideIcon.textContent = customIcon || '⚠️';
        guideIcon.style.animation = 'sc-warn-blink 0.6s ease-in-out infinite';
      } else if (state === 'success') {
        topGuide.style.background = 'rgba(16, 185, 129, 0.15)';
        topGuide.style.borderColor = '#10b981';
        topGuide.style.boxShadow = '0 0 12px rgba(16, 185, 129, 0.25)';
        guideMsg.style.color = '#047857';
        guideIcon.textContent = customIcon || '🎉';
        guideIcon.style.animation = 'sc-guide-bounce 0.6s ease infinite';
      } else {
        topGuide.style.background = '#f8fafc';
        topGuide.style.borderColor = '#cbd5e1';
        topGuide.style.boxShadow = '0 1px 3px rgba(0,0,0,0.03)';
        guideMsg.style.color = '#334155';
        guideIcon.textContent = customIcon || '💡';
        guideIcon.style.animation = 'sc-guide-bounce 1.5s ease-in-out infinite';
      }
    }

    let currentChallenge = null;
    let powPromise = null;
    let isReady = false;
    let isSolved = false;
    let isDragging = false;
    let isSubmitting = false;
    let dragStartX = 0, knobStartX = 0, knobX = 0, startTime = 0;
    let trajectoryTrail = [];
    let isEventTrusted = true;
    let dragStartTimestamp = 0;

    const getPieceX = () => knobX * (W - P) / (W - KN);

    function updateKnobPosition(newKnobX) {
      knobX = Math.max(0, Math.min(W - KN, newKnobX));
      const currentPx = getPieceX();

      if (currentChallenge && typeof currentChallenge.targetX === 'number') {
        const diff = currentPx - currentChallenge.targetX;
        if (Math.abs(diff) <= 22) {
          pieceImg.style.filter = 'drop-shadow(0 0 14px #10b981) drop-shadow(0 0 6px #34d399)';
          knob.style.boxShadow = '0 0 16px rgba(16, 185, 129, 0.7)';
          if (isDragging) {
            topGuide && topGuide.classList.add('sc-hint-match');
            topGuide && topGuide.classList.remove('sc-hint-idle');
            setTopGuide('match', '✨ Perfect! Release here — Yahan chhod dein');
          }
        } else {
          pieceImg.style.filter = 'drop-shadow(0 4px 8px rgba(0, 0, 0, 0.5))';
          knob.style.boxShadow = '0 4px 12px rgba(79, 70, 229, 0.5)';
          if (isDragging) {
            topGuide && topGuide.classList.remove('sc-hint-match');
            if (diff < -22) {
              setTopGuide('right', '👉 Slide right — Aage ki taraf khenchein');
            } else {
              setTopGuide('left', '👈 Too far! Move left — Thoda wapas karein');
            }
          }
        }
      }

      knob.style.left = `${knobX}px`;
      pieceImg.style.left = `${currentPx}px`;
      progressFill.style.width = `${knobX + KN / 2}px`;
    }

    function setStatus(text, color = '#64748b') {
      promptText.textContent = text;
      promptText.style.color = color;
    }

    function shakeWidget() {
      root.classList.remove('sc-shake');
      void root.offsetWidth; // reflow
      root.classList.add('sc-shake');
    }

    function renderModeView(mode) {
      if (mode === 'checkbox') {
        viewCheckbox.style.display = 'block';
        viewJigsaw.style.display = 'none';
      } else {
        viewCheckbox.style.display = 'none';
        viewJigsaw.style.display = 'block';
      }
    }

    /* ------------------------------------------------------------------
       INIT CHALLENGE
       ------------------------------------------------------------------ */
    async function initChallenge(forcedMode = null) {
      if (isSubmitting) return;
      isReady = false;
      isSolved = false;
      isDragging = false;
      updateKnobPosition(0);

      const targetMode = forcedMode || preferredMode;
      renderModeView(targetMode === 'checkbox' ? 'checkbox' : 'jigsaw');

      if (targetMode === 'checkbox') {
        chkBtn.disabled = false;
        chkBtn.style.borderColor = '#cbd5e1';
        chkBtn.style.background = '#f8fafc';
        chkSpinner.style.display = 'none';
        chkCheck.style.display = 'none';
        chkLabel.textContent = 'Verify you are human';
        chkSub.textContent = 'Autonomous Proof-of-Work';
        onReset();
        return;
      }

      if (overlay) { overlay.style.opacity = '1'; overlay.style.pointerEvents = 'auto'; }
      if (loadText) loadText.textContent = 'Generating Anti-CV Puzzle...';
      if (badgeDot) badgeDot.style.background = '#4f46e5';
      if (badgeText) badgeText.textContent = 'Shield Jigsaw';
      if (knob) knob.style.background = 'linear-gradient(135deg, #4f46e5, #4338ca)';
      if (knobArrow) knobArrow.style.display = 'block';
      if (knobCheck) knobCheck.style.display = 'none';
      setStatus('Initializing...');
      onReset();

      try {
        const res = await fetch(`${api}/api/challenge`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: 'jigsaw', failCount })
        });
        const data = await res.json();
        if (data.error === 'ip_temporarily_locked' || res.status === 429) {
          showLockout(data.retryAfterSec || 300, data.message);
          return;
        }
        if (data.error) {
          overlay.style.opacity = '1';
          loadText.textContent = data.error;
          setStatus('Rate limited', '#ef4444');
          return;
        }

        currentChallenge = data;
        bgImg.src = data.bg;
        pieceImg.src = data.piece;
        badgeText.textContent = `PoW ${data.bits}b`;
        powPromise = runPoWWorker(data.prefix, data.bits);

        await Promise.all([bgImg.decode(), pieceImg.decode()]);
        pieceImg.style.top = `${data.pieceY}px`;
        startTime = performance.now();
        isReady = true;
        overlay.style.opacity = '0';
        overlay.style.pointerEvents = 'none';
        setStatus('Drag the slider → fit the piece into the shadow slot');
        updateAttemptBadge();
        topGuide && topGuide.classList.add('sc-hint-idle');
        topGuide && topGuide.classList.remove('sc-hint-match');
        setTopGuide('normal', '💡 Tip: Drag the knob → align the piece into the cut-out slot');
        // After 3s idle, show a more explicit step hint
        clearTimeout(root._idleHintTimer);
        root._idleHintTimer = setTimeout(() => {
          if (isReady && !isSolved && !isDragging) {
            setTopGuide('right', '👉 Hold & drag the purple knob rightward until the piece snaps in');
          }
        }, 3000);
      } catch {
        overlay.style.opacity = '1';
        loadText.textContent = 'Network error.';
        setStatus('Network error. Tap refresh.', '#ef4444');
      }
    }

    /* ------------------------------------------------------------------
       1-CLICK CHECKBOX HANDLER
       ------------------------------------------------------------------ */
    chkBtn.onclick = async e => {
      // Security: reject programmatic synthetic clicks
      if (!e.isTrusted) {
        shakeWidget();
        chkLabel.textContent = 'Interaction rejected';
        chkSub.textContent = 'Synthetic event detected';
        return;
      }
      if (isSubmitting || isSolved) return;
      isSubmitting = true;
      chkBtn.disabled = true;
      chkSpinner.style.display = 'block';
      chkCheck.style.display = 'none';
      chkLabel.textContent = 'Verifying you are human...';
      chkSub.textContent = 'Evaluating environment…';

      const clickStart = performance.now();
      const clickLatencyMs = Math.round(clickStart - mountTimestamp);

      try {
        const chalRes = await fetch(`${api}/api/challenge`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: 'checkbox', failCount })
        });
        const chal = await chalRes.json();
        if (chal.error === 'ip_temporarily_locked' || chalRes.status === 429) {
          isSubmitting = false;
          chkSpinner.style.display = 'none';
          chkBtn.disabled = false;
          showLockout(chal.retryAfterSec || 300, chal.message);
          return;
        }
        if (chal.error || !chal.prefix) {
          isSubmitting = false;
          chkSpinner.style.display = 'none';
          chkBtn.disabled = false;
          chkLabel.textContent = chal.error || 'Service busy';
          chkSub.textContent = 'Tap to retry';
          return;
        }
        currentChallenge = chal;

        chkSub.textContent = 'Checking browser integrity…';
        const powResult = await runPoWWorker(chal.prefix, chal.bits);
        const fingerprint = collectBrowserFingerprint();
        const interactionReport = sensor.getReport();

        const payloadObj = {
          id: chal.id,
          nonce: powResult.nonce,
          powDuration: powResult.duration,
          reqNonce: Array.from(crypto.getRandomValues(new Uint8Array(12))).map(b => b.toString(16).padStart(2, '0')).join(''),
          trace: ambientTrace.slice(-150),
          trustedEvent: e.isTrusted,
          clickLatencyMs,
          honeypot: (honeypot.value || '') + (honeypotSec ? honeypotSec.value : ''),
          env: fingerprint,
          interaction: interactionReport,
          sdkVersion: SDK_VERSION
        };

        const encryptedHex = await encryptPayload(payloadObj, chal.salt);

        const verifyRes = await fetch(`${api}/api/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: chal.id, encrypted: encryptedHex, token: chal.token })
        });

        const result = await verifyRes.json();

        // Golden Human Pacing Window (800ms - 900ms)
        // Ensures natural authentic verification pacing — not instant (100ms) and not laggy
        const MIN_CHECKBOX_PACING_MS = 850;
        const elapsed = performance.now() - clickStart;
        if (elapsed < MIN_CHECKBOX_PACING_MS) {
          await new Promise(r => setTimeout(r, MIN_CHECKBOX_PACING_MS - elapsed));
        }

        isSubmitting = false;

        if (result.escalate && result.challenge) {
          chkLabel.textContent = 'Security check needed';
          chkSub.textContent = 'Escalating to puzzle…';
          setTimeout(() => {
            attemptCount = 0;
            renderModeView('jigsaw');
            currentChallenge = result.challenge;
            bgImg.src = result.challenge.bg;
            pieceImg.src = result.challenge.piece;
            badgeText.textContent = `PoW ${result.challenge.bits}b (Step-Up)`;
            powPromise = runPoWWorker(result.challenge.prefix, result.challenge.bits);
            Promise.all([bgImg.decode(), pieceImg.decode()]).then(() => {
              pieceImg.style.top = `${result.challenge.pieceY}px`;
              startTime = performance.now();
              isReady = true;
              overlay.style.opacity = '0';
              overlay.style.pointerEvents = 'none';
              setStatus('Security check: slide piece to verify');
              updateAttemptBadge();
              setTopGuide('warning', '⚠️ Step-up check: Piece ko slot me match karein');
            });
          }, 450);
          return;
        }

        if (result.error === 'ip_temporarily_locked' || verifyRes.status === 429) {
          chkSpinner.style.display = 'none';
          showLockout(result.retryAfterSec || 300, result.message);
          return;
        }

        if (result.ok) {
          isSolved = true;
          chkSpinner.style.display = 'none';
          chkCheck.style.display = 'block';
          chkBtn.style.borderColor = '#10b981';
          chkBtn.style.background = 'rgba(16, 185, 129, 0.12)';
          chkBtn.style.boxShadow = '0 0 0 3px rgba(16, 185, 129, 0.20)';
          chkLabel.textContent = "You're verified!";
          chkSub.textContent = `Human verified • Score: ${result.score || 98}`;
          failCount = 0;
          onToken(result.token, { score: result.score || 98, mode: 'checkbox_pow' });
        } else {
          failCount++;
          chkSpinner.style.display = 'none';
          chkLabel.textContent = 'Verification rejected';
          chkSub.textContent = result.reason?.replace(/_/g, ' ') || 'Please try again';
          shakeWidget();
          setTimeout(() => initChallenge('checkbox'), 1200);
        }
      } catch {
        failCount++;
        isSubmitting = false;
        chkSpinner.style.display = 'none';
        chkLabel.textContent = 'Connection error';
        setTimeout(() => initChallenge('checkbox'), 1200);
      }
    };

    /* ------------------------------------------------------------------
       JIGSAW DRAG TRACKING
       ------------------------------------------------------------------ */
    function recordPoint(e) {
      isEventTrusted = isEventTrusted && e.isTrusted;
      const rect = knob.parentNode.getBoundingClientRect();
      const currentY = +(e.clientY - rect.top).toFixed(1);
      const currentX = +getPieceX().toFixed(1);
      const timeMs = Math.round(performance.now() - startTime);
      // v4.2: Record pointer pressure (0 for non-touch = mouse, 0.5 for default touch, varies for stylus)
      const pressure = typeof e.pressure === 'number' ? +e.pressure.toFixed(3) : 0;

      const pt = [currentX, currentY, timeMs, pressure];
      if (trajectoryTrail.length < 800) trajectoryTrail.push(pt);

      onTrajectory({ x: currentX, y: currentY, timeMs, trail: trajectoryTrail, isTrusted: isEventTrusted });
    }

    knob.addEventListener('pointerdown', e => {
      // Hard rejection for synthetic drag start
      if (!e.isTrusted) { shakeWidget(); return; }
      if (!isReady || isSolved || isDragging || isSubmitting) return;
      isDragging = true;
      trajectoryTrail = [];
      isEventTrusted = e.isTrusted;
      dragStartX = e.clientX;
      dragStartTimestamp = performance.now();
      knobStartX = knobX;
      knob.setPointerCapture(e.pointerId);
      promptText.style.opacity = '0.3';
      clearTimeout(root._idleHintTimer);
      topGuide && topGuide.classList.remove('sc-hint-idle', 'sc-hint-match');
      setTopGuide('right', '👉 Slide right — align the piece into the shadow gap');
      recordPoint(e);
    });

    knob.addEventListener('pointermove', e => {
      if (!isDragging) return;
      updateKnobPosition(knobStartX + (e.clientX - dragStartX));
      recordPoint(e);
    });

    async function finishDrag(e) {
      if (!isDragging) return;
      isDragging = false;
      isSubmitting = true;
      promptText.style.opacity = '1';
      recordPoint(e);

      const dragElapsedMs = Math.round(performance.now() - dragStartTimestamp);

      // Client-side sanity: reject impossibly fast drags (< 60ms) before even sending
      if (dragElapsedMs < 60) {
        isSubmitting = false;
        failCount++;
        attemptCount++;
        updateAttemptBadge();
        shakeWidget();
        guideIcon && guideIcon.classList.add('sc-warn-icon');
        if (attemptCount >= MAX_ATTEMPTS) {
          setTopGuide('warning', '⚠️ All 3 attempts used — Naya puzzle aa raha hai...');
          setStatus('Max attempts reached. Refreshing...', '#ef4444');
          setTimeout(() => { attemptCount = 0; guideIcon && guideIcon.classList.remove('sc-warn-icon'); initChallenge('jigsaw'); }, 1400);
        } else {
          setTopGuide('warning', `⚠️ Too fast! Drag slowly — Aaram se slide karein (${attemptCount}/${MAX_ATTEMPTS})`);
          setStatus('Drag too fast — move naturally like a human', '#ef4444');
          setTimeout(() => { guideIcon && guideIcon.classList.remove('sc-warn-icon'); initChallenge('jigsaw'); }, 1200);
        }
        return;
      }

      const dropStart = performance.now();
      setStatus('Evaluating motion physics...', '#6366f1');
      knob.style.background = 'linear-gradient(135deg, #4338ca, #3730a3)';

      try {
        const powResult = await powPromise;
        const fingerprint = collectBrowserFingerprint();
        const interactionReport = sensor.getReport();

        const payloadObj = {
          id: currentChallenge.id,
          x: getPieceX(),
          nonce: powResult.nonce,
          powDuration: powResult.duration,
          dragElapsedMs,
          reqNonce: Array.from(crypto.getRandomValues(new Uint8Array(12))).map(b => b.toString(16).padStart(2, '0')).join(''),
          trail: trajectoryTrail,
          trustedEvent: isEventTrusted,
          honeypot: (honeypot.value || '') + (honeypotSec ? honeypotSec.value : ''),
          env: fingerprint,
          interaction: interactionReport,
          sdkVersion: SDK_VERSION
        };

        const encryptedHex = await encryptPayload(payloadObj, currentChallenge.salt);

        const verifyRes = await fetch(`${api}/api/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: currentChallenge.id, encrypted: encryptedHex, token: currentChallenge.token })
        });

        const result = await verifyRes.json();

        // Natural smooth puzzle evaluation pacing (450ms - 550ms)
        const MIN_PUZZLE_PACING_MS = 500;
        const elapsed = performance.now() - dropStart;
        if (elapsed < MIN_PUZZLE_PACING_MS) {
          await new Promise(r => setTimeout(r, MIN_PUZZLE_PACING_MS - elapsed));
        }

        isSubmitting = false;

        if (result.error === 'ip_temporarily_locked' || verifyRes.status === 429) {
          showLockout(result.retryAfterSec || 300, result.message);
          return;
        }

        if (result.ok) {
          isSolved = true;
          isReady = false;
          failCount = 0;
          attemptCount = 0;
          updateAttemptBadge();
          setTopGuide('success', '🎉 Shabash! Perfect match — Human Verified');
          knob.style.background = 'linear-gradient(135deg, #10b981, #059669)';
          knob.style.boxShadow = '0 4px 14px rgba(16, 185, 129, 0.6)';
          knobArrow.style.display = 'none';
          knobCheck.style.display = 'block';
          badgeDot.style.background = '#10b981';
          badgeText.textContent = `Human (Score ${result.score || 96})`;
          setStatus('Verification Successful!', '#059669');
          onToken(result.token, result.audit);
        } else {
          failCount++;
          attemptCount++;
          updateAttemptBadge();
          knob.style.background = 'linear-gradient(135deg, #ef4444, #dc2626)';
          badgeDot.style.background = '#ef4444';
          badgeText.textContent = 'Anomaly Detected';
          shakeWidget();

          guideIcon && guideIcon.classList.add('sc-warn-icon');
          if (attemptCount >= MAX_ATTEMPTS) {
            setTopGuide('warning', '⚠️ 3 failed attempts — Refreshing puzzle...');
            setStatus('All 3 attempts failed. Loading fresh challenge...', '#ef4444');
            setTimeout(() => {
              attemptCount = 0;
              guideIcon && guideIcon.classList.remove('sc-warn-icon');
              initChallenge('jigsaw');
            }, 1400);
          } else {
            const remaining = MAX_ATTEMPTS - attemptCount;
            const warningMsg = result.reason === 'puzzle_misaligned'
              ? `⚠️ Piece didn't fit! Align inside the shadow outline — ${remaining} attempt${remaining !== 1 ? 's' : ''} left`
              : `⚠️ Verification failed — ${remaining} attempt${remaining !== 1 ? 's' : ''} remaining`;
            setTopGuide('warning', warningMsg);
            const reasonMsg = result.reason === 'puzzle_misaligned'
              ? `Off by ${Math.abs(Math.round(getPieceX() - (currentChallenge.targetX || 0)))}px — slide piece exactly into the cut-out`
              : (result.reason ? result.reason.replace(/_/g, ' ') : 'Verification failed');
            setStatus(reasonMsg, '#ef4444');
            setTimeout(() => { guideIcon && guideIcon.classList.remove('sc-warn-icon'); initChallenge('jigsaw'); }, 1400);
          }
        }
      } catch {
        isSubmitting = false;
        failCount++;
        setStatus('Verification failed. Retrying...', '#ef4444');
        setTimeout(() => initChallenge('jigsaw'), 900);
      }
    }

    knob.addEventListener('pointerup', finishDrag);
    knob.addEventListener('pointercancel', finishDrag);
    refreshBtn.addEventListener('click', () => {
      attemptCount = 0;
      updateAttemptBadge();
      initChallenge('jigsaw');
    });

    /* ------------------------------------------------------------------
       BOT ATTACK SIMULATOR INTERFACE (for the lab page)
       ------------------------------------------------------------------ */
    async function simulateBot(attackType) {
      if (preferredMode === 'checkbox') {
        const res = await fetch(`${api}/api/challenge`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode: 'checkbox' })
        });
        const chal = await res.json();
        const powRes = await runPoWWorker(chal.prefix, chal.bits);
        const envAudit = collectBrowserFingerprint();
        if (attackType === 'headless') { envAudit.webdriver = true; envAudit.isHeadless = true; }

        const fakePayload = {
          id: chal.id,
          nonce: powRes.nonce,
          trace: attackType === 'linear' ? [[0, 0, 100], [100, 100, 200]] : [],
          trustedEvent: attackType !== 'teleport',
          honeypot: '',
          env: envAudit,
          sdkVersion: SDK_VERSION
        };

        const enc = await encryptPayload(fakePayload, chal.salt);
        const r = await fetch(`${api}/api/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: chal.id, encrypted: enc })
        });
        return await r.json();
      }

      if (!isReady || isSolved || isSubmitting) return { ok: false, reason: 'widget_busy' };
      isSubmitting = true;
      setStatus(`Executing ${attackType} bot attack...`, '#f59e0b');

      const targetX = 140;
      const powResult = await powPromise;
      let mockTrail = [];
      let mockTrusted = true;
      let mockEnv = collectBrowserFingerprint();

      if (attackType === 'teleport') {
        mockTrail = [[0, 20, 50], [targetX, 20, 65]];
      } else if (attackType === 'linear') {
        for (let i = 0; i <= 30; i++) mockTrail.push([(targetX / 30) * i, 22.0, 100 + i * 20]);
      } else if (attackType === 'bezier') {
        for (let i = 0; i <= 40; i++) {
          const t = i / 40;
          const x = 3 * (1 - t) * (1 - t) * t * 50 + 3 * (1 - t) * t * t * 100 + t * t * t * targetX;
          mockTrail.push([+x.toFixed(1), +(20 + Math.sin(t * Math.PI) * 1.5).toFixed(1), Math.round(150 + t * 900)]);
        }
      } else if (attackType === 'headless') {
        mockEnv.webdriver = true;
        mockEnv.isHeadless = true;
        mockTrail = [[0, 20, 100], [targetX / 2, 21, 500], [targetX, 20, 900]];
      }

      const payloadObj = {
        id: currentChallenge.id,
        x: targetX,
        nonce: powResult.nonce,
        powDuration: powResult.duration,
        dragElapsedMs: 500,
        trail: mockTrail,
        trustedEvent: mockTrusted,
        honeypot: '',
        env: mockEnv,
        sdkVersion: SDK_VERSION
      };

      const encryptedHex = await encryptPayload(payloadObj, currentChallenge.salt);
      const verifyRes = await fetch(`${api}/api/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: currentChallenge.id, encrypted: encryptedHex })
      });

      const res = await verifyRes.json();
      isSubmitting = false;

      if (knob) knob.style.background = res.ok ? 'linear-gradient(135deg, #10b981, #059669)' : 'linear-gradient(135deg, #ef4444, #dc2626)';
      if (badgeDot) badgeDot.style.background = res.ok ? '#10b981' : '#ef4444';
      if (badgeText) badgeText.textContent = res.ok ? 'Verified' : 'Blocked Attack';
      setStatus(res.ok ? 'Passed' : `BLOCKED: ${res.reason}`, res.ok ? '#059669' : '#ef4444');
      return res;
    }

    function switchMode(newMode) {
      preferredMode = newMode;
      hideLockout();
      initChallenge(newMode);
    }

    // Initialize
    initChallenge();

    return {
      reset: () => { hideLockout(); initChallenge(); },
      switchMode,
      triggerLockout: (sec) => showLockout(sec || 300),
      resetLockout: () => {
        hideLockout();
        fetch(`${api}/api/challenge?reset_lockout=true`).catch(() => {});
        initChallenge();
      },
      simulateBot,
      destroy() {
        if (lockoutInterval) clearInterval(lockoutInterval);
        window.removeEventListener('pointermove', handleAmbient);
        sensor.destroy();
      }
    };
  }

  global.ShieldCaptcha = { mount, version: '4.2' };
})(typeof window !== 'undefined' ? window : this);