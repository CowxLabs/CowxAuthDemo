(function () {
  'use strict';

  const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const CIRCUMFERENCE = 2 * Math.PI * 16;

  let state = {
    secret: null,
    algorithm: 'SHA-1',
    digits: 6,
    period: 30,
    issuer: '',
    account: '',
    counter: null,
    type: 'totp',
  };

  let qrCodeInstance = null;
  let countdownInterval = null;
  let toastTimeout = null;
  let inputTimer = null;

  const $ = (id) => document.getElementById(id);
  const codeDisplay = $('code-display');
  const codeValue = $('code-value');
  const codeLabel = $('code-label');
  const ringFg = $('ring-fg');
  const ringLabel = $('ring-label');
  const secretInput = $('secret-input');
  const inputToggle = $('input-toggle');
  const inputHint = $('input-hint');
  const detailsSection = $('details-section');
  const qrSection = $('qr-section');
  const qrToggle = $('qr-toggle');
  const qrContainer = $('qr-container');
  const qrCodeEl = $('qr-code');
  const themeToggle = $('theme-toggle');
  const copyBtn = $('copy-btn');
  const toast = $('toast');
  const detailAlgorithm = $('detail-algorithm');
  const detailDigits = $('detail-digits');
  const detailPeriod = $('detail-period');
  const detailIssuer = $('detail-issuer');

  function base32Decode(str) {
    const cleaned = str.replace(/[\s-=]/g, '').toUpperCase();
    const chars = [];
    for (const ch of cleaned) {
      const idx = BASE32_ALPHABET.indexOf(ch);
      if (idx === -1) throw new Error('Invalid Base32 character: ' + ch);
      chars.push(idx);
    }
    const bits = [];
    for (const c of chars) {
      for (let i = 4; i >= 0; i--) bits.push((c >> i) & 1);
    }
    const bytes = [];
    for (let i = 0; i + 7 < bits.length; i += 8) {
      let byte = 0;
      for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
      bytes.push(byte);
    }
    return new Uint8Array(bytes);
  }

  function parseOTPAuthURI(uri) {
    const trimmed = uri.trim();
    const parsed = { secret: null, algorithm: 'SHA-1', digits: 6, period: 30, issuer: '', account: '', counter: null, type: 'totp' };

    if (!trimmed.startsWith('otpauth://')) {
      try {
        const decoded = base32Decode(trimmed);
        if (decoded.length > 0) parsed.secret = trimmed.replace(/\s|-/g, '').toUpperCase();
      } catch {
        parsed.secret = null;
      }
      return parsed;
    }

    try {
      const url = new URL(trimmed);
      const proto = url.protocol;
      if (proto !== 'otpauth:') return parsed;

      const host = url.hostname;
      if (host !== 'totp' && host !== 'hotp') return parsed;
      parsed.type = host;

      const path = url.pathname.replace(/^\//, '');
      const colonIdx = path.indexOf(':');
      if (colonIdx >= 0) {
        parsed.issuer = decodeURIComponent(path.slice(0, colonIdx));
        parsed.account = decodeURIComponent(path.slice(colonIdx + 1));
      } else {
        parsed.account = decodeURIComponent(path);
      }

      const secret = url.searchParams.get('secret');
      if (!secret) return parsed;

      try {
        const decoded = base32Decode(secret);
        if (decoded.length > 0) parsed.secret = secret.replace(/\s|-/g, '').toUpperCase();
      } catch {
        return parsed;
      }

      const alg = url.searchParams.get('algorithm');
      if (alg) {
        const normalized = alg.toUpperCase().replace(/-/g, '');
        if (normalized === 'SHA1') parsed.algorithm = 'SHA-1';
        else if (normalized === 'SHA256') parsed.algorithm = 'SHA-256';
        else if (normalized === 'SHA512') parsed.algorithm = 'SHA-512';
      }

      const digits = parseInt(url.searchParams.get('digits'), 10);
      if (!isNaN(digits) && digits >= 6 && digits <= 8) parsed.digits = digits;

      const period = parseInt(url.searchParams.get('period'), 10);
      if (!isNaN(period) && period > 0) parsed.period = period;

      const issuerParam = url.searchParams.get('issuer');
      if (issuerParam) parsed.issuer = decodeURIComponent(issuerParam);

      if (parsed.type === 'hotp') {
        const counter = parseInt(url.searchParams.get('counter'), 10);
        if (!isNaN(counter)) parsed.counter = counter;
      }
    } catch {
      return parsed;
    }

    return parsed;
  }

  async function generateTOTP(secret, algorithm, digits, period, timestamp, hotpCounter) {
    const keyData = base32Decode(secret);
    const counter = hotpCounter !== undefined
      ? hotpCounter
      : Math.floor((timestamp || Date.now()) / 1000 / (period || 30));

    const counterBuffer = new ArrayBuffer(8);
    const view = new DataView(counterBuffer);
    const high = Math.floor(counter / 0x100000000);
    const low = counter >>> 0;
    view.setUint32(0, high, false);
    view.setUint32(4, low, false);

    let hashAlg;
    if (algorithm === 'SHA-1') hashAlg = 'SHA-1';
    else if (algorithm === 'SHA-256') hashAlg = 'SHA-256';
    else if (algorithm === 'SHA-512') hashAlg = 'SHA-512';
    else hashAlg = 'SHA-1';

    const key = await crypto.subtle.importKey(
      'raw', keyData, { name: 'HMAC', hash: { name: hashAlg } }, false, ['sign']
    );

    const hmac = await crypto.subtle.sign('HMAC', key, counterBuffer);
    const hmacArray = new Uint8Array(hmac);
    const offset = hmacArray[hmacArray.length - 1] & 0xf;
    const truncated =
      ((hmacArray[offset] & 0x7f) << 24) |
      ((hmacArray[offset + 1] & 0xff) << 16) |
      ((hmacArray[offset + 2] & 0xff) << 8) |
      (hmacArray[offset + 3] & 0xff);
    const code = truncated % Math.pow(10, digits);
    return String(code).padStart(digits, '0');
  }

  function getRemaining(period) {
    return period - (Math.floor(Date.now() / 1000) % period);
  }

  function showToast(message, isError) {
    clearTimeout(toastTimeout);
    toast.textContent = message;
    toast.className = 'toast' + (isError ? ' error' : '');
    toast.classList.add('show');
    toastTimeout = setTimeout(() => toast.classList.remove('show'), 2500);
  }

  function updateRing(remaining, period) {
    const fraction = remaining / period;
    const offset = CIRCUMFERENCE * (1 - fraction);
    ringFg.setAttribute('stroke-dashoffset', offset);
    ringLabel.textContent = remaining;
  }

  function updateDetails(parsed) {
    if (!parsed || !parsed.secret) {
      detailsSection.style.display = 'none';
      qrSection.style.display = 'none';
      return;
    }
    detailsSection.style.display = 'block';
    detailAlgorithm.textContent = parsed.algorithm === 'SHA-1' ? 'SHA1' : parsed.algorithm;
    detailDigits.textContent = parsed.digits;
    detailPeriod.textContent = parsed.period + 's';
    detailIssuer.textContent = parsed.issuer || '—';

    if (parsed.issuer || parsed.account) {
      codeLabel.textContent = parsed.issuer
        ? parsed.issuer + (parsed.account ? ' — ' + parsed.account : '')
        : parsed.account;
    } else {
      codeLabel.textContent = 'One-Time Password';
    }

    qrSection.style.display = 'block';
  }

  function generateQR(uri) {
    if (!uri || !uri.startsWith('otpauth://')) return;
    if (qrCodeEl && typeof QRCode !== 'undefined') {
      if (qrCodeInstance) {
        qrCodeInstance.clear();
        qrCodeInstance.makeCode(uri);
      } else {
        qrCodeEl.innerHTML = '';
        qrCodeInstance = new QRCode(qrCodeEl, {
          text: uri,
          width: 200,
          height: 200,
          colorDark: '#c000ff',
          colorLight: '#0a0015',
          correctLevel: QRCode.CorrectLevel.M
        });
      }
    }
  }

  async function updateCode() {
    if (!state.secret) {
      codeDisplay.setAttribute('data-status', 'STANDBY');
      codeValue.textContent = '———';
      codeValue.classList.remove('error-state');
      ringFg.setAttribute('stroke-dashoffset', CIRCUMFERENCE);
      ringLabel.textContent = '--';
      return;
    }

    try {
      let code;
      if (state.type === 'hotp' && state.counter !== null) {
        code = await generateTOTP(state.secret, state.algorithm, state.digits, state.period, undefined, state.counter);
      } else {
        code = await generateTOTP(state.secret, state.algorithm, state.digits, state.period);
      }
      if (codeValue.textContent !== code) {
        codeValue.textContent = code;
        codeValue.classList.remove('error-state');
        codeValue.classList.remove('updating');
        void codeValue.offsetWidth;
        codeValue.classList.add('updating');
      }
      const remaining = state.type === 'totp' ? getRemaining(state.period) : 0;
      updateRing(remaining, state.period);
    } catch (err) {
      codeValue.textContent = 'ERR';
      codeValue.classList.add('error-state');
      ringLabel.textContent = '--';
    }
  }

  function startCountdown() {
    stopCountdown();
    updateCode();
    countdownInterval = setInterval(updateCode, 1000);
  }

  function stopCountdown() {
    if (countdownInterval) {
      clearInterval(countdownInterval);
      countdownInterval = null;
    }
  }

  function processInput(value) {
    const parsed = parseOTPAuthURI(value);

    if (parsed && parsed.secret) {
      state.secret = parsed.secret;
      state.algorithm = parsed.algorithm;
      state.digits = parsed.digits;
      state.period = parsed.period;
      state.issuer = parsed.issuer;
      state.account = parsed.account;
      state.counter = parsed.counter;
      state.type = parsed.type;
      inputHint.textContent = 'Secret loaded — code refreshes every ' + state.period + 's';
      inputHint.style.color = '';
      codeDisplay.setAttribute('data-status', 'ACTIVE');
      updateDetails(parsed);
      generateQR(value.trim().startsWith('otpauth://') ? value.trim() : constructURI(parsed));
      startCountdown();
    } else if (value.trim() === '') {
      state.secret = null;
      codeValue.textContent = '———';
      codeDisplay.setAttribute('data-status', 'READY');
      codeValue.classList.remove('error-state');
      inputHint.textContent = 'Paste a Base32 secret or an otpauth:// URI';
      inputHint.style.color = '';
      detailsSection.style.display = 'none';
      qrSection.style.display = 'none';
      stopCountdown();
      updateRing(0, 30);
    } else {
      codeDisplay.setAttribute('data-status', 'ERROR');
      state.secret = null;
      codeValue.textContent = 'ERR';
      codeValue.classList.add('error-state');
      inputHint.textContent = parsed && !parsed.secret ? 'Missing or invalid secret in URI' : 'Invalid secret format';
      inputHint.style.color = 'var(--error)';
      detailsSection.style.display = 'none';
      qrSection.style.display = 'none';
      stopCountdown();
      updateRing(0, 30);
    }
  }

  function constructURI(state) {
    const label = state.issuer
      ? encodeURIComponent(state.issuer) + ':' + encodeURIComponent(state.account || 'user')
      : encodeURIComponent(state.account || 'user');
    let uri = 'otpauth://' + state.type + '/' + label + '?secret=' + state.secret;
    if (state.issuer) uri += '&issuer=' + encodeURIComponent(state.issuer);
    if (state.algorithm !== 'SHA-1') uri += '&algorithm=' + state.algorithm;
    if (state.digits !== 6) uri += '&digits=' + state.digits;
    if (state.period !== 30) uri += '&period=' + state.period;
    if (state.type === 'hotp' && state.counter !== null) uri += '&counter=' + state.counter;
    return uri;
  }

  function handleInput() {
    clearTimeout(inputTimer);
    inputTimer = setTimeout(() => processInput(secretInput.value), 300);
  }

  function copyCode() {
    const code = codeValue.textContent;
    if (!code || code === '———' || code === 'ERR') {
      showToast('No code to copy', true);
      return;
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(code).then(() => {
        copyBtn.classList.add('copied');
        copyBtn.querySelector('span').textContent = 'Copied!';
        showToast('Code copied to clipboard');
        setTimeout(() => {
          copyBtn.classList.remove('copied');
          copyBtn.querySelector('span').textContent = 'Copy Code';
        }, 2000);
      }).catch(() => fallbackCopy(code));
    } else {
      fallbackCopy(code);
    }
  }

  function fallbackCopy(text) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      copyBtn.classList.add('copied');
      copyBtn.querySelector('span').textContent = 'Copied!';
      showToast('Code copied to clipboard');
      setTimeout(() => {
        copyBtn.classList.remove('copied');
        copyBtn.querySelector('span').textContent = 'Copy Code';
      }, 2000);
    } catch {
      showToast('Failed to copy', true);
    }
    document.body.removeChild(ta);
  }

  function toggleSecretVisibility() {
    if (secretInput.type === 'password') {
      secretInput.type = 'text';
      inputToggle.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
    } else {
      secretInput.type = 'password';
      inputToggle.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
    }
  }

  function toggleTheme() {
    const html = document.documentElement;
    const current = html.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    document.querySelector('meta[name="theme-color"]').setAttribute('content', next === 'dark' ? '#0a0015' : '#1a0a2e');
    localStorage.setItem('ezotp-theme', next);

    if (qrCodeInstance && state.secret) {
      qrCodeInstance.clear();
      qrCodeInstance = new QRCode(qrCodeEl, {
        text: constructURI(state),
        width: 200,
        height: 200,
        colorDark: '#c000ff',
        colorLight: next === 'dark' ? '#0a0015' : '#1a0a2e',
        correctLevel: QRCode.CorrectLevel.M
      });
    }
  }

  function toggleQR() {
    qrSection.classList.toggle('expanded');
    const span = qrToggle.querySelector('span');
    if (qrSection.classList.contains('expanded')) {
      span.textContent = 'Hide QR Code';
    } else {
      span.textContent = 'Show QR Code';
    }
  }

  function init() {
    const savedTheme = localStorage.getItem('ezotp-theme');
    if (savedTheme) {
      document.documentElement.setAttribute('data-theme', savedTheme);
      document.querySelector('meta[name="theme-color"]').setAttribute('content', savedTheme === 'dark' ? '#0a0015' : '#1a0a2e');
    }

    codeValue.addEventListener('click', copyCode);
    copyBtn.addEventListener('click', copyCode);
    secretInput.addEventListener('input', handleInput);
    inputToggle.addEventListener('click', toggleSecretVisibility);
    themeToggle.addEventListener('click', toggleTheme);
    qrToggle.addEventListener('click', toggleQR);

    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
        e.preventDefault();
        secretInput.focus();
        secretInput.select();
      }
    });

    const urlParams = new URLSearchParams(window.location.search);
    const uriParam = urlParams.get('uri');
    if (uriParam) {
      secretInput.value = uriParam;
      processInput(uriParam);
    }

    if (typeof QRCode === 'undefined') {
      qrToggle.style.display = 'none';
    }

    if (!secretInput.value) {
      updateRing(0, 30);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
