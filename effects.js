/*
 * CIPNFT UI Effects
 * Copyright (c) 2026 Decentralized Science Labs — GenesisL1 Blockchain (L1 Coin)
 * MIT License (see LICENSE)
 */

(function () {
  'use strict';

  const ACCENT = '#0044ff';
  const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef!<>-_\\/[]{}—=+*^?#________';

  const prefersReducedMotion = (() => {
    try {
      return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
    } catch (_) {
      return false;
    }
  })();

  function randChar() {
    return CHARS[Math.floor(Math.random() * CHARS.length)];
  }

  function escHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function makeCipherText(plain) {
    // Preserve spaces and common punctuation for readability and consistent widths.
    const keep = new Set([' ', '\t', '\n', '.', ',', ':', ';', '/', '|', '-', '—', '_', '#', '@', '(', ')', '[', ']', '{', '}', '+']);
    let out = '';
    for (const ch of String(plain)) {
      if (keep.has(ch)) out += ch;
      else out += randChar();
    }
    return out;
  }

  class SmoothScramble {
    constructor(el, opts = {}) {
      this.el = el;
      this.accent = opts.accent || ACCENT;
      this.charChangeProb = typeof opts.charChangeProb === 'number' ? opts.charChangeProb : 0.14;
      this.duration = typeof opts.duration === 'number' ? opts.duration : 34; // frames
      this.update = this.update.bind(this);
      this.frame = 0;
      this.queue = [];
      this.frameRequest = null;
      this.resolve = null;
    }

    setText(newText, opts = {}) {
      const duration = typeof opts.duration === 'number' ? opts.duration : this.duration;
      const charChangeProb = typeof opts.charChangeProb === 'number' ? opts.charChangeProb : this.charChangeProb;

      if (prefersReducedMotion) {
        this.el.textContent = newText;
        return Promise.resolve();
      }

      const oldText = this.el.innerText;
      const length = Math.max(oldText.length, newText.length);
      const promise = new Promise((resolve) => (this.resolve = resolve));
      this.queue = [];

      const half = Math.max(8, Math.floor(duration / 2));
      for (let i = 0; i < length; i++) {
        const from = oldText[i] || '';
        const to = newText[i] || '';

        // Newlines are kept stable (not scrambled) to avoid layout oddities.
        if (from === '\n' || to === '\n') {
          this.queue.push({ from: '\n', to: '\n', start: 0, end: 0, char: '\n', stable: true });
          continue;
        }

        const start = Math.floor(Math.random() * half);
        const end = start + half + Math.floor(Math.random() * half);
        this.queue.push({ from, to, start, end, char: '', stable: false });
      }

      this._charChangeProb = charChangeProb;

      if (this.frameRequest) cancelAnimationFrame(this.frameRequest);
      this.frame = 0;
      this.update();
      return promise;
    }

    update() {
      let output = '';
      let complete = 0;

      for (let i = 0, n = this.queue.length; i < n; i++) {
        const item = this.queue[i];
        const { from, to, start, end, stable } = item;

        if (stable) {
          output += '\n';
          complete++;
          continue;
        }

        if (this.frame >= end) {
          complete++;
          output += escHtml(to);
        } else if (this.frame >= start) {
          if (!item.char || Math.random() < this._charChangeProb) {
            item.char = randChar();
          }
          output += `<span style="color:${this.accent}">${escHtml(item.char)}</span>`;
        } else {
          output += escHtml(from);
        }
      }

      // Preserve line breaks if any
      this.el.innerHTML = output.replace(/\n/g, '<br>');

      if (complete === this.queue.length) {
        if (this.resolve) this.resolve();
        this.resolve = null;
      } else {
        this.frameRequest = requestAnimationFrame(this.update);
        this.frame++;
      }
    }
  }

  const scramblers = new WeakMap();

  function getScrambler(el) {
    let s = scramblers.get(el);
    if (!s) {
      s = new SmoothScramble(el);
      scramblers.set(el, s);
    }
    return s;
  }

  async function toggleEncrypted(el) {
    if (!el || el.dataset._cipherBusy === '1') return;
    el.dataset._cipherBusy = '1';

    try {
      const plain = el.dataset.plain || el.textContent;
      if (!el.dataset.plain) {
        el.dataset.plain = plain;
        el.setAttribute('aria-label', plain.trim());
      }

      const scr = getScrambler(el);
      const isEncrypted = el.dataset.encrypted === '1';

      if (!isEncrypted) {
        const cipher = makeCipherText(plain);
        el.dataset.cipher = cipher;
        el.dataset.encrypted = '1';
        el.classList.add('is-encrypted');
        await scr.setText(cipher, { duration: 32, charChangeProb: 0.12 });
      } else {
        el.dataset.encrypted = '0';
        el.classList.remove('is-encrypted');
        await scr.setText(plain, { duration: 32, charChangeProb: 0.14 });
      }
    } finally {
      el.dataset._cipherBusy = '0';
    }
  }

  function initNavCipherToggle() {
    // Some pages (e.g. the main app console) request a clean/static nav.
    // Opt-out via: <body data-disable-nav-cipher="1">.
    try {
      const b = document.body;
      if (b && (b.dataset && b.dataset.disableNavCipher === '1')) return;
    } catch (_) {}
    const links = document.querySelectorAll('nav .nav-links a');
    links.forEach((a) => {
      if (a.dataset.cipherToggleInit === '1') return;
      if (!a.dataset.plain) {
        a.dataset.plain = a.textContent;
        a.setAttribute('aria-label', a.textContent.trim());
      }
      a.dataset.cipherToggleInit = '1';
      // Toggle encryption on each re-hover (mouseenter fires once per enter).
      a.addEventListener('mouseenter', () => toggleEncrypted(a));
    });
  }

  function initMobileNavMenu() {
    const nav = document.querySelector('nav');
    const btn = document.getElementById('navToggle');
    if (!nav || !btn) return;
    if (btn.dataset._init === '1') return;
    btn.dataset._init = '1';

    const setExpanded = (open) => {
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    };

    btn.addEventListener('click', () => {
      const open = !nav.classList.contains('nav-open');
      nav.classList.toggle('nav-open', open);
      setExpanded(open);
    });

    // Close menu when clicking a link (mobile UX)
    nav.querySelectorAll('.nav-links a').forEach(a => {
      a.addEventListener('click', () => {
        nav.classList.remove('nav-open');
        setExpanded(false);
      });
    });
  }

  function initFrontPageLinkCipherToggle() {
    // Front page is identified by presence of the hero title.
    const isFront = !!document.querySelector('#main-title');
    if (!isFront) return;

    const els = document.querySelectorAll('a, button');
    els.forEach((el) => {
      if (!el || el.dataset.cipherToggleInit === '1') return;

      // Avoid breaking composite anchors (logo has a <span> marker).
      if (el.classList && el.classList.contains('logo')) return;

      // IMPORTANT UX: do NOT scramble anything in the upper navigation/menu.
      // (Users asked to remove the encrypted hover effect from the top menu.)
      try {
        if (el.closest && el.closest('nav')) return;
      } catch (_) {}

      // Only apply to simple text-only anchors.
      if (el.tagName === 'A') {
        if (!el.getAttribute('href')) return;
        if (el.children && el.children.length > 0) return;
      }

      // Only apply to buttons with visible text.
      if (el.tagName === 'BUTTON') {
        const t = (el.textContent || '').trim();
        if (!t) return;
      }

      // Store original label once.
      if (!el.dataset.plain) {
        el.dataset.plain = el.textContent;
        try { el.setAttribute('aria-label', (el.textContent || '').trim()); } catch (_) {}
      }

      el.dataset.cipherToggleInit = '1';
      el.addEventListener('mouseenter', () => toggleEncrypted(el));
    });
  }

  function animateSlogan() {
    const title = document.querySelector('#main-title');
    if (!title) return;

    const lines = title.querySelectorAll('.cipher-line');
    if (!lines || lines.length === 0) {
      // Fallback: scramble the whole title if spans are not used.
      const scr = getScrambler(title);
      const plain = title.innerText;
      scr.setText(makeCipherText(plain), { duration: 26, charChangeProb: 0.12 })
        .then(() => scr.setText(plain, { duration: 38, charChangeProb: 0.16 }))
        .catch(() => {});
      return;
    }

    lines.forEach((line, idx) => {
      const plain = line.dataset.plain || line.textContent;
      line.dataset.plain = plain;
      const scr = getScrambler(line);
      const delay = idx * 190;
      setTimeout(() => {
        scr.setText(makeCipherText(plain), { duration: 24, charChangeProb: 0.12 })
          .then(() => scr.setText(plain, { duration: 36, charChangeProb: 0.16 }))
          .catch(() => {});
      }, delay);
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    // Disable upper-menu cipher hover effect completely.
    initFrontPageLinkCipherToggle();
    initMobileNavMenu();
    // Only affects pages that include a hero title with #main-title.
    animateSlogan();
  });

  window.CIPNFTEffects = {
    SmoothScramble,
    makeCipherText,
    initNavCipherToggle,
    initMobileNavMenu,
    initFrontPageLinkCipherToggle,
    animateSlogan,
  };
})();
