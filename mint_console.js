// CIPNFT — Unified Console (Encrypt, Tokenize, View)
// 2-page flow: mint.html (this page) + marketplace.html
// Copyright (c) 2026 Decentralized Science Labs — GenesisL1
// MIT License

(async function () {
  'use strict';

  const $ = (id) => document.getElementById(id);

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function setText(id, txt) {
    const el = $(id);
    if (el) el.textContent = String(txt ?? '');
  }

  function toast(msg) {
    const el = $("toast");
    if (!el) return;
    el.textContent = String(msg ?? '');
    el.classList.add('show');
    setTimeout(() => el.classList.remove('show'), 3200);
  }

  function logLine(msg) {
    const out = $("consoleOut");
    if (!out) return;
    out.textContent = (out.textContent ? out.textContent + "\n" : "") + String(msg ?? '');
    out.scrollTop = out.scrollHeight;
  }

  // ---------------- Terms text renderer (adapted from terms.js) ----------------
  function renderTosMarkup(raw) {
    const el = $("tosTextOut");
    if (!el) return;
    let txt = String(raw || "");

    // Convert literal "\\n" sequences if present.
    if (!/\n/.test(txt) && /\\n/.test(txt)) {
      txt = txt.replace(/\\r\\n/g, "\n").replace(/\\n/g, "\n");
    }

    if (!/\n/.test(txt)) {
      let t = txt.replace(/\s+/g, " ").trim();
      t = t.replace(/^(CIPNFT\s+TERMS\s+OF\s+SERVICE)\s+/i, "$1\n\n");
      t = t.replace(/(BY\s+USING\s+THE\s+CIPNFT[\s\S]*?TERMS\.)\s+(?=\d+\))/i, "$1\n\n");
      t = t.replace(/\s+(?=\d{1,2}\)\s+[A-Z])/g, "\n\n");
      t = t.replace(/\s+\(([a-z])\)\s+/g, "\n   ($1) ");
      txt = t;
    }

    const looksHtml = /<\s*\w+[\s>]/.test(txt);
    if (!looksHtml) {
      const lines = txt.replace(/\r\n/g, "\n").split("\n");
      const blocks = [];
      let cur = [];

      const flush = () => {
        if (!cur.length) return;
        const joined = cur.join(" ").replace(/\s+/g, " ").trim();
        if (joined) blocks.push({ t: "p", v: joined });
        cur = [];
      };

      const isAllCapsHeading = (s) => {
        if (!s) return false;
        if (/[a-z]/.test(s)) return false;
        const letters = s.replace(/[^A-Z]/g, "");
        if (letters.length < 6) return false;
        if (s.length > 110) return false;
        return true;
      };

      for (const line of lines) {
        const s = String(line || "").trim();
        if (!s) {
          flush();
          continue;
        }

        if (/^CIPNFT\s+TERMS\s+OF\s+SERVICE/i.test(s)) {
          flush();
          blocks.push({ t: "title", v: s });
          continue;
        }

        if (/^\d+\)\s+/.test(s)) {
          flush();
          blocks.push({ t: "sec", v: s });
          continue;
        }

        if (isAllCapsHeading(s)) {
          flush();
          blocks.push({ t: "head", v: s });
          continue;
        }

        cur.push(s);
      }
      flush();

      const escHtml = (s) => String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/\"/g, "&quot;");

      el.innerHTML = blocks.map(b => {
        const v = escHtml(b.v);
        if (b.t === "title") return `<h1 class="tos-title">${v}</h1>`;
        if (b.t === "sec") return `<h2 class="tos-sec">${v}</h2>`;
        if (b.t === "head") return `<h3 class="tos-head">${v}</h3>`;
        return `<p>${v}</p>`;
      }).join("\n");
      return;
    }

    // Minimal sanitize for HTML terms (best-effort)
    try {
      const parser = new DOMParser();
      const doc = parser.parseFromString(`<div>${txt}</div>`, 'text/html');
      const root = doc.body.firstElementChild;
      const ALLOW = new Set(['DIV','P','BR','STRONG','EM','B','I','U','UL','OL','LI','A','H1','H2','H3','H4','CODE','PRE','BLOCKQUOTE']);

      const walk = (node) => {
        const children = Array.from(node.childNodes);
        for (const ch of children) {
          if (ch.nodeType === 1) {
            const tag = ch.tagName.toUpperCase();
            if (!ALLOW.has(tag)) {
              const t = doc.createTextNode(ch.textContent || '');
              ch.replaceWith(t);
              continue;
            }

            for (const attr of Array.from(ch.attributes)) {
              const n = attr.name.toLowerCase();
              if (n.startsWith('on') || n === 'style') ch.removeAttribute(attr.name);
              if (tag === 'A' && n === 'href') {
                const href = String(attr.value || '');
                if (/^\s*javascript:/i.test(href)) ch.removeAttribute('href');
                else {
                  ch.setAttribute('rel', 'noopener noreferrer');
                  ch.setAttribute('target', '_blank');
                }
              }
            }
            walk(ch);
          }
        }
      };

      if (root) walk(root);
      el.innerHTML = root ? root.innerHTML : '';
    } catch (_) {
      el.textContent = txt;
    }
  }

  // ---------------- Tokenize helpers ----------------
  function countWords(s) {
    return String(s || "").trim().split(/\s+/).filter(Boolean).length;
  }

  function updateTitleHelp() {
    const inp = $("titleIn");
    const help = $("titleHelp");
    if (!inp || !help) return;
    const t = String(inp.value || "").trim();
    const w = countWords(t);
    const bytes = new TextEncoder().encode(t).length;
    help.textContent = `Title is stored on-chain in plaintext. Words: ${w}/5 · Bytes: ${bytes}/80`;
    help.style.color = (w > 5 || bytes > 80 || !t) ? "var(--accent)" : "var(--text-muted)";
  }

  function encModeFromUI() {
    const v = $("encModeSelect")?.value || "classic";
    return (v === "pqc") ? CIPNFT.ENC_MODE_PQC : CIPNFT.ENC_MODE_CLASSIC;
  }

  function showKeyPanel() {
    const v = $("encModeSelect")?.value || "classic";

    // Drives the global key-login indicator and the noWalletLink logic.
    CIPNFT.setPreferredEncMode(v === "pqc" ? "pqc" : "classic");

    const classic = $("classicKeyPanel");
    const pqc = $("pqcKeyPanel");
    if (classic) classic.style.display = (v === "classic") ? "" : "none";
    if (pqc) pqc.style.display = (v === "pqc") ? "" : "none";

    const titleEl = $("keyCardTitle");
    if (titleEl) {
      titleEl.textContent = (v === "pqc")
        ? "Quantum-resistant Encryption Key Registration (Owner Identity)"
        : "Classic Encryption Key Registration (Owner Identity)";
    }

    CIPNFT.renderWalletHeader();
  }

  async function refreshFeesAndTos() {
    await CIPNFT.refreshOnchain();

    const sym = CIPNFT.nativeSymbol();
    setText("tosVerPill", `TOS v${CIPNFT.state.tosVersionCurrent ?? "—"}`);
    setText("tosAcceptedPill", CIPNFT.state.tosAcceptedCurrent ? "ACCEPTED" : (CIPNFT.state.address ? "NOT ACCEPTED" : "NOT CONNECTED"));

    setText("flatFeeOut", `${CIPNFT.toEtherString(CIPNFT.state.flatMintFeeWei)} ${sym}`);
    setText("perByteFeeOut", `${CIPNFT.toEtherString(CIPNFT.state.perByteFeeWei)} ${sym} / byte`);
  }

  function refreshClassicLocal() {
    const seed = CIPNFT.state.classicSeedHex || "";
    const pub = CIPNFT.state.classicEncPublicKey ? ethers.hexlify(CIPNFT.state.classicEncPublicKey) : "";
    if ($("seedHex")) $("seedHex").value = seed;
    if ($("pubKeyHex")) $("pubKeyHex").value = pub;
  }

  async function refreshClassicOnchain() {
    if (!CIPNFT.state.address) {
      setText("pubKeyStatus", "—");
      return;
    }
    try {
      const on = await CIPNFT.getMyOnchainPubKey();
      const onStr = String(on);
      if (!on || onStr === ethers.ZeroHash) {
        setText("pubKeyStatus", "On-chain: NOT SET");
        return;
      }
      const localPub = CIPNFT.state.classicEncPublicKey ? ethers.hexlify(CIPNFT.state.classicEncPublicKey).toLowerCase() : null;
      const ok = localPub && (localPub === onStr.toLowerCase());
      setText("pubKeyStatus", ok ? "On-chain: SET (matches local)" : "On-chain: SET (does NOT match local)");
    } catch (e) {
      setText("pubKeyStatus", `On-chain: error (${CIPNFT.fmtErr(e)})`);
    }
  }

  async function refreshPqcLocal() {
    if ($("pqcSeedHex")) $("pqcSeedHex").value = CIPNFT.state.pqcSeedHex || "";
    if (!$("pqcPubInfo")) return;
    if (CIPNFT.state.pqcPubKeyBytes) {
      const h = ethers.keccak256(CIPNFT.state.pqcPubKeyBytes);
      $("pqcPubInfo").value = `len=${CIPNFT.state.pqcPubKeyBytes.length}, hash=${h}`;
    } else {
      $("pqcPubInfo").value = "not derived";
    }
  }

  async function refreshPqcOnchain() {
    if (!CIPNFT.state.address) {
      setText("pqcKeyStatus", "—");
      return;
    }
    try {
      const on = await CIPNFT.getMyOnchainPqcPubKey();
      if (!on || on.length === 0) {
        setText("pqcKeyStatus", "On-chain: NOT SET");
        return;
      }
      const onHash = ethers.keccak256(on);
      const localHash = CIPNFT.state.pqcPubKeyBytes ? ethers.keccak256(CIPNFT.state.pqcPubKeyBytes) : null;
      const ok = localHash && (localHash.toLowerCase() === onHash.toLowerCase());
      setText("pqcKeyStatus", ok ? "On-chain: SET (matches local)" : "On-chain: SET (does NOT match local)");
    } catch (e) {
      setText("pqcKeyStatus", `On-chain: error (${CIPNFT.fmtErr(e)})`);
    }
  }

  async function refreshKeysUI() {
    refreshClassicLocal();
    await refreshClassicOnchain();
    await refreshPqcLocal();
    await refreshPqcOnchain();
    CIPNFT.renderWalletHeader();
  }

  function refreshMintFeeEstimate() {
    const pt = $("metadataIn")?.value || "";
    const bytes = CIPNFT.bytesLenUtf8(pt);
    const est = (CIPNFT.state.flatMintFeeWei || 0n) + ((CIPNFT.state.perByteFeeWei || 0n) * BigInt(bytes));
    setText("plainBytesOut", `${bytes} bytes`);
    setText("mintFeeOut", CIPNFT.state.flatMintFeeWei != null ? `${CIPNFT.toNativeString(est)}` : "—");
  }

  // ---------------- Wallet / chain helpers ----------------
  async function ensureNetworkRead() {
    await CIPNFT.init();
    await CIPNFT.ensureReadProvider();
    await CIPNFT.getReadContract();
    CIPNFT.renderWalletHeader();
  }

  async function connectWallet() {
    // Avoid popup if already connected.
    if (CIPNFT.state && CIPNFT.state.address && CIPNFT.state.signer) {
      CIPNFT.renderWalletHeader();
      return;
    }
    await CIPNFT.connectWallet();
    CIPNFT.renderWalletHeader();
  }

  async function connectAndRefreshAll() {
    await connectWallet();
    updateTitleHelp();

    try { await refreshFeesAndTos(); } catch (e) {
      logLine("On-chain Terms/Fees not available: " + CIPNFT.fmtErr(e));
    }

    try { await refreshKeysUI(); } catch (e) {
      logLine("Key status refresh failed: " + CIPNFT.fmtErr(e));
    }

    try { refreshMintFeeEstimate(); } catch (_) {}
  }

  // ---------------- Key actions ----------------
  async function doDeriveClassic() {
    await connectWallet();
    await CIPNFT.deriveKeyFromSignature();
    await refreshKeysUI();
    logLine("Classic key derived.");
  }

  function doExportClassic() {
    const seed = CIPNFT.state.classicSeedHex;
    if (!seed) throw new Error("Nothing to export (no Classic seed).");
    const text =
`CIPNFT Classic Seed Export\n\n` +
`Contract: ${CIPNFT.state.contractAddress}\n` +
`Chain ID: ${CIPNFT.state.chainId}\n` +
`Wallet: ${CIPNFT.state.address}\n\n` +
`SEED_HEX=${seed}\n\n` +
`Keep this secret.`;
    CIPNFT.downloadText(`cipnft-classic-seed-${(CIPNFT.state.address||"").slice(0,6)}.txt`, text);
    logLine("Classic seed exported.");
  }

  async function doImportClassic() {
    const seed = prompt("Paste Classic SEED_HEX (0x… 32 bytes):");
    if (!seed) return;
    await connectWallet();
    CIPNFT.importSeed(seed.trim());
    await refreshKeysUI();
    logLine("Classic seed imported.");
  }

  async function doRegisterClassic() {
    await connectWallet();
    const ok = await CIPNFT.confirmModal({
      title: "SAVE YOUR SEED",
      messageHtml: `
        <div class="advanced-warn mono" style="font-weight:700;">
          <b>WARNING:</b> BEFORE REGISTERING, YOU MUST SAVE YOUR <b>SEED / PRIVATE KEY</b>.
          IF YOU LOSE IT, YOU CAN NOT DECRYPT YOUR NFTs. CIPNFT CAN NOT RECOVER LOST KEYS.
        </div>
        <div style="margin-top:12px; color: var(--text-muted);">
          Key registration stores only your <b>public</b> key on-chain. Your seed stays in your browser/export.
        </div>
      `,
      okText: "I saved the key",
      cancelText: "Cancel"
    });
    if (!ok) {
      logLine("Key registration cancelled.");
      return;
    }

    const tx = await CIPNFT.registerPubKey();
    await refreshKeysUI();
    logLine("Registered Classic pubkey. tx=" + tx);
  }

  async function doGeneratePqc() {
    await connectWallet();
    await CIPNFT.generatePqcKey();
    await refreshKeysUI();
    logLine("PQC key generated.");
  }

  async function doDerivePqc() {
    await connectWallet();
    await CIPNFT.derivePqcKeyFromSignature();
    await refreshKeysUI();
    logLine("PQC seed derived (signature).");
  }

  function doExportPqc() {
    const seed = CIPNFT.state.pqcSeedHex;
    if (!seed) throw new Error("Nothing to export (no PQC seed).");

    const text =
`CIPNFT PQC Seed Export (ML-KEM-768)\n\n` +
`Contract: ${CIPNFT.state.contractAddress}\n` +
`Chain ID: ${CIPNFT.state.chainId}\n` +
`Wallet: ${CIPNFT.state.address}\n\n` +
`PQC_SEED_HEX=${seed}\n\n` +
`Keep this secret.`;

    CIPNFT.downloadText(`cipnft-pqc-seed-${(CIPNFT.state.address||"").slice(0,6)}.txt`, text);
    logLine("PQC seed exported.");
  }

  async function doImportPqc() {
    const seed = prompt("Paste PQC_SEED_HEX (0x… raw-seed):");
    if (!seed) return;
    await connectWallet();
    CIPNFT.importPqcSeed(seed.trim());
    await refreshKeysUI();
    logLine("PQC seed imported.");
  }

  async function doRegisterPqc() {
    await connectWallet();
    const ok = await CIPNFT.confirmModal({
      title: "SAVE YOUR PQC SEED",
      messageHtml: `
        <div class="advanced-warn mono" style="font-weight:700;">
          <b>WARNING:</b> BEFORE REGISTERING, YOU MUST SAVE YOUR <b>PQC SEED / PRIVATE KEY</b>.
          IF YOU LOSE IT, YOU CAN NOT DECRYPT YOUR NFTs. CIPNFT CAN NOT RECOVER LOST KEYS.
        </div>
        <div style="margin-top:12px; color: var(--text-muted);">
          Registration stores only your <b>PQC public key</b> on-chain.
        </div>
      `,
      okText: "I saved the key",
      cancelText: "Cancel"
    });
    if (!ok) {
      logLine("PQC key registration cancelled.");
      return;
    }

    const tx = await CIPNFT.registerPqcPubKey();
    await refreshKeysUI();
    logLine("Registered PQC pubkey. tx=" + tx);
  }

  // ---------------- View key (tokenization) ----------------
  function newViewKey() {
    if (!$("viewKeyOut")) return;
    $("viewKeyOut").value = CIPNFT.randomViewKeyText();
    toast("View key generated.");
  }

  async function copyViewKey() {
    const v = $("viewKeyOut")?.value || "";
    if (!v) return;
    await navigator.clipboard.writeText(v);
    toast("View key copied.");
  }

  function downloadViewKey() {
    const v = $("viewKeyOut")?.value || "";
    if (!v) throw new Error("No view key.");
    const content =
`CIPNFT View Key\n\n` +
`Contract: ${CIPNFT.state.contractAddress}\n` +
`ChainId: ${CIPNFT.state.chainId ?? ""}\n` +
`Wallet: ${CIPNFT.state.address ?? ""}\n\n` +
`VIEW_KEY=${v}\n`;
    CIPNFT.downloadText(`cipnft_viewkey_${(CIPNFT.state.address||"addr").slice(0,6)}.txt`, content);
    toast("View key file downloaded.");
  }

  // ---------------- Terms UI ----------------
  let termsLoaded = false;

  async function toggleTermsText() {
    const box = $("termsTextBox");
    if (!box) return;

    const isOpen = box.style.display !== 'none';
    if (isOpen) {
      box.style.display = 'none';
      return;
    }

    // Open
    box.style.display = 'block';

    if (termsLoaded) return;

    setText("termsTextStatus", "Loading terms text from chain…");

    try {
      await ensureNetworkRead();
      await CIPNFT.refreshOnchain();
      const c = await CIPNFT.getReadContract();
      const v = CIPNFT.state.tosVersionCurrent;
      const txt = await c.tosText(v);
      renderTosMarkup(txt || "");
      setText("termsTextStatus", "OK.");
      termsLoaded = true;
    } catch (e) {
      renderTosMarkup(String(e?.message || e));
      setText("termsTextStatus", "Failed to load terms text.");
    }
  }

  async function acceptTos() {
    await connectWallet();
    setText("tosAcceptedPill", "WAIT…");
    const tx = await CIPNFT.acceptCurrentTos();
    logLine("Accepted TOS. tx=" + tx);
    await refreshFeesAndTos();
  }

  // ---------------- Mint / Tokenize ----------------
  async function doMint() {
    try {
      await connectWallet();
      await refreshFeesAndTos();

      // Safety popup: must save keys.
      const ok = await CIPNFT.confirmModal({
        title: "SAVE YOUR KEYS",
        messageHtml: `
          <div class="advanced-warn mono" style="font-weight:700;">
            <b>WARNING:</b> BEFORE TOKENIZING, SAVE YOUR <b>SEED / PRIVATE KEY</b> AND YOUR <b>VIEW KEY</b> (IF ENABLED).
            IF YOU LOSE THEM, YOU CAN NOT DECRYPT YOUR NFT. THERE IS NO RECOVERY.
          </div>
          <div style="margin-top:12px; color: var(--text-muted);">
            After minting, the ciphertext is on-chain — but the keys are only in your browser/export.
          </div>
        `,
        okText: "I saved keys",
        cancelText: "Cancel"
      });
      if (!ok) {
        setText("mintStatus", "Cancelled");
        logLine("Tokenization cancelled.");
        return;
      }

      const title = String($("titleIn")?.value || "").trim();
      updateTitleHelp();
      if (!title) throw new Error("Title is required.");
      const w = countWords(title);
      const b = new TextEncoder().encode(title).length;
      if (w > 5) throw new Error("Title must be at most 5 words.");
      if (b > 80) throw new Error("Title too long (max 80 bytes).");

      const plaintext = $("metadataIn")?.value || "";
      if (!plaintext) throw new Error("Plaintext is empty.");

      const useView = !!$("chkViewKey")?.checked;
      const vk = $("viewKeyOut")?.value || "";
      if (useView && vk.length < 16) throw new Error("View key is required (generate one). ");

      const mode = encModeFromUI();
      setText("mintStatus", "Tokenizing…");

      const res = await CIPNFT.mintEncrypted({
        title,
        plaintextUtf8: plaintext,
        enableViewKey: useView,
        viewKeyText: vk,
        encMode: mode
      });

      setText("mintStatus", res.tokenId != null ? `Tokenized token #${res.tokenId}` : "Tokenized (tokenId not found in receipt)");
      logLine(`Tokenize tx=${res.txHash}`);
      if (res.tokenId != null) logLine(`TokenId=${res.tokenId}`);
      logLine(`Fee=${CIPNFT.toNativeString(res.feeWei)}, bytes=${res.plaintextBytes}`);

      // Convenience: auto-load the token into the right-side console.
      if (res.tokenId != null && $("tokenIdIn")) {
        $("tokenIdIn").value = String(res.tokenId);
        try { await loadToken(); } catch (_) {}
      }
    } catch (e) {
      setText("mintStatus", "Tokenize failed");
      logLine("Tokenize failed: " + CIPNFT.fmtErr(e));
      throw e;
    }
  }

  // ---------------- Token Console (Load/Decrypt) ----------------
  let currentToken = null;
  let lastPlaintext = '';
  let fullCipherVisible = false;

  function clearToken() {
    currentToken = null;
    lastPlaintext = '';
    fullCipherVisible = false;

    if ($("tokenIdIn")) $("tokenIdIn").value = '';

    const idsText = [
      'ownerOut','titleOut','tosOut','listedOut','priceOut','modeOut','cipherBytesOut','viewEnabledOut',
      'cipherPreviewOut','tokenStatus','ownerDecryptStatus','viewDecryptStatus'
    ];
    idsText.forEach(id => setText(id, '—'));

    const plain = $("plainOut");
    if (plain) plain.value = '';

    const cipherFullBox = $("cipherFullBox");
    if (cipherFullBox) cipherFullBox.style.display = 'none';
    const cipherFullOut = $("cipherFullOut");
    if (cipherFullOut) cipherFullOut.value = '';
    const btnToggleCipher = $("btnToggleCipher");
    if (btnToggleCipher) btnToggleCipher.textContent = 'LOAD FULL CIPHERTEXT';
  }

  async function loadToken() {
    await ensureNetworkRead();

    const tokenId = String($("tokenIdIn")?.value || '').trim();
    if (!tokenId) throw new Error('Enter tokenId.');

    setText('tokenStatus', `Loading token #${tokenId}…`);
    currentToken = await CIPNFT.getTokenBundle(tokenId);

    setText('ownerOut', currentToken.owner);
    setText('titleOut', currentToken.title);
    setText('tosOut', String(currentToken.tosVersion));
    setText('listedOut', currentToken.listed ? 'YES' : 'NO');
    setText('priceOut', currentToken.listed ? `${CIPNFT.toNativeString(currentToken.priceWei)}` : '—');
    setText('modeOut', currentToken.encMode === CIPNFT.ENC_MODE_PQC ? 'PQC (ML‑KEM‑768)' : 'CLASSIC (X25519)');
    setText('cipherBytesOut', `${currentToken.metaCipherBytes.length}`);
    setText('viewEnabledOut', (currentToken.viewWrapBytes && currentToken.viewWrapBytes.length) ? 'YES' : 'NO');

    // Preview ciphertext (short)
    const preview = CIPNFT.cipherPreviewText(currentToken.metaCipherHex, 520);
    setText('cipherPreviewOut', preview || '—');

    // Hide full ciphertext by default.
    const cipherFullBox = $("cipherFullBox");
    if (cipherFullBox) cipherFullBox.style.display = 'none';
    const cipherFullOut = $("cipherFullOut");
    if (cipherFullOut) cipherFullOut.value = '';
    fullCipherVisible = false;
    const btnToggleCipher = $("btnToggleCipher");
    if (btnToggleCipher) btnToggleCipher.textContent = 'LOAD FULL CIPHERTEXT';

    // Switch key mode hint to match token (helps users decrypt without guesswork)
    try {
      const prefer = (currentToken.encMode === CIPNFT.ENC_MODE_PQC) ? 'pqc' : 'classic';
      if ($("encModeSelect")) {
        $("encModeSelect").value = prefer;
        showKeyPanel();
      } else {
        CIPNFT.setPreferredEncMode(prefer);
      }
    } catch (_) {}

    // Attempt to load saved view key (if any)
    try {
      const k = `CIPNFT_VIEWKEY_${CIPNFT.state.chainId}_${CIPNFT.state.contractAddress}_${currentToken.tokenId}`;
      const saved = localStorage.getItem(k);
      if (saved && $("viewKeyIn")) $("viewKeyIn").value = saved;
    } catch (_) {}

    setText('tokenStatus', `Loaded token #${tokenId}.`);
    toast('Token loaded.');
  }

  function toggleFullCiphertext() {
    if (!currentToken) return;
    const box = $("cipherFullBox");
    const out = $("cipherFullOut");
    const btn = $("btnToggleCipher");

    fullCipherVisible = !fullCipherVisible;
    if (box) box.style.display = fullCipherVisible ? 'block' : 'none';
    if (out && fullCipherVisible) out.value = currentToken.metaCipherHex;
    if (btn) btn.textContent = fullCipherVisible ? 'HIDE FULL CIPHERTEXT' : 'LOAD FULL CIPHERTEXT';
  }

  async function decryptAsOwner() {
    if (!currentToken) throw new Error('Load a token first.');
    await ensureNetworkRead();

    setText('ownerDecryptStatus', 'Decrypting…');

    const dek = await CIPNFT.decryptDEKAsOwner(currentToken.ownerEncDEKBytes, currentToken.encMode);
    CIPNFT.verifyDekHash(dek, currentToken.dekHash);
    const pt = CIPNFT.decryptMetaCipher(currentToken.metaCipherBytes, dek);

    if ($("plainOut")) $("plainOut").value = pt;
    lastPlaintext = pt;

    setText('ownerDecryptStatus', 'OK.');
    toast('Decrypted as owner.');
  }

  async function decryptWithViewKey() {
    if (!currentToken) throw new Error('Load a token first.');
    if (!currentToken.viewWrapBytes || !currentToken.viewWrapBytes.length) throw new Error('Token has no view key enabled.');
    await ensureNetworkRead();

    const vk = String($("viewKeyIn")?.value || '').trim();
    if (!vk) throw new Error('Enter view key.');

    setText('viewDecryptStatus', 'Decrypting…');
    const dek = CIPNFT.decryptDEKWithViewKey(currentToken.viewWrapBytes, vk);
    CIPNFT.verifyDekHash(dek, currentToken.dekHash);
    const pt = CIPNFT.decryptMetaCipher(currentToken.metaCipherBytes, dek);

    if ($("plainOut")) $("plainOut").value = pt;
    lastPlaintext = pt;

    setText('viewDecryptStatus', 'OK.');
    toast('Decrypted with view key.');
  }

  async function loadSavedViewKey() {
    if (!currentToken) throw new Error('Load a token first.');
    await ensureNetworkRead();
    const k = `CIPNFT_VIEWKEY_${CIPNFT.state.chainId}_${CIPNFT.state.contractAddress}_${currentToken.tokenId}`;
    const saved = localStorage.getItem(k);
    if (!saved) throw new Error('No saved view key found in this browser for this token.');
    if ($("viewKeyIn")) $("viewKeyIn").value = saved;
    toast('Loaded saved view key.');
  }

  function downloadPlain() {
    if (!currentToken) throw new Error('Load a token first.');
    if (!lastPlaintext) throw new Error('Nothing to download.');
    const fname = `cipnft_token${currentToken.tokenId}_plaintext.json`;
    CIPNFT.downloadText(fname, lastPlaintext);
    toast('Downloaded plaintext.');
  }

  // ---------------- My Vault ----------------
  let myTokens = [];

  function clearMyTokens() {
    myTokens = [];
    const table = $("myTokensTable");
    if (table) table.innerHTML = '';
    setText('myTokensStatus', '—');
  }

  function eraseStatusText(r) {
    if (r.eraseActive) return `ERASING field ${r.eraseField} word ${r.eraseNextWord}`;
    if (r.eraseDone) return `ERASED`;
    return `idle`;
  }

  function renderMyTokens(rows) {
    const out = $("myTokensTable");
    if (!out) return;
    if (!rows.length) {
      out.className = '';
      out.innerHTML = `<div class="mono" style="color: var(--text-muted);">No tokens owned.</div>`;
      return;
    }

    out.className = 'grid market';
    const sym = CIPNFT.nativeSymbol();

    out.innerHTML = rows.map(r => {
      const priceEth = esc(CIPNFT.toEtherString(r.priceWei));
      const listingPill = r.open ? `<span class="pill ok">OPEN</span>` : `<span class="pill">CLOSED</span>`;
      const erasePill = r.eraseActive
        ? `<span class="pill warn">ERASING</span>`
        : (r.eraseDone ? `<span class="pill warn">ERASED</span>` : `<span class="pill">IDLE</span>`);

      return `
        <div class="card" data-row-token="${esc(r.tokenId)}">
          <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:12px;">
            <div>
              <div class="mono">TOKEN #${esc(r.tokenId)}</div>
              <div style="margin-top: 8px; font-weight: 600;">${esc(r.title || 'Untitled')}</div>
            </div>
            <div style="text-align:right;">
              <div class="mono" style="color: var(--text-muted); font-size:0.72rem;">LISTING</div>
              <div style="margin-top: 6px;">${listingPill}</div>
            </div>
          </div>

          <div class="mono" style="color: var(--text-muted); font-size:0.72rem; margin-top: 14px; word-break: break-all;">
            CIPHERTEXT (${esc(r.cipherLen || 0)} bytes, preview): ${esc(CIPNFT.cipherPreviewText(r.cipherPreviewHex, 300))}
          </div>

          <div style="display:flex; gap:14px; align-items:flex-end; margin-top: 14px; flex-wrap: wrap;">
            <div style="flex: 1; min-width: 220px;">
              <div class="mono" style="color: var(--text-muted); font-size:0.72rem;">PRICE (${esc(sym)})</div>
              <input class="inline" id="priceEth_${esc(r.tokenId)}" value="${priceEth}" placeholder="0.0" />
            </div>
            <div style="flex: 1; min-width: 220px;">
              <div class="mono" style="color: var(--text-muted); font-size:0.72rem;">ERASE STATUS</div>
              <div class="mono" style="color: var(--text-muted); font-size:0.75rem; margin-top: 6px;">${erasePill} ${esc(eraseStatusText(r))}</div>
            </div>
          </div>

          <div class="actions-inline" style="margin-top: 14px;">
            <button class="btn small" data-open="${esc(r.tokenId)}">OPEN</button>
            <button class="btn small" data-title="${esc(r.tokenId)}">TITLE</button>
            <button class="btn small" data-list="${esc(r.tokenId)}">LIST/UPDATE</button>
            <button class="btn small" data-delist="${esc(r.tokenId)}">DELIST</button>
            <button class="btn small" data-erase="${esc(r.tokenId)}">ERASE</button>
            <button class="btn small danger" data-burn="${esc(r.tokenId)}">BURN</button>
          </div>
        </div>
      `;
    }).join('');

    // Wire actions
    out.querySelectorAll('button[data-open]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const tokenId = btn.getAttribute('data-open');
        try {
          if ($("tokenIdIn")) $("tokenIdIn").value = tokenId;
          await loadToken();
          $("load-token-card")?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } catch (e) {
          alert(CIPNFT.fmtErr(e));
        }
      });
    });

    out.querySelectorAll('button[data-title]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const tokenId = btn.getAttribute('data-title');
        try {
          await connectWallet();
          const row = myTokens.find(x => x.tokenId === String(tokenId));
          const cur = row ? (row.title || "") : "";
          const next = prompt("Set public title (visible to anyone, max 5 words):", cur);
          if (next === null) return;
          setText('myTokensStatus', 'Sending title update…');
          const txHash = await CIPNFT.setTitle(tokenId, String(next).trim());
          setText('myTokensStatus', `Title updated: ${txHash}`);
          await refreshManagedToken(tokenId);
          renderMyTokens(myTokens);
        } catch (e) {
          setText('myTokensStatus', '—');
          alert(CIPNFT.fmtErr(e));
        }
      });
    });

    out.querySelectorAll('button[data-list]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const tokenId = btn.getAttribute('data-list');
        try {
          await connectWallet();
          const v = String($("priceEth_" + tokenId)?.value || '').trim();
          const priceEth = v === '' ? '0' : v;
          const priceWei = ethers.parseEther(priceEth);
          setText('myTokensStatus', `Listing #${tokenId}…`);
          const txHash = await CIPNFT.setListing(tokenId, true, priceWei);
          toast('Listing updated.');
          await refreshManagedToken(tokenId, { eraseDone: myTokens.find(x=>x.tokenId===String(tokenId))?.eraseDone });
          setText('myTokensStatus', `Updated: ${txHash}`);
        } catch (e) {
          setText('myTokensStatus', '—');
          alert(CIPNFT.fmtErr(e));
        }
      });
    });

    out.querySelectorAll('button[data-delist]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const tokenId = btn.getAttribute('data-delist');
        try {
          await connectWallet();
          setText('myTokensStatus', `Delisting #${tokenId}…`);
          const txHash = await CIPNFT.setListing(tokenId, false, 0n);
          toast('Delisted.');
          await refreshManagedToken(tokenId, { eraseDone: myTokens.find(x=>x.tokenId===String(tokenId))?.eraseDone });
          setText('myTokensStatus', `Delisted: ${txHash}`);
        } catch (e) {
          setText('myTokensStatus', '—');
          alert(CIPNFT.fmtErr(e));
        }
      });
    });

    out.querySelectorAll('button[data-erase]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const tokenId = btn.getAttribute('data-erase');
        try {
          await connectWallet();
          const maxWordsEl = $("eraseMaxWords");
          const maxWords = Math.max(1, Number((maxWordsEl ? maxWordsEl.value : 600) || 600));
          setText('myTokensStatus', `Erasing #${tokenId} (${maxWords} words)…`);
          const txHash = await CIPNFT.eraseTokenData(tokenId, maxWords);
          toast('Erase step submitted.');

          await refreshManagedToken(tokenId, { erasureStarted: true });
          setText('myTokensStatus', `Erase step tx: ${txHash}`);
        } catch (e) {
          setText('myTokensStatus', '—');
          alert(CIPNFT.fmtErr(e));
        }
      });
    });

    out.querySelectorAll('button[data-burn]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const tokenId = btn.getAttribute('data-burn');
        try {
          await connectWallet();
          const ok = confirm(`Burn token #${tokenId}?\n\nThis destroys the NFT.\nRecommended: ERASE encrypted data first.\n\nContinue?`);
          if (!ok) return;
          setText('myTokensStatus', `Burning #${tokenId}…`);
          const txHash = await CIPNFT.burn(tokenId);
          toast('Token burned.');
          myTokens = myTokens.filter(x => x.tokenId !== String(tokenId));
          renderMyTokens(myTokens);
          setText('myTokensStatus', `Burned: ${txHash}`);
        } catch (e) {
          setText('myTokensStatus', '—');
          alert(CIPNFT.fmtErr(e));
        }
      });
    });
  }

  async function refreshManagedToken(tokenId, opts = {}) {
    await ensureNetworkRead();
    const c = await CIPNFT.getReadContract();
    const addr = (CIPNFT.state.address || '').toLowerCase();

    // If no longer owned, drop.
    try {
      const owner = String(await c.ownerOf(tokenId)).toLowerCase();
      if (owner !== addr) {
        myTokens = myTokens.filter(x => x.tokenId !== String(tokenId));
        renderMyTokens(myTokens);
        return;
      }
    } catch (_) {
      myTokens = myTokens.filter(x => x.tokenId !== String(tokenId));
      renderMyTokens(myTokens);
      return;
    }

    const card = await CIPNFT.getTokenCard(tokenId);
    let erase = { active: false, field: 0, nextWord: 0 };
    try { erase = await CIPNFT.getEraseState(tokenId); } catch (_) {}

    const i = myTokens.findIndex(x => x.tokenId === String(tokenId));
    const prev = i >= 0 ? myTokens[i] : {};

    const row = {
      tokenId: String(tokenId),
      title: String(card.title || ''),
      encMode: Number(card.encMode),
      cipherLen: Number(card.cipherLen),
      cipherPreviewHex: card.cipherPreviewHex,
      open: Boolean(card.open),
      priceWei: card.priceWei,
      eraseActive: Boolean(erase.active),
      eraseField: Number(erase.field),
      eraseNextWord: Number(erase.nextWord),
      eraseDone: Boolean(prev.eraseDone)
    };

    if (opts.erasureStarted && !row.eraseActive) row.eraseDone = true;

    if (i >= 0) myTokens[i] = row;
    else myTokens.push(row);

    myTokens.sort((a,b) => (BigInt(a.tokenId) < BigInt(b.tokenId) ? -1 : 1));
    renderMyTokens(myTokens);
  }

  async function syncMyTokensState() {
    await connectWallet();
    await ensureNetworkRead();

    const outStatus = $("myTokensStatus");
    const outTable = $("myTokensTable");
    if (outTable) outTable.innerHTML = '';
    if (outStatus) outStatus.textContent = 'Fetching owned tokens from state index…';

    const c = await CIPNFT.getReadContract();
    const addr = CIPNFT.state.address;
    const addrLower = addr.toLowerCase();

    const tokenIds = [];
    try {
      const nBig = await c.ownedCount(addr);
      const n = BigInt(nBig.toString());
      const batch = 25n;
      for (let start = 0n; start < n; start += batch) {
        const end = (start + batch < n) ? (start + batch) : n;
        const ps = [];
        for (let i = start; i < end; i++) ps.push(c.ownedTokenAt(addr, i));
        const tids = await Promise.all(ps);
        for (const tid of tids) tokenIds.push(tid.toString());
      }
    } catch (e) {
      if (outStatus) outStatus.textContent = 'Owner index not available (or RPC failed). Please redeploy the latest contract (owner index required).';
      throw new Error('Owner token index not available on this deployment.');
    }

    if (!tokenIds.length) {
      myTokens = [];
      renderMyTokens([]);
      if (outStatus) outStatus.textContent = 'No tokens owned.';
      return;
    }

    const concurrency = Math.min(10, tokenIds.length);
    let idx = 0;
    const rows = new Array(tokenIds.length);

    const workers = new Array(concurrency).fill(0).map(async () => {
      while (idx < tokenIds.length) {
        const i = idx++;
        const tokenId = tokenIds[i];
        try {
          const owner = String(await c.ownerOf(tokenId));
          if (owner.toLowerCase() !== addrLower) {
            rows[i] = null;
            continue;
          }

          const card = await CIPNFT.getTokenCard(tokenId);
          let erase = { active: false, field: 0, nextWord: 0 };
          try { erase = await CIPNFT.getEraseState(tokenId); } catch (_) {}

          rows[i] = {
            tokenId: String(tokenId),
            title: String(card.title || ''),
            encMode: Number(card.encMode),
            cipherLen: Number(card.cipherLen),
            cipherPreviewHex: card.cipherPreviewHex,
            open: Boolean(card.open),
            priceWei: card.priceWei,
            eraseActive: Boolean(erase.active),
            eraseField: Number(erase.field),
            eraseNextWord: Number(erase.nextWord),
            eraseDone: false
          };
        } catch (_) {
          rows[i] = null;
        }
      }
    });

    await Promise.all(workers);

    myTokens = rows.filter(Boolean);
    myTokens.sort((a,b) => (BigInt(a.tokenId) < BigInt(b.tokenId) ? -1 : 1));
    renderMyTokens(myTokens);

    if (outStatus) outStatus.textContent = `Found ${myTokens.length} token(s) via state index.`;
  }

  // ---------------- Incoming Offers (owner) ----------------
  function selectedVkMode() {
    const el = document.querySelector('input[name="vkMode"]:checked');
    return el ? el.value : 'clear';
  }

  function updateVkModeUI() {
    const m = selectedVkMode();
    const box = $("newViewKeyBox");
    if (!box) return;
    box.style.display = (m === 'new') ? 'block' : 'none';
    if (m === 'new' && !($("newViewKeyOut")?.value)) {
      if ($("newViewKeyOut")) $("newViewKeyOut").value = CIPNFT.randomViewKeyText();
    }
  }

  async function copyNewViewKey() {
    const v = $("newViewKeyOut")?.value || '';
    if (!v) return;
    await navigator.clipboard.writeText(v);
    toast('New view key copied.');
  }

  function downloadNewViewKey(forTokenId) {
    const v = $("newViewKeyOut")?.value || '';
    if (!v) throw new Error('No new view key.');

    const tokenId = (forTokenId != null && String(forTokenId).trim() !== '')
      ? String(forTokenId).trim()
      : (currentToken ? String(currentToken.tokenId) : '');

    const content =
`CIPNFT View Key (transfer)\n\n` +
`Contract: ${CIPNFT.state.contractAddress}\n` +
`ChainId: ${CIPNFT.state.chainId ?? ''}\n` +
`TokenId: ${tokenId || ''}\n\n` +
`VIEW_KEY=${v}\n`;

    const fname = tokenId ? `cipnft_viewkey_token${tokenId}.txt` : `cipnft_viewkey.txt`;
    CIPNFT.downloadText(fname, content);
    toast('View key file downloaded.');
  }

  async function getOwnedTokenIdsFromStateIndex(ownerAddr) {
    await ensureNetworkRead();
    const c = await CIPNFT.getReadContract();

    const tokenIds = [];
    const nBig = await c.ownedCount(ownerAddr);
    const n = BigInt(nBig.toString());
    const batch = 25n;
    for (let start = 0n; start < n; start += batch) {
      const end = (start + batch < n) ? (start + batch) : n;
      const ps = [];
      for (let i = start; i < end; i++) ps.push(c.ownedTokenAt(ownerAddr, i));
      const tids = await Promise.all(ps);
      for (const tid of tids) tokenIds.push(tid.toString());
    }
    return tokenIds;
  }

  function renderOffers(rows) {
    const out = $("offersTable");
    if (!out) return;

    if (!rows.length) {
      out.innerHTML = `<div class="mono" style="color: var(--text-muted);">No active offers found.</div>`;
      return;
    }

    const head = `
      <div class="table-row" style="font-weight:600; grid-template-columns: 0.75fr 1.25fr 0.9fr 1.1fr 0.9fr auto;">
        <div>TOKEN</div>
        <div>BUYER</div>
        <div>AMOUNT</div>
        <div>EXPIRY</div>
        <div>STATUS</div>
        <div></div>
      </div>`;

    const body = rows.map(r => {
      const exp = new Date(r.expiry * 1000).toISOString().slice(0,19) + 'Z';
      const tokenIdEsc = esc(r.tokenId);
      const buyerEsc = esc(r.buyer);
      const openHref = `./mint.html?tokenId=${encodeURIComponent(String(r.tokenId))}#load-token-card`;

      return `
        <div class="table-row" style="grid-template-columns: 0.75fr 1.25fr 0.9fr 1.1fr 0.9fr auto;">
          <div class="mono"><a class="link" href="${openHref}">#${tokenIdEsc}</a></div>
          <div class="mono">${buyerEsc}</div>
          <div class="mono">${esc(CIPNFT.toEtherString(r.amountWei))} ${esc(CIPNFT.nativeSymbol())}</div>
          <div class="mono">${esc(exp)}</div>
          <div class="mono">${esc(r.status)}</div>
          <div class="actions-inline">
            <a class="btn small" style="text-decoration:none;" href="${openHref}">OPEN</a>
            <button class="btn small" data-deliver="${tokenIdEsc}|${buyerEsc}">${r.status === 'DELIVERED' ? 'RE-DELIVER' : 'DELIVER'}</button>
            ${r.status === 'DELIVERED' ? `<button class="btn small" data-revoke="${tokenIdEsc}|${buyerEsc}">REVOKE</button>` : ''}
          </div>
        </div>`;
    }).join('');

    out.innerHTML = head + body;

    out.querySelectorAll('button[data-deliver]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const raw = btn.getAttribute('data-deliver') || '';
        const parts = raw.split('|');
        const tokenId = parts[0];
        const buyer = parts.slice(1).join('|');

        try {
          if (!tokenId || !buyer) throw new Error('Bad offer row.');
          await connectWallet();

          const mode = selectedVkMode();
          const keepViewWrap = (mode === 'keep');
          const newViewKeyText = (mode === 'new') ? String($("newViewKeyOut")?.value || '') : '';

          setText('offersStatus', `Delivering token #${tokenId}…`);
          const txHash = await CIPNFT.deliverOffer({ tokenId, buyerAddr: buyer, keepViewWrap, newViewKeyText });
          setText('offersStatus', `Delivered: ${txHash}`);
          toast('Delivery posted. Buyer must verify and finalize.');

          if (mode === 'new' && newViewKeyText) {
            downloadNewViewKey(tokenId);
          }

          await loadOffersState();
        } catch (e) {
          setText('offersStatus', '—');
          alert(CIPNFT.fmtErr(e));
        }
      });
    });

    out.querySelectorAll('button[data-revoke]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const raw = btn.getAttribute('data-revoke') || '';
        const parts = raw.split('|');
        const tokenId = parts[0];
        const buyer = parts.slice(1).join('|');

        try {
          if (!tokenId || !buyer) throw new Error('Bad offer row.');
          await connectWallet();

          setText('offersStatus', `Revoking delivery for token #${tokenId}…`);
          const txHash = await CIPNFT.revokeDelivery(tokenId, buyer);
          setText('offersStatus', `Revoked: ${txHash}`);
          toast('Delivery revoked.');
          await loadOffersState();
        } catch (e) {
          setText('offersStatus', '—');
          alert(CIPNFT.fmtErr(e));
        }
      });
    });
  }

  async function loadOffersState() {
    await connectWallet();
    await ensureNetworkRead();

    setText('offersStatus', 'Loading offers for your tokens from on-chain state…');
    if ($("offersTable")) $("offersTable").innerHTML = '';

    const ownerAddr = CIPNFT.state.address;
    if (!ownerAddr) {
      setText('offersStatus', 'Connect wallet to load offers.');
      return;
    }

    let tokenIds = [];
    try {
      tokenIds = await getOwnedTokenIdsFromStateIndex(ownerAddr);
    } catch (e) {
      setText('offersStatus', 'Owner index not available (or RPC failed). Please redeploy the latest contract.');
      throw e;
    }

    if (!tokenIds.length) {
      renderOffers([]);
      setText('offersStatus', 'No tokens owned.');
      return;
    }

    const now = CIPNFT.nowSec();
    const rows = [];

    const concurrency = Math.min(6, tokenIds.length);
    let idx = 0;

    const workers = new Array(concurrency).fill(0).map(async () => {
      while (idx < tokenIds.length) {
        const i = idx++;
        const tokenId = tokenIds[i];
        try {
          let cursor = 0;
          const pageSize = 50;
          let guard = 0;

          while (guard < 40) {
            const { rows: page, newCursor } = await CIPNFT.getOffersForToken(tokenId, cursor, pageSize);
            if (!page || page.length === 0) break;

            for (const r of page) {
              if (!r || !r.expiry) continue;
              const active = r.expiry > now;
              const delivered = (r.deliveredAt && r.deliveredAt > 0);
              const status = !active ? 'EXPIRED' : (delivered ? 'DELIVERED' : 'ACTIVE');
              rows.push({ tokenId: String(tokenId), buyer: String(r.buyer), amountWei: r.amountWei, expiry: r.expiry, status });
            }

            if (newCursor === cursor) break;
            cursor = newCursor;
            if (page.length < pageSize) break;
            guard++;
          }
        } catch (_) {
          // Skip token on RPC hiccup.
        }
      }
    });

    await Promise.all(workers);

    rows.sort((a,b) => b.expiry - a.expiry);
    const visible = rows.filter(r => r.status !== 'EXPIRED');
    renderOffers(visible);

    const activeN = rows.filter(r => r.status === 'ACTIVE').length;
    const deliveredN = rows.filter(r => r.status === 'DELIVERED').length;
    const expiredN = rows.filter(r => r.status === 'EXPIRED').length;
    setText('offersStatus', `Offers loaded. Active: ${activeN}. Delivered: ${deliveredN}. Hidden expired: ${expiredN}.`);
  }

  // ---------------- My Offers (buyer) ----------------
  function renderMyOffers(rows) {
    const out = $("myOffersTable");
    if (!out) return;

    if (!rows.length) {
      out.innerHTML = `<div class="mono" style="color: var(--text-muted);">No offers found.</div>`;
      return;
    }

    const head = `
      <div class="table-row compact" style="font-weight:600;">
        <div>TOKEN</div>
        <div>AMOUNT</div>
        <div>EXPIRY</div>
        <div></div>
      </div>`;

    const body = rows.map(r => {
      const exp = new Date(r.expiry * 1000).toISOString().slice(0,19) + 'Z';
      const tokenIdEsc = esc(r.tokenId);
      const openHref = `./mint.html?tokenId=${encodeURIComponent(String(r.tokenId))}#load-token-card`;

      const statusPill = r.status.startsWith('DELIVERED')
        ? `<span class="pill ok">${esc(r.status)}</span>`
        : (r.status.startsWith('ACTIVE') ? `<span class="pill warn">${esc(r.status)}</span>` : `<span class="pill">${esc(r.status)}</span>`);

      return `
        <div class="table-row compact">
          <div class="mono">
            <a class="link" href="${openHref}">#${tokenIdEsc}</a>
            <div style="margin-top:6px;">${statusPill}</div>
          </div>
          <div class="mono">${esc(CIPNFT.toEtherString(r.amountWei))} ${esc(CIPNFT.nativeSymbol())}</div>
          <div class="mono">${esc(exp)}</div>
          <div class="actions-inline">
            <a class="btn small" style="text-decoration:none;" href="${openHref}">OPEN</a>
            ${r.status.startsWith('DELIVERED') ? `<button class="btn small" data-finalize="${tokenIdEsc}">VERIFY & FINALIZE</button>` : ''}
            ${r.status.startsWith('ACTIVE') ? `<button class="btn small" data-cancel="${tokenIdEsc}">CANCEL</button>` : ''}
            ${r.status === 'EXPIRED' ? `<button class="btn small" data-refund="${tokenIdEsc}">REFUND</button>` : ''}
          </div>
        </div>`;
    }).join('');

    out.innerHTML = head + body;

    out.querySelectorAll('button[data-cancel]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const tokenId = btn.getAttribute('data-cancel');
        try {
          await connectWallet();
          setText('myOffersStatus', `Cancelling offer for token #${tokenId}…`);
          const txHash = await CIPNFT.cancelOffer(tokenId);
          toast('Offer cancelled.');
          await loadMyOffers();
          setText('myOffersStatus', `Cancelled: ${txHash}`);
        } catch (e) {
          setText('myOffersStatus', '—');
          alert(CIPNFT.fmtErr(e));
        }
      });
    });

    out.querySelectorAll('button[data-refund]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const tokenId = btn.getAttribute('data-refund');
        try {
          await connectWallet();
          setText('myOffersStatus', `Refunding expired offer for token #${tokenId}…`);
          const txHash = await CIPNFT.refundExpiredOffer(tokenId);
          toast('Refund requested.');
          await loadMyOffers();
          setText('myOffersStatus', `Refunded: ${txHash}`);
        } catch (e) {
          setText('myOffersStatus', '—');
          alert(CIPNFT.fmtErr(e));
        }
      });
    });

    out.querySelectorAll('button[data-finalize]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const tokenId = btn.getAttribute('data-finalize');
        try {
          await connectWallet();
          setText('myOffersStatus', `Verifying delivery for token #${tokenId}…`);
          const chk = await CIPNFT.verifyDeliveryForBuyer(tokenId, CIPNFT.state.address);
          if (!chk.ok) throw new Error(`Delivery verification failed: ${chk.reason}`);
          setText('myOffersStatus', `Finalizing…`);
          const txHash = await CIPNFT.finalizeOffer(tokenId);
          toast('Trade finalized.');
          await loadMyOffers();
          setText('myOffersStatus', `Finalized: ${txHash}`);
          // Refresh vault list if present (owner changed).
          try { await syncMyTokensState(); } catch (_) {}
        } catch (e) {
          setText('myOffersStatus', '—');
          alert(CIPNFT.fmtErr(e));
        }
      });
    });
  }

  async function loadMyOffers() {
    await connectWallet();
    await ensureNetworkRead();

    if (!CIPNFT.state.address) {
      setText('myOffersStatus', 'Connect wallet to load your offers.');
      if ($("myOffersTable")) $("myOffersTable").innerHTML = '';
      return;
    }

    setText('myOffersStatus', 'Loading your offers from on-chain state…');

    const now = CIPNFT.nowSec();
    const rows = [];

    let cursor = 0;
    const pageSize = 50;
    let guard = 0;

    while (guard < 40) {
      const { rows: page, newCursor } = await CIPNFT.getOffersForBuyer(CIPNFT.state.address, cursor, pageSize);
      if (!page || page.length === 0) break;

      for (const r of page) {
        if (!r || !r.expiry) continue;
        const active = r.expiry > now;
        const delivered = (r.deliveredAt && r.deliveredAt > 0);
        rows.push({
          tokenId: r.tokenId,
          amountWei: r.amountWei,
          expiry: r.expiry,
          status: !active ? 'EXPIRED' : (delivered ? 'DELIVERED / READY' : 'ACTIVE / WAITING')
        });
      }

      if (newCursor === cursor) break;
      cursor = newCursor;
      if (page.length < pageSize) break;
      guard++;
    }

    rows.sort((a,b) => b.expiry - a.expiry);
    renderMyOffers(rows);

    const activeN = rows.filter(r => r.status.startsWith('ACTIVE')).length;
    const deliveredN = rows.filter(r => r.status.startsWith('DELIVERED')).length;
    setText('myOffersStatus', `Offers loaded from state. Active: ${activeN}. Delivered: ${deliveredN}.`);
  }

  // ---------------- Query param (open token directly) ----------------
  function parseQueryTokenId() {
    try {
      const u = new URL(window.location.href);
      return u.searchParams.get('tokenId');
    } catch (_) {
      return null;
    }
  }

  // ---------------- Bind / Init ----------------
  await CIPNFT.bootstrap();
  showKeyPanel();

  // header status
  CIPNFT.renderWalletHeader();

  // Mode select (classic / pqc)
  $("encModeSelect")?.addEventListener('change', () => showKeyPanel());

  // Connect
  $("btnConnect")?.addEventListener('click', async () => {
    try {
      await connectAndRefreshAll();
      // Auto-sync vault + offers after connect.
      try { await syncMyTokensState(); } catch (_) {}
      try { await loadOffersState(); } catch (_) {}
      try { await loadMyOffers(); } catch (_) {}
    } catch (e) {
      alert(CIPNFT.fmtErr(e));
    }
  });

  // Terms
  $("btnAcceptTos")?.addEventListener('click', async () => {
    try { await acceptTos(); }
    catch (e) { logLine("Accept TOS failed: " + CIPNFT.fmtErr(e)); alert(CIPNFT.fmtErr(e)); }
  });
  $("btnToggleTermsText")?.addEventListener('click', async () => { await toggleTermsText(); });

  // Classic
  $("btnDerive")?.addEventListener('click', async () => { try { await doDeriveClassic(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnExportSeed")?.addEventListener('click', () => { try { doExportClassic(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnImportSeed")?.addEventListener('click', async () => { try { await doImportClassic(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnClearSeed")?.addEventListener('click', async () => { try { await connectWallet(); CIPNFT.clearSeed(); await refreshKeysUI(); logLine('Classic seed cleared.'); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnRegisterPubKey")?.addEventListener('click', async () => { try { await doRegisterClassic(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });

  // PQC
  $("btnGenPqcKey")?.addEventListener('click', async () => { try { await doGeneratePqc(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnDerivePqcKey")?.addEventListener('click', async () => { try { await doDerivePqc(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnExportPqcSeed")?.addEventListener('click', () => { try { doExportPqc(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnImportPqcSeed")?.addEventListener('click', async () => { try { await doImportPqc(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnClearPqcSeed")?.addEventListener('click', async () => { try { await connectWallet(); CIPNFT.clearPqcSeed(); await refreshKeysUI(); logLine('PQC seed cleared.'); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnRegisterPqcPubKey")?.addEventListener('click', async () => { try { await doRegisterPqc(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });

  // View key (tokenize)
  $("btnNewViewKey")?.addEventListener('click', () => newViewKey());
  $("btnCopyViewKey")?.addEventListener('click', async () => { try { await copyViewKey(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnDownloadViewKey")?.addEventListener('click', () => { try { downloadViewKey(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });

  // Mint
  $("titleIn")?.addEventListener('input', updateTitleHelp);
  $("metadataIn")?.addEventListener('input', refreshMintFeeEstimate);
  $("btnMint")?.addEventListener('click', async () => { try { await doMint(); } catch (e) { /* already logged */ } });

  // Load / decrypt token
  $("btnLoadToken")?.addEventListener('click', async () => { try { await loadToken(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnClearToken")?.addEventListener('click', () => clearToken());
  $("btnToggleCipher")?.addEventListener('click', () => toggleFullCiphertext());
  $("cipherPreviewOut")?.addEventListener('click', () => toggleFullCiphertext());

  $("btnDecryptOwner")?.addEventListener('click', async () => {
    try { await connectWallet(); await decryptAsOwner(); }
    catch (e) { setText('ownerDecryptStatus', '—'); alert(CIPNFT.fmtErr(e)); }
  });

  $("btnDecryptViewKey")?.addEventListener('click', async () => {
    try { await decryptWithViewKey(); }
    catch (e) { setText('viewDecryptStatus', '—'); alert(CIPNFT.fmtErr(e)); }
  });

  $("btnLoadSavedViewKey")?.addEventListener('click', async () => { try { await loadSavedViewKey(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnDownloadPlain")?.addEventListener('click', () => { try { downloadPlain(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });

  // Incoming offers
  $("btnScanOffers")?.addEventListener('click', async () => { try { await loadOffersState(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  document.querySelectorAll('input[name="vkMode"]').forEach(r => r.addEventListener('change', updateVkModeUI));
  $("btnGenNewViewKey")?.addEventListener('click', () => { if ($("newViewKeyOut")) $("newViewKeyOut").value = CIPNFT.randomViewKeyText(); toast('New view key generated.'); });
  $("btnCopyNewViewKey")?.addEventListener('click', async () => { try { await copyNewViewKey(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnDownloadNewViewKey")?.addEventListener('click', () => { try { downloadNewViewKey(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });

  // Vault
  $("btnScanMyTokens")?.addEventListener('click', async () => { try { await syncMyTokensState(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnClearMyTokens")?.addEventListener('click', () => clearMyTokens());

  // My offers
  $("btnLoadMyOffers")?.addEventListener('click', async () => { try { await loadMyOffers(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });

  // Initial UI refresh (no wallet needed)
  updateTitleHelp();
  try { refreshMintFeeEstimate(); } catch (_) {}

  try {
    await refreshFeesAndTos();
  } catch (e) {
    // Do not break page load (wrong chain/contract is common during dev).
    setText('flatFeeOut', '—');
    setText('perByteFeeOut', '—');
    setText('tosVerPill', 'TOS v—');
    setText('tosAcceptedPill', 'NOT CONNECTED');
    logLine('Init: could not read on-chain Terms/Fees. ' + CIPNFT.fmtErr(e));
  }

  try { await refreshKeysUI(); } catch (_) {}

  updateVkModeUI();

  // Auto-open token if URL has tokenId.
  const tid = parseQueryTokenId();
  if (tid && $("tokenIdIn")) {
    $("tokenIdIn").value = tid;
    try { await loadToken(); } catch (_) {}
  }

  // If wallet session was auto-restored, opportunistically load vault + offers.
  if (CIPNFT.state.address) {
    try { await syncMyTokensState(); } catch (_) {}
    try { await loadOffersState(); } catch (_) {}
    try { await loadMyOffers(); } catch (_) {}
  }
})();
