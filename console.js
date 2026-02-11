/* CIPNFT — Console page (Encrypt, Tokenize, View)
   Combines the old mint + verify flows into a 2-column + bottom layout.
*/

(async function () {
  const $ = (id) => document.getElementById(id);

  // ---------------- UI helpers ----------------

  function toast(msg) {
    const el = $("toast");
    if (!el) return;
    el.textContent = msg;
    el.classList.add("show");
    setTimeout(() => el.classList.remove("show"), 3200);
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'}[c]));
  }

  function setText(id, txt) {
    const el = $(id);
    if (el) el.textContent = txt;
  }

  function logLine(msg) {
    const out = $("consoleOut");
    if (!out) return;
    const prev = String(out.textContent || "");
    out.textContent = (prev ? prev + "\n" : "") + String(msg);
    out.scrollTop = out.scrollHeight;
  }

  function countWords(s) {
    return String(s || "").trim().split(/\s+/).filter(Boolean).length;
  }

  // ---------------- Confirm modal (custom button labels) ----------------

  function showConfirmModal({ title, messageHtml, okText, cancelText }) {
    const overlay = $("confirmOverlay");
    const titleEl = $("confirmTitle");
    const msgEl = $("confirmMessage");
    const btnCancel = $("confirmCancel");
    const btnOk = $("confirmOk");

    if (!overlay || !titleEl || !msgEl || !btnCancel || !btnOk) {
      // Fallback to native confirm (labels not customizable)
      return Promise.resolve(window.confirm(String(title || "Are you sure?")));
    }

    // Set content
    titleEl.textContent = String(title || "Warning");
    msgEl.innerHTML = messageHtml || "";
    btnOk.textContent = String(okText || "OK");
    btnCancel.textContent = String(cancelText || "Cancel");

    // Show
    overlay.classList.add("show");
    overlay.setAttribute("aria-hidden", "false");

    // Promise wrapper
    return new Promise((resolve) => {
      const cleanup = () => {
        overlay.classList.remove("show");
        overlay.setAttribute("aria-hidden", "true");
        btnCancel.onclick = null;
        btnOk.onclick = null;
        overlay.onclick = null;
        document.removeEventListener("keydown", onKeyDown);
      };

      const onKeyDown = (e) => {
        if (e.key === "Escape") {
          cleanup();
          resolve(false);
        }
      };

      document.addEventListener("keydown", onKeyDown);

      // Click outside = cancel
      overlay.onclick = (e) => {
        if (e.target === overlay) {
          cleanup();
          resolve(false);
        }
      };

      btnCancel.onclick = () => {
        cleanup();
        resolve(false);
      };
      btnOk.onclick = () => {
        cleanup();
        resolve(true);
      };
    });
  }

  // ---------------- Common chain helpers ----------------

  function setStatusBar() {
    CIPNFT.renderWalletHeader();
  }

  async function ensureNetworkRead() {
    await CIPNFT.init();
    // Do NOT force injected wallet for reads.
    await CIPNFT.ensureReadProvider();
    await CIPNFT.getReadContract();
    setStatusBar();
  }

  async function connectWallet() {
    // Avoid prompting if already connected via bootstrap() + eth_accounts.
    if (CIPNFT.state && CIPNFT.state.address && CIPNFT.state.signer) {
      setStatusBar();
      return;
    }
    await CIPNFT.connectWallet();
    setStatusBar();
  }

  // ---------------- Key Login + Registration ----------------

  function encModeFromUI() {
    const v = $("encModeSelect")?.value || "classic";
    return (v === "pqc") ? CIPNFT.ENC_MODE_PQC : CIPNFT.ENC_MODE_CLASSIC;
  }

  function showKeyPanel() {
    const v = $("encModeSelect")?.value || "classic";
    // Drives nav key-login status indicator
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
    setText("tosVerPill", `TOS v${CIPNFT.state.tosVersionCurrent ?? "—"}`);
    setText("tosAcceptedPill", CIPNFT.state.tosAcceptedCurrent ? "ACCEPTED" : "NOT ACCEPTED");

    setText("flatFeeOut", `${CIPNFT.toEtherString(CIPNFT.state.flatMintFeeWei)} L1`);
    setText("perByteFeeOut", `${CIPNFT.toEtherString(CIPNFT.state.perByteFeeWei)} L1 / byte`);
  }

  function refreshClassicLocal() {
    const seed = CIPNFT.state.classicSeedHex || "";
    const pub = CIPNFT.state.classicEncPublicKey ? ethers.hexlify(CIPNFT.state.classicEncPublicKey) : "";
    const seedEl = $("seedHex");
    const pubEl = $("pubKeyHex");
    if (seedEl) seedEl.value = seed;
    if (pubEl) pubEl.value = pub;
  }

  async function refreshClassicOnchain() {
    const st = $("pubKeyStatus");
    if (!CIPNFT.state.address) {
      if (st) st.textContent = "—";
      return;
    }
    try {
      const on = await CIPNFT.getMyOnchainPubKey();
      const onStr = String(on);
      if (!on || onStr === ethers.ZeroHash) {
        if (st) st.textContent = "On-chain: NOT SET";
        return;
      }
      const localPub = CIPNFT.state.classicEncPublicKey ? ethers.hexlify(CIPNFT.state.classicEncPublicKey).toLowerCase() : null;
      const ok = localPub && (localPub === onStr.toLowerCase());
      if (st) st.textContent = ok ? "On-chain: SET (matches local)" : "On-chain: SET (does NOT match local)";
    } catch (e) {
      if (st) st.textContent = `On-chain: error (${CIPNFT.fmtErr(e)})`;
    }
  }

  async function refreshPqcLocal() {
    const seedEl = $("pqcSeedHex");
    const infoEl = $("pqcPubInfo");
    if (seedEl) seedEl.value = CIPNFT.state.pqcSeedHex || "";
    if (!infoEl) return;
    if (CIPNFT.state.pqcPubKeyBytes) {
      const h = ethers.keccak256(CIPNFT.state.pqcPubKeyBytes);
      infoEl.value = `len=${CIPNFT.state.pqcPubKeyBytes.length}, hash=${h}`;
    } else {
      infoEl.value = "not derived";
    }
  }

  async function refreshPqcOnchain() {
    const st = $("pqcKeyStatus");
    if (!CIPNFT.state.address) {
      if (st) st.textContent = "—";
      return;
    }
    try {
      const on = await CIPNFT.getMyOnchainPqcPubKey();
      if (!on || on.length === 0) {
        if (st) st.textContent = "On-chain: NOT SET";
        return;
      }
      const onHash = ethers.keccak256(on);
      const localHash = CIPNFT.state.pqcPubKeyBytes ? ethers.keccak256(CIPNFT.state.pqcPubKeyBytes) : null;
      const ok = localHash && (localHash.toLowerCase() === onHash.toLowerCase());
      if (st) st.textContent = ok ? "On-chain: SET (matches local)" : "On-chain: SET (does NOT match local)";
    } catch (e) {
      if (st) st.textContent = `On-chain: error (${CIPNFT.fmtErr(e)})`;
    }
  }

  async function refreshKeysUI() {
    refreshClassicLocal();
    await refreshClassicOnchain();
    await refreshPqcLocal();
    await refreshPqcOnchain();
    CIPNFT.renderWalletHeader();
  }

  async function doDeriveClassic() {
    try {
      await connectWallet();
      await CIPNFT.deriveKeyFromSignature();
      await refreshKeysUI();
      logLine("Classic key derived.");
    } catch (e) {
      logLine("Derive failed: " + CIPNFT.fmtErr(e));
      alert(CIPNFT.fmtErr(e));
    }
  }

  async function doImportClassic() {
    const seed = prompt("Paste Classic SEED_HEX (0x… 32 bytes):");
    if (!seed) return;
    try {
      CIPNFT.importSeed(seed.trim());
      await refreshKeysUI();
      logLine("Classic seed imported.");
    } catch (e) {
      logLine("Import failed: " + CIPNFT.fmtErr(e));
      alert(CIPNFT.fmtErr(e));
    }
  }

  function doExportClassic() {
    const seed = CIPNFT.state.classicSeedHex;
    if (!seed) {
      logLine("Nothing to export (no Classic seed).");
      return;
    }
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

  async function doRegisterClassic() {
    try {
      await connectWallet();
      const ok = await showConfirmModal({
        title: "Save your Seed before registering",
        messageHtml: `<b class="warn-strong">WARNING:</b> Your <b>Seed (private key)</b> is NOT stored on-chain and cannot be recovered.\n\nPlease save it now (export / password manager) before registering your pubkey on-chain.`,
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
      toast("Classic pubkey registered.");
    } catch (e) {
      logLine("Register failed: " + CIPNFT.fmtErr(e));
      alert(CIPNFT.fmtErr(e));
    }
  }

  async function doGeneratePqc() {
    try {
      await connectWallet();
      await CIPNFT.generatePqcKey();
      await refreshKeysUI();
      logLine("PQC key generated.");
    } catch (e) {
      logLine("Generate PQC failed: " + CIPNFT.fmtErr(e));
      alert(CIPNFT.fmtErr(e));
    }
  }

  async function doDerivePqc() {
    try {
      await connectWallet();
      await CIPNFT.derivePqcKeyFromSignature();
      await refreshKeysUI();
      logLine("PQC seed derived (signature)." );
    } catch (e) {
      logLine("Derive PQC failed: " + CIPNFT.fmtErr(e));
      alert(CIPNFT.fmtErr(e));
    }
  }

  async function doImportPqc() {
    const seed = prompt("Paste PQC_SEED_HEX (0x…):");
    if (!seed) return;
    try {
      await CIPNFT.importPqcSeed(seed.trim());
      await refreshKeysUI();
      logLine("PQC seed imported.");
    } catch (e) {
      logLine("Import PQC failed: " + CIPNFT.fmtErr(e));
      alert(CIPNFT.fmtErr(e));
    }
  }

  function doExportPqc() {
    const seed = CIPNFT.state.pqcSeedHex;
    if (!seed) {
      logLine("Nothing to export (no PQC seed)." );
      return;
    }
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

  async function doRegisterPqc() {
    try {
      await connectWallet();
      const ok = await showConfirmModal({
        title: "Save your Seed before registering",
        messageHtml: `<b class="warn-strong">WARNING:</b> Your <b>PQC Seed (private key)</b> is NOT stored on-chain and cannot be recovered.\n\nPlease save it now (export / password manager) before registering your PQC pubkey on-chain.`,
        okText: "I saved the key",
        cancelText: "Cancel"
      });
      if (!ok) {
        logLine("Key registration cancelled.");
        return;
      }
      const tx = await CIPNFT.registerPqcPubKey();
      await refreshKeysUI();
      logLine("Registered PQC pubkey. tx=" + tx);
      toast("PQC pubkey registered.");
    } catch (e) {
      logLine("Register PQC failed: " + CIPNFT.fmtErr(e));
      alert(CIPNFT.fmtErr(e));
    }
  }

  async function acceptTos() {
    try {
      await connectWallet();
      setText("tosAcceptedPill", "WAIT…");
      const tx = await CIPNFT.acceptCurrentTos();
      logLine("Accepted TOS. tx=" + tx);
      toast("Terms accepted.");
      await refreshFeesAndTos();
    } catch (e) {
      logLine("Accept TOS failed: " + CIPNFT.fmtErr(e));
      alert(CIPNFT.fmtErr(e));
      try { await refreshFeesAndTos(); } catch (_) {}
    }
  }

  // ---------------- View key (mint) ----------------

  function newViewKey() {
    const vk = CIPNFT.randomViewKeyText();
    const el = $("viewKeyOut");
    if (el) el.value = vk;
    logLine("New view key generated.");
  }

  async function copyViewKey() {
    try {
      const v = $("viewKeyOut")?.value || "";
      await navigator.clipboard.writeText(v);
      logLine("View key copied.");
      toast("View key copied.");
    } catch (e) {
      logLine("Copy failed: " + CIPNFT.fmtErr(e));
      alert(CIPNFT.fmtErr(e));
    }
  }

  function downloadViewKey() {
    const v = $("viewKeyOut")?.value || "";
    if (!v) {
      logLine("No view key to download.");
      return;
    }
    const text =
`CIPNFT View Key\n\n` +
`Contract: ${CIPNFT.state.contractAddress}\n` +
`Chain ID: ${CIPNFT.state.chainId}\n\n` +
`VIEW_KEY=${v}\n\n` +
`Keep this safe. Anyone with this can decrypt tokens that include viewWrap.`;
    CIPNFT.downloadText(`cipnft-view-key-${Date.now()}.txt`, text);
    logLine("View key downloaded.");
  }

  // ---------------- Mint / tokenize ----------------

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

  function refreshMintFeeEstimate() {
    const pt = $("metadataIn")?.value || "";
    const bytes = CIPNFT.bytesLenUtf8(pt);
    const est = CIPNFT.state.flatMintFeeWei + (CIPNFT.state.perByteFeeWei * BigInt(bytes));
    setText("plainBytesOut", `${bytes} bytes`);
    setText("mintFeeOut", `${CIPNFT.toEtherString(est)} L1`);
  }

  async function doMint() {
    try {
      await connectWallet();

      const title = String($("titleIn")?.value || "").trim();
      updateTitleHelp();
      if (!title) throw new Error("Title is required.");
      const w = countWords(title);
      const b = new TextEncoder().encode(title).length;
      if (w > 5) throw new Error("Title must be at most 5 words.");
      if (b > 80) throw new Error("Title too long (max 80 bytes)." );

      const plaintext = $("metadataIn")?.value || "";
      if (!plaintext) throw new Error("Plaintext is empty.");

      const useView = !!$("chkViewKey")?.checked;
      const vk = $("viewKeyOut")?.value || "";
      if (useView && vk.length < 16) throw new Error("View key is required (generate one)." );

      // User-requested hard warning gate.
      const ok = await showConfirmModal({
        title: "Save your keys before tokenizing",
        messageHtml:
          `<b class="warn-strong">WARNING:</b> Before you tokenize, you must save your <b>Seed (private key)</b> ` +
          `and (if enabled) the <b>View Key</b>.\n\n` +
          `If you lose these keys, decryption is permanently impossible.`,
        okText: "I saved keys",
        cancelText: "Cancel"
      });
      if (!ok) {
        setText("mintStatus", "Cancelled");
        logLine("Tokenization cancelled.");
        return;
      }

      const mode = encModeFromUI();
      setText("mintStatus", "Tokenizing…" );

      const res = await CIPNFT.mintEncrypted({
        title,
        plaintextUtf8: plaintext,
        enableViewKey: useView,
        viewKeyText: vk,
        encMode: mode
      });

      setText("mintStatus", res.tokenId != null ? `Tokenized token #${res.tokenId}` : "Tokenized (tokenId not found in receipt)" );
      logLine(`Tokenize tx=${res.txHash}`);
      if (res.tokenId != null) logLine(`TokenId=${res.tokenId}`);
      logLine(`Fee=${CIPNFT.toEtherString(res.feeWei)} L1, bytes=${res.plaintextBytes}`);
      toast(res.tokenId != null ? `Tokenized #${res.tokenId}` : "Tokenized." );

      // Convenience: auto-fill the token loader with the new tokenId.
      if (res.tokenId != null && $("tokenIdIn")) {
        $("tokenIdIn").value = String(res.tokenId);
      }
    } catch (e) {
      setText("mintStatus", "Tokenize failed");
      logLine("Tokenize failed: " + CIPNFT.fmtErr(e));
      alert(CIPNFT.fmtErr(e));
    }
  }

  // ---------------- Token loading / decrypt ----------------

  let currentToken = null; // token bundle
  let lastPlaintext = "";
  let cipherFullShown = false;

  function clearToken() {
    currentToken = null;
    lastPlaintext = "";

    setText("ownerOut", "—");
    setText("tosOut", "—");
    setText("listedOut", "—");
    setText("priceOut", "—");
    setText("cipherBytesOut", "—");
    setText("viewEnabledOut", "—");
    const prevEl = $("cipherPreviewOut");
    if (prevEl) {
      prevEl.textContent = "—";
      prevEl.dataset.fullHex = "";
    }
    const fullBox = $("cipherFullBox");
    if (fullBox) fullBox.style.display = "none";
    const fullOut = $("cipherFullOut");
    if (fullOut) fullOut.value = "";
    const b = $("btnToggleCipher");
    if (b) b.textContent = "LOAD FULL CIPHERTEXT";
    cipherFullShown = false;

    setText("tokenStatus", "—");
    setText("ownerDecryptStatus", "—");
    setText("viewDecryptStatus", "—");
    const pt = $("plainOut");
    if (pt) pt.value = "";
  }

  function toggleFullCiphertext() {
    const prevEl = $("cipherPreviewOut");
    const fullBox = $("cipherFullBox");
    const fullOut = $("cipherFullOut");
    const btn = $("btnToggleCipher");
    if (!prevEl || !fullBox || !fullOut || !btn) return;
    const fullHex = String(prevEl.dataset.fullHex || "");
    if (!fullHex) return;
    cipherFullShown = !cipherFullShown;
    if (cipherFullShown) {
      fullOut.value = fullHex;
      fullBox.style.display = "block";
      btn.textContent = "HIDE FULL CIPHERTEXT";
      fullBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
    } else {
      fullBox.style.display = "none";
      btn.textContent = "LOAD FULL CIPHERTEXT";
    }
  }

  async function loadToken() {
    const tokenIdRaw = String($("tokenIdIn")?.value || "").trim();
    if (!tokenIdRaw) throw new Error("Enter token id." );

    await ensureNetworkRead();
    setText("tokenStatus", "Loading…" );

    const tokenId = tokenIdRaw;
    const b = await CIPNFT.getTokenBundle(tokenId);
    currentToken = b;

    setText("ownerOut", CIPNFT.shortAddr(b.owner));
    setText("tosOut", String(b.tosVersion));
    setText("listedOut", b.open ? "OPEN" : "CLOSED");
    setText("priceOut", `${CIPNFT.toEtherString(b.priceWei)} ${CIPNFT.nativeSymbol()}`);
    setText("cipherBytesOut", `${b.metaCipherBytes.length} bytes`);
    setText("viewEnabledOut", b.viewWrapBytes.length ? "YES" : "NO");

    const prevEl = $("cipherPreviewOut");
    if (prevEl) {
      const fullHex = b.metaCipherHex;
      prevEl.dataset.fullHex = fullHex;
      prevEl.textContent = CIPNFT.cipherPreviewText(fullHex, 520);
    }

    setText("tokenStatus", `Loaded token #${b.tokenId} · MODE: ${Number(b.encMode) === CIPNFT.ENC_MODE_PQC ? "PQC" : "CLASSIC"}`);

    // If user arrived from a link, keep the query tokenId clean.
    try {
      const u = new URL(window.location.href);
      u.searchParams.set('tokenId', String(b.tokenId));
      window.history.replaceState({}, '', u.toString());
    } catch (_) {}

    toast(`Loaded token #${b.tokenId}`);
  }

  async function decryptAsOwner() {
    if (!currentToken) throw new Error("Load a token first.");
    await ensureNetworkRead();
    setText("ownerDecryptStatus", "Decrypting…" );

    const dek = await CIPNFT.decryptDEKAsOwner(currentToken.ownerEncDEKBytes, currentToken.encMode);
    CIPNFT.verifyDekHash(dek, currentToken.dekHash);
    const pt = CIPNFT.decryptMetaCipher(currentToken.metaCipherBytes, dek);
    const out = $("plainOut");
    if (out) out.value = pt;
    lastPlaintext = pt;
    setText("ownerDecryptStatus", "OK." );
    toast("Decrypted as owner.");
  }

  async function decryptWithViewKey() {
    if (!currentToken) throw new Error("Load a token first.");
    if (!currentToken.viewWrapBytes.length) throw new Error("Token has no view key enabled.");
    await ensureNetworkRead();
    const vk = String($("viewKeyIn")?.value || "").trim();
    if (!vk) throw new Error("Enter view key." );
    setText("viewDecryptStatus", "Decrypting…" );
    const dek = CIPNFT.decryptDEKWithViewKey(currentToken.viewWrapBytes, vk);
    CIPNFT.verifyDekHash(dek, currentToken.dekHash);
    const pt = CIPNFT.decryptMetaCipher(currentToken.metaCipherBytes, dek);
    const out = $("plainOut");
    if (out) out.value = pt;
    lastPlaintext = pt;
    setText("viewDecryptStatus", "OK." );
    toast("Decrypted with view key.");

    // Optional UX: save view key locally for this browser + token.
    try {
      const k = `CIPNFT_VIEWKEY_${CIPNFT.state.chainId}_${CIPNFT.state.contractAddress}_${currentToken.tokenId}`;
      localStorage.setItem(k, vk);
    } catch (_) {}
  }

  function downloadPlain() {
    if (!currentToken) throw new Error("Load a token first.");
    if (!lastPlaintext) throw new Error("Nothing to download." );
    const fname = `cipnft_token${currentToken.tokenId}_plaintext.json`;
    CIPNFT.downloadText(fname, lastPlaintext);
    toast("Downloaded plaintext." );
  }

  async function loadSavedViewKey() {
    if (!currentToken) throw new Error("Load a token first.");
    await ensureNetworkRead();
    const k = `CIPNFT_VIEWKEY_${CIPNFT.state.chainId}_${CIPNFT.state.contractAddress}_${currentToken.tokenId}`;
    const saved = localStorage.getItem(k);
    if (!saved) throw new Error("No saved view key found in this browser for this token." );
    const el = $("viewKeyIn");
    if (el) el.value = saved;
    toast("Loaded saved view key." );
  }

  // ---------------- My Vault ----------------

  let myTokens = []; // owned token summaries

  function clearMyTokens() {
    myTokens = [];
    const table = $("myTokensTable");
    if (table) table.innerHTML = "";
    setText("myTokensStatus", "—" );
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
      out.className = "";
      out.innerHTML = `<div class="mono" style="color: var(--text-muted);">No tokens found.</div>`;
      return;
    }

    out.className = "grid market";
    const sym = CIPNFT.nativeSymbol();

    out.innerHTML = rows.map(r => {
      const priceEth = esc(CIPNFT.toEtherString(r.priceWei));
      const listingPill = r.open ? `<span class="pill ok">OPEN</span>` : `<span class="pill">CLOSED</span>`;
      const erasePill = r.eraseActive ? `<span class="pill warn">ERASING</span>` : (r.eraseDone ? `<span class="pill warn">ERASED</span>` : `<span class="pill">IDLE</span>`);
      const modePill = (Number(r.encMode) === CIPNFT.ENC_MODE_PQC) ? `<span class="pill warn">PQC</span>` : `<span class="pill ok">CLASSIC</span>`;

      return `
        <div class="card" data-row-token="${esc(r.tokenId)}">
          <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:12px;">
            <div>
              <div class="mono">TOKEN #${esc(r.tokenId)} ${modePill}</div>
              <div style="margin-top: 8px; font-weight: 600;">${esc(r.title || "Untitled")}</div>
            </div>
            <div style="text-align:right;">
              <div class="mono" style="color: var(--text-muted); font-size:0.72rem;">LISTING</div>
              <div style="margin-top: 6px;">${listingPill}</div>
            </div>
          </div>

          <div class="mono cipher-preview" style="color: var(--text-muted); font-size:0.72rem; margin-top: 14px; word-break: break-all;">
            CIPHERTEXT (${esc(r.cipherLen || 0)} bytes, preview): ${esc(CIPNFT.cipherPreviewText(r.cipherPreviewHex, 260))}
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
            <button class="btn small" data-open="${esc(r.tokenId)}">LOAD</button>
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
          const inp = $("tokenIdIn");
          if (inp) inp.value = tokenId;
          await loadToken();
          inp?.scrollIntoView({ behavior: 'smooth', block: 'center' });
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
          const next = prompt('Set public title (visible to anyone, max 5 words):', cur);
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
          await refreshManagedToken(tokenId, { eraseDone: myTokens.find(x => x.tokenId === tokenId)?.eraseDone });
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
          await refreshManagedToken(tokenId, { eraseDone: myTokens.find(x => x.tokenId === tokenId)?.eraseDone });
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
          const maxWords = Math.max(1, Number($("eraseMaxWords")?.value || 600));
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
          const ok = window.confirm(`Burn token #${tokenId}?\n\nThis destroys the NFT.\nRecommended: ERASE encrypted data first.\n\nContinue?`);
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

    // If no longer owned, drop it.
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
      title: String(card.title || ""),
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

    if (i >= 0) myTokens[i] = row; else myTokens.push(row);
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
      if (outStatus) outStatus.textContent = 'Owner index not available (or RPC failed).';
      throw new Error('Owner token index not available on this deployment.');
    }

    if (!tokenIds.length) {
      myTokens = [];
      renderMyTokens([]);
      if (outStatus) outStatus.textContent = 'No tokens owned.';
      return;
    }

    const concurrency = 10;
    let idx = 0;
    const rows = new Array(tokenIds.length);
    const workers = new Array(Math.min(concurrency, tokenIds.length)).fill(0).map(async () => {
      while (idx < tokenIds.length) {
        const i = idx++;
        const tokenId = tokenIds[i];
        try {
          const owner = String(await c.ownerOf(tokenId));
          if (owner.toLowerCase() !== addrLower) { rows[i] = null; continue; }
          const card = await CIPNFT.getTokenCard(tokenId);
          let erase = { active: false, field: 0, nextWord: 0 };
          try { erase = await CIPNFT.getEraseState(tokenId); } catch (_) {}
          rows[i] = {
            tokenId: String(tokenId),
            title: String(card.title || ""),
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

  // ---------------- Incoming offers (seller) ----------------

  function selectedVkMode() {
    const el = document.querySelector('input[name="vkMode"]:checked');
    return el ? el.value : 'clear';
  }

  function updateVkModeUI() {
    const m = selectedVkMode();
    const box = $("newViewKeyBox");
    if (!box) return;
    box.style.display = (m === 'new') ? 'block' : 'none';
    if (m === 'new') {
      const out = $("newViewKeyOut");
      if (out && !out.value) out.value = CIPNFT.randomViewKeyText();
    }
  }

  async function copyNewViewKey() {
    const v = $("newViewKeyOut")?.value;
    if (!v) return;
    await navigator.clipboard.writeText(v);
    toast('New view key copied.');
  }

  function downloadNewViewKey() {
    const v = $("newViewKeyOut")?.value;
    if (!v) throw new Error('No new view key.');
    const tokenId = currentToken ? currentToken.tokenId : '';
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

  function renderIncomingOffers(rows) {
    const out = $("incomingOffersTable");
    if (!out) return;

    if (!rows.length) {
      out.innerHTML = `<div class="mono" style="color: var(--text-muted);">No active incoming offers found.</div>`;
      return;
    }

    const head = `
      <div class="table-row" style="font-weight:600; grid-template-columns: 0.75fr 1.35fr 0.8fr 1.1fr 0.9fr auto;">
        <div>TOKEN</div>
        <div>BUYER</div>
        <div>AMOUNT</div>
        <div>EXPIRY</div>
        <div>STATUS</div>
        <div></div>
      </div>`;

    const body = rows.map(r => {
      const exp = new Date(r.expiry * 1000).toISOString().slice(0,19) + 'Z';
      return `
        <div class="table-row" style="grid-template-columns: 0.75fr 1.35fr 0.8fr 1.1fr 0.9fr auto;" data-row="${esc(r.tokenId)}|${esc(r.buyer)}">
          <div class="mono">#${esc(r.tokenId)}</div>
          <div class="mono">${esc(r.buyer)}</div>
          <div class="mono">${esc(CIPNFT.toEtherString(r.amountWei))} ${esc(CIPNFT.nativeSymbol())}</div>
          <div class="mono">${esc(exp)}</div>
          <div class="mono">${esc(r.status)}</div>
          <div class="actions-inline">
            <button class="btn small" data-load-token="${esc(r.tokenId)}">LOAD</button>
            <button class="btn small" data-deliver="${esc(r.tokenId)}|${esc(r.buyer)}">${r.status.startsWith('DELIVERED') ? 'RE-DELIVER' : 'DELIVER'}</button>
            ${r.status.startsWith('DELIVERED') ? `<button class="btn small" data-revoke="${esc(r.tokenId)}|${esc(r.buyer)}">REVOKE</button>` : ''}
          </div>
        </div>`;
    }).join('');

    out.innerHTML = head + body;

    out.querySelectorAll('button[data-load-token]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const tokenId = btn.getAttribute('data-load-token');
        try {
          const inp = $("tokenIdIn");
          if (inp) inp.value = tokenId;
          await loadToken();
          inp?.scrollIntoView({ behavior: 'smooth', block: 'center' });
        } catch (e) {
          alert(CIPNFT.fmtErr(e));
        }
      });
    });

    out.querySelectorAll('button[data-deliver]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const pair = btn.getAttribute('data-deliver');
        const [tokenId, buyer] = String(pair || '').split('|');
        try {
          await connectWallet();
          const mode = selectedVkMode();
          const keepViewWrap = (mode === 'keep');
          const newViewKeyText = (mode === 'new') ? ($("newViewKeyOut")?.value || '') : '';
          setText('incomingOffersStatus', `Delivering token #${tokenId} to ${buyer}…`);
          const txHash = await CIPNFT.deliverOffer({ tokenId, buyerAddr: buyer, keepViewWrap, newViewKeyText });
          toast('Offer delivered. Buyer can verify & finalize.');
          setText('incomingOffersStatus', `Delivered: ${txHash}`);
          await loadIncomingOffers();
        } catch (e) {
          setText('incomingOffersStatus', '—');
          alert(CIPNFT.fmtErr(e));
        }
      });
    });

    out.querySelectorAll('button[data-revoke]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const pair = btn.getAttribute('data-revoke');
        const [tokenId, buyer] = String(pair || '').split('|');
        try {
          await connectWallet();
          setText('incomingOffersStatus', `Revoking delivery for #${tokenId}…`);
          const txHash = await CIPNFT.revokeDelivery(tokenId, buyer);
          toast('Delivery revoked.');
          setText('incomingOffersStatus', `Revoked: ${txHash}`);
          await loadIncomingOffers();
        } catch (e) {
          setText('incomingOffersStatus', '—');
          alert(CIPNFT.fmtErr(e));
        }
      });
    });
  }

  async function loadIncomingOffers() {
    if (!CIPNFT.state.address) {
      setText('incomingOffersStatus', 'Connect wallet to load incoming offers.');
      const out = $("incomingOffersTable");
      if (out) out.innerHTML = '';
      return;
    }

    await ensureNetworkRead();
    setText('incomingOffersStatus', 'Scanning offers for all tokens you own…');

    const c = await CIPNFT.getReadContract();
    const addr = CIPNFT.state.address;

    // Gather owned tokens via state index.
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
      setText('incomingOffersStatus', 'Owner index not available (or RPC failed).');
      throw e;
    }

    if (!tokenIds.length) {
      renderIncomingOffers([]);
      setText('incomingOffersStatus', 'No tokens owned.' );
      return;
    }

    const now = CIPNFT.nowSec();
    const rows = [];

    // Concurrency-limited token loop (keeps the UI responsive)
    const concurrency = 6;
    let idx = 0;
    const workers = new Array(Math.min(concurrency, tokenIds.length)).fill(0).map(async () => {
      while (idx < tokenIds.length) {
        const tokenId = tokenIds[idx++];
        let cursor = 0;
        const pageSize = 50;
        let guard = 0;
        while (guard < 40) {
          const { rows: page, newCursor } = await CIPNFT.getOffersForToken(tokenId, cursor, pageSize);
          if (!page || page.length === 0) break;
          for (const r of page) {
            if (!r || !r.expiry) continue;
            const active = r.expiry > now;
            if (!active) continue;
            const delivered = (r.deliveredAt && r.deliveredAt > 0);
            rows.push({
              tokenId: tokenId,
              buyer: r.buyer,
              amountWei: r.amountWei,
              expiry: r.expiry,
              status: delivered ? 'DELIVERED' : 'ACTIVE'
            });
          }
          if (newCursor === cursor) break;
          cursor = newCursor;
          if (page.length < pageSize) break;
          guard++;
        }
      }
    });
    await Promise.all(workers);

    rows.sort((a,b) => b.expiry - a.expiry);
    renderIncomingOffers(rows);

    const activeN = rows.filter(r => r.status === 'ACTIVE').length;
    const deliveredN = rows.filter(r => r.status === 'DELIVERED').length;
    setText('incomingOffersStatus', `Incoming offers loaded. Active: ${activeN}. Delivered: ${deliveredN}.`);
  }

  function clearIncomingOffers() {
    setText('incomingOffersStatus', '—');
    const out = $("incomingOffersTable");
    if (out) out.innerHTML = '';
  }

  // ---------------- My Offers (buyer) ----------------

  function renderMyOffers(rows) {
    const out = $("myOffersTable");
    if (!out) return;

    if (!rows.length) {
      out.innerHTML = `<div class="mono" style="color: var(--text-muted);">No active offers found.</div>`;
      return;
    }

    const head = `
      <div class="table-row" style="font-weight:600;">
        <div>TOKEN</div>
        <div>AMOUNT</div>
        <div>EXPIRY</div>
        <div>STATUS</div>
        <div></div>
      </div>`;

    const body = rows.map(r => {
      const exp = new Date(r.expiry * 1000).toISOString().slice(0,19) + 'Z';
      return `
        <div class="table-row">
          <div class="mono">#${esc(r.tokenId)}</div>
          <div class="mono">${esc(CIPNFT.toEtherString(r.amountWei))} ${esc(CIPNFT.nativeSymbol())}</div>
          <div class="mono">${esc(exp)}</div>
          <div class="mono">${esc(r.status)}</div>
          <div class="actions-inline">
            <button class="btn small" data-open-offer="${esc(r.tokenId)}">LOAD</button>
            ${r.status.startsWith('DELIVERED') ? `<button class="btn small requires-wallet" data-finalize="${esc(r.tokenId)}">VERIFY & FINALIZE</button>` : ''}
            <button class="btn small requires-wallet" data-cancel="${esc(r.tokenId)}">CANCEL</button>
          </div>
        </div>
      `;
    }).join('');

    out.innerHTML = head + body;

    out.querySelectorAll('button[data-open-offer]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const tokenId = btn.getAttribute('data-open-offer');
        try {
          const inp = $("tokenIdIn");
          if (inp) inp.value = tokenId;
          await loadToken();
          inp?.scrollIntoView({ behavior: 'smooth', block: 'center' });
        } catch (e) {
          alert(CIPNFT.fmtErr(e));
        }
      });
    });

    out.querySelectorAll('button[data-cancel]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const tokenId = btn.getAttribute('data-cancel');
        try {
          await connectWallet();
          await CIPNFT.cancelOffer(tokenId);
          toast('Offer cancelled.');
          await loadMyOffers();
        } catch (e) {
          alert(CIPNFT.fmtErr(e));
        }
      });
    });

    out.querySelectorAll('button[data-finalize]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const tokenId = btn.getAttribute('data-finalize');
        try {
          await connectWallet();
          setText('myOffersStatus', 'Verifying delivery & finalizing…');
          const txHash = await CIPNFT.finalizeOffer(tokenId);
          toast('Finalized. NFT transferred to you.');
          setText('myOffersStatus', `Finalized: ${txHash}`);
          await loadMyOffers();
        } catch (e) {
          setText('myOffersStatus', '—');
          alert(CIPNFT.fmtErr(e));
        }
      });
    });
  }

  async function loadMyOffers() {
    const out = $("myOffersTable");
    if (!CIPNFT.state.address) {
      setText('myOffersStatus', 'Connect wallet to load your offers.');
      if (out) out.innerHTML = '';
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
    // Hide expired by default
    const filtered = rows.filter(r => !r.status.startsWith('EXPIRED'));
    renderMyOffers(filtered);
    const activeN = filtered.filter(r => r.status.startsWith('ACTIVE')).length;
    const deliveredN = filtered.filter(r => r.status.startsWith('DELIVERED')).length;
    setText('myOffersStatus', `Offers loaded from state. Active: ${activeN}. Delivered: ${deliveredN}.`);
  }

  function clearMyOffers() {
    setText('myOffersStatus', '—');
    const out = $("myOffersTable");
    if (out) out.innerHTML = '';
  }

  // ---------------- Init / bind ----------------

  function parseQueryTokenId() {
    try {
      const u = new URL(window.location.href);
      return u.searchParams.get('tokenId');
    } catch (_) {
      return null;
    }
  }

  async function init() {
    // Bootstrap restores local keys + non-interactive wallet session if present.
    await CIPNFT.bootstrap();
    setStatusBar();

    // UI text
    try {
      setText('maxPlainOut', `${CIPNFT.MAX_PLAINTEXT} bytes`);
    } catch (_) {}

    // Default key panel (respect saved preference)
    const pref = (CIPNFT.state.preferredEncMode === 'pqc') ? 'pqc' : 'classic';
    const sel = $("encModeSelect");
    if (sel) sel.value = pref;
    showKeyPanel();

    // Initial fee/terms load (read-only) — don't break page load.
    try { await refreshFeesAndTos(); } catch (e) {
      setText('flatFeeOut', '—');
      setText('perByteFeeOut', '—');
      setText('tosVerPill', 'TOS v—');
      setText('tosAcceptedPill', 'NOT CONNECTED');
      logLine('Init: could not read on-chain Terms/Fees. ' + CIPNFT.fmtErr(e));
    }

    // Initial key status
    try { await refreshKeysUI(); } catch (e) { logLine('Init: key UI refresh warning. ' + CIPNFT.fmtErr(e)); }

    // Initial fee estimate
    try { updateTitleHelp(); } catch (_) {}
    try { refreshMintFeeEstimate(); } catch (_) {}

    // Bind: wallet connect
    $("btnConnect")?.addEventListener('click', async () => {
      try {
        await connectWallet();
        logLine('Wallet connected.');
        try { await refreshFeesAndTos(); } catch (_) {}
        try { await refreshKeysUI(); } catch (_) {}
        try { refreshMintFeeEstimate(); } catch (_) {}

        // Auto-load offers/tokens if the user is connected already.
        try { await syncMyTokensState(); } catch (_) {}
        try { await loadIncomingOffers(); } catch (_) {}
        try { await loadMyOffers(); } catch (_) {}
      } catch (e) {
        alert(CIPNFT.fmtErr(e));
      }
    });

    // Bind: key panel
    $("encModeSelect")?.addEventListener('change', showKeyPanel);

    // Bind: terms
    $("btnAcceptTos")?.addEventListener('click', acceptTos);

    // Bind: classic keys
    $("btnDerive")?.addEventListener('click', doDeriveClassic);
    $("btnImportSeed")?.addEventListener('click', doImportClassic);
    $("btnExportSeed")?.addEventListener('click', () => { try { doExportClassic(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
    $("btnClearSeed")?.addEventListener('click', async () => { CIPNFT.clearSeed(); await refreshKeysUI(); logLine('Classic seed cleared.'); });
    $("btnRegisterPubKey")?.addEventListener('click', doRegisterClassic);

    // Bind: pqc keys
    $("btnGenPqcKey")?.addEventListener('click', doGeneratePqc);
    $("btnDerivePqcKey")?.addEventListener('click', doDerivePqc);
    $("btnImportPqcSeed")?.addEventListener('click', doImportPqc);
    $("btnExportPqcSeed")?.addEventListener('click', () => { try { doExportPqc(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
    $("btnClearPqcSeed")?.addEventListener('click', async () => { CIPNFT.clearPqcSeed(); await refreshKeysUI(); logLine('PQC seed cleared.'); });
    $("btnRegisterPqcPubKey")?.addEventListener('click', doRegisterPqc);

    // Bind: view key (mint)
    $("btnNewViewKey")?.addEventListener('click', newViewKey);
    $("btnCopyViewKey")?.addEventListener('click', copyViewKey);
    $("btnDownloadViewKey")?.addEventListener('click', downloadViewKey);

    // Bind: mint
    $("titleIn")?.addEventListener('input', updateTitleHelp);
    $("metadataIn")?.addEventListener('input', refreshMintFeeEstimate);
    $("btnMint")?.addEventListener('click', doMint);

    // Bind: token load
    $("btnLoadToken")?.addEventListener('click', async () => { try { await loadToken(); } catch (e) { alert(CIPNFT.fmtErr(e)); setText('tokenStatus', '—'); } });
    $("btnClearToken")?.addEventListener('click', clearToken);
    $("btnToggleCipher")?.addEventListener('click', toggleFullCiphertext);

    // Bind: decrypt
    $("btnDecryptOwner")?.addEventListener('click', async () => { try { await connectWallet(); await decryptAsOwner(); } catch (e) { setText('ownerDecryptStatus', '—'); alert(CIPNFT.fmtErr(e)); } });
    $("btnDecryptViewKey")?.addEventListener('click', async () => { try { await decryptWithViewKey(); } catch (e) { setText('viewDecryptStatus', '—'); alert(CIPNFT.fmtErr(e)); } });
    $("btnLoadSavedViewKey")?.addEventListener('click', async () => { try { await loadSavedViewKey(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
    $("btnDownloadPlain")?.addEventListener('click', () => { try { downloadPlain(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });

    // Bind: vault
    $("btnScanMyTokens")?.addEventListener('click', async () => { try { await syncMyTokensState(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
    $("btnClearMyTokens")?.addEventListener('click', clearMyTokens);

    // Bind: incoming offers
    document.querySelectorAll('input[name="vkMode"]').forEach(r => r.addEventListener('change', updateVkModeUI));
    updateVkModeUI();
    $("btnGenNewViewKey")?.addEventListener('click', () => { const el = $("newViewKeyOut"); if (el) el.value = CIPNFT.randomViewKeyText(); toast('New view key generated.'); });
    $("btnCopyNewViewKey")?.addEventListener('click', async () => { try { await copyNewViewKey(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
    $("btnDownloadNewViewKey")?.addEventListener('click', () => { try { downloadNewViewKey(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });

    $("btnLoadIncomingOffers")?.addEventListener('click', async () => { try { await loadIncomingOffers(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
    $("btnClearIncomingOffers")?.addEventListener('click', clearIncomingOffers);

    // Bind: my offers
    $("btnLoadMyOffers")?.addEventListener('click', async () => { try { await loadMyOffers(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
    $("btnClearMyOffers")?.addEventListener('click', clearMyOffers);

    // If user arrived with a tokenId= query, load it immediately (read-only).
    const q = parseQueryTokenId();
    if (q && $("tokenIdIn")) {
      $("tokenIdIn").value = q;
      try { await loadToken(); } catch (_) {}
    }

    // Auto-load if already connected (restored session)
    if (CIPNFT.state.address) {
      try { await refreshKeysUI(); } catch (_) {}
      try { await syncMyTokensState(); } catch (_) {}
      try { await loadIncomingOffers(); } catch (_) {}
      try { await loadMyOffers(); } catch (_) {}
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    init().catch(e => alert(CIPNFT.fmtErr(e)));
  });
})();
