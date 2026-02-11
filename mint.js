/* Mint page logic (supports Classic + PQC envelope modes) */

(async function () {
  const $ = (id) => document.getElementById(id);


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


  function setText(id, txt) {
    const el = $(id);
    if (el) el.textContent = txt;
  }

  function logLine(msg) {
    const out = $("consoleOut");
    if (!out) return;
    out.textContent = (out.textContent ? out.textContent + "\n" : "") + msg;
    out.scrollTop = out.scrollHeight;
  }

  function encModeFromUI() {
    const v = $("encModeSelect")?.value || "classic";
    return (v === "pqc") ? CIPNFT.ENC_MODE_PQC : CIPNFT.ENC_MODE_CLASSIC;
  }

  function showKeyPanel() {
    const v = $("encModeSelect")?.value || "classic";
    // This drives the global "key login status" indicator in the nav.
    CIPNFT.setPreferredEncMode(v === "pqc" ? "pqc" : "classic");
    $("classicKeyPanel").style.display = (v === "classic") ? "" : "none";
    $("pqcKeyPanel").style.display = (v === "pqc") ? "" : "none";

    const titleEl = $("keyCardTitle");
    if (titleEl) {
      titleEl.textContent = (v === "pqc")
        ? "Quantum-resistant Encryption Key Registration (Owner Identity)"
        : "Classic Encryption Key Registration (Owner Identity)";
    }

    // Key mode switch can change which local login is relevant.
    CIPNFT.renderWalletHeader();
  }

  async function refreshHeader() {
    // Common nav + header elements (connect button, key-login status, chain warnings)
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
    $("seedHex").value = seed;
    $("pubKeyHex").value = pub;
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
      setText("pubKeyStatus", ok ? "On-chain: SET (matches local)" : `On-chain: SET (does NOT match local)`);
    } catch (e) {
      setText("pubKeyStatus", `On-chain: error (${CIPNFT.fmtErr(e)})`);
    }
  }

  async function refreshPqcLocal() {
    $("pqcSeedHex").value = CIPNFT.state.pqcSeedHex || "";
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
      setText("pqcKeyStatus", ok ? "On-chain: SET (matches local)" : `On-chain: SET (does NOT match local)`);
    } catch (e) {
      setText("pqcKeyStatus", `On-chain: error (${CIPNFT.fmtErr(e)})`);
    }
  }

  async function refreshKeysUI() {
    refreshClassicLocal();
    await refreshClassicOnchain();
    await refreshPqcLocal();
    await refreshPqcOnchain();
    // Updates the global key-login indicator in the nav.
    CIPNFT.renderWalletHeader();
  }

  function refreshMintFeeEstimate() {
  const pt = $("metadataIn").value || "";
  const bytes = CIPNFT.bytesLenUtf8(pt);
  const est = CIPNFT.state.flatMintFeeWei + (CIPNFT.state.perByteFeeWei * BigInt(bytes));
  setText("plainBytesOut", `${bytes} bytes`);
  setText("mintFeeOut", `${CIPNFT.toEtherString(est)} L1`);
}

  async function connect() {
    try {
      await CIPNFT.connectWallet();
      await refreshHeader();
  updateTitleHelp();
      logLine("Wallet connected.");

      try { await refreshFeesAndTos(); }
      catch (e) { logLine("On-chain Terms/Fees not available: " + CIPNFT.fmtErr(e)); }

      try { await refreshKeysUI(); }
      catch (e) { logLine("Key status refresh failed: " + CIPNFT.fmtErr(e)); }

      try { refreshMintFeeEstimate(); } catch (_) {}
    } catch (e) {
      logLine("Connect failed: " + CIPNFT.fmtErr(e));
    }
  }

  // ----- Classic actions -----
  async function doDeriveClassic() {
    try {
      await CIPNFT.deriveKeyFromSignature();
      await refreshKeysUI();
      logLine("Classic key derived.");
    } catch (e) {
      logLine("Derive failed: " + CIPNFT.fmtErr(e));
    }
  }

  function doExportClassic() {
    const seed = CIPNFT.state.classicSeedHex;
    if (!seed) return logLine("Nothing to export (no Classic seed).");
    const text =
`CIPNFT Classic Seed Export

Contract: ${CIPNFT.state.contractAddress}
Chain ID: ${CIPNFT.state.chainId}
Wallet: ${CIPNFT.state.address}

SEED_HEX=${seed}

Keep this secret.`;
    CIPNFT.downloadText(`cipnft-classic-seed-${(CIPNFT.state.address||"").slice(0,6)}.txt`, text);
    logLine("Classic seed exported.");
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
    }
  }

  async function doRegisterClassic() {
    try {
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
    } catch (e) {
      logLine("Register failed: " + CIPNFT.fmtErr(e));
    }
  }

  // ----- PQC actions -----
  async function doGeneratePqc() {
    try {
      await CIPNFT.generatePqcKey();
      await refreshKeysUI();
      logLine("PQC key generated.");
    } catch (e) {
      logLine("Generate PQC failed: " + CIPNFT.fmtErr(e));
    }
  }

  async function doDerivePqc() {
    try {
      await CIPNFT.derivePqcKeyFromSignature();
      await refreshKeysUI();
      logLine("PQC seed derived (signature).");
    } catch (e) {
      logLine("Derive PQC failed: " + CIPNFT.fmtErr(e));
    }
  }

  function doExportPqc() {
    const seed = CIPNFT.state.pqcSeedHex;
    if (!seed) return logLine("Nothing to export (no PQC seed).");
    const text =
`CIPNFT PQC Seed Export (ML-KEM-768)

Contract: ${CIPNFT.state.contractAddress}
Chain ID: ${CIPNFT.state.chainId}
Wallet: ${CIPNFT.state.address}

PQC_SEED_HEX=${seed}

Keep this secret.`;
    CIPNFT.downloadText(`cipnft-pqc-seed-${(CIPNFT.state.address||"").slice(0,6)}.txt`, text);
    logLine("PQC seed exported.");
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
    }
  }

  async function doRegisterPqc() {
    try {
      const ok = await CIPNFT.confirmModal({
        title: "SAVE YOUR SEED",
        messageHtml: `
          <div class="advanced-warn mono" style="font-weight:700;">
            <b>WARNING:</b> BEFORE REGISTERING, YOU MUST SAVE YOUR <b>PQC SEED / PRIVATE KEY</b>.
            IF YOU LOSE IT, YOU CAN NOT DECRYPT PQC TOKENS. CIPNFT CAN NOT RECOVER LOST KEYS.
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
      const tx = await CIPNFT.registerPqcPubKey();
      await refreshKeysUI();
      logLine("Registered PQC pubkey. tx=" + tx);
    } catch (e) {
      logLine("Register PQC failed: " + CIPNFT.fmtErr(e));
    }
  }

  // ----- View key -----
  function newViewKey() {
    const vk = CIPNFT.randomViewKeyText();
    $("viewKeyOut").value = vk;
    logLine("New view key generated.");
  }

  async function copyViewKey() {
    try {
      const v = $("viewKeyOut").value || "";
      await navigator.clipboard.writeText(v);
      logLine("View key copied.");
    } catch (e) {
      logLine("Copy failed: " + CIPNFT.fmtErr(e));
    }
  }

  function downloadViewKey() {
    const v = $("viewKeyOut").value || "";
    if (!v) return logLine("No view key to download.");
    const text =
`CIPNFT View Key

Contract: ${CIPNFT.state.contractAddress}
Chain ID: ${CIPNFT.state.chainId}

VIEW_KEY=${v}

Keep this safe. Anyone with this can decrypt tokens that include viewWrap.`;
    CIPNFT.downloadText(`cipnft-view-key-${Date.now()}.txt`, text);
    logLine("View key downloaded.");
  }

  // ----- Tokenize -----
  async function doMint() {
    try {
      if (!CIPNFT.state.address) throw new Error("Connect wallet first.");

      // Explicit acknowledgement: keys are not recoverable.
      const ok = await CIPNFT.confirmModal({
        title: "SAVE YOUR KEYS",
        messageHtml: `
          <div class="advanced-warn mono" style="font-weight:700;">
            <b>WARNING:</b> BEFORE TOKENIZING, SAVE YOUR <b>SEED / PRIVATE KEY</b> AND YOUR <b>VIEW KEY</b> (IF ENABLED).
            IF YOU LOSE THEM, YOU CAN NOT DECRYPT THIS NFT. THERE IS NO RECOVERY.
          </div>
          <div style="margin-top:12px; color: var(--text-muted);">
            The view key is never stored on-chain. If view access is enabled, anyone with the view key can decrypt.
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

      const title = String($("titleIn").value || "").trim();
      updateTitleHelp();
      if (!title) throw new Error("Title is required.");
      const w = countWords(title);
      const b = new TextEncoder().encode(title).length;
      if (w > 5) throw new Error("Title must be at most 5 words.");
      if (b > 80) throw new Error("Title too long (max 80 bytes).");

      const plaintext = $("metadataIn").value || "";
      if (!plaintext) throw new Error("Plaintext is empty.");

      const useView = $("chkViewKey").checked;
      const vk = $("viewKeyOut").value || "";
      if (useView && vk.length < 16) throw new Error("View key is required (generate one).");

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
      logLine(`Fee=${CIPNFT.toEtherString(res.feeWei)} L1, bytes=${res.plaintextBytes}`);
    } catch (e) {
      setText("mintStatus", "Tokenize failed");
      logLine("Tokenize failed: " + CIPNFT.fmtErr(e));
    }
  }

  async function acceptTos() {
    try {
      setText("tosAcceptedPill", "WAIT…");
      const tx = await CIPNFT.acceptCurrentTos();
      logLine("Accepted TOS. tx=" + tx);
      await refreshFeesAndTos();
    } catch (e) {
      logLine("Accept TOS failed: " + CIPNFT.fmtErr(e));
      await refreshFeesAndTos();
    }
  }

  // ---- Bind ----
  // Init + restore prior wallet session (no popup)
  await CIPNFT.bootstrap();
  showKeyPanel();

  $("encModeSelect")?.addEventListener("change", () => {
    showKeyPanel();
    // no-op
  });

  $("btnConnect")?.addEventListener("click", connect);
  $("btnAcceptTos")?.addEventListener("click", acceptTos);

  // classic
  $("btnDerive")?.addEventListener("click", doDeriveClassic);
  $("btnExportSeed")?.addEventListener("click", doExportClassic);
  $("btnImportSeed")?.addEventListener("click", doImportClassic);
  $("btnClearSeed")?.addEventListener("click", () => { CIPNFT.clearSeed(); refreshKeysUI(); logLine("Classic seed cleared."); });
  $("btnRegisterPubKey")?.addEventListener("click", doRegisterClassic);

  // pqc
  $("btnGenPqcKey")?.addEventListener("click", doGeneratePqc);
  $("btnDerivePqcKey")?.addEventListener("click", doDerivePqc);
  $("btnExportPqcSeed")?.addEventListener("click", doExportPqc);
  $("btnImportPqcSeed")?.addEventListener("click", doImportPqc);
  $("btnClearPqcSeed")?.addEventListener("click", () => { CIPNFT.clearPqcSeed(); refreshKeysUI(); logLine("PQC seed cleared."); });
  $("btnRegisterPqcPubKey")?.addEventListener("click", doRegisterPqc);

  // view key
  $("btnNewViewKey")?.addEventListener("click", newViewKey);
  $("btnCopyViewKey")?.addEventListener("click", copyViewKey);
  $("btnDownloadViewKey")?.addEventListener("click", downloadViewKey);

  // mint
  $("titleIn")?.addEventListener("input", () => { updateTitleHelp(); });
  $("metadataIn")?.addEventListener("input", refreshMintFeeEstimate);
  $("chkViewKey")?.addEventListener("change", () => {});
  $("btnMint")?.addEventListener("click", doMint);

  // initial UI refresh (not connected)
  await refreshHeader();
  try {
    await refreshFeesAndTos();
  } catch (e) {
    // Do not break page load. Most common causes:
    // - wrong CONTRACT_ADDRESS / wrong chain
    // - wallet provider injection conflict
    setText("mintStatus", "Init warning");
    logLine("Init: could not read on-chain Terms/Fees. " + CIPNFT.fmtErr(e));
    // keep estimate placeholders
    setText("flatFeeOut", "—");
    setText("perByteFeeOut", "—");
    setText("tosVerPill", "TOS v—");
    setText("tosAcceptedPill", "NOT CONNECTED");
  }
  try {
    await refreshKeysUI();
  } catch (e) {
    logLine("Init: key UI refresh warning. " + CIPNFT.fmtErr(e));
  }
  try {
    refreshMintFeeEstimate();
  } catch (_) {}
})();
