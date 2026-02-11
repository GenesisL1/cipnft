/* CIPNFT — Decrypt & View page */

const $ = (id) => document.getElementById(id);

let currentToken = null; // token bundle
let lastPlaintext = "";

let cipherFullShown = false;

let myTokens = []; // owned token summaries for management UI

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'}[c]));
}

function toast(msg) {
  const el = $("toast");
  if (!el) return;
  el.textContent = msg;
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 3200);
}

function clearMyTokens() {
  myTokens = [];
  const table = $("myTokensTable");
  if (table) table.innerHTML = "";
  const st = $("myTokensStatus");
  if (st) st.textContent = "—";
}

function eraseStatusText(r) {
  if (r.eraseActive) {
    return `ERASING field ${r.eraseField} word ${r.eraseNextWord}`;
  }
  if (r.eraseDone) return `ERASED`;
  return `idle`;
}

function renderMyTokens(rows) {
  const out = $("myTokensTable");
  if (!out) return;
  if (!rows.length) {
    out.className = "";
    out.innerHTML = `<div class="mono" style="color: var(--text-muted);">No tokens found in scan window.</div>`;
    return;
  }

  out.className = "grid market";
  const sym = CIPNFT.nativeSymbol();

  out.innerHTML = rows.map(r => {
    const priceEth = esc(CIPNFT.toEtherString(r.priceWei));
    const listingPill = r.open
      ? `<span class="pill ok">OPEN</span>`
      : `<span class="pill">CLOSED</span>`;
    const erasePill = r.eraseActive
      ? `<span class="pill warn">ERASING</span>`
      : (r.eraseDone ? `<span class="pill warn">ERASED</span>` : `<span class="pill">IDLE</span>`);

    return `
      <div class="card" data-row-token="${esc(r.tokenId)}">
        <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:12px;">
          <div>
            <div class="mono">TOKEN #${esc(r.tokenId)}</div>
            <div style="margin-top: 8px; font-weight: 600;">${esc(r.title || "Untitled")}</div>
          </div>
          <div style="text-align:right;">
            <div class="mono" style="color: var(--text-muted); font-size:0.72rem;">LISTING</div>
            <div style="margin-top: 6px;">${listingPill}</div>
          </div>
        </div>

        <div class="mono cipher-preview" style="color: var(--text-muted); font-size:0.72rem; margin-top: 14px; word-break: break-all;">
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

  // Wire row actions
  out.querySelectorAll('button[data-open]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const tokenId = btn.getAttribute('data-open');
      try {
        $("tokenIdIn").value = tokenId;
        await loadToken();
        $("tokenIdIn").scrollIntoView({ behavior: 'smooth', block: 'center' });
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
        $("myTokensStatus").textContent = "Sending title update…";
        const txHash = await CIPNFT.setTitle(tokenId, String(next).trim());
        $("myTokensStatus").textContent = `Title updated: ${txHash}`;
        await refreshManagedToken(tokenId);
        renderMyTokens(myTokens);
      } catch (e) {
        $("myTokensStatus").textContent = "—";
        alert(CIPNFT.fmtErr(e));
      }
    });
  });

out.querySelectorAll('button[data-list]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const tokenId = btn.getAttribute('data-list');
      try {
        await connectWallet();
        const v = String($("priceEth_" + tokenId).value || '').trim();
        const priceEth = v === '' ? '0' : v;
        const priceWei = ethers.parseEther(priceEth);
        $("myTokensStatus").textContent = `Listing #${tokenId}…`;
        const txHash = await CIPNFT.setListing(tokenId, true, priceWei);
        toast('Listing updated.');
        await refreshManagedToken(tokenId, { eraseDone: myTokens.find(x=>x.tokenId===tokenId)?.eraseDone });
        $("myTokensStatus").textContent = `Updated: ${txHash}`;
      } catch (e) {
        $("myTokensStatus").textContent = '—';
        alert(CIPNFT.fmtErr(e));
      }
    });
  });

  out.querySelectorAll('button[data-delist]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const tokenId = btn.getAttribute('data-delist');
      try {
        await connectWallet();
        $("myTokensStatus").textContent = `Delisting #${tokenId}…`;
        const txHash = await CIPNFT.setListing(tokenId, false, 0n);
        toast('Delisted.');
        await refreshManagedToken(tokenId, { eraseDone: myTokens.find(x=>x.tokenId===tokenId)?.eraseDone });
        $("myTokensStatus").textContent = `Delisted: ${txHash}`;
      } catch (e) {
        $("myTokensStatus").textContent = '—';
        alert(CIPNFT.fmtErr(e));
      }
    });
  });

  out.querySelectorAll('button[data-erase]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const tokenId = btn.getAttribute('data-erase');
      try {
        await connectWallet();
        const maxWords = Math.max(1, Number($("eraseMaxWords").value || 600));
        $("myTokensStatus").textContent = `Erasing #${tokenId} (${maxWords} words)…`;
        const txHash = await CIPNFT.eraseTokenData(tokenId, maxWords);
        toast('Erase step submitted.');

        // Mark as "started" so we can display ERASED when it completes.
        const row = myTokens.find(x => x.tokenId === String(tokenId));
        if (row) row.eraseDone = row.eraseDone || false;

        await refreshManagedToken(tokenId, { erasureStarted: true });
        $("myTokensStatus").textContent = `Erase step tx: ${txHash}`;
      } catch (e) {
        $("myTokensStatus").textContent = '—';
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
        $("myTokensStatus").textContent = `Burning #${tokenId}…`;
        const txHash = await CIPNFT.burn(tokenId);
        toast('Token burned.');
        // Remove from list
        myTokens = myTokens.filter(x => x.tokenId !== String(tokenId));
        renderMyTokens(myTokens);
        $("myTokensStatus").textContent = `Burned: ${txHash}`;
      } catch (e) {
        $("myTokensStatus").textContent = '—';
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

  // Heuristic: if an erase step was started (by us) and the state is no longer active,
  // mark as done.
  if (opts.erasureStarted && !row.eraseActive) {
    row.eraseDone = true;
  }

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

  // Pull tokenIds using the on-chain owner index (state-only, no events).
  const tokenIds = [];

  try {
    const nBig = await c.ownedCount(addr);
    const n = BigInt(nBig.toString());
    const batch = 25n;
    for (let start = 0n; start < n; start += batch) {
      const end = (start + batch < n) ? (start + batch) : n;
      const ps = [];
      for (let i = start; i < end; i++) {
        ps.push(c.ownedTokenAt(addr, i));
      }
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

  // Fetch listing + erase state for each tokenId.
  const concurrency = 10;
  let idx = 0;
  const rows = new Array(tokenIds.length);
  const workers = new Array(Math.min(concurrency, tokenIds.length)).fill(0).map(async () => {
    while (idx < tokenIds.length) {
      const i = idx++;
      const tokenId = tokenIds[i];
      try {
        // Defensive: confirm still owned (should always be true if index is correct)
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



function setStatusBar() {
  CIPNFT.renderWalletHeader();
}

async function ensureNetworkRead() {
  await CIPNFT.init();
  // Do NOT force injected wallet for reads. Ensure RPC read provider is ready.
  await CIPNFT.ensureReadProvider();
  await CIPNFT.getReadContract();
  setStatusBar();
}

async function connectWallet() {
  // Avoid unnecessary wallet popups if a prior session was restored via eth_accounts.
  if (CIPNFT.state && CIPNFT.state.address && CIPNFT.state.signer) {
    setStatusBar();
    return;
  }
  await CIPNFT.connectWallet();
  setStatusBar();
}

function exportSeed() {
  // Export the seed relevant to the current token mode (if loaded).
  // Classic seeds are 32 bytes; PQC seeds are 64 bytes.
  const wantPqc = (currentToken && Number(currentToken.encMode) === 1) || (!CIPNFT.state.seedHex && !!CIPNFT.state.pqcSeedHex);

  if (wantPqc) {
    const seed = CIPNFT.state.pqcSeedHex;
    if (!seed) throw new Error("No PQC seed set. Click IMPORT and paste PQC_SEED_HEX, or set it on the Tokenize page.");
    const content =
`CIPNFT PQC Seed Export (ML-KEM-768)

Contract: ${CIPNFT.state.contractAddress}
ChainId: ${CIPNFT.state.chainId ?? ""}
Wallet: ${CIPNFT.state.address ?? ""}

PQC_SEED_HEX=${seed}

Keep this secret.`;
    const fname = `cipnft_pqc_seed_${(CIPNFT.state.address||"addr").slice(0,6)}.txt`;
    CIPNFT.downloadText(fname, content);
    toast("PQC seed exported.");
    return;
  }

  if (!CIPNFT.state.seedHex) throw new Error("No Classic seed set.");
  const content =
`CIPNFT Classic Encryption Seed Backup

Contract: ${CIPNFT.state.contractAddress}
ChainId: ${CIPNFT.state.chainId ?? ""}
Wallet: ${CIPNFT.state.address ?? ""}

SEED_HEX=${CIPNFT.state.seedHex}

Keep this private.`;
  const fname = `cipnft_seed_${(CIPNFT.state.address||"addr").slice(0,6)}.txt`;
  CIPNFT.downloadText(fname, content);
  toast("Classic seed exported.");
}


async function importSeed() {
  const raw = prompt(`Paste a seed (either Classic SEED_HEX or PQC_SEED_HEX).

- Classic: 32 bytes (0x + 64 hex chars)
- PQC: 64 bytes (0x + 128 hex chars)

Tip: you can paste the whole line like:
  SEED_HEX=0x...
or
  PQC_SEED_HEX=0x...`);

  if (!raw) return;

  // Accept raw hex or KEY=hex formats.
  let s = String(raw).trim();
  if (s.includes("=")) s = s.split("=").pop().trim();

  // Normalize
  if (!s.startsWith("0x")) s = "0x" + s;

  const b = ethers.getBytes(s);
  if (b.length === 32) {
    const res = CIPNFT.importSeed(s);
    $("seedHex").value = res.seedHex;
    $("pubKeyHex").value = res.publicKeyHex;
    toast("Classic seed imported.");
    setStatusBar();
    return;
  }
  if (b.length === 64) {
    const res = await CIPNFT.importPqcSeed(s);
    $("seedHex").value = res.seedHex;
    // PQC public key is large; display its hash for compactness.
    $("pubKeyHex").value = res.pubKeyHash;
    toast("PQC seed imported (pubkey shown as hash).");
    setStatusBar();
    return;
  }

  throw new Error(`Seed must be 32 bytes (Classic) or 64 bytes (PQC). Provided: ${b.length} bytes.`);
}


function clearSeed() {
  // Clear the seed relevant to the current token mode (if loaded).
  const wantPqc = (currentToken && Number(currentToken.encMode) === 1);
  if (wantPqc) {
    CIPNFT.clearPqcSeed();
    $("seedHex").value = "";
    $("pubKeyHex").value = "";
    toast("PQC seed cleared.");
    setStatusBar();
    return;
  }
  CIPNFT.clearSeed();
  $("seedHex").value = "";
  $("pubKeyHex").value = "";
  toast("Classic seed cleared.");
  setStatusBar();
}


async function deriveKey() {
  // This derives the Classic (X25519) identity only.
  if (currentToken && Number(currentToken.encMode) === 1) {
    const ok = confirm(`This token uses PQC envelopes.

DERIVE (SIGN) on this page derives the Classic key only and is NOT used to decrypt PQC tokens.

To decrypt PQC tokens:
- Click IMPORT and paste PQC_SEED_HEX (64 bytes), or
- Set/import the PQC seed on the Tokenize page.

Derive Classic key anyway?`);
    if (!ok) return;
  }
  const res = await CIPNFT.deriveKeyFromSignature();
  $("seedHex").value = res.seedHex;
  $("pubKeyHex").value = res.publicKeyHex;
  toast("Derived Classic key.");
  setStatusBar();
}


async function loadToken() {
  await ensureNetworkRead();
  const tokenId = String($("tokenIdIn").value || "").trim();
  if (!tokenId) throw new Error("Enter tokenId.");
  $("tokenStatus").textContent = "Loading…";
  currentToken = await CIPNFT.getTokenBundle(tokenId);
  $("ownerOut").textContent = currentToken.owner;
  $("titleOut").textContent = currentToken.title || "—";
  $("tosOut").textContent = `v${currentToken.tosVersion}`;
  $("listedOut").textContent = currentToken.open ? "open" : "closed";
  $("priceOut").textContent = `${CIPNFT.toEtherString(currentToken.priceWei)} ${CIPNFT.nativeSymbol()}`;
  const isPqcToken = (Number(currentToken.encMode) === 1);
  $("modeOut").textContent = isPqcToken ? "PQC" : "classic";

  // Hint the global "key login status" indicator to the mode required for this token.
  CIPNFT.setPreferredEncMode(isPqcToken ? "pqc" : "classic");
  setStatusBar();
  $("cipherBytesOut").textContent = String(currentToken.metaCipherBytes.length);
  $("viewEnabledOut").textContent = currentToken.viewWrapBytes.length ? "yes" : "no";

  // Ciphertext preview (hex). Full ciphertext is only rendered on user click.
  try {
    const hex = ethers.hexlify(currentToken.metaCipherBytes);
    const maxPreview = 360;
    const preview = hex.length > maxPreview ? (hex.slice(0, maxPreview) + "…") : hex;
    const prevEl = $("cipherPreviewOut");
    if (prevEl) {
      prevEl.textContent = preview;
      prevEl.dataset.fullHex = hex;
      prevEl.title = "Click to load full ciphertext";
    }
    const fullBox = $("cipherFullBox");
    const fullOut = $("cipherFullOut");
    if (fullBox) fullBox.style.display = "none";
    if (fullOut) fullOut.value = "";
    const b = $("btnToggleCipher");
    if (b) b.textContent = "LOAD FULL CIPHERTEXT";
    cipherFullShown = false;
  } catch (_) {}

  $("tokenStatus").textContent = `Loaded token #${currentToken.tokenId}.`;
  $("ownerDecryptStatus").textContent = "—";
  $("viewDecryptStatus").textContent = "—";
  $("plainOut").value = "";
  lastPlaintext = "";

  // try auto-load saved view key (best effort) if present
  try {
    const k = `CIPNFT_VIEWKEY_${CIPNFT.state.chainId}_${CIPNFT.state.contractAddress}_${currentToken.tokenId}`;
    const saved = localStorage.getItem(k);
    if (saved) {
      $("viewKeyIn").value = saved;
      $("viewDecryptStatus").textContent = "Loaded saved view key from this browser.";
    }
  } catch (_) {}
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
    // scroll into view so the user sees it immediately
    fullBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } else {
    fullBox.style.display = "none";
    btn.textContent = "LOAD FULL CIPHERTEXT";
  }
}

function clearToken() {
  currentToken = null;
  $("ownerOut").textContent = "—";
  $("tosOut").textContent = "—";
  $("listedOut").textContent = "—";
  $("priceOut").textContent = "—";
  $("cipherBytesOut").textContent = "—";
  $("viewEnabledOut").textContent = "—";
  const prevEl = $("cipherPreviewOut");
  if (prevEl) { prevEl.textContent = "—"; prevEl.dataset.fullHex = ""; }
  const fullBox = $("cipherFullBox");
  if (fullBox) fullBox.style.display = "none";
  const fullOut = $("cipherFullOut");
  if (fullOut) fullOut.value = "";
  const b = $("btnToggleCipher");
  if (b) b.textContent = "LOAD FULL CIPHERTEXT";
  cipherFullShown = false;
  $("tokenStatus").textContent = "—";
  $("offersTable").innerHTML = "";
  $("offersStatus").textContent = "—";
  $("plainOut").value = "";
  lastPlaintext = "";
}

async function decryptAsOwner() {
  if (!currentToken) throw new Error("Load a token first.");
  await ensureNetworkRead();
  $("ownerDecryptStatus").textContent = "Decrypting…";
  const dek = await CIPNFT.decryptDEKAsOwner(currentToken.ownerEncDEKBytes, currentToken.encMode);
  CIPNFT.verifyDekHash(dek, currentToken.dekHash);
  const pt = CIPNFT.decryptMetaCipher(currentToken.metaCipherBytes, dek);
  $("plainOut").value = pt;
  lastPlaintext = pt;
  $("ownerDecryptStatus").textContent = "OK.";
  toast("Decrypted as owner.");
}

async function decryptWithViewKey() {
  if (!currentToken) throw new Error("Load a token first.");
  if (!currentToken.viewWrapBytes.length) throw new Error("Token has no view key enabled.");
  await ensureNetworkRead();
  const vk = String($("viewKeyIn").value || "").trim();
  if (!vk) throw new Error("Enter view key.");
  $("viewDecryptStatus").textContent = "Decrypting…";
  const dek = CIPNFT.decryptDEKWithViewKey(currentToken.viewWrapBytes, vk);
  CIPNFT.verifyDekHash(dek, currentToken.dekHash);
  const pt = CIPNFT.decryptMetaCipher(currentToken.metaCipherBytes, dek);
  $("plainOut").value = pt;
  lastPlaintext = pt;
  $("viewDecryptStatus").textContent = "OK.";
  toast("Decrypted with view key.");
}

function downloadPlain() {
  if (!currentToken) throw new Error("Load a token first.");
  if (!lastPlaintext) throw new Error("Nothing to download.");
  const fname = `cipnft_token${currentToken.tokenId}_plaintext.json`;
  CIPNFT.downloadText(fname, lastPlaintext);
  toast("Downloaded plaintext.");
}

function selectedVkMode() {
  const el = document.querySelector('input[name="vkMode"]:checked');
  return el ? el.value : 'clear';
}

function updateVkModeUI() {
  const m = selectedVkMode();
  const box = $("newViewKeyBox");
  if (!box) return;
  box.style.display = (m === 'new') ? 'block' : 'none';
  if (m === 'new' && !$("newViewKeyOut").value) {
    $("newViewKeyOut").value = CIPNFT.randomViewKeyText();
  }
}

async function copyNewViewKey() {
  const v = $("newViewKeyOut").value;
  if (!v) return;
  await navigator.clipboard.writeText(v);
  toast("New view key copied.");
}

function downloadNewViewKey(forTokenId) {
  const v = $("newViewKeyOut").value;
  if (!v) throw new Error("No new view key.");
  const tokenId = (forTokenId != null && String(forTokenId).trim() !== "")
    ? String(forTokenId).trim()
    : (currentToken ? String(currentToken.tokenId) : "");

  const content =
`CIPNFT View Key (transfer)\n\n` +
`Contract: ${CIPNFT.state.contractAddress}\n` +
`ChainId: ${CIPNFT.state.chainId ?? ""}\n` +
`TokenId: ${tokenId || ""}\n\n` +
`VIEW_KEY=${v}\n`;
  const fname = tokenId ? `cipnft_viewkey_token${tokenId}.txt` : `cipnft_viewkey.txt`;
  CIPNFT.downloadText(fname, content);
  toast("View key file downloaded.");
}

async function getOwnedTokenIdsFromStateIndex(ownerAddr) {
  // Uses the on-chain owner index (state-based enumeration, no events).
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
  if (!rows.length) {
    $("offersTable").innerHTML = `<div class="mono" style="color: var(--text-muted);">No active offers found.</div>`;
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
    const openHref = `./verify.html?tokenId=${encodeURIComponent(String(r.tokenId))}`;
    return `
      <div class="table-row" style="grid-template-columns: 0.75fr 1.25fr 0.9fr 1.1fr 0.9fr auto;">
        <div class="mono"><a class="link" href="${openHref}">#${tokenIdEsc}</a></div>
        <div class="mono">${buyerEsc}</div>
        <div class="mono">${CIPNFT.toEtherString(r.amountWei)} ${esc(CIPNFT.nativeSymbol())}</div>
        <div class="mono">${exp}</div>
        <div class="mono">${esc(r.status)}</div>
        <div class="actions-inline">
          <a class="btn small" style="text-decoration:none;" href="${openHref}">OPEN</a>
          <button class="btn small" data-deliver="${tokenIdEsc}|${buyerEsc}">${r.status === 'DELIVERED' ? 'RE-DELIVER' : 'DELIVER'}</button>
          ${r.status === 'DELIVERED' ? `<button class="btn small" data-revoke="${tokenIdEsc}|${buyerEsc}">REVOKE</button>` : ''}
        </div>
      </div>`;
  }).join('');

  $("offersTable").innerHTML = head + body;

  $("offersTable").querySelectorAll('button[data-deliver]').forEach(btn => {
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
        const newViewKeyText = (mode === 'new') ? String($("newViewKeyOut").value || '') : "";

        $("offersStatus").textContent = `Delivering token #${tokenId}…`;
        const txHash = await CIPNFT.deliverOffer({ tokenId, buyerAddr: buyer, keepViewWrap, newViewKeyText });
        $("offersStatus").textContent = `Delivered: ${txHash}`;
        toast('Delivery posted. Buyer must verify and finalize.');

        if (mode === 'new' && newViewKeyText) {
          // Include tokenId in the view key export.
          downloadNewViewKey(tokenId);
        }

        await loadOffersState();
      } catch (e) {
        $("offersStatus").textContent = '—';
        alert(CIPNFT.fmtErr(e));
      }
    });
  });

  $("offersTable").querySelectorAll('button[data-revoke]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const raw = btn.getAttribute('data-revoke') || '';
      const parts = raw.split('|');
      const tokenId = parts[0];
      const buyer = parts.slice(1).join('|');
      try {
        if (!tokenId || !buyer) throw new Error('Bad offer row.');
        await connectWallet();

        $("offersStatus").textContent = `Revoking delivery for token #${tokenId}…`;
        const txHash = await CIPNFT.revokeDelivery(tokenId, buyer);
        $("offersStatus").textContent = `Revoked: ${txHash}`;
        toast('Delivery revoked.');
        await loadOffersState();
      } catch (e) {
        $("offersStatus").textContent = '—';
        alert(CIPNFT.fmtErr(e));
      }
    });
  });
}

async function loadOffersState() {
  // Load offers for all tokens currently owned by the connected wallet.
  await connectWallet();
  await ensureNetworkRead();

  $("offersStatus").textContent = 'Loading offers for your tokens from on-chain state…';
  $("offersTable").innerHTML = '';

  const ownerAddr = CIPNFT.state.address;
  if (!ownerAddr) {
    $("offersStatus").textContent = 'Connect wallet to load offers.';
    return;
  }

  let tokenIds = [];
  try {
    tokenIds = await getOwnedTokenIdsFromStateIndex(ownerAddr);
  } catch (e) {
    $("offersStatus").textContent = 'Owner index not available (or RPC failed). Please redeploy the latest contract.';
    throw e;
  }

  if (!tokenIds.length) {
    renderOffers([]);
    $("offersStatus").textContent = 'No tokens owned.';
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

        while (guard < 40) { // up to ~2000 offers/token (safety)
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
        // Skip token on RPC hiccup; keep scanning.
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
  $("offersStatus").textContent = `Offers loaded. Active: ${activeN}. Delivered: ${deliveredN}. Hidden expired: ${expiredN}.`;
}

async function loadSavedViewKey() {
  if (!currentToken) throw new Error('Load a token first.');
  await ensureNetworkRead();
  const k = `CIPNFT_VIEWKEY_${CIPNFT.state.chainId}_${CIPNFT.state.contractAddress}_${currentToken.tokenId}`;
  const saved = localStorage.getItem(k);
  if (!saved) throw new Error('No saved view key found in this browser for this token.');
  $("viewKeyIn").value = saved;
  toast('Loaded saved view key.');
}

function parseQueryTokenId() {
  const u = new URL(window.location.href);
  const tid = u.searchParams.get('tokenId');
  return tid;
}

async function init() {
  // Init + restore prior wallet session (no popup)
  await CIPNFT.bootstrap();
  setStatusBar();

  $("btnConnect").addEventListener('click', async () => {
    try {
      await connectWallet();
      // Auto-load "My Vault" tokens immediately after connecting.
      try { await syncMyTokensState(); } catch (_) {}
    } catch (e) {
      alert(CIPNFT.fmtErr(e));
    }
  });

  $("btnDerive").addEventListener('click', async () => { try { await connectWallet(); await deriveKey(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnImportSeed").addEventListener('click', async () => { try { await importSeed(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnExportSeed").addEventListener('click', () => { try { exportSeed(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnClearSeed").addEventListener('click', () => { try { clearSeed(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });

  $("btnLoadToken").addEventListener('click', async () => { try { await loadToken(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnClearToken").addEventListener('click', () => clearToken());

  const btnToggleCipher = $("btnToggleCipher");
  if (btnToggleCipher) btnToggleCipher.addEventListener('click', () => toggleFullCiphertext());
  const cipherPrev = $("cipherPreviewOut");
  if (cipherPrev) cipherPrev.addEventListener('click', () => toggleFullCiphertext());

  $("btnDecryptOwner").addEventListener('click', async () => { try { await connectWallet(); await decryptAsOwner(); } catch (e) { $("ownerDecryptStatus").textContent = '—'; alert(CIPNFT.fmtErr(e)); } });
  $("btnDecryptViewKey").addEventListener('click', async () => { try { await decryptWithViewKey(); } catch (e) { $("viewDecryptStatus").textContent = '—'; alert(CIPNFT.fmtErr(e)); } });
  $("btnLoadSavedViewKey").addEventListener('click', async () => { try { await loadSavedViewKey(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnDownloadPlain").addEventListener('click', () => { try { downloadPlain(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });

  $("btnScanOffers").addEventListener('click', async () => { try { await loadOffersState(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });

  // My vault
  const btnScanMine = $("btnScanMyTokens");
  if (btnScanMine) btnScanMine.addEventListener('click', async () => { try { await syncMyTokensState(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  const btnClearMine = $("btnClearMyTokens");
  if (btnClearMine) btnClearMine.addEventListener('click', () => clearMyTokens());

  document.querySelectorAll('input[name="vkMode"]').forEach(r => r.addEventListener('change', updateVkModeUI));
  $("btnGenNewViewKey").addEventListener('click', () => { $("newViewKeyOut").value = CIPNFT.randomViewKeyText(); toast('New view key generated.'); });
  $("btnCopyNewViewKey").addEventListener('click', async () => { try { await copyNewViewKey(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnDownloadNewViewKey").addEventListener('click', () => { try { downloadNewViewKey(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });

  updateVkModeUI();

  // auto tokenId from query param
  const tid = parseQueryTokenId();
  if (tid) {
    $("tokenIdIn").value = tid;
    try { await loadToken(); } catch (_) {}
  }

  // If the wallet is already authorized (restored via eth_accounts),
  // automatically sync owned tokens on page open.
  if (CIPNFT.state && CIPNFT.state.address) {
    try { await syncMyTokensState(); } catch (_) {}
  }
}

document.addEventListener('DOMContentLoaded', () => { init().catch(e => alert(CIPNFT.fmtErr(e))); });
