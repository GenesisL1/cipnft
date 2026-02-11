/* CIPNFT — Marketplace page */

const $ = (id) => document.getElementById(id);

function toast(msg) {
  const el = $("toast");
  if (!el) return;
  el.textContent = msg;
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 3200);
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'' :'&#39;'}[c]));
}

function updateStatusBar() {
  CIPNFT.renderWalletHeader();
}

// -------- Incoming offers (owner) --------

async function ensureNetworkRead() {
  await CIPNFT.init();
  // Do not require wallet for reads.
  await CIPNFT.ensureReadProvider();
  await CIPNFT.getReadContract();
  updateStatusBar();
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
    : "";

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

function renderIncomingOffers(rows) {
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

  out.innerHTML = head + body;

  out.querySelectorAll('button[data-deliver]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const raw = btn.getAttribute('data-deliver') || '';
      const parts = raw.split('|');
      const tokenId = parts[0];
      const buyer = parts.slice(1).join('|');
      try {
        if (!tokenId || !buyer) throw new Error('Bad offer row.');
        await connect();

        const mode = selectedVkMode();
        const keepViewWrap = (mode === 'keep');
        const newViewKeyText = (mode === 'new') ? String($("newViewKeyOut").value || '') : "";

        $("offersStatus").textContent = `Delivering token #${tokenId}…`;
        const txHash = await CIPNFT.deliverOffer({ tokenId, buyerAddr: buyer, keepViewWrap, newViewKeyText });
        $("offersStatus").textContent = `Delivered: ${txHash}`;
        toast('Delivery posted. Buyer must verify and finalize.');

        if (mode === 'new' && newViewKeyText) {
          downloadNewViewKey(tokenId);
        }

        await loadIncomingOffersState();
      } catch (e) {
        $("offersStatus").textContent = '—';
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
        await connect();

        $("offersStatus").textContent = `Revoking delivery for token #${tokenId}…`;
        const txHash = await CIPNFT.revokeDelivery(tokenId, buyer);
        $("offersStatus").textContent = `Revoked: ${txHash}`;
        toast('Delivery revoked.');
        await loadIncomingOffersState();
      } catch (e) {
        $("offersStatus").textContent = '—';
        alert(CIPNFT.fmtErr(e));
      }
    });
  });
}

async function loadIncomingOffersState() {
  // Load offers for all tokens currently owned by the connected wallet.
  await connect();
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
    renderIncomingOffers([]);
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
        // skip token on RPC hiccup
      }
    }
  });
  await Promise.all(workers);

  rows.sort((a,b) => b.expiry - a.expiry);
  const visible = rows.filter(r => r.status !== 'EXPIRED');
  renderIncomingOffers(visible);

  const activeN = rows.filter(r => r.status === 'ACTIVE').length;
  const deliveredN = rows.filter(r => r.status === 'DELIVERED').length;
  const expiredN = rows.filter(r => r.status === 'EXPIRED').length;
  $("offersStatus").textContent = `Offers loaded. Active: ${activeN}. Delivered: ${deliveredN}. Hidden expired: ${expiredN}.`;
}

// Latest-first pagination (6 listings per page)
let currentPage = 0;
const PAGE_SIZE = 6;

async function connect() {
  await CIPNFT.connectWallet();
  updateStatusBar();
}

function listingCardHTML({ tokenId, title, priceWei, offerInfo, cipherPreview, cipherLen, encMode, maxDays, defaultDays, minOfferNotice }) {
  const priceNative = CIPNFT.toEtherString(priceWei);
  const sym = CIPNFT.nativeSymbol();
  const offerLine = offerInfo
    ? `<div class="mono" style="color: var(--text-muted); font-size:0.75rem; margin-top:10px;">YOUR OFFER: ${esc(offerInfo)}</div>`
    : `<div class="mono" style="color: var(--text-muted); font-size:0.75rem; margin-top:10px;">YOUR OFFER: —</div>`;

  const modePill = (Number(encMode) === CIPNFT.ENC_MODE_PQC)
    ? `<span class="pill warn">PQC</span>`
    : `<span class="pill ok">CLASSIC</span>`;

  return `
    <div class="card" data-token="${esc(tokenId)}">
      <div class="card-image">
        <div class="shape frame"></div>
        <div class="encrypted-layer"><div class="lock-icon">🔒</div></div>
      </div>
      <div class="mono" style="font-size: 0.7rem; color: var(--text-muted);">TOKEN: #${esc(tokenId)}</div>
      <div class="card-meta">
        <h4>${esc(title || "Untitled")}</h4>
        <span class="mono">${esc(priceNative)} ${esc(sym)}</span>
      </div>

      <div class="mono" style="color: var(--text-muted); font-size:0.72rem; margin-top: 8px;">MODE: ${modePill}</div>

      <div class="cipher-preview mono" style="color: var(--text-muted); font-size:0.72rem; margin-top: 10px; word-break: break-all;">
        CIPHERTEXT (${esc(cipherLen)} bytes, preview): ${esc(cipherPreview || "—")}
      </div>

      ${offerLine}
      ${minOfferNotice || ''}

      <div class="field" style="margin-top: 12px;">
        <label>Offer expiry (days)</label>
        <input class="expiryDays" type="number" min="1" max="${esc(maxDays)}" value="${esc(defaultDays)}" />
      </div>

      <div class="actions" style="margin-top: 10px;">
        <button class="btn small btnOffer requires-wallet">MAKE OFFER (ESCROW)</button>
        <button class="btn small btnCancelOffer requires-wallet" style="display:none;">CANCEL OFFER</button>
        <a class="btn small" style="text-decoration:none;" href="./mint.html?tokenId=${esc(tokenId)}#load-token-card">OPEN</a>
      </div>

      <div class="mono" style="color: var(--text-muted); margin-top: 10px;" data-status>—</div>
    </div>
  `;
}

async function loadListings() {
  await CIPNFT.init();
  try { await CIPNFT.ensureProvider(); } catch (_) {}

  // Load on-chain offer rules (spam resistance)
  try { await CIPNFT.refreshOnchain(); } catch (_) {}
  const capSec = Number(CIPNFT.state.maxOfferDurationSec || 0);
  const maxDays = capSec > 0 ? Math.max(1, Math.ceil(capSec / 86400)) : 365;
  const defaultDays = Math.min(7, maxDays);
  const minOfferPriceWei = (CIPNFT.state.minOfferPriceWei !== undefined && CIPNFT.state.minOfferPriceWei !== null) ? CIPNFT.state.minOfferPriceWei : 0n;

  // Fetch newest listings first (last 6)
  const res = await CIPNFT.getListedLatest(currentPage, PAGE_SIZE);
  const tokenIds = res.tokenIds || [];
  const prices = res.prices || [];
  const totalPages = res.totalPages || 0;
  const total = res.total || 0;
  currentPage = res.pageIndex || 0;

  // Update pager UI
  const info = $("listingsPageInfo");
  if (info) {
    info.textContent = (totalPages === 0)
      ? 'No listings found.'
      : `Page ${currentPage + 1} / ${totalPages} · ${total} total listings`;
  }
  const btnNewer = $("btnNewer");
  const btnOlder = $("btnOlder");
  if (btnNewer) btnNewer.disabled = (totalPages === 0) || (currentPage <= 0);
  if (btnOlder) btnOlder.disabled = (totalPages === 0) || (currentPage >= totalPages - 1);

  // Fetch public card data (title + ciphertext preview)
  const cards = await Promise.all(tokenIds.map(tid => CIPNFT.getTokenCard(tid).catch(() => null)));

  // If connected, also show the user's offer for each token.
  let offerInfos = new Array(tokenIds.length).fill(null);
  let hasBuyerPubKey = true;
  let hasBuyerPqcPubKey = true;
  if (CIPNFT.state.address) {
    try {
      const pk = await CIPNFT.getMyOnchainPubKey();
      hasBuyerPubKey = pk && pk !== "0x0000000000000000000000000000000000000000000000000000000000000000";
    } catch (_) {}

    try {
      const pk2 = await CIPNFT.getMyOnchainPqcPubKey();
      hasBuyerPqcPubKey = pk2 && pk2.length === CIPNFT.PQC_PUBKEY_BYTES;
    } catch (_) {}


    const now = CIPNFT.nowSec();
    const offers = await Promise.all(tokenIds.map(tid => CIPNFT.getOffer(tid, CIPNFT.state.address).catch(() => null)));
    offerInfos = offers.map((o, i) => {
      if (!o || o.expiry === 0) return null;
      const exp = o.expiry;
      const active = exp > now;
        const amt = CIPNFT.toEtherString(o.amountWei);
        const sym = CIPNFT.nativeSymbol();
        return active ? `${amt} ${sym} (active, exp ${new Date(exp*1000).toISOString().slice(0,19)}Z)` : `${amt} ${sym} (expired)`;
    });
  }

  const out = $("listingsOut");
  if (!tokenIds.length) {
    out.innerHTML = `<div class="mono" style="color: var(--text-muted); padding: 20px;">No tokens are currently listed.</div>`;
    return;
  }
  out.innerHTML = tokenIds.map((tid, i) => {
    const c = cards[i];
    const title = c ? c.title : "";
    const encMode = c ? c.encMode : 0;
    const cipherLen = c ? c.cipherLen : 0;
    const cipherPreview = c ? CIPNFT.cipherPreviewText(c.cipherPreviewHex, 300) : "—";
    const belowMin = (minOfferPriceWei > 0n && prices[i] < minOfferPriceWei);
    const sym = CIPNFT.nativeSymbol();
    const minOfferNotice = belowMin ? `<div class="mono" style="color: var(--text-muted); font-size:0.72rem; margin-top: 8px;">MIN OFFER: ${esc(CIPNFT.toEtherString(minOfferPriceWei))} ${esc(sym)} (this listing is below the protocol minimum)</div>` : `<div class="mono" style="color: var(--text-muted); font-size:0.72rem; margin-top: 8px;">MIN OFFER: ${esc(CIPNFT.toEtherString(minOfferPriceWei))} ${esc(sym)}</div>`;
    return listingCardHTML({ tokenId: tid, title, encMode, cipherLen, cipherPreview, priceWei: prices[i], offerInfo: offerInfos[i], maxDays, defaultDays, minOfferNotice });
  }).join("\n");

  // wire buttons
  out.querySelectorAll('.card').forEach((card, idx) => {
    const tokenId = card.getAttribute('data-token');
    const priceWei = prices[idx];
    const btnOffer = card.querySelector('.btnOffer');
    const btnCancel = card.querySelector('.btnCancelOffer');
    const status = card.querySelector('[data-status]');
    const expiryInput = card.querySelector('.expiryDays');

    const mode = (cards[idx] && cards[idx].encMode != null) ? Number(cards[idx].encMode) : 0;

    if (CIPNFT.state.address && ((mode === CIPNFT.ENC_MODE_PQC && !hasBuyerPqcPubKey) || (mode === CIPNFT.ENC_MODE_CLASSIC && !hasBuyerPubKey))) {
      status.textContent = (mode === CIPNFT.ENC_MODE_PQC) ? 'You must register your PQC encryption pubkey before making offers.' : 'You must register your encryption pubkey before making offers.';
      btnOffer.disabled = true;
    }

    if (minOfferPriceWei > 0n && priceWei < minOfferPriceWei) {
      status.textContent = `Listing price is below protocol minimum offer price (${CIPNFT.toEtherString(minOfferPriceWei)} ${CIPNFT.nativeSymbol()}).`;
      btnOffer.disabled = true;
    }

    btnOffer.addEventListener('click', async () => {
      try {
        // Switch the global key-login status indicator to the mode required by this token.
        CIPNFT.setPreferredEncMode(mode === CIPNFT.ENC_MODE_PQC ? "pqc" : "classic");
        if (!CIPNFT.state.address) throw new Error('Connect wallet first.');

        // Hard gate: registered key is required to create offers.
        // If not registered, show a clear message and send the user to:
        // // KEY LOGIN + REGISTRATION
        if (mode === CIPNFT.ENC_MODE_PQC) {
          const pk2 = await CIPNFT.getMyOnchainPqcPubKey().catch(() => null);
          const ok = pk2 && pk2.length === CIPNFT.PQC_PUBKEY_BYTES;
          if (!ok) {
            alert('Register your key on chain first.');
            location.href = './mint.html#key-login-card';
            return;
          }
        } else {
          const ZERO32 = "0x" + "00".repeat(32);
          const pk = await CIPNFT.getMyOnchainPubKey().catch(() => null);
          const ok = pk && String(pk).toLowerCase() !== ZERO32;
          if (!ok) {
            alert('Register your key on chain first.');
            location.href = './mint.html#key-login-card';
            return;
          }
        }
        if (minOfferPriceWei > 0n && priceWei < minOfferPriceWei) {
          throw new Error(`Listing price is below protocol minimum offer price (${CIPNFT.toEtherString(minOfferPriceWei)} ${CIPNFT.nativeSymbol()}).`);
        }
// Re-fetch on-chain offer rules at click-time and base expiry on chain time.
// This prevents BAD_EXPIRY if the user's local clock is skewed or rules changed.
await CIPNFT.refreshOnchain();
const capSecNow = Number(CIPNFT.state.maxOfferDurationSec || 0);
const maxDaysNow = capSecNow > 0 ? Math.max(1, Math.ceil(capSecNow / 86400)) : 365;

let daysRaw = parseInt(String(expiryInput.value || defaultDays), 10);
if (!Number.isFinite(daysRaw) || daysRaw < 1) daysRaw = defaultDays;

const days = Math.max(1, Math.min(maxDaysNow, daysRaw));
let expDelta = Math.floor(days * 86400);
if (capSecNow > 0) expDelta = Math.min(expDelta, capSecNow);

const chainNow = await CIPNFT.chainNowSec();
const expiry = chainNow + expDelta;
        status.textContent = 'Sending offer tx…';
        const txHash = await CIPNFT.createOffer(tokenId, expiry, priceWei);
        status.textContent = `Offer created: ${txHash}`;
        toast('Offer created and escrowed on-chain.');
        await loadListings();
      } catch (e) {
        status.textContent = '—';
        alert(CIPNFT.fmtErr(e));
      }
    });

    btnCancel.addEventListener('click', async () => {
      try {
        if (!CIPNFT.state.address) throw new Error('Connect wallet first.');
        status.textContent = 'Cancelling…';
        const txHash = await CIPNFT.cancelOffer(tokenId);
        status.textContent = `Cancelled: ${txHash}`;
        toast('Offer cancelled (funds refunded).');
        await loadListings();
        await loadMyOffers();
      } catch (e) {
        status.textContent = '—';
        alert(CIPNFT.fmtErr(e));
      }
    });
  });
}

function renderMyOffers(rows) {
  if (!rows.length) {
    $("myOffersTable").innerHTML = `<div class="mono" style="color: var(--text-muted);">No active offers found.</div>`;
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
        <div style="display:flex; gap:8px; justify-content:flex-end;">
          <a class="btn small" style="text-decoration:none;" href="./mint.html?tokenId=${esc(r.tokenId)}#load-token-card">OPEN</a>
          ${r.status.startsWith('DELIVERED') ? '<button class="btn small requires-wallet" data-finalize="'+esc(r.tokenId)+'">VERIFY & FINALIZE</button>' : ''}
          <button class="btn small requires-wallet" data-cancel="${esc(r.tokenId)}">CANCEL</button>
        </div>
      </div>
    `;
  }).join('');

  $("myOffersTable").innerHTML = head + body;

  $("myOffersTable").querySelectorAll('button[data-cancel]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const tokenId = btn.getAttribute('data-cancel');
      try {
        await CIPNFT.cancelOffer(tokenId);
        toast('Offer cancelled.');
        await loadMyOffers();
        await loadListings();
      } catch (e) {
        alert(CIPNFT.fmtErr(e));
      }
    });
  });


$("myOffersTable").querySelectorAll('button[data-finalize]').forEach(btn => {
  btn.addEventListener('click', async () => {
    const tokenId = btn.getAttribute('data-finalize');
    try {
      if (!CIPNFT.state.address) throw new Error('Connect wallet first.');
      $("myOffersStatus").textContent = 'Verifying delivery & finalizing…';
      const txHash = await CIPNFT.finalizeOffer(tokenId);
      toast('Finalized. NFT transferred to you.');
      $("myOffersStatus").textContent = `Finalized: ${txHash}`;
      await loadMyOffers();
    } catch (e) {
      $("myOffersStatus").textContent = '—';
      alert(CIPNFT.fmtErr(e));
    }
  });
});
}

async function loadMyOffers() {
  if (!CIPNFT.state.address) {
    $("myOffersStatus").textContent = 'Connect wallet to load your offers.';
    $("myOffersTable").innerHTML = '';
    return;
  }

  $("myOffersStatus").textContent = 'Loading your offers from on-chain state…';

  const now = CIPNFT.nowSec();
  const rows = [];

  let cursor = 0;
  const pageSize = 50;
  let guard = 0;

  while (guard < 40) { // up to ~2000 offers (safety guard)
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
  $("myOffersStatus").textContent = `Offers loaded from state. Active: ${activeN}. Delivered: ${deliveredN}.`;
}

async function init() {
  await CIPNFT.bootstrap();
  updateStatusBar();

  // Incoming offers (owner) controls
  const btnScanOffers = $("btnScanOffers");
  if (btnScanOffers) btnScanOffers.addEventListener('click', async () => {
    try { await loadIncomingOffersState(); } catch (e) { alert(CIPNFT.fmtErr(e)); }
  });

  document.querySelectorAll('input[name="vkMode"]').forEach(r => r.addEventListener('change', updateVkModeUI));
  const btnGenVk = $("btnGenNewViewKey");
  if (btnGenVk) btnGenVk.addEventListener('click', () => {
    const out = $("newViewKeyOut");
    if (out) out.value = CIPNFT.randomViewKeyText();
    toast('New view key generated.');
  });
  const btnCopyVk = $("btnCopyNewViewKey");
  if (btnCopyVk) btnCopyVk.addEventListener('click', async () => {
    try { await copyNewViewKey(); } catch (e) { alert(CIPNFT.fmtErr(e)); }
  });
  const btnDlVk = $("btnDownloadNewViewKey");
  if (btnDlVk) btnDlVk.addEventListener('click', () => {
    try { downloadNewViewKey(); } catch (e) { alert(CIPNFT.fmtErr(e)); }
  });
  try { updateVkModeUI(); } catch (_) {}

  $("btnConnect").addEventListener('click', async () => {
    try {
      await connect();
      // Auto-load the buyer's offers as soon as a wallet is connected.
      try { await loadMyOffers(); } catch (_) {}
      // Reload listings too (so the user's offer lines appear immediately)
      try { await loadListings(); } catch (_) {}
    } catch (e) {
      alert(CIPNFT.fmtErr(e));
    }
  });

  // Pagination buttons
  $("btnNewer").addEventListener('click', async () => {
    if (currentPage <= 0) return;
    currentPage = Math.max(0, currentPage - 1);
    try { await loadListings(); } catch (e) { alert(CIPNFT.fmtErr(e)); }
  });
  $("btnOlder").addEventListener('click', async () => {
    currentPage = currentPage + 1;
    try { await loadListings(); } catch (e) { alert(CIPNFT.fmtErr(e)); }
  });

  $("btnLoadMyOffers").addEventListener('click', async () => {
    try { await loadMyOffers(); } catch (e) { alert(CIPNFT.fmtErr(e)); }
  });

  // Auto-load everything on open (read-only listings always; offers if authorized).
  try { await loadListings(); } catch (_) {}
  try { await loadMyOffers(); } catch (_) {}
}

document.addEventListener('DOMContentLoaded', () => { init().catch(e => alert(CIPNFT.fmtErr(e))); });
