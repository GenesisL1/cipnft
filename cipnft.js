/* CIPNFT core (browser-only, no Node.js)
 *
 * Provides:
 * - Wallet connection (EIP-1193)
 * - Contract instance (address from config.js)
 * - Two envelope modes for the per-token DEK:
 *      (0) Classic: X25519 sealed box via libsodium (crypto_box_seal)
 *      (1) PQC: ML-KEM-768 (post-quantum) + XChaCha20-Poly1305 wrap
 * - Metadata encryption: XChaCha20-Poly1305 (client-side; ciphertext stored on-chain)
 * - Optional view key: plaintext key that can decrypt DEK via on-chain viewWrap
 *
 * NOTE: This is a reference implementation. Do not consider it audited.
 */

(function () {
  // EIP-6963 provider discovery support (helps when multiple wallet extensions
  // conflict and window.ethereum isn't set as expected).
  const _eip6963 = {
    providers: [], // { info, provider }
    listening: false
  };
  function startEip6963Listener() {
    if (_eip6963.listening) return;
    _eip6963.listening = true;
    window.addEventListener('eip6963:announceProvider', (event) => {
      try {
        const detail = event.detail;
        if (!detail || !detail.provider) return;
        // De-dup by uuid if present; else by reference
        const uuid = detail.info && detail.info.uuid ? detail.info.uuid : null;
        const exists = _eip6963.providers.some(p => (uuid && p.info && p.info.uuid === uuid) || p.provider === detail.provider);
        if (!exists) _eip6963.providers.push(detail);
      } catch (_) {}
    });
  }
  function requestEip6963Providers() {
    try {
      startEip6963Listener();
      window.dispatchEvent(new Event('eip6963:requestProvider'));
    } catch (_) {}
  }
  const ABI = [
    // Admin / Terms / Fees
    "function admin() view returns (address)",
    "function tosVersionCurrent() view returns (uint256)",
    "function tosText(uint256 version) view returns (string)",
    "function tosHash(uint256 version) view returns (bytes32)",
    "function tosAccepted(address user, uint256 version) view returns (bool)",
    "function acceptTos(uint256 version)",
    "function perByteFeeWei() view returns (uint256)",
    "function flatMintFeeWei() view returns (uint256)",
    "function mintFeeFor(uint256 plaintextBytes) view returns (uint256)",

    // Offer rules (anti-spam)
    "function maxOfferDurationSec() view returns (uint64)",
    "function minOfferPriceWei() view returns (uint256)",
    "function setOfferRules(uint64 maxOfferDurationSec_, uint256 minOfferPriceWei_)",

    // Encryption keys
    "function setEncryptionPublicKey(bytes32 pubKey)",
    "function encryptionPubKey(address) view returns (bytes32)",
    "function setPqcPublicKey(bytes pubKey)",
    "function pqcPubKey(address) view returns (bytes)",

    // Mint + token data
    "function mint(string title, bytes metaCipher, bytes ownerEncDEK, bytes32 dekHash, bytes viewWrap, uint8 encMode) payable returns (uint256 tokenId)",
    "function getTokenData(uint256 tokenId) view returns (bytes metaCipher, bytes ownerEncDEK, bytes viewWrap, bytes32 dekHash)",
    "function titleOf(uint256 tokenId) view returns (string)",
    "function setTitle(uint256 tokenId, string newTitle)",
    "function getTokenCard(uint256 tokenId) view returns (string title, uint8 encMode, bool open, uint256 priceWei, uint32 cipherLen, bytes32 dekHash, bytes cipherPreview, uint32 tosVersion)",
    "function encryptionMode(uint256 tokenId) view returns (uint8)",
    "function tosVersionOf(uint256 tokenId) view returns (uint32)",
    "function ownerOf(uint256 tokenId) view returns (address)",

    // Owner index (state-based)
    "function ownedCount(address) view returns (uint256)",
    "function ownedTokenAt(address owner, uint256 index) view returns (uint256 tokenId)",
    
    // Erase / burn
    "function getEraseState(uint256 tokenId) view returns (bool active, uint8 field, uint32 nextWord)",
    "function eraseTokenData(uint256 tokenId, uint256 maxWords)",
    "function burn(uint256 tokenId)",

    // Listings
    "function setListing(uint256 tokenId, bool open, uint256 priceWei)",
    "function listings(uint256 tokenId) view returns (bool open, uint256 priceWei)",
    "function listedCount() view returns (uint256)",
    "function listedTokenAt(uint256 index) view returns (uint256 tokenId)",
    
    // Offers + delivery + finalize
    "function createOffer(uint256 tokenId, uint64 expiry) payable",
    "function cancelOffer(uint256 tokenId)",
    "function refundExpiredOffer(uint256 tokenId, address buyer)",
    "function getOffer(uint256 tokenId, address buyer) view returns (uint256 amountWei, uint64 expiry, bytes32 buyerKeyRef)",
    "function offerCount(uint256 tokenId) view returns (uint256)",
    "function offerBuyerAt(uint256 tokenId, uint256 index) view returns (address buyer)",
        "function buyerOfferCount(address buyer) view returns (uint256)",
    "function buyerOfferTokenAt(address buyer, uint256 index) view returns (uint256 tokenId)",
                "function getDelivery(uint256 tokenId, address buyer) view returns (address seller, uint64 deliveredAt, bytes ownerEncDEK, bytes viewWrap)",
    "function deliverOffer(uint256 tokenId, address buyer, bytes newOwnerEncDEK, bytes newViewWrap)",
    "function revokeDelivery(uint256 tokenId, address buyer)",
    "function finalizeOffer(uint256 tokenId)",

    // Events (for discovery / scanning)
    "event OfferCreated(uint256 indexed tokenId, address indexed buyer, uint256 amountWei, uint64 expiry, bytes32 buyerKeyRef)",
    "event Minted(uint256 indexed tokenId, address indexed owner, bytes32 dekHash, uint256 cipherSize, uint32 tosVersion, uint256 feePaid)"
  ];

  // ---- Crypto constants (must match contract) ----
  const MAX_PLAINTEXT = 64 * 1024;
  const NONCE_BYTES = 24;
  const AEAD_TAG_BYTES = 16;

  // View-wrap is nonce(24) || aead(DEK 32) => 24 + (32+16)=72
  const VIEW_WRAP_BYTES = NONCE_BYTES + (32 + AEAD_TAG_BYTES);

  // Classic sealed-box is 32 + 48 = 80 for 32-byte message (libsodium)
  const OWNER_ENVELOPE_BYTES_CLASSIC = 80;

  // PQC sizes for ML-KEM-768
  const ENC_MODE_CLASSIC = 0;
  const ENC_MODE_PQC = 1;
  const PQC_PUBKEY_BYTES = 1184;
  const PQC_KEM_CT_BYTES = 1088;
  const PQC_OWNER_ENVELOPE_BYTES = PQC_KEM_CT_BYTES + NONCE_BYTES + (32 + AEAD_TAG_BYTES); // 1160

  const state = {
    ready: false,
    provider: null,
    // Read-only provider/contract (RPC) used for public reads when wallet is
    // absent or on a different chain.
    readProvider: null,
    readContract: null,
    readChainId: null,
    signer: null,
    address: null,
    chainId: null,
    contract: null,
    contractAddress: null,
    contractOk: null,

    // selected EIP-1193 provider (injected wallet)
    eip1193: null,
    walletLabel: null,

    // on-chain cached
    admin: null,
    tosVersionCurrent: null,
    tosHashCurrent: null,
    tosAcceptedCurrent: false,
    perByteFeeWei: 0n,
    flatMintFeeWei: 0n,

    maxOfferDurationSec: 0,
    minOfferPriceWei: 0n,

    // on-chain key-registration status for the connected wallet
    // (used for the "// KEY LOGIN + REGISTRATION" hint link)
    classicOnchainPubKeyRef: null, // bytes32 (hex string) or null if unknown
    pqcOnchainPubKeyLen: null,     // number (bytes) or null if unknown

    // Classic (X25519) encryption identity
    classicSeedHex: null,          // 0x.. 32 bytes (hex)
    classicLoginType: null,        // 'signed' | 'imported' | null
    classicEncPublicKey: null,     // Uint8Array(32)
    encPublicKey: null,            // legacy alias for classicEncPublicKey
    classicEncPrivateKey: null,    // Uint8Array(32)
    encPrivateKey: null,           // legacy alias for classicEncPrivateKey

    // PQC (ML-KEM-768) encryption identity
    pqcSeedHex: null,              // 0x.. raw-seed (typically 64 bytes; library-defined)
    pqcLoginType: null,            // 'generated' | 'signed' | 'imported' | null
    pqcPubKeyBytes: null,          // Uint8Array(1184)

    // UX hint: which key-login mode the user currently considers "active"
    // for operations. Controls the nav "Key login status" line.
    // Values: 'classic' | 'pqc'
    preferredEncMode: "classic",

    // last DEK (in-memory only)
    lastDEK: null
  };

  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  // -------- Utilities --------
  function assertConfig() {
    if (!window.CIPNFT_CONFIG) throw new Error("Missing config.js (CIPNFT_CONFIG).");
    if (!window.CIPNFT_CONFIG.CONTRACT_ADDRESS) throw new Error("Missing CONTRACT_ADDRESS in config.js");
  }

  // Decode custom-error selectors (4-byte) into readable names where possible.
// This helps MetaMask / RPC providers that surface only the selector (e.g. 0x05bcfca9).
const CUSTOM_ERROR_SELECTORS = {
  // Offer / listing / expiry
  "0x05bcfca9": "BAD_EXPIRY()",
  "0x63a78418": "BAD_VALUE()",
};

function _extractRevertData(e) {
  // Try common shapes: ethers v6, MetaMask, RPC errors.
  return (
    (e && e.data && typeof e.data === "string" ? e.data : null) ||
    (e && e.data && e.data.data && typeof e.data.data === "string" ? e.data.data : null) ||
    (e && e.info && e.info.error && typeof e.info.error.data === "string" ? e.info.error.data : null) ||
    (e && e.error && typeof e.error.data === "string" ? e.error.data : null) ||
    null
  );
}

function _decodeCustomErrorName(e) {
  const data = _extractRevertData(e);
  if (!data || typeof data !== "string") return null;
  if (!data.startsWith("0x") || data.length < 10) return null;
  const sig = data.slice(0, 10).toLowerCase();
  return CUSTOM_ERROR_SELECTORS[sig] || null;
}

function fmtErr(e) {
  const decoded = _decodeCustomErrorName(e);
  const base = (e && e.shortMessage) ? e.shortMessage : (e && e.message) ? e.message : String(e);
  if (!decoded) return base;

  if (decoded === "BAD_EXPIRY()") {
    const cap = (state && state.maxOfferDurationSec) ? ` (cap: ${state.maxOfferDurationSec}s)` : "";
    return `Offer expiry rejected on-chain: BAD_EXPIRY. Choose an expiry in the future and within the protocol cap${cap}.`;
  }
  if (decoded === "BAD_VALUE()") {
    const min = (state && state.minOfferPriceWei != null) ? ` Min listing price: ${toEtherString(state.minOfferPriceWei)} ${nativeSymbol()}.` : "";
    return `Value/price rejected on-chain: BAD_VALUE.${min}`;
  }
  return `${base}

Revert: ${decoded}`;
}

  function shortAddr(a) {
    if (!a) return "—";
    const s = String(a);
    return s.slice(0, 6) + "…" + s.slice(-4);
  }

  function nowSec() {
    return Math.floor(Date.now() / 1000);
  }

async function chainNowSec() {
  // Use chain time (latest block timestamp) rather than local system time.
  // This avoids BAD_EXPIRY errors if the user's clock is skewed.
  await ensureProvider();
  const b = await state.provider.getBlock("latest");
  return Number(b && b.timestamp ? b.timestamp : Math.floor(Date.now() / 1000));
}

  function keyLoginStatusText() {
    // Exactly four states (as requested):
    // - No login active
    // - Classic wallet signed login active
    // - Quantum resistant login active
    // - Quantum resistant wallet signed login active
    //
    const pref = (state.preferredEncMode === "pqc") ? "pqc" : "classic";
    if (pref === "pqc") {
      if (state.pqcSeedHex) {
        return (state.pqcLoginType === "signed")
          ? "Quantum resistant wallet signed login active"
          : "Quantum resistant login active";
      }
      return "No login active";
    }

    if (state.classicSeedHex) {
      return "Classic wallet signed login active";
    }
    return "No login active";
  }

  function renderWalletHeader() {
    // Updates common UI elements if present on the current page.
    // Safe to call on any page.

    // Global CSS hook: hide tx/action buttons until a wallet is connected.
    try {
      document.body.classList.toggle('wallet-connected', !!state.address);
    } catch (_) {}

    try {
      const btn = document.getElementById('btnConnect');
      if (btn) {
        const label = state.address ? shortAddr(state.address) : 'CONNECT WALLET';
        btn.textContent = label;
        // Keep hover cipher effect stable by updating dataset.plain.
        btn.dataset.plain = label;
        btn.dataset.encrypted = '0';
        btn.classList.remove('is-encrypted');
        try {
          btn.setAttribute('aria-label', label);
          if (state.address) btn.setAttribute('title', String(state.address));
        } catch (_) {}
      }
    } catch (_) {}

    try {
      const k = document.getElementById('statusKeyLogin');
      if (k) k.textContent = `KEY LOGIN STATUS: ${keyLoginStatusText()}`;
    } catch (_) {}

    // Show a "// KEY LOGIN + REGISTRATION" hint link whenever the user is
    // not "ready" for the currently-selected key mode (Classic/PQC).
    // Ready = local seed present AND corresponding on-chain pubkey registered.
    try {
      const link = document.getElementById('noWalletLink');
      if (link) {
        const ZERO32 = "0x" + "00".repeat(32);
        const classicRegistered = !!(state.classicOnchainPubKeyRef && String(state.classicOnchainPubKeyRef).toLowerCase() !== ZERO32);
        const pqcRegistered = (state.pqcOnchainPubKeyLen === PQC_PUBKEY_BYTES);

        const pref = (state.preferredEncMode === "pqc") ? "pqc" : "classic";
        const localOk = (pref === "pqc") ? !!state.pqcSeedHex : !!state.classicSeedHex;
        const onchainOk = (pref === "pqc") ? pqcRegistered : classicRegistered;

        const needSetup = !(localOk && onchainOk);

        // App flow is now 2 pages: mint.html (Encrypt/Tokenize/View) + marketplace.html.
        // Always send the user to the Key Login + Registration card.
        link.href = './mint.html#key-login-card';
        link.style.display = needSetup ? 'inline-block' : 'none';
      }
    } catch (_) {}

    try {
      const c = document.getElementById('statusContract');
      if (c) c.textContent = state.contractAddress ? `CONTRACT: ${shortAddr(state.contractAddress)}` : 'CONTRACT: —';
      const ch = document.getElementById('statusChain');
      if (ch) {
        const exp = expectedChainId();
        const got = state.chainId;
        if (!got) ch.textContent = 'CHAIN: —';
        else if (exp && got !== exp) ch.textContent = `CHAIN: ${got} (EXPECTED ${exp})`;
        else ch.textContent = `CHAIN: ${got}`;
      }
      const w = document.getElementById('statusWallet');
      if (w) w.textContent = `WALLET: ${state.address ? shortAddr(state.address) : '—'}`;
    } catch (_) {}
  }

  function bytesLenUtf8(s) {
    return textEncoder.encode(String(s ?? "")).length;
  }

  // Title validation should match the Solidity contract constraints:
  // - UTF-8 byte length: 1..80
  // - Word count: 1..5
  // Word separators are ASCII whitespace only: space, tab, \n, \r.
  //
  // Returns a sanitized title (trimmed) if valid; throws otherwise.
  function validateTitleBasic(title) {
    const t = String(title ?? "").trim();
    const b = textEncoder.encode(t);
    if (b.length === 0 || b.length > 80) throw new Error("BAD_TITLE_LEN");

    let words = 0;
    let inWord = false;
    for (let i = 0; i < b.length; i++) {
      const c = b[i];
      const isSpace = (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d);
      if (isSpace) {
        if (inWord) inWord = false;
      } else {
        if (!inWord) {
          words++;
          if (words > 5) throw new Error("TITLE_TOO_MANY_WORDS");
          inWord = true;
        }
      }
    }

    if (words === 0) throw new Error("BAD_TITLE");
    return t;
  }

  function downloadText(filename, text) {
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  // -------- UI: confirm modal (custom button labels) --------
  // Used to force an explicit acknowledgement for critical user actions
  // such as key registration and minting.
  const _confirmModal = {
    mounted: false,
    open: false,
    resolver: null,
    onKeydown: null,
  };

  function _ensureConfirmModalMounted() {
    if (_confirmModal.mounted) return;
    _confirmModal.mounted = true;

    const backdrop = document.createElement('div');
    backdrop.id = 'cipnftConfirmModal';
    backdrop.className = 'cipnft-modal-backdrop';
    backdrop.innerHTML = `
      <div class="cipnft-modal" role="dialog" aria-modal="true" aria-labelledby="cipnftConfirmTitle">
        <div class="cipnft-modal-head">
          <div class="cipnft-modal-title" id="cipnftConfirmTitle">CONFIRM</div>
        </div>
        <div class="cipnft-modal-body" id="cipnftConfirmBody"></div>
        <div class="cipnft-modal-actions">
          <button class="btn small" id="cipnftConfirmCancel" type="button">CANCEL</button>
          <button class="btn small primary" id="cipnftConfirmOk" type="button">OK</button>
        </div>
      </div>
    `;
    document.body.appendChild(backdrop);

    const btnOk = backdrop.querySelector('#cipnftConfirmOk');
    const btnCancel = backdrop.querySelector('#cipnftConfirmCancel');

    const close = (result) => {
      if (!_confirmModal.open) return;
      _confirmModal.open = false;
      backdrop.classList.remove('show');
      document.body.classList.remove('cipnft-modal-open');
      try {
        if (_confirmModal.onKeydown) window.removeEventListener('keydown', _confirmModal.onKeydown);
      } catch (_) {}
      const r = _confirmModal.resolver;
      _confirmModal.resolver = null;
      if (typeof r === 'function') r(!!result);
    };

    btnOk.addEventListener('click', () => close(true));
    btnCancel.addEventListener('click', () => close(false));
    backdrop.addEventListener('click', (e) => {
      if (e && e.target === backdrop) close(false);
    });

    // Keep a reference so confirmModal can close on Escape.
    _confirmModal.onKeydown = (e) => {
      if (!_confirmModal.open) return;
      if (e.key === 'Escape') {
        e.preventDefault();
        close(false);
      }
    };

    // Expose internal close to the confirmModal function via closure.
    _confirmModal._close = close;
  }

  /**
   * Show a confirmation modal with custom button labels.
   *
   * @param {Object} opts
   * @param {string} [opts.title]
   * @param {string} [opts.messageHtml]
   * @param {string} [opts.okText]
   * @param {string} [opts.cancelText]
   * @returns {Promise<boolean>}
   */
  function confirmModal(opts = {}) {
    _ensureConfirmModalMounted();
    const backdrop = document.getElementById('cipnftConfirmModal');
    const titleEl = document.getElementById('cipnftConfirmTitle');
    const bodyEl = document.getElementById('cipnftConfirmBody');
    const btnOk = document.getElementById('cipnftConfirmOk');
    const btnCancel = document.getElementById('cipnftConfirmCancel');
    if (!backdrop || !titleEl || !bodyEl || !btnOk || !btnCancel) {
      // Fallback if DOM injection fails.
      return Promise.resolve(window.confirm(String(opts.messageHtml || opts.title || 'Confirm?')));
    }

    const title = (opts.title != null && String(opts.title).trim()) ? String(opts.title).trim() : 'CONFIRM';
    titleEl.textContent = title;

    const msg = (opts.messageHtml != null) ? String(opts.messageHtml) : '';
    bodyEl.innerHTML = msg;

    btnOk.textContent = (opts.okText != null && String(opts.okText).trim()) ? String(opts.okText).trim() : 'OK';
    btnCancel.textContent = (opts.cancelText != null && String(opts.cancelText).trim()) ? String(opts.cancelText).trim() : 'CANCEL';

    backdrop.classList.add('show');
    document.body.classList.add('cipnft-modal-open');
    _confirmModal.open = true;
    try { window.addEventListener('keydown', _confirmModal.onKeydown); } catch (_) {}
    try { btnOk.focus(); } catch (_) {}

    return new Promise((resolve) => {
      _confirmModal.resolver = resolve;
    });
  }

  function nativeSymbol() {
    const s = window.CIPNFT_CONFIG && window.CIPNFT_CONFIG.NATIVE_SYMBOL;
    return (typeof s === "string" && s.trim()) ? s.trim() : "L1";
  }

  function expectedChainId() {
    const v = window.CIPNFT_CONFIG && window.CIPNFT_CONFIG.EXPECTED_CHAIN_ID;
    if (v === null || v === undefined) return null;
    const n = Number(v);
    return Number.isFinite(n) ? n : null;
  }

  function toEtherString(weiBig) {
    // Back-compat: returns a decimal string for native-currency wei.
    try {
      return ethers.formatEther(weiBig);
    } catch {
      return String(weiBig);
    }
  }

  function toNativeString(weiBig) {
    return toEtherString(weiBig);
  }

  function deriveAAD() {
    // Bind AEAD to (chainId, contract) so ciphertext cannot be replayed to another contract.
    if (!state.chainId || !state.contractAddress) return new Uint8Array([]);
    const packed = ethers.solidityPacked(["uint256", "address"], [state.chainId, state.contractAddress]);
    return ethers.getBytes(packed);
  }

  // -------- Vendor loading (PQC) --------
  let _mlkem = null;
  async function getMLKEM() {
    if (_mlkem) return _mlkem;
    // Dynamic import keeps Classic mode lightweight.
    try {
      // Some environments (or extension sandboxes) do not expose CryptoKey/
      // FinalizationRegistry as globals. mlkem-wasm expects them.
      if (typeof globalThis.CryptoKey === "undefined") {
        globalThis.CryptoKey = class CryptoKey {};
      }
      if (typeof globalThis.FinalizationRegistry === "undefined") {
        globalThis.FinalizationRegistry = class FinalizationRegistry {
          constructor(_) {}
          register() {}
          unregister() {}
        };
      }
      const mod = await import("./vendor/mlkem.js");
      _mlkem = mod.default;
      return _mlkem;
    } catch (e) {
      throw new Error("ML-KEM module failed to load. Use a local HTTP server (not file://) and ensure vendor/mlkem.js exists.");
    }
  }

  function resolveInjectedProvider() {
    // If multiple wallets are installed, some inject window.ethereum.providers.
    // Prefer MetaMask when present; otherwise use the first.
    const eth = window.ethereum;
    if (!eth) {
      // Fallback to EIP-6963 discovery
      requestEip6963Providers();
      const list = _eip6963.providers;
      if (list.length > 0) {
        const mm = list.find(p => p && p.info && /metamask/i.test(p.info.name || ""));
        return (mm ? mm.provider : list[0].provider);
      }
      return null;
    }

    if (Array.isArray(eth.providers) && eth.providers.length > 0) {
      const mm = eth.providers.find(p => p && p.isMetaMask);
      return mm || eth.providers[0];
    }
    return eth;
  }

  function providerLabel(p) {
    if (!p) return "unknown";
    if (p.isMetaMask) return "metamask";
    if (p.isRabby) return "rabby";
    if (p.isCoinbaseWallet) return "coinbase";
    if (p.isBraveWallet) return "brave";
    return "wallet";
  }

  // -------- Wallet + contract --------
  async function init() {
    assertConfig();

    if (window.sodium && sodium.ready) {
      await sodium.ready;
    } else {
      throw new Error("libsodium not loaded");
    }
    if (!window.ethers) throw new Error("ethers not loaded");

    try {
      state.contractAddress = ethers.getAddress(window.CIPNFT_CONFIG.CONTRACT_ADDRESS);
    } catch (e) {
      throw new Error("Invalid CONTRACT_ADDRESS in config.js");
    }
    if (state.contractAddress === ethers.ZeroAddress) {
      // Keep the UI runnable, but make the error obvious at the point of use.
      state.contractOk = false;
      console.warn(
        "CIPNFT: CONTRACT_ADDRESS is still the zero address. Edit web/config.js and set CIPNFT_CONFIG.CONTRACT_ADDRESS to your deployed contract."
      );
    }
    state.contractAddr = state.contractAddress;
    state.ready = true;
    return state;
  }

  // -------- Read-only RPC (public reads) --------
  async function ensureReadProvider() {
    if (state.readProvider) return state.readProvider;

    const url = (window.CIPNFT_CONFIG && window.CIPNFT_CONFIG.RPC_URL)
      ? String(window.CIPNFT_CONFIG.RPC_URL)
      : "";
    if (!url) {
      throw new Error(
        "Missing CIPNFT_CONFIG.RPC_URL in config.js (needed for RPC default reads)."
      );
    }

    // ethers v6 JsonRpcProvider is appropriate for public reads.
    state.readProvider = new ethers.JsonRpcProvider(url);
    try {
      const net = await state.readProvider.getNetwork();
      state.readChainId = Number(net.chainId);
      // If wallet isn't connected yet, show chainId from RPC.
      if (!state.chainId) state.chainId = state.readChainId;
    } catch (_) {}
    return state.readProvider;
  }

  async function getReadContract() {
    if (state.readContract) return state.readContract;
    await init();
    const p = await ensureReadProvider();
    state.readContract = new ethers.Contract(state.contractAddress, ABI, p);
    return state.readContract;
  }

  async function ensureProvider() {
    let injected = resolveInjectedProvider();
    // If a wallet uses EIP-6963 without window.ethereum, it may announce asynchronously.
    if (!injected && !_eip6963.providers.length) {
      requestEip6963Providers();
      await new Promise(r => setTimeout(r, 60));
      injected = resolveInjectedProvider();
    }
    if (!injected) throw new Error("No injected wallet found. Install a wallet extension.");
    state.eip1193 = injected;
    state.walletLabel = providerLabel(injected);
    if (!state.provider) state.provider = new ethers.BrowserProvider(injected);
    // best-effort chainId fetch (works without requesting accounts)
    try {
      const net = await state.provider.getNetwork();
      state.chainId = Number(net.chainId);
    } catch (_) {}
    return state.provider;
  }

  async function assertContractDeployed() {
    await ensureProvider();
    const code = await state.provider.getCode(state.contractAddress);
    if (!code || code === "0x") {
      state.contractOk = false;
      const cid = state.chainId ? String(state.chainId) : "?";
      throw new Error(
        `No CIPNFT contract deployed at ${state.contractAddress} on chainId ${cid}. ` +
        `Switch network in your wallet or update web/config.js.`
      );
    }
    state.contractOk = true;
  }

  async function connectWallet() {
    // Mobile UX: if the user opens CIPNFT in a regular mobile browser (Chrome/Safari),
    // there may be no injected provider at all. In that case, "Connect Wallet" must
    // deep-link into a wallet app (MetaMask / Trust / etc.) to actually work.
    try {
      await ensureProvider();
    } catch (e) {
      const ua = String(navigator.userAgent || "");
      const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(ua);
      if (isMobile) {
        const host = location.host;
        const path = location.pathname + location.search + location.hash;
        // MetaMask deep-link format: https://metamask.app.link/dapp/<domain>/<path>
        // Note: path must not be URL-encoded as a whole; MM expects literal slashes.
        const mm = "https://metamask.app.link/dapp/" + host + (path.startsWith("/") ? path : ("/" + path));
        // Trust Wallet deep-link (best effort).
        const tw = "https://link.trustwallet.com/open_url?coin_id=60&url=" + encodeURIComponent(location.href);

        // Show a clear instruction and open MetaMask deep-link.
        alert(
          "No injected wallet was found in this browser.\n\n" +
          "To connect on mobile, open this page inside a wallet app (MetaMask / Trust Wallet), or install MetaMask and use the deep link.\n\n" +
          "Opening MetaMask…"
        );
        // Prefer MetaMask; user can copy/paste the Trust link if needed.
        try { window.location.href = mm; } catch (_) { window.open(mm, "_blank"); }

        // Also expose links in console for power users.
        console.log("MetaMask deep link:", mm);
        console.log("Trust Wallet link:", tw);
        return state;
      }
      throw e;
    }
    try {
      await state.provider.send("eth_requestAccounts", []);
    } catch (e) {
      // If multiple wallets are installed, MetaMask may fail to inject. This is outside
      // the dapp, but we can provide a clearer message.
      throw new Error(
        "Wallet connection failed. If you have multiple wallet extensions installed, disable all but one (e.g., MetaMask), then reload." +
        "\n\nOriginal: " + fmtErr(e)
      );
    }
    state.signer = await state.provider.getSigner();
    state.address = await state.signer.getAddress();
    const net = await state.provider.getNetwork();
    state.chainId = Number(net.chainId);
    state.contract = new ethers.Contract(state.contractAddress, ABI, state.signer);

    // Do not hard-fail connection just because the contract isn't on this chain.
    // We still want the UI to show the connected address and then display a clear
    // error explaining the missing deployment / wrong network.
    try {
      await assertContractDeployed();
    } catch (e) {
      // keep state.contractOk=false; caller can surface message
      state.contractOk = false;
    }

    // attempt to auto-load stored seeds
    loadClassicSeedFromStorage();
    loadPqcSeedFromStorage();

    // Only attempt to read protocol state if the contract is actually deployed.
    if (state.contractOk) {
      await refreshOnchain();
    }
    return state;
  }

  async function autoConnectIfAuthorized() {
    // Attempts to restore a prior connection without prompting.
    // Uses eth_accounts (no popup). Safe to call on every page load.
    await ensureProvider();
    let accounts = [];
    try {
      accounts = await state.provider.send("eth_accounts", []);
    } catch (_) {
      accounts = [];
    }
    if (!accounts || accounts.length === 0) {
      // Still load locally-stored seeds for login status.
      loadClassicSeedFromStorage();
      loadPqcSeedFromStorage();
      renderWalletHeader();
      return false;
    }

    try {
      state.signer = await state.provider.getSigner();
      state.address = await state.signer.getAddress();
    } catch (_) {
      // Some wallets may return accounts but still block getSigner without a request.
      renderWalletHeader();
      return false;
    }

    const net = await state.provider.getNetwork();
    state.chainId = Number(net.chainId);
    state.contract = new ethers.Contract(state.contractAddress, ABI, state.signer);

    // Auto-load stored seeds + login types
    loadClassicSeedFromStorage();
    loadPqcSeedFromStorage();

    // Best-effort contract check + state refresh
    try {
      await assertContractDeployed();
      await refreshOnchain();
    } catch (_) {}

    renderWalletHeader();
    return true;
  }

  async function bootstrap() {
    // Convenience helper used by page scripts.
    // 1) Initializes crypto dependencies
    // 2) Restores local key-login state (from localStorage)
    // 3) Restores a prior wallet connection without prompting (eth_accounts)
    await init();

    // Always prefer RPC for read-only bootstrapping (works without a wallet).
    try {
      await ensureReadProvider();
      if (state.readChainId && !state.chainId) state.chainId = state.readChainId;
    } catch (_) {}

    // Wallet is optional; attempt non-interactive discovery if present.
    try { await ensureProvider(); } catch (_) {}

    // Load UX preference for "active" key-login mode (classic vs pqc).
    loadPreferredEncModeFromStorage();

    try { await autoConnectIfAuthorized(); } catch (_) {}
    renderWalletHeader();
    return state;
  }

  async function refreshOnchain() {
    // IMPORTANT: Public reads MUST default to RPC (read provider), not the injected wallet.
    // This ensures the marketplace/terms load even when no wallet is present or the wallet
    // is on the wrong chain.
    await init();
    const p = await ensureReadProvider();

    // Verify deployment exists on the RPC chain.
    try {
      const code = await p.getCode(state.contractAddress);
      if (!code || code === "0x") {
        state.contractOk = false;
        const cid = state.readChainId ? String(state.readChainId) : "?";
        throw new Error(
          `No CIPNFT contract deployed at ${state.contractAddress} on RPC chainId ${cid}. ` +
          `Update web/config.js or point RPC_URL to the correct GenesisL1 RPC.`
        );
      }
      state.contractOk = true;
    } catch (e) {
      // If getCode itself fails (CORS / network), surface a clearer hint.
      if (!state.contractOk) {
        throw new Error(
          "Failed to reach RPC or read contract code. If this happens only on your HTTPS domain, " +
          "your RPC must be HTTPS and must allow browser CORS (Access-Control-Allow-Origin).\n\n" +
          fmtErr(e)
        );
      }
    }

    const c = await getReadContract();

    let adm;
    try {
      adm = await c.admin();
    } catch (e) {
      throw new Error("Failed to read contract state over RPC. Is this the correct CIPNFT deployment for this UI/ABI?\n\n" + fmtErr(e));
    }
    const tv = await c.tosVersionCurrent();
    const th = await c.tosHash(tv);
    const pb = await c.perByteFeeWei();
    const ff = await c.flatMintFeeWei();
    const md = await c.maxOfferDurationSec();
    const mp = await c.minOfferPriceWei();
    state.admin = adm;
    state.tosVersionCurrent = Number(tv);
    state.tosHashCurrent = th;
    state.perByteFeeWei = BigInt(pb.toString());
    state.flatMintFeeWei = BigInt(ff.toString());
    state.maxOfferDurationSec = Number(md);
    state.minOfferPriceWei = BigInt(mp.toString());

    if (state.address) {
      const ok = await c.tosAccepted(state.address, state.tosVersionCurrent);
      state.tosAcceptedCurrent = !!ok;

      // Cache on-chain key registration status for the connected wallet.
      // This is used to keep the UI logic honest: "ready" means the user has
      // both a local key (seed) AND a registered public key on-chain.
      try {
        const pkRef = await c.encryptionPubKey(state.address);
        state.classicOnchainPubKeyRef = pkRef;
      } catch (_) {
        state.classicOnchainPubKeyRef = null;
      }

      try {
        const pk2 = await c.pqcPubKey(state.address);
        const bytes = ethers.getBytes(pk2);
        state.pqcOnchainPubKeyLen = bytes.length;
      } catch (_) {
        state.pqcOnchainPubKeyLen = null;
      }
    } else {
      state.classicOnchainPubKeyRef = null;
      state.pqcOnchainPubKeyLen = null;
    }
    return state;
  }

  async function acceptCurrentTos() {
    if (!state.contract || !state.signer) throw new Error("Connect wallet first.");
    await refreshOnchain();
    const v = state.tosVersionCurrent;
    const tx = await state.contract.acceptTos(v);
    await tx.wait();
    await refreshOnchain();
    return tx.hash;
  }

  // -------- Local storage keys --------
  function _lsKey(kind) {
    const addr = (state.address || "0x0").toLowerCase();
    const chain = String(state.chainId || 0);
    const ca = (state.contractAddress || "0x0").toLowerCase();
    return `cipnft:${kind}:${chain}:${ca}:${addr}`;
  }

  // A global (non-identity-bound) localStorage key for UX preference.
  // This allows the UI to remember whether the user currently treats
  // Classic vs Quantum-resistant as the "active" key-login mode.
  function _lsPrefEncModeKey() {
    const chain = String(state.chainId || 0);
    const ca = (state.contractAddress || "0x0").toLowerCase();
    return `cipnft:preferredEncMode:${chain}:${ca}`;
  }

  function loadPreferredEncModeFromStorage() {
    try {
      const v = localStorage.getItem(_lsPrefEncModeKey());
      if (v === "classic" || v === "pqc") state.preferredEncMode = v;
    } catch {}
  }

  function setPreferredEncMode(mode) {
    const m = String(mode || "").toLowerCase();
    if (m !== "classic" && m !== "pqc") return;
    state.preferredEncMode = m;
    try { localStorage.setItem(_lsPrefEncModeKey(), m); } catch {}
    renderWalletHeader();
  }

  // -------- Classic (X25519) key management --------
  function _setClassicFromSeedBytes(seed32, loginType) {
    if (!(seed32 instanceof Uint8Array) || seed32.length !== 32) throw new Error("Classic seed must be 32 bytes");
    const kp = sodium.crypto_box_seed_keypair(seed32);
    state.classicSeedHex = ethers.hexlify(seed32);
    state.classicLoginType = loginType || state.classicLoginType || "signed";
    state.classicEncPublicKey = kp.publicKey;
    state.classicEncPrivateKey = kp.privateKey;
    // legacy aliases
    state.seedHex = state.classicSeedHex;
    state.encPublicKey = state.classicEncPublicKey;
    state.encPrivateKey = state.classicEncPrivateKey;
    try {
      localStorage.setItem(_lsKey("classicSeed"), state.classicSeedHex);
      localStorage.setItem(_lsKey("classicLoginType"), state.classicLoginType || "signed");
    } catch {}
    return { seedHex: state.classicSeedHex, pubKeyHex: ethers.hexlify(state.classicEncPublicKey) };
  }

  function loadClassicSeedFromStorage() {
    try {
      const v = localStorage.getItem(_lsKey("classicSeed"));
      if (v) {
        const b = ethers.getBytes(v);
        const t = localStorage.getItem(_lsKey("classicLoginType")) || "signed";
        if (b.length === 32) _setClassicFromSeedBytes(b, t);
      }
    } catch {}
  }

  async function deriveKeyFromSignature() {
    // legacy name: derives the Classic X25519 identity
    if (!state.signer || !state.address) throw new Error("Connect wallet first.");

    const origin = (location && location.origin) ? location.origin : "unknown";
    const msg =
`CIPNFT Classic Encryption Key Derivation v2

This signature derives a local encryption key used to encrypt/decrypt CIPNFT on-chain ciphertext.

Origin: ${origin}
Account: ${state.address}
Chain ID: ${state.chainId}
Contract: ${state.contractAddress}

Security notes:
- Do NOT sign this message on untrusted sites.
- Back up the derived seed (EXPORT). Some wallets may produce different signatures each time.`;

    const sig = await state.signer.signMessage(msg);
    const sigBytes = ethers.getBytes(sig);

    // Seed = keccak256(signatureBytes). This is secret unless the signature is revealed.
    const seedHex = ethers.keccak256(sigBytes);
    const seed32 = ethers.getBytes(seedHex);

    // Treat Classic as the active key-login mode.
    setPreferredEncMode("classic");
    return _setClassicFromSeedBytes(seed32, "signed");
  }

  function importSeed(seedHex) {
    // legacy name: imports Classic seed
    if (!seedHex) throw new Error("Missing seed");
    const b = ethers.getBytes(seedHex);
    setPreferredEncMode("classic");
    return _setClassicFromSeedBytes(b, "imported");
  }

  function clearSeed() {
    state.classicSeedHex = null;
    state.classicLoginType = null;
    state.classicEncPublicKey = null;
    state.classicEncPrivateKey = null;
    // legacy aliases
    state.seedHex = null;
    state.encPublicKey = null;
    state.encPrivateKey = null;
    try {
      localStorage.removeItem(_lsKey("classicSeed"));
      localStorage.removeItem(_lsKey("classicLoginType"));
    } catch {}
  }

  async function registerPubKey() {
    // legacy name: registers Classic pubkey
    if (!state.contract || !state.signer) throw new Error("Connect wallet first.");
    if (!state.classicEncPublicKey) throw new Error("Derive/import your Classic key first.");
    const pubHex = ethers.hexlify(state.classicEncPublicKey);
    const tx = await state.contract.setEncryptionPublicKey(pubHex);
    await tx.wait();
    return tx.hash;
  }

  async function getMyOnchainPubKey() {
    const c = await getReadContract();
    if (!state.address) throw new Error("Connect wallet first.");
    return await c.encryptionPubKey(state.address);
  }

  async function ensureClassicKey() {
    if (state.classicEncPublicKey && state.classicEncPrivateKey) return true;
    loadClassicSeedFromStorage();
    if (state.classicEncPublicKey && state.classicEncPrivateKey) return true;
    throw new Error("Classic encryption key not set. Click DERIVE/IMPORT.");
  }

  // -------- PQC (ML-KEM-768) key management --------
  async function _setPqcFromSeedBytes(seedBytes, loginType) {
    const mlkem = await getMLKEM();
    // Import private key seed and derive public key.
    const sk = await mlkem.importKey(
      "raw-seed",
      seedBytes,
      { name: "ML-KEM-768" },
      false,
      ["decapsulateBits"]
    );
    const pk = await mlkem.getPublicKey(sk, ["encapsulateBits"]);
    const pkBytes = new Uint8Array(await mlkem.exportKey("raw-public", pk));

    if (pkBytes.length !== PQC_PUBKEY_BYTES) throw new Error(`Unexpected PQ public key length: ${pkBytes.length}`);

    state.pqcSeedHex = ethers.hexlify(seedBytes);
    state.pqcLoginType = loginType || state.pqcLoginType || "generated";
    state.pqcPubKeyBytes = pkBytes;
    try {
      localStorage.setItem(_lsKey("pqcSeed"), state.pqcSeedHex);
      localStorage.setItem(_lsKey("pqcLoginType"), state.pqcLoginType || "generated");
    } catch {}
    return { seedHex: state.pqcSeedHex, pubKeyLen: pkBytes.length, pubKeyHash: ethers.keccak256(pkBytes) };
  }

  function loadPqcSeedFromStorage() {
    try {
      const v = localStorage.getItem(_lsKey("pqcSeed"));
      if (v) {
        // defer actual import until needed (because it requires module)
        state.pqcSeedHex = v;
        state.pqcLoginType = localStorage.getItem(_lsKey("pqcLoginType")) || state.pqcLoginType;
      }
    } catch {}
  }

  async function ensurePqcKey() {
    if (state.pqcPubKeyBytes && state.pqcSeedHex) return true;
    loadPqcSeedFromStorage();
    if (state.pqcSeedHex && !state.pqcPubKeyBytes) {
      const seed = ethers.getBytes(state.pqcSeedHex);
      await _setPqcFromSeedBytes(seed, state.pqcLoginType || "generated");
      return true;
    }
    if (state.pqcSeedHex && state.pqcPubKeyBytes) return true;
    throw new Error("PQC key not set. Generate/derive/import your PQC seed first.");
  }

  async function generatePqcKey() {
    const mlkem = await getMLKEM();
    const { publicKey, privateKey } = await mlkem.generateKey(
      { name: "ML-KEM-768" },
      true,
      ["encapsulateBits", "decapsulateBits"]
    );
    const seedBytes = new Uint8Array(await mlkem.exportKey("raw-seed", privateKey));
    setPreferredEncMode("pqc");
    return await _setPqcFromSeedBytes(seedBytes, "generated");
  }

  async function derivePqcKeyFromSignature() {
    if (!state.signer || !state.address) throw new Error("Connect wallet first.");
    const origin = (location && location.origin) ? location.origin : "unknown";
    const msg =
`CIPNFT PQC Encryption Key Seed v1 (ML-KEM-768)

This signature derives a local post-quantum key seed used to decrypt PQ-enveloped CIPNFT tokens.

Origin: ${origin}
Account: ${state.address}
Chain ID: ${state.chainId}
Contract: ${state.contractAddress}

Security notes:
- Do NOT sign this message on untrusted sites.
- Back up the derived seed (EXPORT). Some wallets may produce different signatures each time.`;

    const sig = await state.signer.signMessage(msg);
    const sigBytes = ethers.getBytes(sig);

    // Derive 64 bytes from signature bytes (BLAKE2b via libsodium generichash).
    const seed = sodium.crypto_generichash(64, sigBytes);
    setPreferredEncMode("pqc");
    return await _setPqcFromSeedBytes(seed, "signed");
  }

  async function importPqcSeed(seedHex) {
    if (!seedHex) throw new Error("Missing PQC seed");
    const b = ethers.getBytes(seedHex);
    setPreferredEncMode("pqc");
    return await _setPqcFromSeedBytes(b, "imported");
  }

  function clearPqcSeed() {
    state.pqcSeedHex = null;
    state.pqcLoginType = null;
    state.pqcPubKeyBytes = null;
    try {
      localStorage.removeItem(_lsKey("pqcSeed"));
      localStorage.removeItem(_lsKey("pqcLoginType"));
    } catch {}
  }

  async function registerPqcPubKey() {
    if (!state.contract || !state.signer) throw new Error("Connect wallet first.");
    await ensurePqcKey();
    const tx = await state.contract.setPqcPublicKey(state.pqcPubKeyBytes);
    await tx.wait();
    return tx.hash;
  }

  async function getMyOnchainPqcPubKey() {
    const c = await getReadContract();
    if (!state.address) throw new Error("Connect wallet first.");
    const b = await c.pqcPubKey(state.address);
    const bytes = ethers.getBytes(b);
    return bytes;
  }

  async function getOnchainPqcPubKey(addr) {
    const c = await getReadContract();
    const b = await c.pqcPubKey(addr);
    return ethers.getBytes(b);
  }

  // -------- View key --------
  function randomViewKeyText() {
    // Strong view key: 32 random bytes encoded as base64url (copy/paste friendly)
    const b = sodium.randombytes_buf(32);
    // base64url
    let s = btoa(String.fromCharCode(...b));
    s = s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    return s;
  }

  function viewKeyToSymmetricKey(viewKeyText) {
    // Derive a 32-byte symmetric key from the viewKey text using BLAKE2b (libsodium generichash).
    const m = textEncoder.encode(String(viewKeyText));
    const k = sodium.crypto_generichash(32, m);
    return k;
  }

  // -------- Encryption / decryption --------
  function _encryptMetaCipher(plaintextBytes, dekBytes) {
    const aad = deriveAAD();
    const nonce = sodium.randombytes_buf(NONCE_BYTES);
    const cipher = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintextBytes, aad, null, nonce, dekBytes);
    const metaCipher = new Uint8Array(nonce.length + cipher.length);
    metaCipher.set(nonce, 0);
    metaCipher.set(cipher, nonce.length);
    return metaCipher;
  }

  function _wrapViewKey(dekBytes, viewKeyText) {
    const vkKey = viewKeyToSymmetricKey(viewKeyText);
    const vnonce = sodium.randombytes_buf(NONCE_BYTES);
    const vc = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(dekBytes, null, null, vnonce, vkKey);
    const viewWrap = new Uint8Array(vnonce.length + vc.length);
    viewWrap.set(vnonce, 0);
    viewWrap.set(vc, vnonce.length);
    return viewWrap;
  }

  function _wrapDekClassic(dekBytes, ownerPubKeyBytes32) {
    if (!ownerPubKeyBytes32 || ownerPubKeyBytes32.length !== 32) throw new Error("Invalid Classic owner pubkey");
    return sodium.crypto_box_seal(dekBytes, ownerPubKeyBytes32);
  }

  async function _wrapDekPqc(dekBytes, ownerPqcPubKeyBytes) {
    if (!ownerPqcPubKeyBytes || ownerPqcPubKeyBytes.length !== PQC_PUBKEY_BYTES) {
      throw new Error(`Invalid PQC owner pubkey (need ${PQC_PUBKEY_BYTES} bytes)`);
    }
    const mlkem = await getMLKEM();
    const pk = await mlkem.importKey("raw-public", ownerPqcPubKeyBytes, { name: "ML-KEM-768" }, true, ["encapsulateBits"]);
    const { ciphertext, sharedKey } = await mlkem.encapsulateBits({ name: "ML-KEM-768" }, pk);

    const ctBytes = new Uint8Array(ciphertext);
    const shared = new Uint8Array(sharedKey);
    if (ctBytes.length !== PQC_KEM_CT_BYTES) throw new Error(`Unexpected KEM ciphertext length: ${ctBytes.length}`);
    if (shared.length !== 32) throw new Error(`Unexpected KEM shared key length: ${shared.length}`);

    const aad = deriveAAD();
    const nonce = sodium.randombytes_buf(NONCE_BYTES);
    const wrapped = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(dekBytes, aad, null, nonce, shared);
    // envelope = kemCt(1088) || nonce(24) || wrappedDek(48)
    const env = new Uint8Array(ctBytes.length + nonce.length + wrapped.length);
    env.set(ctBytes, 0);
    env.set(nonce, ctBytes.length);
    env.set(wrapped, ctBytes.length + nonce.length);
    return env;
  }

  async function encryptMetadata(plaintextUtf8, ownerKeyBytes, opts) {
    const plaintext = textEncoder.encode(String(plaintextUtf8 ?? ""));
    if (plaintext.length > MAX_PLAINTEXT) throw new Error(`Plaintext too large: ${plaintext.length} bytes (max ${MAX_PLAINTEXT})`);

    const encMode = (opts && typeof opts.encMode === "number") ? opts.encMode : ENC_MODE_CLASSIC;

    const dek = sodium.randombytes_buf(32);
    const metaCipher = _encryptMetaCipher(plaintext, dek);

    let ownerEncDEK;
    if (encMode === ENC_MODE_CLASSIC) {
      ownerEncDEK = _wrapDekClassic(dek, ownerKeyBytes);
      if (ownerEncDEK.length !== OWNER_ENVELOPE_BYTES_CLASSIC) throw new Error("Classic envelope length mismatch");
    } else if (encMode === ENC_MODE_PQC) {
      ownerEncDEK = await _wrapDekPqc(dek, ownerKeyBytes);
      if (ownerEncDEK.length !== PQC_OWNER_ENVELOPE_BYTES) throw new Error("PQC envelope length mismatch");
    } else {
      throw new Error("Unknown encMode");
    }

    const dekHash = ethers.keccak256(dek);

    // optional viewWrap
    let viewWrap = new Uint8Array([]);
    if (opts && opts.enableViewKey) {
      const vkText = opts.viewKeyText;
      if (!vkText || vkText.length < 16) throw new Error("View key missing");
      viewWrap = _wrapViewKey(dek, vkText);
      if (viewWrap.length !== VIEW_WRAP_BYTES) throw new Error("viewWrap length mismatch");
    }

    return {
      plaintextBytes: plaintext.length,
      dek,
      dekHash,
      metaCipher,
      ownerEncDEK,
      viewWrap,
      encMode
    };
  }

  function decryptMetaCipher(metaCipherBytes, dekBytes) {
    if (!metaCipherBytes || metaCipherBytes.length < NONCE_BYTES + AEAD_TAG_BYTES) throw new Error("Invalid metaCipher");
    const nonce = metaCipherBytes.slice(0, NONCE_BYTES);
    const cipher = metaCipherBytes.slice(NONCE_BYTES);
    const aad = deriveAAD();
    const pt = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, cipher, aad, nonce, dekBytes);
    return textDecoder.decode(pt);
  }

  async function _unwrapDekClassic(ownerEncDEKBytes) {
    if (!ownerEncDEKBytes || ownerEncDEKBytes.length !== OWNER_ENVELOPE_BYTES_CLASSIC) throw new Error("Invalid Classic ownerEncDEK");
    await ensureClassicKey();
    const dek = sodium.crypto_box_seal_open(ownerEncDEKBytes, state.classicEncPublicKey, state.classicEncPrivateKey);
    state.lastDEK = dek;
    return dek;
  }

  async function _unwrapDekPqc(ownerEncDEKBytes) {
    if (!ownerEncDEKBytes || ownerEncDEKBytes.length !== PQC_OWNER_ENVELOPE_BYTES) throw new Error("Invalid PQC ownerEncDEK");
    await ensurePqcKey();

    const kemCt = ownerEncDEKBytes.slice(0, PQC_KEM_CT_BYTES);
    const nonce = ownerEncDEKBytes.slice(PQC_KEM_CT_BYTES, PQC_KEM_CT_BYTES + NONCE_BYTES);
    const wrapped = ownerEncDEKBytes.slice(PQC_KEM_CT_BYTES + NONCE_BYTES);

    const mlkem = await getMLKEM();
    const skSeed = ethers.getBytes(state.pqcSeedHex);
    const sk = await mlkem.importKey("raw-seed", skSeed, { name: "ML-KEM-768" }, false, ["decapsulateBits"]);
    const sharedKey = await mlkem.decapsulateBits({ name: "ML-KEM-768" }, sk, kemCt);
    const shared = new Uint8Array(sharedKey);
    if (shared.length !== 32) throw new Error("Unexpected KEM shared key length");

    const aad = deriveAAD();
    const dek = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, wrapped, aad, nonce, shared);
    state.lastDEK = dek;
    return dek;
  }

  async function decryptDEKAsOwner(ownerEncDEKBytes, encMode) {
    const mode = (typeof encMode === "number") ? encMode : (
      ownerEncDEKBytes && ownerEncDEKBytes.length === PQC_OWNER_ENVELOPE_BYTES ? ENC_MODE_PQC : ENC_MODE_CLASSIC
    );

    if (mode === ENC_MODE_CLASSIC) return await _unwrapDekClassic(ownerEncDEKBytes);
    if (mode === ENC_MODE_PQC) return await _unwrapDekPqc(ownerEncDEKBytes);
    throw new Error("Unknown encMode");
  }

  function decryptDEKWithViewKey(viewWrapBytes, viewKeyText) {
    if (!viewWrapBytes || viewWrapBytes.length !== VIEW_WRAP_BYTES) throw new Error("No viewWrap enabled on token");
    const vkKey = viewKeyToSymmetricKey(viewKeyText);
    const nonce = viewWrapBytes.slice(0, NONCE_BYTES);
    const cipher = viewWrapBytes.slice(NONCE_BYTES);
    const dek = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, cipher, null, nonce, vkKey);
    return dek;
  }

  function verifyDekHash(dekBytes, dekHashHex) {
    const h = ethers.keccak256(dekBytes);
    if (h.toLowerCase() !== String(dekHashHex).toLowerCase()) {
      throw new Error("DEK hash mismatch (wrong key / wrong envelope)");
    }
    return true;
  }

  // -------- High-level flows --------
  async function mintEncrypted({ title, plaintextUtf8, enableViewKey, viewKeyText, encMode }) {
    if (!state.contract || !state.signer) throw new Error("Connect wallet first.");
    await refreshOnchain();

    const mode = (typeof encMode === "number") ? encMode : ENC_MODE_CLASSIC;

    if (!state.tosAcceptedCurrent) {
      throw new Error(`You must accept the current Terms (v${state.tosVersionCurrent}).`);
    }

    const t = (title ?? "").toString().trim();
    validateTitleBasic(t);

    let ownerKeyBytes;
    if (mode === ENC_MODE_CLASSIC) {
      await ensureClassicKey();
      const onchainPub = await getMyOnchainPubKey();
      if (!onchainPub || onchainPub === ethers.ZeroHash) throw new Error("No on-chain Classic pubkey registered.");
      const localPubHex = ethers.hexlify(state.classicEncPublicKey).toLowerCase();
      if (String(onchainPub).toLowerCase() !== localPubHex) {
        throw new Error("Your local Classic pubkey does not match the on-chain pubkey for this address. Import the correct seed or re-register the pubkey.");
      }
      ownerKeyBytes = state.classicEncPublicKey;
    } else if (mode === ENC_MODE_PQC) {
      await ensurePqcKey();
      const onchainPk = await getMyOnchainPqcPubKey();
      if (!onchainPk || onchainPk.length !== PQC_PUBKEY_BYTES) throw new Error("No on-chain PQC pubkey registered.");
      const localHash = ethers.keccak256(state.pqcPubKeyBytes);
      const onchainHash = ethers.keccak256(onchainPk);
      if (localHash.toLowerCase() !== onchainHash.toLowerCase()) {
        throw new Error("Your local PQC public key does not match the on-chain PQC public key. Import the correct PQC seed or re-register.");
      }
      ownerKeyBytes = state.pqcPubKeyBytes;
    } else {
      throw new Error("Unknown encMode");
    }

    const enc = await encryptMetadata(plaintextUtf8, ownerKeyBytes, { enableViewKey, viewKeyText, encMode: mode });

    const requiredFee = await state.contract.mintFeeFor(enc.plaintextBytes);
    const req = BigInt(requiredFee.toString());

    const tx = await state.contract.mint(
      t,
      enc.metaCipher,
      enc.ownerEncDEK,
      enc.dekHash,
      enc.viewWrap,
      mode,
      { value: req }
    );
    const rcpt = await tx.wait();

    // Extract tokenId from Minted event
    let tokenId = null;
    for (const log of rcpt.logs || []) {
      try {
        const parsed = state.contract.interface.parseLog(log);
        if (parsed && parsed.name === "Minted") {
          tokenId = Number(parsed.args.tokenId);
          break;
        }
      } catch (_) {
        // ignore non-contract logs
      }
    }

    return { tokenId, txHash: tx.hash, receipt: rcpt, plaintextBytes: enc.plaintextBytes, feeWei: req };
  }

    async function getTokenBundle(tokenId) {
    const c = await getReadContract();

    const [metaCipher, ownerEncDEK, viewWrap, dekHash] = await c.getTokenData(tokenId);
    const encMode = Number(await c.encryptionMode(tokenId));
    const owner = await c.ownerOf(tokenId);
    const title = await c.titleOf(tokenId);
    const listing = await c.listings(tokenId);
    const tosVersion = Number(await c.tosVersionOf(tokenId));
    const erase = await c.getEraseState(tokenId);

    const open = !!listing[0];
    const priceWei = BigInt(listing[1].toString());

    return {
      tokenId: Number(tokenId),
      title,
      encMode,

      owner,
      open,
      listed: open, // alias

      priceWei,
      tosVersion,

      eraseActive: Boolean(erase[0]),

      eraseField: Number(erase[1]),
      eraseNextWord: Number(erase[2]),

      metaCipherHex: metaCipher,
      ownerEncDEKHex: ownerEncDEK,
      viewWrapHex: viewWrap,
      dekHash,

      metaCipherBytes: ethers.getBytes(metaCipher),
      ownerEncDEKBytes: ethers.getBytes(ownerEncDEK),
      viewWrapBytes: ethers.getBytes(viewWrap)
    };
  }

  async function deliverOffer({ tokenId, buyerAddr, keepViewWrap, newViewKeyText }) {
    if (!state.contract || !state.signer) throw new Error("Connect wallet first.");

    const bundle = await getTokenBundle(tokenId);
    const dek = await decryptDEKAsOwner(bundle.ownerEncDEKBytes, bundle.encMode);
    verifyDekHash(dek, bundle.dekHash);

    const offer = await getOffer(tokenId, buyerAddr);
    if (!offer || offer.expiry === 0) throw new Error("No active offer for this buyer/token.");
    if (offer.expiry !== 0 && offer.expiry < nowSec()) throw new Error("Offer is expired.");
    if (offer.buyerKeyRef === ethers.ZeroHash) throw new Error("Offer has no buyer key snapshot.");

    let newOwnerEncDEK;
    if (bundle.encMode === ENC_MODE_CLASSIC) {
      const buyerPubBytes = ethers.getBytes(offer.buyerKeyRef);
      newOwnerEncDEK = sodium.crypto_box_seal(dek, buyerPubBytes);
    } else {
      const buyerPk = await getOnchainPqcPubKey(buyerAddr);
      if (!buyerPk || buyerPk.length !== PQC_PUBKEY_BYTES) throw new Error("Buyer has no PQC pubkey registered.");
      const h = ethers.keccak256(buyerPk);
      if (h.toLowerCase() !== String(offer.buyerKeyRef).toLowerCase()) throw new Error("Buyer PQC key changed since offer. Ask buyer to re-offer.");
      newOwnerEncDEK = await _wrapDekPqc(dek, buyerPk);
    }

    // viewWrap choice
    let newViewWrapBytes = new Uint8Array([]);
    if (keepViewWrap) {
      newViewWrapBytes = bundle.viewWrapBytes;
    } else if (newViewKeyText) {
      newViewWrapBytes = _wrapViewKey(dek, newViewKeyText);
    }

    const tx = await state.contract.deliverOffer(
      tokenId,
      buyerAddr,
      newOwnerEncDEK,
      newViewWrapBytes
    );
    await tx.wait();
    return tx.hash;
  }

  async function verifyDeliveryForBuyer(tokenId, buyerAddr) {
    const bundle = await getTokenBundle(tokenId);
    const del = await getDelivery(tokenId, buyerAddr);
    if (!del.deliveredAt) return { ok: false, reason: "NOT_DELIVERED" };

    let dek;
    try {
      dek = await decryptDEKAsOwner(del.ownerEncDEKBytes, bundle.encMode);
    } catch (_) {
      return { ok: false, reason: "DECRYPT_FAILED" };
    }

    try {
      verifyDekHash(dek, bundle.dekHash);
    } catch (_) {
      return { ok: false, reason: "HASH_MISMATCH" };
    }

    // Require that the ciphertext decrypts successfully before allowing finalize.
    // This prevents "valid DEK hash but unusable payload" edge cases.
    try {
      decryptMetaCipher(bundle.metaCipherBytes, dek);
    } catch (_) {
      return { ok: false, reason: "META_DECRYPT_FAILED" };
    }

    return { ok: true };
  }

  async function finalizeOffer(tokenId) {
    if (!state.contract || !state.signer) throw new Error("Connect wallet first.");
    const chk = await verifyDeliveryForBuyer(tokenId, state.address);
    if (!chk.ok) throw new Error(`Delivery verification failed: ${chk.reason}`);
    const tx = await state.contract.finalizeOffer(tokenId);
    await tx.wait();
    return tx.hash;
  }

  // -------- Contract helpers (unchanged) --------
  async function setListing(tokenId, open, priceWei) {
    if (!state.contract || !state.signer) throw new Error("Connect wallet first.");
    const tx = await state.contract.setListing(tokenId, open, priceWei);
    await tx.wait();
    return tx.hash;
  }

  async function getListed(cursor, size) {
    const c = await getReadContract();
    const nBig = await c.listedCount();
    const n = BigInt(nBig.toString());
    const cur = BigInt(cursor);
    const sz = BigInt(size);
    if (cur >= n) {
      return { tokenIds: [], prices: [], pricesWei: [], newCursor: Number(cur) };
    }
    let end = cur + sz;
    if (end > n) end = n;
    const outLen = Number(end - cur);
    const idxs = Array.from({ length: outLen }, (_, i) => cur + BigInt(i));

    // Fetch tokenIds from the on-chain listed index
    const idsRaw = await Promise.all(idxs.map((ix) => c.listedTokenAt(ix)));
    const tokenIds = idsRaw.map((x) => Number(x.toString()));

    // Fetch prices (listing struct is public)
    const pricesOut = await Promise.all(idsRaw.map(async (tid) => {
      const r = await c.listings(tid);
      const price = (r.priceWei !== undefined) ? r.priceWei : r[1];
      return BigInt(price.toString());
    }));

    return {
      tokenIds,
      prices: pricesOut,
      pricesWei: pricesOut,
      newCursor: Number(end)
    };
  }

  // Latest-first listing pagination.
  // pageIndex = 0 means "newest" (last listed) page.
  // Returns tokenIds ordered newest → oldest.
  async function getListedLatest(pageIndex, pageSize) {
    const c = await getReadContract();
    const nBig = await c.listedCount();
    const total = Number(nBig.toString());
    const sz = Math.max(1, Math.min(50, Number(pageSize || 6)));
    if (total === 0) {
      return { tokenIds: [], prices: [], pricesWei: [], total: 0, pageIndex: 0, totalPages: 0 };
    }
    const totalPages = Math.max(1, Math.ceil(total / sz));
    const p = Math.max(0, Math.min(totalPages - 1, Number(pageIndex || 0)));

    const endExclusive = total - (p * sz);              // exclusive
    const start = Math.max(0, endExclusive - sz);       // inclusive

    const idxs = [];
    for (let i = endExclusive - 1; i >= start; i--) idxs.push(BigInt(i));

    const idsRaw = await Promise.all(idxs.map(ix => c.listedTokenAt(ix)));
    const tokenIds = idsRaw.map(x => Number(x.toString()));
    const pricesOut = await Promise.all(idsRaw.map(async (tid) => {
      const r = await c.listings(tid);
      const price = (r.priceWei !== undefined) ? r.priceWei : r[1];
      return BigInt(price.toString());
    }));

    return {
      tokenIds,
      prices: pricesOut,
      pricesWei: pricesOut,
      total,
      pageIndex: p,
      totalPages
    };
  }



  async function getTokenCard(tokenId) {
    const c = await getReadContract();
    const res = await c.getTokenCard(tokenId);
    const title = (res.title !== undefined) ? res.title : res[0];
    const encMode = Number((res.encMode !== undefined) ? res.encMode : res[1]);
    const open = Boolean((res.open !== undefined) ? res.open : res[2]);
    const priceWei = BigInt(((res.priceWei !== undefined) ? res.priceWei : res[3]).toString());
    const cipherLen = Number(((res.cipherLen !== undefined) ? res.cipherLen : res[4]).toString());
    const dekHash = (res.dekHash !== undefined) ? res.dekHash : res[5];
    const cipherPreviewHex = (res.cipherPreview !== undefined) ? res.cipherPreview : res[6];
    const tosVersion = Number(((res.tosVersion !== undefined) ? res.tosVersion : res[7]).toString());

    return {
      tokenId: Number(tokenId),
      title,
      encMode,
      open,
      priceWei,
      cipherLen,
      dekHash,
      cipherPreviewHex,
      tosVersion
    };
  }

  async function setTitle(tokenId, newTitle) {
    if (!state.contract || !state.signer) throw new Error("Connect wallet first.");
    const t = validateTitleBasic(newTitle);
    const tx = await state.contract.setTitle(tokenId, t);
    await tx.wait();
    return tx.hash;
  }

  function cipherPreviewText(hexStr, maxChars = 300) {
    const s = String(hexStr || "");
    if (!s) return "—";
    if (s.length <= maxChars) return s;
    return s.slice(0, maxChars) + "…";
  }
  async function createOffer(tokenId, expiry, valueWei) {
    if (!state.contract || !state.signer) throw new Error("Connect wallet first.");
    const tx = await state.contract.createOffer(tokenId, expiry, { value: valueWei });
    await tx.wait();
    return tx.hash;
  }

  async function cancelOffer(tokenId) {
    if (!state.contract || !state.signer) throw new Error("Connect wallet first.");
    const tx = await state.contract.cancelOffer(tokenId);
    await tx.wait();
    return tx.hash;
  }

  async function refundExpiredOffer(tokenId, buyerAddr) {
    if (!state.contract || !state.signer) throw new Error("Connect wallet first.");
    const tx = await state.contract.refundExpiredOffer(tokenId, buyerAddr);
    await tx.wait();
    return tx.hash;
  }

  async function getOffer(tokenId, buyerAddr) {
    const c = await getReadContract();
    const [amountWei, expiry, buyerKeyRef] = await c.getOffer(tokenId, buyerAddr);
    return {
      amountWei: BigInt(amountWei.toString()),
      expiry: Number(expiry),
      buyerKeyRef
    };
  }


  async function getOffersForToken(tokenId, cursor = 0, size = 50) {
    const c = await getReadContract();
    const nBig = await c.offerCount(tokenId);
    const n = BigInt(nBig.toString());
    const cur = BigInt(cursor);
    const sz = BigInt(size);
    if (cur >= n) return { rows: [], newCursor: Number(cur) };
    let end = cur + sz;
    if (end > n) end = n;
    const outLen = Number(end - cur);
    const idxs = Array.from({ length: outLen }, (_, i) => cur + BigInt(i));

    const buyers = await Promise.all(idxs.map((ix) => c.offerBuyerAt(tokenId, ix)));

    const offers = await Promise.all(buyers.map((b) => c.getOffer(tokenId, b)));
    const dels = await Promise.all(buyers.map((b) => c.getDelivery(tokenId, b)));

    const rows = buyers.map((b, i) => {
      const o = offers[i];
      const d = dels[i];
      const amountWei = o.amountWei !== undefined ? o.amountWei : o[0];
      const expiry = o.expiry !== undefined ? o.expiry : o[1];
      const buyerKeyRef = o.buyerKeyRef !== undefined ? o.buyerKeyRef : o[2];
      const seller = d.seller !== undefined ? d.seller : d[0];
      const deliveredAt = d.deliveredAt !== undefined ? d.deliveredAt : d[1];
      return {
        buyer: String(b),
        amountWei: BigInt(amountWei.toString()),
        expiry: Number(expiry),
        buyerKeyRef,
        deliverySeller: String(seller),
        deliveredAt: Number(deliveredAt),
      };
    });

    return { rows, newCursor: Number(end) };
  }

  async function getOffersForBuyer(buyerAddr, cursor = 0, size = 50) {
    const c = await getReadContract();
    const nBig = await c.buyerOfferCount(buyerAddr);
    const n = BigInt(nBig.toString());
    const cur = BigInt(cursor);
    const sz = BigInt(size);
    if (cur >= n) return { rows: [], newCursor: Number(cur) };
    let end = cur + sz;
    if (end > n) end = n;
    const outLen = Number(end - cur);
    const idxs = Array.from({ length: outLen }, (_, i) => cur + BigInt(i));

    const tids = await Promise.all(idxs.map((ix) => c.buyerOfferTokenAt(buyerAddr, ix)));

    const offers = await Promise.all(tids.map((tid) => c.getOffer(tid, buyerAddr)));
    const dels = await Promise.all(tids.map((tid) => c.getDelivery(tid, buyerAddr)));

    const rows = tids.map((tid, i) => {
      const o = offers[i];
      const d = dels[i];
      const amountWei = o.amountWei !== undefined ? o.amountWei : o[0];
      const expiry = o.expiry !== undefined ? o.expiry : o[1];
      const seller = d.seller !== undefined ? d.seller : d[0];
      const deliveredAt = d.deliveredAt !== undefined ? d.deliveredAt : d[1];
      return {
        tokenId: tid.toString(),
        amountWei: BigInt(amountWei.toString()),
        expiry: Number(expiry),
        deliverySeller: String(seller),
        deliveredAt: Number(deliveredAt),
      };
    });

    return { rows, newCursor: Number(end) };
  }

  async function getDelivery(tokenId, buyerAddr) {
    const c = await getReadContract();
    const [seller, deliveredAt, ownerEncDEK, viewWrap] = await c.getDelivery(tokenId, buyerAddr);
    return {
      seller,
      deliveredAt: Number(deliveredAt),
      ownerEncDEKHex: ownerEncDEK,
      viewWrapHex: viewWrap,
      ownerEncDEKBytes: ethers.getBytes(ownerEncDEK),
      viewWrapBytes: ethers.getBytes(viewWrap)
    };
  }

  async function revokeDelivery(tokenId, buyerAddr) {
    if (!state.contract || !state.signer) throw new Error("Connect wallet first.");
    const tx = await state.contract.revokeDelivery(tokenId, buyerAddr);
    await tx.wait();
    return tx.hash;
  }

  async function getEraseState(tokenId) {
  const c = await getReadContract();
  const [active, field, nextWord] = await c.getEraseState(tokenId);
  return { active: !!active, field: Number(field), nextWord: Number(nextWord) };
}

  async function eraseTokenData(tokenId, maxWords) {
  if (!state.contract || !state.signer) throw new Error("Connect wallet first.");
  const mw = (maxWords == null) ? 600 : Number(maxWords);
  if (!Number.isFinite(mw) || mw <= 0) throw new Error("Bad maxWords");
  const tx = await state.contract.eraseTokenData(tokenId, mw);
  await tx.wait();
  return tx.hash;
}

  async function burn(tokenId) {
    if (!state.contract || !state.signer) throw new Error("Connect wallet first.");
    const tx = await state.contract.burn(tokenId);
    await tx.wait();
    return tx.hash;
  }

function guessScanWindow(currentBlock) {
  const cfg = window.CIPNFT_CONFIG || {};
  if (cfg.DEPLOYMENT_BLOCK && cfg.DEPLOYMENT_BLOCK > 0) return { from: cfg.DEPLOYMENT_BLOCK, to: currentBlock };
  // default: last ~200k blocks
  const from = Math.max(0, currentBlock - 200000);
  return { from, to: currentBlock };
}

window.CIPNFT = {
    ABI,
    state,

    // constants
    ENC_MODE_CLASSIC,
    ENC_MODE_PQC,
    PQC_PUBKEY_BYTES,
    PQC_OWNER_ENVELOPE_BYTES,
    OWNER_ENVELOPE_BYTES_CLASSIC,
    VIEW_WRAP_BYTES,
    MAX_PLAINTEXT,

    // utils
    fmtErr,
    shortAddr,
    bytesLenUtf8,
    downloadText,
    confirmModal,
    nativeSymbol,
    expectedChainId,
    keyLoginStatusText,
    renderWalletHeader,
    setPreferredEncMode,
    toEtherString,
    toNativeString,
    nowSec,
    chainNowSec,
    cipherPreviewText,

    // wallet + chain
    init,
    ensureReadProvider,
    getReadContract,
    ensureProvider,
    connectWallet,
    autoConnectIfAuthorized,
    bootstrap,
    refreshOnchain,
    acceptCurrentTos,

    // classic key
    deriveKeyFromSignature,
    importSeed,
    clearSeed,
    registerPubKey,
    getMyOnchainPubKey,
    ensureClassicKey,

    // pqc key
    generatePqcKey,
    derivePqcKeyFromSignature,
    importPqcSeed,
    clearPqcSeed,
    registerPqcPubKey,
    getMyOnchainPqcPubKey,
    ensurePqcKey,

    // view key + crypto
    randomViewKeyText,
    viewKeyToSymmetricKey,

    encryptMetadata,
    decryptDEKAsOwner,
    decryptDEKWithViewKey,
    verifyDekHash,
    decryptMetaCipher,

    // high-level flows
    mintEncrypted,
    getTokenBundle,
    getTokenCard,
    deliverOffer,
    verifyDeliveryForBuyer,
    finalizeOffer,

    // listings/offers/erase
    getListed,
    getListedLatest,
    setListing,
    setTitle,
    createOffer,
    cancelOffer,
    refundExpiredOffer,
    getOffer,
    getOffersForToken,
    getOffersForBuyer,
    getDelivery,
    revokeDelivery,
    getEraseState,
    eraseTokenData,
    burn,

    // legacy
    guessScanWindow
  };
})();
