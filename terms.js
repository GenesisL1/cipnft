/* CIPNFT — Terms page */

const $ = (id) => document.getElementById(id);

function toast(msg) {
  const el = $("toast");
  if (!el) return;
  el.textContent = msg;
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 3200);
}

function setPill(el, text, cls) {
  el.textContent = text;
  el.className = "pill" + (cls ? (" " + cls) : "");
}

function setStatusBar() {
  CIPNFT.renderWalletHeader();
}

function shortHex(h, head = 10, tail = 8) {
  if (!h) return "—";
  const s = String(h);
  if (s.length <= head + tail + 2) return s;
  return s.slice(0, head) + "…" + s.slice(-tail);
}

function renderTosMarkup(raw) {
  const el = $("tosTextOut");
  if (!el) return;
  let txt = String(raw || "");

  // Some deployments/tools end up storing literal "\\n" sequences on-chain.
  // If we see those (and no real newlines), convert them so formatting survives.
  if (!/\n/.test(txt) && /\\n/.test(txt)) {
    txt = txt.replace(/\\r\\n/g, "\n").replace(/\\n/g, "\n");
  }

  // Some admin UIs / copy-paste paths collapse newlines into spaces.
  // If we have NO real newlines but we do see section markers like "1) DEFINITIONS",
  // reconstruct a readable layout by inserting newlines before those markers.
  if (!/\n/.test(txt)) {
    let t = txt.replace(/\s+/g, " ").trim();

    // Title separation
    t = t.replace(/^(CIPNFT\s+TERMS\s+OF\s+SERVICE)\s+/i, "$1\n\n");

    // Ensure the IMPORTANT blurb (if present) is separated from section 1)
    t = t.replace(/(BY\s+USING\s+THE\s+CIPNFT[\s\S]*?TERMS\.)\s+(?=\d+\))/i, "$1\n\n");

    // New sections: "1) DEFINITIONS", "12) DISCLAIMER OF WARRANTIES", etc.
    t = t.replace(/\s+(?=\d{1,2}\)\s+[A-Z])/g, "\n\n");

    // Subclauses: "(a) ...", "(b) ..."
    t = t.replace(/\s+\(([a-z])\)\s+/g, "\n   ($1) ");

    txt = t;
  }

  // If the TOS text already contains HTML, render it but with a minimal sanitizer.
  const looksHtml = /<\s*\w+[\s>]/.test(txt);
  if (!looksHtml) {
    // Plain text (what you paste in Remix most of the time):
    // turn it into readable headings + paragraphs even if there are no blank lines.
    const escHtml = (s) => String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;");

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
      // treat short ALL CAPS lines as headings (e.g., DISCLAIMER OF WARRANTIES)
      const hasLower = /[a-z]/.test(s);
      if (hasLower) return false;
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

      // Title line
      if (/^CIPNFT\s+TERMS\s+OF\s+SERVICE/i.test(s)) {
        flush();
        blocks.push({ t: "title", v: s });
        continue;
      }

      // Section headers like: 1) DEFINITIONS
      if (/^\d+\)\s+/.test(s)) {
        flush();
        blocks.push({ t: "sec", v: s });
        continue;
      }

      // Other ALL CAPS headings (IMPORTANT..., DISCLAIMER..., etc.)
      if (isAllCapsHeading(s)) {
        flush();
        blocks.push({ t: "head", v: s });
        continue;
      }

      // Normal line → accumulate into a paragraph
      cur.push(s);
    }
    flush();

    el.innerHTML = blocks.map(b => {
      const v = escHtml(b.v);
      if (b.t === "title") return `<h1 class="tos-title">${v}</h1>`;
      if (b.t === "sec") return `<h2 class="tos-sec">${v}</h2>`;
      if (b.t === "head") return `<h3 class="tos-head">${v}</h3>`;
      return `<p>${v}</p>`;
    }).join("\n");
    return;
  }

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
            // Replace disallowed element with its text content.
            const t = doc.createTextNode(ch.textContent || '');
            ch.replaceWith(t);
            continue;
          }
          // Strip dangerous attributes
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
    // Fallback: show as plain text.
    el.textContent = txt;
  }
}

async function ensureRead() {
  await CIPNFT.bootstrap();
  // Do not depend on wallet for reads (market/terms must work publicly).
  await CIPNFT.ensureReadProvider();
  await CIPNFT.refreshOnchain();
  setStatusBar();
}

async function connect() {
  await CIPNFT.connectWallet();
  setStatusBar();
}

async function refresh() {
  await ensureRead();
  const v = CIPNFT.state.tosVersionCurrent;
  setPill($("tosVerPill"), `TOS v${v}`, "");

  if (!CIPNFT.state.address) setPill($("tosAcceptedPill"), "Not connected", "warn");
  else if (CIPNFT.state.tosAcceptedCurrent) setPill($("tosAcceptedPill"), "Accepted", "ok");
  else setPill($("tosAcceptedPill"), "Not accepted", "warn");

  $("tosHashOut").textContent = CIPNFT.state.tosHashCurrent ? shortHex(CIPNFT.state.tosHashCurrent) : "—";

  // Text
  const c = await CIPNFT.getReadContract();
  const txt = await c.tosText(v);
  renderTosMarkup(txt || "");

  // Fees
  const flat = CIPNFT.state.flatMintFeeWei;
  const perByte = CIPNFT.state.perByteFeeWei;
  const sym = CIPNFT.nativeSymbol();
  $("flatFeeOut").textContent = `${CIPNFT.toEtherString(flat)} ${sym}`;
  $("perByteFeeOut").textContent = `${CIPNFT.toEtherString(perByte)} ${sym} / byte`;

  const ex10k = flat + perByte * 10000n;
  const ex64k = flat + perByte * 65536n;
  $("ex10k").textContent = `${CIPNFT.toEtherString(ex10k)} ${sym}`;
  $("ex64k").textContent = `${CIPNFT.toEtherString(ex64k)} ${sym}`;

  // Offer rules (anti-spam)
  const maxSec = Number(CIPNFT.state.maxOfferDurationSec || 0);
  if (maxSec > 0) {
    const days = maxSec / 86400;
    $("maxOfferOut").textContent = `${days.toFixed(2)} days (${maxSec} sec)`;
  } else {
    $("maxOfferOut").textContent = "No cap";
  }
  $("minOfferOut").textContent = `${CIPNFT.toEtherString(CIPNFT.state.minOfferPriceWei)} ${sym}`;

  $("termsStatus").textContent = "OK.";
}

async function accept() {
  await connect();
  $("termsStatus").textContent = "Sending accept tx…";
  const v = await CIPNFT.acceptCurrentTos();
  await refresh();
  $("termsStatus").textContent = `Accepted TOS v${v.toString()}.`;
  toast(`Accepted TOS v${v.toString()}.`);
}

async function init() {
  // Init + restore prior wallet session (no popup)
  await CIPNFT.bootstrap();
  setStatusBar();

  $("btnConnect").addEventListener('click', async () => { try { await connect(); await refresh(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnRefresh").addEventListener('click', async () => { try { await refresh(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });
  $("btnAccept").addEventListener('click', async () => { try { await accept(); } catch (e) { alert(CIPNFT.fmtErr(e)); } });

  // best-effort read without connect
  try { await refresh(); } catch (_) {}
}

document.addEventListener('DOMContentLoaded', () => { init().catch(e => alert(CIPNFT.fmtErr(e))); });
