// Landing page animations + wallet connect
// Copyright (c) 2026 Decentralized Science Labs — GenesisL1 Blockchain (L1 Coin)
// MIT License (see LICENSE)

function fmtErr(e) {
  return (window.CIPNFT && CIPNFT.fmtErr) ? CIPNFT.fmtErr(e) : (e && e.message) ? e.message : String(e);
}

function animateCounters() {
  const counters = document.querySelectorAll('.stat-item h3[data-target]');
  counters.forEach(counter => {
    const target = +counter.getAttribute('data-target');
    const increment = target / 100;
    const updateCounter = () => {
      const c = +counter.innerText;
      if (c < target) {
        counter.innerText = Math.ceil(c + increment);
        setTimeout(updateCounter, 20);
      } else {
        counter.innerText = target;
      }
    };
    updateCounter();
  });
}

async function onConnect() {
  try {
    await CIPNFT.init();
    await CIPNFT.connectWallet();
    CIPNFT.renderWalletHeader();
  } catch (e) {
    alert(fmtErr(e));
  }
}

function initLanding() {
  animateCounters();

  // Restore prior wallet connection without prompting.
  (async () => {
    try {
      await CIPNFT.bootstrap();
    } catch (_) {
      // Landing should still load even if the wallet/provider is unavailable.
    }
  })();

  const btn = document.getElementById('btnConnect');
  if (btn) btn.addEventListener('click', onConnect);
}

document.addEventListener('DOMContentLoaded', initLanding);
