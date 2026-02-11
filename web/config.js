// CIPNFT front-end configuration
//
// IMPORTANT:
// 1) Set CONTRACT_ADDRESS to your deployed contract.
// 2) DEPLOYMENT_BLOCK is kept for compatibility, but this suite discovers listings/offers
//    from on-chain state indexes (no event scanning required).
//
// This project is browser-only (no Node.js build). Edit this file directly.

window.CIPNFT_CONFIG = {
  // Deployed CryptonftEncryptedListingNFT contract
  CONTRACT_ADDRESS: "0x05e4F1929947bE93a853F2de155fc1d6137f8446",

  // Optional. Kept for backwards-compatibility.
  DEPLOYMENT_BLOCK: 0,

  // Chain configuration (GenesisL1)
  // The UI will warn when connected to a different chain.
  EXPECTED_CHAIN_ID: 29,

  // Default public RPC (read-only, no wallet required)
  RPC_URL: "https://rpc.genesisl1.org",

  // Native currency display symbol (UI only)
  NATIVE_SYMBOL: "L1"
};
