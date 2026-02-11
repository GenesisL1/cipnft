# CIPNFT --- Cipher/IP NFT (Encrypted Data, Fully On‑Chain)

**Protocol Whitepaper:** https://cipnft.com/CIPNFT_on_GenesisL1_Whitepaper.pdf

**dApp urls:** 

- https://cipnft.com
- https://genesisl1.github.io/cipnft/
- localhost


**CIPNFT** (Cryptographic Information Protocol NFT) is a browser‑only
dApp + Solidity contract that lets you encrypt sensitive data locally in
your browser, then mint it as an NFT where the ciphertext lives directly
on‑chain.

> You tokenize knowledge and IP as an NFT while keeping the content
> private by default.

------------------------------------------------------------------------

## 🐇 Why CIPNFT Is Different

Most NFTs store only metadata and link to external storage (IPFS or
HTTP).\
CIPNFT stores encrypted ciphertext fully on‑chain.

Key properties:

-   ✅ Client‑side encryption (plaintext never leaves your device)
-   ✅ On‑chain ciphertext permanence
-   ✅ Cryptographic delivery marketplace flow
-   ✅ Verifiable finalize step
-   ✅ Fully static frontend (no backend required)

------------------------------------------------------------------------

## 🧠 Core Concept

CIPNFT turns encrypted data into a transferable blockchain asset.

Instead of: NFT → URL → External file

We have: NFT → On‑chain ciphertext → Decrypt with key

The blockchain becomes the vault.

------------------------------------------------------------------------

## 🔐 Full User Flow

### 1️⃣ Key Login / Registration

-   Generate or import encryption keys
-   Save private + view keys securely
-   Optionally register key on‑chain

⚠️ If you lose your keys, decryption access is permanently lost.

------------------------------------------------------------------------

### 2️⃣ Encrypt → Tokenize

1.  Paste plaintext data
2.  Browser encrypts locally
3.  Mint NFT storing ciphertext on‑chain

The NFT now represents an encrypted container of value.

------------------------------------------------------------------------

### 3️⃣ View / Verify

-   Load token by ID
-   Fetch on‑chain ciphertext
-   Attempt decryption with your keys
-   Verify delivery status (if traded)

------------------------------------------------------------------------

### 4️⃣ Marketplace Flow

Owner lists token →\
Buyer makes escrowed offer →\
Owner delivers encrypted payload →\
Buyer verifies →\
Buyer finalizes transfer

This enables trading encrypted IP safely.

------------------------------------------------------------------------

## 🏗 Repository Structure

-   `cipnft.sol` --- NFT + encrypted payload + escrow logic
-   `mint.html / mint.js` --- Encrypt & mint UI
-   `marketplace.html / marketplace.js` --- Trading UI
-   `verify.html / verify.js` --- Verification UI
-   `terms.html / terms.js` --- On‑chain TOS flow
-   `config.js` --- Network + contract config

------------------------------------------------------------------------

## 💻 Running Locally

### Python

``` bash
python3 -m http.server 8000
```

Open:

    http://localhost:8000/mint.html

No backend required.

------------------------------------------------------------------------

## 🌍 Deployment

Works on: - GitHub Pages - Netlify - Vercel - Any static hosting

Ensure: - HTTPS enabled - Correct contract address in `config.js`

------------------------------------------------------------------------

## 🧬 Use Cases

-   Encrypted research datasets
-   Tokenized private IP
-   Time‑locked disclosures
-   Scientific provenance proofs
-   Secure digital licensing

------------------------------------------------------------------------

## 🔒 Security Notes

-   Plaintext stays in your browser
-   Ciphertext is public on-chain
-   Keys must be backed up securely
-   Production deployments should be audited

------------------------------------------------------------------------

## 📜 License

MIT License

------------------------------------------------------------------------

Part of the GenesisL1 ecosystem.
