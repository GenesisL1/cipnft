// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Decentralized Science Labs — GenesisL1 Blockchain (L1 Coin)
pragma solidity ^0.8.20;

/**
 * CryptonftEncryptedListingNFT (Browser-only reference implementation)
 *
 * Core:
 * - Stores encrypted metadata fully on-chain (ciphertext only).
 * - Keeps a per-owner encrypted DEK "envelope" so only the current owner can decrypt.
 * - Optional plaintext "view key": if shared, anyone can decrypt metadata (via on-chain DEK wrap).
 *
 * Trading:
 * - On-chain listings: openToTransfer + price, discoverable via getListed().
 * - Escrowed offers: buyer deposits exact price; owner accepts by re-wrapping DEK to buyer and transferring atomically.
 *
 * Governance / UX:
 * - On-chain Terms of Service (TOS) text (versioned).
 * - Users must accept the CURRENT TOS on-chain before minting.
 * - Mint fees: (flat fee) + (per-byte fee * plaintext bytes), admin-updatable.
 * - Fees accumulate on the contract and can be withdrawn by admin without touching escrowed offers.
 *
 * IMPORTANT REALITIES:
 * - The chain cannot verify that a provided newOwnerEncDEK decrypts to the correct DEK (no X25519 on EVM).
 *   Clients must verify DEK correctness using dekHash (keccak256(DEK)).
 * - Previous owners can keep plaintext/keys once they have decrypted; revocation is not possible.
 * - "Erase from state" can scrub current storage slots, but cannot erase blockchain history.
 */
interface IERC165 {
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

interface IERC721 is IERC165 {
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    function balanceOf(address owner) external view returns (uint256 balance);
    function ownerOf(uint256 tokenId) external view returns (address owner);

    function approve(address to, uint256 tokenId) external;
    function getApproved(uint256 tokenId) external view returns (address operator);

    function setApprovalForAll(address operator, bool _approved) external;
    function isApprovedForAll(address owner, address operator) external view returns (bool);

    function transferFrom(address from, address to, uint256 tokenId) external;
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external;
}

interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4);
}

interface IERC721Metadata is IERC721 {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function tokenURI(uint256 tokenId) external view returns (string memory);
}

abstract contract ERC165 is IERC165 {
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}

contract CryptonftEncryptedListingNFT is ERC165, IERC721Metadata {

// ---------- Custom Errors (bytecode-size optimized) ----------
    error ALREADY_MINTED();
    error AMOUNT_EXCEEDS_FEES();
    error BAD_DELIVERY();
    error BAD_ENC_MODE();
    error BAD_EXPIRY();
    error BAD_FIELD();
    error BAD_MAXWORDS();
    error BAD_OWNER_ENVELOPE();
    error BAD_PQC_PUBKEY();
    error BAD_PUBKEY();
    error BAD_TITLE();
    error BAD_TITLE_LEN();
    error BAD_VALUE();
    error BAD_VIEW_WRAP();
    error BUYER_KEY_CHANGED();
    error CIPHER_TOO_SMALL();
    error DISABLED_USE_ACCEPT_OFFER();
    error EMPTY_TOS();
    error EXPIRED();
    error INSUFFICIENT_FEE();
    error META_TOO_LARGE();
    error NOT_ADMIN();
    error NOT_AUTH();
    error NOT_CURRENT_TOS();
    error NOT_DELIVERED();
    error NOT_EXPIRED();
    error NOT_LISTED();
    error NOT_MINTED();
    error NOT_OWNER();
    error NOT_SELLER();
    error NO_BUYER_KEYREF();
    error NO_BUYER_PQC_PUBKEY();
    error NO_BUYER_PUBKEY();
    error NO_DELIVERY();
    error NO_OFFER();
    error NO_PQC_PUBKEY();
    error NO_PUBKEY_SET();
    error NO_TOS();
    error OFFER_EXISTS();
    error OWNER_CANNOT_OFFER();
    error PAY_FAILED();
    error PLAINTEXT_TOO_LARGE();
    error PRICE_CHANGED();
    error REENTRANCY();
    error REFUND_FAILED();
    error SELLER_NOT_OWNER();
    error TITLE_TOO_MANY_WORDS();
    error TOS_NOT_ACCEPTED();
    error UNSAFE_RECEIVER();
    error WITHDRAW_FAILED();
    error ZERO_ADDR();


    // ---------- Constants ----------
    uint256 public constant MAX_PLAINTEXT_BYTES = 64 * 1024; // 64 KiB
    uint256 public constant NONCE_BYTES = 24;               // XChaCha20-Poly1305 nonce
    uint256 public constant AEAD_TAG_BYTES = 16;            // Poly1305 tag
    uint256 public constant MAX_CIPHERTEXT_BYTES = MAX_PLAINTEXT_BYTES + NONCE_BYTES + AEAD_TAG_BYTES; // 65576

    uint256 public constant OWNER_ENVELOPE_BYTES = 80;      // libsodium crypto_box_seal for 32-byte DEK => 32 + 48
    // Encryption modes
    uint8 public constant ENC_MODE_CLASSIC = 0;            // libsodium sealed box (X25519 + XSalsa20-Poly1305)
    uint8 public constant ENC_MODE_PQC     = 1;            // ML-KEM-768 (post-quantum) + XChaCha20-Poly1305 wrap

    // Post-quantum (ML-KEM-768) sizes
    uint256 public constant PQC_PUBKEY_BYTES = 1184;       // ML-KEM-768 public key size (raw-public)
    uint256 public constant PQC_KEM_CT_BYTES = 1088;       // ML-KEM-768 ciphertext size (encapsulateBits)
    uint256 public constant PQC_OWNER_ENVELOPE_BYTES = PQC_KEM_CT_BYTES + NONCE_BYTES + (32 + AEAD_TAG_BYTES); // 1088 + 24 + 48 = 1160

    uint256 public constant VIEW_WRAP_BYTES = 72;           // nonce(24) + DEK(32) + tag(16)

    // ---------- Admin ----------
    address public admin;

    modifier onlyAdmin() {
        if (!(msg.sender == admin)) revert NOT_ADMIN();
        _;
    }

    // ---------- TOS (versioned, on-chain) ----------
    uint256 public tosVersionCurrent; // starts at 1
    mapping(uint256 => string) private _tosText;  // version => text
    mapping(uint256 => bytes32) public tosHash;   // version => keccak256(text)
    mapping(address => mapping(uint256 => bool)) public tosAccepted; // user => version => accepted

    // ---------- Fees (native token) ----------
    uint256 public perByteFeeWei;   // fee per plaintext byte
    uint256 public flatMintFeeWei;  // flat mint fee
    uint256 public accumulatedFees; // fees collected (withdrawable by admin)

    // ---------- Offer anti-spam controls ----------
    // Maximum offer expiry duration from creation time (seconds). Default: 7 days.
    uint64 public maxOfferDurationSec;
    // Minimum offer / listing price (wei). Default: 1 L1 (1e18). Set to 0 to allow free transfers.
    uint256 public minOfferPriceWei;

    // ---------- ERC721 storage ----------
    string private _name;
    string private _symbol;
    uint256 private _nextId = 1;

    mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;
    // NOTE: Standard ERC721 approvals are intentionally not supported.
    // Transfers must occur via finalizeOffer() so the DEK envelope is updated
    // in the same state transition. Approve/transfer functions remain in the
    // interface for compatibility but revert or return constants.

    // ---------- Owner token index (on-chain enumeration) ----------
    // Enables enumeration of tokens owned by an address using contract state only (no event scanning).
    // Maintained on mint, internal transfers (finalizeOffer), and burn.
    mapping(address => uint256[]) private _ownedTokens;
    mapping(uint256 => uint256) private _ownedTokensIndex; // tokenId => index in _ownedTokens[owner]

    // ---------- Encryption storage ----------
    struct TokenData {
        bytes metaCipher;     // nonce || ciphertext(tag included)
        bytes ownerEncDEK;    // sealed-box(DEK) to current owner pubkey
        bytes viewWrap;       // optional: nonce || aead(DEK) under viewKey-derived symmetric key
        bytes32 dekHash;      // keccak256(DEK) commitment for verification
        uint8  encMode;      // 0=classic envelope, 1=post-quantum envelope
    }

    mapping(uint256 => TokenData) private _tokenData;

    // tokenId => tos version that was required and accepted at mint time
    mapping(uint256 => uint32) public tosVersionOf;

    // tokenId => public (non-encrypted) short title
    mapping(uint256 => string) private _titles;

    uint32 public constant MAX_TITLE_BYTES = 80;
    uint8  public constant MAX_TITLE_WORDS = 5;

    event TitleUpdated(uint256 indexed tokenId, string title);


    struct EraseState {
        bool active;
        uint8 field;     // 0=metaCipher, 1=ownerEncDEK, 2=viewWrap
        uint32 nextWord; // next 32-byte word index to clear in current field
    }
    mapping(uint256 => EraseState) private _erase;

    // wallet address => X25519 public key (32 bytes)
    mapping(address => bytes32) public encryptionPubKey;

    // Post-quantum public key for ML-KEM-768 (raw format, 1184 bytes).
    // Used when interacting with PQ-encrypted tokens (encMode = ENC_MODE_PQC).
    mapping(address => bytes) public pqcPubKey;


    // ---------- Listing storage ----------
    struct Listing {
        bool open;
        uint256 priceWei;
    }
    mapping(uint256 => Listing) public listings;

    uint256[] private _listedTokens;
    mapping(uint256 => uint256) private _listedIndexPlus1; // tokenId => idx+1

    // ---------- Offer storage ----------
    struct Offer {
        uint256 amountWei;     // escrowed native L1
        uint64  expiry;        // unix time
        bytes32 buyerKeyRef;   // CLASSIC: buyer's bytes32 pubkey snapshot; PQC: keccak256(raw PQ pubkey) snapshot
    }
    // tokenId => buyer => offer
    mapping(uint256 => mapping(address => Offer)) private _offers;

    // Offer indexes (state-based discovery; no event scanning required)
    mapping(uint256 => address[]) private _offerBuyers; // tokenId => buyers with offers
    mapping(uint256 => mapping(address => uint256)) private _offerBuyerIndexPlus1; // tokenId => buyer => idx+1

    mapping(address => uint256[]) private _buyerOfferTokens; // buyer => tokenIds offered
    mapping(address => mapping(uint256 => uint256)) private _buyerOfferIndexPlus1; // buyer => tokenId => idx+1



// ---------- Delivery storage (two-step finalize) ----------
/**
 * Seller "delivers" the re-wrapped DEK envelope to the buyer on-chain, WITHOUT transferring or taking payment.
 * Buyer then verifies decryption off-chain and calls finalizeOffer() to transfer + release escrow.
 *
 * This prevents a seller from receiving payment if they provide an incorrect envelope.
 */
struct Delivery {
    address seller;
    uint64  deliveredAt;   // unix time (0 = none)
    bytes   ownerEncDEK;   // CLASSIC: 80 bytes; PQC: 1160 bytes (sealed DEK for buyer)
    bytes   viewWrap;      // 0 or 72 bytes
}
// tokenId => buyer => delivery
mapping(uint256 => mapping(address => Delivery)) private _deliveries;


    // ---------- Reentrancy guard ----------
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;

    // ---------- Events ----------
    // admin / tos / fees
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);

    event TosVersionAdded(uint256 indexed version, bytes32 indexed textHash);
    event TosAccepted(address indexed user, uint256 indexed version);

    event FeesUpdated(uint256 perByteFeeWei, uint256 flatMintFeeWei);
    event OfferRulesUpdated(uint64 maxOfferDurationSec, uint256 minOfferPriceWei);

    event FeesWithdrawn(address indexed to, uint256 amountWei);

    // encryption / nft / market
    event EncryptionPublicKeySet(address indexed user, bytes32 pubKey);
    event PqcPublicKeySet(address indexed user, bytes32 pubKeyHash);

    event Minted(uint256 indexed tokenId, address indexed owner, bytes32 dekHash, uint256 cipherSize, uint32 tosVersion, uint256 feePaid);

    event ListingUpdated(uint256 indexed tokenId, bool open, uint256 priceWei);

    event OfferCreated(uint256 indexed tokenId, address indexed buyer, uint256 amountWei, uint64 expiry, bytes32 buyerKeyRef);
    event OfferCancelled(uint256 indexed tokenId, address indexed buyer);
    event OfferAccepted(uint256 indexed tokenId, address indexed buyer, uint256 amountWei);

event OfferDelivered(uint256 indexed tokenId, address indexed buyer, address indexed seller, uint256 amountWei);
event OfferDeliveryRevoked(uint256 indexed tokenId, address indexed buyer, address indexed seller);
event OfferFinalized(uint256 indexed tokenId, address indexed buyer, address indexed seller, uint256 amountWei);

    event OwnerEnvelopeUpdated(uint256 indexed tokenId, address indexed owner);
    event ViewWrapUpdated(uint256 indexed tokenId, bool enabled);

    event Burned(uint256 indexed tokenId);

    event TokenDataEraseStarted(uint256 indexed tokenId);
    event TokenDataEraseProgress(uint256 indexed tokenId, uint8 field, uint32 nextWord);
    event TokenDataErased(uint256 indexed tokenId);

    // ---------- Modifiers ----------
    modifier nonReentrant() {
        if (!(_status != _ENTERED)) revert REENTRANCY();
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }

    // ---------- Constructor ----------
    constructor(string memory name_, string memory symbol_, string memory initialTosText_) {
        _name = name_;
        _symbol = symbol_;
        _status = _NOT_ENTERED;

        admin = msg.sender;

        // initialize TOS version 1
        if (!(bytes(initialTosText_).length > 0)) revert EMPTY_TOS();
        tosVersionCurrent = 1;
        _tosText[1] = initialTosText_;
        tosHash[1] = keccak256(bytes(initialTosText_));
        emit TosVersionAdded(1, tosHash[1]);

        // Default anti-spam parameters
        maxOfferDurationSec = uint64(7 days);
        minOfferPriceWei = 1 ether;
    }

    // ---------- Admin controls ----------
    function transferAdmin(address newAdmin) external onlyAdmin {
        if (!(newAdmin != address(0))) revert ZERO_ADDR();
        address old = admin;
        admin = newAdmin;
        emit AdminTransferred(old, newAdmin);
    }

    function addTosVersion(string calldata tosText_) external onlyAdmin {
        if (!(bytes(tosText_).length > 0)) revert EMPTY_TOS();
        uint256 v = tosVersionCurrent + 1;
        tosVersionCurrent = v;
        _tosText[v] = tosText_;
        bytes32 h = keccak256(bytes(tosText_));
        tosHash[v] = h;
        emit TosVersionAdded(v, h);
    }

    function tosText(uint256 version) external view returns (string memory) {
        return _tosText[version];
    }

    function acceptTos(uint256 version) external {
        if (!(version == tosVersionCurrent)) revert NOT_CURRENT_TOS();
        if (!(bytes(_tosText[version]).length > 0)) revert NO_TOS();
        tosAccepted[msg.sender][version] = true;
        emit TosAccepted(msg.sender, version);
    }

    function setFees(uint256 perByteFeeWei_, uint256 flatMintFeeWei_) external onlyAdmin {
        perByteFeeWei = perByteFeeWei_;
        flatMintFeeWei = flatMintFeeWei_;
        emit FeesUpdated(perByteFeeWei_, flatMintFeeWei_);
    }

    function setOfferRules(uint64 maxOfferDurationSec_, uint256 minOfferPriceWei_) external onlyAdmin {
        maxOfferDurationSec = maxOfferDurationSec_;
        minOfferPriceWei = minOfferPriceWei_;
        emit OfferRulesUpdated(maxOfferDurationSec_, minOfferPriceWei_);
    }

    function withdrawFees(address payable to, uint256 amountWei) external onlyAdmin nonReentrant {
        if (!(to != address(0))) revert ZERO_ADDR();
        if (!(amountWei <= accumulatedFees)) revert AMOUNT_EXCEEDS_FEES();
        accumulatedFees -= amountWei;
        (bool ok, ) = to.call{ value: amountWei }("");
        if (!(ok)) revert WITHDRAW_FAILED();
        emit FeesWithdrawn(to, amountWei);
    }

    function mintFeeFor(uint256 plaintextBytes) public view returns (uint256) {
        if (!(plaintextBytes <= MAX_PLAINTEXT_BYTES)) revert PLAINTEXT_TOO_LARGE();
        return flatMintFeeWei + (perByteFeeWei * plaintextBytes);
    }

    // ---------- ERC165 ----------
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return
            interfaceId == type(IERC165).interfaceId ||
            interfaceId == type(IERC721).interfaceId ||
            interfaceId == type(IERC721Metadata).interfaceId;
    }

    // ---------- ERC721Metadata ----------
    function name() external view override returns (string memory) { return _name; }
    function symbol() external view override returns (string memory) { return _symbol; }

    function tokenURI(uint256 tokenId) external view override returns (string memory) {
        if (!(_exists(tokenId))) revert NOT_MINTED();
        // Token metadata is accessed via getTokenData()/getTokenCard().
        // tokenURI is kept for wallet compatibility but intentionally empty.
        return "";
    }

    // ---------- ERC721 core ----------
    function balanceOf(address owner) public view override returns (uint256) {
        if (!(owner != address(0))) revert ZERO_ADDR();
        return _balances[owner];
    }

    function ownerOf(uint256 tokenId) public view override returns (address) {
        address o = _owners[tokenId];
        if (!(o != address(0))) revert NOT_MINTED();
        return o;
    }

    // ---------- Owner token enumeration (state-based) ----------
    /**
     * Number of tokens currently owned by `owner`.
     * Mirrors balanceOf() but uses the explicit owner index.
     */
    function ownedCount(address owner) external view returns (uint256) {
        if (!(owner != address(0))) revert ZERO_ADDR();
        return _ownedTokens[owner].length;
    }

    /**
     * Read tokenId owned by `owner` at `index` from the on-chain owner index.
     * This avoids event scanning and avoids contract-side pagination loops (code-size efficiency).
     */
    function ownedTokenAt(address owner, uint256 index) external view returns (uint256 tokenId) {
        if (!(owner != address(0))) revert ZERO_ADDR();
        return _ownedTokens[owner][index];
    }

    // ---------- ERC721 approvals (disabled) ----------
    function approve(address, uint256) external pure override {
        revert DISABLED_USE_ACCEPT_OFFER();
    }

    function getApproved(uint256 tokenId) public view override returns (address) {
        if (!(_exists(tokenId))) revert NOT_MINTED();
        return address(0);
    }

    function setApprovalForAll(address, bool) external pure override {
        revert DISABLED_USE_ACCEPT_OFFER();
    }

    function isApprovedForAll(address, address) public pure override returns (bool) {
        return false;
    }

    /**
     * WARNING: Standard ERC721 transfers are disabled to prevent "stranding"
     * encrypted ownership transfers without re-encrypting the DEK envelope.
     * Use acceptOffer() flow instead.
     */
    function transferFrom(address, address, uint256) external pure override {
        revert DISABLED_USE_ACCEPT_OFFER();
    }

    function safeTransferFrom(address, address, uint256) external pure override {
        revert DISABLED_USE_ACCEPT_OFFER();
    }

    function safeTransferFrom(address, address, uint256, bytes calldata) external pure override {
        revert DISABLED_USE_ACCEPT_OFFER();
    }

    // ---------- Key registration ----------
    function setEncryptionPublicKey(bytes32 pubKey) external {
        if (!(pubKey != bytes32(0))) revert BAD_PUBKEY();
        encryptionPubKey[msg.sender] = pubKey;
        emit EncryptionPublicKeySet(msg.sender, pubKey);
    }


    /**
     * Register a post-quantum ML-KEM-768 public key (raw format, 1184 bytes).
     * Used when interacting with PQ-encrypted tokens (encMode = ENC_MODE_PQC).
     */
    function setPqcPublicKey(bytes calldata pubKey) external {
        if (!(pubKey.length == PQC_PUBKEY_BYTES)) revert BAD_PQC_PUBKEY();
        pqcPubKey[msg.sender] = pubKey;
        emit PqcPublicKeySet(msg.sender, keccak256(pubKey));
    }

    // ---------- Mint ----------
    /**
     * metaCipher: nonce(24) || XChaCha20-Poly1305(ciphertext with 16-byte tag included)
     * ownerEncDEK: sealed-box(DEK32) => 80 bytes
     * viewWrap: optional nonce(24) || aead(DEK32, tag) => 72 bytes
     *
     * Mint requires:
     * - caller has set encryptionPubKey
     * - caller has accepted CURRENT TOS (tosAccepted[msg.sender][tosVersionCurrent] == true)
     * - msg.value covers: flatMintFeeWei + perByteFeeWei * plaintextBytes
     *   where plaintextBytes = metaCipher.length - NONCE_BYTES - AEAD_TAG_BYTES
     */
    function mint(
        string calldata title,
        bytes calldata metaCipher,
        bytes calldata ownerEncDEK,
        bytes32 dekHash,
        bytes calldata viewWrap,
        uint8 encMode
    ) external payable nonReentrant returns (uint256 tokenId) {
        if (!(encMode == ENC_MODE_CLASSIC || encMode == ENC_MODE_PQC)) revert BAD_ENC_MODE();
        if (encMode == ENC_MODE_CLASSIC) {
            if (!(encryptionPubKey[msg.sender] != bytes32(0))) revert NO_PUBKEY_SET();
            if (!(ownerEncDEK.length == OWNER_ENVELOPE_BYTES)) revert BAD_OWNER_ENVELOPE();
        } else {
            if (!(pqcPubKey[msg.sender].length == PQC_PUBKEY_BYTES)) revert NO_PQC_PUBKEY();
            if (!(ownerEncDEK.length == PQC_OWNER_ENVELOPE_BYTES)) revert BAD_OWNER_ENVELOPE();
        }
        if (!(tosAccepted[msg.sender][tosVersionCurrent])) revert TOS_NOT_ACCEPTED();

        _validateTitle(title);

        if (!(metaCipher.length >= NONCE_BYTES + AEAD_TAG_BYTES)) revert CIPHER_TOO_SMALL();
        if (!(metaCipher.length <= MAX_CIPHERTEXT_BYTES)) revert META_TOO_LARGE();

        if (!(viewWrap.length == 0 || viewWrap.length == VIEW_WRAP_BYTES)) revert BAD_VIEW_WRAP();

        uint256 plaintextBytes = metaCipher.length - NONCE_BYTES - AEAD_TAG_BYTES;
        uint256 requiredFee = mintFeeFor(plaintextBytes);
        if (!(msg.value >= requiredFee)) revert INSUFFICIENT_FEE();

        accumulatedFees += requiredFee;

        tokenId = _nextId++;

        _titles[tokenId] = title;
        emit TitleUpdated(tokenId, title);


        TokenData storage d = _tokenData[tokenId];
        d.metaCipher = metaCipher;
        d.ownerEncDEK = ownerEncDEK;
        d.viewWrap = viewWrap;
        d.dekHash = dekHash;
        d.encMode = encMode;

        // Mint after writing TokenData. Standard ERC721 safe-receiver checks are not required here
        // because transfers are disabled and minting is always to the caller.
        _mint(msg.sender, tokenId);

        tosVersionOf[tokenId] = uint32(tosVersionCurrent);

        emit Minted(tokenId, msg.sender, dekHash, metaCipher.length, uint32(tosVersionCurrent), requiredFee);
        if (viewWrap.length != 0) {
            emit ViewWrapUpdated(tokenId, true);
        }

        // Refund any excess
        uint256 refund = msg.value - requiredFee;
        if (refund != 0) {
            (bool ok, ) = payable(msg.sender).call{ value: refund }("");
            if (!(ok)) revert REFUND_FAILED();
        }
    }

    // ---------- Token data views ----------
    function getTokenData(uint256 tokenId) external view returns (
        bytes memory metaCipher,
        bytes memory ownerEncDEK,
        bytes memory viewWrap,
        bytes32 dekHash
    ) {
        if (!(_exists(tokenId))) revert NOT_MINTED();
        TokenData storage d = _tokenData[tokenId];
        return (d.metaCipher, d.ownerEncDEK, d.viewWrap, d.dekHash);
    }

    function titleOf(uint256 tokenId) external view returns (string memory) {
        if (!(_exists(tokenId))) revert NOT_MINTED();
        return _titles[tokenId];
    }

    uint256 public constant CIPHER_PREVIEW_MAX_BYTES = 160;

    function getTokenCard(uint256 tokenId) external view returns (
        string memory title,
        uint8 encMode,
        bool open,
        uint256 priceWei,
        uint32 cipherLen,
        bytes32 dekHash,
        bytes memory cipherPreview,
        uint32 tosVersion
    ) {
        if (!(_exists(tokenId))) revert NOT_MINTED();
        TokenData storage d = _tokenData[tokenId];
        Listing storage l = listings[tokenId];

        title = _titles[tokenId];
        encMode = d.encMode;
        open = l.open;
        priceWei = l.priceWei;
        cipherLen = uint32(d.metaCipher.length);
        dekHash = d.dekHash;
        tosVersion = tosVersionOf[tokenId];

        uint256 n = d.metaCipher.length;
        uint256 mlen = n < CIPHER_PREVIEW_MAX_BYTES ? n : CIPHER_PREVIEW_MAX_BYTES;
        cipherPreview = new bytes(mlen);
        for (uint256 i = 0; i < mlen; i++) {
            cipherPreview[i] = d.metaCipher[i];
        }
    }

    function setTitle(uint256 tokenId, string calldata newTitle) external {
        if (!(_exists(tokenId))) revert NOT_MINTED();
        if (!(ownerOf(tokenId) == msg.sender)) revert NOT_OWNER();
        _validateTitle(newTitle);
        _titles[tokenId] = newTitle;
        emit TitleUpdated(tokenId, newTitle);
    }


    function encryptionMode(uint256 tokenId) external view returns (uint8) {
        if (!(_exists(tokenId))) revert NOT_MINTED();
        return _tokenData[tokenId].encMode;
    }

    function getOffer(uint256 tokenId, address buyer) external view returns (uint256 amountWei, uint64 expiry, bytes32 buyerKeyRef) {
        Offer storage o = _offers[tokenId][buyer];
        return (o.amountWei, o.expiry, o.buyerKeyRef);
    }


function getDelivery(uint256 tokenId, address buyer) external view returns (address seller, uint64 deliveredAt, bytes memory ownerEncDEK, bytes memory viewWrap) {
    Delivery storage d = _deliveries[tokenId][buyer];
    return (d.seller, d.deliveredAt, d.ownerEncDEK, d.viewWrap);
}



    // ---------- Owner controls (token) ----------
    function updateOwnerEncDEK(uint256 tokenId, bytes calldata newOwnerEncDEK) external {
    if (!(ownerOf(tokenId) == msg.sender)) revert NOT_OWNER();
    uint8 mode = _tokenData[tokenId].encMode;

    if (mode == ENC_MODE_CLASSIC) {
        if (!(newOwnerEncDEK.length == OWNER_ENVELOPE_BYTES)) revert BAD_OWNER_ENVELOPE();
    } else {
        if (!(newOwnerEncDEK.length == PQC_OWNER_ENVELOPE_BYTES)) revert BAD_OWNER_ENVELOPE();
    }

    _tokenData[tokenId].ownerEncDEK = newOwnerEncDEK;
    emit OwnerEnvelopeUpdated(tokenId, msg.sender);
}

function setViewWrap(uint256 tokenId, bytes calldata viewWrap) external {
        if (!(ownerOf(tokenId) == msg.sender)) revert NOT_OWNER();
        if (!(viewWrap.length == 0 || viewWrap.length == VIEW_WRAP_BYTES)) revert BAD_VIEW_WRAP();
        _tokenData[tokenId].viewWrap = viewWrap;
        emit ViewWrapUpdated(tokenId, viewWrap.length != 0);
    }

    // ---------- Listings ----------
    function setListing(uint256 tokenId, bool open, uint256 priceWei) external {
        if (!(ownerOf(tokenId) == msg.sender)) revert NOT_OWNER();

        // If open, require a minimum price to reduce spam offers (admin adjustable).
        if (open) {
            if (!(priceWei >= minOfferPriceWei)) revert BAD_VALUE();
        }

        listings[tokenId].open = open;
        listings[tokenId].priceWei = priceWei;

        if (open) _addListed(tokenId);
        else _removeListed(tokenId);

        emit ListingUpdated(tokenId, open, priceWei);
    }

    function listedCount() external view returns (uint256) {
        return _listedTokens.length;
    }

    /**
     * Return the tokenId at position `index` in the on-chain listed index.
     * Listing state and price can be read via getTokenCard(tokenId) or listings(tokenId).
     */
    function listedTokenAt(uint256 index) external view returns (uint256 tokenId) {
        return _listedTokens[index];
    }


    // ---------- Offer enumeration (state-based) ----------
    function offerCount(uint256 tokenId) external view returns (uint256) {
        return _offerBuyers[tokenId].length;
    }

    /**
     * Return the buyer address at position `index` in the on-chain offer index for `tokenId`.
     * Offer details can be read via getOffer(tokenId, buyer) and getDelivery(tokenId, buyer).
     */
    function offerBuyerAt(uint256 tokenId, uint256 index) external view returns (address buyer) {
        return _offerBuyers[tokenId][index];
    }

    function buyerOfferCount(address buyer) external view returns (uint256) {
        if (!(buyer != address(0))) revert ZERO_ADDR();
        return _buyerOfferTokens[buyer].length;
    }

    /**
     * Return the tokenId at position `index` in the on-chain offer index for `buyer`.
     * Offer details can be read via getOffer(tokenId, buyer) and getDelivery(tokenId, buyer).
     */
    function buyerOfferTokenAt(address buyer, uint256 index) external view returns (uint256 tokenId) {
        if (!(buyer != address(0))) revert ZERO_ADDR();
        return _buyerOfferTokens[buyer][index];
    }

    // ---------- Offers (buyer) ----------
    function createOffer(uint256 tokenId, uint64 expiry) external payable nonReentrant {
        if (!(_exists(tokenId))) revert NOT_MINTED();

        Listing storage l = listings[tokenId];
        if (!(l.open)) revert NOT_LISTED();

        // spam resistance: expiry must be in the future and not exceed the protocol cap (admin adjustable).
        if (!(expiry > block.timestamp)) revert BAD_EXPIRY();
        if (maxOfferDurationSec != 0) {
            if (!(uint256(expiry) <= block.timestamp + uint256(maxOfferDurationSec))) revert BAD_EXPIRY();
        }

        // spam resistance: offers must meet the minimum price (admin adjustable).
        if (!(l.priceWei >= minOfferPriceWei)) revert BAD_VALUE();
        if (!(msg.value == l.priceWei)) revert BAD_VALUE();

        address tokenOwner = ownerOf(tokenId);
        if (!(msg.sender != tokenOwner)) revert OWNER_CANNOT_OFFER();

        uint8 mode = _tokenData[tokenId].encMode;
        bytes32 keyRef;
        if (mode == ENC_MODE_CLASSIC) {
            bytes32 pk = encryptionPubKey[msg.sender];
            if (!(pk != bytes32(0))) revert NO_BUYER_PUBKEY();
            keyRef = pk;
        } else {
            bytes memory pk2 = pqcPubKey[msg.sender];
            if (!(pk2.length == PQC_PUBKEY_BYTES)) revert NO_BUYER_PQC_PUBKEY();
            keyRef = keccak256(pk2);
        }

        Offer storage o = _offers[tokenId][msg.sender];
        if (!(o.expiry == 0)) revert OFFER_EXISTS();

        o.amountWei = msg.value;
        o.expiry = expiry;
        o.buyerKeyRef = keyRef;

        _indexOffer(tokenId, msg.sender);

        emit OfferCreated(tokenId, msg.sender, msg.value, expiry, keyRef);
    }

    function cancelOffer(uint256 tokenId) external nonReentrant {
        Offer storage o = _offers[tokenId][msg.sender];
        uint256 amount = o.amountWei;
        if (!(o.expiry != 0)) revert NO_OFFER();

        _deindexOffer(tokenId, msg.sender);

        delete _offers[tokenId][msg.sender];

        // If seller already delivered, clear delivery to avoid orphaned data
        Delivery storage d = _deliveries[tokenId][msg.sender];
        if (d.deliveredAt != 0) {
            delete _deliveries[tokenId][msg.sender];
        }

        (bool ok, ) = payable(msg.sender).call{ value: amount }("");
        if (!(ok)) revert REFUND_FAILED();

        emit OfferCancelled(tokenId, msg.sender);
    }

    function refundExpiredOffer(uint256 tokenId, address buyer) external nonReentrant {
        Offer storage o = _offers[tokenId][buyer];
        uint256 amount = o.amountWei;
        if (!(o.expiry != 0)) revert NO_OFFER();
        if (!(block.timestamp > uint256(o.expiry))) revert NOT_EXPIRED();

        _deindexOffer(tokenId, buyer);

        delete _offers[tokenId][buyer];

        // If seller already delivered, clear delivery to avoid orphaned data
        Delivery storage d = _deliveries[tokenId][buyer];
        if (d.deliveredAt != 0) {
            delete _deliveries[tokenId][buyer];
        }

        (bool ok, ) = payable(buyer).call{ value: amount }("");
        if (!(ok)) revert REFUND_FAILED();

        emit OfferCancelled(tokenId, buyer);
    }

    // ---------- Offers (seller accept) ----------
    /**
     * Seller accepts offer by:
     * - re-wrapping DEK to buyerKeyRef snapshot stored in offer
     * - optionally updating viewWrap
     * - transfer NFT to buyer
     * - pay the seller from escrow
     */
    
// ---------- Offers (seller delivers) ----------
/**
 * Seller delivers the re-wrapped DEK envelope to the buyer ON-CHAIN.
 *
 * This does NOT transfer the NFT and does NOT release escrowed payment.
 * The buyer must verify decryption off-chain and call finalizeOffer() to complete sale.
 *
 * NOTE: This contract cannot verify correctness of re-encryption on-chain. Buyer verifies using dekHash.
 */
function deliverOffer(
    uint256 tokenId,
    address buyer,
    bytes calldata newOwnerEncDEK,
    bytes calldata newViewWrap
) external nonReentrant {
    if (!(ownerOf(tokenId) == msg.sender)) revert NOT_OWNER();

    Offer storage o = _offers[tokenId][buyer];
    uint256 amount = o.amountWei;
    if (!(o.expiry != 0)) revert NO_OFFER();
    if (!(block.timestamp <= uint256(o.expiry))) revert EXPIRED();
    if (!(o.buyerKeyRef != bytes32(0))) revert NO_BUYER_KEYREF();

    uint8 mode = _tokenData[tokenId].encMode;
    if (mode == ENC_MODE_CLASSIC) {
        bytes32 pk = encryptionPubKey[buyer];
        if (!(pk != bytes32(0))) revert NO_BUYER_PUBKEY();
        if (!(pk == o.buyerKeyRef)) revert BUYER_KEY_CHANGED();
        if (!(newOwnerEncDEK.length == OWNER_ENVELOPE_BYTES)) revert BAD_OWNER_ENVELOPE();
    } else {
        bytes memory pk2 = pqcPubKey[buyer];
        if (!(pk2.length == PQC_PUBKEY_BYTES)) revert NO_BUYER_PQC_PUBKEY();
        if (!(keccak256(pk2) == o.buyerKeyRef)) revert BUYER_KEY_CHANGED();
        if (!(newOwnerEncDEK.length == PQC_OWNER_ENVELOPE_BYTES)) revert BAD_OWNER_ENVELOPE();
    }

    if (!(newViewWrap.length == 0 || newViewWrap.length == VIEW_WRAP_BYTES)) revert BAD_VIEW_WRAP();

    // If currently listed, enforce the current price and close the listing to remove it from the marketplace.
    Listing storage l = listings[tokenId];
    if (l.open) {
        if (!(amount == l.priceWei)) revert PRICE_CHANGED();
        _closeListing(tokenId);
    }

    Delivery storage d = _deliveries[tokenId][buyer];
    d.seller = msg.sender;
    d.deliveredAt = uint64(block.timestamp);
    d.ownerEncDEK = newOwnerEncDEK;
    d.viewWrap = newViewWrap;

    emit OfferDelivered(tokenId, buyer, msg.sender, amount);
}

function revokeDelivery(uint256 tokenId, address buyer) external nonReentrant {
    if (!(ownerOf(tokenId) == msg.sender)) revert NOT_OWNER();
    Delivery storage d = _deliveries[tokenId][buyer];
    if (!(d.deliveredAt != 0)) revert NO_DELIVERY();
    if (!(d.seller == msg.sender)) revert NOT_SELLER();
    delete _deliveries[tokenId][buyer];
    emit OfferDeliveryRevoked(tokenId, buyer, msg.sender);
}

// ---------- Offers (buyer finalizes) ----------
/**
 * Buyer finalizes a delivered offer:
 * - verifies offer is active (not expired)
 * - verifies a delivery exists and the seller is still the current owner
 * - transfers the NFT
 * - releases escrowed payment to the seller
 *
 * Buyer should verify off-chain that the delivered ownerEncDEK decrypts to the correct DEK (via dekHash).
 */
function finalizeOffer(uint256 tokenId) external nonReentrant {
    address buyer = msg.sender;

    Offer storage o = _offers[tokenId][buyer];
    uint256 amount = o.amountWei;
    if (!(o.expiry != 0)) revert NO_OFFER();
    if (!(block.timestamp <= uint256(o.expiry))) revert EXPIRED();

    Delivery storage d = _deliveries[tokenId][buyer];
    if (!(d.deliveredAt != 0)) revert NOT_DELIVERED();
    address seller = d.seller;
    if (!(seller != address(0))) revert BAD_DELIVERY();

    // seller must still own the token
    if (!(ownerOf(tokenId) == seller)) revert SELLER_NOT_OWNER();

    bytes memory newOwnerEncDEK = d.ownerEncDEK;
    bytes memory newViewWrap = d.viewWrap;

    uint8 mode = _tokenData[tokenId].encMode;
    if (mode == ENC_MODE_CLASSIC) {
        if (!(newOwnerEncDEK.length == OWNER_ENVELOPE_BYTES)) revert BAD_OWNER_ENVELOPE();
    } else {
        if (!(newOwnerEncDEK.length == PQC_OWNER_ENVELOPE_BYTES)) revert BAD_OWNER_ENVELOPE();
    }
    if (!(newViewWrap.length == 0 || newViewWrap.length == VIEW_WRAP_BYTES)) revert BAD_VIEW_WRAP();

    // Effects first
    _deindexOffer(tokenId, buyer);
    delete _offers[tokenId][buyer];
    delete _deliveries[tokenId][buyer];

    // ensure listing is closed
    _closeListing(tokenId);

    TokenData storage td = _tokenData[tokenId];
    td.ownerEncDEK = newOwnerEncDEK;
    td.viewWrap = newViewWrap;

    emit OwnerEnvelopeUpdated(tokenId, buyer);
    emit ViewWrapUpdated(tokenId, newViewWrap.length != 0);

    // Transfer
    _transfer(seller, buyer, tokenId);

    // Pay seller from escrow
    (bool ok, ) = payable(seller).call{ value: amount }("");
    if (!(ok)) revert PAY_FAILED();

    emit OfferFinalized(tokenId, buyer, seller, amount);
}




    // ---------- Erase encrypted data from current state (scrub storage) ----------
    /**
     * Erases (scrubs) the encrypted metadata + key envelopes from the *current* state trie.
     *
     * - This does NOT delete historical chain data (past state / tx calldata can still be archived).
     * - Designed to be called in multiple transactions to avoid gas limits.
     *
     * How it works:
     * - Clears underlying storage slots for: metaCipher, ownerEncDEK, viewWrap
     * - Then clears the length slots + dekHash, and deletes the TokenData struct.
     *
     * Usage:
     * - Call eraseTokenData(tokenId, maxWords) repeatedly until it emits TokenDataErased.
     *   (maxWords is the number of 32-byte storage words to clear per call.)
     */
    function getEraseState(uint256 tokenId) external view returns (bool active, uint8 field, uint32 nextWord) {
        EraseState storage e = _erase[tokenId];
        return (e.active, e.field, e.nextWord);
    }

    function eraseTokenData(uint256 tokenId, uint256 maxWords) external nonReentrant {
        if (!(ownerOf(tokenId) == msg.sender)) revert NOT_OWNER();
        if (!(maxWords > 0)) revert BAD_MAXWORDS();

        // prevent accidental sale while erasing
        if (listings[tokenId].open) {
            _closeListing(tokenId);
        }

        EraseState storage e = _erase[tokenId];
        if (!e.active) {
            e.active = true;
            e.field = 0;
            e.nextWord = 0;
            emit TokenDataEraseStarted(tokenId);
        }

        uint256 remaining = maxWords;

        while (remaining > 0 && e.field < 3) {
            uint256 used;
            bool doneField;
            (used, doneField) = _scrubTokenBytesField(tokenId, e.field, e.nextWord, remaining);

            if (used == 0 && !doneField) {
                // shouldn't happen, but avoid infinite loops
                break;
            }

            if (doneField) {
                e.field += 1;
                e.nextWord = 0;
            } else {
                // partial progress within current field
                e.nextWord += uint32(used);
            }

            if (used >= remaining) {
                remaining = 0;
            } else {
                remaining -= used;
            }

            emit TokenDataEraseProgress(tokenId, e.field, e.nextWord);
        }

        if (e.field >= 3) {
            // clear dekHash slot
            _clearDekHash(tokenId);

            // ensure high-level reads are empty
            delete _tokenData[tokenId];

            delete _erase[tokenId];

            emit TokenDataErased(tokenId);
        }
    }

    function _clearDekHash(uint256 tokenId) internal {
        uint256 mappingSlot;
        assembly { mappingSlot := _tokenData.slot }
        bytes32 base = keccak256(abi.encode(tokenId, mappingSlot));
        uint256 dekSlot = uint256(base) + 3; // struct field 3: dekHash
        assembly { sstore(dekSlot, 0) }
    }

    function _scrubTokenBytesField(
        uint256 tokenId,
        uint8 field,
        uint32 startWord,
        uint256 maxWords
    ) internal returns (uint256 usedWords, bool doneField) {
        // field: 0 metaCipher, 1 ownerEncDEK, 2 viewWrap
        if (!(field < 3)) revert BAD_FIELD();

        uint256 mappingSlot;
        assembly { mappingSlot := _tokenData.slot }
        bytes32 base = keccak256(abi.encode(tokenId, mappingSlot));
        uint256 slot = uint256(base) + uint256(field);

        return _scrubBytesAtSlot(slot, startWord, maxWords);
    }

    function _scrubBytesAtSlot(
        uint256 slot,
        uint32 startWord,
        uint256 maxWords
    ) internal returns (uint256 usedWords, bool done) {
        uint256 v;
        assembly { v := sload(slot) }

        // short bytes (<=31): stored directly in slot; lowest bit = 0
        if ((v & 1) == 0) {
            // if already empty, we're done
            if (v == 0) {
                return (0, true);
            }
            // clearing the slot clears the value
            assembly { sstore(slot, 0) }
            return (1, true);
        }

        // long bytes: slot stores length*2 + 1
        uint256 len = v >> 1;
        if (len == 0) {
            // inconsistent but treat as done
            assembly { sstore(slot, 0) }
            return (0, true);
        }

        uint256 totalWords = (len + 31) / 32;
        if (startWord >= totalWords) {
            // all data words already cleared; clear length slot
            assembly { sstore(slot, 0) }
            return (0, true);
        }

        uint256 dataStart = uint256(keccak256(abi.encode(slot)));

        uint256 i = startWord;
        uint256 cleared = 0;
        while (i < totalWords && cleared < maxWords) {
            uint256 dataSlot = dataStart + i;
            assembly { sstore(dataSlot, 0) }
            i++;
            cleared++;
        }

        if (i >= totalWords) {
            // finished clearing data words; clear the length slot too
            assembly { sstore(slot, 0) }
            return (cleared, true);
        }

        return (cleared, false);
    }

    // ---------- Burn ----------
    function burn(uint256 tokenId) external nonReentrant {
        address o = ownerOf(tokenId);
        if (!(o == msg.sender)) revert NOT_OWNER();

        // close listing and clear price
        _closeListing(tokenId);

        // NOTE: offers are state-indexed. Buyers should cancel or refund after expiry.
        delete _tokenData[tokenId];
        delete tosVersionOf[tokenId];
        delete _titles[tokenId];

        _burn(tokenId);

        emit Burned(tokenId);
    }

    // ---------- Internal listing helpers ----------
    function _addListed(uint256 tokenId) internal {
        if (_listedIndexPlus1[tokenId] != 0) return;
        _listedTokens.push(tokenId);
        _listedIndexPlus1[tokenId] = _listedTokens.length;
    }

    function _removeListed(uint256 tokenId) internal {
        uint256 idxPlus1 = _listedIndexPlus1[tokenId];
        if (idxPlus1 == 0) return;

        uint256 idx = idxPlus1 - 1;
        uint256 lastId = _listedTokens[_listedTokens.length - 1];

        if (idx != _listedTokens.length - 1) {
            _listedTokens[idx] = lastId;
            _listedIndexPlus1[lastId] = idx + 1;
        }

        _listedTokens.pop();
        _listedIndexPlus1[tokenId] = 0;
    }

    function _closeListing(uint256 tokenId) internal {
        // remove from listed set if open
        if (listings[tokenId].open) {
            listings[tokenId].open = false;
            listings[tokenId].priceWei = 0;
            _removeListed(tokenId);
            emit ListingUpdated(tokenId, false, 0);
        } else {
            // still clear price on transfer/burn to avoid stale prices for new owner
            if (listings[tokenId].priceWei != 0) {
                listings[tokenId].priceWei = 0;
                emit ListingUpdated(tokenId, false, 0);
            }
        }
    }


    // ---------- Offer index helpers ----------
    function _indexOffer(uint256 tokenId, address buyer) internal {
        _addOfferBuyer(tokenId, buyer);
        _addBuyerOfferToken(buyer, tokenId);
    }

    function _deindexOffer(uint256 tokenId, address buyer) internal {
        _removeOfferBuyer(tokenId, buyer);
        _removeBuyerOfferToken(buyer, tokenId);
    }

    function _addOfferBuyer(uint256 tokenId, address buyer) internal {
        uint256 idxPlus1 = _offerBuyerIndexPlus1[tokenId][buyer];
        if (idxPlus1 != 0) return;
        _offerBuyers[tokenId].push(buyer);
        _offerBuyerIndexPlus1[tokenId][buyer] = _offerBuyers[tokenId].length;
    }

    function _removeOfferBuyer(uint256 tokenId, address buyer) internal {
        uint256 idxPlus1 = _offerBuyerIndexPlus1[tokenId][buyer];
        if (idxPlus1 == 0) return;

        uint256 idx = idxPlus1 - 1;
        uint256 lastIdx = _offerBuyers[tokenId].length - 1;

        if (idx != lastIdx) {
            address lastBuyer = _offerBuyers[tokenId][lastIdx];
            _offerBuyers[tokenId][idx] = lastBuyer;
            _offerBuyerIndexPlus1[tokenId][lastBuyer] = idx + 1;
        }

        _offerBuyers[tokenId].pop();
        delete _offerBuyerIndexPlus1[tokenId][buyer];
    }

    function _addBuyerOfferToken(address buyer, uint256 tokenId) internal {
        uint256 idxPlus1 = _buyerOfferIndexPlus1[buyer][tokenId];
        if (idxPlus1 != 0) return;
        _buyerOfferTokens[buyer].push(tokenId);
        _buyerOfferIndexPlus1[buyer][tokenId] = _buyerOfferTokens[buyer].length;
    }

    function _removeBuyerOfferToken(address buyer, uint256 tokenId) internal {
        uint256 idxPlus1 = _buyerOfferIndexPlus1[buyer][tokenId];
        if (idxPlus1 == 0) return;

        uint256 idx = idxPlus1 - 1;
        uint256 lastIdx = _buyerOfferTokens[buyer].length - 1;

        if (idx != lastIdx) {
            uint256 lastTokenId = _buyerOfferTokens[buyer][lastIdx];
            _buyerOfferTokens[buyer][idx] = lastTokenId;
            _buyerOfferIndexPlus1[buyer][lastTokenId] = idx + 1;
        }

        _buyerOfferTokens[buyer].pop();
        delete _buyerOfferIndexPlus1[buyer][tokenId];
    }

    // ---------- Internal ERC721 helpers ----------
    function _exists(uint256 tokenId) internal view returns (bool) {
        return _owners[tokenId] != address(0);
    }

    function _mint(address to, uint256 tokenId) internal {
        if (!(to != address(0))) revert ZERO_ADDR();
        if (!(!_exists(tokenId))) revert ALREADY_MINTED();

        _balances[to] += 1;
        _owners[tokenId] = to;

        _addTokenToOwnerEnumeration(to, tokenId);

        emit Transfer(address(0), to, tokenId);
    }

    function _burn(uint256 tokenId) internal {
        address o = ownerOf(tokenId);

        _balances[o] -= 1;
        _removeTokenFromOwnerEnumeration(o, tokenId);
        delete _owners[tokenId];

        emit Transfer(o, address(0), tokenId);
    }

    function _transfer(address from, address to, uint256 tokenId) internal {
        if (!(ownerOf(tokenId) == from)) revert NOT_OWNER();
        if (!(to != address(0))) revert ZERO_ADDR();

        _balances[from] -= 1;
        _balances[to] += 1;
        _removeTokenFromOwnerEnumeration(from, tokenId);
        _addTokenToOwnerEnumeration(to, tokenId);
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }

    // ---------- Owner enumeration internals ----------
    function _addTokenToOwnerEnumeration(address to, uint256 tokenId) internal {
        _ownedTokensIndex[tokenId] = _ownedTokens[to].length;
        _ownedTokens[to].push(tokenId);
    }

    function _removeTokenFromOwnerEnumeration(address from, uint256 tokenId) internal {
        uint256 lastIndex = _ownedTokens[from].length - 1;
        uint256 idx = _ownedTokensIndex[tokenId];

        if (idx != lastIndex) {
            uint256 lastTokenId = _ownedTokens[from][lastIndex];
            _ownedTokens[from][idx] = lastTokenId;
            _ownedTokensIndex[lastTokenId] = idx;
        }

        _ownedTokens[from].pop();
        delete _ownedTokensIndex[tokenId];
    }

    // ---------- Utils ----------

    function _validateTitle(string memory t) internal pure {
        bytes memory b = bytes(t);
        if (!(b.length > 0 && b.length <= MAX_TITLE_BYTES)) revert BAD_TITLE_LEN();

        uint256 words = 0;
        bool inWord = false;

        for (uint256 i = 0; i < b.length; i++) {
            bytes1 c = b[i];
            bool isSpace = (c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d);
            if (isSpace) {
                if (inWord) inWord = false;
            } else {
                if (!inWord) {
                    words++;
                    if (!(words <= MAX_TITLE_WORDS)) revert TITLE_TOO_MANY_WORDS();
                    inWord = true;
                }
            }
        }

        if (!(words > 0)) revert BAD_TITLE();
    }

    // Accept native L1 (fees, escrow). Explicit receive to be safe with direct transfers.
    receive() external payable {}
}
