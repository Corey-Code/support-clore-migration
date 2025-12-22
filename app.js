import * as secp from '@noble/secp256k1';
import bs58check from 'bs58check';
import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';

/* =========================
   Utilities
   ========================= */

function u8(x) {
  if (x instanceof Uint8Array) return x;
  if (x instanceof ArrayBuffer) return new Uint8Array(x);
  return new Uint8Array(x);
}

function dbg(name, v) {
  // console.log('[DBG]', name, {
  //   type: typeof v,
  //   ctor: v && v.constructor && v.constructor.name,
  //   isU8: v instanceof Uint8Array,
  //   length: v && v.length,
  // });
  return v;
}

/* =========================
   Private key handling
   ========================= */

function wifToHex(wif) {
  const decoded = bs58check.decode(wif);
  // drop version byte, drop compression flag if present
  const key =
    decoded.length === 34 ? decoded.slice(1, 33) : decoded.slice(1, 32);

  return Array.from(key)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex) {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  if (hex.length !== 64) {
    throw new Error('Private key must be 32-byte hex (64 chars) or WIF');
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/* =========================
   Noble hash wiring (SYNC)
   ========================= */

secp.hashes.sha256 = (msg) => u8(sha256(u8(msg)));
secp.hashes.hmacSha256 = (key, msg) => u8(hmac(sha256, u8(key), u8(msg)));

/* =========================
   Message hashing
   ========================= */

const MESSAGE_PREFIX = '\x16Clore Signed Message:\n';

function doubleSha256(bytes) {
  const h1 = secp.hashes.sha256(bytes);
  const h2 = secp.hashes.sha256(h1);
  return h2;
}

function toBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

/* =========================
   Global signer
   ========================= */

window.signCloreMessage = async function signCloreMessage(
  privateKeyInput,
  cloreAddress,
  evmAddress
) {
  if (!privateKeyInput || !cloreAddress || !evmAddress) {
    throw new Error('Missing inputs');
  }

  const message = `Claim request for CLORE tokens to Ethereum address ${evmAddress} from ${cloreAddress}`;

  // Build Bitcoin-style message payload
  const enc = new TextEncoder();
  const msgBytes = enc.encode(message);
  const prefixBytes = enc.encode(MESSAGE_PREFIX);

  const payload = new Uint8Array([
    ...prefixBytes,
    msgBytes.length,
    ...msgBytes,
  ]);

  const msgHash = dbg('msgHash', u8(doubleSha256(payload)));

  // Normalize private key (hex or WIF)
  const input = privateKeyInput.trim();
  const hex =
    input.startsWith('0x') || input.length === 64
      ? input.replace(/^0x/, '')
      : wifToHex(input);

  const privKeyBytes = dbg('privKeyBytes', u8(hexToBytes(hex)));

  // Optional entropy (safe in browser)
  const extraEntropy = crypto.getRandomValues(new Uint8Array(32));

  const signature = await secp.sign(msgHash, privKeyBytes, {
    der: false,
    prehash: false,
    extraEntropy,
  });

  return {
    message,
    signature: toBase64(signature),
  };
};
