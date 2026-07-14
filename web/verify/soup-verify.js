/*
 * soup-verify.js — the SAME passport verification as `soup verify`, in the browser.
 *
 * Pure JavaScript, zero dependencies, works offline and even from file:// (no
 * WebCrypto secure-context requirement). It mirrors, byte-for-byte:
 *   - canonical JSON (soup_cli.passport.hashing.canonical_json)
 *   - SHA-256 hash chain (schema.build_hash_chain)
 *   - Ed25519 signature over the root-hash string (crypto.verify_passport)
 *
 * If this file and the Python core ever disagree, a valid passport would read
 * as tampered — so the number formatting and canonicalisation below are kept
 * deliberately identical to the Python implementation.
 */
(function (global) {
  "use strict";

  // ---- canonical JSON (mirrors Python _encode) --------------------------- //
  function formatNumber(n) {
    if (!isFinite(n)) throw new Error("NaN/Infinity not allowed");
    return n.toString(); // 1 -> "1", 2.0 -> "2", 0.9 -> "0.9" (matches Python)
  }
  function canonicalJson(v) {
    if (v === null) return "null";
    const t = typeof v;
    if (t === "boolean") return v ? "true" : "false";
    if (t === "number") return formatNumber(v);
    if (t === "string") return JSON.stringify(v);
    if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
    if (t === "object") {
      const keys = Object.keys(v).sort();
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(v[k])).join(",") + "}";
    }
    throw new Error("cannot canonicalise " + t);
  }

  function utf8(str) {
    return new TextEncoder().encode(str);
  }
  function toHex(bytes) {
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, "0");
    return s;
  }
  function b64ToBytes(b64) {
    const bin = atob(b64.replace(/\s+/g, ""));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // ---- SHA-256 (pure JS) -------------------------------------------------- //
  const K256 = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  function sha256(msg) {
    const h = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    const ml = msg.length * 8;
    const withOne = msg.length + 1;
    const total = withOne + ((56 - (withOne % 64) + 64) % 64) + 8;
    const buf = new Uint8Array(total);
    buf.set(msg);
    buf[msg.length] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(total - 4, ml >>> 0);
    dv.setUint32(total - 8, Math.floor(ml / 0x100000000));
    const w = new Uint32Array(64);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let off = 0; off < total; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (hh + S1 + ch + K256[i] + w[i]) | 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
      h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
    }
    const out = new Uint8Array(32);
    const odv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) odv.setUint32(i * 4, h[i] >>> 0);
    return out;
  }
  function sha256Hex(str) {
    return "sha256:" + toHex(sha256(utf8(str)));
  }

  // ---- SHA-512 (pure JS, BigInt) ----------------------------------------- //
  const K512 = [
    "428a2f98d728ae22", "7137449123ef65cd", "b5c0fbcfec4d3b2f", "e9b5dba58189dbbc",
    "3956c25bf348b538", "59f111f1b605d019", "923f82a4af194f9b", "ab1c5ed5da6d8118",
    "d807aa98a3030242", "12835b0145706fbe", "243185be4ee4b28c", "550c7dc3d5ffb4e2",
    "72be5d74f27b896f", "80deb1fe3b1696b1", "9bdc06a725c71235", "c19bf174cf692694",
    "e49b69c19ef14ad2", "efbe4786384f25e3", "0fc19dc68b8cd5b5", "240ca1cc77ac9c65",
    "2de92c6f592b0275", "4a7484aa6ea6e483", "5cb0a9dcbd41fbd4", "76f988da831153b5",
    "983e5152ee66dfab", "a831c66d2db43210", "b00327c898fb213f", "bf597fc7beef0ee4",
    "c6e00bf33da88fc2", "d5a79147930aa725", "06ca6351e003826f", "142929670a0e6e70",
    "27b70a8546d22ffc", "2e1b21385c26c926", "4d2c6dfc5ac42aed", "53380d139d95b3df",
    "650a73548baf63de", "766a0abb3c77b2a8", "81c2c92e47edaee6", "92722c851482353b",
    "a2bfe8a14cf10364", "a81a664bbc423001", "c24b8b70d0f89791", "c76c51a30654be30",
    "d192e819d6ef5218", "d69906245565a910", "f40e35855771202a", "106aa07032bbd1b8",
    "19a4c116b8d2d0c8", "1e376c085141ab53", "2748774cdf8eeb99", "34b0bcb5e19b48a8",
    "391c0cb3c5c95a63", "4ed8aa4ae3418acb", "5b9cca4f7763e373", "682e6ff3d6b2b8a3",
    "748f82ee5defb2fc", "78a5636f43172f60", "84c87814a1f0ab72", "8cc702081a6439ec",
    "90befffa23631e28", "a4506cebde82bde9", "bef9a3f7b2c67915", "c67178f2e372532b",
    "ca273eceea26619c", "d186b8c721c0c207", "eada7dd6cde0eb1e", "f57d4f7fee6ed178",
    "06f067aa72176fba", "0a637dc5a2c898a6", "113f9804bef90dae", "1b710b35131c471b",
    "28db77f523047d84", "32caab7b40c72493", "3c9ebe0a15c9bebc", "431d67c49c100d4c",
    "4cc5d4becb3e42b6", "597f299cfc657e2a", "5fcb6fab3ad6faec", "6c44198c4a475817",
  ].map((x) => BigInt("0x" + x));
  const MASK64 = (1n << 64n) - 1n;
  function rotr64(x, n) { return ((x >> n) | (x << (64n - n))) & MASK64; }
  function sha512(msg) {
    let h = [
      "6a09e667f3bcc908", "bb67ae8584caa73b", "3c6ef372fe94f82b", "a54ff53a5f1d36f1",
      "510e527fade682d1", "9b05688c2b3e6c1f", "1f83d9abfb41bd6b", "5be0cd19137e2179",
    ].map((x) => BigInt("0x" + x));
    const ml = BigInt(msg.length) * 8n;
    const withOne = msg.length + 1;
    const total = withOne + ((112 - (withOne % 128) + 128) % 128) + 16;
    const buf = new Uint8Array(total);
    buf.set(msg);
    buf[msg.length] = 0x80;
    // 128-bit length, big-endian; we only need the low 64 bits.
    let len = ml;
    for (let i = 0; i < 8; i++) { buf[total - 1 - i] = Number(len & 0xffn); len >>= 8n; }
    const w = new Array(80);
    for (let off = 0; off < total; off += 128) {
      for (let i = 0; i < 16; i++) {
        let word = 0n;
        for (let j = 0; j < 8; j++) word = (word << 8n) | BigInt(buf[off + i * 8 + j]);
        w[i] = word;
      }
      for (let i = 16; i < 80; i++) {
        const s0 = rotr64(w[i - 15], 1n) ^ rotr64(w[i - 15], 8n) ^ (w[i - 15] >> 7n);
        const s1 = rotr64(w[i - 2], 19n) ^ rotr64(w[i - 2], 61n) ^ (w[i - 2] >> 6n);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK64;
      }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 80; i++) {
        const S1 = rotr64(e, 14n) ^ rotr64(e, 18n) ^ rotr64(e, 41n);
        const ch = (e & f) ^ (~e & MASK64 & g);
        const t1 = (hh + S1 + ch + K512[i] + w[i]) & MASK64;
        const S0 = rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) & MASK64;
        hh = g; g = f; f = e; e = (d + t1) & MASK64; d = c; c = b; b = a; a = (t1 + t2) & MASK64;
      }
      h = [
        (h[0] + a) & MASK64, (h[1] + b) & MASK64, (h[2] + c) & MASK64, (h[3] + d) & MASK64,
        (h[4] + e) & MASK64, (h[5] + f) & MASK64, (h[6] + g) & MASK64, (h[7] + hh) & MASK64,
      ];
    }
    const out = new Uint8Array(64);
    for (let i = 0; i < 8; i++) {
      let word = h[i];
      for (let j = 7; j >= 0; j--) { out[i * 8 + j] = Number(word & 0xffn); word >>= 8n; }
    }
    return out;
  }

  // ---- Ed25519 verify (pure JS, BigInt) ---------------------------------- //
  const P = (1n << 255n) - 19n;
  const D = -121665n * inv(121666n) % P;
  const Dp = ((D % P) + P) % P;
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  const I = powmod(2n, (P - 1n) / 4n, P); // sqrt(-1)

  function mod(a) { return ((a % P) + P) % P; }
  function powmod(b, e, m) {
    b = ((b % m) + m) % m;
    let r = 1n;
    while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
    return r;
  }
  function inv(a) { return powmod(a, P - 2n, P); }

  // Extended coordinates (X, Y, Z, T).
  function edAdd(p, q) {
    const [X1, Y1, Z1, T1] = p;
    const [X2, Y2, Z2, T2] = q;
    const A = mod((Y1 - X1) * (Y2 - X2));
    const B = mod((Y1 + X1) * (Y2 + X2));
    const C = mod(T1 * 2n * Dp * T2);
    const Dd = mod(Z1 * 2n * Z2);
    const E = B - A, F = Dd - C, G = Dd + C, H = B + A;
    return [mod(E * F), mod(G * H), mod(F * G), mod(E * H)];
  }
  function edScalarMul(p, e) {
    let q = [0n, 1n, 1n, 0n]; // neutral
    while (e > 0n) {
      if (e & 1n) q = edAdd(q, p);
      p = edAdd(p, p);
      e >>= 1n;
    }
    return q;
  }
  const By = 4n * inv(5n) % P;
  const Bx = recoverX(By, 0n);
  const B = [mod(Bx), mod(By), 1n, mod(Bx * By)];

  function recoverX(y, sign) {
    const y2 = mod(y * y);
    const u = mod(y2 - 1n);
    const v = mod(Dp * y2 + 1n);
    let x = mod(u * inv(v));
    let xx = powmod(x, (P + 3n) / 8n, P);
    if (mod(xx * xx - x) !== 0n) xx = mod(xx * I);
    if (mod(xx * xx - x) !== 0n) return null;
    if ((xx & 1n) !== sign) xx = mod(-xx);
    return xx;
  }
  function decodePoint(bytes) {
    if (bytes.length !== 32) return null;
    let y = 0n;
    for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(bytes[i]);
    const sign = (y >> 255n) & 1n;
    y &= (1n << 255n) - 1n;
    if (y >= P) return null;
    const x = recoverX(y, sign);
    if (x === null) return null;
    return [x, y, 1n, mod(x * y)];
  }
  function encodePoint(p) {
    const [X, Y, Z] = p;
    const zi = inv(Z);
    const x = mod(X * zi);
    const y = mod(Y * zi);
    const out = new Uint8Array(32);
    let yy = y;
    for (let i = 0; i < 32; i++) { out[i] = Number(yy & 0xffn); yy >>= 8n; }
    out[31] |= Number(x & 1n) << 7;
    return out;
  }
  function pointEqual(p, q) {
    const [X1, Y1, Z1] = p;
    const [X2, Y2, Z2] = q;
    if (mod(X1 * Z2 - X2 * Z1) !== 0n) return false;
    if (mod(Y1 * Z2 - Y2 * Z1) !== 0n) return false;
    return true;
  }
  function leToBig(bytes) {
    let r = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) r = (r << 8n) | BigInt(bytes[i]);
    return r;
  }

  function ed25519Verify(pubKey, message, sig) {
    if (pubKey.length !== 32 || sig.length !== 64) return false;
    const A = decodePoint(pubKey);
    if (!A) return false;
    const Rbytes = sig.slice(0, 32);
    const R = decodePoint(Rbytes);
    if (!R) return false;
    const s = leToBig(sig.slice(32, 64));
    if (s >= L) return false;
    const hInput = new Uint8Array(32 + 32 + message.length);
    hInput.set(Rbytes, 0);
    hInput.set(pubKey, 32);
    hInput.set(message, 64);
    const h = leToBig(sha512(hInput)) % L;
    const sB = edScalarMul(B, s);
    const hA = edScalarMul(A, h);
    const RplushA = edAdd(R, hA);
    return pointEqual(sB, RplushA);
  }

  // ---- passport verification (mirrors crypto.verify_passport) ------------ //
  function buildHashChain(blocks) {
    const blockHashes = {};
    for (const name of Object.keys(blocks)) {
      blockHashes[name] = sha256Hex(canonicalJson(blocks[name]));
    }
    const rootHash = sha256Hex(canonicalJson(blockHashes));
    return { block_hashes: blockHashes, root_hash: rootHash };
  }

  function verifyPassport(passport) {
    const reasons = [];
    const result = {
      valid: false, reasons, provenance_class: null, signer_type: null,
      signer_label: null, model_name: null, model_version: null,
      gate_verdict: null, unattested_fields: [],
    };
    if (!passport || typeof passport !== "object") {
      reasons.push("passport is not a JSON object");
      return result;
    }
    if (passport.soup_passport_version !== "1.0") {
      reasons.push("unsupported soup_passport_version " + JSON.stringify(passport.soup_passport_version));
    }
    const model = passport.model || {};
    result.model_name = model.name || null;
    result.model_version = model.version || null;
    result.provenance_class = passport.provenance_class || null;
    result.unattested_fields = passport.unattested_fields || [];
    const signer = ((passport.blocks || {}).accountability || {}).signer || {};
    result.signer_type = signer.type || null;
    result.signer_label = signer.label || null;
    result.gate_verdict = ((passport.blocks || {}).evaluation || {}).gate_verdict || null;

    if (!passport.blocks || typeof passport.blocks !== "object") {
      reasons.push("missing 'blocks' object");
      return result;
    }
    if (!passport.hash_chain || typeof passport.hash_chain !== "object") {
      reasons.push("missing 'hash_chain' object");
      return result;
    }

    // Recompute the hash chain and compare, naming any altered block.
    const recomputed = buildHashChain(passport.blocks);
    const stored = passport.hash_chain;
    const storedBH = stored.block_hashes || {};
    let chainOk = true;
    const names = new Set([...Object.keys(storedBH), ...Object.keys(recomputed.block_hashes)]);
    for (const name of [...names].sort()) {
      if (!(name in storedBH)) { reasons.push("block '" + name + "' missing from stored block_hashes"); chainOk = false; }
      else if (!(name in recomputed.block_hashes)) { reasons.push("unexpected block '" + name + "'"); chainOk = false; }
      else if (storedBH[name] !== recomputed.block_hashes[name]) { reasons.push("block '" + name + "' was altered (hash mismatch)"); chainOk = false; }
    }
    if (stored.root_hash !== recomputed.root_hash) { reasons.push("root_hash mismatch"); chainOk = false; }

    const signature = passport.signature;
    if (!signature || !signature.value) {
      reasons.push("passport is not signed");
      return result;
    }
    if (signature.algorithm !== "ed25519") {
      reasons.push("unsupported signature algorithm " + JSON.stringify(signature.algorithm));
      return result;
    }
    let sigOk = false;
    try {
      const pub = b64ToBytes(signature.public_key || "");
      const sig = b64ToBytes(signature.value || "");
      sigOk = ed25519Verify(pub, utf8(stored.root_hash || ""), sig);
    } catch (e) {
      reasons.push("signature could not be parsed: " + e.message);
    }
    if (!sigOk) reasons.push("signature is invalid (tampered or wrong key)");

    result.valid = chainOk && sigOk;
    return result;
  }

  const api = { canonicalJson, sha256Hex, sha512, ed25519Verify, verifyPassport, buildHashChain };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  global.SoupVerify = api;
})(typeof window !== "undefined" ? window : globalThis);
