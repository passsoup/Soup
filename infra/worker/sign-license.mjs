/*
 * sign-license.mjs — mint a signed Soup license with Web Crypto Ed25519.
 *
 * This is the automated equivalent of tools/issue_license.py. It runs both in a
 * Cloudflare Worker and in Node (both expose the same Web Crypto `crypto.subtle`
 * with Ed25519). The signature MUST be byte-identical to what the Python issuer
 * produces, or the CLI (`soup license activate`) would reject it — so the
 * canonical JSON here mirrors soup_cli.passport.hashing.canonical_json exactly.
 */

// --- canonical JSON: mirrors the Python/JS canonicaliser (JS number format) ---
function formatNumber(n) {
  if (!isFinite(n)) throw new Error("NaN/Infinity not allowed");
  return n.toString();
}
export function canonicalJson(v) {
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

function b64encode(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Import the issuer private key from a base64 PKCS8 DER (the Worker secret). */
export async function importIssuerKey(pkcs8B64) {
  return crypto.subtle.importKey(
    "pkcs8",
    b64ToBytes(pkcs8B64),
    { name: "Ed25519" },
    false,
    ["sign"]
  );
}

/** The raw 32-byte public key (base64) — must equal keys/license_pub.b64. */
export async function publicKeyB64FromPrivate(pkcs8B64) {
  // Derive by importing as a JWK round-trip is awkward; instead the caller
  // provides the known public key. This helper exists for tests that pass a
  // freshly generated key pair.
  throw new Error("provide the public key explicitly (keys/license_pub.b64)");
}

/**
 * Build + sign a license document. Returns the object the customer activates.
 *   params: { org_id, tier, features[], adopt_credits|null, issued_at, expires_at }
 *   privateKey: CryptoKey (Ed25519, from importIssuerKey)
 *   publicKeyB64: raw 32-byte ed25519 public key, base64 (keys/license_pub.b64)
 */
export async function signLicense(params, privateKey, publicKeyB64) {
  const license = {
    org_id: params.org_id,
    tier: params.tier,
    features: (params.features || []).slice().sort(),
    adopt_credits: params.adopt_credits == null ? null : params.adopt_credits,
    issued_at: params.issued_at,
    expires_at: params.expires_at,
  };
  const payload = new TextEncoder().encode(canonicalJson(license));
  const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, payload));
  return {
    license,
    signature: {
      algorithm: "ed25519",
      value: b64encode(sig),
      public_key: publicKeyB64,
    },
  };
}

/** Map a Stripe price/tier to the features a license should grant. */
export function featuresForTier(tier) {
  if (tier === "enterprise") {
    return [
      "org-signing", "registry", "adopt", "airgap",
      "pack:eu-ai-act-gpai", "pack:gdpr", "pack:bank-mrm",
      "pack:eu-ai-act-highrisk", "pack:hipaa", "pack:nist-ai-rmf", "pack:iso-42001",
    ];
  }
  // pro
  return ["org-signing", "registry", "adopt", "pack:eu-ai-act-gpai", "pack:gdpr"];
}

/** ISO date one year (or `days`) from a base epoch-ms. */
export function expiryIso(fromMs, days = 365) {
  return new Date(fromMs + days * 86400_000).toISOString();
}
