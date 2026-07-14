/*
 * Soup billing Worker — the automated "printing press".
 *
 * Flow: Stripe fires a webhook when someone pays for Pro -> this Worker verifies
 * the webhook, mints a signed license (Ed25519, verified to activate in the CLI),
 * emails it to the customer, and records the sale + 51% referral commission in KV
 * for the future payout dashboard. No human in the loop.
 *
 * Secrets (set with `wrangler secret put <NAME>`), never in git:
 *   ISSUER_PKCS8_B64      base64 PKCS8 DER of the license issuer PRIVATE key
 *   ISSUER_PUBLIC_B64     raw 32-byte ed25519 public key, base64 (keys/license_pub.b64)
 *   STRIPE_WEBHOOK_SECRET the "whsec_..." from the Stripe webhook endpoint
 *   RESEND_API_KEY        Resend API key for sending the license email
 * Vars (wrangler.toml [vars]):
 *   FROM_EMAIL            e.g. "licenses@passsoup.dev"
 *   REFUND_WINDOW_DAYS    payout lock, e.g. "14"
 *   COMMISSION_RATE       e.g. "0.51"
 * Bindings:
 *   SALES  (KV namespace) — referral ledger
 */

import { canonicalJson, importIssuerKey, signLicense, featuresForTier, expiryIso } from "./sign-license.mjs";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/stripe/webhook") {
      return handleStripeWebhook(request, env);
    }
    if (request.method === "GET" && url.pathname === "/health") {
      return json({ status: "ok" });
    }
    // Minimal referral read API for the future dashboard (public summary only).
    if (request.method === "GET" && url.pathname.startsWith("/ref/")) {
      return referralSummary(url.pathname.slice("/ref/".length), env);
    }
    return new Response("Not found", { status: 404 });
  },
};

// --------------------------------------------------------------------------- //
// Stripe webhook
// --------------------------------------------------------------------------- //
async function handleStripeWebhook(request, env) {
  const payload = await request.text();
  const sig = request.headers.get("Stripe-Signature") || "";
  const ok = await verifyStripeSignature(payload, sig, env.STRIPE_WEBHOOK_SECRET);
  if (!ok) return new Response("bad signature", { status: 400 });

  let event;
  try { event = JSON.parse(payload); } catch { return new Response("bad json", { status: 400 }); }

  if (event.type !== "checkout.session.completed") {
    return json({ ignored: event.type });
  }
  const session = event.data.object;
  const email = session.customer_details?.email || session.customer_email;
  const referrer = session.client_reference_id || null; // the ?ref=... we passed in
  const amount = session.amount_total || 0;             // cents
  const currency = session.currency || "usd";
  const nowMs = Date.parse(event.created ? event.created * 1000 : Date.now()) || Date.now();

  if (!email) return json({ error: "no customer email" }, 400);

  // 1. Mint the license (Pro; Enterprise stays a sales conversation).
  const key = await importIssuerKey(env.ISSUER_PKCS8_B64);
  const issued = new Date(nowMs).toISOString();
  const doc = await signLicense(
    {
      org_id: slug(email),
      tier: "pro",
      features: featuresForTier("pro"),
      adopt_credits: 10,
      issued_at: issued,
      expires_at: expiryIso(nowMs, 365),
    },
    key,
    env.ISSUER_PUBLIC_B64
  );
  const licenseText = JSON.stringify(doc, null, 2);

  // 2. Email it to the customer.
  await sendLicenseEmail(env, email, licenseText);

  // 3. Record the sale + referral commission for the payout dashboard.
  if (env.SALES) {
    const rate = parseFloat(env.COMMISSION_RATE || "0.51");
    const lockDays = parseInt(env.REFUND_WINDOW_DAYS || "14", 10);
    const record = {
      session_id: session.id,
      email,
      referrer,
      amount,
      currency,
      commission: referrer ? Math.round(amount * rate) : 0,
      created_at: issued,
      payout_unlock_at: new Date(nowMs + lockDays * 86400_000).toISOString(),
      paid_out: false,
      refunded: false,
    };
    await env.SALES.put("sale:" + session.id, JSON.stringify(record));
    if (referrer) {
      const idxKey = "ref:" + referrer;
      const prev = JSON.parse((await env.SALES.get(idxKey)) || "[]");
      prev.push(session.id);
      await env.SALES.put(idxKey, JSON.stringify(prev));
    }
  }

  return json({ ok: true, licensed: email, referrer });
}

// --------------------------------------------------------------------------- //
// Stripe signature verification (HMAC-SHA256 over `${t}.${payload}`)
// --------------------------------------------------------------------------- //
async function verifyStripeSignature(payload, header, secret) {
  if (!secret) return false;
  const parts = Object.fromEntries(
    header.split(",").map((kv) => kv.split("=").map((s) => s.trim()))
  );
  const t = parts.t, v1 = parts.v1;
  if (!t || !v1) return false;
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${t}.${payload}`));
  const expected = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
  // constant-time-ish compare
  if (expected.length !== v1.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ v1.charCodeAt(i);
  return diff === 0;
}

// --------------------------------------------------------------------------- //
// Email (Resend)
// --------------------------------------------------------------------------- //
async function sendLicenseEmail(env, to, licenseText) {
  const b64 = btoa(unescape(encodeURIComponent(licenseText)));
  const body = {
    from: env.FROM_EMAIL || "licenses@passsoup.dev",
    to: [to],
    subject: "Your Soup Pro license",
    text:
      "Thanks for subscribing to Soup Pro.\n\n" +
      "Your license file is attached. Activate it offline:\n\n" +
      "  soup license activate soup.license.key\n\n" +
      "Then paid features (org signing, EU AI Act / GDPR packs, registry) unlock.\n",
    attachments: [{ filename: "soup.license.key", content: b64 }],
  };
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error("email send failed: " + res.status + " " + (await res.text()));
}

// --------------------------------------------------------------------------- //
// Referral summary (read-only; the dashboard will build on this)
// --------------------------------------------------------------------------- //
async function referralSummary(code, env) {
  if (!env.SALES) return json({ error: "no store" }, 500);
  const ids = JSON.parse((await env.SALES.get("ref:" + decodeURIComponent(code))) || "[]");
  let pending = 0, payable = 0, sales = 0;
  const now = Date.now();
  for (const id of ids) {
    const s = JSON.parse((await env.SALES.get("sale:" + id)) || "null");
    if (!s || s.refunded) continue;
    sales += 1;
    if (s.paid_out) continue;
    if (Date.parse(s.payout_unlock_at) <= now) payable += s.commission;
    else pending += s.commission;
  }
  return json({ code, sales, commission_pending: pending, commission_payable: payable });
}

// --------------------------------------------------------------------------- //
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status, headers: { "Content-Type": "application/json" },
  });
}
function slug(email) {
  return String(email).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60);
}
