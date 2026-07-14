# Soup billing Worker — automated license issuance

This Cloudflare Worker is the **automated printing press**: a customer pays for
Pro on Stripe → Stripe calls this Worker → it mints a signed license and emails
it to the customer, and records the 51% referral commission. No manual step.

> The license-signing crypto and the Stripe-signature check are both tested in
> Node against the real CLI (`soup license activate` accepts a Worker-minted
> license). What still needs a live environment is the Stripe webhook wiring and
> the email provider — steps below.

## What you need (accounts)

- **Cloudflare** account (you have one — the domain is there).
- **Stripe** account with the Pro Payment Link you already made.
- **Resend** account (free tier) for sending the license email — get an API key
  and verify the `passsoup.dev` sending domain. (Any email API works; Resend is
  the default in `worker.js`.)

## One-time setup

```bash
npm i -g wrangler
cd infra/worker
wrangler login

# 1. Create the referral/sales store and paste its id into wrangler.toml
wrangler kv namespace create SALES

# 2. Prepare the issuer key as a base64 PKCS8 secret (run once, locally):
python3 - <<'PY'
import base64
pem = open("../../tools/secrets/license_issuer_priv.pem").read()
der = base64.b64decode("".join(l for l in pem.splitlines() if "KEY" not in l))
print(base64.b64encode(der).decode())
PY
# copy the printed line, then:
wrangler secret put ISSUER_PKCS8_B64        # paste it
wrangler secret put ISSUER_PUBLIC_B64        # paste keys/license_pub.b64
wrangler secret put RESEND_API_KEY           # your Resend key
# STRIPE_WEBHOOK_SECRET is set after step 4.

# 3. Deploy
wrangler deploy
# -> gives you a URL like https://soup-billing.<you>.workers.dev
```

## Wire Stripe → Worker

4. In the **Stripe Dashboard → Developers → Webhooks → Add endpoint**:
   - URL: `https://soup-billing.<you>.workers.dev/stripe/webhook`
   - Event: `checkout.session.completed`
   - Copy the signing secret (`whsec_...`) and run:
     ```bash
     wrangler secret put STRIPE_WEBHOOK_SECRET
     ```
5. On the Payment Link, make sure Stripe **collects the customer email** (it does
   by default). The site already passes the referrer as `client_reference_id`.

That's it. Pay through the Pro link in Stripe **test mode** → within seconds the
customer gets the license email, and `GET /ref/<email>` shows the referrer's
running commission.

## Endpoints

- `POST /stripe/webhook` — Stripe calls this. Verifies signature, mints + emails
  the license, records the sale.
- `GET /ref/<code>` — read-only referral summary `{sales, commission_pending,
  commission_payable}` (the payout dashboard will build on this).
- `GET /health` — liveness.

## Security notes

- The issuer **private key** lives only as a Worker **secret** — never in git,
  never in the browser. Rotating it means re-issuing `keys/license_pub.*` and
  shipping a new CLI version.
- Go to **Stripe live mode** and swap the Payment Link on the site
  (`web/site/index.html`, `STRIPE_PRO`) from the `test_` link to the live one
  before taking real money.

## What this Worker does NOT do yet (the referral payout dashboard)

Storing commissions is done; **paying them out** and a **login dashboard** need:
`Stripe Connect` (so referrers can receive money, with the KYC Stripe requires),
referrer accounts/auth, and a UI. That is a separate build — see the plan the
team discussed. The `payout_unlock_at` field already enforces the refund-window
lock so you never pay a commission on a sale that later gets refunded.
