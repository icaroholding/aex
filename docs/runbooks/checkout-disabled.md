# Runbook: `checkout_disabled`

## Symptom

- **Status:** `503 Service Unavailable`
- **`code`:** `checkout_disabled`
- **Message:** `checkout not configured; set STRIPE_SECRET_KEY +
  STRIPE_PRICE_DEV + STRIPE_PRICE_TEAM and restart`

## Likely cause

`POST /v1/checkout/session` was hit but the control plane lacks
either `STRIPE_SECRET_KEY` (the outbound Stripe API key, used to
create Checkout Sessions) or one of the price ids. Distinct from
`stripe_disabled` (the webhook 503), because the webhook doesn't
need `STRIPE_SECRET_KEY` — it only needs `STRIPE_WEBHOOK_SECRET`.

## Remediation

1. Verify the secrets:

    ```bash
    fly secrets list -a aex-control-plane | grep -Ei 'STRIPE_(SECRET_KEY|PRICE_)'
    ```

    You should see all three:
    - `STRIPE_SECRET_KEY`
    - `STRIPE_PRICE_DEV`
    - `STRIPE_PRICE_TEAM`

2. Missing? Set them (test mode `sk_test_…`, live mode `sk_live_…`):

    ```bash
    fly secrets set \
        "STRIPE_SECRET_KEY=sk_test_..." \
        "STRIPE_PRICE_DEV=price_..." \
        "STRIPE_PRICE_TEAM=price_..." \
        -a aex-control-plane
    ```

3. Smoke-test:

    ```bash
    curl -sS -X POST https://api.spize.io/v1/checkout/session \
        -H "Content-Type: application/json" \
        -d '{"tier":"dev"}' | jq .
    # → { "url": "https://checkout.stripe.com/c/pay/cs_test_..." }
    ```

## Related

- `crates/aex-control-plane/src/routes/checkout.rs`
- `crates/aex-control-plane/src/stripe.rs::create_checkout_session`
- [`stripe-disabled.md`](stripe-disabled.md) — distinct: that one
  is for the inbound webhook, this one for outbound API.
