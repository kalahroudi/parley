# Billing (Stripe, test mode)

Flat per-device seats. The seat limit is checked once, when an admin **approves** a new device, and nowhere else: a tunnel that is open is never cut, and a device that is already approved keeps working whatever happens to the subscription.

## What the limit is

- No subscription: 3 devices (the free tier).
- A subscription in good standing (`active` or `trialing`): the quantity on the subscription, never fewer than 3.
- A subscription that lapses (`past_due`, `unpaid`, `canceled`, `paused`, ...): the paid quantity still applies for **7 days**, counted from the time Stripe reports the first lapse (not from when we receive it, and not extended by the events that follow), then the limit is 3 again.
- Devices over the limit stay enrolled. Approving another is refused (`402 seat_limit`) and the request stays pending, so approving works again once a seat frees up (revoking a device frees its seat) or the plan grows.
- Lowering the quantity takes effect at once for new approvals; it removes nothing.

## How it is wired

- `POST /v1/admin/billing`: the plan, the limit, seats used, and the grace deadline. Admin only.
- `POST /v1/admin/billing/checkout {"seats": n}`: a Stripe Checkout session for this tenant. The tenant name travels in the subscription's metadata, which only the gateway sets.
- `POST /v1/admin/billing/portal`: a Stripe Customer Portal session (card, seat count, cancel).
- `POST /v1/stripe/webhook`: Stripe's `customer.subscription.created|updated|deleted`. The body is verified against `Stripe-Signature` (HMAC-SHA256, 5 minute tolerance) before anything in it is read. Events apply in Stripe's order, not arrival order; any event that is not about our price, our tenants, or the right mode is acknowledged and ignored.

## Configuration (secrets and variables on the gateway Worker)

| Name | Meaning |
|---|---|
| `STRIPE_SECRET_KEY` | API key. `sk_test_...` or `rk_test_...`. A live key is refused unless `STRIPE_ALLOW_LIVE` is `1`. |
| `STRIPE_WEBHOOK_SECRET` | Signing secret of the webhook endpoint (`whsec_...`). |
| `STRIPE_PRICE_ID` | The per-device recurring price. Only items with this price count as seats. |
| `BILLING_RETURN_URL` | Where Stripe sends the admin back to (https, or http on localhost). Fixed in configuration, never taken from a request. |
| `STRIPE_ALLOW_LIVE` | `1` to accept a live key and live-mode events. Unset in test deployments. |

Set the key and the secret with `wrangler secret put`, never in a file. Local testing: `stripe listen --forward-to localhost:8787/v1/stripe/webhook` prints the endpoint's `whsec_` secret.

## What this does not cover

- Stripe sees the tenant name, the admin's billing details and the seat count. It sees no task data; the gateway holds none.
- The seat count is the number of approved, non-revoked enrollment records. An approved device that is not revoked is never purged (the 30-day retention applies to rejected and revoked records and expired requests), so a seat cannot be freed by waiting. Offboarding (T503) frees a seat by revoking the device.
- Checkout and Portal are tested against a stand-in for Stripe's API. T510 runs them against Stripe's test environment.
- Deleting a tenant (T503) does not cancel its Stripe subscription or delete its Stripe customer.
