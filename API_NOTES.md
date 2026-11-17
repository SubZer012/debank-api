# DeBank internal API — findings and maintenance notes

Recorded 2026-11-15 from live probes against `api.debank.com` and a read of the
debank.com web bundle. Everything here was observed directly unless marked
**unverified**. DeBank can change any of it without notice; the last section says
how to re-derive it.

This file is about the API. The measured rate-limit behaviour of
`/portfolio/project_list` stays in the comment block at the top of `debank.py`.

## Implementation update — 2026-11-16 (`v1.1.2-rc.1`)

- Fixed `_get` signing: `_signed_query` sorts keys ascending with raw values;
  the URL query is encoded independently. The hash algorithm is unchanged.
- Exhausted HTTP 429 errors now say "rate limit or bad signature"; attempts,
  delays, `Result.ok`, parsed models, dust filtering and portfolio outputs are
  unchanged. No API-key headers or speculative lower-casing were added.
- Four offline regressions cover canonical ordering, empty/raw values,
  transport/signature separation, existing endpoint signatures, and failed-fetch
  semantics. Run `python -m unittest discover -s tests -v`.
- Live verification: one `/history/list` request with integer `start_time=0`,
  `page_count=20` and `user_addr` returned `error_code=0` and 20 history rows.
  No diagnostic retries were used. Upper-case and URL-special values remain
  unverified against the server; their offline tests only lock serialization.
- Compatibility checks against `v1.1.1` confirmed unchanged parsed rows,
  totals and failed-fetch behavior. No external records were written.
- `v1.1.2-rc.1` identifies the review candidate, not an approved stable release.
  After review/merge, publish `v1.1.2` at the approved commit and move consumer
  pins deliberately in their own reviews; do not move existing tags.
- History methods/pagination and raw-payload methods are not added: the notes
  below document available endpoints and requirements for future consumers.
  The only existing implementation defect identified here was signing.

Sections below retain the original 2026-11-15 observations; the defect and
proposed signing fix in §1 describe the pre-fix client.

---

## 1. Known defect: multi-parameter requests are signed wrongly

`DebankClient._get` builds one query string and uses it for both the URL and the
signature:

```python
qs = urlencode(sorted(params.items(), reverse=True))
```

DeBank verifies the signature against the query with **keys in ascending order**.
Reverse order is only correct by coincidence when there is exactly one parameter —
which is the case for both endpoints this client calls
(`/token/cache_balance_list`, `/portfolio/project_list`, each with `user_addr`
only). Nothing is broken today.

Any endpoint with two or more parameters fails, and it fails in a misleading way:

> **A bad signature is answered with `429 {"error_code":429,"error_msg":"Request too fast, please try again later."}`** —
> byte-for-byte the same response as real rate limiting.

Isolation test on `/history/list` with `page_count`, `start_time`, `user_addr`
(same session, 3 s apart, repeated to rule out chance):

| Signed string key order | URL key order | Result |
|---|---|---|
| ascending | ascending | 200 |
| ascending | descending | 200 |
| descending | descending | 429 |
| descending (repeat) | descending | 429 |
| ascending (repeat) | ascending | 200 |
| ascending, with empty `chain=` added | ascending | 200 |
| ascending, with `chain=eth` added | ascending | 200 |

So: only the order inside the **signed string** matters; the order in the URL does
not; empty-valued parameters are fine.

### Canonical signed string

```
METHOD + "\n" + path + "\n" + query
query = "&".join(f"{key}={value}" for key, value in sorted(params.items()))
```

- Keys ascending. Values raw, not URL-encoded.
- The rest of `_sign` (the two SHA-256 hashes and the HMAC-style XOR construction)
  is correct as written.
- **Unverified:** values that would need URL-encoding, and upper-case values. The
  reference implementation `null-routed/debank-hash-sign-v2` lower-cases the path
  and the whole query before signing; every value tested here was already
  lower-case, so that step has not been exercised.

### Where the reverse order came from

`LuKks/debank-re` reverses the caller's **insertion** order
(`[...query.entries()].reverse()`, commented "Must be reversed for valid
signature"). That yields ascending order only if the caller happened to list keys
descending. `null-routed/debank-hash-sign-v2` sorts ascending
(`a[0].localeCompare(b[0])`), which matches what the server accepts. Trust the
second reference for ordering.

### Fix, when a multi-parameter endpoint is added

1. In `_get`, build two strings: the signed query (ascending, raw values) and the
   URL query (any order, URL-encoded). Pass the first to `_build_headers`.
2. Add a unit test for the signed-string builder — pure function, no network:
   several keys given out of order must come out ascending.
3. Confirm with one live call to the new endpoint, then tag a release.

The change does not alter the output of the two existing endpoints (one parameter
sorts the same in either direction), so it is safe for the pinned consumers.

---

## 2. Reading DeBank's error responses

| Response | Meaning |
|---|---|
| HTTP 429, `{"error_code":429,"error_msg":"Request too fast, …"}` | Rate limit **or bad signature**. Indistinguishable from the body |
| HTTP 430, `{"code":430,"message":"This request has been limited"}` | Seen when the request carried `X-API-Key` / `X-API-Time` headers with a self-generated key. A plain request seconds later succeeded |
| HTTP 500, `{"error_code":500,"error_msg":"Internal Server Error",…}` | Malformed parameter value. Seen for `start_time=1793836800.0`; the integer form works |
| HTTP 404, HTML body | No such path (`/history/all_list` does not exist on the internal API) |
| HTTP 200 with `"error_code": 0` | Success. Payload is under `data` |

**Telling a bad signature from a rate limit:** in the same session, call a
known-good single-parameter endpoint such as `/token/cache_balance_list`. If that
returns 200 while the new call returns 429 on its very first attempt, and keeps
doing so, the request is malformed — do not add retries or delays.

---

## 3. Headers

What this client sends is sufficient: `source: web`, `account` (a per-session
browser id), `x-api-ts`, `x-api-nonce`, `x-api-ver: v2`, `x-api-sign`, plus
`origin` / `referer` / `user-agent`, over a Chrome-impersonating TLS session.

What the web app additionally sends, and what to do about it:

| Header | Web app behaviour | This client |
|---|---|---|
| `X-API-Key`, `X-API-Time` | A UUID and a timestamp generated once and kept in local storage; replaced when a response carries `x-set-api-key` | **Do not send.** A self-generated key drew a 430 |
| `X-Trans-Language` | UI language | Not needed |
| `source` | `web`; the app switches to `headless` / `unknown` when it detects automation | Keep `web` |
| `x-api-ver` | `v2`; a `v2.1` path exists behind a debug URL flag | Keep `v2` |

---

## 4. Endpoints

| Endpoint | Parameters | Status | Notes |
|---|---|---|---|
| `/token/cache_balance_list` | `user_addr` | In use | Spot balances, all chains, one call. Has not been seen to 429 |
| `/portfolio/project_list` | `user_addr` | In use | DeFi positions. Quota-limited per IP — see `debank.py` |
| `/history/list` | `user_addr`, `start_time`, `page_count`; optional `chain`, `token_id` | Verified, not implemented here | §5 |
| `/user/config` | `id` | Verified | Returns `limit_strategy` (`history.can_load`, `nft.can_load`, portfolio refresh settings, `level`). All permissive for an anonymous session |
| `/history/token_search` | `chain`, `q` | Seen in the web bundle, **unverified** | Token filter for the history view |
| `/bundle/history_list` | `id`, … | Seen in the web bundle, **unverified** | History for a saved bundle of addresses; presumably needs a logged-in session |

The official paid API (`pro-openapi.debank.com`, `AccessKey` header) exposes
`/v1/user/history_list` and `/v1/user/all_history_list` with the same response
shape. Whether it has the same history depth limit is **unverified**.

---

## 5. `/history/list`

Transaction history for one address across all chains, newest first.

### Request

```
GET /history/list?page_count=20&start_time=<int>&user_addr=<address>
```

- `start_time=0` returns the newest page. Otherwise it returns transactions
  **strictly earlier** than `start_time` (unix seconds).
- `start_time` must be an **integer**. `time_at` in responses is a whole number
  encoded as a float (`1793836800.0`); echoing it back unchanged returns 500.
- `page_count` is 20 in the web app. Pages of 21 were seen.
- `chain=<id>` filters to one chain. `token_id` filters to one token (**unverified**).

### Paging

The web app uses the last row's `time_at` as the next `start_time`. Because the
comparison is strict, transactions sharing that boundary second could be skipped
if the server does not keep them together (the 21-row pages suggest it does, but
that is **unverified**). The safe cursor is `oldest_time_at + 1`, de-duplicating
on transaction id; fall back to `oldest_time_at` if a whole page shares one
second. Stop when a page comes back empty.

### Limits

- **Rolling 180-day window.** On 2026-11-15 the oldest transaction served was
  dated 2026-05-19; any earlier `start_time` returned an empty list, with or
  without a `chain` filter, for an address known to have thousands of older
  transactions. The debank.com history page shows the same cut-off. DeBank
  previously served full history; this is a recent change.
- **The history export is gone.** debank.com used to offer a transaction export
  (`<address>_history.xlsx`). As of 2026-11 the site reports it as removed, at
  least temporarily, and the web bundle contains no export code.
- **Rate.** Short term: 11 consecutive pages at 1 s spacing succeeded, then one
  429; a request a few seconds later succeeded. Over a long crawl the limit is a
  per-IP quota, as with `/portfolio/project_list`: at 1.5 s spacing about 115
  pages went through in one sitting (with four refusals that cleared within 15 s
  to 2 min) before refusals stopped clearing for more than ten minutes. A second
  sitting later the same day allowed about 60 pages before the same block. Once a
  backoff ladder up to 5 min is exhausted, stop and come back later; continuing
  spends more of the quota.

Consequence for any consumer: history older than 180 days cannot be obtained from
DeBank for free. Anything that needs continuous history must capture it on a
schedule shorter than the window.

### Response (`data`)

```
history_list[]   one entry per transaction
  id               transaction hash
  chain            DeBank chain id (eth, base, arb, …)
  time_at          unix seconds, as a float
  idx              transaction index within its block (same value as tx.idx).
                   Matches the chain on transactions the queried address sent;
                   always 0 on transactions it did not send. No block number.
  cate_id          "send" | "receive" | "approve" | "cancel" | null
  project_id       key into project_dict, or null
  other_addr       counterparty / contract
  is_scam          bool
  cex_id           key into cex_dict, or null
  tx               { name, status, from_addr, to_addr, value, selector, message,
                     id, idx; eth_gas_fee and usd_gas_fee only on transactions
                     the queried address sent }
  sends[]          { token_id, amount, price, to_addr }
  receives[]       { token_id, amount, price, from_addr }
  token_approve    { … } or null
token_dict       token_id -> { id, chain, symbol, optimized_symbol, decimals, price,
                               is_scam, is_suspicious, is_verified, is_core,
                               protocol_id, name, logo_url, time_at, … }
project_dict     project_id -> { id, chain, name, logo_url, site_url }
cex_dict         address -> { id, name, is_deposit, is_withdraw, … }
cate_dict        cate_id -> { id, name }
is_big_addr      bool
```

- `token_id` is the contract address for ERC-20s, the chain id for native coins
  (`eth`, `op`, …), and a 32-character id for some other assets (NFT-like).
- `amount` is a JSON number (float), not a raw integer. Precision is limited to
  about 15 significant digits; `decimals` is in `token_dict`.
- `price` is the USD price at transaction time.
- `tx.name` is the contract method name (`multicall`, `borrow`, `transfer`, …);
  it is an input to classification, not a classification.
- The feed includes transactions the address did not send (incoming transfers,
  relayer fills, airdrops, spam).

---

## 6. `/portfolio/project_list` — fields the client currently discards

`_parse_item` reduces each portfolio item to one row with one net USD value. That
is deliberate for the spreadsheet consumers. A consumer that needs more should
read these from the raw item rather than widen `Position`:

| Field | Content |
|---|---|
| `detail.supply_token_list`, `detail.borrow_token_list`, `detail.reward_token_list` | Full token objects per leg (address `id`, `amount`, `price`, `decimals`) |
| `detail.health_rate` | Present on `lending` items |
| `stats.asset_usd_value`, `stats.debt_usd_value`, `stats.net_usd_value` | Collateral, debt and equity separately |
| `pool.id`, `pool.controller`, `pool.adapter_id`, `pool.index`, `position_index` | Identity of the position. Stability over time is **unverified** |
| `detail_types` | `common`, `lending`, `locked`, `vesting` seen; decides which `detail` keys exist (`unlock_at`, `end_at`, …) |
| `asset_token_list`, `asset_dict`, `proxy_detail`, `withdraw_actions`, `update_at` | Present on every item |

Two behaviours of the current parser that surprise new consumers:

- A lending position is reported as its collateral symbol and amount with the
  **net equity** as its USD value; the debt leg is netted out, and the row is
  relabelled `borrow` when debt exceeds assets. debank.com shows the legs
  separately.
- Positions and tokens under `DUST_THRESHOLD_USD` (`$10`) are dropped. For
  positions the test is on `|net|`, so a leveraged position with thin equity and
  large collateral and debt is dropped too.

Token objects in `/token/cache_balance_list` also carry `id` (contract address),
`raw_amount_str`, `decimals`, `is_scam`, `is_suspicious`, which the parser does
not keep.

---

## 7. Rules for changing this client

1. **Do not change what the two existing calls return.** Consumers may pin a tag
   and write results into permanent records. Preserve exported rows; new
   behaviour goes in new methods.
2. **Fix signing before adding any multi-parameter endpoint** (§1), with the unit
   test, in the same change.
3. **Never answer a 429 with more retries or longer delays before ruling out a
   bad signature** (§2). The rate-limit measurements in `debank.py` show retries
   make genuine limiting worse as well.
4. **Keep `Result.ok` semantics.** A failed fetch must stay distinguishable from
   an empty wallet.
5. **Do not send `X-API-Key` / `X-API-Time`.**
6. **Send cursors and other numeric parameters as integers.**
7. **Expose raw payloads rather than widening the parsed model** when a consumer
   needs more fields. Parsed rows are a view; the payload is the data.
8. **Tag every behavioural change** and let consumers move their pin deliberately.
9. **Write down what you measured, with the date**, here or in `debank.py`.
   DeBank's behaviour is only knowable by observation, and the observations are
   expensive to repeat.

---

## 8. Re-deriving this when DeBank changes something

The web app is the specification. To find what it currently does:

1. Fetch `https://debank.com/profile/<any address>/history` with the
   Chrome-impersonating session. The HTML references
   `https://assets.debank.com/static/js/main.<hash>.js`.
2. `main.<hash>.js` is only the webpack runtime. It contains the chunk map: an
   object of chunk id → hash. Chunks live at
   `https://assets.debank.com/static/js/<id>.<hash>.chunk.js` (about 70 files,
   12 MB).
3. Search the chunks for the API path (`/history/`, `/portfolio/`, …). The call
   site shows the exact parameter names and the paging logic.
4. The request wrapper is the module that sets `X-API-Key`. It shows every header,
   how parameters are filtered (null / undefined dropped, empty strings kept) and
   which arguments go to the signer: the merged query object, the method, and the
   canonical path.
5. **Grepping for `x-api-sign` finds nothing.** Header names are hex-encoded in
   the bundle (`782d6170692d7369676e` is `x-api-sign`), and the signer itself
   runs inside an embedded script VM — look for the helper names `sss`
   (SHA-256 hex) and `hssss` (HMAC-SHA-256 hex). Reading the VM is not practical;
   use the two reference implementations and confirm by experiment as in §1.
6. UI strings are in `https://assets.debank.com/locales/en/common.<hash>.json`
   (the hash is in the bundle). Searching it is a quick way to see whether a
   feature — an export button, a history limit — still exists.
7. Change one variable per request when experimenting, keep a known-good call in
   the same session as a control, and space requests a few seconds apart.

References:

- <https://github.com/null-routed/debank-hash-sign-v2> — signing, including key ordering
- <https://github.com/LuKks/debank-re> — signing and nonce generation; ordering comment is misleading (§1)
- <https://docs.cloud.debank.com> — official paid API; same response models
