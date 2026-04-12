"""
DeBank internal API client — reverse-engineered
-------------------------------------------------
Fetches DeFi protocol positions and spot token balances for any EVM address
via api.debank.com (DeBank's web-app backend). No API key required.

Caveats:
  - Unofficial — violates DeBank's ToS.
  - The signing algorithm or endpoint shapes can change without notice.

References for the signing algorithm:
  https://github.com/LuKks/debank-re          (full Node.js client)
  https://github.com/null-routed/debank-hash-sign-v2  (Go+JS signing impl)

TLS fingerprinting:
  DeBank detects non-browser TLS Client Hello fingerprints. Install curl_cffi
  for Chrome fingerprint spoofing (strongly recommended):

    pip install curl_cffi

  Without it, plain requests is used and may receive 429s or connection drops.

Usage:
  from debank import DebankClient

  client = DebankClient("0xYourAddress")
  result = client.fetch_all()          # spot + DeFi combined
  tokens = client.fetch_tokens()       # spot balances only
  defi   = client.fetch_protocols()    # DeFi positions only

Standalone test:
  python debank.py <0x_address>
"""

from dataclasses import dataclass, field
import hashlib
import json
import secrets
import sys
import time
import uuid
from urllib.parse import urlencode

# Try curl_cffi for Chrome TLS fingerprint spoofing.
# Without it, TLS fingerprinting may cause 429s or connection resets.
try:
    from curl_cffi import requests as _req

    def _make_session():
        return _req.Session(impersonate="chrome110")

    _HAS_CFFI = True
except ImportError:
    import requests as _req

    def _make_session():
        return _req.Session()

    _HAS_CFFI = False


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Position:
    name: str
    symbol: str
    amount: float
    usd_value: float
    chain: str
    protocol: str
    position_type: str
    extra: dict = field(default_factory=dict)


@dataclass
class Result:
    address: str
    positions: list
    total_usd: float


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_URL = "https://api.debank.com"
DUST_THRESHOLD_USD = 10.0

# DeBank's position "name" field → internal position_type
DEBANK_TYPE_MAP = {
    "Yield":               "lending",
    "Lending":             "lending",
    "Deposit":             "lending",
    "Liquidity Pool":      "lp",
    "Farming":             "lp",
    "Staked":              "staking",
    "Locked":              "locked",
    "Reward":              "reward",
    "Leveraged Farming":   "leverage",
    "Perpetuals":          "perp",
    "Options":             "derivative",
    "Governance":          "locked",
    "Vesting":             "locked",
    "Insurance":           "spot",
}


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def _sign(method: str, path: str, qs: str, nonce: str, ts: int) -> str:
    """
    Compute x-api-sign for api.debank.com requests.

    Ported from LuKks/debank-re (index.js) and null-routed/debank-hash-sign-v2.
    Equivalent to HMAC-SHA256(key=hash2, message=hash1) but implemented as the
    manual XOR construction used in the JS source.

      request_string = METHOD + "\\n" + path + "\\n" + qs
      key_string     = "debank-api\\nn_" + nonce + "\\n" + str(ts)

      hash1   = sha256(request_string).hexdigest()      # hex string
      hash2   = sha256(key_string).hexdigest()          # hex string

      xor1    = bytes(ord(c) ^ 0x36 for c in hash2)    # ipad XOR
      xor2    = bytes(ord(c) ^ 0x5C for c in hash2)    # opad XOR

      h1_raw  = sha256(xor1 + hash1.encode()).digest()  # RAW 32 bytes (not hex)
      sign    = sha256(xor2 + h1_raw).hexdigest()       # final hex signature

    Critical: h1 must be the raw digest bytes, NOT the hex string. The JS
    sha256() returns a Buffer, so the second sha256 takes raw bytes as input.
    Using hexdigest() for h1 produces a wrong signature (was the original bug).

    qs is the pre-built query string (no leading '?'), reverse-sorted by key.
    """
    request_string = f"{method.upper()}\n{path}\n{qs}"
    key_string = f"debank-api\nn_{nonce}\n{ts}"

    hash1 = hashlib.sha256(request_string.encode()).hexdigest()
    hash2 = hashlib.sha256(key_string.encode()).hexdigest()

    xor1 = bytes([ord(c) ^ 0x36 for c in hash2])  # ipad
    xor2 = bytes([ord(c) ^ 0x5C for c in hash2])  # opad

    h1_raw = hashlib.sha256(xor1 + hash1.encode()).digest()   # raw bytes, not hex
    sign   = hashlib.sha256(xor2 + h1_raw).hexdigest()

    return sign


def _build_headers(method: str, path: str, qs: str) -> dict:
    ts    = int(time.time())
    nonce = secrets.token_hex(20)  # 40 random hex chars; header value = "n_" + nonce
    sign  = _sign(method, path, qs, nonce, ts)

    return {
        "accept":          "*/*",
        "accept-language": "en-US,en;q=0.9",
        "origin":          "https://debank.com",
        "referer":         "https://debank.com/",
        "source":          "web",
        "user-agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
        "x-api-nonce": f"n_{nonce}",
        "x-api-sign":  sign,
        "x-api-ts":    str(ts),
        "x-api-ver":   "v2",
        # Tracks a "browser session" UID — fresh one per client instance
        "account": json.dumps(
            {"random_at": ts, "random_id": uuid.uuid4().hex, "user_addr": None},
            separators=(",", ":"),
        ),
    }


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class DebankClient:
    """
    Fetches DeFi protocol positions and spot token balances for one EVM
    address via DeBank's internal web API (api.debank.com).

    No API key required — uses the reverse-engineered signing algorithm.
    """

    def __init__(self, address: str):
        self.address = address.lower()
        self._session = _make_session()

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _get(self, path: str, params: dict) -> any:
        # Build query string once — used for both signing and the URL so they match exactly
        qs  = urlencode(sorted(params.items(), reverse=True)) if params else ""
        url = f"{BASE_URL}{path}?{qs}" if qs else f"{BASE_URL}{path}"

        for attempt in range(3):
            headers = _build_headers("GET", path, qs)
            try:
                resp = self._session.get(
                    url,
                    headers=headers,
                    timeout=30,
                )
            except Exception as e:
                if attempt == 2:
                    raise
                print(f"\n  [debank] Connection error ({e}), retrying...", end="", flush=True)
                time.sleep(2 ** attempt)
                continue

            if resp.status_code == 429:
                wait = 2 ** attempt
                print(f"\n  [debank] Rate limited, retrying in {wait}s...", end="", flush=True)
                time.sleep(wait)
                continue

            resp.raise_for_status()
            return resp.json()

        raise RuntimeError("DeBank request failed after 3 attempts")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch_all(self) -> Result:
        """Fetch spot token balances and DeFi positions, return combined result."""
        short = f"{self.address[:6]}...{self.address[-4:]}"
        print(f"  DeBank {short}  ", end="", flush=True)

        try:
            spot_positions  = self.fetch_tokens()
            defi_positions  = self.fetch_protocols()
        except Exception as e:
            print(f"[error: {e}]")
            return Result(
                address=self.address,
                positions=[],
                total_usd=0.0,
            )

        positions = sorted(
            spot_positions + defi_positions,
            key=lambda p: p.usd_value,
            reverse=True,
        )
        total = sum(p.usd_value for p in positions)
        prot  = len({p.protocol for p in defi_positions})
        print(
            f"{len(spot_positions)} tokens, {len(defi_positions)} DeFi positions "
            f"across {prot} protocols  (${total:,.2f})"
        )
        return Result(
            address=self.address,
            positions=positions,
            total_usd=total,
        )

    def fetch_tokens(self) -> list:
        """
        Call /token/cache_balance_list to get spot wallet balances across all
        chains in a single request. Returns cached data (same as DeBank dashboard).
        """
        path   = "/token/cache_balance_list"
        params = {"user_addr": self.address}
        data   = self._get(path, params)

        tokens = data.get("data", data) if isinstance(data, dict) else data
        if not isinstance(tokens, list):
            raise ValueError(f"Unexpected token response shape: {type(tokens).__name__}")

        positions = []
        for t in tokens:
            amount    = float(t.get("amount", 0) or 0)
            price     = float(t.get("price", 0) or 0)
            usd_value = amount * price

            if usd_value < DUST_THRESHOLD_USD:
                continue

            symbol = t.get("optimized_symbol") or t.get("symbol", "?")
            chain  = t.get("chain", "unknown")

            positions.append(Position(
                name=t.get("name", symbol),
                symbol=symbol,
                amount=amount,
                usd_value=usd_value,
                chain=chain,
                protocol="Wallet",
                position_type="spot",
            ))

        return positions

    def fetch_protocols(self) -> list:
        """Call /portfolio/project_list and parse all DeFi protocol positions."""
        path   = "/portfolio/project_list"
        params = {"user_addr": self.address}
        data   = self._get(path, params)

        # Response may be a list directly or wrapped in {"data": [...]}
        projects = data.get("data", data) if isinstance(data, dict) else data
        if not isinstance(projects, list):
            raise ValueError(f"Unexpected response shape: {type(projects).__name__}")

        positions = []
        for proj in projects:
            proj_name = proj.get("name", "Unknown")
            chain     = proj.get("chain", "unknown")
            for item in proj.get("portfolio_item_list", []):
                pos = self._parse_item(item, proj_name, chain)
                if pos:
                    positions.append(pos)

        return sorted(positions, key=lambda p: p.usd_value, reverse=True)

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse_item(self, item: dict, protocol: str, chain: str):
        """Parse one portfolio_item into a Position, or return None if dust/invalid."""
        stats   = item.get("stats", {})
        net_usd = float(stats.get("net_usd_value", 0) or 0)

        if abs(net_usd) < DUST_THRESHOLD_USD:
            return None

        # Position type — derived from DeBank's "name" field on the item
        name_field = item.get("name", "")
        pos_type   = DEBANK_TYPE_MAP.get(name_field, "lending")

        # If debt exceeds assets, the net is a liability — flip sign and tag as borrow
        asset_usd = float(stats.get("asset_usd_value", 0) or 0)
        debt_usd  = float(stats.get("debt_usd_value",  0) or 0)
        if debt_usd > asset_usd:
            pos_type = "borrow"
            net_usd  = -abs(net_usd)

        # Build symbol and amount from token lists
        detail        = item.get("detail", {})
        supply_tokens = detail.get("supply_token_list") or []
        reward_tokens = detail.get("reward_token_list") or []

        if supply_tokens:
            symbols = [
                t.get("optimized_symbol") or t.get("symbol", "?")
                for t in supply_tokens
            ]
            if len(symbols) == 1:
                symbol = symbols[0]
                amount = float(supply_tokens[0].get("amount", 0) or 0)
                display_name = f"{symbol} ({name_field})"
            else:
                symbol       = "+".join(symbols)
                amount       = 0.0
                display_name = f"{symbol} ({name_field})"
        else:
            symbol       = "?"
            amount       = 0.0
            display_name = f"{protocol} {name_field}"

        return Position(
            name=display_name,
            symbol=symbol,
            amount=amount,
            usd_value=net_usd,
            chain=chain,
            protocol=protocol,
            position_type=pos_type,
            extra={
                "asset_usd":    asset_usd,
                "debt_usd":     debt_usd,
                "reward_tokens": [
                    t.get("optimized_symbol") or t.get("symbol", "?")
                    for t in reward_tokens
                ],
            },
        )


# ---------------------------------------------------------------------------
# Standalone test — python debank.py <0x_address>
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python debank.py <0x_address>")
        sys.exit(1)

    address = sys.argv[1]

    if _HAS_CFFI:
        print("TLS: curl_cffi (Chrome fingerprint)")
    else:
        print("WARNING: curl_cffi not installed — using plain requests (may get 429s)")
        print("  Install with: pip install curl_cffi\n")

    print(f"Fetching DeBank positions (spot + DeFi) for {address}...\n")

    client = DebankClient(address)
    result = client.fetch_all()

    if not result.positions:
        print("\nNo positions returned — check address or inspect error above.")
        sys.exit(1)

    # Pretty-print results
    col = f"{'Protocol':<24} {'Name':<36} {'Symbol':<14} {'Type':<14} {'USD Value':>12}"
    print(f"\n{col}")
    print("-" * 104)
    for p in result.positions:
        sign = "-" if p.usd_value < 0 else " "
        print(
            f"{p.protocol:<24} {p.name:<36} {p.symbol:<14} "
            f"{p.position_type:<14} {sign}${abs(p.usd_value):>10,.2f}"
        )
    print("-" * 104)
    print(f"{'TOTAL':<88} ${result.total_usd:>10,.2f}")
    print(f"\n{len(result.positions)} positions | {len({p.protocol for p in result.positions})} protocols")
