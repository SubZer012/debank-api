"""Offline request-signing regressions. Run: python -m unittest discover -s tests."""

import hashlib
import hmac
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlencode, urlsplit

import debank


class SigningTests(unittest.TestCase):
    def test_canonical_query(self):
        self.assertEqual(
            debank._signed_query({"user_addr": "0xabc", "start_time": 0,
                                  "page_count": 20, "chain": ""}),
            "chain=&page_count=20&start_time=0&user_addr=0xabc",
        )
        self.assertEqual(debank._signed_query({}), "")
        self.assertEqual(debank._signed_query({"q": "A B/+&="}), "q=A B/+&=")

    def test_request_signs_raw_query_but_encodes_url(self):
        params = {"user_addr": "0xabc", "start_time": 0, "page_count": 20,
                  "chain": "", "q": "A B/+&="}
        canonical = "chain=&page_count=20&q=A B/+&=&start_time=0&user_addr=0xabc"
        nonce, ts = "a" * 40, 1794787200
        key = hashlib.sha256(f"debank-api\nn_{nonce}\n{ts}".encode()).hexdigest()
        message = hashlib.sha256(f"GET\n/history/list\n{canonical}".encode()).hexdigest()
        expected = hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()
        session = Mock()
        session.get.return_value.status_code = 200
        session.get.return_value.json.return_value = {"data": {"history_list": []}}
        with patch.object(debank, "_make_session", return_value=session), \
             patch.object(debank.time, "time", return_value=ts), \
             patch.object(debank.secrets, "token_hex", return_value=nonce):
            result = debank.DebankClient("0xabc")._get("/history/list", params)
        self.assertEqual(result, {"data": {"history_list": []}})
        url = session.get.call_args.args[0]
        self.assertEqual(parse_qs(urlsplit(url).query, keep_blank_values=True),
                         {key: [str(value)] for key, value in params.items()})
        headers = session.get.call_args.kwargs["headers"]
        self.assertEqual(headers["x-api-sign"], expected)
        self.assertFalse({"x-api-key", "x-api-time"} & {key.lower() for key in headers})

    def test_existing_endpoint_signatures_unchanged(self):
        params = {"user_addr": "0xabcdef0123456789abcdef0123456789abcdef01"}
        old_query = urlencode(sorted(params.items(), reverse=True))
        for path in ("/token/cache_balance_list", "/portfolio/project_list"):
            with self.subTest(path=path):
                self.assertEqual(
                    debank._sign("GET", path, debank._signed_query(params), "a" * 40, 1794787200),
                    debank._sign("GET", path, old_query, "a" * 40, 1794787200),
                )

    def test_429_remains_failure_not_empty_wallet(self):
        session = Mock()
        session.get.return_value.status_code = 429
        with patch.object(debank, "_make_session", return_value=session), \
             patch.object(debank.time, "sleep"):
            result = debank.DebankClient("0xAbC").fetch_all()
        self.assertFalse(result.ok)
        self.assertEqual(result.address, "0xAbC")
        self.assertIn("rate limit or bad signature", result.error)
        self.assertEqual(session.get.call_count, debank.RATE_LIMIT_MAX_ATTEMPTS)


if __name__ == "__main__":
    unittest.main()
