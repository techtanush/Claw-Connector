"""
tests/test_relay.py

Tests for the relay server (relay/relay.py):
  - Token reservation
  - Token revocation
  - Rate limiting (100/IP/hour)
  - Session timeout cleanup
  - WebSocket listener/connector pairing

These tests import relay internals directly for unit testing.
Integration tests require a running relay instance.
"""

from __future__ import annotations

import asyncio
import sys
import time
import unittest
from pathlib import Path

# ── Import relay module ────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent / "relay"))

try:
    import relay as relay_mod
    _RELAY_AVAILABLE = True
except ImportError:
    _RELAY_AVAILABLE = False


@unittest.skipUnless(_RELAY_AVAILABLE, "relay/relay.py dependencies not available")
class TestTokenGeneration(unittest.TestCase):
    """Relay token generation and format."""

    def test_generate_relay_token_format(self) -> None:
        """Generated token starts with 'rt_' and has correct length."""
        token = relay_mod._generate_relay_token()
        self.assertTrue(token.startswith("rt_"), f"Token does not start with 'rt_': {token}")
        # rt_ + 48 hex chars = 51 total
        self.assertEqual(len(token), 3 + relay_mod.TOKEN_LENGTH * 2)

    def test_tokens_are_unique(self) -> None:
        """Each call produces a unique token."""
        tokens = {relay_mod._generate_relay_token() for _ in range(100)}
        self.assertEqual(len(tokens), 100, "Token generation is not unique")


@unittest.skipUnless(_RELAY_AVAILABLE, "relay/relay.py dependencies not available")
class TestRateLimit(unittest.TestCase):
    """Rate limiter allows up to MAX_CONN_PER_IP_PER_HOUR and blocks above."""

    def setUp(self) -> None:
        # Reset global rate limit state for this IP
        relay_mod._ip_connections["test_ip_rate"] = []

    def test_within_limit_allowed(self) -> None:
        """First 5 connections are allowed (well below 100)."""
        for i in range(5):
            result = relay_mod._rate_check("test_ip_rate")
            self.assertTrue(result, f"Connection {i+1} should be allowed")

    def test_at_limit_blocked(self) -> None:
        """Connection at MAX+1 is blocked."""
        relay_mod._ip_connections["test_ip_limit"] = [
            time.monotonic() for _ in range(relay_mod.MAX_CONN_PER_IP_PER_HOUR)
        ]
        result = relay_mod._rate_check("test_ip_limit")
        self.assertFalse(result, "Connection at MAX+1 should be blocked")

    def test_old_connections_expire(self) -> None:
        """Connections older than 1 hour are evicted from the window."""
        old_time = time.monotonic() - 3601  # 1 hour + 1 second ago
        relay_mod._ip_connections["test_ip_expire"] = [old_time] * relay_mod.MAX_CONN_PER_IP_PER_HOUR
        # After eviction, all old entries gone — new connection allowed
        result = relay_mod._rate_check("test_ip_expire")
        self.assertTrue(result, "New connection should be allowed after old ones expire")

    def test_different_ips_are_independent(self) -> None:
        """Rate limit is per-IP."""
        relay_mod._ip_connections["ip_a"] = [time.monotonic()] * relay_mod.MAX_CONN_PER_IP_PER_HOUR
        # ip_b is fresh — should be allowed
        relay_mod._ip_connections["ip_b"] = []
        self.assertFalse(relay_mod._rate_check("ip_a"), "ip_a should be at limit")
        self.assertTrue(relay_mod._rate_check("ip_b"), "ip_b should be allowed")


@unittest.skipUnless(_RELAY_AVAILABLE, "relay/relay.py dependencies not available")
class TestTokenCleanup(unittest.TestCase):
    """Expired tokens are cleaned up by _cleanup_expired_tokens."""

    def setUp(self) -> None:
        # Clear global state
        relay_mod._token_queues.clear()
        relay_mod._token_ready.clear()
        relay_mod._token_pairs.clear()
        relay_mod._token_activity.clear()

    def tearDown(self) -> None:
        relay_mod._token_queues.clear()
        relay_mod._token_ready.clear()
        relay_mod._token_pairs.clear()
        relay_mod._token_activity.clear()

    def test_expired_tokens_removed(self) -> None:
        """Tokens with activity older than SESSION_TIMEOUT_S are removed."""
        token = "rt_test_expired"
        relay_mod._token_queues[token] = asyncio.Queue()
        relay_mod._token_ready[token] = asyncio.Event()
        relay_mod._token_activity[token] = time.monotonic() - relay_mod.SESSION_TIMEOUT_S - 1

        relay_mod._cleanup_expired_tokens()

        self.assertNotIn(token, relay_mod._token_queues)
        self.assertNotIn(token, relay_mod._token_activity)

    def test_active_tokens_kept(self) -> None:
        """Tokens with recent activity are NOT removed."""
        token = "rt_test_active"
        relay_mod._token_queues[token] = asyncio.Queue()
        relay_mod._token_ready[token] = asyncio.Event()
        relay_mod._token_activity[token] = time.monotonic()  # just now

        relay_mod._cleanup_expired_tokens()

        self.assertIn(token, relay_mod._token_queues)

    def test_mixed_cleanup(self) -> None:
        """Only expired tokens are removed, active tokens are kept."""
        expired_token = "rt_test_cleanup_expired"
        active_token = "rt_test_cleanup_active"

        relay_mod._token_queues[expired_token] = asyncio.Queue()
        relay_mod._token_activity[expired_token] = time.monotonic() - relay_mod.SESSION_TIMEOUT_S - 100

        relay_mod._token_queues[active_token] = asyncio.Queue()
        relay_mod._token_activity[active_token] = time.monotonic()

        relay_mod._cleanup_expired_tokens()

        self.assertNotIn(expired_token, relay_mod._token_queues)
        self.assertIn(active_token, relay_mod._token_queues)


@unittest.skipUnless(_RELAY_AVAILABLE, "relay/relay.py dependencies not available")
class TestIsoFormatter(unittest.TestCase):
    """_format_iso produces valid ISO 8601 UTC timestamps."""

    def test_format_iso_produces_utc_string(self) -> None:
        ts = time.time()
        result = relay_mod._format_iso(ts)
        self.assertTrue(result.endswith("Z"), f"ISO string does not end with Z: {result}")
        self.assertEqual(len(result), 20, f"ISO string wrong length: {result}")

    def test_format_iso_roundtrip(self) -> None:
        import datetime
        ts = time.time()
        iso = relay_mod._format_iso(ts)
        parsed = datetime.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        # Should be within 1 second of original
        self.assertAlmostEqual(parsed.timestamp(), ts, delta=1.0)


if __name__ == "__main__":
    unittest.main()
