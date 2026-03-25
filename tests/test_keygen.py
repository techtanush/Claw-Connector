"""
tests/test_keygen.py

Tests for keypair generation and key file management.
Covers SKILL_SPEC.md §14 bullet group "Key generation and connection".
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

# ── Path setup ─────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from negotiate import (
    generate_keypair,
    load_private_key_bytes,
    build_diplomat_address_token,
    decode_diplomat_address_token,
)


class TestKeypairGeneration(unittest.TestCase):
    """Keypair generation and file-system security."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        skill_dir = Path(self.tmp) / "skills" / "claw-diplomat"
        skill_dir.mkdir(parents=True)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ── Basic generation ──────────────────────────────────────────────────

    def test_generate_keypair_creates_files(self) -> None:
        """generate_keypair writes both key files."""
        priv, pub = generate_keypair(self.tmp)
        key_path = Path(self.tmp) / "skills" / "claw-diplomat" / "diplomat.key"
        pub_path = Path(self.tmp) / "skills" / "claw-diplomat" / "diplomat.pub"
        self.assertTrue(key_path.exists(), "diplomat.key not created")
        self.assertTrue(pub_path.exists(), "diplomat.pub not created")

    def test_generate_keypair_returns_bytes(self) -> None:
        """generate_keypair returns (private_bytes, public_bytes)."""
        priv, pub = generate_keypair(self.tmp)
        self.assertIsInstance(priv, bytes)
        self.assertIsInstance(pub, bytes)
        self.assertEqual(len(priv), 32, "NaCl private key must be 32 bytes")
        self.assertEqual(len(pub), 32, "NaCl public key must be 32 bytes")

    def test_private_key_file_mode_600(self) -> None:
        """diplomat.key must have mode 0600 (no group or other read/write)."""
        generate_keypair(self.tmp)
        key_path = Path(self.tmp) / "skills" / "claw-diplomat" / "diplomat.key"
        mode = stat.S_IMODE(key_path.stat().st_mode)
        bad_bits = mode & (
            stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH
        )
        self.assertEqual(bad_bits, 0, f"diplomat.key has world/group bits set: {oct(mode)}")

    def test_public_key_file_mode_644(self) -> None:
        """diplomat.pub must have mode 0644."""
        generate_keypair(self.tmp)
        pub_path = Path(self.tmp) / "skills" / "claw-diplomat" / "diplomat.pub"
        mode = stat.S_IMODE(pub_path.stat().st_mode)
        expected = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
        self.assertEqual(
            mode & 0o777,
            expected & 0o777,
            f"diplomat.pub mode is {oct(mode)}, expected 0644",
        )

    def test_generate_keypair_idempotent_skip(self) -> None:
        """Calling generate_keypair twice does NOT overwrite existing key."""
        priv1, pub1 = generate_keypair(self.tmp)
        priv2, pub2 = generate_keypair(self.tmp)
        # Second call must return the same bytes (loaded from disk, not regenerated)
        self.assertEqual(priv1, priv2, "Private key was regenerated on second call")
        self.assertEqual(pub1, pub2, "Public key was regenerated on second call")

    # ── Key loading ───────────────────────────────────────────────────────

    def test_load_private_key_requires_mode_600(self) -> None:
        """load_private_key_bytes raises PermissionError if mode is wrong."""
        generate_keypair(self.tmp)
        key_path = Path(self.tmp) / "skills" / "claw-diplomat" / "diplomat.key"
        # Deliberately loosen permissions
        key_path.chmod(0o644)
        with self.assertRaises(PermissionError):
            load_private_key_bytes(self.tmp)

    def test_load_private_key_returns_correct_bytes(self) -> None:
        """load_private_key_bytes returns the same bytes written by generate_keypair."""
        priv, _ = generate_keypair(self.tmp)
        loaded = load_private_key_bytes(self.tmp)
        self.assertEqual(priv, loaded)


class TestDiplomatAddressToken(unittest.TestCase):
    """Token build and decode roundtrip."""

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        skill_dir = Path(self.tmp) / "skills" / "claw-diplomat"
        skill_dir.mkdir(parents=True)
        _, self.pub_bytes = generate_keypair(self.tmp)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_token_round_trip(self) -> None:
        """build then decode produces correct fields."""
        token = build_diplomat_address_token(
            workspace_root=self.tmp,
            alias="Alice",
            relay_url="wss://relay.example.com:443",
            relay_token="rt_abc123",
            nat_hint="1.2.3.4",
            ttl_days=7,
        )
        decoded = decode_diplomat_address_token(token)
        self.assertEqual(decoded["v"], 1)
        self.assertEqual(decoded["alias"], "Alice")
        self.assertEqual(decoded["relay"], "wss://relay.example.com:443")
        self.assertEqual(decoded["relay_token"], "rt_abc123")
        self.assertEqual(decoded["nat_hint"], "1.2.3.4")
        self.assertIn("pubkey", decoded)
        self.assertIn("issued_at", decoded)
        self.assertIn("expires_at", decoded)

    def test_token_required_fields_present(self) -> None:
        """All required token fields are non-empty."""
        token = build_diplomat_address_token(
            workspace_root=self.tmp,
            alias="Bob",
            relay_url="wss://relay.example.com:443",
            relay_token="rt_xyz",
            nat_hint="unknown",
            ttl_days=7,
        )
        decoded = decode_diplomat_address_token(token)
        for field in ("v", "alias", "pubkey", "relay", "relay_token", "nat_hint", "issued_at", "expires_at"):
            self.assertIn(field, decoded, f"Missing field: {field}")
            self.assertIsNotNone(decoded[field], f"Field is None: {field}")

    def test_token_expiry_is_ttl_days_from_now(self) -> None:
        """Token expires_at is ttl_days days after issued_at."""
        import datetime
        token = build_diplomat_address_token(
            workspace_root=self.tmp,
            alias="Carol",
            relay_url="wss://relay.example.com:443",
            relay_token="rt_exp",
            nat_hint="unknown",
            ttl_days=7,
        )
        decoded = decode_diplomat_address_token(token)
        issued = datetime.datetime.fromisoformat(decoded["issued_at"].replace("Z", "+00:00"))
        expires = datetime.datetime.fromisoformat(decoded["expires_at"].replace("Z", "+00:00"))
        delta_days = (expires - issued).total_seconds() / 86400
        self.assertAlmostEqual(delta_days, 7.0, delta=0.01)

    def test_expired_token_detected(self) -> None:
        """decode_diplomat_address_token raises ValueError for expired token."""
        import datetime
        import base64
        # Build an already-expired token manually
        past = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(days=1)
        payload = {
            "v": 1,
            "alias": "Eve",
            "pubkey": self.pub_bytes.hex(),
            "relay": "wss://relay.example.com:443",
            "relay_token": "rt_old",
            "nat_hint": "unknown",
            "issued_at": (past - datetime.timedelta(days=8)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": past.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        token = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
        with self.assertRaises(ValueError, msg="Expired token should raise ValueError"):
            decode_diplomat_address_token(token)


if __name__ == "__main__":
    unittest.main()
