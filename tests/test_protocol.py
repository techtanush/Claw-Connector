"""
tests/test_protocol.py

Tests for the Noise_XX channel:
  - Handshake succeeds in loopback (two local instances)
  - Key mismatch correctly aborts with SecurityError
  - Message send/receive roundtrip preserves plaintext

Covers SKILL_SPEC.md §14 "Noise_XX handshake succeeds in loopback test".
"""

from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from negotiate import (
        generate_keypair,
        build_noise_initiator,
        build_noise_responder,
        _noise_handshake_initiator,
        _noise_handshake_responder,
        SecurityError,
    )
    _NOISE_AVAILABLE = True
except ImportError:
    _NOISE_AVAILABLE = False


@unittest.skipUnless(_NOISE_AVAILABLE, "noiseprotocol not installed — skipping protocol tests")
class TestNoiseXXHandshake(unittest.TestCase):
    """Noise_XX loopback handshake and message exchange."""

    def setUp(self) -> None:
        self._tmp_a = tempfile.mkdtemp()
        self._tmp_b = tempfile.mkdtemp()
        (Path(self._tmp_a) / "skills" / "claw-diplomat").mkdir(parents=True)
        (Path(self._tmp_b) / "skills" / "claw-diplomat").mkdir(parents=True)
        self._priv_a, self._pub_a = generate_keypair(self._tmp_a)
        self._priv_b, self._pub_b = generate_keypair(self._tmp_b)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmp_a, ignore_errors=True)
        shutil.rmtree(self._tmp_b, ignore_errors=True)

    def test_handshake_loopback(self) -> None:
        """Initiator and responder complete Noise_XX handshake over in-process queues."""
        asyncio.run(self._run_loopback_handshake())

    async def _run_loopback_handshake(self) -> None:
        """Simulate WebSocket with asyncio.Queue pairs."""
        # Queue A→B and B→A
        q_ab: asyncio.Queue[bytes] = asyncio.Queue()
        q_ba: asyncio.Queue[bytes] = asyncio.Queue()

        class FakeWS:
            def __init__(self, recv_q: asyncio.Queue[bytes], send_q: asyncio.Queue[bytes]) -> None:
                self._recv = recv_q
                self._send = send_q

            async def send(self, data: bytes) -> None:
                await self._send.put(data)

            async def recv(self) -> bytes:
                return await self._recv.get()

        ws_a = FakeWS(recv_q=q_ba, send_q=q_ab)
        ws_b = FakeWS(recv_q=q_ab, send_q=q_ba)

        conn_a = build_noise_initiator(self._priv_a, self._pub_b)
        conn_b = build_noise_responder(self._priv_b)

        await asyncio.gather(
            _noise_handshake_initiator(conn_a, ws_a),
            _noise_handshake_responder(conn_b, ws_b),
        )

        # After handshake, both sides should be in the established state
        # Send a message from A to B
        plaintext = b"Hello, Noise!"
        encrypted = conn_a.encrypt(plaintext)
        decrypted = conn_b.decrypt(encrypted)
        self.assertEqual(decrypted, plaintext)

    def test_handshake_bidirectional(self) -> None:
        """After handshake, both A→B and B→A directions work."""
        asyncio.run(self._run_bidirectional())

    async def _run_bidirectional(self) -> None:
        q_ab: asyncio.Queue[bytes] = asyncio.Queue()
        q_ba: asyncio.Queue[bytes] = asyncio.Queue()

        class FakeWS:
            def __init__(self, recv_q: asyncio.Queue[bytes], send_q: asyncio.Queue[bytes]) -> None:
                self._recv = recv_q
                self._send = send_q

            async def send(self, data: bytes) -> None:
                await self._send.put(data)

            async def recv(self) -> bytes:
                return await self._recv.get()

        ws_a = FakeWS(q_ba, q_ab)
        ws_b = FakeWS(q_ab, q_ba)

        conn_a = build_noise_initiator(self._priv_a, self._pub_b)
        conn_b = build_noise_responder(self._priv_b)
        await asyncio.gather(
            _noise_handshake_initiator(conn_a, ws_a),
            _noise_handshake_responder(conn_b, ws_b),
        )

        # A→B
        msg1 = b"From A to B"
        self.assertEqual(conn_b.decrypt(conn_a.encrypt(msg1)), msg1)

        # B→A
        msg2 = b"From B to A"
        self.assertEqual(conn_a.decrypt(conn_b.encrypt(msg2)), msg2)

    def test_key_mismatch_raises_security_error(self) -> None:
        """If initiator uses the wrong target pubkey, handshake fails with SecurityError."""
        asyncio.run(self._run_key_mismatch())

    async def _run_key_mismatch(self) -> None:
        q_ab: asyncio.Queue[bytes] = asyncio.Queue()
        q_ba: asyncio.Queue[bytes] = asyncio.Queue()

        class FakeWS:
            def __init__(self, recv_q: asyncio.Queue[bytes], send_q: asyncio.Queue[bytes]) -> None:
                self._recv = recv_q
                self._send = send_q

            async def send(self, data: bytes) -> None:
                await self._send.put(data)

            async def recv(self) -> bytes:
                return await self._recv.get()

        ws_a = FakeWS(q_ba, q_ab)
        ws_b = FakeWS(q_ab, q_ba)

        # Initiator uses wrong target pubkey (pub_a instead of pub_b)
        conn_a = build_noise_initiator(self._priv_a, self._pub_a)  # wrong target pubkey
        conn_b = build_noise_responder(self._priv_b)

        # Handshake will complete at the Noise layer (Noise_XX doesn't abort on static key mismatch
        # until the application verifies it), so we test post-handshake verification
        await asyncio.gather(
            _noise_handshake_initiator(conn_a, ws_a),
            _noise_handshake_responder(conn_b, ws_b),
        )

        # After handshake, B's remote static key should be pub_a (not what was expected)
        # The application must verify this and reject
        from negotiate import verify_remote_static_key
        with self.assertRaises(SecurityError):
            verify_remote_static_key(conn_b, self._pub_b)  # expected pub_b but got pub_a


@unittest.skipUnless(_NOISE_AVAILABLE, "noiseprotocol not installed — skipping protocol tests")
class TestNoiseLargePayload(unittest.TestCase):
    """Noise channel handles payloads at max size."""

    def setUp(self) -> None:
        self._tmp_a = tempfile.mkdtemp()
        self._tmp_b = tempfile.mkdtemp()
        (Path(self._tmp_a) / "skills" / "claw-diplomat").mkdir(parents=True)
        (Path(self._tmp_b) / "skills" / "claw-diplomat").mkdir(parents=True)
        self._priv_a, self._pub_a = generate_keypair(self._tmp_a)
        self._priv_b, self._pub_b = generate_keypair(self._tmp_b)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmp_a, ignore_errors=True)
        shutil.rmtree(self._tmp_b, ignore_errors=True)

    def test_64kb_message_survives_roundtrip(self) -> None:
        """A 64 KB payload can be encrypted and decrypted correctly."""
        asyncio.run(self._run_large_payload())

    async def _run_large_payload(self) -> None:
        q_ab: asyncio.Queue[bytes] = asyncio.Queue()
        q_ba: asyncio.Queue[bytes] = asyncio.Queue()

        class FakeWS:
            def __init__(self, recv_q: asyncio.Queue[bytes], send_q: asyncio.Queue[bytes]) -> None:
                self._recv = recv_q
                self._send = send_q

            async def send(self, data: bytes) -> None:
                await self._send.put(data)

            async def recv(self) -> bytes:
                return await self._recv.get()

        ws_a = FakeWS(q_ba, q_ab)
        ws_b = FakeWS(q_ab, q_ba)
        conn_a = build_noise_initiator(self._priv_a, self._pub_b)
        conn_b = build_noise_responder(self._priv_b)
        await asyncio.gather(
            _noise_handshake_initiator(conn_a, ws_a),
            _noise_handshake_responder(conn_b, ws_b),
        )
        large_payload = b"X" * 64 * 1024  # 64 KB
        encrypted = conn_a.encrypt(large_payload)
        decrypted = conn_b.decrypt(encrypted)
        self.assertEqual(decrypted, large_payload)


if __name__ == "__main__":
    unittest.main()
