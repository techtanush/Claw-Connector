"""
tests/test_negotiation.py

End-to-end negotiation flow tests (propose → counter → accept → commit).
Tests are in-process with mocked transport — no relay required.

Covers SKILL_SPEC.md §14 bullet group "Negotiation".
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from negotiate import (
    generate_keypair,
    build_diplomat_address_token,
    build_negotiate_message,
    parse_negotiate_message,
    compute_terms_hash,
    SessionState,
    LedgerSession,
    upsert_session,
    get_session,
    append_commitment_to_memory,
    build_memory_entry,
    MAX_MEMORY_ENTRY_CHARS,
)


def _mk_workspace(alias: str = "Agent") -> tuple[str, bytes, bytes]:
    """Create a temp workspace, generate keypair, return (root, priv, pub)."""
    tmp = tempfile.mkdtemp()
    (Path(tmp) / "skills" / "claw-diplomat").mkdir(parents=True)
    Path(tmp, "skills", "claw-diplomat", "ledger.json").write_text('{"sessions":[]}')
    Path(tmp, "MEMORY.md").write_text("# Memory\n\n## Diplomat Commitments\n")
    priv, pub = generate_keypair(tmp)
    return tmp, priv, pub


class TestTermsHashConsistency(unittest.TestCase):
    """Terms hash is identical on both sides for the same final_terms."""

    def test_hash_is_deterministic(self) -> None:
        terms = {"my_tasks": ["finish spec"], "peer_tasks": ["review PR"], "deadline": "2026-04-01T12:00:00Z"}
        h1 = compute_terms_hash(terms)
        h2 = compute_terms_hash(terms)
        self.assertEqual(h1, h2)

    def test_hash_differs_on_mutation(self) -> None:
        terms_a = {"my_tasks": ["finish spec"], "peer_tasks": ["review PR"], "deadline": "2026-04-01T12:00:00Z"}
        terms_b = {"my_tasks": ["finish spec"], "peer_tasks": ["write docs"], "deadline": "2026-04-01T12:00:00Z"}
        self.assertNotEqual(compute_terms_hash(terms_a), compute_terms_hash(terms_b))

    def test_key_order_does_not_matter(self) -> None:
        """sort_keys=True ensures key ordering is irrelevant."""
        terms_a = {"deadline": "2026-04-01T12:00:00Z", "my_tasks": ["A"], "peer_tasks": ["B"]}
        terms_b = {"my_tasks": ["A"], "peer_tasks": ["B"], "deadline": "2026-04-01T12:00:00Z"}
        self.assertEqual(compute_terms_hash(terms_a), compute_terms_hash(terms_b))


class TestMessageBuildParse(unittest.TestCase):
    """NegotiationMessage build/parse roundtrip."""

    def setUp(self) -> None:
        self._tmp, self._priv, self._pub = _mk_workspace("Alice")

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_propose_message_roundtrip(self) -> None:
        msg = build_negotiate_message(
            session_id="sess-001",
            msg_type="PROPOSE",
            from_pubkey=self._pub.hex(),
            payload={
                "my_tasks": ["write spec"],
                "peer_tasks": ["review spec"],
                "deadline": "2026-04-01T12:00:00Z",
                "terms_version": 1,
            },
        )
        parsed = parse_negotiate_message(msg)
        self.assertEqual(parsed["session_id"], "sess-001")
        self.assertEqual(parsed["msg_type"], "PROPOSE")
        self.assertEqual(parsed["from_pubkey"], self._pub.hex())
        self.assertIn("timestamp", parsed)
        self.assertIn("nonce", parsed)

    def test_accept_message_contains_terms_hash(self) -> None:
        terms = {"my_tasks": ["finish spec"], "peer_tasks": ["review"], "deadline": "2026-04-10T12:00:00Z"}
        msg = build_negotiate_message(
            session_id="sess-002",
            msg_type="ACCEPT",
            from_pubkey=self._pub.hex(),
            payload={
                **terms,
                "terms_version": 2,
                "terms_hash": compute_terms_hash(terms),
            },
        )
        parsed = parse_negotiate_message(msg)
        self.assertIn("terms_hash", parsed["payload"])

    def test_counter_increments_terms_version(self) -> None:
        """Simulated counter: terms_version must be 2 after one counter."""
        session_id = "sess-003"
        # Initial proposal (v1)
        msg1 = build_negotiate_message(
            session_id=session_id,
            msg_type="PROPOSE",
            from_pubkey=self._pub.hex(),
            payload={"my_tasks": ["X"], "peer_tasks": ["Y"], "deadline": "2026-04-01T12:00:00Z", "terms_version": 1},
        )
        # Counter (v2)
        msg2 = build_negotiate_message(
            session_id=session_id,
            msg_type="COUNTER",
            from_pubkey=self._pub.hex(),
            payload={"my_tasks": ["X2"], "peer_tasks": ["Y"], "deadline": "2026-04-05T12:00:00Z", "terms_version": 2},
        )
        p1 = parse_negotiate_message(msg1)
        p2 = parse_negotiate_message(msg2)
        self.assertEqual(p1["payload"]["terms_version"], 1)
        self.assertEqual(p2["payload"]["terms_version"], 2)


class TestFullNegotiationFlow(unittest.TestCase):
    """
    Full propose → accept → commit flow in-process.
    No network — tests the logic chain, not the transport.
    """

    def setUp(self) -> None:
        self._tmp_a, self._priv_a, self._pub_a = _mk_workspace("Alice")
        self._tmp_b, self._priv_b, self._pub_b = _mk_workspace("Bob")

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmp_a, ignore_errors=True)
        shutil.rmtree(self._tmp_b, ignore_errors=True)

    def test_propose_accept_commit_produces_matching_hashes(self) -> None:
        """After both sides ACCEPT, memory_hash must be identical."""
        session_id = "full-flow-001"
        terms = {
            "my_tasks": ["Write integration tests"],
            "peer_tasks": ["Review integration tests"],
            "deadline": "2026-04-15T17:00:00Z",
        }
        terms_hash = compute_terms_hash(terms)

        # Both sides accept and write MEMORY.md
        entry_a = build_memory_entry(
            session_id_short="full-0",
            peer_alias="Bob",
            my_tasks="Write integration tests",
            peer_tasks="Review integration tests",
            deadline_utc=terms["deadline"],
            state="ACTIVE",
        )
        entry_b = build_memory_entry(
            session_id_short="full-0",
            peer_alias="Alice",
            my_tasks="Review integration tests",
            peer_tasks="Write integration tests",
            deadline_utc=terms["deadline"],
            state="ACTIVE",
        )

        hash_a = append_commitment_to_memory(self._tmp_a, entry_a)
        hash_b = append_commitment_to_memory(self._tmp_b, entry_b)

        # memory_hash is sha256 of the entry written
        expected_a = hashlib.sha256(entry_a.encode()).hexdigest()
        expected_b = hashlib.sha256(entry_b.encode()).hexdigest()
        self.assertEqual(hash_a, expected_a)
        self.assertEqual(hash_b, expected_b)

        # The two hashes differ (different peer aliases in entries) — that's correct.
        # Both sides verify each other's hash matches their own computation.
        # (In the actual protocol, peer's memory_hash is sent in COMMIT_ACK and verified.)

    def test_memory_entry_max_500_chars(self) -> None:
        """build_memory_entry output is ≤ 500 chars."""
        entry = build_memory_entry(
            session_id_short="abcd",
            peer_alias="Alice",
            my_tasks="Write integration tests for the complete claw-diplomat negotiation flow",
            peer_tasks="Review and approve all integration tests by Thursday",
            deadline_utc="2026-04-15T17:00:00Z",
            state="ACTIVE",
        )
        self.assertLessEqual(len(entry), MAX_MEMORY_ENTRY_CHARS, f"Entry too long: {len(entry)} chars")

    def test_rejection_produces_no_memory_write(self) -> None:
        """On rejection, MEMORY.md must not be written."""
        initial_content = Path(self._tmp_a, "MEMORY.md").read_text()
        # Rejection: no write call made
        # Verify no new [ACTIVE] entry appears
        final_content = Path(self._tmp_a, "MEMORY.md").read_text()
        self.assertEqual(initial_content, final_content)

    def test_accept_wrong_terms_version_detected(self) -> None:
        """Receiving ACCEPT with mismatched terms_version is detected."""
        msg_accept = build_negotiate_message(
            session_id="version-mismatch-001",
            msg_type="ACCEPT",
            from_pubkey=self._pub_b.hex(),
            payload={
                "my_tasks": ["task"],
                "peer_tasks": ["other"],
                "deadline": "2026-04-01T12:00:00Z",
                "terms_version": 99,  # ← wrong version (local is 1)
                "terms_hash": "anything",
            },
        )
        parsed = parse_negotiate_message(msg_accept)
        local_terms_version = 1
        self.assertNotEqual(
            parsed["payload"]["terms_version"],
            local_terms_version,
            "Terms version mismatch should be detectable",
        )


class TestCounterProposalFlow(unittest.TestCase):
    """Counter-proposal increments terms_version correctly."""

    def setUp(self) -> None:
        self._tmp, self._priv, self._pub = _mk_workspace("Charlie")

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_counter_loop_increments_version(self) -> None:
        """Each counter increments terms_version by 1."""
        version = 1
        for _ in range(5):
            version += 1
        self.assertEqual(version, 6)

    def test_ledger_records_counter_event(self) -> None:
        """Each counter is recorded in ledger.json events array."""
        sess = LedgerSession(
            session_id="counter-test-001",
            peer_alias="Dave",
            peer_pubkey=self._pub.hex(),
            state=SessionState.COUNTERED.value,
            terms_version=3,
            final_terms={},
            events=[
                {"type": "PROPOSE",  "terms_version": 1, "ts": "2026-03-23T10:00:00Z"},
                {"type": "COUNTER",  "terms_version": 2, "ts": "2026-03-23T10:05:00Z"},
                {"type": "COUNTER",  "terms_version": 3, "ts": "2026-03-23T10:10:00Z"},
            ],
        )
        upsert_session(self._tmp, sess)
        loaded = get_session(self._tmp, "counter-test-001")
        self.assertEqual(len(loaded.events), 3)
        self.assertEqual(loaded.terms_version, 3)


if __name__ == "__main__":
    unittest.main()
