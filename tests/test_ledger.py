"""
tests/test_ledger.py

Tests for ledger.json state machine, COMMITTED immutability,
and corruption recovery.
Covers SKILL_SPEC.md §14 bullet group "Negotiation" + security rule T2/T5.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from negotiate import (
    load_ledger,
    save_ledger,
    upsert_session,
    get_session,
    SessionState,
    LedgerSession,
    SecurityError,
)


def _mk_workspace() -> str:
    tmp = tempfile.mkdtemp()
    (Path(tmp) / "skills" / "claw-diplomat").mkdir(parents=True)
    # Initialize empty ledger
    Path(tmp, "skills", "claw-diplomat", "ledger.json").write_text('{"sessions":[]}')
    return tmp


class TestLedgerLoadSave(unittest.TestCase):
    """load_ledger and save_ledger roundtrip."""

    def setUp(self) -> None:
        self._tmp = _mk_workspace()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_load_empty_ledger(self) -> None:
        ledger = load_ledger(self._tmp)
        self.assertEqual(ledger, {"sessions": []})

    def test_save_and_load_roundtrip(self) -> None:
        ledger = {"sessions": [{"session_id": "abc", "state": "PROPOSED"}]}
        save_ledger(self._tmp, ledger)
        loaded = load_ledger(self._tmp)
        self.assertEqual(loaded, ledger)

    def test_corrupted_ledger_recovers(self) -> None:
        """load_ledger returns empty ledger and repairs file if JSON is invalid."""
        ledger_path = Path(self._tmp, "skills", "claw-diplomat", "ledger.json")
        ledger_path.write_text("CORRUPTED{{{")
        # Should not raise — returns safe empty state
        ledger = load_ledger(self._tmp)
        self.assertIn("sessions", ledger)
        self.assertIsInstance(ledger["sessions"], list)

    def test_missing_ledger_initializes(self) -> None:
        """load_ledger creates an empty ledger if file is missing."""
        ledger_path = Path(self._tmp, "skills", "claw-diplomat", "ledger.json")
        ledger_path.unlink()
        ledger = load_ledger(self._tmp)
        self.assertEqual(ledger, {"sessions": []})


class TestStateMachine(unittest.TestCase):
    """Session state transitions follow the defined state machine."""

    def setUp(self) -> None:
        self._tmp = _mk_workspace()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _new_session(self, session_id: str) -> LedgerSession:
        return LedgerSession(
            session_id=session_id,
            peer_alias="Alice",
            peer_pubkey="aa" * 32,
            state=SessionState.PROPOSED.value,
            terms_version=1,
            final_terms={},
            events=[],
        )

    def test_proposed_to_accepted(self) -> None:
        sess = self._new_session("s001")
        sess.state = SessionState.ACCEPTED.value
        upsert_session(self._tmp, sess)
        loaded = get_session(self._tmp, "s001")
        self.assertEqual(loaded.state, SessionState.ACCEPTED.value)

    def test_accepted_to_committed(self) -> None:
        sess = self._new_session("s002")
        sess.state = SessionState.COMMITTED.value
        sess.final_terms = {"my_tasks": ["write spec"], "peer_tasks": ["review"], "deadline": "2026-04-01T12:00:00Z"}
        sess.memory_hash = "abc123"
        upsert_session(self._tmp, sess)
        loaded = get_session(self._tmp, "s002")
        self.assertEqual(loaded.state, SessionState.COMMITTED.value)

    def test_terms_version_increments_on_counter(self) -> None:
        """Each counter round increments terms_version."""
        sess = self._new_session("s003")
        upsert_session(self._tmp, sess)
        # Simulate counter: increment
        sess.terms_version = 2
        sess.state = SessionState.COUNTERED.value
        upsert_session(self._tmp, sess)
        loaded = get_session(self._tmp, "s003")
        self.assertEqual(loaded.terms_version, 2)

    def test_get_nonexistent_session_returns_none(self) -> None:
        result = get_session(self._tmp, "nonexistent")
        self.assertIsNone(result)


class TestCommittedImmutability(unittest.TestCase):
    """COMMITTED sessions must reject final_terms mutations (Security T5)."""

    def setUp(self) -> None:
        self._tmp = _mk_workspace()
        self._committed = LedgerSession(
            session_id="s_committed",
            peer_alias="Alice",
            peer_pubkey="aa" * 32,
            state=SessionState.COMMITTED.value,
            terms_version=3,
            final_terms={
                "my_tasks": ["complete feature"],
                "peer_tasks": ["write tests"],
                "deadline": "2026-04-15T17:00:00Z",
            },
            events=[],
            memory_hash="deadbeef",
        )
        upsert_session(self._tmp, self._committed)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_committed_terms_change_raises_security_error(self) -> None:
        """Attempting to mutate final_terms on a COMMITTED session raises SecurityError."""
        tampered = LedgerSession(
            session_id="s_committed",
            peer_alias="Alice",
            peer_pubkey="aa" * 32,
            state=SessionState.COMMITTED.value,
            terms_version=3,
            final_terms={
                "my_tasks": ["do something else"],  # ← tampered
                "peer_tasks": ["write tests"],
                "deadline": "2026-04-15T17:00:00Z",
            },
            events=[],
            memory_hash="deadbeef",
        )
        with self.assertRaises(SecurityError, msg="Tampering with COMMITTED session should raise SecurityError"):
            upsert_session(self._tmp, tampered)

    def test_committed_memory_hash_change_raises_security_error(self) -> None:
        """Attempting to change memory_hash on a COMMITTED session raises SecurityError."""
        tampered = LedgerSession(
            session_id="s_committed",
            peer_alias="Alice",
            peer_pubkey="aa" * 32,
            state=SessionState.COMMITTED.value,
            terms_version=3,
            final_terms={
                "my_tasks": ["complete feature"],
                "peer_tasks": ["write tests"],
                "deadline": "2026-04-15T17:00:00Z",
            },
            events=[],
            memory_hash="different_hash",  # ← tampered
        )
        with self.assertRaises(SecurityError):
            upsert_session(self._tmp, tampered)

    def test_committed_state_cannot_revert(self) -> None:
        """A COMMITTED session cannot be reverted to PROPOSED."""
        reverted = LedgerSession(
            session_id="s_committed",
            peer_alias="Alice",
            peer_pubkey="aa" * 32,
            state=SessionState.PROPOSED.value,  # ← revert attempt
            terms_version=3,
            final_terms={
                "my_tasks": ["complete feature"],
                "peer_tasks": ["write tests"],
                "deadline": "2026-04-15T17:00:00Z",
            },
            events=[],
            memory_hash="deadbeef",
        )
        with self.assertRaises(SecurityError):
            upsert_session(self._tmp, reverted)

    def test_committed_state_allows_checkin_update(self) -> None:
        """COMMITTED session's check-in status update (state → DONE) is permitted."""
        # DONE is a terminal state after COMMITTED — allowed
        checkin = LedgerSession(
            session_id="s_committed",
            peer_alias="Alice",
            peer_pubkey="aa" * 32,
            state=SessionState.DONE.value,
            terms_version=3,
            final_terms={
                "my_tasks": ["complete feature"],
                "peer_tasks": ["write tests"],
                "deadline": "2026-04-15T17:00:00Z",
            },
            events=[],
            memory_hash="deadbeef",
        )
        # Should not raise
        upsert_session(self._tmp, checkin)
        loaded = get_session(self._tmp, "s_committed")
        self.assertEqual(loaded.state, SessionState.DONE.value)


if __name__ == "__main__":
    unittest.main()
