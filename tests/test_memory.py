"""
tests/test_memory.py

Tests for MEMORY.md atomic writes, entry formatting, 20-entry limit,
in-place status update, and archive behavior.
Covers SKILL_SPEC.md §14 bullet group "Memory writes".
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from negotiate import (
    append_commitment_to_memory,
    update_memory_entry_status,
    MAX_ACTIVE_COMMITMENTS,
    MAX_MEMORY_ENTRY_CHARS,
)

_MEMORY_HEADER = "# Memory\n\n## Diplomat Commitments\n"

def _mk_workspace() -> str:
    """Create a temp workspace with a valid MEMORY.md."""
    tmp = tempfile.mkdtemp()
    (Path(tmp) / "skills" / "claw-diplomat").mkdir(parents=True)
    Path(tmp, "MEMORY.md").write_text(_MEMORY_HEADER)
    return tmp


class TestAtomicMemoryWrite(unittest.TestCase):
    """MEMORY.md writes must be atomic and non-corrupting."""

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def setUp(self) -> None:
        self._tmp = _mk_workspace()

    def test_append_writes_entry(self) -> None:
        """append_commitment_to_memory adds a line to ## Diplomat Commitments."""
        entry = "- **[ACTIVE]** Peer: Alice | My: finish spec | Their: review PR | Due: 2026-03-30 17:00 UTC | ID: `a1b2`"
        append_commitment_to_memory(self._tmp, entry)
        content = Path(self._tmp, "MEMORY.md").read_text()
        self.assertIn(entry, content)

    def test_append_returns_sha256(self) -> None:
        """append_commitment_to_memory returns the sha256 of the entry written."""
        entry = "- **[ACTIVE]** Peer: Bob | My: write tests | Their: review tests | Due: 2026-04-01 12:00 UTC | ID: `c3d4`"
        returned_hash = append_commitment_to_memory(self._tmp, entry)
        expected_hash = hashlib.sha256(entry.encode()).hexdigest()
        self.assertEqual(returned_hash, expected_hash)

    def test_entry_max_500_chars(self) -> None:
        """append_commitment_to_memory raises ValueError if entry > MAX_MEMORY_ENTRY_CHARS."""
        long_entry = "- **[ACTIVE]** Peer: Alice | My: " + "x" * 600
        with self.assertRaises(ValueError):
            append_commitment_to_memory(self._tmp, long_entry)

    def test_atomic_write_no_corruption_on_concurrent(self) -> None:
        """Concurrent writes must not corrupt MEMORY.md (test with threading)."""
        errors: list[Exception] = []

        def write_entry(i: int) -> None:
            try:
                entry = f"- **[ACTIVE]** Peer: Peer{i} | My: task{i} | Their: task{i} | Due: 2026-04-0{i % 9 + 1} 12:00 UTC | ID: `id{i:02d}`"
                append_commitment_to_memory(self._tmp, entry)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=write_entry, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"Errors during concurrent writes: {errors}")
        content = Path(self._tmp, "MEMORY.md").read_text()
        # File must still be valid text and contain the header
        self.assertIn("## Diplomat Commitments", content)

    def test_memory_md_created_if_missing(self) -> None:
        """append_commitment_to_memory creates MEMORY.md if it doesn't exist."""
        tmp = tempfile.mkdtemp()
        (Path(tmp) / "skills" / "claw-diplomat").mkdir(parents=True)
        # No MEMORY.md — file does not exist
        entry = "- **[ACTIVE]** Peer: Carol | My: design | Their: review | Due: 2026-04-05 10:00 UTC | ID: `e5f6`"
        append_commitment_to_memory(tmp, entry)
        self.assertTrue(Path(tmp, "MEMORY.md").exists())
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


class TestMaxCommitmentsLimit(unittest.TestCase):
    """20-entry limit enforcement."""

    def setUp(self) -> None:
        self._tmp = _mk_workspace()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _fill_to_limit(self) -> None:
        for i in range(MAX_ACTIVE_COMMITMENTS):
            entry = f"- **[ACTIVE]** Peer: P{i} | My: task{i} | Their: task{i} | Due: 2026-04-{i % 28 + 1:02d} 12:00 UTC | ID: `{i:04x}`"
            append_commitment_to_memory(self._tmp, entry)

    def test_21st_commitment_raises(self) -> None:
        """21st ACTIVE commitment must raise RuntimeError, not write."""
        self._fill_to_limit()
        extra = "- **[ACTIVE]** Peer: Extra | My: overflow | Their: task | Due: 2026-05-01 12:00 UTC | ID: `ffff`"
        with self.assertRaises(RuntimeError, msg="21st commitment should raise RuntimeError"):
            append_commitment_to_memory(self._tmp, extra)

    def test_20_entries_accepted(self) -> None:
        """Exactly 20 ACTIVE entries must succeed."""
        # Should not raise
        self._fill_to_limit()
        content = Path(self._tmp, "MEMORY.md").read_text()
        count = content.count("[ACTIVE]")
        self.assertEqual(count, MAX_ACTIVE_COMMITMENTS)

    def test_done_entry_does_not_count_toward_limit(self) -> None:
        """[DONE] entries do not count toward the 20-entry active limit."""
        # Fill 19 ACTIVE
        for i in range(MAX_ACTIVE_COMMITMENTS - 1):
            entry = f"- **[ACTIVE]** Peer: P{i} | My: task{i} | Their: t{i} | Due: 2026-04-{i % 28 + 1:02d} 12:00 UTC | ID: `{i:04x}`"
            append_commitment_to_memory(self._tmp, entry)
        # Add 1 DONE
        done_entry = "- **[DONE]** Peer: Finished | My: done task | Their: done | Due: 2026-04-01 10:00 UTC | ID: `dddd`"
        append_commitment_to_memory(self._tmp, done_entry)
        # 20th ACTIVE should succeed
        final_entry = "- **[ACTIVE]** Peer: Last | My: last task | Their: last | Due: 2026-04-30 12:00 UTC | ID: `eeee`"
        append_commitment_to_memory(self._tmp, final_entry)  # Must not raise
        content = Path(self._tmp, "MEMORY.md").read_text()
        self.assertIn("`eeee`", content)


class TestInPlaceStatusUpdate(unittest.TestCase):
    """In-place ACTIVE → DONE/OVERDUE/PARTIAL status replacement."""

    def setUp(self) -> None:
        self._tmp = _mk_workspace()
        self._entry_id = "a1b2"
        entry = f"- **[ACTIVE]** Peer: Alice | My: spec | Their: review | Due: 2026-03-28 17:00 UTC | ID: `{self._entry_id}`"
        append_commitment_to_memory(self._tmp, entry)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_update_to_done(self) -> None:
        """update_memory_entry_status replaces [ACTIVE] with [DONE]."""
        update_memory_entry_status(self._tmp, self._entry_id, "DONE")
        content = Path(self._tmp, "MEMORY.md").read_text()
        self.assertIn("[DONE]", content)
        self.assertNotIn("[ACTIVE]", content)

    def test_update_to_overdue(self) -> None:
        """update_memory_entry_status replaces [ACTIVE] with [OVERDUE]."""
        update_memory_entry_status(self._tmp, self._entry_id, "OVERDUE")
        content = Path(self._tmp, "MEMORY.md").read_text()
        self.assertIn("[OVERDUE]", content)

    def test_update_to_partial(self) -> None:
        """update_memory_entry_status replaces [ACTIVE] with [PARTIAL]."""
        update_memory_entry_status(self._tmp, self._entry_id, "PARTIAL")
        content = Path(self._tmp, "MEMORY.md").read_text()
        self.assertIn("[PARTIAL]", content)

    def test_update_preserves_other_fields(self) -> None:
        """Status update does not modify Peer, task, Due, or ID fields."""
        update_memory_entry_status(self._tmp, self._entry_id, "DONE")
        content = Path(self._tmp, "MEMORY.md").read_text()
        self.assertIn("Peer: Alice", content)
        self.assertIn("My: spec", content)
        self.assertIn("Due: 2026-03-28", content)
        self.assertIn(f"ID: `{self._entry_id}`", content)

    def test_update_nonexistent_id_raises(self) -> None:
        """update_memory_entry_status raises ValueError for unknown session_id."""
        with self.assertRaises(ValueError):
            update_memory_entry_status(self._tmp, "zzzz", "DONE")

    def test_update_is_atomic(self) -> None:
        """Status update uses atomic write (file exists and is valid after update)."""
        update_memory_entry_status(self._tmp, self._entry_id, "DONE")
        content = Path(self._tmp, "MEMORY.md").read_text()
        # Must still have the Diplomat Commitments header
        self.assertIn("## Diplomat Commitments", content)


if __name__ == "__main__":
    unittest.main()
