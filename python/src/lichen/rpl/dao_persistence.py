# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""RPL DAO crash-safe persistence interface.

Per spec section 8.6, DAO state requires crash-safe persistence:

- **TX side**: Before transmitting a new logical DAO, the origin must crash-safely
  commit the greater sequence and complete signed DAO bytes before transmission.
  Missing or corrupt state is a hard failure.

- **RX side**: The receiver must maintain crash-safe persistent state per pinned
  public key containing the accepted high-water sequence and a collision-resistant
  digest of the complete signed DAO bytes. Missing or corrupt state must fail closed.

This module provides the abstract interface and a two-slot implementation that
survives interruption at any point.

The two-slot file backend additionally maintains a checksummed RX floor catalog
(``dao_rx_catalog.bin``) recording, per pinned Announce public key, the
high-water floor committed so far. The catalog is written atomically and
anchored through the external ``StateRevisionAnchor`` so a key that has
initialized floors cannot become "unseen" (treated as a first DAO) merely
because its per-key slot files were deleted or restored to an older pair.

Note: The RX side interface is compatible with the `OriginReplayStore` protocol
defined in `dao_origin.py`.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import os
import stat
import struct
import tempfile
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from lichen.rollback_anchor import (
    AnchoredState,
    StateRevisionAnchor,
    advance_anchor,
    read_anchor,
)

# Slot header: magic (4) + generation (4) + sequence (8) + payload_len (4) + checksum (32)
_SLOT_HEADER_SIZE: Final[int] = 52
_SLOT_MAGIC: Final[bytes] = b"DAO1"
_MAX_PAYLOAD_SIZE: Final[int] = 64 * 1024
_MAX_GENERATION: Final[int] = (1 << 32) - 1
_NOFOLLOW: Final[int] = getattr(os, "O_NOFOLLOW", 0)
_TX_INITIALIZED_MARKER: Final[bytes] = b"LICHEN-DAO-TX-INITIALIZED-v1\n"
_DAO_ANCHOR_DOMAIN: Final[bytes] = b"LICHEN-DAO-STATE-ANCHOR-v1\x00"
_RX_CATALOG_MAGIC: Final[bytes] = b"DAOC"
_RX_CATALOG_ANCHOR_KIND: Final[bytes] = b"rx-catalog"
# Aligned with the pin-table budget (_MAX_TRUST_ENTRIES in key_persistence.py):
# the catalog must never cap out below the number of origins the trust store
# can pin. The encoded-size bound below scales with this constant.
_MAX_RX_CATALOG_ENTRIES: Final[int] = 10000
# magic (4) + revision (8) + entry count (4) + entries + checksum (32)
_RX_CATALOG_MAX_SIZE: Final[int] = 4 + 8 + 4 + 32 + _MAX_RX_CATALOG_ENTRIES * (1 + 32 + 8 + 64)


class DaoPersistenceError(Exception):
    """Raised when persistence state is missing, corrupt, or unavailable."""


@dataclass(frozen=True)
class TxState:
    """Crash-safe TX state: sequence and complete signed DAO bytes."""

    sequence: int
    dao_bytes: bytes


@dataclass(frozen=True)
class RxFloor:
    """Crash-safe RX replay floor: high-water sequence and DAO digest."""

    sequence: int
    digest: bytes


class DaoPersistence(ABC):
    """Abstract interface for crash-safe DAO persistence.

    Implementations must provide atomic commit semantics or use two
    independently validated slots with generation numbers so interruption
    cannot expose a partially written record.
    """

    @property
    @abstractmethod
    def is_crash_safe(self) -> bool:
        """Return True if this backend provides crash-safe persistence.

        Per spec section 8.6, crash-safe persistence requires atomic commit
        semantics or two independently validated slots with generation numbers.
        In-memory backends are NOT crash-safe.
        """

    @property
    @abstractmethod
    def fails_closed(self) -> bool:
        """Return True if this backend fails closed on missing/corrupt state.

        Per spec section 8.6: "Missing, corrupt, or unavailable receive state
        MUST fail closed." A backend that returns None on corrupt state does
        NOT satisfy the fail-closed requirement.

        This is separate from crash-safe persistence: a backend can be
        crash-safe (durable storage) but not fail-closed (returns None on
        error), or fail-closed but not crash-safe (in-memory with exceptions).
        Production deployments require BOTH properties.
        """

    @abstractmethod
    def store_tx_state(self, sequence: int, dao_bytes: bytes) -> None:
        """Commit TX state before transmission.

        Per spec section 8.6, implementations with `is_crash_safe=True` MUST
        provide atomic commit semantics or two independently validated slots
        with generation numbers. Non-crash-safe backends (e.g., MemoryPersistence
        for testing) may use simple in-memory storage.

        Args:
            sequence: The Origin Sequence for this DAO.
            dao_bytes: Complete signed DAO bytes.

        Raises:
            DaoPersistenceError: If the commit fails.
        """

    @abstractmethod
    def load_tx_state(self) -> TxState | None:
        """Load TX state after reboot.

        Returns:
            The stored TX state, or None if no valid state exists.
        """

    @abstractmethod
    def store_rx_floor(self, pubkey: bytes, sequence: int, dao_digest: bytes) -> None:
        """Crash-safely commit RX replay floor before accepting a DAO.

        Args:
            pubkey: The 32-byte public key identifying the origin.
            sequence: The high-water Origin Sequence.
            dao_digest: Collision-resistant digest of complete signed DAO bytes.

        Raises:
            DaoPersistenceError: If the commit fails.
        """

    @abstractmethod
    def load_rx_floor(self, pubkey: bytes) -> RxFloor | None:
        """Load RX replay floor for an origin.

        Args:
            pubkey: The 32-byte public key identifying the origin.

        Returns:
            The stored floor, or None if no valid state exists.
        """

    def store_rx_floors_batch(self, floors: list[tuple[bytes, int, bytes]]) -> None:
        """Atomically commit multiple RX replay floors.

        Per spec section 8.6, partial commits violate atomicity requirements
        for crash-safe semantics. This method commits all floors atomically
        (all succeed or none succeed) to prevent inconsistent state across
        origins when a DAO targets multiple addresses.

        Args:
            floors: List of (pubkey, sequence, dao_digest) tuples.

        Raises:
            DaoPersistenceError: If the commit fails.

        The default rejects multi-floor requests because silently performing
        partial sequential commits would violate this method's contract.
        """
        if len(floors) > 1:
            raise DaoPersistenceError("backend does not support atomic multi-floor commits")
        for pubkey, sequence, dao_digest in floors:
            self.store_rx_floor(pubkey, sequence, dao_digest)


class MemoryPersistence(DaoPersistence):
    """In-memory persistence for testing. NOT crash-safe.

    Also implements the OriginReplayStore protocol for compatibility with
    DaoOriginValidator.
    """

    @property
    def is_crash_safe(self) -> bool:
        """Memory persistence is NOT crash-safe."""
        return False

    @property
    def fails_closed(self) -> bool:
        """Memory persistence does not fail closed (returns None on missing)."""
        return False

    def __init__(self) -> None:
        self._tx_state: TxState | None = None
        self._rx_floors: dict[bytes, RxFloor] = {}

    def store_tx_state(self, sequence: int, dao_bytes: bytes) -> None:
        self._tx_state = TxState(sequence, dao_bytes)

    def load_tx_state(self) -> TxState | None:
        return self._tx_state

    def store_rx_floor(self, pubkey: bytes, sequence: int, dao_digest: bytes) -> None:
        if len(pubkey) not in (16, 32):
            raise ValueError("pubkey must be 16 or 32 bytes")
        if len(dao_digest) != 64:
            raise ValueError("dao_digest must be 64 bytes (SHA-512)")
        self._rx_floors[pubkey] = RxFloor(sequence, dao_digest)

    def store_rx_floors_batch(self, floors: list[tuple[bytes, int, bytes]]) -> None:
        """In-memory batch is effectively atomic (no I/O failure points)."""
        for pubkey, sequence, dao_digest in floors:
            if type(pubkey) is not bytes or len(pubkey) not in (16, 32):
                raise ValueError("pubkey must be 16 or 32 immutable bytes")
            if type(sequence) is not int or not 0 <= sequence <= (1 << 64) - 1:
                raise ValueError("sequence must fit in u64")
            if type(dao_digest) is not bytes or len(dao_digest) != 64:
                raise ValueError("dao_digest must be 64 immutable bytes")
        for pubkey, sequence, dao_digest in floors:
            self.store_rx_floor(pubkey, sequence, dao_digest)

    def load_rx_floor(self, pubkey: bytes) -> RxFloor | None:
        return self._rx_floors.get(pubkey)

    # OriginReplayStore protocol compatibility
    def get_floor(self, pubkey: bytes) -> tuple[int, bytes] | None:
        """Get (sequence, dao_digest) floor for pubkey, or None if no record."""
        floor = self.load_rx_floor(pubkey)
        if floor is None:
            return None
        return (floor.sequence, floor.digest)

    def set_floor(self, pubkey: bytes, sequence: int, dao_digest: bytes) -> None:
        """Durably commit new (sequence, dao_digest) floor for pubkey."""
        self.store_rx_floor(pubkey, sequence, dao_digest)


class TwoSlotFilePersistence(DaoPersistence):
    """Two-slot file-based persistence with generation numbers.

    Uses two alternating slots with generation counters. On write, the older
    slot is overwritten and fsynced. On read, the slot with the higher valid
    generation is used. This survives interruption at any point because at
    least one slot remains valid.

    Slot format:
        - Magic bytes "DAO1" (4 bytes)
        - Generation number (4 bytes, big-endian)
        - Sequence number (8 bytes, big-endian)
        - Payload length (4 bytes, big-endian)
        - SHA-256 checksum of generation + sequence + payload (32 bytes)
        - Payload bytes (variable)

    RX floor catalog:
        A single atomically replaced file ``dao_rx_catalog.bin`` records the
        high-water ``(sequence, digest)`` committed for every pinned key that
        has initialized RX floors. It is keyed by the pinned Announce public
        key (spec section 8.6) and its ``(revision, checksum)`` is anchored in
        the external ``StateRevisionAnchor`` so deletion, corruption, or stale
        restoration of the catalog itself is detected. On load, a catalog
        entry without valid slot files fails closed instead of degrading to a
        first-DAO bootstrap.

    TX initialization marker:
        The first ``store_tx_state`` establishes the durable marker file
        ``.dao_tx_initialized`` before the anchored slot transaction. Once
        the marker exists, missing or invalid TX slot files fail closed
        unconditionally (on load and on store, independent of the legacy
        fail_closed flag and of allow_tx_bootstrap): a deleted slot pair must
        never again look like a first bootstrap or reuse Origin Sequence 1.
        Only wiping the entire store — marker, slots, and anchor record —
        returns the backend to bootstrap-authorized first use.
    """

    @property
    def is_crash_safe(self) -> bool:
        """Two-slot file persistence IS crash-safe.

        Per spec section 8.6: "The storage backend MUST provide atomic commit
        semantics or use two independently validated slots with generation
        numbers so interruption cannot expose a partially written record."

        This implementation uses two independently validated slots with
        generation numbers, satisfying the crash-safety requirement regardless
        of the fail_closed setting.
        """
        return True

    @property
    def fails_closed(self) -> bool:
        """Return True if this backend fails closed on missing/corrupt state.

        Per spec section 8.6: "Missing, corrupt, or unavailable receive state
        MUST fail closed." When fail_closed=True, load operations raise
        DaoPersistenceError on corrupt/missing state. When fail_closed=False,
        they return None (for testing scenarios) — but only for state with no
        durable evidence of prior initialization.

        Deletion/corruption detection is UNCONDITIONAL (independent of
        fail_closed) for state backed by durable evidence: an RX key recorded
        in the anchored floor catalog always raises when its slot files are
        missing or invalid, and a TX store whose initialization marker exists
        always raises when its slot files are missing or invalid. This is
        required by spec section 8.6 and is intentional; fail_closed=False is
        a legacy testing flag and never downgrades catalog- or marker-backed
        detection.

        Production deployments requiring spec compliance MUST use fail_closed=True.
        """
        return self._fail_closed

    def __init__(
        self,
        base_dir: Path,
        *,
        revision_anchor: StateRevisionAnchor,
        anchor_key: bytes,
        allow_tx_bootstrap: bool,
        fail_closed: bool = True,
    ) -> None:
        """Initialize persistence.

        Args:
            base_dir: Directory for persistence files.
            fail_closed: If True, missing/corrupt state raises on load. If
                False (legacy testing flag), loads return None only for state
                with no durable evidence of prior initialization; catalog-
                recorded RX keys and TX-marker-initialized stores still raise
                unconditionally per spec section 8.6.

        Raises:
            DaoPersistenceError: If base_dir exists and is a file (not a directory).
        """
        if type(fail_closed) is not bool or type(allow_tx_bootstrap) is not bool:
            raise ValueError("fail_closed and allow_tx_bootstrap must be exact booleans")
        if type(anchor_key) is not bytes or len(anchor_key) != 32:
            raise ValueError("anchor_key must be exact 32-byte bytes")
        self._base_dir = Path(base_dir)
        self._fail_closed = fail_closed
        self._allow_tx_bootstrap = allow_tx_bootstrap
        self._revision_anchor = revision_anchor
        self._anchor_key = hashlib.sha256(_DAO_ANCHOR_DOMAIN + anchor_key).digest()
        # Check if base_dir is an existing file before mkdir - this would cause
        # mkdir to fail with a confusing FileExistsError or NotADirectoryError
        if self._base_dir.exists() or self._base_dir.is_symlink():
            info = self._base_dir.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                raise DaoPersistenceError(
                    f"base_dir exists but is not an owned directory: {self._base_dir}"
                )
        if self._base_dir.exists() and not self._base_dir.is_dir():
            raise DaoPersistenceError(f"base_dir exists but is not a directory: {self._base_dir}")
        self._base_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(self._base_dir, 0o700)
        self._process_lock_path = self._base_dir / ".dao.lock"
        # Lock to prevent TOCTOU race in _write_to_older_slot: concurrent
        # readers could both determine the same slot is "older" and both
        # write to it with the same generation, losing one write.
        self._write_lock = threading.Lock()

    def _state_anchor_key(self, kind: bytes, identity: bytes = b"") -> bytes:
        return hashlib.sha256(self._anchor_key + kind + identity).digest()

    @staticmethod
    def _slot_anchor(generation: int, sequence: int, payload: bytes) -> AnchoredState:
        digest = hashlib.sha256(struct.pack(">Q", sequence) + payload).digest()
        return AnchoredState(generation, digest)

    def _get_anchored_slot(
        self,
        path0: Path,
        path1: Path,
        anchor_key: bytes,
        *,
        allow_initial: bool,
        missing_message: str,
    ) -> tuple[int, int, int, bytes] | None:
        slot0 = self._read_slot(path0)
        slot1 = self._read_slot(path1)
        if (
            slot0 is not None
            and slot1 is not None
            and slot0[0] == slot1[0]
            and slot0[1:] != slot1[1:]
        ):
            raise DaoPersistenceError("DAO persistence slots have conflicting generations")
        external = read_anchor(self._revision_anchor, anchor_key, DaoPersistenceError)
        if external is not None:
            for index, candidate in enumerate((slot0, slot1)):
                if candidate is not None and self._slot_anchor(*candidate) == external:
                    return (index, *candidate)
            if slot0 is None and slot1 is None:
                raise DaoPersistenceError(missing_message)
            raise DaoPersistenceError("DAO persistence rollback or substitution detected")
        result = self._get_best_slot(path0, path1)
        if result is None:
            if external is not None:
                raise DaoPersistenceError(missing_message)
            return None
        _, generation, sequence, payload = result
        state = self._slot_anchor(generation, sequence, payload)
        if not allow_initial or generation != 1:
            raise DaoPersistenceError("DAO state is missing its rollback anchor")
        advance_anchor(
            self._revision_anchor,
            anchor_key,
            None,
            state,
            DaoPersistenceError,
        )
        return result

    def _tx_slot_path(self, slot: int) -> Path:
        return self._base_dir / f"dao_tx_{slot}.bin"

    def _tx_marker_path(self) -> Path:
        return self._base_dir / ".dao_tx_initialized"

    def _tx_marker_exists(self) -> bool:
        path = self._tx_marker_path()
        try:
            descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise DaoPersistenceError("DAO TX initialization marker is unreadable") from exc
        try:
            info = os.fstat(descriptor)
            marker = os.read(descriptor, len(_TX_INITIALIZED_MARKER) + 1)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or marker != _TX_INITIALIZED_MARKER
            ):
                raise DaoPersistenceError("DAO TX initialization marker is unsafe")
            return True
        finally:
            os.close(descriptor)

    def _ensure_tx_marker(self) -> None:
        if self._tx_marker_exists():
            return
        path = self._tx_marker_path()
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".dao-tx-marker.", suffix=".tmp", dir=self._base_dir
        )
        temporary = Path(temporary_name)
        # Once os.fdopen takes ownership, the with-block exit closes the
        # descriptor; closing it again here could hit a recycled fd number.
        owned_by_stream = False
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                owned_by_stream = True
                stream.write(_TX_INITIALIZED_MARKER)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory = os.open(self._base_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            if not owned_by_stream:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            with contextlib.suppress(OSError):
                temporary.unlink(missing_ok=True)
            raise

    def _rx_slot_path(self, pubkey: bytes, slot: int) -> Path:
        key_hex = pubkey.hex()
        return self._base_dir / f"dao_rx_{key_hex}_{slot}.bin"

    def _rx_catalog_path(self) -> Path:
        return self._base_dir / "dao_rx_catalog.bin"

    def _write_slot(self, path: Path, generation: int, sequence: int, payload: bytes) -> None:
        """Write a slot atomically with checksum validation."""
        if len(payload) > _MAX_PAYLOAD_SIZE:
            raise DaoPersistenceError("DAO persistence payload exceeds size limit")
        content = struct.pack(">IQ", generation, sequence) + payload
        checksum = hashlib.sha256(content).digest()
        slot_data = (
            _SLOT_MAGIC
            + struct.pack(">I", generation)
            + struct.pack(">Q", sequence)
            + struct.pack(">I", len(payload))
            + checksum
            + payload
        )

        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        tmp_path = Path(tmp_name)
        # Once os.fdopen takes ownership, the with-block exit closes the
        # descriptor; closing it again here could hit a recycled fd number.
        owned_by_stream = False
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as file:
                owned_by_stream = True
                file.write(slot_data)
                file.flush()
                os.fsync(file.fileno())
            os.replace(tmp_path, path)
            os.chmod(path, 0o600)
        except BaseException:
            if not owned_by_stream:
                with contextlib.suppress(OSError):
                    os.close(fd)
            with contextlib.suppress(OSError):
                tmp_path.unlink(missing_ok=True)
            raise

        # Sync the directory to ensure rename is durable
        dir_fd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def _read_slot(self, path: Path) -> tuple[int, int, bytes] | None:
        """Read and validate a slot.

        Returns:
            (generation, sequence, payload) or None if invalid/missing.
        """
        try:
            descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError:
            return None
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or info.st_size > _SLOT_HEADER_SIZE + _MAX_PAYLOAD_SIZE
            ):
                return None
            data = os.read(descriptor, _SLOT_HEADER_SIZE + _MAX_PAYLOAD_SIZE + 1)
            if len(data) < _SLOT_HEADER_SIZE:
                return None
            if data[:4] != _SLOT_MAGIC:
                return None

            generation = struct.unpack(">I", data[4:8])[0]
            sequence = struct.unpack(">Q", data[8:16])[0]
            payload_len = struct.unpack(">I", data[16:20])[0]
            stored_checksum = data[20:52]
            payload = data[52:]

            if len(payload) != payload_len:
                return None

            # Verify checksum
            content = struct.pack(">IQ", generation, sequence) + payload
            expected_checksum = hashlib.sha256(content).digest()
            if stored_checksum != expected_checksum:
                return None

            return generation, sequence, payload
        finally:
            os.close(descriptor)

    @contextlib.contextmanager
    def _process_lock(self):  # type: ignore[no-untyped-def]
        try:
            descriptor = os.open(
                self._process_lock_path,
                os.O_RDWR | os.O_CREAT | _NOFOLLOW,
                0o600,
            )
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise DaoPersistenceError("DAO persistence lock is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError as exc:
            if "descriptor" in locals():
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            raise DaoPersistenceError(f"DAO persistence lock failed: {exc}") from exc
        except BaseException:
            if "descriptor" in locals():
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            raise
        try:
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            with contextlib.suppress(OSError):
                os.close(descriptor)

    def _get_best_slot(self, path0: Path, path1: Path) -> tuple[int, int, int, bytes] | None:
        """Get the slot with higher valid generation.

        Returns:
            (slot_index, generation, sequence, payload) or None if both invalid.
        """
        slot0 = self._read_slot(path0)
        slot1 = self._read_slot(path1)

        if slot0 is None and slot1 is None:
            return None
        if slot0 is None:
            assert slot1 is not None
            return (1, slot1[0], slot1[1], slot1[2])
        if slot1 is None:
            return (0, slot0[0], slot0[1], slot0[2])
        if slot0[0] == slot1[0] and slot0[1:] != slot1[1:]:
            raise DaoPersistenceError("DAO persistence slots have conflicting generations")
        # Both valid: use higher generation
        if slot1[0] > slot0[0]:
            return (1, slot1[0], slot1[1], slot1[2])
        return (0, slot0[0], slot0[1], slot0[2])

    def _any_slot_exists(self, path0: Path, path1: Path) -> bool:
        """Check if any slot file exists (for distinguishing missing vs corrupt).

        Per spec section 8.6, missing state (fresh node) is not the same as
        corrupt state. A fresh node that has never transmitted has no "previously
        used" sequence to protect, so it may start with default values.
        Corrupt state (files exist but are invalid) is a hard failure.
        """
        return os.path.lexists(path0) or os.path.lexists(path1)

    # ------------------------------------------------------------------
    # RX floor catalog
    #
    # The catalog records, per pinned Announce public key, the high-water
    # (sequence, digest) floor committed so far. It exists so a key that has
    # initialized floors cannot become "unseen" (a first DAO) merely because
    # its two per-key slot files were deleted or restored to an older pair.
    # Deleting the catalog itself (all state) is outside this threat model,
    # but a deleted or stale catalog is still detected whenever the external
    # revision anchor for the catalog is retained.
    # ------------------------------------------------------------------

    def _encode_rx_catalog(self, revision: int, entries: dict[bytes, tuple[int, bytes]]) -> bytes:
        body = bytearray(struct.pack(">QI", revision, len(entries)))
        for key in sorted(entries, key=lambda item: (len(item), item)):
            sequence, dao_digest = entries[key]
            body += struct.pack(">B", len(key))
            body += key
            body += struct.pack(">Q", sequence)
            body += dao_digest
        body_bytes = bytes(body)
        return _RX_CATALOG_MAGIC + body_bytes + hashlib.sha256(body_bytes).digest()

    def _parse_rx_catalog(self, data: bytes) -> tuple[int, dict[bytes, tuple[int, bytes]], bytes]:
        """Parse and checksum-verify catalog bytes into (revision, entries, checksum)."""
        if (
            len(data) < 4 + 8 + 4 + 32
            or data[:4] != _RX_CATALOG_MAGIC
            or len(data) > _RX_CATALOG_MAX_SIZE
        ):
            raise DaoPersistenceError("DAO RX floor catalog is corrupt")
        body = data[4:-32]
        stored_checksum = data[-32:]
        if hashlib.sha256(body).digest() != stored_checksum:
            raise DaoPersistenceError("DAO RX floor catalog is corrupt")
        revision = struct.unpack(">Q", body[:8])[0]
        count = struct.unpack(">I", body[8:12])[0]
        if not 1 <= revision <= (1 << 64) - 1 or count > _MAX_RX_CATALOG_ENTRIES:
            raise DaoPersistenceError("DAO RX floor catalog is corrupt")
        entries: dict[bytes, tuple[int, bytes]] = {}
        offset = 12
        for _ in range(count):
            if offset + 1 > len(body):
                raise DaoPersistenceError("DAO RX floor catalog is corrupt")
            key_len = body[offset]
            offset += 1
            if key_len not in (16, 32) or offset + key_len + 8 + 64 > len(body):
                raise DaoPersistenceError("DAO RX floor catalog is corrupt")
            key = bytes(body[offset : offset + key_len])
            offset += key_len
            sequence = struct.unpack(">Q", body[offset : offset + 8])[0]
            offset += 8
            dao_digest = bytes(body[offset : offset + 64])
            offset += 64
            if key in entries:
                raise DaoPersistenceError("DAO RX floor catalog is corrupt")
            entries[key] = (sequence, dao_digest)
        if offset != len(body):
            raise DaoPersistenceError("DAO RX floor catalog is corrupt")
        return revision, entries, stored_checksum

    def _write_rx_catalog_file(self, encoded: bytes) -> None:
        """Atomically replace the catalog file (staging + rename + fsync)."""
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".dao-rx-catalog.", suffix=".tmp", dir=self._base_dir
        )
        temporary = Path(temporary_name)
        # Once os.fdopen takes ownership, the with-block exit closes the
        # descriptor; closing it again here could hit a recycled fd number.
        owned_by_stream = False
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                owned_by_stream = True
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self._rx_catalog_path())
        except BaseException:
            if not owned_by_stream:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            with contextlib.suppress(OSError):
                temporary.unlink(missing_ok=True)
            raise

        directory = os.open(self._base_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _read_rx_catalog_locked(
        self,
    ) -> tuple[int, dict[bytes, tuple[int, bytes]], AnchoredState | None]:
        """Read and validate the catalog; returns (revision, entries, file state).

        Caller must hold ``_write_lock`` and the process lock. The catalog's
        own ``(revision, checksum)`` is verified against the external anchor
        so stale restoration is detected when the anchor is retained. A file
        exactly one revision ahead of the anchor is a crash between the
        atomic file replacement and the anchor advance and is adopted (the
        file content is checksum-protected), mirroring the announce journal.
        """
        path = self._rx_catalog_path()
        catalog_key = self._state_anchor_key(_RX_CATALOG_ANCHOR_KIND)
        external = read_anchor(self._revision_anchor, catalog_key, DaoPersistenceError)
        try:
            descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW)
        except FileNotFoundError:
            if external is not None:
                raise DaoPersistenceError("DAO RX floor catalog was deleted") from None
            return 0, {}, None
        except OSError as exc:
            raise DaoPersistenceError("DAO RX floor catalog is unreadable") from exc
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or info.st_size > _RX_CATALOG_MAX_SIZE
            ):
                raise DaoPersistenceError("DAO RX floor catalog is unsafe")
            data = os.read(descriptor, _RX_CATALOG_MAX_SIZE + 1)
        finally:
            os.close(descriptor)
        revision, entries, checksum = self._parse_rx_catalog(data)
        state = AnchoredState(revision, checksum)
        if external is None:
            if revision != 1:
                raise DaoPersistenceError("DAO RX floor catalog is missing its rollback anchor")
            advance_anchor(self._revision_anchor, catalog_key, None, state, DaoPersistenceError)
        elif revision == external.revision:
            if checksum != external.digest:
                raise DaoPersistenceError("DAO RX floor catalog rollback or substitution detected")
        elif revision == external.revision + 1:
            advance_anchor(self._revision_anchor, catalog_key, external, state, DaoPersistenceError)
        else:
            raise DaoPersistenceError("DAO RX floor catalog rollback or substitution detected")
        return revision, entries, state

    def _record_rx_catalog_locked(self, pubkey: bytes, sequence: int, dao_digest: bytes) -> None:
        """Advance the catalog's high-water record for ``pubkey``.

        Caller must hold ``_write_lock`` and the process lock. Floors only
        move forward: an equal sequence must carry the identical digest, and
        a lower sequence than the recorded floor is a rollback.
        """
        revision, entries, expected = self._read_rx_catalog_locked()
        previous = entries.get(pubkey)
        if previous is not None:
            if previous[0] == sequence:
                if previous[1] != dao_digest:
                    raise DaoPersistenceError("DAO persistence sequence collision")
                return
            if previous[0] > sequence:
                raise DaoPersistenceError("DAO persistence sequence rollback")
        elif len(entries) >= _MAX_RX_CATALOG_ENTRIES:
            raise DaoPersistenceError("DAO RX floor catalog capacity exceeded")
        entries[pubkey] = (sequence, dao_digest)
        if revision == (1 << 64) - 1:
            raise DaoPersistenceError("DAO RX floor catalog revision exhausted")
        new_revision = revision + 1
        encoded = self._encode_rx_catalog(new_revision, entries)
        self._write_rx_catalog_file(encoded)
        advance_anchor(
            self._revision_anchor,
            self._state_anchor_key(_RX_CATALOG_ANCHOR_KIND),
            expected,
            AnchoredState(new_revision, encoded[-32:]),
            DaoPersistenceError,
        )

    def _write_to_older_slot(
        self,
        path0: Path,
        path1: Path,
        sequence: int,
        payload: bytes,
        anchor_key: bytes,
        *,
        allow_initial: bool,
        initialized_marker: bool = False,
    ) -> None:
        """Write to the older slot with incremented generation.

        Thread-safe: uses a lock to prevent TOCTOU race where concurrent
        callers could read the same slot state, both compute the same
        "older" slot and generation, and one write would be lost.

        ``initialized_marker`` records that a durable TX-initialization
        marker pre-existed this store; combined with no recoverable anchored
        state it proves the slot files were deleted (spec section 8.6).
        """
        with self._write_lock, self._process_lock():
            self._write_to_older_slot_locked(
                path0,
                path1,
                sequence,
                payload,
                anchor_key,
                allow_initial=allow_initial,
                initialized_marker=initialized_marker,
            )

    def _write_to_older_slot_locked(
        self,
        path0: Path,
        path1: Path,
        sequence: int,
        payload: bytes,
        anchor_key: bytes,
        *,
        allow_initial: bool,
        initialized_marker: bool = False,
    ) -> None:
        """Write to the older slot with incremented generation.

        Caller must hold ``_write_lock`` and the process lock.
        """
        current_result = self._get_anchored_slot(
            path0,
            path1,
            anchor_key,
            allow_initial=allow_initial,
            missing_message="initialized DAO state was deleted",
        )
        slot0 = self._read_slot(path0)
        slot1 = self._read_slot(path1)
        # Wholly invalid slot files that exist on disk are corrupt durable
        # state, not a fresh store. A write here would silently reset the
        # acknowledged generation, so this fails closed unconditionally per
        # spec section 8.6 — the legacy fail_closed flag only governs loads
        # of state with no durable evidence of prior initialization. The
        # corrupt artifacts are preserved for forensics.
        if slot0 is None and slot1 is None and self._any_slot_exists(path0, path1):
            raise DaoPersistenceError("refusing to overwrite corrupt DAO persistence state")

        # A pre-existing TX-initialization marker proves a store was
        # attempted before. With no recoverable anchored slot state and no
        # external anchor record, the only explanation is slot deletion:
        # reusing Origin Sequence 1 here would replay an acknowledged
        # sequence (spec section 8.6). Bootstrap authorization does not
        # override durable evidence of prior initialization.
        if initialized_marker and current_result is None:
            raise DaoPersistenceError("initialized TX state was deleted")

        if current_result is not None:
            if sequence < current_result[2]:
                raise DaoPersistenceError("DAO persistence sequence rollback")
            if sequence == current_result[2]:
                if payload != current_result[3]:
                    raise DaoPersistenceError("DAO persistence sequence collision")
                return

        # Write to older slot with generation = max + 1
        current_generation = 0 if current_result is None else current_result[1]
        if current_generation == _MAX_GENERATION:
            raise DaoPersistenceError("DAO persistence generation exhausted")
        new_gen = current_generation + 1
        if current_result is None or current_result[0] == 1:
            self._write_slot(path0, new_gen, sequence, payload)
        else:
            self._write_slot(path1, new_gen, sequence, payload)
        previous = read_anchor(self._revision_anchor, anchor_key, DaoPersistenceError)
        advance_anchor(
            self._revision_anchor,
            anchor_key,
            previous,
            self._slot_anchor(new_gen, sequence, payload),
            DaoPersistenceError,
        )

    def store_tx_state(self, sequence: int, dao_bytes: bytes) -> None:
        if type(sequence) is not int or not 0 <= sequence <= (1 << 64) - 1:
            raise ValueError("sequence must fit in u64")
        if type(dao_bytes) is not bytes:
            raise TypeError("dao_bytes must be immutable bytes")
        path0 = self._tx_slot_path(0)
        path1 = self._tx_slot_path(1)
        # Capture whether the durable initialization marker pre-existed this
        # store: if it did and no anchored slot state survives, the TX slots
        # were deleted and the store must fail closed (spec section 8.6).
        marker_existed = self._tx_marker_exists()
        # Establish the legacy initialization sentinel before the anchored
        # state transaction.  A marker failure therefore cannot report a
        # failed store after the slot and external rollback anchor committed.
        self._ensure_tx_marker()
        self._write_to_older_slot(
            path0,
            path1,
            sequence,
            dao_bytes,
            self._state_anchor_key(b"tx"),
            allow_initial=self._allow_tx_bootstrap,
            initialized_marker=marker_existed,
        )

    def load_tx_state(self) -> TxState | None:
        path0 = self._tx_slot_path(0)
        path1 = self._tx_slot_path(1)
        marker_exists = self._tx_marker_exists()
        with self._write_lock, self._process_lock():
            result = self._get_anchored_slot(
                path0,
                path1,
                self._state_anchor_key(b"tx"),
                allow_initial=self._allow_tx_bootstrap,
                missing_message="initialized TX state was deleted",
            )
        if result is None:
            # The durable TX-initialization marker proves a store was
            # attempted before, so missing or invalid slot files are
            # deletion or corruption — never a fresh node. This fails closed
            # unconditionally per spec 8.6, independent of the legacy
            # fail_closed flag and of allow_tx_bootstrap.
            if marker_exists:
                if self._any_slot_exists(path0, path1):
                    raise DaoPersistenceError("TX state corrupt")
                raise DaoPersistenceError("initialized TX state was deleted")
            # Per spec 8.6, distinguish missing (fresh node) from corrupt:
            # - No slots exist: fresh node, return None (allowed to start fresh)
            # - Slots exist but invalid: corrupt state, fail closed if configured
            if self._fail_closed and self._any_slot_exists(path0, path1):
                raise DaoPersistenceError("TX state corrupt")
            return None
        _, _, sequence, payload = result
        return TxState(sequence, payload)

    def store_rx_floor(self, pubkey: bytes, sequence: int, dao_digest: bytes) -> None:
        """Crash-safely commit one RX replay floor (spec section 8.6).

        Commit order: the per-key slot pair and its external rollback anchor
        first, then the catalog record, so the catalog's high-water never
        leads the committed slots.

        Failure modes:
        - Capacity and catalog/anchor liveness are pre-checked BEFORE the
          slot commit: those failures are deterministic and leave persistent
          state untouched (a new origin at catalog capacity, or a catalog
          whose anchored revision cannot be validated, never writes slots).
        - A failure during the catalog record (e.g. ENOSPC on the catalog
          write, or an external anchor compare-and-advance conflict) occurs
          AFTER the slot floor is durably committed. The commit is therefore
          INDETERMINATE at the time of the error: the raised
          DaoPersistenceError does not imply the floor was rejected. The
          committed slot floor remains effective and authoritative; loads
          heal the catalog from it when the catalog can be written and fail
          closed (preserving the committed floor) while it cannot. Recovery
          never re-opens a replay window but may require freeing storage.

        Raises:
            DaoPersistenceError: If the pre-checks fail or the commit fails.
            ValueError: If pubkey/sequence/dao_digest are malformed.
        """
        if type(pubkey) is not bytes:
            raise TypeError("pubkey must be immutable bytes")
        if len(pubkey) not in (16, 32):
            raise ValueError("pubkey must be 16 or 32 bytes")
        if type(sequence) is not int or not 0 <= sequence <= (1 << 64) - 1:
            raise ValueError("sequence must fit in u64")
        if type(dao_digest) is not bytes:
            raise TypeError("dao_digest must be immutable bytes")
        if len(dao_digest) != 64:
            raise ValueError("dao_digest must be 64 bytes (SHA-512)")
        path0 = self._rx_slot_path(pubkey, 0)
        path1 = self._rx_slot_path(pubkey, 1)
        with self._write_lock, self._process_lock():
            # Pre-check catalog capacity and anchor liveness BEFORE the slot
            # commit so a doomed store fails deterministically instead of
            # leaving an indeterminate post-commit state.
            _revision, entries, _expected = self._read_rx_catalog_locked()
            if pubkey not in entries and len(entries) >= _MAX_RX_CATALOG_ENTRIES:
                raise DaoPersistenceError("DAO RX floor catalog capacity exceeded")
            self._write_to_older_slot_locked(
                path0,
                path1,
                sequence,
                dao_digest,
                self._state_anchor_key(b"rx", pubkey),
                allow_initial=True,
            )
            # Record the committed floor in the anchored catalog AFTER the
            # slot commit so the catalog's high-water never leads the slots.
            self._record_rx_catalog_locked(pubkey, sequence, dao_digest)

    def store_rx_floors_batch(self, floors: list[tuple[bytes, int, bytes]]) -> None:
        """Atomically commit multiple RX replay floors.

        This backend deliberately rejects more than one floor because separate
        per-key slot files cannot provide an all-or-nothing multi-key commit.
        """
        if not floors:
            return
        if len(floors) > 1:
            raise DaoPersistenceError("two-slot backend rejects non-atomic multi-floor commit")
        # Validate all inputs before writing any
        for pubkey, _sequence, dao_digest in floors:
            if len(pubkey) not in (16, 32):
                raise ValueError("pubkey must be 16 or 32 bytes")
            if len(dao_digest) != 64:
                raise ValueError("dao_digest must be 64 bytes (SHA-512)")
        pubkey, sequence, dao_digest = floors[0]
        self.store_rx_floor(pubkey, sequence, dao_digest)

    def load_rx_floor(self, pubkey: bytes) -> RxFloor | None:
        if len(pubkey) not in (16, 32):
            raise ValueError("pubkey must be 16 or 32 bytes")
        path0 = self._rx_slot_path(pubkey, 0)
        path1 = self._rx_slot_path(pubkey, 1)
        with self._write_lock, self._process_lock():
            result = self._get_anchored_slot(
                path0,
                path1,
                self._state_anchor_key(b"rx", pubkey),
                allow_initial=True,
                missing_message=f"initialized RX floor was deleted for pubkey {pubkey.hex()}",
            )
            catalog_entry = self._read_rx_catalog_locked()[1].get(pubkey)
            if result is not None:
                _, _, sequence, digest = result
                if catalog_entry is not None:
                    entry_sequence, entry_digest = catalog_entry
                    # Restored or substituted slot files must never lower the
                    # recorded high-water floor or diverge from it at the same
                    # sequence.
                    if sequence < entry_sequence or (
                        sequence == entry_sequence and digest != entry_digest
                    ):
                        raise DaoPersistenceError(
                            f"DAO RX floor rollback or substitution detected"
                            f" for pubkey {pubkey.hex()}"
                        )
                # Heal the catalog forward to the verified floor. This closes
                # the crash window between a slot commit and its catalog
                # record and converges pre-catalog slot state. It is a no-op
                # when the entry already matches and never rewrites the floor
                # slots, so byte-identical retransmissions do not rewrite the
                # replay floor (spec 8.6).
                self._record_rx_catalog_locked(pubkey, sequence, digest)
        if result is None:
            if catalog_entry is not None:
                # The anchored catalog records that this pinned key committed
                # a floor, so missing or invalid slot files are deletion or
                # corruption, not a first DAO. Fail closed per spec 8.6
                # ("Missing, corrupt, or unavailable receive state MUST fail
                # closed") regardless of the legacy fail_closed setting, and
                # name the actual condition: slot files present but invalid
                # are corruption, absent slot files are deletion.
                if self._any_slot_exists(path0, path1):
                    raise DaoPersistenceError(f"RX floor corrupt for pubkey {pubkey.hex()}")
                raise DaoPersistenceError(
                    f"initialized RX floor was deleted for pubkey {pubkey.hex()}"
                )
            # Per spec 8.6, distinguish missing (no prior DAO from this origin)
            # from corrupt. Missing RX floor for an origin is normal (first DAO).
            # Corrupt floor files are a hard failure when fail_closed.
            if self._fail_closed and self._any_slot_exists(path0, path1):
                raise DaoPersistenceError(f"RX floor corrupt for pubkey {pubkey.hex()}")
            return None
        _, _, sequence, digest = result
        return RxFloor(sequence, digest)

    # OriginReplayStore protocol compatibility
    def get_floor(self, pubkey: bytes) -> tuple[int, bytes] | None:
        """Get (sequence, dao_digest) floor for pubkey, or None if no record.

        Note: When fail_closed=True and state is corrupt, this raises
        DaoPersistenceError per spec 8.6: "Missing, corrupt, or unavailable
        receive state MUST fail closed."
        """
        floor = self.load_rx_floor(pubkey)
        if floor is None:
            return None
        return (floor.sequence, floor.digest)

    def set_floor(self, pubkey: bytes, sequence: int, dao_digest: bytes) -> None:
        """Durably commit new (sequence, dao_digest) floor for pubkey."""
        self.store_rx_floor(pubkey, sequence, dao_digest)


def compute_dao_digest(dao_bytes: bytes) -> bytes:
    """Compute collision-resistant digest of complete signed DAO bytes.

    This is the digest stored in the RX floor for idempotent retransmission
    detection per spec section 8.6.

    Uses SHA-512 for consistency with dao_origin.py.
    """
    return hashlib.sha512(dao_bytes).digest()
