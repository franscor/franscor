"""Merkle tree of RFC 6962 / RFC 9162 §2.1: tree hash, inclusion and consistency proofs.

    leaf hash  = SHA-256(0x00 || leaf bytes)
    node hash  = SHA-256(0x01 || left || right)
    empty tree = SHA-256("")

A log that only appends can prove, for two sizes m < n, that the first m
entries of the larger tree are exactly the smaller tree (consistency), and
that an entry is in a tree of a given root (inclusion). Hashes are bytes
here; documents carry them as lowercase hex.
"""

from __future__ import annotations

import hashlib
from typing import Dict, List, Sequence, Tuple

EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


class MerkleTree:
    """Append-only list of leaf hashes with cached complete subtrees."""

    def __init__(self, leaves: Sequence[bytes] = ()):
        self.leaves: List[bytes] = list(leaves)
        self._memo: Dict[Tuple[int, int], bytes] = {}

    def __len__(self) -> int:
        return len(self.leaves)

    def append(self, data: bytes) -> int:
        self.leaves.append(leaf_hash(data))
        return len(self.leaves) - 1

    def _mth(self, start: int, size: int) -> bytes:
        if size == 0:
            return EMPTY_ROOT
        if size == 1:
            return self.leaves[start]
        full = size & (size - 1) == 0   # a complete subtree never changes once written
        if full and (start, size) in self._memo:
            return self._memo[(start, size)]
        k = _split(size)
        h = node_hash(self._mth(start, k), self._mth(start + k, size - k))
        if full:
            self._memo[(start, size)] = h
        return h

    def root(self, size: int = -1) -> bytes:
        size = len(self.leaves) if size < 0 else size
        if not 0 <= size <= len(self.leaves):
            raise ValueError("size out of range")
        return self._mth(0, size)

    def inclusion_proof(self, index: int, size: int = -1) -> List[bytes]:
        size = len(self.leaves) if size < 0 else size
        if not 0 <= index < size <= len(self.leaves):
            raise ValueError("index out of range")

        def path(m: int, start: int, n: int) -> List[bytes]:
            if n == 1:
                return []
            k = _split(n)
            if m < k:
                return path(m, start, k) + [self._mth(start + k, n - k)]
            return path(m - k, start + k, n - k) + [self._mth(start, k)]

        return path(index, 0, size)

    def consistency_proof(self, first: int, second: int = -1) -> List[bytes]:
        second = len(self.leaves) if second < 0 else second
        if not 0 <= first <= second <= len(self.leaves):
            raise ValueError("sizes out of range")
        if first == 0 or first == second:
            return []

        def sub(m: int, start: int, n: int, complete: bool) -> List[bytes]:
            if m == n:
                return [] if complete else [self._mth(start, n)]
            k = _split(n)
            if m <= k:
                return sub(m, start, k, complete) + [self._mth(start + k, n - k)]
            return sub(m - k, start + k, n - k, False) + [self._mth(start, k)]

        return sub(first, 0, second, True)


def verify_inclusion(leaf: bytes, index: int, size: int, proof: Sequence[bytes], root: bytes) -> bool:
    """RFC 9162 §2.1.3.2. `leaf` is the leaf hash."""
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes,
                       proof: Sequence[bytes]) -> bool:
    """RFC 9162 §2.1.4.2, plus the trivial cases (first = 0, first = second)."""
    if not 0 <= first <= second:
        return False
    if first == second:
        return not proof and first_root == second_root
    if first == 0:
        return not proof and first_root == EMPTY_ROOT
    if not proof:
        return False
    path = list(proof)
    if first & (first - 1) == 0:
        path = [first_root] + path
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0
