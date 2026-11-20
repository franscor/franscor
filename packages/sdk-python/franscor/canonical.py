"""Canonical JSON: one object, one byte sequence, in every language.

Derived from `intermesh.canonical` (sorted keys, fixed separators, UTF-8
unescaped). One extension: non-integer numbers are allowed and serialized
like ECMAScript's `Number.prototype.toString` (the RFC 8785 rule), so a
Python float and a JavaScript number produce identical bytes. Integral
values beyond 2^53-1 (whether int or float), NaN and infinities are
rejected because the two languages would not agree on them.

Records without floats (all evidence records) produce exactly the same
bytes as `intermesh.canonical`, so InterMesh verifiers keep working.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
from json.encoder import encode_basestring as _quote  # same escaping as dumps(ensure_ascii=False)
from typing import Any

MAX_SAFE_INT = 2**53 - 1


class CanonicalError(ValueError):
    """The value cannot be serialized reproducibly across languages."""


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64(raw: str) -> bytes:
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def _number(x: float) -> str:
    if math.isnan(x) or math.isinf(x):
        raise CanonicalError(f"{x!r} has no JSON representation")
    if x == 0:
        return "0"
    if x.is_integer():
        if abs(x) > MAX_SAFE_INT:
            raise CanonicalError(f"integral number {x!r} exceeds 2^53-1; use a string")
        return str(int(x))
    text = repr(x)
    sign = ""
    if text.startswith("-"):
        sign, text = "-", text[1:]
    mantissa, _, exp_text = text.partition("e")
    exp = int(exp_text) if exp_text else 0
    int_part, _, frac_part = mantissa.partition(".")
    raw = (int_part + frac_part).lstrip("0")
    stripped = raw.rstrip("0")
    e = exp - len(frac_part) + (len(raw) - len(stripped))
    digits, k = stripped, len(stripped)
    n = e + k
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        exponent = n - 1
        sign_e = "+" if exponent >= 0 else "-"
        head = digits[0] + ("." + digits[1:] if k > 1 else "")
        out = f"{head}e{sign_e}{abs(exponent)}"
    return sign + out


def _encode(value: Any, path: str, out: list) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise CanonicalError(f"{path}: integer {value} exceeds 2^53-1; use a string")
        out.append(str(value))
    elif isinstance(value, float):
        out.append(_number(value))
    elif isinstance(value, str):
        out.append(_quote(value))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _encode(item, f"{path}[{i}]", out)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        first = True
        for key in sorted(value):
            if not isinstance(key, str):
                raise CanonicalError(f"{path}: object keys must be strings")
            if not first:
                out.append(",")
            first = False
            out.append(_quote(key))
            out.append(":")
            _encode(value[key], f"{path}.{key}", out)
        out.append("}")
    else:
        raise CanonicalError(f"{path}: {type(value).__name__} is not JSON")


def canonical_json(value: Any) -> str:
    out: list = []
    _encode(value, "$", out)
    return "".join(out)


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()
