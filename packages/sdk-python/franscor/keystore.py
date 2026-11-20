"""Where private keys live.

* ``file`` (default): ``$FRANSCOR_HOME/identities/<name>.key``, mode 0600,
  optionally encrypted with ``FRANSCOR_KEY_PASSPHRASE``. Readable by both SDKs.
* ``keyring``: the OS credential store (macOS Keychain, Windows Credential
  Manager, Secret Service on Linux) through the ``keyring`` package
  (``pip install franscor[keyring]``). Python only for now.

Select with ``FRANSCOR_KEY_STORE=keyring`` or ``connect(key_store=...)``.
Replaced keys are never silently destroyed: the file store keeps them as
``<name>.key.rotated-<ms>`` so evidence they signed stays attributable.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional, Protocol

SERVICE = "franscor"


class KeyStore(Protocol):
    name: str

    def load(self, ident: str) -> Optional[bytes]: ...

    def save(self, ident: str, pem: bytes, *, replace: bool = False) -> None: ...


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


class FileKeyStore:
    name = "file"

    def __init__(self, home: Path):
        self.home = Path(home)

    def path(self, ident: str) -> Path:
        return self.home / "identities" / f"{ident}.key"

    def load(self, ident: str) -> Optional[bytes]:
        p = self.path(ident)
        return p.read_bytes() if p.exists() else None

    def save(self, ident: str, pem: bytes, *, replace: bool = False) -> None:
        p = self.path(ident)
        if p.exists():
            if not replace:
                raise FileExistsError(p)
            p.rename(p.with_name(f"{p.name}.rotated-{time.time_ns() // 1_000_000}"))
        _write_private(p, pem)


class KeyringKeyStore:
    name = "keyring"

    def __init__(self, service: str = SERVICE, backend=None):
        if backend is None:
            try:
                import keyring as backend  # type: ignore[no-redef]
            except ImportError:
                raise RuntimeError("FRANSCOR_KEY_STORE=keyring needs `pip install franscor[keyring]`") from None
        self._kr = backend
        self.service = service

    def load(self, ident: str) -> Optional[bytes]:
        value = self._kr.get_password(self.service, ident)
        return value.encode("ascii") if value else None

    def save(self, ident: str, pem: bytes, *, replace: bool = False) -> None:
        current = self._kr.get_password(self.service, ident)
        if current and not replace:
            raise FileExistsError(f"{self.service}/{ident}")
        if current:
            self._kr.set_password(self.service, f"{ident}.rotated-{time.time_ns() // 1_000_000}", current)
        self._kr.set_password(self.service, ident, pem.decode("ascii"))


def default_store(home: Path) -> KeyStore:
    kind = os.environ.get("FRANSCOR_KEY_STORE", "file").lower()
    if kind == "keyring":
        return KeyringKeyStore()
    if kind != "file":
        raise ValueError(f"unknown FRANSCOR_KEY_STORE {kind!r} (file | keyring)")
    return FileKeyStore(home)
