"""RAM-only handling of the router password.

The value lives in a bytearray that is overwritten with zeros after use. It cannot be
printed, logged, pickled or serialised by accident. Limitation (documented): CPython
creates short-lived immutable copies while the HTTP request body is parsed; the request
handler drops those references immediately, but cannot zero them.
"""
from __future__ import annotations

import hashlib
from typing import Optional, Union


class Secret:
    __slots__ = ("_buf",)

    def __init__(self, value: Optional[Union[str, bytes, bytearray]] = None) -> None:
        if value is None:
            self._buf = bytearray()
        elif isinstance(value, str):
            self._buf = bytearray(value.encode("utf-8"))
        else:
            self._buf = bytearray(value)

    def __bool__(self) -> bool:
        return len(self._buf) > 0

    def __len__(self) -> int:
        return len(self._buf)

    def feed(self, h: "hashlib._Hash") -> None:
        """Hash the secret without creating an immutable copy."""
        h.update(self._buf)

    def wipe(self) -> None:
        for i in range(len(self._buf)):
            self._buf[i] = 0
        self._buf = bytearray()

    @property
    def wiped(self) -> bool:
        return not self._buf

    def __repr__(self) -> str:
        return "Secret(***)" if self._buf else "Secret(<empty>)"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return repr(self)

    def __reduce__(self):  # no pickling / deep copies to disk
        raise TypeError("Secret cannot be serialised")

    def __getstate__(self):
        raise TypeError("Secret cannot be serialised")

    def __eq__(self, other: object) -> bool:  # avoid accidental comparisons that leak timing
        return NotImplemented

    __hash__ = None  # type: ignore[assignment]
