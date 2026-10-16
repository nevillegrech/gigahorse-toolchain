"""The exact executed-code input, independent of ABI and signature hints."""

from __future__ import annotations

import hashlib
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .model import Program


def normalize_bytecode(text: str) -> str:
    text = "".join(text.split())
    if text.startswith(("0x", "0X")):
        text = text[2:]
    if not text or len(text) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", text):
        raise ValueError("Expected nonempty runtime bytecode as even-length hexadecimal text")
    return text.lower()


def executed_code(program: Program) -> bytes | None:
    return bytes.fromhex(program.runtime_bytecode) if program.runtime_bytecode is not None else None


def code_context(program: Program) -> dict:
    code = executed_code(program)
    return {
        "available": code is not None,
        "byte_length": len(code) if code is not None else None,
        "sha256": hashlib.sha256(code).hexdigest() if code is not None else None,
        "source": "relations/bytecode.hex" if code is not None else None,
        "scope": "Executed analysis input; not external-account code or an independent native-lifting proof.",
    }
