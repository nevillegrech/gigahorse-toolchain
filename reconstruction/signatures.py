"""Optional, offline signature hints, checked against EVM Keccak selectors.

These labels come from external knowledge. A matching selector is not evidence
that a contract implements the candidate ABI, return types or behavior.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .model import Program

SPECIAL_SELECTORS = {"0x00000000", "0xeeeeeeee", "0xff5e1ec7"}
SIGNATURE = re.compile(r"([A-Za-z_$][A-Za-z0-9_$]*)\([A-Za-z0-9_$(),\[\]]*\)", re.ASCII)


@dataclass
class SignatureInfo:
    source: str
    source_sha256: str
    selector_hash: str
    candidates: dict[str, list[str]]
    rejected_matching_rows: int


def apply_signature_file(program: Program, path: Path) -> None:
    try:
        from eth_hash.auto import keccak
    except ImportError as exc:
        raise ValueError("Signature hints require uv sync --extra naming") from exc
    selectors = {s for f in program.functions for s in f.selectors}
    if program.semantics:
        selectors.update(s for c in program.semantics.external_calls for s in c.selector_candidates)
    selectors -= SPECIAL_SELECTORS
    candidates: dict[str, set[str]] = {s: set() for s in selectors}
    digest = hashlib.sha256()
    rejected = 0
    # Hash the exact bytes while streaming, so large local dictionaries need
    # not be loaded into memory or fetched from a signature service.
    with path.open("rb") as stream:
        for raw in stream:
            digest.update(raw)
            parts = raw.rstrip(b"\r\n").split(b"\t")
            if len(parts) != 2:
                continue
            selector = parts[0].decode("ascii", errors="replace").lower()
            if selector not in selectors:
                continue
            try:
                signature = parts[1].decode("ascii")
            except UnicodeError:
                rejected += 1
                continue
            if (
                len(signature) > 1024
                or SIGNATURE.fullmatch(signature) is None
                or "0x" + keccak(signature.encode())[:4].hex() != selector
            ):
                rejected += 1
                continue
            candidates[selector].add(signature)
    program.signature_info = SignatureInfo(
        str(path.resolve()),
        digest.hexdigest(),
        "keccak-256-first-four-bytes",
        {s: sorted(values) for s, values in sorted(candidates.items()) if values},
        rejected,
    )
    program.warnings.append(
        "Signature-derived names start with hint_; signature candidates can collide and do not prove parameter types, return types or target behavior."
    )
    if rejected:
        program.warnings.append(
            f"Rejected {rejected} invalid or hash-mismatched signature rows for recovered selectors."
        )
    if program.semantics:
        for call in program.semantics.external_calls:
            if call.selector_resolved:
                hints = program.signature_info.candidates.get(call.selector_candidates[0], [])
                call.signature_hints = sorted(set(call.signature_hints) | set(hints))
                if hints and not any("Signature hints" in w for w in call.warnings):
                    call.warnings.append(
                        "Signature hints can collide and do not establish target behavior."
                    )
