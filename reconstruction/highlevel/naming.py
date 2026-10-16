"""Hash-checked names from local selector/topic dictionaries.

A dictionary row is used only when Keccak-256 of its text reproduces the
selector or topic found in the bytecode. 4-byte selectors can still collide,
so every name stays labelled as a dictionary hint; 32-byte event topics are
effectively unique once the hash matches.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..keccak import keccak256

ROOT = Path(__file__).resolve().parents[2]
SIGNATURE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\([A-Za-z0-9_$(),\[\] ]*\)", re.ASCII)


@dataclass
class Dictionary:
    path: Path | None
    sha256: str | None
    matches: dict[str, list[str]] = field(default_factory=dict)
    rejected: int = 0

    def metadata(self) -> dict:
        return {
            "path": str(self.path) if self.path else None,
            "sha256": self.sha256,
            "rejected_rows_failing_hash_check": self.rejected,
        }


def lookup(path: Path | None, keys: set[str], width: int) -> Dictionary:
    """Return hash-verified candidates for `keys` (lowercase 0x-hex of `width` bytes)."""
    if path is None or not path.is_file() or not keys:
        return Dictionary(path if path and path.is_file() else None, None)
    digest = hashlib.sha256()
    found: dict[str, set[str]] = {}
    rejected = 0
    with path.open("rb") as stream:
        for raw in stream:
            digest.update(raw)
            parts = raw.rstrip(b"\r\n").split(b"\t")
            if len(parts) != 2:
                continue
            key = parts[0].decode("ascii", "replace").lower()
            if key not in keys:
                continue
            try:
                text = parts[1].decode("ascii")
            except UnicodeError:
                rejected += 1
                continue
            if len(text) > 512 or not SIGNATURE.fullmatch(text):
                rejected += 1
                continue
            if "0x" + keccak256(text.encode()).hex()[: 2 * width] != key:
                rejected += 1
                continue
            found.setdefault(key, set()).add(text)
    return Dictionary(path, digest.hexdigest(), {k: sorted(v) for k, v in found.items()}, rejected)


@dataclass
class Names:
    functions: Dictionary
    events: Dictionary
    errors: Dictionary

    def function(self, selector: str) -> str | None:
        candidates = self.functions.matches.get(selector, [])
        return candidates[0] if len(candidates) == 1 else None

    def event(self, topic: str) -> str | None:
        candidates = self.events.matches.get(topic, [])
        return candidates[0] if len(candidates) == 1 else None

    def error(self, selector: str) -> str | None:
        candidates = self.errors.matches.get(selector, [])
        return candidates[0] if len(candidates) == 1 else None

    def metadata(self) -> dict:
        return {
            "policy": "Names are used only when Keccak-256 of the dictionary text reproduces the "
            "selector/topic; 4-byte selectors may still collide, so names remain hints.",
            "functions": self.functions.metadata(),
            "events": self.events.metadata(),
            "errors": self.errors.metadata(),
            "function_candidates": self.functions.matches,
            "event_candidates": self.events.matches,
            "error_candidates": self.errors.matches,
        }


def default_dictionary(name: str) -> Path | None:
    path = ROOT / name
    return path if path.is_file() else None


def load_names(
    selectors: set[str],
    topics: set[str],
    errors: set[str],
    *,
    functions_path: Path | None = None,
    events_path: Path | None = None,
    errors_path: Path | None = None,
    use_defaults: bool = True,
) -> Names:
    if use_defaults:
        functions_path = functions_path or default_dictionary("PublicFunctionSignature.facts")
        events_path = events_path or default_dictionary("EventSignature.facts")
        errors_path = errors_path or default_dictionary("ErrorSignature.facts")
    return Names(
        lookup(functions_path, selectors, 4),
        lookup(events_path, topics, 32),
        lookup(errors_path, errors, 4),
    )


def split_signature(signature: str) -> tuple[str, list[str]]:
    name, _, rest = signature.partition("(")
    inner = rest[:-1]
    params: list[str] = []
    depth = 0
    current = ""
    for char in inner:
        if char == "," and depth == 0:
            params.append(current)
            current = ""
            continue
        depth += char == "("
        depth -= char == ")"
        current += char
    if current:
        params.append(current)
    return name, params
