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
SPECIAL_SELECTORS = {"0x00000000", "0xeeeeeeee", "0xff5e1ec7"}
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
    online_report: dict | None = None

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
            "online_lookup": self.online_report,
            "from_online_cache": {
                "functions": getattr(self.functions, "extra_matches", {}),
                "events": getattr(self.events, "extra_matches", {}),
                "errors": getattr(self.errors, "extra_matches", {}),
            },
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
    online: bool = False,
) -> Names:
    if use_defaults:
        functions_path = functions_path or default_dictionary("PublicFunctionSignature.facts")
        events_path = events_path or default_dictionary("EventSignature.facts")
        errors_path = errors_path or default_dictionary("ErrorSignature.facts")
    names = Names(
        lookup(functions_path, selectors, 4),
        lookup(events_path, topics, 32),
        lookup(errors_path, errors, 4),
    )
    # Pseudo-selectors (fallback/receive markers) are never looked up: any text "matches".
    missing_functions = {
        s for s in selectors if s not in names.functions.matches and s not in SPECIAL_SELECTORS
    }
    missing_events = {t for t in topics if t not in names.events.matches}
    missing_errors = {e for e in errors if e not in names.errors.matches}
    if online and (missing_functions or missing_events or missing_errors):
        names.online_report = fetch_online(missing_functions, missing_events, missing_errors)
    # Previously cached online results are local data now (still hash-checked).
    cached_functions = lookup(cache_path("functions"), missing_functions | missing_errors, 4)
    cached_events = lookup(cache_path("events"), missing_events, 32)
    names.functions = merge(names.functions, lookup(cache_path("functions"), missing_functions, 4))
    names.errors = merge(names.errors, lookup(cache_path("functions"), missing_errors, 4))
    names.events = merge(names.events, cached_events)
    _ = cached_functions
    return names


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


CACHE_DIR = ROOT / "cache" / "signatures"
OPENCHAIN = "https://api.openchain.xyz/signature-database/v1/lookup"


def cache_path(kind: str) -> Path:
    return CACHE_DIR / f"{kind}.tsv"


def fetch_online(
    selectors: set[str], topics: set[str], errors: set[str], *, timeout: int = 20
) -> dict:
    """Look up unresolved keys on openchain.xyz and append hash-checked rows to the local cache.

    Opt-in only: it discloses the queried selectors/topics to that service.
    Returns a report with the queried and newly cached counts.
    """
    import json
    import urllib.parse
    import urllib.request

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    report = {"service": OPENCHAIN, "queried": 0, "cached": 0, "rejected": 0}
    jobs = [("function", sorted(selectors | errors), 4), ("event", sorted(topics), 32)]
    for kind, keys, width in jobs:
        for start in range(0, len(keys), 40):
            batch = keys[start : start + 40]
            if not batch:
                continue
            query = urllib.parse.urlencode({kind: ",".join(batch), "filter": "false"})
            with urllib.request.urlopen(f"{OPENCHAIN}?{query}", timeout=timeout) as response:
                payload = json.loads(response.read())
            report["queried"] += len(batch)
            rows = []
            for key, entries in (payload.get("result", {}).get(kind) or {}).items():
                for entry in entries or []:
                    text = entry.get("name", "")
                    if (
                        not SIGNATURE.fullmatch(text)
                        or "0x" + keccak256(text.encode()).hex()[: 2 * width] != key.lower()
                    ):
                        report["rejected"] += 1
                        continue
                    rows.append(f"{key.lower()}\t{text}\n")
            if rows:
                target = cache_path("functions" if kind == "function" else "events")
                with target.open("a") as stream:
                    stream.writelines(rows)
                report["cached"] += len(rows)
    return report


def merge(primary: Dictionary, extra: Dictionary) -> Dictionary:
    matches = {k: list(v) for k, v in primary.matches.items()}
    for key, values in extra.matches.items():
        if key not in matches:
            matches[key] = list(values)
    result = Dictionary(primary.path, primary.sha256, matches, primary.rejected + extra.rejected)
    result.extra_sources = [str(extra.path)] if extra.path else []  # type: ignore[attr-defined]
    result.extra_matches = {k: v for k, v in extra.matches.items() if k not in primary.matches}  # type: ignore[attr-defined]
    return result
