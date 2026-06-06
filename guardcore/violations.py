"""Violation log - the durable record that drives Hexis enforcement escalation.

Every guard trip and stuck-loop detection appends a structured record here. The
log is the input to the human-driven `hexis:enforce` skill, which decides when a
`warn` guard has earned promotion to a hard `block` (Hexis' two-strike rule).

Two representations, written together:
  - rule-violation-log.jsonl  - machine-readable, one JSON object per line.
  - rule-violation-log.md     - human-readable markdown table (Hexis schema).

Both live under the active profile's Hermes home, so they are profile-local and
survive Hermes updates. Writes use a best-effort file lock so concurrent Hermes
sessions do not interleave rows on platforms that support fcntl.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional

try:  # pragma: no cover - platform dependent
    import fcntl
except Exception:  # pragma: no cover - Windows / restricted runtimes
    fcntl = None

logger = logging.getLogger(__name__)

_MD_HEADER = (
    "# Hexis Rule Violation Log\n\n"
    "Tracks when a rule was violated despite existing. The `hexis:enforce` "
    "skill reads this to decide when a `warn` guard graduates to a hard "
    "`block` (Hexis two-strike rule).\n\n"
    "| Date | Rule | What happened | Root cause | Fix applied |\n"
    "|------|------|---------------|------------|-------------|\n"
)


# Common provider secret shapes, ordered common-first, anchored to avoid
# catastrophic backtracking. Shared by stuck (error snippets) and guards
# (command strings) so nothing secret-shaped is written to a durable log.
_SECRET_RE = re.compile(
    r"sk-[A-Za-z0-9_-]{16,}"
    r"|gh[posu]_[A-Za-z0-9]{20,}"
    r"|AKIA[0-9A-Z]{12,}"
    r"|xox[baprs]-[A-Za-z0-9-]+"
    r"|(?i:bearer)\s+[A-Za-z0-9._~+/-]+=*"
    r"|(?i:password|passwd|pwd|api[_-]?key|token|secret)\s*[=:]\s*\S+"
)


def redact(text: str) -> str:
    """Mask common provider secrets in a short snippet (best-effort)."""
    try:
        return _SECRET_RE.sub("[redacted]", text)
    except Exception:  # pragma: no cover - defensive
        return text


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


# A platform adapter sets the durable state location; the CORE never assumes a
# platform (no hermes_constants, no HERMES_HOME). This is the one piece of
# platform knowledge that was lifted out of the core into the adapters.
_STATE_DIR_OVERRIDE: Optional[Path] = None


def set_state_dir(path) -> None:
    """Point the durable logs at *path*. Called by a platform adapter at init.

    Pass ``None`` to clear the override and fall back to env / default.
    """
    global _STATE_DIR_OVERRIDE
    _STATE_DIR_OVERRIDE = Path(path) if path is not None else None


def state_dir() -> Path:
    """Return the durable state directory. NEVER raises.

    Resolution order:
      1. an explicit override set by an adapter (``set_state_dir``),
      2. ``$GUARDCORE_STATE_DIR``,
      3. ``~/.hexis-guardrails/state`` (platform-neutral default).

    If the chosen path cannot be created (read-only home, ENOSPC, permission
    error), fall back to a temp dir; if even that fails, return the intended path
    uncreated (callers already swallow write errors). The guard block path must
    never fail just because state cannot be written.
    """
    if _STATE_DIR_OVERRIDE is not None:
        d = _STATE_DIR_OVERRIDE
    else:
        env = os.environ.get("GUARDCORE_STATE_DIR")
        d = Path(env) if env else (Path.home() / ".hexis-guardrails" / "state")
    try:
        d.mkdir(parents=True, exist_ok=True)
        return d
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("guardcore: state dir %s not creatable (%s); temp fallback", d, exc)
    try:
        fallback = Path(tempfile.gettempdir()) / "hexis-guardrails-state"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback
    except Exception:  # pragma: no cover - defensive
        return d


def jsonl_path() -> Path:
    return state_dir() / "rule-violation-log.jsonl"


def md_path() -> Path:
    return state_dir() / "rule-violation-log.md"


def tool_log_path() -> Path:
    return state_dir() / "tool-call-log.jsonl"


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    """Best-effort interprocess lock for a state file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    with lock_path.open("a", encoding="utf-8") as lock_fh:
        if fcntl is not None:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)


def _md_escape(text: str) -> str:
    """Make a cell safe for a single-line markdown table cell.

    Collapses every character str.splitlines() treats as a line break (incl. the
    Unicode separators U+2028/U+2029/U+0085 and CR) to a space so the advisory md
    table stays one row per record.
    """
    s = str(text)
    for ch in ("\n", "\r", " ", " ", "\x85"):
        s = s.replace(ch, " ")
    return s.replace("|", "\\|").strip()


def record(
    rule: str,
    what_happened: str,
    root_cause: str = "",
    fix_applied: str = "",
    *,
    severity: str = "warn",
    source: str = "guard",
    session_id: str = "",
    extra: Optional[Dict] = None,
) -> Dict:
    """Append one violation record to both the JSONL and markdown logs."""
    rec = {
        "date": _now_iso(),
        "rule": rule,
        "what_happened": what_happened,
        "root_cause": root_cause,
        "fix_applied": fix_applied,
        "severity": severity,
        "source": source,
        "session_id": session_id,
    }
    if extra:
        rec.update(extra)

    try:
        _append_jsonl(jsonl_path(), rec)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("hexis: failed to append violation jsonl: %s", exc)

    try:
        _append_md_row(rec)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("hexis: failed to append violation md: %s", exc)

    return rec


def _append_jsonl(path: Path, rec: Dict) -> None:
    # ensure_ascii=True escapes U+2028/U+2029/U+0085 so a logged command or error
    # containing a Unicode line separator can't fragment the JSON-lines record
    # (str.splitlines() splits on those; split("\n") on read does not).
    line = json.dumps(rec, ensure_ascii=True) + "\n"
    with _locked(path):
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)


def _append_md_row(rec: Dict) -> None:
    path = md_path()
    row = "| {date} | {rule} | {what} | {cause} | {fix} |\n".format(
        date=_md_escape(rec["date"]),
        rule=_md_escape(rec["rule"]),
        what=_md_escape(rec["what_happened"]),
        cause=_md_escape(rec["root_cause"]),
        fix=_md_escape(rec["fix_applied"]),
    )
    with _locked(path):
        if not path.exists():
            path.write_text(_MD_HEADER, encoding="utf-8")
        with path.open("a", encoding="utf-8") as fh:
            fh.write(row)


def append_rolling_tool_call(rec: Dict, limit: int = 50) -> None:
    """Append a tool-call observation and keep only the latest *limit* rows."""
    path = tool_log_path()
    with _locked(path):
        rows: List[Dict] = []
        if path.exists():
            for line in path.read_text(encoding="utf-8").split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
        rows.append(rec)
        rows = rows[-max(1, limit):]
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(
            "".join(json.dumps(row, ensure_ascii=True) + "\n" for row in rows),
            encoding="utf-8",
        )
        tmp.replace(path)


def load() -> List[Dict]:
    """Return all violation records, oldest first. Never raises.

    Path resolution is inside the try so a state-dir failure returns [] rather
    than propagating out through count_for_rule into the guard block path.
    """
    out: List[Dict] = []
    try:
        path = jsonl_path()
        if not path.exists():
            return []
        with _locked(path):
            text = path.read_text(encoding="utf-8")
        # split("\n") (NOT splitlines) so a U+2028/U+2029/U+0085 inside a value
        # can't break records apart; per-line try/continue so one bad line can't
        # drop the rest (this is the input to the two-strike escalation count).
        for line in text.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("hexis: failed to read violation log: %s", exc)
    return out


def count_for_rule(rule: str) -> int:
    """How many times *rule* has been logged."""
    return sum(1 for r in load() if r.get("rule") == rule)
