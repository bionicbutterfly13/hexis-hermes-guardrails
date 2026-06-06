"""Stuck-loop detector — a Python port of Hexis' stuck-detector.js, wired to
Hermes' ``post_tool_call`` hook.

Maintains a rolling per-session in-memory window and a profile-local durable
``tool-call-log.jsonl`` of recent tool calls. It trips on three patterns
(thresholds from Hexis / OpenHands research):

  1. Same exact tool call repeated 3+ times in a row.
  2. Same error message seen 2+ times.
  3. A-B-A-B oscillation over the last 6+ steps.

On a trip it writes a violation record (source="stuck-loop") and emits a logger
warning. Surfacing the warning *into the model's context* uses the
``transform_tool_result`` hook and is gated behind
``plugins.entries.hexis.stuck_loop.surface_to_model`` (default false) because it
changes what the model sees.

Raw tool arguments are not written to the durable tool log; the log stores tool
name, session id, tool call id when present, a stable signature, and a short
error snippet. The snippet is truncated and redacted for common secret patterns
on a best-effort basis (sk-, gh*_, AKIA, xox*, password=/token=/api_key=/bearer);
treat the log as low-sensitivity, not a guaranteed secret-free store.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections import OrderedDict, deque
from datetime import datetime, timezone
from typing import Deque, Dict, Optional

from . import violations

logger = logging.getLogger(__name__)

_MAX_HISTORY = 50           # per-session rolling window
_MAX_SESSIONS = 512         # bound the number of tracked sessions (LRU)
_REPEAT_THRESHOLD = 3       # same call N times in a row
_ERROR_THRESHOLD = 2        # same error N times total in window
_OSCILLATION_WINDOW = 6     # look back this many steps for A-B-A-B

# In-memory per-session state, bounded to the _MAX_SESSIONS most-recently-active
# sessions. observe() runs inside Hermes' ThreadPoolExecutor, so all three maps
# are guarded by a single lock and evicted in LOCKSTEP (_history is the authority)
# so dedup state can never desync. The lock guards ONLY these in-memory ops —
# file I/O (violations.record / append_rolling_tool_call) runs OUTSIDE it.
_lock = threading.Lock()
_history: "OrderedDict[str, Deque[dict]]" = OrderedDict()   # sid -> deque of {"sig","err"}
_reported: "OrderedDict[str, set]" = OrderedDict()          # sid -> patterns already reported
_pending: "OrderedDict[str, Dict[str, str]]" = OrderedDict()  # sid -> event_key -> pattern


def _touch(sid: str) -> None:
    """Create/refresh a session's slots and evict the oldest over cap.

    MUST be called while holding ``_lock``. _history is the eviction authority;
    the evicted sid is popped from all three maps together (lockstep).
    """
    if sid in _history:
        _history.move_to_end(sid)
        _reported.move_to_end(sid)
        _pending.move_to_end(sid)
    else:
        _history[sid] = deque(maxlen=_MAX_HISTORY)
        _reported[sid] = set()
        _pending[sid] = {}
    while len(_history) > _MAX_SESSIONS:
        old, _ = _history.popitem(last=False)
        _reported.pop(old, None)
        _pending.pop(old, None)


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _call_signature(tool_name: str, args: Optional[dict]) -> str:
    """Stable hash of (tool, args) so identical calls collapse to one sig."""
    try:
        payload = json.dumps(args or {}, sort_keys=True, ensure_ascii=False, default=str)
    except Exception:
        payload = repr(args)
    return f"{tool_name}:" + hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


def _event_key(tool_call_id: Optional[str], sig: str) -> str:
    return str(tool_call_id) if tool_call_id else sig


# Bound the input scanned/parsed by _extract_error so a huge tool result can't
# cost O(n) inside the synchronous post_tool_call hook.
_MAX_ERROR_SCAN = 20000


def _extract_error(result) -> Optional[str]:
    """Pull a comparable, redacted error string out of a tool result, if it errored."""
    if result is None:
        return None
    text = result if isinstance(result, str) else None
    if text is None:
        return None
    if len(text) > _MAX_ERROR_SCAN:  # bound BEFORE parsing/scanning
        text = text[:_MAX_ERROR_SCAN]
    # Tool errors are returned as json.dumps({"error": "..."}).
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and obj.get("error"):
            return violations.redact(str(obj["error"])[:200])
    except Exception:
        pass
    low = text.lower()
    if "traceback (most recent call last)" in low or low.startswith("error"):
        return violations.redact(text[:200])
    return None


def _detect(hist: Deque[dict]) -> Optional[str]:
    """Return a description of the stuck pattern found, or None."""
    items = list(hist)
    if len(items) >= _REPEAT_THRESHOLD:
        tail = items[-_REPEAT_THRESHOLD:]
        if len({i["sig"] for i in tail}) == 1:
            return (
                f"same tool call repeated {_REPEAT_THRESHOLD}x in a row "
                f"({tail[-1]['sig']})"
            )

    errs = [i["err"] for i in items if i["err"]]
    if errs:
        last = errs[-1]
        if sum(1 for e in errs if e == last) >= _ERROR_THRESHOLD:
            return f"same error seen {_ERROR_THRESHOLD}+ times: {last[:120]}"

    if len(items) >= _OSCILLATION_WINDOW:
        window = items[-_OSCILLATION_WINDOW:]
        sigs = [i["sig"] for i in window]
        a, b = sigs[0], sigs[1]
        if a != b and all(
            sigs[i] == (a if i % 2 == 0 else b) for i in range(_OSCILLATION_WINDOW)
        ):
            return f"A-B-A-B oscillation over {_OSCILLATION_WINDOW} steps ({a} <-> {b})"

    return None


def observe(
    tool_name: str,
    args: Optional[dict],
    result,
    session_id: str = "",
    tool_call_id: Optional[str] = None,
    surface: bool = False,
) -> Optional[str]:
    """Record a tool call and check for a stuck pattern.

    Returns the pattern description if a *new* stuck pattern was detected this
    step, else None. Always safe — swallows all errors. The lock guards only the
    in-memory bookkeeping; the durable tool-log / violation writes happen OUTSIDE
    the lock so parallel tool threads are never serialized on disk. ``surface``
    controls whether the pattern is parked in ``_pending`` for the transform hook
    (skipped when surface_to_model is off — nothing consumes it then).
    """
    try:
        sid = session_id or "default"
        tool = tool_name or ""
        sig = _call_signature(tool, args)
        err = _extract_error(result)

        pattern: Optional[str] = None
        with _lock:
            _touch(sid)
            _history[sid].append({"sig": sig, "err": err})
            candidate = _detect(_history[sid])
            if candidate and candidate not in _reported[sid]:
                _reported[sid].add(candidate)
                pattern = candidate
                if surface:
                    _pending[sid][_event_key(tool_call_id, sig)] = candidate

        # File I/O OUTSIDE the lock.
        violations.append_rolling_tool_call(
            {
                "date": _now_iso(),
                "session_id": sid,
                "tool_name": tool,
                "tool_call_id": str(tool_call_id or ""),
                "signature": sig,
                "error": err or "",
            },
            limit=_MAX_HISTORY,
        )

        if not pattern:
            return None
        violations.record(
            rule="stuck_loop",
            what_happened=pattern,
            root_cause="agent repeating without progress",
            fix_applied="warned",
            severity="warn",
            source="stuck-loop",
            session_id=sid,
            extra={
                "tool_call_id": str(tool_call_id or ""),
                "tool_signature": sig,
            },
        )
        logger.warning("hexis stuck-loop detected [%s]: %s", sid, pattern)
        return pattern
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("hexis stuck detector error: %s", exc)
        return None


def consume_pending_warning(
    tool_name: str,
    args: Optional[dict],
    session_id: str = "",
    tool_call_id: Optional[str] = None,
) -> Optional[str]:
    """Return (and clear) the stuck warning for a call already observed."""
    try:
        sid = session_id or "default"
        sig = _call_signature(tool_name or "", args)
        key = _event_key(tool_call_id, sig)
        with _lock:
            slot = _pending.get(sid)
            return slot.pop(key, None) if slot is not None else None
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("hexis stuck warning consume error: %s", exc)
        return None


def reset(session_id: str = "") -> None:
    """Clear per-session state (called on session end)."""
    sid = session_id or "default"
    with _lock:
        _history.pop(sid, None)
        _reported.pop(sid, None)
        _pending.pop(sid, None)
