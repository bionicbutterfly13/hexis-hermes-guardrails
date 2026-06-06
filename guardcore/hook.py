"""Universal pre-command guard hook for subprocess-based agent platforms.

ONE entry point shared by Claude Code, Codex CLI, and Cursor (and extensible to
goose, OpenHands, Gemini CLI, Continue, ...). It reads the platform's pending
tool call as JSON on stdin, runs the shared ``guardcore`` rules, and emits that
platform's "deny" response when a block-mode guard matches.

The platforms converged on one contract: stdin JSON carrying the command, and a
block via a JSON decision on stdout (exit 0). The only differences are the field
names and the exact deny shape — handled by ``_extract`` / ``_emit_deny``:

  Claude Code / Codex : PreToolUse, command at tool_input.command,
                        deny -> {"hookSpecificOutput":{"permissionDecision":"deny",...}}
  Cursor              : beforeShellExecution, command at top-level "command",
                        deny -> {"permission":"deny","agent_message","user_message"}

Wiring (the installer writes these configs for you):
  Claude Code  hooks.json  PreToolUse matcher "Bash"   -> python -m guardcore.hook
  Codex CLI    hooks.json  PreToolUse matcher "^Bash$"  -> python -m guardcore.hook
  Cursor       .cursor/hooks.json beforeShellExecution  -> python -m guardcore.hook

Safety posture: this guard only ever *denies on a real rule match*. On a parse
error or internal fault it ALLOWS (exit 0) rather than bricking the agent loop —
it is defense-in-depth, not the sole gate. Platforms that support fail-closed on
hook crash (e.g. Cursor's failClosed:true) provide the crash-time backstop.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from . import guards

# Tool names that denote a shell/command execution across platforms.
_SHELL_TOOLS = frozenset({
    "bash", "shell", "terminal", "execute_command",
    "run_shell_command", "developer__shell",
})


def _load_modes() -> dict:
    """Guard modes for hook platforms: a config file if present, else defaults.

    Looks at ``$GUARDCORE_CONFIG`` then ``~/.hexis-guardrails/config.json`` for a
    top-level ``{"guards": {...}}`` map; otherwise uses ``guards.DEFAULT_MODES``.
    """
    candidates = []
    env = os.environ.get("GUARDCORE_CONFIG")
    if env:
        candidates.append(Path(env))
    candidates.append(Path.home() / ".hexis-guardrails" / "config.json")
    for p in candidates:
        try:
            if p.is_file():
                data = json.loads(p.read_text(encoding="utf-8"))
                g = data.get("guards") if isinstance(data, dict) else None
                if isinstance(g, dict):
                    return g
        except Exception:
            continue
    return dict(guards.DEFAULT_MODES)


def _extract(event: dict):
    """Return (platform, command, cwd, session_id) from a platform hook event.

    platform: "cursor" (beforeShellExecution; top-level ``command``) or
    "pretooluse" (Claude Code / Codex / compatible; ``tool_input.command``).
    command is ``None`` when this event is not a shell/command call to inspect.
    """
    name = (
        event.get("hook_event_name")
        or event.get("hookEventName")
        or event.get("event")
        or event.get("event_type")
        or ""
    )
    session_id = event.get("session_id") or event.get("sessionId") or ""

    if name == "beforeShellExecution":
        return "cursor", event.get("command"), event.get("cwd"), session_id

    # PreToolUse family (Claude Code, Codex, OpenHands, goose, Continue, ...).
    tool = (event.get("tool_name") or event.get("tool") or "").lower()
    ti = event.get("tool_input") or event.get("parameters") or {}
    command = ti.get("command") if isinstance(ti, dict) else None
    cwd = event.get("cwd") or event.get("working_dir")
    # If a tool name is present, only inspect recognized shell tools; if absent,
    # fall back to "inspect whatever carries a command" (defensive).
    if command is not None and tool and tool not in _SHELL_TOOLS:
        command = None
    return "pretooluse", command, cwd, session_id


def _emit_allow() -> int:
    # Empty object = "no opinion": never overrides a platform's own allow/ask
    # flow; we only ever assert a decision to DENY.
    sys.stdout.write("{}")
    return 0


def _emit_deny(platform: str, reason: str) -> int:
    if platform == "cursor":
        sys.stdout.write(json.dumps({
            "permission": "deny",
            "agent_message": reason,
            "user_message": reason,
        }))
        return 0
    # Claude Code / Codex (and PreToolUse-compatible platforms).
    sys.stdout.write(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    return 0


def main(argv=None) -> int:
    try:
        raw = sys.stdin.read()
        event = json.loads(raw) if raw and raw.strip() else {}
        if not isinstance(event, dict):
            event = {}
    except Exception:
        return _emit_allow()  # unparseable event — do not brick the agent

    try:
        platform, command, cwd, session_id = _extract(event)
        if not command:
            return _emit_allow()
        decision = guards.evaluate(
            command, _load_modes(), session_id=session_id or "", cwd=cwd
        )
        if isinstance(decision, dict) and decision.get("action") == "block":
            return _emit_deny(platform, decision.get("message") or "blocked by hexis guardrails")
        return _emit_allow()
    except Exception:
        return _emit_allow()  # internal guard fault must not break the agent loop


if __name__ == "__main__":
    raise SystemExit(main())
