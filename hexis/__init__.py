"""Hexis metacognitive guardrails for Hermes Agent.

Ports the Hexis operating model (github.com/hexis-framework/hexis, MIT, commit
abef260) onto Hermes-native plugin surfaces. Hexis itself targets Claude Code;
this plugin re-expresses the portable parts of its model as a standalone Hermes
plugin so nothing in hermes-agent/ is patched and the integration survives
Hermes updates.

The command guards are heuristic defense-in-depth over the ``terminal`` tool's
command string, NOT a security boundary — Hermes core is the real gate. See
README.md and guards.py for the bypass caveats.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

# Import the shared, platform-agnostic core. When this plugin is installed into a
# Hermes profile the installer vendors ``guardcore`` alongside this file, so add
# our own dir to sys.path to resolve it; in a source checkout it imports normally.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
from guardcore import guards, stuck, violations  # noqa: E402

logger = logging.getLogger(__name__)

_SKILL_PATH = Path(__file__).resolve().parent / "SKILL.md"


def _hexis_cfg():
    """Read the hexis config subtree as a dict, tolerant of missing/malformed config.

    Returns {} for any non-dict value (a truthy non-dict like the string
    'enabled' must NOT pass through — `.get()` on it would raise and fail the
    whole hook open).
    """
    try:
        from hermes_cli.config import cfg_get, load_config

        cfg = load_config()
        val = cfg_get(cfg, "plugins", "entries", "hexis", default={})
        return val if isinstance(val, dict) else {}
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("hexis: config unavailable, using defaults: %s", exc)
        return {}


def _stuck_cfg():
    """Return the stuck_loop config subtree as a dict (tolerant of non-dict)."""
    sl = _hexis_cfg().get("stuck_loop")
    return sl if isinstance(sl, dict) else {}


def _pre_tool_call(tool_name=None, args=None, session_id="", **kwargs):
    """Command guard. Returns a block directive or None."""
    if tool_name != "terminal":
        return None
    if not isinstance(args, dict):
        return None
    command = args.get("command")
    if not command:
        return None
    # The terminal schema exposes the per-command working dir as 'workdir'
    # (tools/terminal_tool.py), NOT 'cwd'. Keep 'cwd' as a fallback for any
    # non-terminal caller.
    cwd = args.get("workdir") or args.get("cwd")
    g = _hexis_cfg().get("guards")
    guards_cfg = g if isinstance(g, dict) else {}
    return guards.evaluate(command, guards_cfg, session_id=session_id or "", cwd=cwd)


def _post_tool_call(
    tool_name=None,
    args=None,
    result=None,
    session_id="",
    tool_call_id=None,
    **kwargs,
):
    """Observe tool calls for stuck-loop patterns. Never blocks."""
    sl_cfg = _stuck_cfg()
    if sl_cfg.get("enabled", True) is False:
        return None
    stuck.observe(
        tool_name,
        args,
        result,
        session_id=session_id or "",
        tool_call_id=tool_call_id,
        surface=bool(sl_cfg.get("surface_to_model", False)),
    )
    return None


def _transform_tool_result(
    tool_name=None,
    args=None,
    result=None,
    session_id="",
    tool_call_id=None,
    **kwargs,
):
    """Append an opt-in stuck warning without observing the call twice."""
    sl_cfg = _stuck_cfg()
    if not sl_cfg.get("surface_to_model", False):
        return None
    pattern = stuck.consume_pending_warning(
        tool_name,
        args,
        session_id=session_id or "",
        tool_call_id=tool_call_id,
    )
    if not pattern or not isinstance(result, str):
        return None
    note = (
        f"\n\n[hexis] Possible stuck loop: {pattern}. "
        "Stop and reassess the root cause before repeating the same move."
    )
    return result + note


def _on_session_end(session_id="", **kwargs):
    """Clear per-session stuck-detector state."""
    stuck.reset(session_id or "")
    return None


def _set_hermes_state_dir():
    """Point guardcore's durable logs at the Hermes profile (the adapter owns this).

    This is the Hermes-specific knowledge that was lifted OUT of the core: the
    core never imports hermes_constants or reads HERMES_HOME — the Hermes adapter
    resolves the profile path and tells the core where to write.
    """
    try:
        from hermes_constants import get_hermes_home  # type: ignore

        home = Path(get_hermes_home())
    except Exception:  # pragma: no cover - defensive
        home = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes")))
    violations.set_state_dir(home / "plugins" / "hexis" / "state")


def register(ctx):
    _set_hermes_state_dir()
    ctx.register_hook("pre_tool_call", _pre_tool_call)
    ctx.register_hook("post_tool_call", _post_tool_call)
    ctx.register_hook("transform_tool_result", _transform_tool_result)
    ctx.register_hook("on_session_end", _on_session_end)

    if _SKILL_PATH.exists():
        try:
            ctx.register_skill(
                name="enforce",
                path=_SKILL_PATH,
                description=(
                    "Hexis enforcement-escalation workflow: review the violation "
                    "log, classify repeat failures, route lessons to the right "
                    "layer, and decide when a warn guard graduates to block."
                ),
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("hexis: skill registration failed: %s", exc)

    logger.info(
        "hexis registered (4 hooks, 1 skill); violation log at %s",
        violations.md_path(),
    )
