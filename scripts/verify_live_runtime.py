#!/usr/bin/env python3
"""Real-runtime validation for the Hexis Hermes guardrails plugin.

Closes the "faked-ctx smoke test" gap. Instead of constructing a fake plugin
context and calling the plugin functions directly, this drives the **real**
Hermes plugin machinery and watches a guard actually fire end-to-end:

  * real plugin discovery  (hermes_cli.plugins.discover_plugins)
  * real PluginContext     (the loader builds it and calls register(ctx))
  * real hook registry     (PluginManager._hooks)
  * real dispatch          (invoke_hook -> cb(**kwargs))
  * real config            (hermes_cli.config.load_config)
  * real violation log     (~/.hermes/plugins/hexis/state/*)

Two layers are exercised, both through genuine Hermes entry points:

  1. Contract layer  — get_pre_tool_call_block_message() is the exact function
     the agent loop calls (model_tools.py). It routes a terminal command through
     the hexis pre_tool_call hook and returns hexis' block directive message.

  2. Agent-loop layer — model_tools.handle_function_call() is the genuine tool
     dispatcher the model's tool calls flow through. A blocked command must come
     back as {"error": "[hexis:...] Blocked ..."} and must NOT execute.

Safety: guards inspect the command **string** only — they never run it. The one
agent-loop probe reads a credential file at a path that does not exist, so even
the impossible "guard regressed and did not block" branch only ever `cat`s a
missing file (harmless, no secret exposure, nothing destructive). The rm/force-
push probes are checked at the hook layer only (which never executes anything).

Run:    python3 scripts/verify_live_runtime.py
Exit:   0 = all checks passed, or SKIP (Hermes not importable on this machine)
        1 = a check FAILED — a guard contract regressed against the live runtime

This writes a handful of clearly-marked rows (session_id starts with
"hexis-live-validation") to the live violation/tool-call logs — that is exactly
what a real guard firing does, and the marker makes the rows identifiable.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


# --------------------------------------------------------------------------- #
# Bootstrap: put the live Hermes checkout on sys.path so `hermes_cli`,         #
# `hermes_constants`, `utils`, and `model_tools` import the same way they do   #
# inside a running Hermes process.                                             #
# --------------------------------------------------------------------------- #
def _bootstrap_hermes_path() -> bool:
    try:
        import hermes_cli.plugins  # noqa: F401
        return True
    except Exception:
        pass

    candidates = []
    env_home = os.environ.get("HERMES_HOME")
    if env_home:
        candidates.append(Path(env_home) / "hermes-agent")
    candidates.append(Path.home() / ".hermes" / "hermes-agent")
    # Derive from the `hermes` launcher if it is a console-script we can read.
    for binname in ("hermes",):
        from shutil import which

        p = which(binname)
        if p:
            candidates.append(Path(p).resolve().parent.parent / "hermes-agent")

    for cand in candidates:
        if cand.is_dir() and (cand / "hermes_cli").is_dir():
            sys.path.insert(0, str(cand))
            try:
                import hermes_cli.plugins  # noqa: F401
                return True
            except Exception:
                sys.path.pop(0)
                continue
    return False


# --------------------------------------------------------------------------- #
# Tiny check harness                                                           #
# --------------------------------------------------------------------------- #
class Checks:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def ok(self, name: str, cond: bool, detail: str = "") -> bool:
        mark = "PASS" if cond else "FAIL"
        line = f"  [{mark}] {name}"
        if detail:
            line += f"  — {detail}"
        print(line)
        if cond:
            self.passed += 1
        else:
            self.failed += 1
        return cond


def main() -> int:
    print("=" * 72)
    print(" Hexis Hermes guardrails — LIVE RUNTIME validation")
    print("=" * 72)

    if not _bootstrap_hermes_path():
        print(
            "\n  [SKIP] Hermes runtime not importable on this machine.\n"
            "         (no ~/.hermes/hermes-agent checkout / hermes_cli on path)\n"
            "         This validator is an integration check; it requires a\n"
            "         live Hermes install with the hexis plugin enabled.\n"
        )
        return 0

    from hermes_cli.plugins import (
        discover_plugins,
        get_plugin_manager,
        get_pre_tool_call_block_message,
        invoke_hook,
    )
    from hermes_cli.config import cfg_get, load_config

    c = Checks()
    marker = f"hexis-live-validation-{os.getpid()}-{int(time.time())}"

    # --- 0. config: is the plugin enabled with the modes we assert below? ---
    print("\n[0] Live config")
    cfg = load_config()
    enabled = cfg_get(cfg, "plugins", "enabled", default=[]) or []
    guards_cfg = cfg_get(cfg, "plugins", "entries", "hexis", "guards", default={}) or {}
    c.ok("hexis present in plugins.enabled", "hexis" in enabled, f"enabled={enabled}")
    c.ok("credential_read mode is 'block'",
         guards_cfg.get("credential_read") == "block",
         f"got {guards_cfg.get('credential_read')!r}")
    c.ok("force_push_main mode is 'block'",
         guards_cfg.get("force_push_main") == "block",
         f"got {guards_cfg.get('force_push_main')!r}")

    # --- 1. real discovery + registration ---------------------------------
    print("\n[1] Real plugin discovery & hook registration")
    discover_plugins(force=True)
    mgr = get_plugin_manager()
    info = {p["key"]: p for p in mgr.list_plugins()}
    hexis = info.get("hexis")
    c.ok("hexis discovered & loaded", bool(hexis) and hexis.get("enabled") is True,
         f"error={hexis.get('error') if hexis else 'not found'}")

    hooks = getattr(mgr, "_hooks", {})

    def _has_hexis_cb(hook: str, fn_name: str) -> bool:
        return any(
            getattr(cb, "__name__", "") == fn_name
            and "hexis" in getattr(cb, "__module__", "")
            for cb in hooks.get(hook, [])
        )

    c.ok("pre_tool_call hook registered by hexis",
         _has_hexis_cb("pre_tool_call", "_pre_tool_call"))
    c.ok("post_tool_call hook registered by hexis",
         _has_hexis_cb("post_tool_call", "_post_tool_call"))
    c.ok("transform_tool_result hook registered by hexis",
         _has_hexis_cb("transform_tool_result", "_transform_tool_result"))
    c.ok("on_session_end hook registered by hexis",
         _has_hexis_cb("on_session_end", "_on_session_end"))

    skills = getattr(mgr, "_plugin_skills", {})
    c.ok("hexis:enforce skill registered", "hexis:enforce" in skills)

    # --- 2. contract layer: block paths (the function the agent loop calls) -
    print("\n[2] Contract layer — get_pre_tool_call_block_message()")

    cred_msg = get_pre_tool_call_block_message(
        "terminal",
        {"command": "cat /tmp/hexis-validate-NOEXIST/.env"},
        session_id=marker,
    )
    c.ok("credential_read BLOCKS a terminal .env read",
         isinstance(cred_msg, str) and cred_msg.startswith("[hexis:credential_read]"),
         repr(cred_msg)[:90])

    fp_msg = get_pre_tool_call_block_message(
        "terminal",
        {"command": "git push --force origin main"},
        session_id=marker,
    )
    c.ok("force_push_main BLOCKS a force-push to main",
         isinstance(fp_msg, str) and fp_msg.startswith("[hexis:force_push_main]"),
         repr(fp_msg)[:90])

    # --- 3. contract layer: warn path + negative controls ------------------
    print("\n[3] Contract layer — warn path & negative controls")

    warn_msg = get_pre_tool_call_block_message(
        "terminal",
        {"command": "rm -rf /tmp/hexis-validate-NOEXIST-dir"},
        session_id=marker,
    )
    c.ok("rm_rf does NOT block (warn mode → command allowed)",
         warn_msg is None, repr(warn_msg)[:60])

    nonterm = get_pre_tool_call_block_message(
        "read_file", {"path": "/tmp/x/.env"}, session_id=marker,
    )
    c.ok("non-terminal tool is ignored by guards",
         nonterm is None, repr(nonterm)[:60])

    benign = get_pre_tool_call_block_message(
        "terminal", {"command": "echo hello"}, session_id=marker,
    )
    c.ok("benign terminal command is not blocked",
         benign is None, repr(benign)[:60])

    # --- 4. durable violation log actually recorded the firings ------------
    print("\n[4] Durable violation log")
    rows = load_violations()
    mine = [r for r in rows if r.get("session_id") == marker]
    cred_rows = [r for r in mine if r.get("rule") == "credential_read"
                 and r.get("fix_applied") == "blocked"]
    warn_rows = [r for r in mine if r.get("rule") == "rm_rf"
                 and r.get("fix_applied") == "allowed (warn mode)"]
    c.ok("credential_read firing written to violation log (fix=blocked)",
         len(cred_rows) >= 1, f"{len(cred_rows)} row(s)")
    c.ok("rm_rf firing written to violation log (fix=allowed warn)",
         len(warn_rows) >= 1, f"{len(warn_rows)} row(s)")

    # --- 5. post_tool_call observer writes the rolling tool-call log -------
    print("\n[5] post_tool_call observer")
    invoke_hook(
        "post_tool_call",
        tool_name="read_file",
        args={"path": "/x"},
        result="{}",
        session_id=marker,
        tool_call_id=marker + "-tc",
    )
    last = load_tool_log_last()
    c.ok("post_tool_call appended a rolling tool-call-log row",
         bool(last) and last.get("session_id") == marker,
         f"last.session_id={last.get('session_id') if last else None}")

    # --- 6. transform_tool_result is gated off (surface_to_model=false) ----
    print("\n[6] transform_tool_result gating")
    tr = invoke_hook(
        "transform_tool_result",
        tool_name="read_file",
        args={"path": "/x"},
        result="some output",
        session_id=marker,
        tool_call_id=marker + "-tc",
    )
    c.ok("transform_tool_result returns nothing when surfacing is off",
         tr == [], f"got {tr!r}")

    # --- 7. on_session_end is a clean no-op --------------------------------
    print("\n[7] on_session_end")
    try:
        se = invoke_hook("on_session_end", session_id=marker)
        c.ok("on_session_end dispatches without error", se == [], f"got {se!r}")
    except Exception as exc:
        c.ok("on_session_end dispatches without error", False, str(exc))

    # --- 8. agent-loop last mile: handle_function_call refuses + no exec ---
    print("\n[8] Agent-loop last mile — model_tools.handle_function_call()")
    try:
        from model_tools import handle_function_call

        out = handle_function_call(
            function_name="terminal",
            function_args={"command": "cat /tmp/hexis-validate-NOEXIST/.env"},
            task_id="hexis-validation",
            tool_call_id=marker + "-agent",
            session_id=marker + "-agentloop",
        )
        parsed = json.loads(out) if isinstance(out, str) else {}
        err = parsed.get("error", "")
        c.ok("agent loop returns a hexis block error (and never executes)",
             isinstance(err, str) and "[hexis:credential_read]" in err,
             repr(err)[:90])
    except Exception as exc:  # import-heavy module; treat import failure softly
        c.ok("agent loop last-mile check ran", False,
             f"could not exercise handle_function_call: {exc}")

    # --- summary -----------------------------------------------------------
    print("\n" + "=" * 72)
    total = c.passed + c.failed
    print(f" RESULT: {c.passed}/{total} checks passed, {c.failed} failed")
    print(f" marker session_id: {marker}")
    print("=" * 72)
    return 0 if c.failed == 0 else 1


# --------------------------------------------------------------------------- #
# Helpers that read the live state via the plugin's OWN path resolution, so    #
# the validator never hard-codes ~/.hermes/plugins/hexis/state.               #
# --------------------------------------------------------------------------- #
def _load_hexis_module():
    """Import the violations module the live plugin actually uses.

    After discover_plugins() loads the Hermes adapter, the adapter has put its
    vendored guardcore on sys.path, so ``guardcore.violations`` is the exact
    module the runtime writes through. Fall back to the legacy in-plugin module
    name for older installs.
    """
    import importlib

    for name in ("guardcore.violations", "hermes_plugins.hexis.violations"):
        try:
            return importlib.import_module(name)
        except Exception:
            continue
    return None


def load_violations():
    v = _load_hexis_module()
    return v.load() if v else []


def load_tool_log_last():
    v = _load_hexis_module()
    if not v:
        return None
    path = v.tool_log_path()
    if not path.exists():
        return None
    rows = [ln for ln in path.read_text(encoding="utf-8").split("\n") if ln.strip()]
    if not rows:
        return None
    try:
        return json.loads(rows[-1])
    except Exception:
        return None


if __name__ == "__main__":
    raise SystemExit(main())
