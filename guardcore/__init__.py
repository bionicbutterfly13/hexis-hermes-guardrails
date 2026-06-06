"""guardcore — the platform-agnostic command-guard core for Hexis guardrails.

Pure and stdlib-only. It knows nothing about any agent platform: no Hermes, no
Claude Code, no Cursor. Platform *adapters* translate each platform's hook
payload into a ``guards.evaluate(...)`` call and translate the returned decision
back into that platform's response shape.

- ``guards.evaluate(command, modes, session_id, cwd) -> {"action": "block", ...} | None``
- ``stuck.observe(tool_name, args, result, ...) -> pattern | None``
- ``violations`` — durable log; an adapter calls ``violations.set_state_dir(...)``
  to choose where logs live (the core never assumes a location).

Adapters:
- Hermes        — in-process Python (``hexis`` package: ``register(ctx)`` + hooks)
- Claude Code / Codex / Cursor — the single subprocess entry ``guardcore.hook``
"""

from __future__ import annotations

from . import guards, stuck, violations

__all__ = ["guards", "stuck", "violations"]
__version__ = "0.1.0"
