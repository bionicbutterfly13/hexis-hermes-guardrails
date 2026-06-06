#!/usr/bin/env bash
# Hermetic install/uninstall smoke test.
#
# Installs the plugin into a throwaway HERMES_HOME, compiles it, verifies hook +
# skill registration and representative block/warn behavior, then uninstalls and
# confirms the directory is gone. Never touches your real ~/.hermes profile.
#
# This is the portable CI check (no live Hermes needed). For a check against the
# real running Hermes runtime, use scripts/verify_live_runtime.py instead.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/hexis"

if [ ! -d "$SRC" ]; then
  echo "Missing plugin source: $SRC" >&2
  exit 1
fi

TMP_ROOT="$(mktemp -d)"
cleanup() { rm -rf "$TMP_ROOT"; }
trap cleanup EXIT

export HERMES_HOME="$TMP_ROOT/hermes-home"
INSTALL_DIR="$HERMES_HOME/plugins/hexis"

mkdir -p "$HERMES_HOME/plugins"
cp -R "$SRC" "$INSTALL_DIR"
# Vendor the shared core alongside the adapter (mirrors scripts/install.sh).
cp -R "$ROOT/guardcore" "$INSTALL_DIR/guardcore"
rm -rf "$INSTALL_DIR/__pycache__" "$INSTALL_DIR/guardcore/__pycache__"

for f in plugin.yaml __init__.py SKILL.md \
         guardcore/__init__.py guardcore/guards.py guardcore/stuck.py \
         guardcore/violations.py guardcore/hook.py; do
  test -f "$INSTALL_DIR/$f"
done

python3 -m py_compile \
  "$INSTALL_DIR/__init__.py" \
  "$INSTALL_DIR"/guardcore/*.py

PYTHONPATH="$HERMES_HOME/plugins${PYTHONPATH:+:$PYTHONPATH}" \
HERMES_HOME="$HERMES_HOME" \
python3 - <<'PY'
import json
import os
from pathlib import Path

import hexis


class FakeCtx:
    def __init__(self):
        self.hooks = []
        self.skills = []

    def register_hook(self, name, func):
        self.hooks.append((name, func))

    def register_skill(self, name, path, description):
        self.skills.append((name, path, description))


ctx = FakeCtx()
hexis.register(ctx)

hook_names = {name for name, _func in ctx.hooks}
expected_hooks = {
    "pre_tool_call",
    "post_tool_call",
    "transform_tool_result",
    "on_session_end",
}
assert hook_names == expected_hooks, hook_names
assert ctx.skills and ctx.skills[0][0] == "enforce", ctx.skills

blocked = hexis._pre_tool_call(
    tool_name="terminal",
    args={"command": "cat .env", "workdir": os.getcwd()},
    session_id="smoke",
)
assert blocked and blocked.get("action") == "block", blocked

allowed = hexis._pre_tool_call(
    tool_name="terminal",
    args={"command": "ls -la", "workdir": os.getcwd()},
    session_id="smoke",
)
assert allowed is None, allowed

warn_only = hexis._pre_tool_call(
    tool_name="terminal",
    args={"command": "rm -rf /tmp/hexis-smoke", "workdir": os.getcwd()},
    session_id="smoke",
)
assert warn_only is None, warn_only

state_file = (
    Path(os.environ["HERMES_HOME"])
    / "plugins"
    / "hexis"
    / "state"
    / "rule-violation-log.jsonl"
)
assert state_file.exists(), state_file
records = [
    json.loads(line)
    for line in state_file.read_text(encoding="utf-8").splitlines()
    if line.strip()
]
assert any(row.get("rule") == "credential_read" for row in records), records
assert any(row.get("rule") == "rm_rf" for row in records), records
print("hook/skill registration + block/warn behavior OK")
PY

rm -rf "$INSTALL_DIR"
if [ -e "$INSTALL_DIR" ]; then
  echo "Uninstall failed: $INSTALL_DIR still exists" >&2
  exit 1
fi

echo "smoke test passed (hermetic; real ~/.hermes untouched)"
