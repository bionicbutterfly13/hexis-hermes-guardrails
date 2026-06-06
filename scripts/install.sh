#!/usr/bin/env bash
# Install the Hexis guardrails plugin into the active Hermes profile.
#
# Copies the plugin code FROM this repo (the source of truth) into
# ~/.hermes/plugins/hexis/. Existing runtime state/ is preserved.
#
# Honors HERMES_HOME (defaults to ~/.hermes).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/hexis"
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
DEST="$HERMES_HOME/plugins/hexis"

if [ ! -d "$SRC" ]; then
  echo "Plugin source not found: $SRC" >&2
  exit 1
fi

mkdir -p "$DEST"
# Copy the Hermes adapter files — never touch DEST/state/ (runtime violation logs).
for f in __init__.py plugin.yaml README.md SKILL.md; do
  cp "$SRC/$f" "$DEST/$f"
done
# Vendor the shared core alongside the adapter so the directory plugin is
# self-contained (the adapter adds its own dir to sys.path to import guardcore).
rm -rf "$DEST/guardcore"
cp -R "$ROOT/guardcore" "$DEST/guardcore"
rm -rf "$DEST/guardcore/__pycache__"
# Remove legacy core files left by older installs (now provided by guardcore/).
rm -f "$DEST/guards.py" "$DEST/stuck.py" "$DEST/violations.py"

echo "Installed hexis plugin -> $DEST"
echo "(runtime state/ preserved if it already existed)"
cat <<'YAML'

Next: enable it in ~/.hermes/config.yaml

plugins:
  enabled:
    - hexis
  entries:
    hexis:
      guards:
        rm_rf: warn
        unscoped_search: warn
        credential_read: block
        force_push_main: block
        pkg_manager_mismatch: warn
      stuck_loop:
        enabled: true
        surface_to_model: false
YAML
