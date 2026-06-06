"""Command guards - a Python port of Hexis' bash-guard.js, wired to Hermes'
``pre_tool_call`` hook.

These are HEURISTIC, token/regex-based, defense-in-depth checks over the literal
``terminal`` command string — NOT a security boundary. They catch the common
shapes of risky commands and can be bypassed (unusual readers, shell
obfuscation, quoting). Hermes core (tools/approval.py, tools/credential_files.py)
is the real gate; a ``block`` here refuses the obvious case, it does not guarantee
the action is impossible.

Design notes / why this is a plugin, not a core patch:
  - Hermes already has its own dangerous-command approval + credential-file
    protection (tools/approval.py, tools/credential_files.py). This layer does
    not replace that. It adds Hexis-style escalation behavior on top: every
    match is logged to the violation log, and each guard can be independently
    set to `warn` (observe + log), `block` (hard gate), or `off` via config.

  - A guard returning ``{"action": "block", "message": ...}`` from
    ``pre_tool_call`` makes Hermes refuse the tool without executing it.
    Returning ``None`` lets the command proceed.

Per-guard mode comes from config ``plugins.entries.hexis.guards.<key>`` and is
one of: ``off`` | ``warn`` | ``block``. Defaults follow warn-first escalation:
high-severity guards (credential reads, force-push to main/master) default to
``block``; everything else defaults to ``warn``.
"""

from __future__ import annotations

import logging
import os
import re
import shlex
from pathlib import Path
from typing import Callable, Dict, List, Optional

from . import violations

logger = logging.getLogger(__name__)

DEFAULT_MODES: Dict[str, str] = {
    "rm_rf": "warn",
    "unscoped_search": "warn",
    "credential_read": "block",
    "force_push_main": "block",
    "pkg_manager_mismatch": "warn",
}


# Shells whose `-c "CMD"` argument is itself a command to inspect.
_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "ash", "ksh"})


def _segments(cmd: str, _depth: int = 0) -> List[List[str]]:
    """Split a command into per-segment shlex token lists.

    Splits on top-level ``;`` ``&&`` ``||`` ``|`` ``&`` (outside quotes), then
    ``shlex.split`` (POSIX, de-quoting) each segment with a ``.split()`` fallback
    on unbalanced quotes. The matchers share this so quoting/escaping is
    normalized once AND command boundaries are preserved (a token from one
    segment can't be attributed to a command in another). Tokens are NEVER passed
    to a shell — this is parse/inspect only.

    A ``bash -c "CMD"`` / ``sh -c "CMD"`` wrapper is expanded one extra level
    (depth-bounded) so its inner command is inspected too.
    """
    raw: List[str] = []
    buf: List[str] = []
    quote: Optional[str] = None
    i, n = 0, len(cmd)
    while i < n:
        c = cmd[i]
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
            i += 1
        elif c in ("'", '"'):
            quote = c
            buf.append(c)
            i += 1
        elif c in "&|" and i + 1 < n and cmd[i + 1] == c:  # && or ||
            raw.append("".join(buf)); buf = []; i += 2
        elif c in (";", "|", "&"):
            raw.append("".join(buf)); buf = []; i += 1
        else:
            buf.append(c)
            i += 1
    raw.append("".join(buf))

    out: List[List[str]] = []
    for seg in raw:
        seg = seg.strip()
        if not seg:
            continue
        try:
            tokens = shlex.split(seg, posix=True)
        except ValueError:
            tokens = seg.split()
        out.append(tokens)
        # Expand `bash -c "CMD"` / `sh -c "CMD"` one extra level so the inner
        # command is inspected (the reader/refspec is inside the -c argument).
        if _depth < 2 and tokens:
            ci = _effective_index(tokens)
            if ci < len(tokens) and tokens[ci].rsplit("/", 1)[-1].lower() in _SHELLS:
                rest = tokens[ci + 1:]
                for j, t in enumerate(rest):
                    if t == "-c" and j + 1 < len(rest):
                        out.extend(_segments(rest[j + 1], _depth + 1))
                        break
    return out


_SEARCH_CMDS = frozenset({"grep", "egrep", "fgrep", "rg", "ack", "find", "fd"})
# Home ROOT only — bare ~, $HOME, /Users/<name>, /home/<name> (optionally trailing
# slash). A scoped subdir like /Users/me/project/src must NOT match.
_HOME_ROOT_RE = re.compile(
    r"^(?:~|\$HOME|\$\{HOME\})/?$|^/Users/[^/]+/?$|^/home/[^/]+/?$"
)


def _match_rm_rf(cmd: str) -> Optional[str]:
    for tokens in _segments(cmd):
        idx = _effective_index(tokens)
        if idx >= len(tokens) or tokens[idx].rsplit("/", 1)[-1] != "rm":
            continue
        for t in tokens[idx + 1:]:
            if t == "--":  # end of options; remaining tokens are filenames
                break
            if t in ("--recursive", "--force"):
                return "destructive 'rm' with -r/-f flags"
            if t.startswith("-") and not t.startswith("--") and re.search(r"[rf]", t):
                return "destructive 'rm' with -r/-f flags"
    return None


def _match_unscoped_search(cmd: str) -> Optional[str]:
    for tokens in _segments(cmd):
        idx = _effective_index(tokens)
        if idx >= len(tokens):
            continue
        if tokens[idx].rsplit("/", 1)[-1].lower() not in _SEARCH_CMDS:
            continue
        for t in tokens[idx + 1:]:
            if t.startswith("-"):
                continue
            if _HOME_ROOT_RE.match(t):
                return "unscoped search/traversal over the home directory"
    return None


# Reader/exfil commands that open a file's contents (case-insensitive, matched as
# a shell token — NOT a substring). Heuristic and intentionally incomplete: this
# is defense-in-depth, not a boundary (see README). The bare `.` source-dot is
# matched as its own token.
_CRED_READERS = frozenset({
    "cat", "less", "more", "head", "tail", "bat", "nl", "xxd", "od", "strings",
    "grep", "egrep", "fgrep", "rg", "ack", "awk", "sed", "cp", "mv", "scp",
    "rsync", "dd", "tee", "gpg", "base64", "wc", "openssl", "source", ".",
    "python", "python2", "python3", "perl", "ruby", "node",
})
_CRED_FILE_RE = re.compile(
    r"(\.env|\.envrc|\.secrets?|\.credentials?|\.pem|\.key|\.netrc|\.pgpass|"
    r"\.npmrc|\.pypirc|\.git-credentials|\.p12|\.pfx|\.tfvars(\.json)?|"
    r"id_rsa|id_ed25519|\.aws/credentials|\.ssh/|kube/config|docker/config\.json)",
    re.IGNORECASE,
)
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Command wrappers to skip when finding the effective command in a segment, so
# `sudo cat ~/.env` / `xargs rm -rf` / `env FOO=bar cat .env` are still inspected.
_CMD_WRAPPERS = frozenset({
    "sudo", "doas", "command", "builtin", "exec", "env", "time", "nice",
    "nohup", "xargs", "stdbuf", "setsid",
})


def _effective_index(tokens: List[str]) -> int:
    """Index of the effective command token (skipping env assignments + wrappers)."""
    idx = 0
    while idx < len(tokens):
        t = tokens[idx]
        if _ENV_ASSIGN_RE.match(t):
            idx += 1
            continue
        if t.rsplit("/", 1)[-1].lower() in _CMD_WRAPPERS:
            idx += 1
            continue
        break
    return idx


def _match_credential_read(cmd: str) -> Optional[str]:
    for tokens in _segments(cmd):
        if not tokens:
            continue
        idx = _effective_index(tokens)
        if idx >= len(tokens):
            continue
        reader = tokens[idx].lower()
        base = reader.rsplit("/", 1)[-1]  # /bin/cat -> cat
        if base not in _CRED_READERS and reader not in _CRED_READERS:
            continue
        if any(_CRED_FILE_RE.search(t) for t in tokens[idx + 1:]):
            return "reading a credential / secret file"
    return None


_FORCE_FLAGS = frozenset({"--force", "-f", "--force-with-lease"})


def _ref_hits_main(ref: str) -> bool:
    """True if a refspec token resolves to main/master on either side."""
    ref = ref.lstrip("+")
    for part in (ref.split(":") if ":" in ref else [ref]):
        leaf = part.rstrip("/").split("/")[-1]  # refs/heads/main, origin/main -> main
        if leaf in ("main", "master"):
            return True
    return False


def _match_force_push_main(cmd: str) -> Optional[str]:
    for tokens in _segments(cmd):
        # 'git ... push' tolerating global options (git -c k=v push, git -C dir push)
        if not tokens or tokens[0] != "git" or "push" not in tokens:
            continue
        after = tokens[tokens.index("push") + 1:]
        flags = [t for t in after if t.startswith("-")]
        positionals = [t for t in after if not t.startswith("-")]
        forced = any(
            f in _FORCE_FLAGS or f.startswith("--force-with-lease") for f in flags
        ) or any(p.startswith("+") for p in positionals)
        if not forced:
            continue
        # positionals are [remote, refspec...]; the remote is positionals[0].
        refspecs = positionals[1:] if positionals else []
        if any(_ref_hits_main(r) for r in refspecs):
            return "force-push targeting main/master"
        if not refspecs:
            # remote-only / no-branch force-push pushes the CURRENT branch,
            # which may be main/master.
            return "force-push with no explicit branch (may hit current branch main/master)"
    return None


_NPM_MUTATION_RE = re.compile(
    r"\bnpm\s+(install|i|add|ci|remove|rm|uninstall|un|unlink)\b"
)
_LOCKFILES = ("pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock")


_PKG_CD_MAX = 16      # cap cd-candidates examined (bounds the stat() walk)
_PKG_SCAN_MAX = 4000  # cap command length scanned for cd-clauses


def _candidate_dirs_from_command(cmd: str, cwd: Optional[str]) -> List[Path]:
    dirs: List[Path] = []
    base = Path(cwd or os.getcwd()).expanduser()
    dirs.append(base)

    # Common form: cd package && npm install. Respect it so Hermes' process cwd
    # does not have to be the project root for the guard to work. Bounded so a
    # crafted `cd x && npm`xN command can't burn seconds of stat() in the hook.
    for match in re.finditer(
        r"(?:^|[;&|]\s*)cd\s+(.+?)\s*(?:&&|;)\s*npm\s+", cmd[:_PKG_SCAN_MAX]
    ):
        if len(dirs) >= _PKG_CD_MAX:
            break
        raw_target = match.group(1).strip()
        try:
            parts = shlex.split(raw_target)
        except Exception:
            parts = raw_target.split()
        if not parts:
            continue
        target = Path(parts[0]).expanduser()
        if not target.is_absolute():
            target = base / target
        dirs.append(target)

    return dirs


def _find_lockfile(start: Path) -> Optional[str]:
    try:
        current = start.resolve()
    except Exception:
        current = start
    for depth, candidate in enumerate((current, *current.parents)):
        if depth > 8:
            break
        for lock in _LOCKFILES:
            if (candidate / lock).exists():
                return lock
    return None


def _match_pkg_manager_mismatch(cmd: str, cwd: Optional[str] = None) -> Optional[str]:
    if not _NPM_MUTATION_RE.search(cmd):
        return None
    for candidate in _candidate_dirs_from_command(cmd, cwd):
        lock = _find_lockfile(candidate)
        if lock:
            return f"npm used but {lock} present (package-manager mismatch)"
    return None


_MATCHERS: Dict[str, Callable[[str], Optional[str]]] = {
    "rm_rf": _match_rm_rf,
    "unscoped_search": _match_unscoped_search,
    "credential_read": _match_credential_read,
    "force_push_main": _match_force_push_main,
}


def _mode_for(key: str, guards_cfg: Dict) -> str:
    default = DEFAULT_MODES.get(key, "warn")
    mode = guards_cfg.get(key, default) if isinstance(guards_cfg, dict) else default
    if mode not in ("off", "warn", "block"):
        # Fail SAFE to the guard's OWN default, not the global 'warn' — a config
        # typo must not silently demote a block-default guard (credential_read,
        # force_push_main) to warn.
        logger.warning(
            "hexis: invalid guard mode %r for %s; using %r", mode, key, default
        )
        mode = default
    return mode


def evaluate(
    command: str,
    guards_cfg: Dict,
    session_id: str = "",
    cwd: Optional[str] = None,
) -> Optional[Dict]:
    """Run all enabled guards against *command*.

    The block decision is a PURE FUNCTION of (command, mode): it is computed from
    the matcher's reason BEFORE any state I/O, and all violation logging is
    wrapped so a logging/disk failure can never turn a block into an allow. This
    is the fail-safe-defaults guarantee — a guard that matches a block-mode rule
    blocks regardless of whether the violation log can be written.
    """
    if not command:
        return None
    if not isinstance(guards_cfg, dict):
        guards_cfg = {}

    block_directive: Optional[Dict] = None
    checks: List[tuple[str, Callable[[], Optional[str]]]] = [
        *((key, lambda matcher=matcher: matcher(command)) for key, matcher in _MATCHERS.items()),
        ("pkg_manager_mismatch", lambda: _match_pkg_manager_mismatch(command, cwd=cwd)),
    ]

    for key, matcher in checks:
        mode = _mode_for(key, guards_cfg)
        if mode == "off":
            continue
        reason = None
        try:
            reason = matcher()
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("hexis: guard %s raised: %s", key, exc)
        if not reason:
            continue

        # Redact secrets from the command before it reaches the model-facing
        # block message OR the durable violation log (a guarded command can
        # carry an inline secret, e.g. `grep AKIA... ~/.env`).
        safe_cmd = violations.redact(command[:200])

        # 1. Decide FIRST — never depends on any fallible side-effect below.
        if mode == "block" and block_directive is None:
            block_directive = {
                "action": "block",
                "message": (
                    f"[hexis:{key}] Blocked: {reason}. "
                    f"Command: {safe_cmd}. "
                    f"Set guard '{key}' to 'warn' or 'off' in your hexis "
                    "guardrails config to change this."
                ),
            }

        # 2. Log second — wrapped so count_for_rule/record can never abort the
        #    loop (e.g. read-only home, ENOSPC) or change the return value.
        try:
            prior = violations.count_for_rule(key)
            violations.record(
                rule=key,
                what_happened=f"{reason}: {safe_cmd}",
                root_cause="",
                fix_applied="blocked" if mode == "block" else "allowed (warn mode)",
                severity=mode,
                source="guard",
                session_id=session_id,
            )
            if mode == "warn":
                logger.warning(
                    "hexis guard '%s' (warn): %s [prior violations: %d]",
                    key, reason, prior,
                )
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("hexis: violation logging failed for %s: %s", key, exc)

    return block_directive
