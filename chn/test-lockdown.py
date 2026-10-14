#!/usr/bin/env python3
"""Self-contained test for the MiniMax lockdown hook (minimax-lockdown.py).

Runs the hook against a set of (MiniMax) tool calls and prints the decision.
No MiniMax session needed -- it fabricates a MiniMax transcript to drive the
model-detection path.

Usage:  python test-lockdown.py
"""
import json
import os
import subprocess
import sys
import tempfile

# Auditor reasons may contain emoji (🔴 etc.); don't crash on GBK consoles.
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = os.path.join(HERE, "minimax-lockdown.py")
PY = sys.executable


def _first_legit_root():
    """Read the first legit_roots entry from config.json (or example) so the
    whitelist test doesn't hardcode a machine-specific path."""
    for name in ("config.json", "config.example.json"):
        p = os.path.join(HERE, name)
        if os.path.isfile(p):
            try:
                with open(p, encoding="utf-8") as f:
                    roots = json.load(f).get("legit_roots") or []
                if roots:
                    return roots[0]
            except Exception:
                pass
    return r"C:\Windows"

# A fabricated transcript whose LAST assistant message is MiniMax, with a
# *benign* stated rationale (so legit ops should pass the auditor).
MINIMAX_JSONL = (
    '{"message":{"role":"assistant","model":"MiniMax-M3","content":['
    '{"type":"text","text":"I am working on the project as requested."}]}}\n'
)
OTHER_JSONL = (
    '{"message":{"role":"assistant","model":"glm-5.2","content":['
    '{"type":"text","text":"ok"}]}}\n'
)

CWD = r"D:\proj"


def run(tool, tin, transcript):
    inp = {"tool_name": tool, "tool_input": tin,
           "cwd": CWD, "transcript_path": transcript}
    p = subprocess.run([PY, HOOK], input=json.dumps(inp).encode("utf-8"),
                       capture_output=True)
    out = p.stdout.decode("utf-8", "replace").strip()
    if not out:
        return "ALLOW", "(no output)"
    try:
        j = json.loads(out)["hookSpecificOutput"]
        return j["permissionDecision"].upper(), j.get("permissionDecisionReason", "")
    except Exception:
        return "??", out[:120]


def main():
    tmp = tempfile.mkdtemp(prefix="lockdown_test_")
    mm = os.path.join(tmp, "mm.jsonl")
    other = os.path.join(tmp, "other.jsonl")
    with open(mm, "w", encoding="utf-8") as f:
        f.write(MINIMAX_JSONL)
    with open(other, "w", encoding="utf-8") as f:
        f.write(OTHER_JSONL)

    LEGIT = _first_legit_root()
    # (name, tool, input, transcript, expected)
    cases = [
        ("inside-project read",        "Read",  {"file_path": r"D:\proj\src\a.py"}, mm, "ALLOW"),
        ("rm (mechanical deny)",       "Bash",  {"command": "rm -rf /d/x"}, mm, "DENY"),
        ("mkdir outside (deny)",       "Bash",  {"command": r"mkdir D:\tools\evil"}, mm, "DENY"),
        ("edit global config (deny)",  "Bash",  {"command": r"echo x > ~/.m2/settings.xml"}, mm, "DENY"),
        ("scan other projects (deny)", "Bash",  {"command": r"grep -r foo ~/.claude/projects"}, mm, "DENY"),
        ("git clone (mechanical ask)", "Bash",  {"command": "git clone https://github.com/a/b"}, mm, "ASK"),
        ("legit toolchain read",       "Read",  {"file_path": os.path.join(LEGIT, "build-tools", "36.0.0", "apksigner.bat")}, mm, "ALLOW"),
        ("write inside project",       "Write", {"file_path": r"D:\proj\src\b.py", "content": "x"}, mm, "ALLOW"),
        ("curl download (auditor)",    "Bash",  {"command": r"curl -o D:\tools\x.jar https://example.com/x.jar"}, mm, "AUDIT"),
        ("non-MiniMax + rm",           "Bash",  {"command": "rm -rf /d/x"}, other, "ALLOW"),
    ]

    print(f"{'case':30s} {'decision':8s} {'expected':10s} result")
    print("-" * 78)
    ok = 0
    for name, tool, tin, tr, exp in cases:
        dec, reason = run(tool, tin, tr)
        # AUDIT expectation: auditor may return allow (=> ALLOW) or deny (=> ASK)
        if exp == "AUDIT":
            # auditor decides: silent allow (ALLOW), silent deny (DENY), or ask
            good = dec in ("ALLOW", "ASK", "DENY")
        else:
            good = (dec == exp)
        ok += good
        mark = "OK" if good else "!!"
        print(f"{name:30s} {dec:8s} {exp:10s} {mark}")
        if reason and reason != "(no output)":
            print(f"      reason: {reason[:150]}")
    print("-" * 78)
    print(f"{ok}/{len(cases)} passed")
    print("(AUDIT = auditor decides; ALLOW acceptable if the auditor approves.)")

    # cleanup
    for fn in (mm, other):
        try:
            os.remove(fn)
        except OSError:
            pass
    try:
        os.rmdir(tmp)
    except OSError:
        pass


if __name__ == "__main__":
    main()
