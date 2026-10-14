#!/usr/bin/env python3
"""Summarize MiniMax lockdown activity from lockdown.log.

Writes a readable report to lockdown-report.txt (UTF-8) and prints its path.

Usage:  python analyze-lockdown-log.py

A Chinese-localized copy lives in ./chn/.
"""
import json
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(HERE, "lockdown.log")
OUT = os.path.join(HERE, "lockdown-report.txt")

# decision label -> (display text, order)
LABELS = {
    "mechanical-deny": "mechanical·hard-deny",
    "mechanical-ask": "mechanical·ask",
    "ask": "auditor·ask",
    "deny": "auditor·silent-deny",
    "memo-allow": "memo·allow",
    "memo-deny": "memo·deny",
    "memo-approved": "memo·record-approval",
}


def bar(n, width=40):
    return "█" * max(1, min(n, width)) if n else ""


def load():
    rows = []
    if not os.path.isfile(LOG):
        return rows
    with open(LOG, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows


def short_reason(r):
    r = re.sub(r"\s+", " ", (r or "").strip())
    return r[:60]


def main():
    rows = load()
    L = []
    L.append("=" * 60)
    L.append("MiniMax lockdown activity report")
    L.append(f"log: {LOG}")
    L.append("=" * 60)

    if not rows:
        L.append("\n(log empty -- no lockdown events recorded yet.)")
        _write(L)
        return

    # overview
    sessions = {r.get("session") for r in rows}
    models = {r.get("model") for r in rows}
    ts_sorted = sorted(r.get("ts", "") for r in rows)
    L.append("\n[overview]")
    L.append(f"  total events : {len(rows)}")
    L.append(f"  time range   : {ts_sorted[0]}  ~  {ts_sorted[-1]}")
    L.append(f"  sessions     : {len(sessions)}")
    L.append(f"  models       : {', '.join(sorted(m for m in models if m))}")

    # by decision type
    L.append("\n[by decision type]")
    dc = Counter((r.get("decision") or "(no decision)") for r in rows)
    for dec, n in dc.most_common():
        label = LABELS.get(dec, str(dec))
        L.append(f"  {label:22s} {n:4d}  {bar(n)}")

    # by day
    L.append("\n[by day] (lower = quieter -- see the fatigue-reduction effect)")
    perday = Counter((r.get("ts", "")[:10]) for r in rows)
    mx = max(perday.values()) if perday else 1
    for day in sorted(perday):
        n = perday[day]
        L.append(f"  {day}  {n:4d}  {'█' * max(1, int(n / mx * 40))}")

    # top trigger reasons
    L.append("\n[top trigger reasons] (which ops get blocked/asked most)")
    rc = Counter(short_reason(r.get("reason")) for r in rows
                 if r.get("decision") not in ("memo-allow",))
    for reason, n in rc.most_common(10):
        L.append(f"  {n:4d}  {reason}")

    # potential "always yes" -- repeatedly approved ops
    L.append("\n[potential 'always yes']")
    L.append("  Ops approved again and again (session-memo hits) -- consider")
    L.append("  automating, or watch for bypass:")
    yes = Counter(r.get("reason") for r in rows if r.get("decision") == "memo-approved")
    if yes:
        for reason, n in yes.most_common(10):
            L.append(f"  {n:4d}  {short_reason(reason)}")
    else:
        L.append("  (none yet -- no repeatedly approved ops)")

    # auditor vs mechanical layer
    mech = sum(n for d, n in dc.items() if d.startswith("mechanical"))
    audit = dc.get("ask", 0) + dc.get("deny", 0)
    L.append("\n[layer split]")
    L.append(f"  mechanical (fast, deterministic) : {mech}")
    L.append(f"  auditor (LLM judged)             : {audit}")
    L.append(f"  popups (bothering you)           : {dc.get('ask', 0) + dc.get('mechanical-ask', 0)}")
    L.append(f"  silent denies (no bother)        : {dc.get('deny', 0) + dc.get('mechanical-deny', 0)}")

    L.append("\n" + "=" * 60)
    _write(L)


def _write(lines):
    text = "\n".join(lines) + "\n"
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    print("report ->", OUT)


if __name__ == "__main__":
    main()
