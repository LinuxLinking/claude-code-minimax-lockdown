#!/usr/bin/env python3
"""Summarize MiniMax lockdown activity from lockdown.log.

Writes a readable report to lockdown-report.txt (UTF-8) and prints its path.

Usage:  python analyze-lockdown-log.py
"""
import json
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(HERE, "lockdown.log")
OUT = os.path.join(HERE, "lockdown-report.txt")

# decision label -> (label text, order)
LABELS = {
    "mechanical-deny": "机械层·硬拦 (deny)",
    "mechanical-ask": "机械层·弹窗 (ask)",
    "ask": "审计层·弹窗 (ask)",
    "deny": "审计层·静默拒 (deny)",
    "memo-allow": "会话记忆·放行",
    "memo-deny": "会话记忆·拒绝",
    "memo-approved": "会话记忆·记录批准",
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
    L.append("MiniMax 锁定活动报告")
    L.append(f"日志: {LOG}")
    L.append("=" * 60)

    if not rows:
        L.append("\n(日志为空——还没有任何锁定事件被记录。)")
        _write(L)
        return

    # overview
    sessions = {r.get("session") for r in rows}
    models = {r.get("model") for r in rows}
    ts_sorted = sorted(r.get("ts", "") for r in rows)
    L.append("\n【总览】")
    L.append(f"  事件总数   : {len(rows)}")
    L.append(f"  时间范围   : {ts_sorted[0]}  ~  {ts_sorted[-1]}")
    L.append(f"  涉及会话   : {len(sessions)}")
    L.append(f"  模型       : {', '.join(sorted(m for m in models if m))}")

    # by decision type
    L.append("\n【按决策类型】")
    dc = Counter((r.get("decision") or "(无决策)") for r in rows)
    for dec, n in dc.most_common():
        label = LABELS.get(dec, str(dec))
        L.append(f"  {label:22s} {n:4d}  {bar(n)}")

    # by day
    L.append("\n【按天分布】（看降频效果——越低越安静）")
    perday = Counter((r.get("ts", "")[:10]) for r in rows)
    mx = max(perday.values()) if perday else 1
    for day in sorted(perday):
        n = perday[day]
        L.append(f"  {day}  {n:4d}  {'█' * max(1, int(n / mx * 40))}")

    # top trigger reasons
    L.append("\n【Top 触发原因】（哪类操作最常被拦/被问）")
    rc = Counter(short_reason(r.get("reason")) for r in rows
                 if r.get("decision") not in ("memo-allow",))
    for reason, n in rc.most_common(10):
        L.append(f"  {n:4d}  {reason}")

    # potential "always yes" -- repeatedly approved ops
    L.append("\n【潜在『总是点 Yes』】")
    L.append("  以下操作被反复批准（会话记忆命中）——考虑自动化，或警惕被绕过：")
    yes = Counter(r.get("reason") for r in rows if r.get("decision") == "memo-approved")
    if yes:
        for reason, n in yes.most_common(10):
            L.append(f"  {n:4d}  {short_reason(reason)}")
    else:
        L.append("  (暂无——还没有反复批准的操作)")

    # auditor vs mechanical layer
    mech = sum(n for d, n in dc.items() if d.startswith("mechanical"))
    audit = dc.get("ask", 0) + dc.get("deny", 0)
    L.append("\n【分层占比】")
    L.append(f"  机械层（快、确定） : {mech}")
    L.append(f"  审计层（LLM 判）   : {audit}")
    L.append(f"  弹窗（打扰你）     : {dc.get('ask', 0) + dc.get('mechanical-ask', 0)}")
    L.append(f"  静默拒绝（不打扰） : {dc.get('deny', 0) + dc.get('mechanical-deny', 0)}")

    L.append("\n" + "=" * 60)
    _write(L)


def _write(lines):
    text = "\n".join(lines) + "\n"
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    print("report ->", OUT)


if __name__ == "__main__":
    main()
