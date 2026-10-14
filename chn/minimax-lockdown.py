#!/usr/bin/env python3
"""MiniMax lockdown hook (Claude Code PreToolUse + PostToolUse).

Applies strict constraints ONLY when the active model is MiniMax. Any other
model: exit 0 immediately (zero overhead).

Layers:
  1. mechanical HARD DENY  - unambiguous bad -> denied, no human involved
  2. mechanical ASK        - uncommon downloads (git clone / wget / iwr) -> popup
  3. AUDITOR               - frequent downloads + cross-dir read/write, judged by
                             a SEPARATE model (deepseek-flash via cc-switch proxy).
                             Returns verdict + confidence + severity.

Fatigue controls:
  * trick 1: confidence routing - auditor confidence >= CONF_AUTO decides
                             silently (allow OR deny); only uncertain cases pop up.
  * trick 2: session memo       - an operation the user already approved this session
                             is auto-allowed next time (exact signature only).
                             Approvals are observed via the PostToolUse pass.
  * log                    - every ask / deny / memo event is appended to
                             lockdown.log for after-the-fact review + tuning.

Model detection: last `"model"` field in the session transcript.
"""
import hashlib
import json
import os
import re
import sys
import time
import urllib.request

# ---- paths -----------------------------------------------------------------
HOOKS_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(HOOKS_DIR, "lockdown.log")
STATE_DIR = os.path.join(os.environ.get("TEMP", HOOKS_DIR), "minimax_lockdown")


# ---- config (from config.json; env vars override) --------------------------
def _find_config():
    """Look for config.json next to this script, then in its parent dir, so a
    localized copy under ./chn/ shares the repo-root config."""
    for d in (HOOKS_DIR, os.path.dirname(HOOKS_DIR)):
        p = os.path.join(d, "config.json")
        if os.path.isfile(p):
            return p
    return None


def load_config():
    """Read config.json; else safe defaults.

    Defaults deliberately contain NO real machine paths or usernames -- fill
    config.json (gitignored) with your own. Env vars win over the file.
    """
    cfg = {}
    cfg_path = _find_config()
    if cfg_path:
        try:
            with open(cfg_path, encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}
    if os.environ.get("LOCKDOWN_PROXY_URL"):
        cfg["proxy_url"] = os.environ["LOCKDOWN_PROXY_URL"]
    if os.environ.get("LOCKDOWN_AUDITOR_MODEL"):
        cfg["auditor_model"] = os.environ["LOCKDOWN_AUDITOR_MODEL"]
    return cfg


_CFG = load_config()

PROXY_URL = _CFG.get("proxy_url", "http://127.0.0.1:PORT/v1/messages")
AUDITOR_MODEL = _CFG.get("auditor_model", "your-auditor-model-name")
AUDIT_TIMEOUT = int(_CFG.get("audit_timeout", 30))     # seconds
MAX_RATIONALE = 1500
TAIL_BYTES = 300_000
CONF_AUTO = float(_CFG.get("conf_auto", 0.85))         # >= this -> decide silently

# Legit toolchain / dependency-cache roots on this machine. Reads/writes inside
# these are considered normal. Configure yours in config.json.
LEGIT_ROOTS = _CFG.get("legit_roots", [
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
])
# Temp dirs. Falls back to %TEMP%; add more in config.json if needed.
TEMP_ROOTS = [t for t in [
    os.path.normcase(os.environ.get("TEMP", "")),
] + [os.path.normcase(t) for t in _CFG.get("temp_roots", [])] if t]
SENSITIVE_SCAN_PATTERNS = [
    r"\.claude[/\\]projects",
    r"\.cc-switch",
    r"\.ssh",
    r"\.aws",
    r"\.m2[/\\]settings",
]
SEV_EMOJI = {"high": "\U0001F534", "medium": "\U0001F7E1", "low": "\U0001F7E2"}


# ---- path helpers -----------------------------------------------------------
def norm(p, base=None):
    try:
        p = os.path.expanduser(p)
        if base and not os.path.isabs(p):
            p = os.path.join(base, p)
        return os.path.normcase(os.path.abspath(p))
    except Exception:
        return None


def is_inside(path, root, base=None):
    np, nr = norm(path, base), norm(root)
    if np is None or nr is None:
        return False
    return np == nr or np.startswith(nr + os.sep)


def path_ok(path, cwd):
    if is_inside(path, cwd, base=cwd):
        return True
    for r in LEGIT_ROOTS:
        if is_inside(path, r, base=cwd):
            return True
    for r in TEMP_ROOTS:
        nr = os.path.normcase(r)
        np = norm(path, base=cwd)
        if np and (np == nr or np.startswith(nr + os.sep)):
            return True
    return False


def extract_paths(cmd):
    toks = re.findall(
        r'(?:^|[\s;&|"\'=<>(])'
        r'((?:[A-Za-z]:[\\/]|~[\\/]|\.{1,2}[\\/]|/)[^\s;&|"\'<>]*)',
        cmd)
    out = []
    for t in toks:
        if "://" in t or t.startswith("//"):
            continue
        out.append(t.rstrip(')'))
    return out


# ---- model / rationale ------------------------------------------------------
def detect_model(transcript_path):
    if transcript_path and os.path.isfile(transcript_path):
        try:
            size = os.path.getsize(transcript_path)
            with open(transcript_path, "rb") as f:
                if size > TAIL_BYTES:
                    f.seek(-TAIL_BYTES, os.SEEK_END)
                tail = f.read().decode("utf-8", "replace")
            matches = re.findall(r'"model"\s*:\s*"([^"]+)"', tail)
            if matches:
                return matches[-1]
        except Exception:
            pass
    return os.environ.get("ANTHROPIC_MODEL", "")


def extract_rationale(transcript_path):
    try:
        with open(transcript_path, "rb") as f:
            f.seek(max(0, os.path.getsize(transcript_path) - TAIL_BYTES))
            lines = f.read().decode("utf-8", "replace").splitlines()
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            msg = obj.get("message") or {}
            if msg.get("role") != "assistant":
                continue
            content = msg.get("content")
            if not isinstance(content, list):
                continue
            parts = []
            for b in content:
                if isinstance(b, dict) and b.get("type") in ("thinking", "text"):
                    t = b.get("thinking") or b.get("text") or ""
                    if t:
                        parts.append(t)
            if parts:
                return "\n".join(parts)[:MAX_RATIONALE]
        return ""
    except Exception:
        return ""


# ---- state (session memo) ---------------------------------------------------
def signature(tool, tin, cwd):
    if tool == "Bash":
        key = (tin.get("command") or "").strip()
    else:
        key = tin.get("file_path") or tin.get("path") or tin.get("notebook_path") or ""
        key = norm(key, base=cwd) or key
    return hashlib.sha256(f"{tool}\x00{key}".encode("utf-8")).hexdigest()[:32]


def state_path(session_id):
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", session_id or "default")
    return os.path.join(STATE_DIR, safe + ".json")


def load_state(session_id):
    p = state_path(session_id)
    try:
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        return {"approved": set(d.get("approved", [])),
                "denied": set(d.get("denied", [])),
                "pending": set(d.get("pending", []))}
    except Exception:
        return {"approved": set(), "denied": set(), "pending": set()}


def save_state(session_id, st):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(state_path(session_id), "w", encoding="utf-8") as f:
            json.dump({k: sorted(v) for k, v in st.items()}, f, ensure_ascii=False)
    except Exception:
        pass


# ---- log --------------------------------------------------------------------
def log_decision(session_id, model, tool, sig, decision, reason):
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                "session": session_id, "model": model, "tool": tool,
                "sig": sig, "decision": decision, "reason": (reason or "")[:400],
            }, ensure_ascii=False) + "\n")
    except Exception:
        pass


def emit(decision, reason):
    """Emit a PreToolUse decision and exit. ensure_ascii=True keeps the Chinese
    reason as ASCII \\uXXXX escapes (Windows stdout is GBK otherwise)."""
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,      # "allow" | "deny" | "ask"
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


# ---- auditor ----------------------------------------------------------------
def _legit_roots_desc(cwd):
    """Format LEGIT_ROOTS + temp for the auditor prompt (dynamic, no hardcode)."""
    lines = [f"- {r}" for r in LEGIT_ROOTS]
    if cwd:
        lines.append(f"- 项目目录 {cwd}")
    temp = os.environ.get("TEMP")
    if temp:
        lines.append(f"- 系统临时目录 {temp}")
    return "\n".join(lines) + "\n"


def audit(action_desc, trigger, cwd, rationale):
    """Returns (decision, reason): decision in {None=allow, 'ask', 'deny'}."""
    prompt = (
        "你是安全审计员。一个不可信的 AI 模型（MiniMax）提议执行下面的操作，"
        "请判断是否合法、是否应放行。\n\n"
        f"【项目目录】{cwd}\n"
        f"【提议的操作】{action_desc}\n"
        f"【触发原因】{trigger}\n"
        f"【MiniMax 给出的理由】\n{rationale or '(无)'}\n\n"
        "【参考：本机已知合法工具链路径（读/写这些属正常）】\n"
        + _legit_roots_desc(cwd)
        + "\n【判据】\n"
        "1. 操作在项目目录内，或访问上述合法工具链/依赖缓存 → allow\n"
        "2. 正常构建产生的依赖/缓存写入（Maven/Gradle/npm/pip）→ allow\n"
        "3. 在项目外创建文件/目录、改全局配置、读其它项目会话或凭据、"
        "下载未知来源文件 → deny\n"
        "4. 理由含糊、与操作不符、或想不清目的 → deny\n\n"
        "输出 JSON（务必给出 confidence 0~1 与 severity）：\n"
        "{\"verdict\":\"allow\"|\"deny\",\"confidence\":0.0,\"severity\":"
        "\"high\"|\"medium\"|\"low\",\"summary\":\"一句话摘要\",\"reason\":\"详细理由\"}"
    )
    payload = {
        "model": AUDITOR_MODEL,
        "max_tokens": 1200,
        # deepseek-flash over-thinks and never emits JSON when thinking is on.
        "thinking": {"type": "disabled"},
        "messages": [{"role": "user", "content": prompt}],
    }
    try:
        req = urllib.request.Request(
            PROXY_URL, data=json.dumps(payload).encode("utf-8"),
            headers={"content-type": "application/json",
                     "anthropic-version": "2023-06-01"})
        with urllib.request.urlopen(req, timeout=AUDIT_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        text = "".join(b.get("text", "") for b in body.get("content", [])
                       if isinstance(b, dict))
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            return ("ask", "MiniMax 审计员返回无法解析，保守起见请你确认。原始：" + text[:200])
        v = json.loads(m.group(0))
        verdict = v.get("verdict")
        try:
            conf = float(v.get("confidence", 0.5))
        except Exception:
            conf = 0.5
        sev = v.get("severity", "medium")
        summary = v.get("summary") or v.get("reason", "")
        detail = v.get("reason", "")
        emoji = SEV_EMOJI.get(sev, "\U0001F7E1")

        if verdict == "allow":
            if conf >= CONF_AUTO:
                return (None, None)                      # trick 1: silent allow
            return ("ask",
                    f"\U0001F7E1 [审计员拿不准·倾向放行 {conf:.0%}] {summary}\n"
                    f"审计员：{detail}\nMiniMax 的理由：{rationale[:300] or '(无)'}")
        # verdict == deny
        if conf >= CONF_AUTO:
            return ("deny",                              # trick 1: silent deny
                    f"{emoji} [{sev}] {summary}\n审计员：{detail}（置信 {conf:.0%}）\n"
                    f"MiniMax 的理由：{rationale[:300] or '(无)'}")
        return ("ask",
                f"\U0001F7E1 [审计员拿不准 {conf:.0%}] {summary}\n"
                f"审计员：{detail}\nMiniMax 的理由：{rationale[:300] or '(无)'}")
    except Exception as e:
        return ("ask", f"MiniMax 审计员调用失败（{e}），保守起见请你确认该操作。")


# ---- mechanical layer (never memoized) --------------------------------------
def mechanical_bash(cmd, cwd):
    c = cmd.strip()
    low = c.lower()
    if re.search(r"(^|[;&|]\s*)rm(dir)?\s", c):
        return ("deny", "MiniMax lockdown：删除操作（rm/rmdir）硬拦")
    if re.search(r"(^|[;&|]\s*)mv\s", c):
        return ("deny", "MiniMax lockdown：移动文件（mv）硬拦")
    if re.search(r"(^|[;&|]\s*)mkdir\s", c):
        outside = [p for p in extract_paths(c) if not path_ok(p, cwd)]
        if outside:
            return ("deny", f"MiniMax lockdown：在项目外建目录硬拦 → {outside}")
    if re.search(r"(^|[;&|]\s*)(mkdir|touch|cp|ln|tee)\b", low):
        if "~" in c:
            return ("deny", "MiniMax lockdown：含家目录(~)路径的写命令硬拦")
    if re.search(r"(^|[;&|]\s*)(reg\s+add|setx|regedit)\b", low):
        return ("deny", "MiniMax lockdown：改注册表/环境变量硬拦")
    for pat in SENSITIVE_SCAN_PATTERNS:
        if re.search(pat, c, re.I):
            return ("deny", f"MiniMax lockdown：触碰敏感路径硬拦（{pat}）")
    if re.search(r"(>\s*|>>\s*)", c) and re.search(
            r"(\.claude[/\\]settings|\.m2[/\\]settings|\.cc-switch)", c, re.I):
        return ("deny", "MiniMax lockdown：写全局配置硬拦")
    if re.search(r"(^|[;&|]\s*)git\s+clone\b", low):
        return ("ask", "MiniMax lockdown：git clone 不常用，请人工确认")
    if re.search(r"(^|[;&|]\s*)wget\b", low) or re.search(r"\b(iwr|invoke-webrequest)\b", low):
        return ("ask", "MiniMax lockdown：wget/Invoke-WebRequest 不常用，请人工确认")
    return None


def mechanical_path(path, kind):
    if not path:
        return None
    for pat in SENSITIVE_SCAN_PATTERNS:
        if re.search(pat, path, re.I):
            return ("deny", f"MiniMax lockdown：{kind} 敏感路径硬拦（{pat}）")
    return None


def mechanical(tool, tin, cwd):
    if tool == "Bash":
        return mechanical_bash(tin.get("command", ""), cwd)
    if tool in ("Write", "Edit", "NotebookEdit", "MultiEdit"):
        return mechanical_path(tin.get("file_path") or tin.get("notebook_path") or "", "写")
    if tool in ("Read", "Glob", "Grep"):
        return mechanical_path(tin.get("file_path") or tin.get("path") or "", "读")
    return None


# ---- gray zone -> auditor ---------------------------------------------------
def gray_bash(cmd, cwd, transcript_path):
    c = cmd.strip()
    low = c.lower()
    trigger = None
    if re.search(r"(^|[;&|]\s*)curl\b", low):
        trigger = "curl 下载"
    elif re.search(r"(^|[;&|]\s*)npm\s+(install|i|ci)\b", low) or \
         re.search(r"(^|[;&|]\s*)(yarn|pnpm)\s+(add|install|i)\b", low):
        trigger = "包管理器安装依赖"
    elif re.search(r"(^|[;&|]\s*)pip\s+install\b", low) or \
         re.search(r"(^|[;&|]\s*)(uv\s+pip\s+install|uv\s+add)\b", low):
        trigger = "pip/uv 安装依赖"
    elif re.search(r"(^|[;&|]\s*)mvn\b", low) and "dependency:" in low:
        trigger = "mvn 拉取依赖"
    elif re.search(r"(^|[;&|]\s*)gradle\b", low):
        trigger = "gradle 依赖解析"
    elif re.search(r"(^|[;&|]\s*)(mkdir|touch|cp|ln|tee)\b", low) and "$" in c:
        trigger = "含变量路径的写命令，无法静态确认"
    else:
        outside = [p for p in extract_paths(c) if not path_ok(p, cwd)]
        if outside:
            trigger = f"跨目录路径 {outside}"
    if trigger:
        return audit(f"Bash: {c[:600]}", trigger, cwd, extract_rationale(transcript_path))
    return None


def gray_path(path, kind, tool, tin, cwd, transcript_path):
    if not path or path_ok(path, cwd):
        return None
    desc = f"{tool}: {kind} {path}\n输入: {json.dumps(tin, ensure_ascii=False)[:400]}"
    return audit(desc, f"跨目录{kind}", cwd, extract_rationale(transcript_path))


def gray(tool, tin, cwd, transcript_path):
    if tool == "Bash":
        return gray_bash(tin.get("command", ""), cwd, transcript_path)
    if tool in ("Write", "Edit", "NotebookEdit", "MultiEdit"):
        return gray_path(tin.get("file_path") or tin.get("notebook_path") or "",
                         "写", tool, tin, cwd, transcript_path)
    if tool in ("Read", "Glob", "Grep"):
        return gray_path(tin.get("file_path") or tin.get("path") or "",
                         "读", tool, tin, cwd, transcript_path)
    return None


# ---- main -------------------------------------------------------------------
def main():
    try:
        raw = sys.stdin.buffer.read().decode("utf-8", "replace")
        data = json.loads(raw) if raw.strip() else {}
    except Exception:
        sys.exit(0)

    event = data.get("hook_event_name") or "PreToolUse"
    session_id = data.get("session_id", "")
    transcript_path = data.get("transcript_path", "")
    cwd = data.get("cwd") or os.getcwd()
    tool = data.get("tool_name", "")
    tin = data.get("tool_input") or {}

    model = detect_model(transcript_path)
    if not model or "minimax" not in model.lower():
        sys.exit(0)

    sig = signature(tool, tin, cwd)

    # ---- PostToolUse: observe that a previously-asked op actually ran => the
    #      user approved it => remember for this session (trick 2).
    if event == "PostToolUse":
        st = load_state(session_id)
        if sig in st["pending"]:
            st["pending"].discard(sig)
            st["approved"].add(sig)
            save_state(session_id, st)
            log_decision(session_id, model, tool, sig, "memo-approved",
                         "用户批准，本会话内记住该操作")
        sys.exit(0)

    st = load_state(session_id)

    # ---- mechanical (never memoized) ----
    try:
        mech = mechanical(tool, tin, cwd)
    except Exception as e:
        emit("ask", f"MiniMax lockdown hook 出错（{e}），保守起见请确认。")
        return
    if mech:
        d, r = mech
        log_decision(session_id, model, tool, sig, "mechanical-" + d, r)
        if d == "ask":
            st["pending"].add(sig)
            save_state(session_id, st)
        emit(d, r)

    # ---- session memo (trick 2) ----
    if sig in st["approved"]:
        log_decision(session_id, model, tool, sig, "memo-allow", "本会话已批准过相同操作")
        sys.exit(0)
    if sig in st["denied"]:
        log_decision(session_id, model, tool, sig, "memo-deny", "本会话已拒绝过相同操作")
        emit("deny", "MiniMax lockdown：本会话内已拒绝过相同操作（记忆）")

    # ---- gray zone -> auditor ----
    try:
        res = gray(tool, tin, cwd, transcript_path)
    except Exception as e:
        emit("ask", f"MiniMax lockdown hook 出错（{e}），保守起见请确认。")
        return
    if res and res[0]:
        d, r = res
        if d == "ask":
            st["pending"].add(sig)
            save_state(session_id, st)
        log_decision(session_id, model, tool, sig, d, r)
        emit(d, r)
    sys.exit(0)


if __name__ == "__main__":
    main()
