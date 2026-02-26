import os
import re
import time
import secrets
import logging
from pathlib import Path
from typing import Any

import httpx
import nonebot
from fastapi import HTTPException
from fastapi.responses import FileResponse
from nonebot import on_regex
from nonebot.adapters.onebot.v11 import Adapter, Bot, GroupMessageEvent, MessageEvent
from nonebot.params import RegexGroup

ONEBOT_ACCESS_TOKEN = os.getenv("ONEBOT_ACCESS_TOKEN", "")
OPENCLAW_BASE_URL = os.getenv("OPENCLAW_BASE_URL", "http://127.0.0.1:18789").rstrip("/")
OPENCLAW_TOKEN = os.getenv("OPENCLAW_TOKEN", "")
OPENCLAW_MODEL = os.getenv("OPENCLAW_MODEL", "openclaw:main")
OPENCLAW_TIMEOUT = float(os.getenv("OPENCLAW_TIMEOUT", "600"))
OPENCLAW_MAX_TOKENS = int(os.getenv("OPENCLAW_MAX_TOKENS", "512"))
OPENCLAW_AGENT_ID = os.getenv("OPENCLAW_AGENT_ID", "main")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://127.0.0.1:8080").rstrip("/")

FILE_DIRECTIVE_RE = re.compile(r"^__SEND_FILE__:(.+)$", re.IGNORECASE)
FILE_HINT_RE = re.compile(r"([A-Za-z0-9_\- .]+\.(?:zip|jar|7z|rar|txt|json|yaml|yml|log|pdf|png|jpg|jpeg|gif|mp4|tar|gz|tgz|xz))", re.IGNORECASE)
FILE_LINK_TTL_SECONDS = int(os.getenv("FILE_LINK_TTL_SECONDS", "900"))
MAX_AUTO_SEND_FILES = int(os.getenv("MAX_AUTO_SEND_FILES", "3"))

ALLOWED_FILE_ROOTS = [
    Path("/root/.openclaw/workspace").resolve(),
    Path("/tmp/openclaw-share").resolve(),
]

# token -> {path, name, expires_at}
TEMP_FILE_LINKS: dict[str, dict[str, Any]] = {}
# session_key -> last sent file path
LAST_SENT_FILE_BY_SESSION: dict[str, str] = {}

nonebot.init(host="0.0.0.0", port=8080, onebot_access_token=ONEBOT_ACCESS_TOKEN)
driver = nonebot.get_driver()
driver.register_adapter(Adapter)

logger = logging.getLogger("nonebot.openclaw.bridge")

ask_ai = on_regex(r"^(?:oc|ai)\s+([\s\S]+)$", priority=10, block=True)
send_file_cmd = on_regex(r"^ocfile\s+(.+)$", priority=9, block=True)

SYSTEM_HINT = (
    "You are running behind a QQ bridge. "
    "If you need to send a server file to the current QQ chat, output one line exactly like: "
    "__SEND_FILE__:file_name_or_path . "
    "You may output multiple __SEND_FILE__ lines, one file per line. "
    "For downloaded artifacts, save under /root/.openclaw/workspace/share/."
)


def _extract_text(content: Any) -> str:
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                if isinstance(item.get("text"), str):
                    parts.append(item["text"])
                elif item.get("type") == "output_text" and isinstance(item.get("text"), str):
                    parts.append(item["text"])
                elif isinstance(item.get("content"), str):
                    parts.append(item["content"])
            elif isinstance(item, str):
                parts.append(item)
        return "\n".join([p for p in parts if p]).strip()
    return ""


def _build_session_key(event: MessageEvent) -> str:
    # Group messages share one session per group; private chat remains per user.
    user_id = str(getattr(event, "user_id", "unknown"))
    if isinstance(event, GroupMessageEvent):
        return f"agent:main:qq:group:{event.group_id}"
    return f"agent:main:qq:private:user:{user_id}"


def _is_under_allowed_roots(p: Path) -> bool:
    rp = p.resolve()
    for root in ALLOWED_FILE_ROOTS:
        try:
            rp.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _iter_files_under_roots() -> list[Path]:
    files: list[Path] = []
    for root in ALLOWED_FILE_ROOTS:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if p.is_file():
                files.append(p)
    return files


def _find_latest_file() -> Path | None:
    files = _iter_files_under_roots()
    if not files:
        return None
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0]


def _resolve_file_path(file_spec: str) -> Path:
    spec = file_spec.strip().strip('"').strip("'")
    if not spec:
        raise ValueError("empty file spec")

    p = Path(spec).expanduser()
    if p.is_absolute():
        rp = p.resolve()
        if not _is_under_allowed_roots(rp):
            allowed = ", ".join(str(x) for x in ALLOWED_FILE_ROOTS)
            raise ValueError(f"file path is outside allowed roots: {allowed}")
        if not rp.exists() or not rp.is_file():
            raise ValueError(f"file not found: {rp}")
        return rp

    for root in ALLOWED_FILE_ROOTS:
        cand = (root / spec).resolve()
        if cand.exists() and cand.is_file() and _is_under_allowed_roots(cand):
            return cand

    matches: list[Path] = []
    for fp in _iter_files_under_roots():
        if fp.name.lower() == Path(spec).name.lower():
            matches.append(fp)
    if matches:
        matches.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        return matches[0]

    q = Path(spec).name.lower()
    fuzzy: list[Path] = []
    for fp in _iter_files_under_roots():
        if q and q in fp.name.lower():
            fuzzy.append(fp)
    if fuzzy:
        fuzzy.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        return fuzzy[0]

    raise ValueError(f"file not found by spec: {spec}")


def _extract_file_hints(text: str) -> list[str]:
    if not text:
        return []
    hints = []
    for m in FILE_HINT_RE.findall(text):
        h = m.strip().strip('"').strip("'")
        if h:
            hints.append(h)
    seen = set()
    out = []
    for h in hints:
        k = h.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(h)
    return out


def _looks_like_send_intent(text: str) -> bool:
    t = (text or "").lower()
    keywords = [
        "send", "upload", "file", "attach", "share", "again", "resend",
        "?", "??", "?", "??", "??", "??", "??", "??", "???", "??", "??",
    ]
    return any(k in t for k in keywords)


def _split_file_directives(text: str) -> tuple[str, list[str]]:
    if not text:
        return "", []
    clean_lines: list[str] = []
    files: list[str] = []
    for line in text.splitlines():
        m = FILE_DIRECTIVE_RE.match(line.strip())
        if m:
            f = m.group(1).strip().strip('"').strip("'")
            if f:
                files.append(f)
        else:
            clean_lines.append(line)
    return "\n".join(clean_lines).strip(), files


def _auto_pick_files(prompt: str, content_text: str, session_key: str) -> list[Path]:
    merged = (prompt or "") + "\n" + (content_text or "")
    picked: list[Path] = []

    for hint in _extract_file_hints(merged):
        try:
            picked.append(_resolve_file_path(hint))
        except Exception:
            pass

    # Prefer last sent file in this session when user asks to resend/send.
    if _looks_like_send_intent(merged):
        last = LAST_SENT_FILE_BY_SESSION.get(session_key)
        if last:
            lp = Path(last)
            if lp.exists() and lp.is_file() and _is_under_allowed_roots(lp):
                picked.insert(0, lp)

    if not picked and _looks_like_send_intent(merged):
        latest = _find_latest_file()
        if latest is not None:
            picked.append(latest)

    seen = set()
    out = []
    for p in picked:
        k = str(p.resolve())
        if k in seen:
            continue
        seen.add(k)
        out.append(p)

    return out[:MAX_AUTO_SEND_FILES]


def _issue_temp_file_link(file_path: Path) -> str:
    token = secrets.token_urlsafe(24)
    TEMP_FILE_LINKS[token] = {
        "path": str(file_path),
        "name": file_path.name,
        "expires_at": time.time() + FILE_LINK_TTL_SECONDS,
    }
    return f"{PUBLIC_BASE_URL}/files/{token}"


@driver.server_app.get("/files/{token}")
async def _download_temp_file(token: str):
    rec = TEMP_FILE_LINKS.get(token)
    now = time.time()

    expired = [k for k, v in TEMP_FILE_LINKS.items() if v.get("expires_at", 0) < now]
    for k in expired:
        TEMP_FILE_LINKS.pop(k, None)

    if not rec or rec.get("expires_at", 0) < now:
        raise HTTPException(status_code=404, detail="file token expired")

    file_path = Path(rec["path"])
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="file not found")

    return FileResponse(path=str(file_path), filename=rec.get("name", file_path.name))


async def _send_file_message(bot: Bot, event: MessageEvent, file_spec: str, session_key: str) -> tuple[bool, str]:
    try:
        file_path = _resolve_file_path(file_spec)
    except Exception as ex:
        return False, str(ex)

    link = _issue_temp_file_link(file_path)
    msg = [{"type": "file", "data": {"file": link, "name": file_path.name}}]

    try:
        if isinstance(event, GroupMessageEvent):
            await bot.call_api("send_group_msg", group_id=event.group_id, message=msg)
        else:
            await bot.call_api("send_private_msg", user_id=event.user_id, message=msg)
        LAST_SENT_FILE_BY_SESSION[session_key] = str(file_path)
        logger.info("file sent via send_*_msg: session=%s file=%s", session_key, file_path)
        return True, f"sent file: {file_path.name}"
    except Exception as ex:
        try:
            if isinstance(event, GroupMessageEvent):
                await bot.call_api(
                    "upload_group_file",
                    group_id=event.group_id,
                    file=link,
                    name=file_path.name,
                )
            else:
                await bot.call_api(
                    "upload_private_file",
                    user_id=event.user_id,
                    file=link,
                    name=file_path.name,
                )
            LAST_SENT_FILE_BY_SESSION[session_key] = str(file_path)
            logger.info("file sent via upload_*_file: session=%s file=%s", session_key, file_path)
            return True, f"sent file: {file_path.name}"
        except Exception as ex2:
            logger.warning("file send failed: session=%s spec=%s err=%s fallback=%s", session_key, file_spec, ex, ex2)
            return False, f"primary={type(ex).__name__}: {ex}; fallback={type(ex2).__name__}: {ex2}"


@send_file_cmd.handle()
async def _(bot: Bot, event: MessageEvent, groups=RegexGroup()):
    file_spec = (groups[0] if groups and len(groups) > 0 else "").strip()
    session_key = _build_session_key(event)
    if not file_spec:
        await send_file_cmd.send("Usage: ocfile <file_name_or_absolute_path>")
        return
    ok, msg = await _send_file_message(bot, event, file_spec, session_key)
    if ok:
        await send_file_cmd.send(msg)
    else:
        await send_file_cmd.send(f"file send failed: {msg}")


@ask_ai.handle()
async def _(bot: Bot, event: MessageEvent, groups=RegexGroup()):
    prompt = (groups[0] if groups and len(groups) > 0 else "").strip()
    if not prompt:
        await ask_ai.send("Usage: oc <your message>")
        return

    session_key = _build_session_key(event)

    headers = {
        "Content-Type": "application/json",
        "x-openclaw-session-key": session_key,
        "x-openclaw-agent-id": OPENCLAW_AGENT_ID,
    }
    if OPENCLAW_TOKEN:
        headers["Authorization"] = f"Bearer {OPENCLAW_TOKEN}"

    payload = {
        "model": OPENCLAW_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_HINT},
            {"role": "user", "content": prompt},
        ],
        "user": session_key,
        "stream": False,
        "max_tokens": OPENCLAW_MAX_TOKENS,
    }

    timeout = httpx.Timeout(timeout=OPENCLAW_TIMEOUT, connect=15.0, read=OPENCLAW_TIMEOUT, write=60.0)

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                f"{OPENCLAW_BASE_URL}/v1/chat/completions",
                headers=headers,
                json=payload,
            )

        if resp.status_code >= 400:
            text = resp.text.strip().replace("\n", " ")
            await ask_ai.send(f"OpenClaw request failed: HTTP {resp.status_code} {text[:300]}")
            return

        data = resp.json()
        choices = data.get("choices") or []
        msg = choices[0].get("message", {}) if choices else {}
        content = _extract_text(msg.get("content"))

        content_text, file_specs = _split_file_directives(content)

        if not file_specs:
            auto_files = _auto_pick_files(prompt, content_text, session_key)
            file_specs = [str(p) for p in auto_files]

        if content_text:
            await ask_ai.send(content_text[:1800])

        sent_any = False
        attempted = []
        for spec in file_specs[:MAX_AUTO_SEND_FILES]:
            attempted.append(spec)
            ok, detail = await _send_file_message(bot, event, spec, session_key)
            if ok:
                sent_any = True
            else:
                await ask_ai.send(f"file send failed: {spec} | {detail}")

        # final fallback: resend last file when user clearly asks to send
        if not sent_any and _looks_like_send_intent((prompt or "") + "\n" + (content_text or "")):
            last = LAST_SENT_FILE_BY_SESSION.get(session_key)
            if last and last not in attempted:
                ok, detail = await _send_file_message(bot, event, last, session_key)
                if ok:
                    sent_any = True
                else:
                    await ask_ai.send(f"file send failed: {last} | {detail}")

        if not content_text and not file_specs and not sent_any:
            await ask_ai.send("OpenClaw returned empty content.")

    except httpx.ReadTimeout:
        await ask_ai.send(
            "OpenClaw request error: ReadTimeout: request exceeded timeout. Task may be too large; split task or use faster model."
        )
    except Exception as ex:
        await ask_ai.send(f"OpenClaw request error: {type(ex).__name__}: {ex}")


if __name__ == "__main__":
    nonebot.run()
