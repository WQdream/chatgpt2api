"""OpenAI Sentinel Token (PoW) 生成与请求工具函数。

用于密码登录、注册等需要 sentinel token 的流程。
"""
from __future__ import annotations

import base64
import json
import os
import random
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote, urljoin, urlsplit

if TYPE_CHECKING:
    from curl_cffi.requests import Session


class SentinelTokenGenerator:
    """Sentinel Token 生成器（PoW - Proof of Work）。"""
    MAX_ATTEMPTS = 500_000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(self, device_id: str, ua: str):
        self.device_id = device_id
        self.user_agent = ua
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text: str) -> str:
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= h >> 16
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= h >> 16
        return format(h & 0xFFFFFFFF, "08x")

    def _get_config(self) -> list:
        perf_now = random.uniform(1000, 50000)
        return [
            "1920x1080",
            time.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)", time.gmtime()),
            4294705152,
            random.random(),
            self.user_agent,
            "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js",
            None,
            None,
            "en-US",
            random.random(),
            random.choice(["vendorSub-undefined", "plugins-undefined", "mimeTypes-undefined", "hardwareConcurrency-undefined"]),
            random.choice(["location", "implementation", "URL", "documentURI", "compatMode"]),
            random.choice(["Object", "Function", "Array", "Number", "parseFloat", "undefined"]),
            perf_now,
            self.sid,
            "",
            random.choice([4, 8, 12, 16]),
            time.time() * 1000 - perf_now,
        ]

    @staticmethod
    def _b64(data) -> str:
        return base64.b64encode(json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).decode("ascii")

    def generate_requirements_token(self) -> str:
        data = self._get_config()
        data[3] = 1
        data[9] = round(random.uniform(5, 50))
        return "gAAAAAC" + self._b64(data)

    def generate_token(self, seed: str, difficulty: str) -> str:
        start = time.time()
        data = self._get_config()
        difficulty = str(difficulty or "0")
        for i in range(self.MAX_ATTEMPTS):
            data[3] = i
            data[9] = round((time.time() - start) * 1000)
            payload = self._b64(data)
            if self._fnv1a_32(seed + payload)[: len(difficulty)] <= difficulty:
                return "gAAAAAB" + payload + "~S"
        return "gAAAAAB" + self.ERROR_PREFIX + self._b64(str(None))


# ── 默认 User-Agent 和 sec-ch-ua ──────────────────────────────
DEFAULT_SENTINEL_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)
DEFAULT_SENTINEL_SEC_CH_UA = '"Chromium";v="145", "Google Chrome";v="145", "Not/A)Brand";v="99"'

SENTINEL_FRAME_URL = "https://sentinel.openai.com/backend-api/sentinel/frame.html"
SENTINEL_RUNTIME_URL = "https://auth.openai.com/__sentinel_sdk_runtime__"
DEFAULT_OBSERVER_WAIT_MS = 5000
SENTINEL_BROWSER_CONCURRENCY = max(1, int(os.getenv("SENTINEL_BROWSER_CONCURRENCY") or "2"))
SENTINEL_BROWSER_TIMEOUT_MS = max(15_000, int(os.getenv("SENTINEL_BROWSER_TIMEOUT_MS") or "45000"))
_sentinel_browser_slots = threading.BoundedSemaphore(SENTINEL_BROWSER_CONCURRENCY)


@dataclass(frozen=True)
class SentinelSDKDescriptor:
    version: str
    script_url: str


@dataclass(frozen=True)
class SentinelSDKTokens:
    token: str
    so_token: str
    sdk_version: str
    oai_sc: str = ""
    proof_token: str = ""
    turnstile_token: str = ""
    challenge_token: str = ""
    requirements: dict[str, bool] = field(default_factory=dict)
    runtime_mode: str = "chromium"


def discover_official_sdk(
    session: "Session",
    *,
    user_agent: str = "",
) -> SentinelSDKDescriptor:
    """从官方 frame.html 动态解析当前 Sentinel SDK 地址与版本。"""
    ua = user_agent or DEFAULT_SENTINEL_USER_AGENT
    resp = session.get(
        SENTINEL_FRAME_URL,
        headers={
            "Accept": "text/html,application/xhtml+xml",
            "Referer": "https://auth.openai.com/",
            "User-Agent": ua,
        },
        timeout=20,
        verify=True,
    )
    text = str(getattr(resp, "text", "") or "")
    status = int(getattr(resp, "status_code", 0) or 0)
    if status != 200:
        raise RuntimeError(f"sentinel_sdk_frame_http_{status}")
    match = re.search(
        r"src\s*=\s*['\"]([^'\"]*/sentinel/([^/'\"]+)/sdk\.js(?:\?[^'\"]*)?)['\"]",
        text,
        flags=re.IGNORECASE,
    )
    if not match:
        raise RuntimeError("sentinel_sdk_script_not_found")
    version = str(match.group(2)).strip()
    script_url = urljoin(SENTINEL_FRAME_URL, str(match.group(1)).strip())
    parsed = urlsplit(script_url)
    if (
        parsed.scheme.lower() != "https"
        or parsed.hostname != "sentinel.openai.com"
        or not re.fullmatch(rf"/sentinel/{re.escape(version)}/sdk\.js", parsed.path)
    ):
        raise RuntimeError("sentinel_sdk_untrusted_script_url")
    return SentinelSDKDescriptor(version=version, script_url=script_url)


def build_sdk_evaluation_expression(flow: str, *, observer_wait_ms: int = DEFAULT_OBSERVER_WAIT_MS) -> str:
    """构造仅调用官方 SDK 公共接口的浏览器表达式。"""
    flow_json = json.dumps(str(flow), ensure_ascii=False)
    wait_ms = max(DEFAULT_OBSERVER_WAIT_MS, int(observer_wait_ms or DEFAULT_OBSERVER_WAIT_MS))
    return f"""
async () => {{
  const flow = {flow_json};
  const collect = async () => {{
    await SentinelSDK.init(flow);
    await new Promise(resolve => setTimeout(resolve, {wait_ms}));
    const token = await SentinelSDK.token(flow);
    const soToken = await SentinelSDK.sessionObserverToken(flow);
    return {{
      token: typeof token === "string" ? token : "",
      so_token: typeof soToken === "string" ? soToken : ""
    }};
  }};
  return await Promise.race([
    collect(),
    new Promise((_, reject) => setTimeout(() => reject(new Error("sentinel_sdk_timeout")), {SENTINEL_BROWSER_TIMEOUT_MS}))
  ]);
}}
""".strip()


def _playwright_proxy(proxy: str) -> dict[str, str] | None:
    value = str(proxy or "").strip()
    if not value:
        return None
    parsed = urlsplit(value if "://" in value else f"http://{value}")
    if not parsed.hostname:
        return {"server": value}
    server = f"{parsed.scheme or 'http'}://{parsed.hostname}"
    if parsed.port:
        server += f":{parsed.port}"
    result = {"server": server}
    if parsed.username:
        result["username"] = unquote(parsed.username)
    if parsed.password:
        result["password"] = unquote(parsed.password)
    return result


def _browser_launch_options(playwright, proxy: str) -> dict:
    options: dict = {"headless": True}
    proxy_config = _playwright_proxy(proxy)
    if proxy_config:
        options["proxy"] = proxy_config
    configured = str(os.getenv("SENTINEL_BROWSER_EXECUTABLE") or "").strip()
    if configured:
        options["executable_path"] = configured
    elif os.name == "nt" and not Path(playwright.chromium.executable_path).exists():
        options["channel"] = "msedge"
    return options


def run_official_sdk(
    *,
    descriptor: SentinelSDKDescriptor,
    device_id: str,
    flow: str,
    user_agent: str,
    proxy: str = "",
    observer_wait_ms: int = DEFAULT_OBSERVER_WAIT_MS,
) -> dict[str, object]:
    """在真实 Chromium 页面上下文中加载并执行当前官方 Sentinel SDK。"""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError("sentinel_playwright_missing") from exc

    runtime_html = (
        "<!doctype html><html><head><meta charset='utf-8'></head><body>"
        f"<script src='{descriptor.script_url}'></script>"
        "</body></html>"
    )
    expression = build_sdk_evaluation_expression(flow, observer_wait_ms=observer_wait_ms)
    if not _sentinel_browser_slots.acquire(timeout=max(60, SENTINEL_BROWSER_TIMEOUT_MS // 1000 + 15)):
        raise RuntimeError("sentinel_browser_concurrency_timeout")
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(**_browser_launch_options(playwright, proxy))
            try:
                context = browser.new_context(user_agent=user_agent, ignore_https_errors=False)
                context.set_default_timeout(SENTINEL_BROWSER_TIMEOUT_MS)
                context.set_default_navigation_timeout(SENTINEL_BROWSER_TIMEOUT_MS)
                context.add_cookies(
                    [
                        {
                            "name": "oai-did",
                            "value": str(device_id),
                            "domain": ".auth.openai.com",
                            "path": "/",
                            "secure": True,
                            "sameSite": "Lax",
                        },
                        {
                            "name": "oai-did",
                            "value": str(device_id),
                            "domain": ".openai.com",
                            "path": "/",
                            "secure": True,
                            "sameSite": "Lax",
                        },
                    ]
                )
                page = context.new_page()
                requirements: dict[str, object] = {}

                def capture_requirements(response) -> None:
                    if "/backend-api/sentinel/req" not in str(response.url):
                        return
                    try:
                        payload = response.json()
                    except Exception:
                        return
                    if isinstance(payload, dict):
                        requirements.clear()
                        requirements.update(payload)

                page.on("response", capture_requirements)
                page.route(
                    SENTINEL_RUNTIME_URL,
                    lambda route: route.fulfill(status=200, content_type="text/html", body=runtime_html),
                )
                page.goto(SENTINEL_RUNTIME_URL, wait_until="load", timeout=SENTINEL_BROWSER_TIMEOUT_MS)
                page.wait_for_function("typeof SentinelSDK !== 'undefined'", timeout=SENTINEL_BROWSER_TIMEOUT_MS)
                result = page.evaluate(expression)
                oai_sc = next(
                    (
                        str(cookie.get("value") or "")
                        for cookie in context.cookies()
                        if cookie.get("name") == "oai-sc"
                        and str(cookie.get("domain") or "").lstrip(".").endswith("openai.com")
                    ),
                    "",
                )
                return {
                    "token": str((result or {}).get("token") or ""),
                    "so_token": str((result or {}).get("so_token") or ""),
                    "oai_sc": oai_sc,
                    "requirements": requirements,
                }
            finally:
                browser.close()
    finally:
        _sentinel_browser_slots.release()


_SDK_RUNTIME_ERROR_MARKERS = (
    "typeerror",
    "referenceerror",
    "cannot read properties",
    "cannot set properties",
    "is not a function",
    "reading 'bind'",
    'reading "bind"',
)


def _contains_encoded_runtime_error(value: str) -> bool:
    raw = str(value or "").strip()
    if not raw:
        return False

    candidates = [raw]
    for prefix in ("gAAAAAB", "gAAAAAC"):
        if raw.startswith(prefix):
            candidates.append(raw[len(prefix) :].removesuffix("~S"))

    inspected = list(candidates)
    for candidate in candidates:
        compact = candidate.strip()
        if not compact:
            continue
        padded = compact + ("=" * (-len(compact) % 4))
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                inspected.append(decoder(padded).decode("utf-8", errors="ignore"))
            except Exception:
                continue

    return any(
        marker in inspected_value.lower()
        for inspected_value in inspected
        for marker in _SDK_RUNTIME_ERROR_MARKERS
    )


def _require_valid_sdk_value(name: str, value: str, *, required: bool) -> None:
    if required and not value:
        raise RuntimeError(f"sentinel_sdk_{name}_missing")
    if value and _contains_encoded_runtime_error(value):
        raise RuntimeError(f"sentinel_sdk_{name}_invalid")


def _normalize_requirements(raw: object, flow: str) -> dict[str, bool]:
    if not isinstance(raw, dict) or not raw:
        raise RuntimeError("sentinel_sdk_requirements_missing")

    sections = ["proofofwork", "turnstile"]
    if flow == "oauth_create_account":
        sections.append("so")
    if any(not isinstance(raw.get(name), dict) or "required" not in raw[name] for name in sections):
        raise RuntimeError("sentinel_sdk_requirements_missing")

    def required(name: str) -> bool:
        value = raw.get(name)
        return bool(value.get("required")) if isinstance(value, dict) else False

    return {
        "proof": required("proofofwork"),
        "turnstile": required("turnstile"),
        "so": required("so"),
    }


def generate_official_sentinel_tokens(
    session: "Session",
    device_id: str,
    flow: str,
    *,
    user_agent: str = "",
    proxy: str = "",
    observer_wait_ms: int = DEFAULT_OBSERVER_WAIT_MS,
) -> SentinelSDKTokens:
    """加载当前官方 SDK，并返回 create_account 所需的双 token。"""
    ua = user_agent or DEFAULT_SENTINEL_USER_AGENT
    descriptor = discover_official_sdk(session, user_agent=ua)
    values = run_official_sdk(
        descriptor=descriptor,
        device_id=device_id,
        flow=flow,
        user_agent=ua,
        proxy=proxy,
        observer_wait_ms=max(DEFAULT_OBSERVER_WAIT_MS, int(observer_wait_ms or DEFAULT_OBSERVER_WAIT_MS)),
    )
    token = str(values.get("token") or "").strip()
    so_token = str(values.get("so_token") or "").strip()
    oai_sc = str(values.get("oai_sc") or "").strip()
    if not token:
        raise RuntimeError("sentinel_sdk_token_missing")
    try:
        combined = json.loads(token)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("sentinel_sdk_combined_token_invalid") from exc
    if not isinstance(combined, dict) or combined.get("e"):
        raise RuntimeError("sentinel_sdk_combined_token_invalid")

    requirements = _normalize_requirements(values.get("requirements"), flow)
    proof_token = combined.get("p") if isinstance(combined.get("p"), str) else ""
    turnstile_token = combined.get("t") if isinstance(combined.get("t"), str) else ""
    challenge_token = combined.get("c") if isinstance(combined.get("c"), str) else ""

    _require_valid_sdk_value("proof_token", proof_token, required=requirements["proof"])
    _require_valid_sdk_value("turnstile_token", turnstile_token, required=requirements["turnstile"])
    _require_valid_sdk_value("challenge_token", challenge_token, required=True)
    _require_valid_sdk_value("so_token", so_token, required=requirements["so"])
    _require_valid_sdk_value("oai_sc", oai_sc, required=flow == "oauth_create_account")

    return SentinelSDKTokens(
        token=token,
        so_token=so_token,
        sdk_version=descriptor.version,
        oai_sc=oai_sc,
        proof_token=proof_token,
        turnstile_token=turnstile_token,
        challenge_token=challenge_token,
        requirements=requirements,
        runtime_mode="chromium",
    )


def build_sentinel_bundle(
    session: "Session",
    device_id: str,
    flow: str,
    *,
    user_agent: str = "",
    proxy: str = "",
    observer_wait_ms: int = DEFAULT_OBSERVER_WAIT_MS,
) -> SentinelSDKTokens:
    """返回官方 SDK 生成的 Sentinel header、SO header 与 oai-sc cookie bundle。"""
    return generate_official_sentinel_tokens(
        session,
        device_id,
        flow,
        user_agent=user_agent,
        proxy=proxy,
        observer_wait_ms=observer_wait_ms,
    )


def build_sentinel_token(
    session: "Session",
    device_id: str,
    flow: str,
    *,
    user_agent: str = "",
    sec_ch_ua: str = "",
) -> tuple[str, str]:
    """请求 sentinel token 并返回 (sentinel_header_value, oai_sc_cookie_value)。

    Args:
        session: curl_cffi Session 实例
        device_id: 设备 ID
        flow: 流程标识（如 "password_verify", "username_password_create" 等）
        user_agent: 可选的 User-Agent 覆盖
        sec_ch_ua: 可选的 sec-ch-ua 覆盖

    Returns:
        (openai-sentinel-token header value, oai-sc cookie value) 元组

    Raises:
        RuntimeError: sentinel 请求失败
    """
    ua = user_agent or DEFAULT_SENTINEL_USER_AGENT
    ch_ua = sec_ch_ua or DEFAULT_SENTINEL_SEC_CH_UA
    generator = SentinelTokenGenerator(device_id, ua)
    resp = session.post(
        "https://sentinel.openai.com/backend-api/sentinel/req",
        data=json.dumps({"p": generator.generate_requirements_token(), "id": device_id, "flow": flow}),
        headers={
            "Content-Type": "text/plain;charset=UTF-8",
            "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
            "Origin": "https://sentinel.openai.com",
            "User-Agent": ua,
            "sec-ch-ua": ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        },
        timeout=20,
        verify=False,
    )

    try:
        data = resp.json() if resp.text else {}
    except Exception:
        fallback = json.dumps(
            {"p": generator.generate_requirements_token(), "t": "", "c": "", "id": device_id, "flow": flow},
            separators=(",", ":"),
        )
        return fallback, ""

    token = str(data.get("token") or "").strip()
    if resp.status_code != 200 or not token:
        raise RuntimeError(f"sentinel_req_failed_{resp.status_code}")
    pow_data = data.get("proofofwork") or {}
    p_value = (
        generator.generate_token(str(pow_data.get("seed") or ""), str(pow_data.get("difficulty") or "0"))
        if pow_data.get("required") and pow_data.get("seed")
        else generator.generate_requirements_token()
    )
    sentinel_value = json.dumps({"p": p_value, "t": "", "c": token, "id": device_id, "flow": flow}, separators=(",", ":"))
    # oai-sc cookie = "0" + sentinel token "c" value (the challenge token from the server)
    oai_sc_value = "0" + token
    return sentinel_value, oai_sc_value
