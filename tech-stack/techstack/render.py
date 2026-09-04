"""Optional JS rendering via Playwright.

On a pure React/Vue/Angular SPA the HTML is ``<div id="root"></div>`` and one
bundle — headers say "CDN" and nothing else. Rendering adds ``js_globals``
(``jQuery.fn.jquery``, ``Vue.version`` — the most reliable version source) and
the real network requests. That is +20% of detectable technologies and the
best version source.

Cost, measured rather than guessed: ~134MB for the package in the script's venv
(Playwright bundles a Node driver) and +5–15s/page. The **browsers are not in
the venv** — they live in a machine-wide cache (``~/Library/Caches/ms-playwright``
on macOS) shared by every venv, so a machine that already ran any Playwright
project needs no second download.

Two distinct failure modes, both degrade to a warning and a scan without
rendering — never a crash:

  * package missing      → ``playwright-not-installed``
  * browsers not fetched → ``browsers-not-installed`` (``playwright install``)

Imported **lazily inside the function** so a scan without ``--render`` never
pays the import.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RenderResult:
    js_globals: dict[str, str] = field(default_factory=dict)
    requests: list[tuple[str, str]] = field(default_factory=list)  # (url, kind)
    error: Optional[str] = None


def render_url(url: str, exprs: list[str], timeout: int = 20) -> RenderResult:
    """Render ``url`` headless, collect js-globals and network requests.

    Imports Playwright lazily; returns ``error`` (never raises) on any failure
    so the caller can degrade gracefully.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return RenderResult(error="playwright-not-installed")

    result = RenderResult()
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                ctx = browser.new_context(
                    ignore_https_errors=True,
                    user_agent=("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                                "AppleWebKit/537.36 (KHTML, like Gecko) "
                                "Chrome/124.0.0.0 Safari/537.36"),
                )
                page = ctx.new_page()

                _RT_MAP = {
                    "script": "script", "stylesheet": "stylesheet",
                    "image": "image", "font": "font", "document": "iframe",
                    "fetch": "other", "xhr": "other", "media": "image",
                    "other": "other",
                }

                def on_request(req):
                    if req.url.startswith("data:"):
                        return
                    kind = _RT_MAP.get(req.resource_type, "other")
                    result.requests.append((req.url, kind))

                page.on("request", on_request)

                page.goto(url, timeout=timeout * 1000, wait_until="networkidle")
                # Let late analytics tags fire.
                try:
                    page.wait_for_timeout(1500)
                except Exception:
                    pass

                for expr in exprs:
                    if not expr:
                        continue
                    try:
                        val = page.evaluate(
                            "() => { try { const v = window."
                            f"{expr}"
                            "; return v == null ? null : String(v); } "
                            "catch(e) { return null; } }"
                        )
                    except Exception:
                        val = None
                    if val:
                        result.js_globals[expr] = str(val)
            finally:
                browser.close()
    except Exception as exc:  # broad: any Playwright/runtime failure degrades
        result.error = _classify(exc)
    return result


def _classify(exc: Exception) -> str:
    """Separate "browsers were never downloaded" from a genuine render failure.

    Playwright reports the missing browser as a plain ``Error`` carrying a
    multi-line ASCII banner. Dumping that into a markdown warning is unreadable
    and, worse, indistinguishable from a site that simply failed to render — so
    it gets its own short code and the caller stops retrying it per page.
    """
    text = str(exc)
    if "Executable doesn't exist" in text or "playwright install" in text:
        return "browsers-not-installed"
    return f"render-failed: {text.splitlines()[0][:200]}"
