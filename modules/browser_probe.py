"""Opt-in browser comparison for redirect cloaking detection.

SECURITY WARNING
----------------
This is the only Hydra plugin that *actively visits and executes*
potentially malicious remote page content (JavaScript, hostile redirects,
drive-by payloads). Every other plugin is passive/read-only via APIs or
banners.

Run Browser Probe ONLY inside a disposable, network-restricted container
or VM — never on the analyst's primary workstation. Headless mode and the
browser sandbox are NOT an anonymity or containment boundary.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urljoin, urlparse

from core.assets import normalize_domain
from core.exceptions import ValidationError
from core.models import PipelineContext, ToolStatus
from core.plugin_base import PluginResult
from modules._base import BaseToolPlugin
from utils.files import write_jsonl
from utils.security import (
    atomic_write_text,
    relative_output_path,
    validate_output_path,
    validate_safe_filename,
)

_IPHONE_USER_AGENT = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 "
    "Mobile/15E148 Safari/604.1"
)


class BrowserProbePlugin(BaseToolPlugin):
    """Compare httpx and real WebKit navigation destinations."""

    name = "browser_probe"
    display_name = "Browser Cloaking Probe"
    required = False
    external_dependency = False
    stage_order = 65
    cacheable = False
    produces = ("urls",)
    capability = "browser"
    active_collection = True
    strict_opsec_allowed = True

    def is_enabled(self) -> bool:
        return self.settings.enable_browser_probe

    def get_binary_path(self) -> Path:
        return Path("built-in")

    def get_install_hint(self) -> str:
        return "pip install -r requirements-optional.txt && playwright install webkit"

    async def run(self, context: PipelineContext, input_path: Path) -> PluginResult:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return self._skip(
                "Playwright not installed — pip install -r requirements-optional.txt "
                "&& playwright install webkit"
            )

        targets = _httpx_targets(context)[: self.settings.browser_probe_max_hosts]
        if not targets:
            return self._skip("No live HTTP services to probe")

        # SECURITY: this plugin executes potentially hostile page content. It must
        # only be used in a disposable, network-restricted container or VM.
        context.add_warning(
            "Browser Probe actively executed remote page content. Use an isolated "
            "container/VM; browser sandboxing is not an anonymity boundary."
        )
        self.update_status(context, ToolStatus.RUNNING)
        records: list[dict[str, object]] = []

        async with async_playwright() as playwright:
            launch_options: dict[str, object] = {"headless": True}
            if self.settings.outbound_proxy_url:
                launch_options["proxy"] = _playwright_proxy(self.settings.outbound_proxy_url)
            browser = await playwright.webkit.launch(**launch_options)
            try:
                for target in targets:
                    try:
                        records.append(
                            await _probe_target(
                                browser,
                                target,
                                context=context,
                                timeout_seconds=self.settings.browser_probe_timeout,
                            )
                        )
                    except Exception as exc:
                        # One bad target (context/page creation failure, proxy
                        # error, etc.) must not discard every target already
                        # probed in this batch.
                        records.append(
                            {
                                "host": target["host"],
                                "httpx_final_url": target["httpx_final_url"],
                                "browser_final_url": None,
                                "redirect_chain": [],
                                "cloaking_suspected": False,
                                "raw_artifact": None,
                                "error": str(exc)[:240],
                            }
                        )
            finally:
                await browser.close()

        output_path = self._output_path(context, "browser_probe.jsonl")
        count = write_jsonl(output_path, records, base_dir=context.output_dir)
        suspected = sum(bool(record["cloaking_suspected"]) for record in records)
        self.update_status(context, ToolStatus.COMPLETED, output_lines=count)
        return PluginResult(
            success=True,
            output_path=output_path,
            lines_produced=count,
            message=f"Browser probe identified {suspected} possible cloaking case(s)",
        )


async def _probe_target(
    browser: object,
    target: dict[str, str],
    *,
    context: PipelineContext,
    timeout_seconds: int,
) -> dict[str, object]:
    browser_context = await browser.new_context(
        user_agent=_IPHONE_USER_AGENT,
        is_mobile=True,
        has_touch=True,
        viewport={"width": 390, "height": 844},
        device_scale_factor=3,
        locale="en-US",
        timezone_id="UTC",
        accept_downloads=False,
        service_workers="block",
    )
    try:
        page = await browser_context.new_page()
        await page.add_init_script(
            """
            Object.defineProperty(window, 'RTCPeerConnection', {value: undefined});
            Object.defineProperty(window, 'webkitRTCPeerConnection', {value: undefined});
            Object.defineProperty(navigator, 'geolocation', {value: undefined});
            """
        )
        redirects: list[str] = []

        def capture_response(response: object) -> None:
            try:
                if response.request.is_navigation_request() and response.url not in redirects:
                    redirects.append(response.url)
            except Exception:
                return

        page.on("response", capture_response)
        error: str | None = None
        await _install_scope_navigation_guard(page, context)
        try:
            await page.goto(
                target["probe_url"],
                wait_until="networkidle",
                timeout=timeout_seconds * 1000,
            )
        except Exception as exc:
            # A noisy page can miss networkidle while still reaching a useful final URL.
            error = str(exc)[:240]

        browser_final_url = page.url
        if browser_final_url and browser_final_url not in redirects:
            redirects.append(browser_final_url)
        browser_host = _url_host(browser_final_url)
        httpx_host = _url_host(target["httpx_final_url"])
        cloaking = bool(browser_host and httpx_host and browser_host != httpx_host)

        # Persist the fully rendered HTML so an analyst can audit what the
        # mobile WebKit view actually saw — same raw-artifact pattern as
        # whois_raw.txt / port_verify_raw/.
        raw_artifact = await _write_html_artifact(context, target["host"], page, browser_final_url)

        return {
            "host": target["host"],
            "httpx_final_url": target["httpx_final_url"],
            "browser_final_url": browser_final_url,
            "redirect_chain": redirects,
            "cloaking_suspected": cloaking,
            "raw_artifact": raw_artifact,
            "error": error,
        }
    finally:
        # Always torn down, even if page creation, script injection, or
        # navigation raised — discards cookies, storage, cache, and workers.
        await browser_context.close()


async def _write_html_artifact(
    context: PipelineContext,
    host: str,
    page: object,
    final_url: str,
) -> str | None:
    try:
        html = await page.content()
    except Exception:
        html = ""
    try:
        filename = validate_safe_filename(f"{host}.html")
    except ValidationError:
        filename = validate_safe_filename(f"host-{abs(hash(host))}.html")
    raw_path = validate_output_path(
        context.output_dir / "browser_probe_raw" / filename, context.output_dir
    )
    content = f"<!-- final_url: {final_url} -->\n{html if isinstance(html, str) else ''}"
    try:
        atomic_write_text(raw_path, content)
    except OSError:
        return None
        return relative_output_path(raw_path, context.output_dir)


def allow_browser_navigation(url: str, context: PipelineContext) -> bool:
    """Document navigations must re-check CollectionScope. Redirects are not authorization."""
    from core.intel.scope import allows_active_collection

    scope = getattr(context, "collection_scope", None)
    if scope is None:
        return True
    return allows_active_collection(url, scope)


async def _install_scope_navigation_guard(page: object, context: PipelineContext) -> None:
    """Abort in-browser document navigations whose hostname is not authorized."""
    if getattr(context, "collection_scope", None) is None:
        return

    async def guard(route: object) -> None:
        try:
            request = route.request
            if request.is_navigation_request() and not allow_browser_navigation(
                request.url, context
            ):
                await route.abort("blockedbyclient")
                return
        except Exception:
            await route.continue_()
            return
        await route.continue_()

    await page.route("**/*", guard)


def _httpx_targets(context: PipelineContext) -> list[dict[str, str]]:
    from core.intel.scope import allows_active_collection

    scope = getattr(context, "collection_scope", None)
    targets: dict[str, dict[str, str]] = {}
    for record in context.httpx_results:
        probe_url = str(record.get("url") or record.get("input") or "")
        if not probe_url:
            continue
        if "://" not in probe_url:
            probe_url = f"https://{probe_url}"
        input_raw = str(record.get("input") or "")
        input_url = (
            input_raw if "://" in input_raw else (f"https://{input_raw}" if input_raw else probe_url)
        )
        if scope is not None:
            if allows_active_collection(probe_url, scope):
                pass
            elif allows_active_collection(input_url, scope):
                probe_url = input_url
            else:
                continue
        host = _url_host(str(record.get("input") or probe_url))
        if not host:
            continue
        if scope is not None and not allows_active_collection(host, scope):
            continue
        explicit_final = str(record.get("final_url") or "")
        location = str(record.get("location") or "")
        httpx_final = explicit_final or (urljoin(probe_url, location) if location else probe_url)
        targets.setdefault(
            host,
            {
                "host": host,
                "probe_url": probe_url,
                "httpx_final_url": httpx_final,
            },
        )
    return [targets[host] for host in sorted(targets)]


def _url_host(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    return normalize_domain(parsed.hostname or "")


def _playwright_proxy(proxy_url: str) -> dict[str, str]:
    parsed = urlparse(proxy_url)
    server = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        server += f":{parsed.port}"
    config = {"server": server}
    if parsed.username:
        config["username"] = parsed.username
    if parsed.password:
        config["password"] = parsed.password
    return config
