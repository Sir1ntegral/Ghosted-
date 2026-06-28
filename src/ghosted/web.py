"""Ghosted's own web search + fetch — curl_cffi (TLS impersonation) + bs4,
with a stdlib fallback. Decoupled from rabbit.research.sovereign_browser_engine.

A tool fetches the web with its own masked client. Search uses DuckDuckGo's
HTML endpoint (no JavaScript required, the most parseable surface). Everything
degrades gracefully: curl_cffi -> stdlib urllib; bs4 -> regex; offline -> [].

Contract preserved for console / homepage:
    SovereignBrowserEngine().web_search(query) -> list[SearchResult]
        each result: .title  .url  .snippet  .trust_score
    .fetch_page(url, use_browser=False) -> PageContent(.url,.title,.text,.links)
"""

from __future__ import annotations

import html
import re
import urllib.parse
from dataclasses import dataclass, field

__all__ = ["SovereignBrowserEngine", "SearchResult", "PageContent"]

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
_DDG_HTML = "https://html.duckduckgo.com/html/"


@dataclass
class SearchResult:
    title: str = ""
    url: str = ""
    snippet: str = ""
    trust_score: str = "web"


@dataclass
class PageContent:
    url: str = ""
    title: str = ""
    text: str = ""
    links: list[str] = field(default_factory=list)


def _fetch(url: str, *, params: dict | None = None, timeout: int = 15) -> str:
    """GET *url* and return decoded body text. Masked via curl_cffi if available,
    else stdlib urllib. Returns '' on any failure (never raises)."""
    full = url + ("?" + urllib.parse.urlencode(params) if params else "")
    # Primary: curl_cffi with a real-browser TLS/JA3 fingerprint.
    try:
        from curl_cffi import requests as creq  # type: ignore

        r = creq.get(full, impersonate="chrome", timeout=timeout)
        return r.text or ""
    except Exception:
        pass
    # Fallback: our own stdlib HTTP client.
    try:
        from ghosted.http import sovereign_http_get

        r = sovereign_http_get(full, connect_timeout=timeout, read_timeout=timeout)
        return r.body.decode("utf-8", "replace") if r.success else ""
    except Exception:
        return ""


def _unwrap_ddg(href: str) -> str:
    """DuckDuckGo HTML wraps targets as /l/?uddg=<encoded>. Unwrap to the real URL."""
    if "uddg=" in href:
        q = urllib.parse.urlparse(href).query
        v = urllib.parse.parse_qs(q).get("uddg")
        if v:
            return urllib.parse.unquote(v[0])
    if href.startswith("//"):
        return "https:" + href
    return href


class SovereignBrowserEngine:
    """Standalone web search + page fetch. No rabbit, no browser daemon."""

    def web_search(self, query: str, *, limit: int = 20) -> list[SearchResult]:
        query = (query or "").strip()
        if not query:
            return []
        body = _fetch(_DDG_HTML, params={"q": query})
        if not body:
            return []
        try:
            return self._parse_bs4(body, limit)
        except Exception:
            return self._parse_regex(body, limit)

    def _parse_bs4(self, body: str, limit: int) -> list[SearchResult]:
        from bs4 import BeautifulSoup  # type: ignore

        soup = BeautifulSoup(body, "html.parser")
        out: list[SearchResult] = []
        for res in soup.select("div.result, div.web-result"):
            a = res.select_one("a.result__a")
            if not a:
                continue
            sn = res.select_one(".result__snippet")
            out.append(
                SearchResult(
                    title=a.get_text(" ", strip=True),
                    url=_unwrap_ddg(a.get("href", "")),
                    snippet=sn.get_text(" ", strip=True) if sn else "",
                    trust_score="web",
                )
            )
            if len(out) >= limit:
                break
        return out

    def _parse_regex(self, body: str, limit: int) -> list[SearchResult]:
        out: list[SearchResult] = []
        for m in re.finditer(
            r'result__a"[^>]*href="(?P<href>[^"]+)"[^>]*>(?P<title>.*?)</a>', body, re.S
        ):
            title = html.unescape(re.sub(r"<[^>]+>", "", m.group("title"))).strip()
            out.append(
                SearchResult(
                    title=title,
                    url=_unwrap_ddg(html.unescape(m.group("href"))),
                    snippet="",
                    trust_score="web",
                )
            )
            if len(out) >= limit:
                break
        return out

    def fetch_page(self, url: str, *, use_browser: bool = False) -> PageContent:
        body = _fetch(url)
        if not body:
            return PageContent(url=url)
        title, text, links = "", "", []
        try:
            from bs4 import BeautifulSoup  # type: ignore

            soup = BeautifulSoup(body, "html.parser")
            if soup.title and soup.title.string:
                title = soup.title.string.strip()
            text = soup.get_text(" ", strip=True)
            links = [a["href"] for a in soup.find_all("a", href=True)]
        except Exception:
            text = html.unescape(re.sub(r"<[^>]+>", " ", body)).strip()
        return PageContent(url=url, title=title, text=text, links=links)

    def youtube_search(self, query: str, *, limit: int = 10) -> list[SearchResult]:
        """Search filtered to YouTube. (Same engine, site-scoped query.)"""
        return self.web_search(f"{query} site:youtube.com", limit=limit)

    def tor_fetch(self, url: str) -> PageContent:
        """Fetch over Tor (socks5h://127.0.0.1:9050) when a Tor daemon is up.

        Tries curl_cffi through the local SOCKS proxy; falls back to a plain
        fetch (clearnet) so the call never hard-fails when Tor is absent."""
        try:
            from curl_cffi import requests as creq  # type: ignore

            r = creq.get(
                url,
                impersonate="chrome",
                proxies={"https": "socks5h://127.0.0.1:9050", "http": "socks5h://127.0.0.1:9050"},
                timeout=30,
            )
            from bs4 import BeautifulSoup  # type: ignore

            soup = BeautifulSoup(r.text or "", "html.parser")
            return PageContent(
                url=url,
                title=(soup.title.string or "").strip() if soup.title else "",
                text=soup.get_text(" ", strip=True),
                links=[a["href"] for a in soup.find_all("a", href=True)],
            )
        except Exception:
            return self.fetch_page(url)
