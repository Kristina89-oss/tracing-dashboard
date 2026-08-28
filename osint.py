"""
OSINT search for an address/hash: Chainabuse (scam reports) + public web
search (DuckDuckGo HTML, no key required) -- a plain query plus a query
refined with fraud/leak markers. Works for any string (ETH, BTC, XMR, tx
hash) -- Chainabuse and search engines match on text regardless of chain.
"""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path
from urllib.parse import unquote

import requests
from bs4 import BeautifulSoup

sys.path.insert(0, str(Path(__file__).parent.parent / "chainabuse-client"))
from chainabuse_client import ChainabuseClient, ChainabuseError  # noqa: E402

DDG_URL = "https://html.duckduckgo.com/html/"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


def check_chainabuse(address: str) -> dict:
    try:
        client = ChainabuseClient()
        return client.screen_address(address)
    except ChainabuseError as e:
        return {"count": 0, "reports": [], "error": str(e)}


def _web_search(query: str, max_results: int = 8) -> list[dict]:
    resp = requests.post(DDG_URL, data={"q": query}, headers={"User-Agent": UA}, timeout=20)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    results = []
    for item in soup.select(".result")[:max_results]:
        title_el = item.select_one(".result__a")
        snippet_el = item.select_one(".result__snippet")
        if not title_el:
            continue
        href = title_el.get("href", "")
        m = re.search(r"uddg=([^&]+)", href)
        if m:
            href = unquote(m.group(1))
        results.append({
            "title": title_el.get_text(strip=True),
            "url": href,
            "snippet": snippet_el.get_text(strip=True) if snippet_el else "",
        })
    return results


def web_exposure(query: str) -> list[dict]:
    """Exact string plus a query refined with fraud/leak markers.
    Deduplicated by URL; DDG is queried politely with a pause in between."""
    seen: dict[str, dict] = {}
    for q in (f'"{query}"', f'"{query}" scam OR fraud OR hack OR rugpull OR leaked'):
        try:
            for hit in _web_search(q):
                seen.setdefault(hit["url"], hit)
        except requests.RequestException:
            pass
        time.sleep(2)  # polite pause -- DDG rate-limits frequent automated requests
    return list(seen.values())[:15]
