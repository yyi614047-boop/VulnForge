"""Bounded public-document retrieval and source-attributed web search."""
import hashlib
import ipaddress
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from html.parser import HTMLParser
from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field

from app.tools.registry import ToolOutput, ToolRegistry


class FetchParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str


class SearchParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=500)
    limit: int = Field(default=5, ge=1, le=10)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class PlainText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts, self.hidden = [], 0
    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.hidden += 1
        if tag in {"p", "div", "br", "li", "h1", "h2", "h3", "pre"}:
            self.parts.append("\n")
    def handle_endtag(self, tag):
        if tag in {"script", "style"}:
            self.hidden = max(0, self.hidden-1)
    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


class WebResearch:
    def __init__(self, *, opener=None, resolver=None, allowed_domains: Iterable[str] = ()):
        self.opener = opener or urllib.request.build_opener(NoRedirect())
        self.resolver = resolver or socket.getaddrinfo
        self.allowed_domains = self._normalize_domains(allowed_domains)

    @staticmethod
    def _normalize_domains(domains):
        normalized = set()
        for domain in domains:
            if not isinstance(domain, str) or not domain.strip():
                raise ValueError("Allowed domains must be non-empty host names")
            value = domain.strip().rstrip(".").lower()
            if "://" in value or "/" in value or ":" in value or "*" in value or "@" in value:
                raise ValueError("Allowed domains must be host names without schemes, paths, ports, or wildcards")
            try:
                value = value.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise ValueError("Invalid allowed domain") from exc
            if len(value) > 253 or any(not label or len(label) > 63 for label in value.split(".")):
                raise ValueError("Invalid allowed domain")
            normalized.add(value)
        if len(normalized) > 20:
            raise ValueError("At most 20 allowed domains may be configured")
        return frozenset(normalized)

    def _domain_allowed(self, hostname):
        if self.allowed_domains is None:
            return True
        host = hostname.rstrip(".").lower().encode("idna").decode("ascii")
        return any(host == domain or host.endswith("." + domain) for domain in self.allowed_domains)

    def validate_url(self, url, *, enforce_allowlist=True):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.port not in {None, 443}:
            raise ValueError("Use a public HTTPS URL without credentials or custom ports")
        if enforce_allowlist and not self.allowed_domains:
            raise ValueError("Web access is disabled because the domain allowlist is empty")
        if enforce_allowlist and not self._domain_allowed(parsed.hostname):
            raise ValueError(f"Research domain is not allowlisted: {parsed.hostname}")
        addresses = self.resolver(parsed.hostname, 443, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(row[4][0]).is_global for row in addresses):
            raise ValueError("Private/local research endpoints are not supported")

    def download(self, url, *, enforce_allowlist=True, redirect_domains=None):
        for _ in range(4):
            self.validate_url(url, enforce_allowlist=enforce_allowlist)
            if redirect_domains and not self._matches_domains(urllib.parse.urlsplit(url).hostname, redirect_domains):
                raise ValueError("Research provider redirected outside its allowed host")
            try:
                response = self.opener.open(urllib.request.Request(url, headers={"User-Agent": "LocalLabResearch/0.1"}), timeout=20)
            except urllib.error.HTTPError as exc:
                if exc.code in {301, 302, 303, 307, 308} and exc.headers.get("Location"):
                    url = urllib.parse.urljoin(url, exc.headers["Location"])
                    exc.close()
                    if redirect_domains and not self._matches_domains(
                        urllib.parse.urlsplit(url).hostname, redirect_domains
                    ):
                        raise ValueError("Research provider redirected outside its allowed host")
                    continue
                raise
            with response:
                raw = response.read(1048577)
                if len(raw) > 1048576:
                    raise ValueError("Research document exceeds 1 MiB")
                return url, raw, response.headers.get_content_type(), response.headers.get_content_charset() or "utf-8"
        raise ValueError("Too many research redirects")

    @staticmethod
    def _matches_domains(hostname, domains):
        if not hostname:
            return False
        host = hostname.rstrip(".").lower()
        return any(host == domain or host.endswith("." + domain) for domain in domains)

    def fetch(self, params):
        url, raw, kind, encoding = self.download(params.url)
        if not (kind.startswith("text/") or kind in {"application/json", "application/xml", "application/rss+xml"}):
            raise ValueError("Research supports text/HTML/JSON/XML documents only")
        text = raw.decode(encoding, errors="replace")
        if kind == "text/html":
            parser = PlainText()
            parser.feed(text)
            text = "\n".join(line.strip() for line in "".join(parser.parts).splitlines() if line.strip())
        evidence = {"requested_url": params.url, "url": url, "sha256": hashlib.sha256(raw).hexdigest(),
                    "fetched_at": datetime.now(timezone.utc).isoformat(), "content_type": kind,
                    "text": text[:100000], "truncated": len(text) > 100000}
        return ToolOutput(evidence["text"], evidence)

    def search(self, params):
        if not self.allowed_domains:
            raise ValueError("Web search is disabled because the domain allowlist is empty")
        query = params.query
        if self.allowed_domains:
            site_filter = " OR ".join(f"site:{domain}" for domain in sorted(self.allowed_domains))
            query = f"{query} ({site_filter})"
        url = "https://www.bing.com/search?" + urllib.parse.urlencode({"q": query, "format": "rss"})
        _, raw, _, _ = self.download(
            url, enforce_allowlist=False, redirect_domains=("bing.com",)
        )
        root = ET.fromstring(raw)
        hits = [{"title": item.findtext("title", ""), "url": item.findtext("link", ""),
                 "snippet": item.findtext("description", "")} for item in root.findall("./channel/item")]
        hits = [h for h in hits if h["url"].startswith("https://")]
        hits = [
            hit for hit in hits
            if self._valid_allowlisted_source(hit["url"])
        ]
        hits = hits[:params.limit]
        return ToolOutput(json.dumps(hits), {"query": params.query, "provider": "bing-rss", "hits": hits})

    def _valid_allowlisted_source(self, url):
        try:
            parsed = urllib.parse.urlsplit(url)
            return (
                parsed.scheme == "https"
                and parsed.hostname is not None
                and parsed.username is None
                and parsed.password is None
                and parsed.port in {None, 443}
                and self._domain_allowed(parsed.hostname)
            )
        except (UnicodeError, ValueError):
            return False

    def registry(self):
        registry = ToolRegistry()
        registry.register("search_web", SearchParams, self.search)
        registry.register("fetch_public_document", FetchParams, self.fetch)
        return registry
