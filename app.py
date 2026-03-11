import ipaddress
import os
import re
import socket
from urllib.parse import urljoin, quote, urlparse

import requests
from flask import Flask, request, render_template, jsonify, Response

VERSION = "1.0.5"
app = Flask(__name__)

# Private/reserved IP ranges blocked for SSRF protection
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_safe_url(url: str) -> tuple[bool, str]:
    """Return (True, '') when the URL is safe to fetch, or (False, reason) otherwise."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "Only http and https schemes are allowed"
    hostname = parsed.hostname
    if not hostname:
        return False, "Could not determine hostname"
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False, f"Could not resolve hostname: {hostname}"
    for _family, _type, _proto, _canonname, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Invalid IP address: {ip_str}"
        if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved:
            return False, f"Access to private/reserved address {ip_str} is not allowed"
        for network in _BLOCKED_NETWORKS:
            if ip in network:
                return False, f"Access to blocked network range {network} is not allowed"
    return True, ""


def _proxy_base() -> str:
    """
    Return the absolute origin of this proxy (scheme + host, no trailing slash).

    On Render (and most PaaS), TLS is terminated at the load balancer and the
    Flask app only sees plain HTTP internally.  X-Forwarded-Proto carries the
    scheme the client actually used, so we must honour it — otherwise every
    /fetch?url=... link we embed is http://, which the browser blocks as mixed
    content when the outer page is served over HTTPS.
    """
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
    return f"{scheme}://{request.host}"


def _to_https(url: str) -> str:
    """Upgrade http:// to https:// so proxied sub-requests never trigger mixed-content blocks."""
    if url.startswith("http://"):
        return "https://" + url[7:]
    return url


def _make_proxy_url(target: str, proxy_base: str) -> str:
    """Build the full proxy URL for a target, always on HTTPS."""
    return proxy_base + "/fetch?url=" + quote(_to_https(target), safe="")


def _resolve(link: str, base_url: str, proxy_base: str) -> str | None:
    """
    Turn any link value into a proxy URL.
    Returns None when the link should be left untouched (fragment, data URI, etc.).
    """
    if not link or link.startswith(("#", "data:", "javascript:", "mailto:", "tel:")):
        return None
    if link.startswith("//"):
        return _make_proxy_url("https:" + link, proxy_base)
    if link.startswith(("http://", "https://")):
        return _make_proxy_url(link, proxy_base)
    # Relative URL
    return _make_proxy_url(urljoin(base_url, link), proxy_base)


# ── HTML attribute rewriting ───────────────────────────────────────────────────

# Attributes that carry a single URL
_SINGLE_URL_ATTRS = re.compile(
    r'\b(src|href|action|data-src|poster|background)=([\'"])(.*?)\2',
    re.IGNORECASE | re.DOTALL,
)

# srcset: "url 1x, url 2x, ..."
_SRCSET_ATTR = re.compile(r'\bsrcset=([\'"])(.*?)\1', re.IGNORECASE | re.DOTALL)


def _rewrite_html(html: str, base_url: str, proxy_base: str) -> str:
    def replace_single(m):
        attr, q, link = m.group(1), m.group(2), m.group(3)
        proxied = _resolve(link.strip(), base_url, proxy_base)
        if proxied is None:
            return m.group(0)
        return f'{attr}={q}{proxied}{q}'

    def replace_srcset(m):
        q, value = m.group(1), m.group(2)
        parts = []
        for entry in value.split(","):
            entry = entry.strip()
            if not entry:
                continue
            tokens = entry.split()
            link = tokens[0]
            descriptor = (" " + " ".join(tokens[1:])) if len(tokens) > 1 else ""
            proxied = _resolve(link, base_url, proxy_base)
            parts.append((proxied or link) + descriptor)
        return f'srcset={q}{", ".join(parts)}{q}'

    html = _SINGLE_URL_ATTRS.sub(replace_single, html)
    html = _SRCSET_ATTR.sub(replace_srcset, html)
    return html


# ── CSS rewriting ──────────────────────────────────────────────────────────────

_CSS_URL    = re.compile(r'url\(([^)]+)\)', re.IGNORECASE)
_CSS_IMPORT = re.compile(r'@import\s+[\'"]([^\'"]+)[\'"]', re.IGNORECASE)


def _rewrite_css(css: str, base_url: str, proxy_base: str) -> str:
    def replace_url(m):
        inner = m.group(1).strip().strip("'\"")
        proxied = _resolve(inner, base_url, proxy_base)
        if proxied is None:
            return m.group(0)
        return f"url('{proxied}')"

    def replace_import(m):
        link = m.group(1)
        proxied = _resolve(link, base_url, proxy_base)
        if proxied is None:
            return m.group(0)
        return f'@import "{proxied}"'

    css = _CSS_URL.sub(replace_url, css)
    css = _CSS_IMPORT.sub(replace_import, css)
    return css


# ── Flask routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", version=VERSION)


@app.route("/fetch")
def fetch_route():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "Missing url parameter"}), 400

    if not url.startswith(("http://", "https://")):
        url = "https://" + url          # default to HTTPS

    safe, reason = _is_safe_url(url)
    if not safe:
        return jsonify({"error": f"Blocked: {reason}"}), 403

    proxy_base = _proxy_base()

    try:
        resp = requests.get(
            url,
            timeout=30,
            verify=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; RemoteBrowser/1.0)"},
            allow_redirects=True,
        )
        content_type = resp.headers.get("Content-Type", "text/html")

        if "text/html" in content_type.lower():
            encoding = resp.encoding or resp.apparent_encoding or "utf-8"
            html = resp.text

            # Remove any existing <base> tag — it would cause the browser to
            # resolve missed URLs directly against the original host (bypassing
            # the proxy and triggering mixed-content blocks).
            html = re.sub(r'<base[^>]*>', '', html, flags=re.IGNORECASE)

            html = _rewrite_html(html, url, proxy_base)
            html = _rewrite_css(html, url, proxy_base)   # covers inline <style> blocks

            # Inject the runtime intercept script as the very first thing inside
            # <head> so it is active before any other script on the page runs.
            # It patches fetch/XHR/src-writes so lazy-loaded resources also go
            # through the proxy instead of hitting the original host directly.
            inject = (
                f'<script>window.__PROXY_BASE__={repr(proxy_base)};</script>'
                '<script src="/static/proxy-intercept.js"></script>'
            )
            html = re.sub(
                r'(<head[^>]*>)',
                r'\1' + inject,
                html, count=1, flags=re.IGNORECASE,
            )
            if '<head' not in html.lower():
                html = inject + html

            content = html.encode(encoding, errors="replace")

        elif "text/css" in content_type.lower():
            encoding = resp.encoding or resp.apparent_encoding or "utf-8"
            content = _rewrite_css(resp.text, url, proxy_base).encode(encoding, errors="replace")

        else:
            content = resp.content

        # Strip headers that would prevent the browser from rendering the
        # proxied content inside our iframe.
        skip_headers = {
            "content-security-policy",
            "x-frame-options",
            "content-encoding",   # requests already decoded the body for us
            "transfer-encoding",
        }
        headers = {
            k: v for k, v in resp.headers.items()
            if k.lower() not in skip_headers
        }
        # Ensure the browser never blocks our proxy responses as mixed content
        headers["Content-Security-Policy"] = "upgrade-insecure-requests"

        return Response(content, content_type=content_type, headers=headers)

    except requests.exceptions.SSLError as e:
        return jsonify({"error": f"SSL error: {e}"}), 502
    except requests.exceptions.ConnectionError as e:
        return jsonify({"error": f"Connection error: {e}"}), 502
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timed out"}), 504
    except Exception as e:
        return jsonify({"error": f"Failed to fetch URL: {e}"}), 500


@app.route("/version")
def version():
    return jsonify({"version": VERSION})


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
