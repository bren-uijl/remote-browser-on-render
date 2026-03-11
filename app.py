import ipaddress
import os
import re
import socket
from urllib.parse import urljoin, quote, urlparse

import requests
from flask import Flask, request, render_template, jsonify, Response

VERSION = "1.0.3"
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
    """Absolute origin of this proxy (e.g. https://remote-browser-on-render.onrender.com)."""
    # Use the incoming request's host so it works both locally and on Render
    return request.host_url.rstrip("/")


def _rewrite_css_urls(css_text: str, base_url: str, proxy_base: str) -> str:
    """Rewrite url(...) references inside CSS so they route through the proxy."""
    def replace_css_url(match):
        inner = match.group(1).strip().strip("'\"")

        # Skip fragment-only anchors, data URIs, and paths already pointing at our proxy
        if inner.startswith(("#", "data:", "/fetch?")):
            return match.group(0)

        # Protocol-relative → assume https
        if inner.startswith("//"):
            absolute = "https:" + inner
        elif inner.startswith(("http://", "https://")):
            absolute = inner
        else:
            absolute = urljoin(base_url, inner)

        proxied = proxy_base + "/fetch?url=" + quote(absolute, safe="")
        return f"url('{proxied}')"

    return re.sub(r"url\(([^)]+)\)", replace_css_url, css_text)


@app.route("/")
def index():
    return render_template("index.html", version=VERSION)


@app.route("/fetch")
def fetch_route():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "Missing url parameter"}), 400

    # Ensure URL includes a scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # SSRF protection: block private / internal addresses
    safe, reason = _is_safe_url(url)
    if not safe:
        return jsonify({"error": f"Blocked: {reason}"}), 403

    proxy_base = _proxy_base()

    try:
        resp = requests.get(url, timeout=30, verify=True)
        content_type = resp.headers.get("Content-Type", "text/html")

        if content_type and "text/html" in content_type.lower():
            encoding = resp.encoding or resp.apparent_encoding or "utf-8"
            html = resp.text

            # Insert a <base> tag so the browser resolves relative URLs against
            # the original host — this alone isn't enough because the browser
            # would then fetch those resources directly (bypassing the proxy),
            # but it ensures urljoin() below resolves paths correctly.
            if re.search(r"<head", html, re.IGNORECASE):
                html = re.sub(
                    r"(<head[^>]*>)",
                    r'\1<base href="' + url + r'">',
                    html,
                    flags=re.IGNORECASE,
                )

            def replace_attr_url(match):
                attr       = match.group(1)
                quote_char = match.group(2)
                link       = match.group(3)

                # Skip fragment-only anchors — they are page-internal and must
                # never be proxied (this was the root cause of the CORS errors).
                if link.startswith("#"):
                    return f"{attr}={quote_char}{link}{quote_char}"

                # Protocol-relative URLs
                if link.startswith("//"):
                    absolute = "https:" + link
                    proxied  = proxy_base + "/fetch?url=" + quote(absolute, safe="")
                    return f"{attr}={quote_char}{proxied}{quote_char}"

                # Already absolute — route through OUR proxy origin, not the
                # target host.  Without this fix the browser was requesting
                # topgear.com/fetch?url=... instead of ourserver.com/fetch?url=...
                if link.startswith(("http://", "https://")):
                    proxied = proxy_base + "/fetch?url=" + quote(link, safe="")
                    return f"{attr}={quote_char}{proxied}{quote_char}"

                # data: URIs — pass through untouched
                if link.startswith("data:"):
                    return f"{attr}={quote_char}{link}{quote_char}"

                # Relative URL — resolve against base and proxy
                absolute = urljoin(url, link)
                proxied  = proxy_base + "/fetch?url=" + quote(absolute, safe="")
                return f"{attr}={quote_char}{proxied}{quote_char}"

            # Match src/href for ALL values (including absolute ones) so we can
            # rewrite them through the correct proxy origin.
            pattern = r'(src|href)=([\'"])([^\'"]+?)\2'
            html = re.sub(pattern, replace_attr_url, html, flags=re.IGNORECASE)

            # Rewrite CSS url() references (inline styles + <style> blocks)
            html = _rewrite_css_urls(html, url, proxy_base)

            content = html.encode(encoding, errors="replace")

        elif content_type and "text/css" in content_type.lower():
            encoding = resp.encoding or resp.apparent_encoding or "utf-8"
            css = _rewrite_css_urls(resp.text, url, proxy_base)
            content = css.encode(encoding, errors="replace")

        else:
            content = resp.content

        return Response(content, content_type=content_type)

    except requests.exceptions.SSLError as e:
        return jsonify({"error": f"SSL error while fetching URL: {e}"}), 502
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
