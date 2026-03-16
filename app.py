import ipaddress
import json
import os
import re
import secrets
import socket
import threading
from urllib.parse import urljoin, quote, urlparse, parse_qs

import requests
from flask import Flask, request, render_template, jsonify, Response, stream_with_context
from openai import OpenAI

VERSION = "1.1.7"
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ── NVIDIA client ─────────────────────────────────────────────────────────────
_nvidia_client = OpenAI(
    api_key=os.environ.get(
        "NVIDIA_API_KEY",
        "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"
    ),
    base_url="https://integrate.api.nvidia.com/v1",
)
AI_MODEL = "openai/gpt-oss-120b"

# ── Session store ─────────────────────────────────────────────────────────────
_sessions: dict[str, requests.Session] = {}
_sessions_lock = threading.Lock()
SESSION_COOKIE = "_rbsid"

# CDN origin map per session — populated when we see script/link tags in HTML
_cdn_origins: dict[str, set] = {}
_cdn_lock = threading.Lock()

def _get_session(sid: str) -> requests.Session:
    with _sessions_lock:
        if sid not in _sessions:
            s = requests.Session()
            s.headers.update({"User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/123.0.0.0 Safari/537.36"
            )})
            _sessions[sid] = s
        return _sessions[sid]

def _record_cdn_origins(sid: str, html: str) -> None:
    """Store both origin AND full base path for every external script/link."""
    entries: set[str] = set()
    for m in re.finditer(r'(?:src|href)=["\'](https?://[^"\'\s>]+)', html, re.IGNORECASE):
        url_str = m.group(1)
        try:
            p = urlparse(url_str)
            if not p.netloc:
                continue
            origin = f"https://{p.netloc}"
            entries.add(origin)  # bare origin
            # Also store the directory path (e.g. https://githubassets.com/assets/)
            path_dir = p.path.rsplit("/", 1)[0] + "/" if "/" in p.path else "/"
            if path_dir != "/":
                entries.add(origin + path_dir)
        except Exception:
            pass
    if entries:
        with _cdn_lock:
            _cdn_origins.setdefault(sid, set()).update(entries)

def _get_cdn_origins(sid: str) -> list[str]:
    with _cdn_lock:
        # Return longer (more specific) paths first
        return sorted(_cdn_origins.get(sid, []), key=len, reverse=True)

# ── SSRF protection ───────────────────────────────────────────────────────────
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

def _is_safe_url(url: str) -> tuple[bool, str]:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "Only http/https allowed"
    hostname = parsed.hostname
    if not hostname:
        return False, "No hostname"
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False, f"Cannot resolve {hostname}"
    for _f, _t, _p, _c, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            return False, "Bad IP"
        if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved:
            return False, f"Blocked: {sockaddr[0]}"
        for net in _BLOCKED_NETWORKS:
            if ip in net:
                return False, f"Blocked network: {net}"
    return True, ""

# ── Proxy helpers ─────────────────────────────────────────────────────────────
def _proxy_base() -> str:
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme)
    return f"{scheme}://{request.host}"

def _to_https(url: str) -> str:
    return "https://" + url[7:] if url.startswith("http://") else url

def _make_proxy_url(target: str, proxy_base: str) -> str:
    return proxy_base + "/fetch?url=" + quote(_to_https(target), safe="")

def _resolve(link: str, base_url: str, proxy_base: str) -> str | None:
    if not link or link.startswith(("#", "data:", "javascript:", "mailto:", "tel:", "blob:")):
        return None
    if link.startswith("//"):
        return _make_proxy_url("https:" + link, proxy_base)
    if link.startswith(("http://", "https://")):
        return _make_proxy_url(link, proxy_base)
    return _make_proxy_url(urljoin(base_url, link), proxy_base)

# ── HTML rewriting ────────────────────────────────────────────────────────────
_SINGLE_URL_ATTRS = re.compile(
    r'\b(src|href|action|data-src|data-href|poster|background)=([\'"])(.*?)\2',
    re.IGNORECASE | re.DOTALL,
)
_SRCSET_ATTR  = re.compile(r'\bsrcset=([\'"])(.*?)\1', re.IGNORECASE | re.DOTALL)
_NOSCRIPT     = re.compile(r'<noscript[^>]*>.*?</noscript>', re.IGNORECASE | re.DOTALL)
_NEXT_DATA    = re.compile(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>.*?</script>', re.IGNORECASE | re.DOTALL)
_REACT_ROOT   = re.compile(r'\s*data-reactroot=["\'][^"\']*["\']', re.IGNORECASE)
_META_REFRESH = re.compile(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]*>', re.IGNORECASE)

def _rewrite_html(html: str, base_url: str, proxy_base: str) -> str:
    html = _NOSCRIPT.sub('', html)
    html = _NEXT_DATA.sub('', html)
    html = _REACT_ROOT.sub('', html)
    html = _META_REFRESH.sub('', html)

    def replace_single(m):
        attr, q, link = m.group(1), m.group(2), m.group(3).strip()
        proxied = _resolve(link, base_url, proxy_base)
        return f'{attr}={q}{proxied}{q}' if proxied else m.group(0)

    def replace_srcset(m):
        q, value = m.group(1), m.group(2)
        parts = []
        for entry in value.split(","):
            entry = entry.strip()
            if not entry:
                continue
            tokens = entry.split()
            proxied = _resolve(tokens[0], base_url, proxy_base)
            descriptor = (" " + " ".join(tokens[1:])) if len(tokens) > 1 else ""
            parts.append((proxied or tokens[0]) + descriptor)
        return f'srcset={q}{", ".join(parts)}{q}'

    html = _SINGLE_URL_ATTRS.sub(replace_single, html)
    html = _SRCSET_ATTR.sub(replace_srcset, html)
    # Force eager loading — lazy images never trigger in an iframe
    html = re.sub(r'loading=["\']lazy["\']', 'loading="eager"', html, flags=re.IGNORECASE)
    return html

# ── CSS rewriting ─────────────────────────────────────────────────────────────
_CSS_URL    = re.compile(r'url\(([^)]+)\)', re.IGNORECASE)
_CSS_IMPORT = re.compile(r'@import\s+[\'"]([^\'"]+)[\'"]', re.IGNORECASE)

def _rewrite_css(css: str, base_url: str, proxy_base: str) -> str:
    def replace_url(m):
        inner = m.group(1).strip().strip("'\"")
        proxied = _resolve(inner, base_url, proxy_base)
        return f"url('{proxied}')" if proxied else m.group(0)

    def replace_import(m):
        proxied = _resolve(m.group(1), base_url, proxy_base)
        return f'@import "{proxied}"' if proxied else m.group(0)

    return _CSS_IMPORT.sub(replace_import, _CSS_URL.sub(replace_url, css))

# ── Headers ───────────────────────────────────────────────────────────────────
_STRIP_RESPONSE = {
    "content-security-policy", "content-security-policy-report-only",
    "x-frame-options", "content-encoding", "transfer-encoding",
    "strict-transport-security",
}
_STRIP_REQUEST = {
    "host", "content-length", "transfer-encoding",
    "connection", "accept-encoding",
}

def _fwd_request_headers(target_url: str) -> dict:
    h = {k: v for k, v in request.headers if k.lower() not in _STRIP_REQUEST}
    h["Host"] = urlparse(target_url).netloc
    return h

def _clean_response_headers(resp_headers: dict, base_url: str, proxy_base: str) -> dict:
    out = {k: v for k, v in resp_headers.items() if k.lower() not in _STRIP_RESPONSE}
    if "Location" in out:
        loc = out["Location"]
        abs_loc = _to_https(urljoin(base_url, loc))
        out["Location"] = proxy_base + "/fetch?url=" + quote(abs_loc, safe="")
    out["Content-Security-Policy"] = "upgrade-insecure-requests"
    out["X-Frame-Options"] = "ALLOWALL"
    return out

# ── Core proxy logic ──────────────────────────────────────────────────────────
def _do_proxy(url: str, sid: str, proxy_base: str) -> Response:
    """
    Fetch url through the session, rewrite content, return Response.
    Follows redirect chains server-side so:
      - cookies accumulate in the session jar across the full chain
      - the final content-URL is correct (not an intermediate redirect)
      - catch-all Referer resolution works correctly
    """
    sess = _get_session(sid)
    method  = request.method.upper()
    body    = request.get_data() if method in ("POST", "PUT", "PATCH") else None
    headers = _fwd_request_headers(url)

    # Follow redirect chain ourselves so session cookies are preserved
    MAX_REDIRECTS = 15
    current_url = url
    for _ in range(MAX_REDIRECTS):
        safe, reason = _is_safe_url(current_url)
        if not safe:
            return jsonify({"error": f"Blocked: {reason}"}), 403

        resp = sess.request(
            method=method,
            url=current_url,
            headers={**headers, "Host": urlparse(current_url).netloc},
            data=body,
            timeout=30,
            verify=True,
            allow_redirects=False,
        )

        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location", "")
            if not loc:
                break
            next_url = _to_https(urljoin(current_url, loc))
            # 303 / non-idempotent redirect → switch to GET
            if resp.status_code in (303,) or (resp.status_code == 302 and method == "POST"):
                method = "GET"
                body   = None
            current_url = next_url
            continue
        break

    content_type = resp.headers.get("Content-Type", "text/html")
    out_headers  = _clean_response_headers(dict(resp.headers), current_url, proxy_base)

    # Forward cookies from the entire chain (already in session jar, but also
    # send them to the browser so JS can read them if SameSite=None)
    for cookie in sess.cookies:
        out_headers.setdefault("Set-Cookie",
            f"{cookie.name}={cookie.value}; Path=/; SameSite=None; Secure")

    if "text/html" in content_type.lower():
        encoding = resp.encoding or resp.apparent_encoding or "utf-8"
        html = resp.text
        html = re.sub(r'<base[^>]*>', '', html, flags=re.IGNORECASE)
        _record_cdn_origins(sid, html)
        html = _rewrite_html(html, current_url, proxy_base)
        html = _rewrite_css(html, current_url, proxy_base)
        inject = (
            f'<script>window.__PROXY_BASE__={json.dumps(proxy_base)};'
            f'window.__PAGE_URL__={json.dumps(current_url)};</script>'
            f'<script src="/static/proxy-intercept.js?v={VERSION}"></script>'
        )
        if re.search(r'<head', html, re.IGNORECASE):
            html = re.sub(r'(<head[^>]*>)', r'\1' + inject, html, count=1, flags=re.IGNORECASE)
        else:
            html = inject + html
        out_headers.pop("Content-Length", None)
        return Response(html.encode(encoding, errors="replace"), content_type=content_type, headers=out_headers)

    elif "text/css" in content_type.lower():
        encoding = resp.encoding or resp.apparent_encoding or "utf-8"
        css = _rewrite_css(resp.text, current_url, proxy_base)
        out_headers.pop("Content-Length", None)
        return Response(css.encode(encoding, errors="replace"), content_type=content_type, headers=out_headers)

    else:
        out_headers.pop("Content-Length", None)
        return Response(resp.content, content_type=content_type, headers=out_headers)


def _proxy_asset(url: str, sid: str, referer: str = "") -> Response:
    """Stream a non-HTML asset (JS, CSS, image, video, font)."""
    sess    = _get_session(sid)
    headers = _fwd_request_headers(url)
    if referer:
        headers["Referer"] = referer
    body    = request.get_data() if request.method in ("POST", "PUT", "PATCH") else None
    try:
        r = sess.request(
            method=request.method,
            url=url,
            headers=headers,
            data=body,
            timeout=30,
            verify=True,
            allow_redirects=True,   # fine for assets
            stream=True,
        )
        out = {k: v for k, v in r.headers.items() if k.lower() not in _STRIP_RESPONSE}
        out.pop("Content-Length", None)
        return Response(
            r.iter_content(chunk_size=65536),
            status=r.status_code,
            content_type=r.headers.get("Content-Type", "application/octet-stream"),
            headers=out,
            direct_passthrough=True,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 502

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/static/proxy-intercept.js")
def serve_intercept():
    from flask import send_from_directory
    resp = send_from_directory(app.static_folder, "proxy-intercept.js")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"]        = "no-cache"
    return resp

@app.route("/")
def index():
    resp = Response(render_template("index.html", version=VERSION))
    if not request.cookies.get(SESSION_COOKIE):
        resp.set_cookie(SESSION_COOKIE, secrets.token_hex(16), samesite="Lax")
    return resp

@app.route("/fetch", methods=["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"])
def fetch_route():
    url = request.args.get("url", "").strip()
    if not url:
        # Browser navigated to /fetch without a url param — this happens when
        # a page's JS sets location to a relative URL that resolves to our /fetch.
        # Return a small HTML page that tells the iframe to reload via the proxy.
        referer = request.headers.get("Referer", "")
        if "/fetch?url=" in referer:
            try:
                from urllib.parse import parse_qs as _pqs
                page_url = _pqs(urlparse(referer).query).get("url", [""])[0]
                if page_url:
                    pb = _proxy_base()
                    # Redirect back to the same page
                    return Response(
                        f'<html><head><meta http-equiv="refresh" content="0;url={pb}/fetch?url={quote(page_url,safe="")}"></head></html>',
                        content_type="text/html"
                    )
            except Exception:
                pass
        return jsonify({"error": "Missing url parameter"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    proxy_base = _proxy_base()
    sid = request.cookies.get(SESSION_COOKIE, "anonymous")

    try:
        return _do_proxy(url, sid, proxy_base)
    except requests.exceptions.SSLError as e:
        return jsonify({"error": f"SSL error: {e}"}), 502
    except requests.exceptions.ConnectionError as e:
        return jsonify({"error": f"Connection error: {e}"}), 502
    except requests.exceptions.Timeout:
        return jsonify({"error": "Timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/ai/search")
def ai_search():
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "Missing q"}), 400
    try:
        r = requests.get("https://api.duckduckgo.com/",
            params={"q": q, "format": "json", "no_html": "1", "skip_disambig": "1"},
            timeout=10, verify=True,
            headers={"User-Agent": "remote-browser/1.0"})
        data = r.json()
        results = []
        if data.get("AbstractText"):
            results.append({"title": data.get("Heading", q), "snippet": data["AbstractText"], "url": data.get("AbstractURL", "")})
        for rel in data.get("RelatedTopics", [])[:6]:
            if isinstance(rel, dict) and rel.get("Text"):
                results.append({"title": rel.get("Text", "")[:80], "snippet": rel.get("Text", ""), "url": rel.get("FirstURL", "")})
        return jsonify({"query": q, "results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/ai/chat", methods=["POST"])
def ai_chat():
    body     = request.get_json(force=True, silent=True) or {}
    messages = body.get("messages", [])
    page_url = body.get("page_url", "")
    if not messages:
        return jsonify({"error": "No messages"}), 400

    last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")

    # Decide if we need a web search based on keywords
    search_keywords = ["search", "latest", "news", "current", "today", "recent",
                       "price", "who is", "what is", "when", "2024", "2025", "2026"]
    needs_search = any(k in last_user.lower() for k in search_keywords)

    search_context = ""
    search_query   = ""
    if needs_search:
        search_query = last_user[:200]
        try:
            r = requests.get("https://api.duckduckgo.com/",
                params={"q": search_query, "format": "json", "no_html": "1", "skip_disambig": "1"},
                timeout=8, verify=True, headers={"User-Agent": "remote-browser/1.0"})
            data = r.json()
            snippets = []
            if data.get("AbstractText"):
                snippets.append(f"[{data.get('Heading', search_query)}] {data['AbstractText']} ({data.get('AbstractURL', '')})")
            for rel in data.get("RelatedTopics", [])[:5]:
                if isinstance(rel, dict) and rel.get("Text"):
                    snippets.append(f"- {rel['Text']} ({rel.get('FirstURL', '')})")
            if snippets:
                search_context = "\n\nWeb search results:\n" + "\n".join(snippets)
        except Exception:
            pass

    system = (
        "You are an intelligent browser assistant embedded in a server-side web proxy. "
        f"The user is viewing: {page_url or 'the start page'}. "
        "Be concise and helpful. When citing sources use markdown links."
        + search_context
    )

    full_messages = [{"role": "system", "content": system}] + messages

    def generate():
        if search_query and search_context:
            yield f"data: {json.dumps({'type': 'search', 'query': search_query})}\n\n"
        try:
            stream = _nvidia_client.chat.completions.create(
                model=AI_MODEL,
                messages=full_messages,
                temperature=0.7,
                top_p=1,
                max_tokens=4096,
                stream=True,
            )
            for chunk in stream:
                if not chunk.choices:
                    continue
                delta = chunk.choices[0].delta
                if delta and delta.content:
                    yield f"data: {json.dumps({'type': 'token', 'content': delta.content})}\n\n"
            yield f"data: {json.dumps({'type': 'done'})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"

    return Response(stream_with_context(generate()),
        content_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/<path:asset_path>", methods=["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"])
def catch_all(asset_path):
    # Never catch our own routes
    if asset_path.startswith(("static/", "fetch", "ai/", "version")):
        return jsonify({"error": "Not found"}), 404

    # If path looks like a bare hostname (e.g. "youtube.com"), treat as navigation
    first_segment = asset_path.split("/")[0]
    if "." in first_segment and not first_segment.endswith((".js",".css",".png",".jpg",
            ".gif",".svg",".woff",".woff2",".ttf",".ico",".webp",".mp4",".webm",".json")):
        target = "https://" + asset_path
        if request.query_string:
            target += "?" + request.query_string.decode("utf-8", errors="replace")
        safe, reason = _is_safe_url(target)
        if not safe:
            return jsonify({"error": f"Blocked: {reason}"}), 403
        try:
            return _do_proxy(target, request.cookies.get(SESSION_COOKIE,"anonymous"), _proxy_base())
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    sid        = request.cookies.get(SESSION_COOKIE, "anonymous")
    proxy_base = _proxy_base()

    # Determine originating page from Referer
    page_url = ""
    referer  = request.headers.get("Referer", "")
    if "/fetch?url=" in referer:
        try:
            qs = parse_qs(urlparse(referer).query)
            page_url = qs.get("url", [""])[0]
        except Exception:
            pass

    if not page_url:
        return jsonify({"error": "Not found"}), 404

    # For ANY path with a valid referer (including API endpoints like /youtubei/v1/...)
    # try to proxy against the page origin and known CDN origins

    parsed_page   = urlparse(page_url)
    primary_origin = f"{parsed_page.scheme}://{parsed_page.netloc}"
    qs_str = ("?" + request.query_string.decode("utf-8", errors="replace")) if request.query_string else ""

    # Build candidates: primary origin + known CDN base paths (sorted longest first)
    cdn = _get_cdn_origins(sid)
    candidates = [primary_origin] + [c for c in cdn if c != primary_origin]

    for base in candidates:
        # base can be "https://origin" or "https://origin/path/"
        sep = "" if base.endswith("/") else "/"
        target_url = base + sep + asset_path + qs_str
        safe, _ = _is_safe_url(target_url)
        if not safe:
            continue
        try:
            # Pass page_url as Referer so CDN servers accept the request
            result = _proxy_asset(target_url, sid, referer=page_url)
            status = getattr(result, 'status_code', 200)
            if status in (404, 403):
                continue
            return result
        except Exception:
            continue

    return jsonify({"error": f"Not found: /{asset_path}"}), 404

@app.route("/ping")
def ping():
    """Keep-alive endpoint — called every 4 minutes by the UI to prevent Render spindown."""
    return ("", 204)

@app.route("/version")
def version_route():
    return jsonify({"version": VERSION})

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
