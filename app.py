import ipaddress
import json
import os
import re
import secrets
import socket
import threading
from urllib.parse import urljoin, quote, urlparse, urlencode

import requests
from flask import Flask, request, render_template, jsonify, Response, stream_with_context
from openai import OpenAI

VERSION = "1.0.7"
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ── NVIDIA / OpenAI client ────────────────────────────────────────────────────
_nvidia_client = OpenAI(
    api_key=os.environ.get(
        "NVIDIA_API_KEY",
        "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"
    ),
    base_url="https://integrate.api.nvidia.com/v1",
)
AI_MODEL = "openai/gpt-oss-120b"

# ── Server-side cookie jars ───────────────────────────────────────────────────
# Key: session_id (string)  →  Value: requests.Session
_sessions: dict[str, requests.Session] = {}
_sessions_lock = threading.Lock()
SESSION_COOKIE = "_rbsid"

def _get_session(sid: str) -> requests.Session:
    with _sessions_lock:
        if sid not in _sessions:
            s = requests.Session()
            s.headers.update({
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/123.0.0.0 Safari/537.36"
                )
            })
            _sessions[sid] = s
        return _sessions[sid]

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
        return False, "Only http and https schemes are allowed"
    hostname = parsed.hostname
    if not hostname:
        return False, "Could not determine hostname"
    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False, f"Could not resolve hostname: {hostname}"
    for _f, _t, _p, _c, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, f"Invalid IP address: {ip_str}"
        if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved:
            return False, f"Access to private/reserved address {ip_str} is not allowed"
        for net in _BLOCKED_NETWORKS:
            if ip in net:
                return False, f"Access to blocked network {net} is not allowed"
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
    r'\b(src|href|action|data-src|data-href|poster|background|content)=([\'"])(.*?)\2',
    re.IGNORECASE | re.DOTALL,
)
_SRCSET_ATTR  = re.compile(r'\bsrcset=([\'"])(.*?)\1', re.IGNORECASE | re.DOTALL)
_META_REFRESH = re.compile(r'(<meta[^>]+http-equiv=["\']refresh["\'][^>]*>)', re.IGNORECASE)

# Noscript tags break things in proxied pages — just strip them
_NOSCRIPT = re.compile(r'<noscript[^>]*>.*?</noscript>', re.IGNORECASE | re.DOTALL)

# React / Next.js hydration: the server HTML and client JS disagree because
# we rewrote URLs.  The only reliable fix is to disable React hydration by
# stripping the data-reactroot attribute and __NEXT_DATA__ script so React
# never tries to reconcile the server HTML with its own virtual DOM.
_NEXT_DATA   = re.compile(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>.*?</script>', re.IGNORECASE | re.DOTALL)
_REACT_ROOT  = re.compile(r'\s*data-reactroot=["\'][^"\']*["\']', re.IGNORECASE)


def _rewrite_html(html: str, base_url: str, proxy_base: str) -> str:
    # Strip noscript (often contains un-rewritten fallback URLs)
    html = _NOSCRIPT.sub('', html)
    # Kill __NEXT_DATA__ to prevent hydration mismatch crash
    html = _NEXT_DATA.sub('', html)
    html = _REACT_ROOT.sub('', html)
    # Strip meta-refresh redirects
    html = _META_REFRESH.sub('', html)

    def replace_single(m):
        attr, q, link = m.group(1), m.group(2), m.group(3).strip()
        # Skip meta tags that aren't refresh (og:image etc handled separately)
        if attr.lower() == "content":
            # Only proxy if it looks like a URL
            if not link.startswith(("http://", "https://", "//", "/")):
                return m.group(0)
        proxied = _resolve(link, base_url, proxy_base)
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

    css = _CSS_URL.sub(replace_url, css)
    css = _CSS_IMPORT.sub(replace_import, css)
    return css

# ── Headers to strip from proxy responses ────────────────────────────────────
_STRIP_RESPONSE_HEADERS = {
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "content-encoding",
    "transfer-encoding",
    "strict-transport-security",
}
# Headers to never forward to the target
_STRIP_REQUEST_HEADERS = {
    "host", "content-length", "transfer-encoding",
    "connection", "accept-encoding",
}

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    resp = Response(render_template("index.html", version=VERSION))
    if not request.cookies.get(SESSION_COOKIE):
        resp.set_cookie(SESSION_COOKIE, secrets.token_hex(16), samesite="Lax")
    return resp


@app.route("/fetch")
def fetch_route():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "Missing url parameter"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    safe, reason = _is_safe_url(url)
    if not safe:
        return jsonify({"error": f"Blocked: {reason}"}), 403

    proxy_base = _proxy_base()
    sid = request.cookies.get(SESSION_COOKIE, "anonymous")
    sess = _get_session(sid)

    # Forward safe request headers from browser to target
    fwd_headers = {
        k: v for k, v in request.headers
        if k.lower() not in _STRIP_REQUEST_HEADERS
    }
    # Correct Host to the target host
    fwd_headers["Host"] = urlparse(url).netloc

    try:
        resp = sess.get(url, timeout=30, verify=True, headers=fwd_headers, allow_redirects=True)
        content_type = resp.headers.get("Content-Type", "text/html")

        if "text/html" in content_type.lower():
            encoding = resp.encoding or resp.apparent_encoding or "utf-8"
            html = resp.text

            html = re.sub(r'<base[^>]*>', '', html, flags=re.IGNORECASE)
            html = _rewrite_html(html, url, proxy_base)
            html = _rewrite_css(html, url, proxy_base)

            inject = (
                f'<script>window.__PROXY_BASE__={json.dumps(proxy_base)};'
                f'window.__PAGE_URL__={json.dumps(url)};</script>'
                '<script src="/static/proxy-intercept.js"></script>'
            )
            if re.search(r'<head', html, re.IGNORECASE):
                html = re.sub(r'(<head[^>]*>)', r'\1' + inject, html, count=1, flags=re.IGNORECASE)
            else:
                html = inject + html

            content = html.encode(encoding, errors="replace")

        elif "text/css" in content_type.lower():
            encoding = resp.encoding or resp.apparent_encoding or "utf-8"
            content = _rewrite_css(resp.text, url, proxy_base).encode(encoding, errors="replace")
        else:
            content = resp.content

        out_headers = {
            k: v for k, v in resp.headers.items()
            if k.lower() not in _STRIP_RESPONSE_HEADERS
        }
        # Forward cookies back to client via Set-Cookie,
        # but rewrite domain so the browser accepts them from our origin
        for cookie in resp.cookies:
            cookie_str = f"{cookie.name}={cookie.value}; Path=/; SameSite=None; Secure"
            out_headers.setdefault("Set-Cookie", cookie_str)

        out_headers["Content-Security-Policy"] = "upgrade-insecure-requests"
        # Allow our iframe
        out_headers["X-Frame-Options"] = "ALLOWALL"

        return Response(content, content_type=content_type, headers=out_headers)

    except requests.exceptions.SSLError as e:
        return jsonify({"error": f"SSL error: {e}"}), 502
    except requests.exceptions.ConnectionError as e:
        return jsonify({"error": f"Connection error: {e}"}), 502
    except requests.exceptions.Timeout:
        return jsonify({"error": "Request timed out"}), 504
    except Exception as e:
        return jsonify({"error": f"Failed to fetch URL: {e}"}), 500


@app.route("/ai/search")
def ai_search():
    """Lightweight web search used by the AI as a tool call."""
    q = request.args.get("q", "").strip()
    if not q:
        return jsonify({"error": "Missing q"}), 400
    try:
        params = {"q": q, "format": "json", "no_html": "1", "skip_disambig": "1"}
        r = requests.get(
            "https://api.duckduckgo.com/",
            params=params, timeout=10, verify=True,
            headers={"User-Agent": "remote-browser/1.0"},
        )
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
    """SSE streaming endpoint. Accepts {messages, page_url} from the client."""
    body = request.get_json(force=True, silent=True) or {}
    messages = body.get("messages", [])
    page_url  = body.get("page_url", "")

    if not messages:
        return jsonify({"error": "No messages"}), 400

    system_prompt = (
        "You are an intelligent browser assistant embedded in a server-side web proxy. "
        "You help the user understand, summarise, and interact with the web pages they are browsing. "
        f"The user is currently viewing: {page_url or 'the browser start page'}.\n\n"
        "You have access to a web_search tool. Use it whenever the user asks for current "
        "information, facts you're unsure about, or anything that benefits from a fresh search. "
        "Always cite sources when using search results. "
        "Be concise, helpful, and direct."
    )

    tools = [
        {
            "type": "function",
            "function": {
                "name": "web_search",
                "description": "Search the web for current information.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "The search query"}
                    },
                    "required": ["query"]
                }
            }
        }
    ]

    full_messages = [{"role": "system", "content": system_prompt}] + messages

    def generate():
        try:
            # First pass — may trigger tool calls
            stream = _nvidia_client.chat.completions.create(
                model=AI_MODEL,
                messages=full_messages,
                tools=tools,
                tool_choice="auto",
                temperature=0.7,
                top_p=1,
                max_tokens=4096,
                stream=True,
            )

            collected_tool_calls: dict[int, dict] = {}
            text_started = False

            for chunk in stream:
                delta = chunk.choices[0].delta if chunk.choices else None
                if not delta:
                    continue

                # Accumulate tool call fragments
                if delta.tool_calls:
                    for tc in delta.tool_calls:
                        idx = tc.index
                        if idx not in collected_tool_calls:
                            collected_tool_calls[idx] = {
                                "id": tc.id or "",
                                "name": tc.function.name if tc.function else "",
                                "args": ""
                            }
                        if tc.function:
                            if tc.function.name:
                                collected_tool_calls[idx]["name"] = tc.function.name
                            if tc.function.arguments:
                                collected_tool_calls[idx]["args"] += tc.function.arguments

                # Stream text tokens directly to the client
                if delta.content:
                    text_started = True
                    yield f"data: {json.dumps({'type': 'token', 'content': delta.content})}\n\n"

            # Execute tool calls and do a second pass if needed
            if collected_tool_calls and not text_started:
                tool_results = []
                for tc in collected_tool_calls.values():
                    if tc["name"] == "web_search":
                        try:
                            args = json.loads(tc["args"])
                            query = args.get("query", "")
                            yield f"data: {json.dumps({'type': 'search', 'query': query})}\n\n"
                            r = requests.get(
                                "https://api.duckduckgo.com/",
                                params={"q": query, "format": "json", "no_html": "1", "skip_disambig": "1"},
                                timeout=10, verify=True,
                                headers={"User-Agent": "remote-browser/1.0"},
                            )
                            data = r.json()
                            snippets = []
                            if data.get("AbstractText"):
                                snippets.append(f"[{data.get('Heading', query)}] {data['AbstractText']} ({data.get('AbstractURL','')})")
                            for rel in data.get("RelatedTopics", [])[:5]:
                                if isinstance(rel, dict) and rel.get("Text"):
                                    snippets.append(f"- {rel['Text']} ({rel.get('FirstURL','')})")
                            result_text = "\n".join(snippets) or "No results found."
                        except Exception as e:
                            result_text = f"Search failed: {e}"

                        tool_results.append({
                            "role": "tool",
                            "tool_call_id": tc["id"],
                            "content": result_text,
                        })

                if tool_results:
                    second_messages = full_messages + [
                        {"role": "assistant", "tool_calls": [
                            {"id": tc["id"], "type": "function",
                             "function": {"name": tc["name"], "arguments": tc["args"]}}
                            for tc in collected_tool_calls.values()
                        ]}
                    ] + tool_results

                    stream2 = _nvidia_client.chat.completions.create(
                        model=AI_MODEL,
                        messages=second_messages,
                        temperature=0.7,
                        top_p=1,
                        max_tokens=4096,
                        stream=True,
                    )
                    for chunk in stream2:
                        delta = chunk.choices[0].delta if chunk.choices else None
                        if delta and delta.content:
                            yield f"data: {json.dumps({'type': 'token', 'content': delta.content})}\n\n"

            yield f"data: {json.dumps({'type': 'done'})}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"

    return Response(
        stream_with_context(generate()),
        content_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # Disable nginx buffering on Render
        }
    )


@app.route("/version")
def version():
    return jsonify({"version": VERSION})


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
