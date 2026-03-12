> [NOTE]
> It is known that there are much errors, i am fixing it, but please agree our poor coding...

# remote-browser-on-render

A server-side web proxy that lets you browse the internet through a browser-in-browser interface, deployable on [Render](https://render.com).

All HTTP requests are made **server-side** — the end user's IP never reaches the target website.

![Interface](https://img.shields.io/badge/UI-browser--in--browser-4f8ef7?style=flat-square) ![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white) ![Flask](https://img.shields.io/badge/Flask-3.1-black?style=flat-square&logo=flask) ![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)

---

## Features

- **Browser-in-browser UI** — tabbed interface with address bar, back/forward, reload, and a start page
- **Server-side proxying** — all requests are fetched by the server, not the client
- **HTML & CSS rewriting** — relative URLs and `url()` references in CSS are rewritten to route through the proxy
- **SSRF protection** — blocks requests to private IP ranges, loopback, link-local, and cloud metadata endpoints
- **SSL verification** — TLS certificates are verified on all outbound requests
- **Encoding-aware** — uses `apparent_encoding` as a fallback to avoid garbled characters

---

## Architecture

```
Browser  ──GET /──────────────►  Flask app  (Render)
         ◄── HTML (tab UI) ────
         
Browser  ──GET /fetch?url=X──►  Flask app
                                  └─ SSRF check
                                  └─ requests.get(X, verify=True)
                                  └─ rewrite HTML/CSS URLs
         ◄── proxied content ──
```

---

## Getting started

### Run locally

```bash
git clone https://github.com/bren-uijl/remote-browser-on-render.git
cd remote-browser-on-render
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000` in your browser.

### Deploy to Render

1. Fork or push this repo to GitHub.
2. Create a new **Web Service** on [render.com](https://render.com).
3. Connect your GitHub repository.
4. Set the following:

| Setting | Value |
|---|---|
| **Runtime** | Python 3 |
| **Build command** | `pip install -r requirements.txt` |
| **Start command** | `gunicorn app:app` |

5. Click **Deploy**. Render will automatically set the `PORT` environment variable.

---

## API

### `GET /`
Returns the browser UI.

### `GET /fetch?url=<url>`
Fetches the given URL server-side and returns the (rewritten) response.

| Status | Meaning |
|---|---|
| `200` | Success |
| `400` | Missing `url` parameter |
| `403` | Blocked by SSRF protection |
| `500` | Unexpected server error |
| `502` | SSL error or connection failure at the target |
| `504` | Request to target timed out |

### `GET /version`
Returns the current application version as JSON.

```json
{ "version": "1.0.2" }
```

---

## Security

### SSRF protection
The proxy resolves every hostname via DNS before making a request, and blocks any IP that falls within:

- `127.0.0.0/8` — loopback
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` — RFC 1918 private ranges
- `169.254.0.0/16` — link-local (includes the AWS/GCP metadata endpoint)
- `fc00::/7`, `fe80::/10`, `::1/128` — IPv6 private/loopback

### SSL verification
`verify=True` is set on all outbound `requests.get()` calls. Requests to hosts with invalid certificates will fail with a `502` response.

### Known limitations
- JavaScript-triggered navigations (`window.location = ...`) will break out of the proxy context.
- Pages that require cookies or session state (logins) will not work.
- Proxy traffic is not authenticated — consider adding auth middleware if you expose this publicly.

---

## Development

### Run tests

```bash
pip install pytest
pytest test_fetch_rewrite.py -v
```

### Project structure

```
.
├── app.py                  # Flask application
├── requirements.txt        # Pinned dependencies
├── templates/
│   └── index.html          # Browser-in-browser UI
├── static/
│   └── script.js           # (legacy, superseded by inline JS in index.html)
├── test_fetch_rewrite.py   # Unit tests
└── test_screenshot.py      # Screenshot smoke test
```

---

## License

MIT
