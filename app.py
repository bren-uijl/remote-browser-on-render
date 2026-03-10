import os
from flask import Flask, request, render_template, jsonify, Response
import requests
import re
from urllib.parse import urljoin, quote

VERSION = "1.0.1"
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html', version=VERSION)

@app.route('/fetch')
def fetch_route():
    url = request.args.get('url')
    if not url:
        return jsonify({'error': 'Missing url parameter'}), 400
    # Ensure URL includes a scheme
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    try:
        resp = requests.get(url, timeout=30, verify=False)
        content_type = resp.headers.get('Content-Type', 'text/html')
        # If the response is HTML, rewrite URLs so that all resources are loaded through the proxy
        if content_type and 'text/html' in content_type.lower():
            # Decode using response encoding or default UTF-8
            encoding = resp.encoding if resp.encoding else 'utf-8'
            html = resp.text
            # Insert a <base> tag so that root‑relative URLs (e.g. "/_next/...") resolve to the original host
            if re.search(r'<head', html, re.IGNORECASE):
                html = re.sub(r'(<head[^>]*>)', r'\1<base href="' + url + r'">', html, flags=re.IGNORECASE)
            # Function to replace relative src/href attributes with proxy URLs
            def replace_relative(match):
                attr = match.group(1)
                quote_char = match.group(2)
                link = match.group(3)
                # Leave absolute URLs, protocol‑relative URLs, and data URIs unchanged
                if link.startswith(('http://', 'https://', '//', 'data:')):
                    return f"{attr}={quote_char}{link}{quote_char}"
                # Compute absolute URL based on the original request URL
                absolute = urljoin(url, link)
                # Route through the proxy
                proxied = '/fetch?url=' + quote(absolute, safe='')
                return f"{attr}={quote_char}{proxied}{quote_char}"
            # Regex to find src or href attributes with relative URLs (excluding already absolute ones)
            pattern = r'(src|href)=([\'\"])(?!https?://|//|data:)([^\'\"]+?)\2'
            new_html = re.sub(pattern, replace_relative, html, flags=re.IGNORECASE)
            content = new_html.encode(encoding)
        else:
            content = resp.content
        return Response(content, content_type=content_type)
    except Exception as e:
        return jsonify({'error': f'Failed to fetch URL: {e}'}), 500

@app.route('/version')
def version():
    return jsonify({'version': VERSION})

if __name__ == '__main__':
    # Render uses PORT environment variable
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
