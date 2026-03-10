import os
from flask import Flask, request, render_template, jsonify, Response
import requests

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

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
        # Forward the content type from the fetched response, default to text/html
        content_type = resp.headers.get('Content-Type', 'text/html')
        return Response(resp.content, content_type=content_type)
    except Exception as e:
        return jsonify({'error': f'Failed to fetch URL: {e}'}), 500

if __name__ == '__main__':
    # Render uses PORT environment variable
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
