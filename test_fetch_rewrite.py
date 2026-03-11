import socket
import unittest
from unittest.mock import patch, Mock
from app import app

def _safe_getaddrinfo(host, port, *args, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', port or 0))]

def _private_getaddrinfo(host, port, *args, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('192.168.1.1', port or 0))]


class TestFetchRewrite(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    # ── attribute URL rewriting ──────────────────────────────────────────────

    @patch('socket.getaddrinfo', side_effect=_safe_getaddrinfo)
    @patch('requests.get')
    def test_relative_script_and_link_rewrite(self, mock_get, _dns):
        html = '<html><head><script src="./dit_is_een_extern_script.js"></script></head>'
        html += '<body><a href="../other/page.html">Link</a></body></html>'
        mock_resp = Mock()
        mock_resp.headers = {'Content-Type': 'text/html; charset=utf-8'}
        mock_resp.text = html
        mock_resp.content = html.encode('utf-8')
        mock_resp.encoding = 'utf-8'
        mock_resp.apparent_encoding = 'utf-8'
        mock_get.return_value = mock_resp

        response = self.client.get('/fetch?url=https://example.com/subdir/index.html')
        self.assertEqual(response.status_code, 200)
        data = response.get_data(as_text=True)
        self.assertIn('fetch?url=https%3A%2F%2Fexample.com%2Fsubdir%2Fdit_is_een_extern_script.js', data)
        self.assertIn('fetch?url=https%3A%2F%2Fexample.com%2Fother%2Fpage.html', data)

    @patch('socket.getaddrinfo', side_effect=_safe_getaddrinfo)
    @patch('requests.get')
    def test_absolute_url_routed_through_proxy_origin(self, mock_get, _dns):
        """Bug fix: absolute URLs must be routed through OUR server, not the target host."""
        html = '<html><head></head><body><img src="https://example.com/img/logo.png"></body></html>'
        mock_resp = Mock()
        mock_resp.headers = {'Content-Type': 'text/html; charset=utf-8'}
        mock_resp.text = html
        mock_resp.content = html.encode('utf-8')
        mock_resp.encoding = 'utf-8'
        mock_resp.apparent_encoding = 'utf-8'
        mock_get.return_value = mock_resp

        response = self.client.get('/fetch?url=https://example.com/')
        self.assertEqual(response.status_code, 200)
        data = response.get_data(as_text=True)
        # Must point at localhost (our proxy), NOT at example.com/fetch?url=...
        self.assertIn('localhost/fetch?url=https%3A%2F%2Fexample.com%2Fimg%2Flogo.png', data)
        self.assertNotIn('example.com/fetch?url=', data)

    @patch('socket.getaddrinfo', side_effect=_safe_getaddrinfo)
    @patch('requests.get')
    def test_fragment_anchor_not_proxied(self, mock_get, _dns):
        """Bug fix: fragment-only hrefs (#id) must never be rewritten through the proxy."""
        html = '<html><head></head><body><a href="#section1">Jump</a></body></html>'
        mock_resp = Mock()
        mock_resp.headers = {'Content-Type': 'text/html; charset=utf-8'}
        mock_resp.text = html
        mock_resp.content = html.encode('utf-8')
        mock_resp.encoding = 'utf-8'
        mock_resp.apparent_encoding = 'utf-8'
        mock_get.return_value = mock_resp

        response = self.client.get('/fetch?url=https://example.com/')
        self.assertEqual(response.status_code, 200)
        data = response.get_data(as_text=True)
        self.assertIn('href="#section1"', data)
        self.assertNotIn('fetch?url=%23', data)
        self.assertNotIn('fetch?url=#', data)

    # ── CSS url() rewriting ──────────────────────────────────────────────────

    @patch('socket.getaddrinfo', side_effect=_safe_getaddrinfo)
    @patch('requests.get')
    def test_css_url_rewrite_in_html(self, mock_get, _dns):
        html = '<html><head></head><body><div style="background: url(\'images/bg.png\')"></div></body></html>'
        mock_resp = Mock()
        mock_resp.headers = {'Content-Type': 'text/html; charset=utf-8'}
        mock_resp.text = html
        mock_resp.content = html.encode('utf-8')
        mock_resp.encoding = 'utf-8'
        mock_resp.apparent_encoding = 'utf-8'
        mock_get.return_value = mock_resp

        response = self.client.get('/fetch?url=https://example.com/page.html')
        self.assertEqual(response.status_code, 200)
        data = response.get_data(as_text=True)
        self.assertIn('fetch?url=https%3A%2F%2Fexample.com%2Fimages%2Fbg.png', data)

    @patch('socket.getaddrinfo', side_effect=_safe_getaddrinfo)
    @patch('requests.get')
    def test_css_file_url_rewrite(self, mock_get, _dns):
        css = 'body { background: url("../images/hero.jpg"); }'
        mock_resp = Mock()
        mock_resp.headers = {'Content-Type': 'text/css'}
        mock_resp.text = css
        mock_resp.content = css.encode('utf-8')
        mock_resp.encoding = 'utf-8'
        mock_resp.apparent_encoding = 'utf-8'
        mock_get.return_value = mock_resp

        response = self.client.get('/fetch?url=https://example.com/css/style.css')
        self.assertEqual(response.status_code, 200)
        data = response.get_data(as_text=True)
        self.assertIn('fetch?url=https%3A%2F%2Fexample.com%2Fimages%2Fhero.jpg', data)

    @patch('socket.getaddrinfo', side_effect=_safe_getaddrinfo)
    @patch('requests.get')
    def test_css_fragment_not_proxied(self, mock_get, _dns):
        """SVG fragment references in CSS (url(#mask0_...)) must be left untouched."""
        css = 'rect { clip-path: url(#mask0_5467_377537); }'
        mock_resp = Mock()
        mock_resp.headers = {'Content-Type': 'text/css'}
        mock_resp.text = css
        mock_resp.content = css.encode('utf-8')
        mock_resp.encoding = 'utf-8'
        mock_resp.apparent_encoding = 'utf-8'
        mock_get.return_value = mock_resp

        response = self.client.get('/fetch?url=https://example.com/css/style.css')
        self.assertEqual(response.status_code, 200)
        data = response.get_data(as_text=True)
        self.assertIn('url(#mask0_5467_377537)', data)
        self.assertNotIn('fetch?url=', data)

    # ── SSRF protection ──────────────────────────────────────────────────────

    def test_ssrf_localhost_blocked(self):
        self.assertEqual(self.client.get('/fetch?url=http://localhost/admin').status_code, 403)

    def test_ssrf_internal_ip_blocked(self):
        self.assertEqual(self.client.get('/fetch?url=http://192.168.1.1/').status_code, 403)

    def test_ssrf_metadata_endpoint_blocked(self):
        self.assertEqual(self.client.get('/fetch?url=http://169.254.169.254/latest/meta-data/').status_code, 403)

    @patch('socket.getaddrinfo', side_effect=_private_getaddrinfo)
    def test_ssrf_hostname_resolving_to_private_ip_blocked(self, _dns):
        self.assertEqual(self.client.get('/fetch?url=http://internal.corp/secret').status_code, 403)

    # ── Misc ─────────────────────────────────────────────────────────────────

    def test_missing_url_parameter(self):
        self.assertEqual(self.client.get('/fetch').status_code, 400)

    @patch('socket.getaddrinfo', side_effect=_safe_getaddrinfo)
    @patch('requests.get')
    def test_encoding_fallback(self, mock_get, _dns):
        html = '<html><head></head><body>Hello</body></html>'
        mock_resp = Mock()
        mock_resp.headers = {'Content-Type': 'text/html'}
        mock_resp.text = html
        mock_resp.content = html.encode('utf-8')
        mock_resp.encoding = None
        mock_resp.apparent_encoding = 'utf-8'
        mock_get.return_value = mock_resp

        response = self.client.get('/fetch?url=https://example.com/')
        self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()
