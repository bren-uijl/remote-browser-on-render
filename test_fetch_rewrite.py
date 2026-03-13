import socket
import unittest
from unittest.mock import patch, Mock
from app import app

def _safe_dns(host, port, *a, **k):
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', port or 0))]

def _private_dns(host, port, *a, **k):
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('192.168.1.1', port or 0))]

def _html_resp(html, extra_headers=None):
    m = Mock()
    m.headers = {'Content-Type': 'text/html; charset=utf-8', **(extra_headers or {})}
    m.text = html
    m.content = html.encode('utf-8')
    m.encoding = 'utf-8'
    m.apparent_encoding = 'utf-8'
    m.cookies = []
    return m

def _css_resp(css):
    m = Mock()
    m.headers = {'Content-Type': 'text/css'}
    m.text = css
    m.content = css.encode('utf-8')
    m.encoding = 'utf-8'
    m.apparent_encoding = 'utf-8'
    m.cookies = []
    return m

def _fetch(client, url, **kwargs):
    return client.get('/fetch?url=' + url, **kwargs)


class TestFetchRewrite(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    # ── proxy origin ─────────────────────────────────────────────────────────

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.Session.get')
    def test_proxy_base_uses_x_forwarded_proto(self, mock_get, _dns):
        mock_get.return_value = _html_resp('<html><head></head><body><img src="logo.png"></body></html>')
        r = self.client.get(
            '/fetch?url=https://example.com/',
            headers={'X-Forwarded-Proto': 'https', 'Host': 'myproxy.onrender.com'},
        )
        self.assertEqual(r.status_code, 200)
        self.assertIn('https://myproxy.onrender.com/fetch?url=', r.get_data(as_text=True))
        self.assertNotIn('http://myproxy.onrender.com/fetch?url=', r.get_data(as_text=True))

    # ── attribute rewriting ───────────────────────────────────────────────────

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.Session.get')
    def test_relative_src_rewritten(self, mock_get, _dns):
        mock_get.return_value = _html_resp('<html><head></head><body><img src="./img.jpg"></body></html>')
        data = _fetch(self.client, 'https://example.com/').get_data(as_text=True)
        self.assertIn('fetch?url=https%3A%2F%2Fexample.com%2Fimg.jpg', data)

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.Session.get')
    def test_absolute_url_routed_through_proxy(self, mock_get, _dns):
        mock_get.return_value = _html_resp('<html><head></head><body><img src="https://example.com/img.jpg"></body></html>')
        data = _fetch(self.client, 'https://example.com/').get_data(as_text=True)
        self.assertIn('fetch?url=https%3A%2F%2Fexample.com%2Fimg.jpg', data)
        self.assertNotIn('example.com/fetch?url=', data)

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.Session.get')
    def test_srcset_rewritten(self, mock_get, _dns):
        mock_get.return_value = _html_resp('<html><head></head><body><img srcset="a.jpg 1x, b.jpg 2x"></body></html>')
        data = _fetch(self.client, 'https://example.com/').get_data(as_text=True)
        self.assertIn('fetch?url=https%3A%2F%2Fexample.com%2Fa.jpg', data)
        self.assertIn('fetch?url=https%3A%2F%2Fexample.com%2Fb.jpg', data)

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.Session.get')
    def test_fragment_not_proxied(self, mock_get, _dns):
        mock_get.return_value = _html_resp('<html><head></head><body><a href="#s1">x</a></body></html>')
        data = _fetch(self.client, 'https://example.com/').get_data(as_text=True)
        self.assertIn('href="#s1"', data)
        self.assertNotIn('fetch?url=%23', data)

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.Session.get')
    def test_http_upgraded_to_https(self, mock_get, _dns):
        mock_get.return_value = _html_resp('<html><head></head><body><img src="http://example.com/x.jpg"></body></html>')
        data = _fetch(self.client, 'https://example.com/').get_data(as_text=True)
        self.assertNotIn('fetch?url=http%3A%2F%2F', data)
        self.assertIn('fetch?url=https%3A%2F%2F', data)

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.Session.get')
    def test_base_tag_removed(self, mock_get, _dns):
        mock_get.return_value = _html_resp('<html><head><base href="http://example.com/"></head><body></body></html>')
        self.assertNotIn('<base', _fetch(self.client, 'https://example.com/').get_data(as_text=True))

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.Session.get')
    def test_xframe_stripped(self, mock_get, _dns):
        mock_get.return_value = _html_resp('<html><head></head><body></body></html>',
            extra_headers={'X-Frame-Options': 'DENY', 'Content-Security-Policy': "default-src 'self'"})
        r = _fetch(self.client, 'https://example.com/')
        self.assertNotEqual(r.headers.get('X-Frame-Options'), 'DENY')

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.Session.get')
    def test_intercept_script_injected(self, mock_get, _dns):
        mock_get.return_value = _html_resp('<html><head></head><body></body></html>')
        data = _fetch(self.client, 'https://example.com/').get_data(as_text=True)
        self.assertIn('proxy-intercept.js', data)
        self.assertIn('__PROXY_BASE__', data)

    # ── CSS rewriting ─────────────────────────────────────────────────────────

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.Session.get')
    def test_css_url_rewritten(self, mock_get, _dns):
        mock_get.return_value = _css_resp('body{background:url("../img/bg.png")}')
        data = _fetch(self.client, 'https://example.com/css/s.css').get_data(as_text=True)
        self.assertIn('fetch?url=https%3A%2F%2Fexample.com%2Fimg%2Fbg.png', data)

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.Session.get')
    def test_css_fragment_not_proxied(self, mock_get, _dns):
        mock_get.return_value = _css_resp('rect{clip-path:url(#m)}')
        data = _fetch(self.client, 'https://example.com/s.css').get_data(as_text=True)
        self.assertIn('url(#m)', data)
        self.assertNotIn('fetch?url=', data)

    # ── SSRF ─────────────────────────────────────────────────────────────────

    def test_ssrf_localhost(self):
        self.assertEqual(_fetch(self.client, 'http://localhost/').status_code, 403)

    def test_ssrf_private_ip(self):
        self.assertEqual(_fetch(self.client, 'http://192.168.1.1/').status_code, 403)

    def test_ssrf_metadata(self):
        self.assertEqual(_fetch(self.client, 'http://169.254.169.254/').status_code, 403)

    @patch('socket.getaddrinfo', side_effect=_private_dns)
    def test_ssrf_hostname_resolves_private(self, _dns):
        self.assertEqual(_fetch(self.client, 'http://internal/').status_code, 403)

    # ── misc ──────────────────────────────────────────────────────────────────

    def test_missing_url(self):
        self.assertEqual(self.client.get('/fetch').status_code, 400)

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.Session.get')
    def test_encoding_fallback(self, mock_get, _dns):
        m = _html_resp('<html><head></head><body>Hi</body></html>')
        m.encoding = None
        mock_get.return_value = m
        self.assertEqual(_fetch(self.client, 'https://example.com/').status_code, 200)


if __name__ == '__main__':
    unittest.main()
