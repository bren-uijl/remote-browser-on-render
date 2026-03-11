import socket
import unittest
from unittest.mock import patch, Mock
from app import app

def _safe_dns(host, port, *args, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', port or 0))]

def _private_dns(host, port, *args, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('192.168.1.1', port or 0))]

def _mock_html_resp(html):
    m = Mock()
    m.headers = {'Content-Type': 'text/html; charset=utf-8'}
    m.text = html
    m.content = html.encode('utf-8')
    m.encoding = 'utf-8'
    m.apparent_encoding = 'utf-8'
    return m

def _mock_css_resp(css):
    m = Mock()
    m.headers = {'Content-Type': 'text/css'}
    m.text = css
    m.content = css.encode('utf-8')
    m.encoding = 'utf-8'
    m.apparent_encoding = 'utf-8'
    return m


class TestFetchRewrite(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    # ── proxy_base uses X-Forwarded-Proto ────────────────────────────────────

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.get')
    def test_proxy_base_respects_x_forwarded_proto(self, mock_get, _dns):
        """On Render, X-Forwarded-Proto: https must produce https:// proxy URLs."""
        mock_get.return_value = _mock_html_resp(
            '<html><head></head><body><img src="logo.png"></body></html>'
        )
        response = self.client.get(
            '/fetch?url=https://example.com/',
            headers={'X-Forwarded-Proto': 'https', 'Host': 'myproxy.onrender.com'},
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_data(as_text=True)
        # Must be https://, never http://
        self.assertIn('https://myproxy.onrender.com/fetch?url=', data)
        self.assertNotIn('http://myproxy.onrender.com/fetch?url=', data)

    # ── HTTP target URLs upgraded to HTTPS ───────────────────────────────────

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.get')
    def test_http_target_upgraded_to_https(self, mock_get, _dns):
        """http:// URLs in HTML must be upgraded to https:// to avoid mixed content."""
        mock_get.return_value = _mock_html_resp(
            '<html><head></head><body><img src="http://example.com/img.jpg"></body></html>'
        )
        response = self.client.get('/fetch?url=https://example.com/')
        data = response.get_data(as_text=True)
        self.assertNotIn('fetch?url=http%3A%2F%2F', data)
        self.assertIn('fetch?url=https%3A%2F%2F', data)

    # ── Attribute rewriting ──────────────────────────────────────────────────

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.get')
    def test_relative_src_and_href_rewritten(self, mock_get, _dns):
        html = ('<html><head><script src="./app.js"></script></head>'
                '<body><a href="../other/page.html">Link</a></body></html>')
        mock_get.return_value = _mock_html_resp(html)
        response = self.client.get('/fetch?url=https://example.com/subdir/index.html')
        self.assertEqual(response.status_code, 200)
        data = response.get_data(as_text=True)
        self.assertIn('fetch?url=https%3A%2F%2Fexample.com%2Fsubdir%2Fapp.js', data)
        self.assertIn('fetch?url=https%3A%2F%2Fexample.com%2Fother%2Fpage.html', data)

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.get')
    def test_srcset_rewritten(self, mock_get, _dns):
        html = '<html><head></head><body><img srcset="img-1x.jpg 1x, img-2x.jpg 2x"></body></html>'
        mock_get.return_value = _mock_html_resp(html)
        response = self.client.get('/fetch?url=https://example.com/')
        data = response.get_data(as_text=True)
        self.assertIn('fetch?url=https%3A%2F%2Fexample.com%2Fimg-1x.jpg', data)
        self.assertIn('fetch?url=https%3A%2F%2Fexample.com%2Fimg-2x.jpg', data)

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.get')
    def test_form_action_rewritten(self, mock_get, _dns):
        html = '<html><head></head><body><form action="/search"></form></body></html>'
        mock_get.return_value = _mock_html_resp(html)
        response = self.client.get('/fetch?url=https://example.com/')
        data = response.get_data(as_text=True)
        self.assertIn('fetch?url=https%3A%2F%2Fexample.com%2Fsearch', data)

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.get')
    def test_fragment_anchor_not_proxied(self, mock_get, _dns):
        html = '<html><head></head><body><a href="#section1">Jump</a></body></html>'
        mock_get.return_value = _mock_html_resp(html)
        response = self.client.get('/fetch?url=https://example.com/')
        data = response.get_data(as_text=True)
        self.assertIn('href="#section1"', data)
        self.assertNotIn('fetch?url=', data.split('href="#section1"')[0].rsplit('<a', 1)[-1])

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.get')
    def test_existing_base_tag_removed(self, mock_get, _dns):
        """Any <base> tag from the original page must be stripped."""
        html = '<html><head><base href="http://example.com/"></head><body></body></html>'
        mock_get.return_value = _mock_html_resp(html)
        response = self.client.get('/fetch?url=https://example.com/')
        data = response.get_data(as_text=True)
        self.assertNotIn('<base', data)

    # ── CSP / X-Frame-Options stripped ──────────────────────────────────────

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.get')
    def test_xframe_options_stripped(self, mock_get, _dns):
        m = _mock_html_resp('<html><head></head><body></body></html>')
        m.headers = {
            'Content-Type': 'text/html',
            'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "default-src 'self'",
        }
        mock_get.return_value = m
        response = self.client.get('/fetch?url=https://example.com/')
        self.assertNotIn('X-Frame-Options', response.headers)
        self.assertNotIn('x-frame-options', response.headers)

    # ── CSS rewriting ────────────────────────────────────────────────────────

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.get')
    def test_css_url_rewritten(self, mock_get, _dns):
        mock_get.return_value = _mock_css_resp('body { background: url("../images/bg.png"); }')
        response = self.client.get('/fetch?url=https://example.com/css/style.css')
        self.assertIn('fetch?url=https%3A%2F%2Fexample.com%2Fimages%2Fbg.png',
                      response.get_data(as_text=True))

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.get')
    def test_css_import_rewritten(self, mock_get, _dns):
        mock_get.return_value = _mock_css_resp('@import "fonts/custom.css";')
        response = self.client.get('/fetch?url=https://example.com/css/style.css')
        self.assertIn('fetch?url=https%3A%2F%2Fexample.com%2Fcss%2Ffonts%2Fcustom.css',
                      response.get_data(as_text=True))

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.get')
    def test_css_fragment_not_proxied(self, mock_get, _dns):
        mock_get.return_value = _mock_css_resp('rect { clip-path: url(#mask0_5467); }')
        response = self.client.get('/fetch?url=https://example.com/style.css')
        data = response.get_data(as_text=True)
        self.assertIn('url(#mask0_5467)', data)
        self.assertNotIn('fetch?url=', data)

    # ── SSRF ─────────────────────────────────────────────────────────────────

    def test_ssrf_localhost_blocked(self):
        self.assertEqual(self.client.get('/fetch?url=http://localhost/').status_code, 403)

    def test_ssrf_private_ip_blocked(self):
        self.assertEqual(self.client.get('/fetch?url=http://192.168.1.1/').status_code, 403)

    def test_ssrf_metadata_blocked(self):
        self.assertEqual(
            self.client.get('/fetch?url=http://169.254.169.254/latest/meta-data/').status_code, 403)

    @patch('socket.getaddrinfo', side_effect=_private_dns)
    def test_ssrf_hostname_resolving_to_private_ip_blocked(self, _dns):
        self.assertEqual(self.client.get('/fetch?url=http://internal.corp/').status_code, 403)

    # ── Misc ─────────────────────────────────────────────────────────────────

    def test_missing_url_parameter(self):
        self.assertEqual(self.client.get('/fetch').status_code, 400)

    @patch('socket.getaddrinfo', side_effect=_safe_dns)
    @patch('requests.get')
    def test_encoding_fallback(self, mock_get, _dns):
        m = _mock_html_resp('<html><head></head><body>Hello</body></html>')
        m.encoding = None
        mock_get.return_value = m
        self.assertEqual(self.client.get('/fetch?url=https://example.com/').status_code, 200)


if __name__ == '__main__':
    unittest.main()
