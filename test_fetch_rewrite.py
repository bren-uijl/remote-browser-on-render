import socket
import unittest
from unittest.mock import patch, Mock
from app import app

# A mock getaddrinfo that returns a public IP for any hostname,
# so SSRF checks pass for legitimate hosts in unit tests.
def _safe_getaddrinfo(host, port, *args, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', port or 0))]

# A mock getaddrinfo that returns a private IP to trigger SSRF blocks.
def _private_getaddrinfo(host, port, *args, **kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, '', ('192.168.1.1', port or 0))]


class TestFetchRewrite(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    @patch('socket.getaddrinfo', side_effect=_safe_getaddrinfo)
    @patch('requests.get')
    def test_relative_script_and_link_rewrite(self, mock_get, _mock_dns):
        html = '<html><head><script src="./dit_is_een_extern_script.js"></script></head>'
        html += '<body><a href="../other/page.html">Link</a></body></html>'
        mock_resp = Mock()
        mock_resp.headers = {'Content-Type': 'text/html; charset=utf-8'}
        mock_resp.text = html
        mock_resp.content = html.encode('utf-8')
        mock_resp.encoding = 'utf-8'
        mock_resp.apparent_encoding = 'utf-8'
        mock_get.return_value = mock_resp

        original_url = 'https://example.com/subdir/index.html'
        response = self.client.get(f'/fetch?url={original_url}')
        self.assertEqual(response.status_code, 200)
        data = response.get_data(as_text=True)
        expected_script = '/fetch?url=https%3A%2F%2Fexample.com%2Fsubdir%2Fdit_is_een_extern_script.js'
        expected_link = '/fetch?url=https%3A%2F%2Fexample.com%2Fother%2Fpage.html'
        self.assertIn(expected_script, data)
        self.assertIn(expected_link, data)

    @patch('socket.getaddrinfo', side_effect=_safe_getaddrinfo)
    @patch('requests.get')
    def test_css_url_rewrite_in_html(self, mock_get, _mock_dns):
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
        self.assertIn('/fetch?url=https%3A%2F%2Fexample.com%2Fimages%2Fbg.png', data)

    @patch('socket.getaddrinfo', side_effect=_safe_getaddrinfo)
    @patch('requests.get')
    def test_css_file_url_rewrite(self, mock_get, _mock_dns):
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
        self.assertIn('/fetch?url=https%3A%2F%2Fexample.com%2Fimages%2Fhero.jpg', data)

    def test_ssrf_localhost_blocked(self):
        response = self.client.get('/fetch?url=http://localhost/admin')
        self.assertEqual(response.status_code, 403)

    def test_ssrf_internal_ip_blocked(self):
        response = self.client.get('/fetch?url=http://192.168.1.1/')
        self.assertEqual(response.status_code, 403)

    def test_ssrf_metadata_endpoint_blocked(self):
        response = self.client.get('/fetch?url=http://169.254.169.254/latest/meta-data/')
        self.assertEqual(response.status_code, 403)

    @patch('socket.getaddrinfo', side_effect=_private_getaddrinfo)
    def test_ssrf_hostname_resolving_to_private_ip_blocked(self, _mock_dns):
        """A hostname that resolves to an internal IP must be blocked."""
        response = self.client.get('/fetch?url=http://internal.corp/secret')
        self.assertEqual(response.status_code, 403)

    def test_missing_url_parameter(self):
        response = self.client.get('/fetch')
        self.assertEqual(response.status_code, 400)

    @patch('socket.getaddrinfo', side_effect=_safe_getaddrinfo)
    @patch('requests.get')
    def test_encoding_fallback(self, mock_get, _mock_dns):
        """resp.encoding=None should fall back to apparent_encoding without crashing."""
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
