import unittest
from unittest.mock import patch, Mock
from app import app

class TestFetchRewrite(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    @patch('requests.get')
    def test_relative_script_and_link_rewrite(self, mock_get):
        # Mock HTML containing relative script and link
        html = '<html><head><script src="./dit_is_een_extern_script.js"></script></head>'
        html += '<body><a href="../other/page.html">Link</a></body></html>'
        mock_resp = Mock()
        mock_resp.headers = {'Content-Type': 'text/html; charset=utf-8'}
        mock_resp.text = html
        mock_resp.content = html.encode('utf-8')
        mock_resp.encoding = 'utf-8'
        mock_get.return_value = mock_resp

        original_url = 'https://example.com/subdir/index.html'
        response = self.client.get(f'/fetch?url={original_url}')
        self.assertEqual(response.status_code, 200)
        data = response.get_data(as_text=True)
        # Expected rewritten URLs (URL-encoded)
        expected_script = '/fetch?url=https%3A%2F%2Fexample.com%2Fsubdir%2Fdit_is_een_extern_script.js'
        expected_link = '/fetch?url=https%3A%2F%2Fexample.com%2Fother%2Fpage.html'
        self.assertIn(expected_script, data)
        self.assertIn(expected_link, data)

if __name__ == '__main__':
    unittest.main()
