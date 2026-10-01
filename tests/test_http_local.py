"""Loopback-only integration: real curl, controlled HTTP endpoints, no internet."""
import contextlib
import http.server
import io
import json
import shutil
import socketserver
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import netcheck as n


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def do_GET(self):
        code = 500 if self.path == "/error" else 403 if self.path == "/denied" else 302 if self.path == "/redirect" else 200
        self.send_response(code)
        if self.path == "/redirect": self.send_header("Location", "/ok")
        self.send_header("Content-Type", "text/plain")
        # Intentionally omit Content-Length to test body enforcement on older curl.
        self.end_headers()
        try: self.wfile.write(b"x" * (1000000 if self.path == "/large" else 64))
        except (ConnectionError, OSError): pass


@unittest.skipUnless(shutil.which("curl"), "curl is not installed")
class LoopbackHTTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()

    def setUp(self):
        n.STOP.clear()
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        a = n.parser().parse_args(["--output", self.tmp.name]); a.families = [4]
        self.c = n.Checker(a)
        self.url = "http://127.0.0.1:%d" % self.server.server_port

    def test_real_curl_success_metrics(self):
        row = self.c.http(self.url + "/ok", 4)
        self.assertEqual(row["status"], "PASS", row)
        self.assertEqual(row["metrics"]["http_code"], 200)
        self.assertEqual(row["metrics"]["body_bytes_observed"], 64)

    def test_real_curl_403(self):
        row = self.c.http(self.url + "/denied", 4)
        self.assertEqual(row["status"], "WARN", row)
        self.assertEqual(row["curl_exit"], 0)

    def test_real_curl_500(self):
        row = self.c.http(self.url + "/error", 4)
        self.assertEqual(row["status"], "WARN", row)

    def test_redirect_not_silently_followed(self):
        row = self.c.http(self.url + "/redirect", 4)
        self.assertEqual(row["metrics"]["http_code"], 302)
        self.assertTrue(row["metrics"]["redirect_url"].endswith("/ok"))

    def test_body_limit_without_content_length(self):
        row = self.c.http(self.url + "/large", 4, sample_bytes=1024)
        self.assertEqual(row["curl_exit"], 63, row)
        self.assertEqual(row["metrics"]["http_code"], 200)
        self.assertLessEqual(row["metrics"]["body_bytes_observed"], 1024 + 16384)


if __name__ == "__main__": unittest.main(verbosity=2)
