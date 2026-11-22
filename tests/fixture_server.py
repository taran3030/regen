"""A tiny web server for Regen's tests. Three modes:

    hardened  every header in checks/headers.tsv, and 404 for unknown paths
    bare      no security headers, and an exposed .env
    spa       every header, and every path answers 200 with the same home page (a single-page app)

    python3 tests/fixture_server.py <mode> <port>
"""
import pathlib
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODE, PORT = sys.argv[1], int(sys.argv[2])
CHECKS = pathlib.Path(__file__).resolve().parent.parent / "checks" / "headers.tsv"
HEADERS = [line.split("\t")[0] for line in CHECKS.read_text().splitlines() if line.strip() and not line.startswith("#")]
VALUES = {
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
    "X-XSS-Protection": "0",
}
HOME = b"<!doctype html><title>fixture</title><div id=root></div>"


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        if MODE in ("hardened", "spa"):
            for h in HEADERS:
                self.send_header(h, VALUES.get(h, "1"))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            return self._send(200, HOME)
        if MODE == "spa":
            return self._send(200, HOME)
        if MODE == "bare" and path == "/.env":
            return self._send(200, b"DATABASE_PASSWORD=example\n")
        return self._send(404, b"not found")

    do_HEAD = do_GET

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
