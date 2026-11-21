"""Tiny deliberately misconfigured site for testing the scanner without Docker.
Run: python lab/test_target.py   (serves http://127.0.0.1:8099 only)"""
from http.server import BaseHTTPRequestHandler, HTTPServer

PAGES = {
    "/": "<html><body><h1>Test shop</h1><form><input type='password' name='pw'></form></body></html>",
    "/robots.txt": "User-agent: *\nDisallow: /admin\nDisallow: /backup\n",
    "/.git/HEAD": "ref: refs/heads/main\n",
}

class H(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.25"
    sys_version = "PHP/7.0.30"
    def do_GET(self):
        body = PAGES.get(self.path)
        self.send_response(200 if body else 404)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Powered-By", "PHP/7.0.30")
        if self.path == "/":
            self.send_header("Set-Cookie", "PHPSESSID=abc123; path=/")
        self.end_headers()
        self.wfile.write((body or "Not found").encode())
    def log_message(self, *a): pass

if __name__ == "__main__":
    print("Test target on http://127.0.0.1:8099")
    HTTPServer(("127.0.0.1", 8099), H).serve_forever()
