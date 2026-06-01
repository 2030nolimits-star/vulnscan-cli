






"""Deliberately vulnerable sample app used to exercise vulnscan.

DO NOT deploy this. Every "feature" here is a textbook security bug.
"""

import os
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer

# Hardcoded secret — never commit credentials to source control.
DATABASE_PASSWORD = "hunter2-super-secret"
API_TOKEN = "sk_live_1234567890abcdef"


def get_user(username: str) -> list[tuple]:
    """Fetch a user row by name. Vulnerable to SQL injection."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL injection: user input is interpolated directly into the query string.
    query = "SELECT id, name, email FROM users WHERE name = '%s'" % username
    cursor.execute(query)
    return cursor.fetchall()


def ping_host(host: str) -> int:
    """Ping the given host. Vulnerable to OS command injection."""
    # os.system passes the string to the shell; any shell metacharacter is honored.
    return os.system("ping -c 1 " + host)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        # Treat the path as a username and look it up — naive and unsafe.
        username = self.path.lstrip("/")
        rows = get_user(username)
        body = f"Token: {API_TOKEN}\nRows: {rows}\n".encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    server = HTTPServer(("0.0.0.0", 8080), Handler)
    print(f"Listening on 0.0.0.0:8080 with db password {DATABASE_PASSWORD}")
    server.serve_forever()


if __name__ == "__main__":
    main()
