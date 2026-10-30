#!/usr/bin/env python3
"""Run the hub on your own computer.

    python3 serve.py              serve on http://localhost:8000 and open a browser
    python3 serve.py --port 9000  use another port
    python3 serve.py --no-browser don't open a browser
    python3 serve.py --lan        also allow other devices on your network (phones, a second laptop)

Only the Python standard library is needed. Stop it with Ctrl+C.
"""
import argparse
import functools
import http.server
import mimetypes
import socket
import sys
import threading
import webbrowser
from pathlib import Path

DOCS = Path(__file__).resolve().parent / "docs"

# Some Python versions don't know these types; browsers are strict about fonts and scripts.
for ext, kind in {".woff2": "font/woff2", ".svg": "image/svg+xml", ".js": "text/javascript", ".mjs": "text/javascript",
                  ".wasm": "application/wasm", ".json": "application/json"}.items():
    mimetypes.add_type(kind, ext)


class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cache-Control", "no-store")   # always show your latest edits
        super().end_headers()

    def log_message(self, fmt, *args):                    # quieter: only show errors
        if len(args) > 1 and str(args[1]).startswith(("4", "5")):
            super().log_message(fmt, *args)


def lan_address():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 80))                 # no packet is sent; this just picks the outgoing interface
            return s.getsockname()[0]
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser(description="Serve the cybersec hub locally.")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--lan", action="store_true", help="listen on all interfaces so other devices can connect")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    sys.stdout.reconfigure(line_buffering=True)          # show messages right away, even when piped
    if not DOCS.is_dir():
        sys.exit(f"Can't find {DOCS}. Run this from the cybersec-hub folder.")

    host = "0.0.0.0" if args.lan else "127.0.0.1"
    handler = functools.partial(Handler, directory=str(DOCS))
    try:
        server = http.server.ThreadingHTTPServer((host, args.port), handler)
    except OSError as e:
        sys.exit(f"Port {args.port} is busy ({e.strerror}). Try: python3 serve.py --port {args.port + 1}")

    url = f"http://localhost:{args.port}/"
    print(f"Cybersec hub running at {url}")
    print(f"  Crypto 101:   {url}talks/crypto-101/")
    if args.lan:
        ip = lan_address()
        if ip:
            print(f"  On your network: http://{ip}:{args.port}/")
        print("  Note: the real-passkey demo only works on localhost or the live https site, not over the network.")
    print("Press Ctrl+C to stop.")

    if not args.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
