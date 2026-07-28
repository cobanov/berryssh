#!/usr/bin/env python3
"""Serve a BBSSH OTA directory to a BlackBerry device over the local network.

The BlackBerry browser dispatches an over-the-air install based on the MIME
type of the descriptor, so a generic static file server will show the .jad as
plain text instead of installing it.  This serves the two types the device
needs and nothing else.

Plain HTTP on purpose: the OS 7 browser's trust store predates every currently
issued CA, so an HTTPS host will fail to validate.

    python3 tools/ota_server.py archive/binaries/ota-7.1.0

Then open the printed URL in the device's native browser (over Wi-Fi).
"""

import argparse
import functools
import http.server
import pathlib
import socket

MIME_TYPES = {
    ".jad": "text/vnd.sun.j2me.app-descriptor",
    ".cod": "application/vnd.rim.cod",   # RIM COD application (BBSSH)
    ".jar": "application/java-archive",  # plain MIDlet suite
    ".alx": "application/octet-stream",
}


class OTARequestHandler(http.server.SimpleHTTPRequestHandler):
    def guess_type(self, path):
        return MIME_TYPES.get(pathlib.Path(path).suffix.lower()) or super().guess_type(path)

    def log_message(self, fmt, *args):
        # Flushed: this log is the only view of what the device actually fetched,
        # and it is usually being read while redirected to a file.
        print(f"  {self.address_string()}  {fmt % args}", flush=True)

    def end_headers(self):
        # Some devices refuse a download they cannot size up front.
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def lan_address():
    """Best-effort primary LAN IP (no packets are actually sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("192.0.2.1", 9))  # TEST-NET-1, guaranteed unroutable
            return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("directory", type=pathlib.Path, help="directory holding BBSSH.jad and its .cod files")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()

    descriptors = sorted(args.directory.glob("*.jad"))
    if not descriptors:
        raise SystemExit(f"No .jad descriptor in {args.directory}")

    payload = sorted(args.directory.glob("*.cod")) + sorted(args.directory.glob("*.jar"))
    print(f"Serving {len(descriptors)} descriptor(s) + {len(payload)} module(s) from {args.directory}")
    print("\n  On the BlackBerry browser, open:")
    for jad in descriptors:
        print(f"    http://{lan_address()}:{args.port}/{jad.name}")
    print("\nCtrl-C to stop.\n")

    handler = functools.partial(OTARequestHandler, directory=str(args.directory))
    with http.server.ThreadingHTTPServer(("0.0.0.0", args.port), handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    main()
