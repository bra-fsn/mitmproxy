"""
Serve local files instead of contacting the upstream server.

Intercept requests and serve matching files from a local directory,
streaming the response body to keep memory usage constant regardless
of file size.  Set the LOCAL_SERVE_DIR environment variable to the
directory you want to serve.

Usage:

    LOCAL_SERVE_DIR=/path/to/files mitmdump -s http-serve-local-file.py
"""

import mimetypes
import os
from pathlib import Path

from mitmproxy import http

CHUNK_SIZE = 64 * 1024


def _file_chunks(path: Path):
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            yield chunk


def requestheaders(flow: http.HTTPFlow) -> None:
    root = os.environ.get("LOCAL_SERVE_DIR", "")
    if not root:
        return

    root_path = Path(root).resolve()
    # Map the URL path to a local file, rejecting path-traversal attempts.
    rel = flow.request.path.lstrip("/")
    target = (root_path / rel).resolve()
    if not str(target).startswith(str(root_path)):
        flow.response = http.Response.make(403, b"Forbidden")
        return

    if target.is_dir():
        target = target / "index.html"

    if not target.is_file():
        return  # let the request go upstream

    content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
    size = target.stat().st_size

    flow.response = http.Response.make(200, b"", {"Content-Type": content_type})
    flow.response.headers["content-length"] = str(size)
    # Stream the body from disk; mitmproxy will send chunks with backpressure
    # so that even multi-gigabyte files use only a few megabytes of RAM.
    flow.response.stream = _file_chunks(target)
