# An in-process transport standing in for the analyst Worker (GET /snapshot, POST /e): the
# Python twin of camada-node/test/harness.ts fakeAnalyst().
from __future__ import annotations

import gzip
import json
import struct
from typing import Any

from camada.transport import HttpRequest, HttpResponse

from .conftest import read_bin, read_json

BLOCKED_IP = "203.0.113.66"      # an ip4 entry in v3-basic and v4-basic
CHALLENGED_IP = "192.0.2.20"     # a challenge-only ip4 entry in v4-basic
ALLOWED_IP = "10.0.0.7"          # allow-listed inside the blocked 10.0.0.0/8
# v5-rules only (§D3): the ordered custom rules the golden container carries.
RULE_BLOCKED_IP = "198.51.100.7"        # builtin:block, a manual-block entry
SKIP_PATH = "/healthz"                  # cr_00000000000a, skip — beats every side
RULE_BLOCKED_PATH = "/api/v2/dump"      # cr_00000000000c, block by path regex
WARN_UA = "Scrapy/2.11 (+https://scrapy.org)"   # cr_00000000000e, warn
BLOCKED_UA = "curl/8.4.0"               # cr_00000000000f, block
BLOCKED_HEADER = "x-api-key"            # cr_000000000019, `header is` -> block
BLOCKED_HEADER_VALUE = "leaked-key-1"


META_FILES = {"v3": "blk3/v3-basic.meta.json", "v4": "blk3/v4-basic.meta.json", "v5": "blk5/v5-rules.meta.json"}
BIN_FILES = {"v3": "blk3/v3-basic.bin", "v4": "blk3/v4-basic.bin", "v5": "blk5/v5-rules.bin"}


def frame(meta: dict[str, Any], body: bytes) -> bytes:
    m = json.dumps(meta).encode()
    return struct.pack("<I", len(m)) + m + body


class FakeAnalyst:
    def __init__(self) -> None:
        self.events: list[list[dict[str, Any]]] = []      # batches POSTed to /e
        self.sdk_headers: list[str] = []                   # x-camada-sdk seen on /snapshot and /e
        self.snapshot_versions: list[str] = []             # x-camada-snapshot seen on /snapshot
        self.snapshot_requests: list[HttpRequest] = []
        self.config: dict[str, Any] = {
            "tenant": "acme", "beacon": True, "sample": 1, "exclude": [], "trusted_proxy": {"mode": "none"}, "poll_seconds": 30,
        }
        self.snapshot_down = False
        self.ingest_down = False
        self.snapshot_status: int | None = None            # force a status (204, 304, 401, 500)
        self.container = "v3"                              # v3 | v4 | v5
        self.gzip = False                                  # gzip the frame when the client asks for it
        self.ingest_status = 202

    @property
    def meta(self) -> dict[str, Any]:
        return read_json(META_FILES[self.container])

    @property
    def binary(self) -> bytes:
        return read_bin(BIN_FILES[self.container])

    @property
    def etag(self) -> str:
        suffix = {"v3": "", "v4": "-v4", "v5": "-v5"}[self.container]
        return f'"{self.meta["version"]}{suffix}"'

    def transport(self, req: HttpRequest) -> HttpResponse:
        if req.url.endswith("/snapshot") or req.url.endswith("/e"):
            self.sdk_headers.append(req.headers.get("x-camada-sdk", ""))
        if req.url.endswith("/snapshot"):
            self.snapshot_requests.append(req)
            self.snapshot_versions.append(req.headers.get("x-camada-snapshot", ""))
            if self.snapshot_down:
                return HttpResponse(0, {}, b"")
            headers = {"x-camada-config": json.dumps(self.config), "cache-control": "private, no-store"}
            if self.snapshot_status is not None:
                return HttpResponse(self.snapshot_status, headers, b"")
            if req.headers.get("if-none-match") == self.etag:
                return HttpResponse(304, headers, b"")
            body = frame(self.meta, self.binary)
            headers["etag"] = self.etag
            if self.gzip and "gzip" in req.headers.get("accept-encoding", ""):
                headers["content-encoding"] = "gzip"
                body = gzip.compress(body)
            return HttpResponse(200, headers, body)
        if self.ingest_down:
            return HttpResponse(0, {}, b"")
        if req.url.endswith("/e"):
            self.events.append(json.loads(req.body or b"[]"))
            return HttpResponse(self.ingest_status, {}, b"")
        raise AssertionError("unmocked request: " + req.url)

    @property
    def all_events(self) -> list[dict[str, Any]]:
        return [e for batch in self.events for e in batch]
