# Environment wiring. The two-line quickstart depends on this doing the right thing:
#   CAMADA_KEY=<ingest_token>.<snap_token>   (printed by `reconcile instructions` and seed)
#   CAMADA_INGEST_URL / CAMADA_SNAPSHOT_URL  (dev: http://localhost:8787[/snapshot])
#   CAMADA_DISABLED=1                        kill switch, checked at boot and per request
#   CAMADA_SERVERLESS=1                      lazy snapshot mode (no poll thread)
#   CAMADA_TRUSTED_PROXY                     local override: none | vercel | hops:N | cidrs:a,b
#   CAMADA_CHALLENGE=0                       do not enforce challenge verdicts
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .config import TrustedProxy, parse_key, parse_trusted_proxy_env

# PLACEHOLDER default, the same one @camada/node carries — confirm the production ingest domain before any PyPI publish.
DEFAULT_INGEST_URL = "https://in.camada.app"


@dataclass(frozen=True, slots=True)
class Env:
    ingest_token: str
    snap_token: str
    secret: str                              # HMAC key for the challenge nonce/cookie — never leaves the process
    ingest_url: str
    snapshot_url: str
    serverless: bool
    trusted_proxy: TrustedProxy | None       # None = defer to server-delivered config


def resolve_env(env: Mapping[str, str]) -> Env | None:
    """None (SDK stays inert, one log line) rather than raising on bad config."""
    key = parse_key(env.get("CAMADA_KEY"))
    ingest_token = key[0] if key else env.get("CAMADA_TOKEN")
    snap_token = key[1] if key else env.get("CAMADA_SNAPSHOT_TOKEN")
    if not ingest_token or not snap_token:
        return None
    ingest_url = (env.get("CAMADA_INGEST_URL") or DEFAULT_INGEST_URL).rstrip("/")
    return Env(
        ingest_token=ingest_token,
        snap_token=snap_token,
        secret=env.get("CAMADA_KEY") or f"{ingest_token}.{snap_token}",
        ingest_url=ingest_url,
        snapshot_url=env.get("CAMADA_SNAPSHOT_URL") or f"{ingest_url}/snapshot",
        serverless=env.get("CAMADA_SERVERLESS") == "1",
        trusted_proxy=parse_trusted_proxy_env(env.get("CAMADA_TRUSTED_PROXY")),
    )
