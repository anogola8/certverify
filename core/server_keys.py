"""
Server-level Ed25519 keypair for signing verification receipts.
Generated on first use and stored in server_keys.json at the project root.
"""
import json
from pathlib import Path

from django.conf import settings
from .signing import generate_keypair

_KEYS_PATH = Path(settings.BASE_DIR) / "server_keys.json"
_cache = None


def _load():
    global _cache
    if _cache is not None:
        return _cache
    if _KEYS_PATH.exists():
        _cache = json.loads(_KEYS_PATH.read_text())
    else:
        priv, pub = generate_keypair()
        _cache = {"private_key": priv, "public_key": pub}
        _KEYS_PATH.write_text(json.dumps(_cache, indent=2))
    return _cache


def get_private_key() -> str:
    return _load()["private_key"]


def get_public_key() -> str:
    return _load()["public_key"]
