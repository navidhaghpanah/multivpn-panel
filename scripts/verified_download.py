"""Download a pinned core asset and verify it before the installer executes it."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.request


def download(asset, target, override_url="", override_sha=""):
    manifest = json.loads(Path(__file__).with_name("core-releases.json").read_text())
    entry = manifest[asset]
    url = override_url or entry["url"]
    expected = override_sha if override_url else entry["sha256"]
    if not url.startswith("https://") or not re.fullmatch(r"[a-fA-F0-9]{64}", expected):
        raise ValueError("Custom download URLs require a SHA256 checksum")
    target = Path(target)
    digest = hashlib.sha256()
    temporary = target.with_suffix(target.suffix + ".part")
    try:
        with urllib.request.urlopen(url, timeout=60) as response, temporary.open("wb") as output:
            size = 0
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > 256 * 1024 * 1024:
                    raise ValueError("Asset too large")
                output.write(chunk)
                digest.update(chunk)
        if digest.hexdigest() != expected.lower():
            raise ValueError("SHA256 checksum mismatch")
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    download(*sys.argv[1:])
