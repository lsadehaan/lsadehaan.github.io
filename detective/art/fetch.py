#!/usr/bin/env python3
"""Download the game's Magnific pictures and shrink them for the web.

Magnific download links are signed and expire, so they are not stored here.
Get fresh links for the creations listed in manifest.json (for example with
the Magnific MCP tool `creations_get`) and save them as a JSON object mapping
creation id -> url, then run:

    python3 detective/art/fetch.py urls.json

Each picture is resized for its kind (see "sizes" in manifest.json) and saved
as a JPEG in detective/img/.
"""
import io
import json
import os
import sys
import urllib.request

from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "img")


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    with open(os.path.join(HERE, "manifest.json")) as f:
        manifest = json.load(f)
    with open(sys.argv[1]) as f:
        urls = json.load(f)
    os.makedirs(OUT, exist_ok=True)
    missing = []
    for item in manifest["images"]:
        url = urls.get(item["creation"])
        if not url:
            missing.append(item["file"])
            continue
        with urllib.request.urlopen(url, timeout=60) as resp:
            data = resp.read()
        im = Image.open(io.BytesIO(data)).convert("RGB")
        width = manifest["sizes"][item["kind"]]
        if im.width > width:
            im = im.resize((width, round(im.height * width / im.width)), Image.LANCZOS)
        path = os.path.join(OUT, item["file"])
        im.save(path, "JPEG", quality=82, optimize=True, progressive=True)
        print("saved", item["file"], im.size, os.path.getsize(path) // 1024, "KB")
    if missing:
        print("no url for:", ", ".join(missing))


if __name__ == "__main__":
    main()
