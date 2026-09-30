#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
# Copyright (c) 2026 Tiberiu Balasea
#
# Builds the documentation site from site/book.toml into target/site, then
# checks what was built: every link inside the site reaches a page or file
# that exists and, when it names an anchor, an anchor that page has; no page
# loads anything from another host; no page shows an email address. Any of
# the three failing fails the script, with each finding named after the
# source file it came from. Nothing is published or deployed.
#
#   scripts/site.sh           build and check
#   scripts/site.sh --check   check an existing build without rebuilding
#
# Needs mdbook (cargo install mdbook --locked) and python3.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
OUT="$ROOT/target/site"

REBUILD=1
case "${1:-}" in
    "") ;;
    --check) REBUILD=0 ;;
    *) printf 'usage: %s [--check]\n' "$0" >&2; exit 2 ;;
esac

if [ "$REBUILD" -eq 1 ]; then
    if ! command -v mdbook >/dev/null 2>&1; then
        printf 'mdbook is not installed: cargo install mdbook --locked\n' >&2
        exit 2
    fi
    rm -rf "$OUT"
    # mdbook exits 0 even when a renderer fails, so its log is the verdict
    log=$(mdbook build site 2>&1) || { printf '%s\n' "$log" >&2; exit 1; }
    printf '%s\n' "$log"
    if printf '%s\n' "$log" | grep -qE '^ *(ERROR|WARN)'; then
        printf 'mdbook reported a problem, see above\n' >&2
        exit 1
    fi
fi

if [ ! -f "$OUT/index.html" ]; then
    printf '%s has no index.html: build the site first\n' "$OUT" >&2
    exit 2
fi

python3 - "$OUT" "$ROOT/site/src" "$ROOT" <<'PY'
import os
import re
import sys
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

out, src, root = sys.argv[1], sys.argv[2], sys.argv[3]

# Pages mdBook writes on its own. print.html repeats every chapter with its
# links rewritten to anchors in itself, so its findings would only repeat
# the chapters'; 404.html is served from wherever the missing page was asked
# for, so its relative links resolve against no fixed directory.
GENERATED = {"print.html", "404.html"}

# The repository's own rule (scripts/check.sh): names under the RFC 2606 and
# RFC 6761 reserved domains are SIP URIs in walkthroughs, not addresses
# anyone owns.
ADDRESS = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RESERVED = re.compile(
    r"@([A-Za-z0-9.-]+\.)?(example\.(com|net|org)"
    r"|[A-Za-z0-9-]+\.(example|invalid|test|localhost))\b"
)
MAILTO = re.compile(r"mailto:", re.IGNORECASE)
TEXT = (".html", ".js", ".json", ".css", ".txt", ".rs", ".svg", ".md")

# Attributes that make a browser fetch something, as opposed to a link a
# reader may follow.
FETCHED = {
    ("script", "src"), ("img", "src"), ("iframe", "src"), ("source", "src"),
    ("audio", "src"), ("video", "src"), ("embed", "src"), ("object", "data"),
    ("link", "href"),
}
REMOTE_CSS = re.compile(
    r"(@import\s+(url\()?|url\()\s*['\"]?\s*(https?:)?//", re.IGNORECASE
)


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids = set()
        self.links = []
        self.fetched = []
        self.refresh = None

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if value is None:
                continue
            if tag == "meta" and name == "content" and (
                ("http-equiv", "refresh") in attrs
            ):
                self.refresh = value.split("url=", 1)[-1].strip()
            if name in ("id", "name") and (name == "id" or tag == "a"):
                self.ids.add(value)
            if name in ("href", "src") or (tag, name) in FETCHED:
                self.links.append(value)
            if (tag, name) in FETCHED:
                self.fetched.append(value)

    handle_startendtag = handle_starttag


def source_of(rel):
    """The repository file a built page came from, through its symlink."""
    base = rel[: -len(".html")]
    candidates = [base + ".md"]
    if os.path.basename(base) == "index":
        candidates.append(os.path.join(os.path.dirname(base), "README.md"))
    for cand in candidates:
        path = os.path.join(src, cand)
        if os.path.exists(path):
            return os.path.relpath(os.path.realpath(path), root)
    return "target/site/" + rel


files = []
for d, _, names in os.walk(out):
    for n in names:
        files.append(os.path.relpath(os.path.join(d, n), out))

pages = {}
for rel in files:
    if rel.endswith(".html"):
        p = Page()
        with open(os.path.join(out, rel), encoding="utf-8") as f:
            p.feed(f.read())
        pages[rel] = p

broken, remote, addresses = [], [], []

for rel, page in sorted(pages.items()):
    where = source_of(rel)
    for value in page.fetched:
        if urlsplit(value).scheme in ("http", "https") or value.startswith("//"):
            remote.append(f"{where}: loads {value}")
    if rel in GENERATED:
        continue
    # a page that sends the reader on at once is never read: only where it
    # sends them has to exist
    for value in [page.refresh] if page.refresh else page.links:
        parts = urlsplit(value)
        if parts.scheme or value.startswith("//"):
            continue
        path = unquote(parts.path)
        if path:
            target = os.path.normpath(os.path.join(os.path.dirname(rel), path))
            if target.startswith(".."):
                broken.append(f"{where}: {value} leaves the site")
                continue
            if os.path.isdir(os.path.join(out, target)):
                target = os.path.join(target, "index.html")
            if not os.path.isfile(os.path.join(out, target)):
                broken.append(f"{where}: {value} names no page or file")
                continue
        else:
            target = rel
        if parts.fragment and target.endswith(".html"):
            if unquote(parts.fragment) not in pages[target].ids:
                broken.append(f"{where}: {value} names no anchor in {target}")

for rel in sorted(files):
    if not rel.endswith(TEXT):
        continue
    with open(os.path.join(out, rel), encoding="utf-8", errors="replace") as f:
        text = f.read()
    where = source_of(rel) if rel.endswith(".html") else "target/site/" + rel
    if rel.endswith(".css") and REMOTE_CSS.search(text):
        remote.append(f"{where}: a stylesheet fetches from another host")
    if MAILTO.search(text):
        addresses.append(f"{where}: a mailto: link")
    for m in ADDRESS.finditer(text):
        if not RESERVED.search(m.group(0)):
            addresses.append(f"{where}: {m.group(0)}")

checked = sum(
    1 if p.refresh else len(p.links)
    for r, p in pages.items()
    if r not in GENERATED
)
print(f"site: {len(pages)} pages, {len(files)} files, {checked} links checked")

failed = False
for title, found in (
    ("broken links", broken),
    ("resources from another host", remote),
    ("email addresses", addresses),
):
    found = sorted(set(found))
    if found:
        failed = True
        print(f"\n{len(found)} {title}:")
        for line in found:
            print(f"  {line}")
    else:
        print(f"  ok    no {title}")

sys.exit(1 if failed else 0)
PY
