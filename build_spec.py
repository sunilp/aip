#!/usr/bin/env python3
"""Build site/spec/index.html from spec/*.md as one long page with TOC."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_DIR = REPO_ROOT / "spec"

DOC_ORDER = [
    "aip-core",
    "aip-tokens",
    "aip-delegation",
    "aip-provenance",
    "aip-bindings-mcp",
    "aip-bindings-a2a",
    "aip-bindings-http",
]

PAGE_TITLE = "AIP Specification v0.2.0"  # bump manually on each release
ARXIV_URL = "https://arxiv.org/abs/2603.24775"
IETF_URL = "https://datatracker.ietf.org/doc/draft-prakash-aip/"


def slugify(text: str) -> str:
    text = text.strip().lower()
    # Strip leading numeric section prefix like "4. " or "1.2 "
    text = re.sub(r"^\d+(\.\d+)*\.?\s+", "", text)
    text = re.sub(r"[^a-z0-9\s-]", "", text)
    text = re.sub(r"\s+", "-", text)
    return text.strip("-")


def md_to_html(md: str, file_id: str) -> tuple[str, list[tuple[int, str, str]]]:
    """Convert markdown to HTML. Returns (html, headings_for_toc).

    Each heading in headings_for_toc: (level, anchor_id, text).
    Anchors for H2/H3 are prefixed with file_id to be globally unique.
    """
    lines = md.splitlines()
    out: list[str] = []
    headings: list[tuple[int, str, str]] = []
    in_code = False
    in_table = False

    for raw in lines:
        if raw.startswith("```"):
            if in_code:
                out.append("</code></pre>")
                in_code = False
            else:
                lang = raw[3:].strip()
                out.append(f'<pre><code class="lang-{lang}">' if lang else "<pre><code>")
                in_code = True
            continue
        if in_code:
            out.append(escape_html(raw))
            continue

        # Headings.
        m = re.match(r"^(#{1,4})\s+(.*)$", raw)
        if m:
            level = len(m.group(1))
            text = m.group(2).strip()
            text_clean = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
            if level == 1:
                # H1 of the file becomes the section title; we already emit our own H1 wrapper.
                out.append(f"<h2>{render_inline(text_clean)}</h2>")
                continue
            anchor = f"{file_id}-{slugify(text_clean)}"
            headings.append((level, anchor, text_clean))
            out.append(f'<h{level + 1} id="{anchor}">{render_inline(text_clean)}</h{level + 1}>')
            continue

        # Horizontal rules.
        if raw.strip() == "---":
            out.append("<hr/>")
            continue

        # Tables (very simple — pipe-delimited).
        if "|" in raw and raw.strip().startswith("|"):
            cells = [c.strip() for c in raw.strip().strip("|").split("|")]
            if all(re.match(r"^:?-+:?$", c) for c in cells):
                # Separator row, skip.
                continue
            if not in_table:
                out.append("<table>")
                in_table = True
                tag = "th"
            else:
                tag = "td"
            row = "".join(f"<{tag}>{render_inline(c)}</{tag}>" for c in cells)
            out.append(f"<tr>{row}</tr>")
            continue
        elif in_table:
            out.append("</table>")
            in_table = False

        # Lists.
        if re.match(r"^\s*[-*]\s+", raw):
            stripped = re.sub(r"^\s*[-*]\s+", "", raw)
            out.append(f"<li>{render_inline(stripped)}</li>")
            continue
        if re.match(r"^\s*\d+\.\s+", raw):
            stripped = re.sub(r"^\s*\d+\.\s+", "", raw)
            out.append(f"<li>{render_inline(stripped)}</li>")
            continue

        if raw.strip() == "":
            out.append("")
            continue

        out.append(f"<p>{render_inline(raw)}</p>")

    if in_code:
        out.append("</code></pre>")
    if in_table:
        out.append("</table>")

    # Wrap consecutive <li> in <ul>.
    html = "\n".join(out)
    html = re.sub(r"((?:<li>.*?</li>\s*)+)", r"<ul>\1</ul>", html, flags=re.DOTALL)
    return html, headings


def escape_html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_inline(text: str) -> str:
    text = escape_html(text)
    # `code`
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    # **bold**
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    # *em*
    text = re.sub(r"(?<![*])\*([^*]+)\*(?![*])", r"<em>\1</em>", text)
    # [link](url)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)
    # RFC 2119 keywords as callouts — single pass so two-word forms (MUST NOT,
    # SHOULD NOT) are captured before the one-word forms (MUST, SHOULD), preventing
    # nested-span corruption on a second regex pass.
    text = re.sub(
        r"\b(MUST NOT|SHOULD NOT|MUST|SHOULD|REQUIRED|RECOMMENDED|MAY|OPTIONAL)\b",
        r'<span class="rfc2119">\1</span>',
        text,
    )
    return text


def build_page() -> str:
    sections_html: list[str] = []
    toc_entries: list[str] = []
    for doc in DOC_ORDER:
        md = (SPEC_DIR / f"{doc}.md").read_text()
        body_html, headings = md_to_html(md, doc)
        sections_html.append(f'<section id="{doc}">\n{body_html}\n</section>')
        toc_entries.append(f'<li class="toc-h1"><a href="#{doc}">{doc}</a></li>')
        for level, anchor, text in headings:
            cls = f"toc-h{level}"
            toc_entries.append(f'<li class="{cls}"><a href="#{anchor}">{text}</a></li>')

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{PAGE_TITLE} -- AIP</title>
<link rel="stylesheet" href="/aip/css/style.css"/>
<link rel="stylesheet" href="/aip/css/spec.css"/>
</head>
<body>
<header class="spec-header">
<h1>{PAGE_TITLE}</h1>
<p class="spec-links">
  <a href="{ARXIV_URL}">arXiv:2603.24775</a> ·
  <a href="{IETF_URL}">IETF draft-prakash-aip-00</a> ·
  <a href="https://github.com/sunilp/aip">GitHub</a>
</p>
</header>
<div class="spec-layout">
<aside class="spec-toc"><nav><ul>
{"\n".join(toc_entries)}
</ul></nav></aside>
<main class="spec-content">
{"\n".join(sections_html)}
</main>
</div>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(REPO_ROOT / "site" / "spec" / "index.html"))
    args = parser.parse_args()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build_page())
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
