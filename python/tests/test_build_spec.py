"""Tests for site/build_spec.py — converts spec/*.md into one rendered HTML page."""
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_SCRIPT = REPO_ROOT / "site" / "build_spec.py"
SPEC_DIR = REPO_ROOT / "spec"
OUT_FILE = REPO_ROOT / "site" / "spec" / "index.html"


def test_build_emits_index_html(tmp_path):
    out = tmp_path / "index.html"
    subprocess.run(
        [sys.executable, str(BUILD_SCRIPT), "--out", str(out)],
        check=True,
    )
    html = out.read_text()
    # All seven spec docs are stitched into one page.
    for name in [
        "aip-core",
        "aip-tokens",
        "aip-delegation",
        "aip-provenance",
        "aip-bindings-mcp",
        "aip-bindings-a2a",
        "aip-bindings-http",
    ]:
        assert f'id="{name}"' in html, f"missing section anchor for {name}"
    # Title and headers present.
    assert "AIP Specification" in html
    # Sticky TOC present.
    assert 'class="spec-toc"' in html


def test_build_idempotent(tmp_path):
    out1 = tmp_path / "a.html"
    out2 = tmp_path / "b.html"
    subprocess.run([sys.executable, str(BUILD_SCRIPT), "--out", str(out1)], check=True)
    subprocess.run([sys.executable, str(BUILD_SCRIPT), "--out", str(out2)], check=True)
    assert out1.read_text() == out2.read_text()


def test_h2_anchors_use_filename_prefix(tmp_path):
    out = tmp_path / "index.html"
    subprocess.run([sys.executable, str(BUILD_SCRIPT), "--out", str(out)], check=True)
    html = out.read_text()
    # H2 inside a section gets a slug prefixed by the file id.
    # spec/aip-bindings-a2a.md has "## 4. Verification Flow" → id="aip-bindings-a2a-verification-flow"
    assert 'id="aip-bindings-a2a-verification-flow"' in html
