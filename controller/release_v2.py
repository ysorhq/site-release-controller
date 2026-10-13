#!/usr/bin/env python3
"""Independent verifier: consumes only a static artifact and trusted manifest.

Never runs private-candidate code, receives a source token or deploy credentials.
An unsigned GPT receipt digest is an input identity, NOT a trusted attestation.
"""
import argparse
import base64
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

SOURCE_REPO = "ewgenij87snwork/yevgeniy-sorokin"
# This protocol has proved isolation ONLY. A GPT receipt digest is not proof of PASS.
CANARY_MODE = "CANARY_VERIFY_ONLY_NO_RELEASE"
CANARY_GPT_STATUS = "BLOCKED"
ORIGIN = "https://yevgeniy-sorokin.pages.dev"
ROUTES = (
    "/", "/work/", "/work/clroom/", "/work/secure-data-room/",
    "/work/deals-marketplace/", "/notes/", "/notes/angular-data-flow-bugs/",
    "/knowledge/", "/knowledge/angular-value-trace/", "/skills/",
    "/skills/angular-value-trace/",
)
MACHINE = (
    "llms.txt", "knowledge-index.json", ".well-known/agent-skills/index.json",
    "assets/agent-surface/webmcp.js",
    "assets/agent-surface/knowledge-tools.mjs",
)
FORBIDDEN_NAMES = {
    ".env", ".env.local", ".env.production", "package.json",
    "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "wrangler.toml",
}
FORBIDDEN_SUFFIXES = {".map", ".ts", ".tsx", ".vue", ".pem", ".key"}
HEX40 = re.compile(r"^[a-f0-9]{40}$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")


class Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.active = False
        self.data = []
        self.bodies = []

    def handle_starttag(self, tag, attrs):
        if tag != "script":
            return
        d = dict(attrs)
        self.active = "src" not in d and d.get("type", "") not in (
            "application/json", "application/ld+json",
        )
        self.data = []

    def handle_data(self, data):
        if self.active:
            self.data.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self.active:
            script = "".join(self.data)
            if script.strip():
                self.bodies.append(script)
        if tag == "script":
            self.active = False


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact_digest(root: Path) -> str:
    if not root.is_dir():
        raise ValueError("public root missing")
    lines = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError("public symlink: " + rel)
        if path.is_dir():
            continue
        if not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError("nonregular public file: " + rel)
        if path.name in FORBIDDEN_NAMES or path.suffix in FORBIDDEN_SUFFIXES or ".git" in path.parts:
            raise ValueError("forbidden public file: " + rel)
        if rel.startswith("node_modules/") or "/../" in rel or rel.startswith(".git/"):
            raise ValueError("private public path: " + rel)
        lines.append(rel + "\0" + file_digest(path))
    if len(lines) < len(ROUTES):
        raise ValueError("public artifact too small")
    return hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest()


def static_contract(root: Path):
    headers = (root / "_headers").read_text()
    if "__WEBMCP_ORIGIN_TRIAL_TOKEN__" in headers:
        raise ValueError("unresolved origin trial placeholder")
    if not re.search(r"(?im)^\s*Strict-Transport-Security:\s*max-age=(?:31536000|[4-9]\d{7,})", headers):
        raise ValueError("HSTS not enforced")
    matches = re.findall(r"(?im)^\s*Content-Security-Policy:\s*(.+)$", headers)
    if len(matches) != 1:
        raise ValueError("single canonical CSP required")
    csp = matches[0]
    for token in (
        "default-src 'self'", "base-uri 'self'", "object-src 'none'",
        "frame-ancestors 'none'", "script-src 'self'",
    ):
        if token not in csp:
            raise ValueError("weakened CSP: " + token)
    for token in ("'unsafe-inline'", "'unsafe-eval'", "http:"):
        if token in csp:
            raise ValueError("unsafe CSP: " + token)
    if (root / "_redirects").exists():
        redirects = (root / "_redirects").read_text()
        if re.search(r"(?m)^\s*/\*\s+/index\.html\s+200\b", redirects):
            raise ValueError("SPA fallback forbidden")
    not_found = (root / "404.html").read_text()
    if "noindex,follow" not in not_found or "Page not found" not in not_found:
        raise ValueError("true 404 contract missing")
    sitemap = ET.fromstring((root / "sitemap.xml").read_text())
    actual = {
        node.text.strip()
        for node in sitemap.iter()
        if (node.tag.endswith("}loc") or node.tag == "loc") and node.text
    }
    wanted = {ORIGIN + route for route in ROUTES}
    if actual != wanted:
        raise ValueError("frozen sitemap routes differ")
    for route in ROUTES:
        html = (root / (route.lstrip("/") + "index.html")).read_text()
        if html.count("<h1") != 1:
            raise ValueError("wrong H1 count: " + route)
        if 'href="' + ORIGIN + route + '"' not in html:
            raise ValueError("canonical mismatch: " + route)
        if "index,follow" not in html:
            raise ValueError("robots mismatch: " + route)
        scripts = Scripts()
        scripts.feed(html)
        for script in scripts.bodies:
            digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
            if "'sha256-" + digest + "'" not in csp:
                raise ValueError("inline executable missing CSP hash: " + route)
    for name in MACHINE:
        if not (root / name).is_file():
            raise ValueError("missing machine surface: " + name)
    return {"routes": len(ROUTES), "machine_surfaces": len(MACHINE)}


def verify(manifest: Path, root: Path, head: str, tree: str, cloud_digest: str):
    if not HEX40.fullmatch(head) or not HEX40.fullmatch(tree) or not HEX64.fullmatch(cloud_digest):
        raise ValueError("invalid immutable binding inputs")
    obj = json.loads(manifest.read_text())
    expected = {
        "schema": 2, "source_repo": SOURCE_REPO,
        "source_head": head, "source_tree": tree,
        "gpt_receipt_sha256": cloud_digest,
        "release_mode": CANARY_MODE,
        "gpt_ci_status": CANARY_GPT_STATUS,
    }
    for key, value in expected.items():
        if obj.get(key) != value:
            raise ValueError("manifest binding mismatch: " + key)
    digest = artifact_digest(root)
    if obj.get("artifact_sha256") != digest:
        raise ValueError("artifact digest mismatch")
    result = static_contract(root)
    return {"artifact_sha256": digest, **result}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--gpt-receipt-sha256", required=True)
    parser.add_argument("--create", action="store_true", help="Trusted host writes manifest after candidate sandbox exits")
    args = parser.parse_args()
    try:
        if args.create:
            if not HEX40.fullmatch(args.head) or not HEX40.fullmatch(args.tree) or not HEX64.fullmatch(args.gpt_receipt_sha256):
                raise ValueError("invalid immutable binding inputs")
            static_contract(args.artifact)
            obj = {
                "schema": 2, "source_repo": SOURCE_REPO,
                "source_head": args.head, "source_tree": args.tree,
                "gpt_receipt_sha256": args.gpt_receipt_sha256,
                "release_mode": CANARY_MODE,
                "gpt_ci_status": CANARY_GPT_STATUS,
                "artifact_sha256": artifact_digest(args.artifact),
            }
            args.manifest.write_text(json.dumps(obj, sort_keys=True, indent=2) + "\n")
        result = verify(args.manifest, args.artifact, args.head, args.tree, args.gpt_receipt_sha256)
        print("CANARY_ONLY_PASS (NOT RELEASE ADMISSION):", json.dumps(result, sort_keys=True))
    except Exception as exc:
        print("BLOCKED:", str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
