import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("release_v2", ROOT / "controller/release_v2.py")
v2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v2)
HEAD = "c234a18bb55fa935cdc612f4643fb0f035aa4761"
TREE = "b70613686239066904f94668bc8b1ef5caf2f8e4"
RECEIPT = "a" * 64


class ReleaseV2Tests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root = Path(self.t.name)
        self.site = self.root / "site"
        self.site.mkdir()
        for route in v2.ROUTES:
            page = self.site / (route.lstrip("/") + "index.html")
            page.parent.mkdir(parents=True, exist_ok=True)
            page.write_text(
                '<!doctype html><html><head><meta name="robots" content="index,follow">'
                '<link rel="canonical" href="' + v2.ORIGIN + route + '">'
                '</head><body><h1>OK</h1></body></html>'
            )
        (self.site / "_headers").write_text(
            "/*\n"
            "  Strict-Transport-Security: max-age=31536000\n"
            "  Content-Security-Policy: default-src 'self'; base-uri 'self'; "
            "object-src 'none'; frame-ancestors 'none'; script-src 'self'\n"
        )
        (self.site / "404.html").write_text("Page not found noindex,follow")
        (self.site / "sitemap.xml").write_text(
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            + "".join("<url><loc>" + v2.ORIGIN + path + "</loc></url>" for path in v2.ROUTES)
            + "</urlset>"
        )
        for name in v2.MACHINE:
            path = self.site / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("ok")
        self.manifest = self.root / "manifest.json"
        self.refresh()

    def refresh(self):
        obj = {
            "schema": 2, "source_repo": v2.SOURCE_REPO,
            "source_head": HEAD, "source_tree": TREE,
            "gpt_receipt_sha256": RECEIPT,
            "artifact_sha256": v2.artifact_digest(self.site),
        }
        self.manifest.write_text(json.dumps(obj))

    def verify(self, **kw):
        return v2.verify(
            self.manifest, self.site,
            kw.get("head", HEAD), kw.get("tree", TREE), kw.get("receipt", RECEIPT),
        )

    def test_positive(self):
        self.assertEqual(self.verify()["routes"], 11)

    def test_wrong_head(self):
        with self.assertRaisesRegex(ValueError, "binding"):
            self.verify(head="f" * 40)

    def test_wrong_tree(self):
        with self.assertRaisesRegex(ValueError, "binding"):
            self.verify(tree="f" * 40)

    def test_wrong_receipt(self):
        with self.assertRaisesRegex(ValueError, "binding"):
            self.verify(receipt="f" * 64)

    def test_artifact_tamper(self):
        (self.site / "index.html").write_text("TAMPER")
        with self.assertRaisesRegex(ValueError, "digest"):
            self.verify()

    def test_forbidden_secret(self):
        (self.site / ".env").write_text("S=1")
        with self.assertRaisesRegex(ValueError, "forbidden"):
            self.verify()

    def test_symlink(self):
        (self.site / "link").symlink_to("/etc/passwd")
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.verify()

    def test_weak_csp(self):
        path = self.site / "_headers"
        path.write_text(path.read_text().replace("script-src 'self'", "script-src 'self' 'unsafe-inline'"))
        self.refresh()
        with self.assertRaisesRegex(ValueError, "unsafe CSP"):
            self.verify()

    def test_missing_route(self):
        (self.site / "work/index.html").unlink()
        self.refresh()
        with self.assertRaises(FileNotFoundError):
            self.verify()

    def test_origin_trial_placeholder(self):
        path = self.site / "_headers"
        path.write_text(path.read_text() + "  Origin-Trial: __WEBMCP_ORIGIN_TRIAL_TOKEN__\n")
        self.refresh()
        with self.assertRaisesRegex(ValueError, "placeholder"):
            self.verify()


if __name__ == "__main__":
    unittest.main(verbosity=2)
