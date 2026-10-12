import importlib.util, json, tempfile, time, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("wg",ROOT/"controller/workflow_surface_gate.py")
wg=importlib.util.module_from_spec(spec); spec.loader.exec_module(wg)
HEAD="a"*40

class Tests(unittest.TestCase):
    def setup_roots(self):
        td=tempfile.TemporaryDirectory(); root=Path(td.name)
        trusted=root/"trusted"; candidate=root/"candidate"; comments=root/"comments.json"
        for r in [trusted,candidate]:
            (r/".github/workflows").mkdir(parents=True)
            (r/"controller").mkdir()
            (r/"bootstrap-requests").mkdir()
            (r/"network-requests").mkdir()
            (r/".github/workflows/base.yml").write_text("name: base\n")
            (r/"controller/workflow_surface_gate.py").write_text("gate\n")
            (r/"controller/release_controller.py").write_text("release\n")
            (r/"bootstrap-requests/transport-public.pem").write_text("cert\n")
            (r/"bootstrap-requests/current.json").write_text("{}\n")
            (r/"network-requests/current.json").write_text("{}\n")
        comments.write_text("[]\n")
        return td,trusted,candidate,comments
    def comment(self,t,c,path,head=HEAD,expires=None,login="ewgenij87snwork"):
        _,dig=wg.protected_surface_snapshot(c)
        paths=wg.changed_paths(wg.protected_surface_snapshot(t)[0],wg.protected_surface_snapshot(c)[0])
        data={
          "head_sha":head,"protected_surface_sha256":dig,"changed_paths":paths,
          "expires_at_epoch":int(time.time())+3600 if expires is None else expires,
          "reason":"test"
        }
        path.write_text(json.dumps([{"user":{"login":login},"body":wg.AUTH_MARKER+"\n"+json.dumps(data)}]))
    def test_unchanged(self):
        td,t,c,p=self.setup_roots()
        try:self.assertEqual(wg.authorize(t,c,HEAD,p)["mode"],"unchanged")
        finally:td.cleanup()
    def test_unauthorized_workflow_change_blocks(self):
        td,t,c,p=self.setup_roots(); (c/".github/workflows/new.yml").write_text("name: new\n")
        try:
            with self.assertRaises(ValueError): wg.authorize(t,c,HEAD,p)
        finally:td.cleanup()
    def test_unauthorized_gate_script_change_blocks(self):
        td,t,c,p=self.setup_roots(); (c/"controller/workflow_surface_gate.py").write_text("tampered\n")
        try:
            with self.assertRaises(ValueError): wg.authorize(t,c,HEAD,p)
        finally:td.cleanup()
    def test_unauthorized_release_controller_change_blocks(self):
        td,t,c,p=self.setup_roots(); (c/"controller/release_controller.py").write_text("tampered\n")
        try:
            with self.assertRaises(ValueError): wg.authorize(t,c,HEAD,p)
        finally:td.cleanup()
    def test_unauthorized_bootstrap_request_change_blocks(self):
        td,t,c,p=self.setup_roots()
        (c/"bootstrap-requests/current.json").write_text('{"changed":true}\n')
        try:
            with self.assertRaises(ValueError): wg.authorize(t,c,HEAD,p)
        finally: td.cleanup()

    def test_unauthorized_network_request_change_blocks(self):
        td,t,c,p=self.setup_roots()
        (c/"network-requests/current.json").write_text('{"changed":true}\n')
        try:
            with self.assertRaises(ValueError): wg.authorize(t,c,HEAD,p)
        finally: td.cleanup()

    def test_exact_owner_comment_passes(self):
        td,t,c,p=self.setup_roots(); (c/".github/workflows/new.yml").write_text("name: new\n")
        try:
            self.comment(t,c,p)
            self.assertEqual(wg.authorize(t,c,HEAD,p)["mode"],"authorized")
        finally:td.cleanup()
    def test_wrong_author_commenter_blocks(self):
        td,t,c,p=self.setup_roots(); (c/".github/workflows/new.yml").write_text("name: new\n")
        try:
            self.comment(t,c,p,login="someone-else")
            with self.assertRaises(ValueError): wg.authorize(t,c,HEAD,p)
        finally:td.cleanup()
    def test_wrong_head_blocks(self):
        td,t,c,p=self.setup_roots(); (c/".github/workflows/new.yml").write_text("name: new\n")
        try:
            self.comment(t,c,p,head="b"*40)
            with self.assertRaises(ValueError): wg.authorize(t,c,HEAD,p)
        finally:td.cleanup()
    def test_digest_drift_blocks(self):
        td,t,c,p=self.setup_roots(); (c/".github/workflows/new.yml").write_text("name: new\n")
        try:
            self.comment(t,c,p)
            (c/".github/workflows/new.yml").write_text("name: changed\n")
            with self.assertRaises(ValueError): wg.authorize(t,c,HEAD,p)
        finally:td.cleanup()
    def test_expired_blocks(self):
        td,t,c,p=self.setup_roots(); (c/".github/workflows/new.yml").write_text("name: new\n")
        try:
            self.comment(t,c,p,expires=1)
            with self.assertRaises(ValueError): wg.authorize(t,c,HEAD,p,now=2)
        finally:td.cleanup()
    def test_excessive_lifetime_blocks(self):
        td,t,c,p=self.setup_roots(); (c/".github/workflows/new.yml").write_text("name: new\n")
        try:
            self.comment(t,c,p,expires=100000)
            with self.assertRaises(ValueError): wg.authorize(t,c,HEAD,p,now=1)
        finally:td.cleanup()

if __name__=="__main__": unittest.main(verbosity=2)
