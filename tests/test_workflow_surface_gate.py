import importlib.util, json, tempfile, time, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("wg",ROOT/"controller/workflow_surface_gate.py")
wg=importlib.util.module_from_spec(spec); spec.loader.exec_module(wg)
HEAD="a"*40

class Tests(unittest.TestCase):
    def setup_roots(self):
        td=tempfile.TemporaryDirectory(); root=Path(td.name)
        trusted=root/"trusted"; candidate=root/"candidate"
        for r in [trusted,candidate]:
            (r/".github/workflows").mkdir(parents=True)
            (r/"maintenance").mkdir()
            (r/".github/workflows/base.yml").write_text("name: base\n")
            (r/"maintenance/workflow-authorizations.json").write_text('{"schema":1,"authorizations":[]}\n')
        return td,trusted,candidate
    def test_unchanged(self):
        td,t,c=self.setup_roots()
        try:self.assertEqual(wg.authorize(t,c,HEAD)["mode"],"unchanged")
        finally:td.cleanup()
    def test_unauthorized_change_blocks(self):
        td,t,c=self.setup_roots(); (c/".github/workflows/new.yml").write_text("name: new\n")
        try:
            with self.assertRaises(ValueError): wg.authorize(t,c,HEAD)
        finally:td.cleanup()
    def test_exact_authorization_passes(self):
        td,t,c=self.setup_roots(); (c/".github/workflows/new.yml").write_text("name: new\n")
        try:
            _,dig=wg.workflow_snapshot(c)
            reg={"schema":1,"authorizations":[{
              "head_sha":HEAD,"workflow_snapshot_sha256":dig,
              "changed_paths":["new.yml"],"expires_at_epoch":int(time.time())+3600,
              "reason":"test"
            }]}
            (t/"maintenance/workflow-authorizations.json").write_text(json.dumps(reg))
            self.assertEqual(wg.authorize(t,c,HEAD)["mode"],"authorized")
        finally:td.cleanup()
    def test_wrong_head_blocks(self):
        td,t,c=self.setup_roots(); (c/".github/workflows/new.yml").write_text("name: new\n")
        try:
            _,dig=wg.workflow_snapshot(c)
            reg={"schema":1,"authorizations":[{
              "head_sha":"b"*40,"workflow_snapshot_sha256":dig,
              "changed_paths":["new.yml"],"expires_at_epoch":int(time.time())+3600,"reason":"test"}]}
            (t/"maintenance/workflow-authorizations.json").write_text(json.dumps(reg))
            with self.assertRaises(ValueError): wg.authorize(t,c,HEAD)
        finally:td.cleanup()
    def test_digest_drift_blocks(self):
        td,t,c=self.setup_roots(); (c/".github/workflows/new.yml").write_text("name: new\n")
        try:
            _,dig=wg.workflow_snapshot(c)
            reg={"schema":1,"authorizations":[{
              "head_sha":HEAD,"workflow_snapshot_sha256":dig,
              "changed_paths":["new.yml"],"expires_at_epoch":int(time.time())+3600,"reason":"test"}]}
            (t/"maintenance/workflow-authorizations.json").write_text(json.dumps(reg))
            (c/".github/workflows/new.yml").write_text("name: changed\n")
            with self.assertRaises(ValueError): wg.authorize(t,c,HEAD)
        finally:td.cleanup()
    def test_expired_blocks(self):
        td,t,c=self.setup_roots(); (c/".github/workflows/new.yml").write_text("name: new\n")
        try:
            _,dig=wg.workflow_snapshot(c)
            reg={"schema":1,"authorizations":[{
              "head_sha":HEAD,"workflow_snapshot_sha256":dig,
              "changed_paths":["new.yml"],"expires_at_epoch":1,"reason":"test"}]}
            (t/"maintenance/workflow-authorizations.json").write_text(json.dumps(reg))
            with self.assertRaises(ValueError): wg.authorize(t,c,HEAD,now=2)
        finally:td.cleanup()

if __name__=="__main__": unittest.main(verbosity=2)
