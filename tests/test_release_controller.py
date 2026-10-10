import importlib.util, json, tempfile, time, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("rc",ROOT/"controller/release_controller.py")
rc=importlib.util.module_from_spec(spec); spec.loader.exec_module(rc)

HEAD="1"*40; TREE="2"*40; RECEIPT="3"*64

def request(**cloud_overrides):
    cloud={"status":"PASS","receipt_sha256":RECEIPT,"finished_at_epoch":int(time.time()),"max_age_seconds":14400,"gates":dict(rc.REQUIRED_GATES)}
    cloud.update(cloud_overrides)
    return {"schema":1,"source_repo":"ewgenij87snwork/yevgeniy-sorokin","source_head":HEAD,"source_tree":TREE,"gpt_cloud":cloud}

class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(); self.root=Path(self.t.name)
        self.req=self.root/"request.json"; self.site=self.root/"site"; self.site.mkdir()
        (self.site/"index.html").write_text("<!doctype html><title>ok</title>\n")
    def tearDown(self): self.t.cleanup()
    def write_req(self,data): self.req.write_text(json.dumps(data)); return self.req
    def test_happy_path_and_manifest(self):
        r=rc.load_request(self.write_req(request())); rc.verify_identity(r,HEAD,TREE)
        out=self.root/"manifest.json"; m=rc.write_manifest(r,self.site,out)
        self.assertEqual(m["source_head"],HEAD); rc.verify_manifest(out,self.site,HEAD)
    def test_wrong_head_blocks(self):
        r=rc.load_request(self.write_req(request()))
        with self.assertRaisesRegex(ValueError,"head"): rc.verify_identity(r,"f"*40,TREE)
    def test_wrong_tree_blocks(self):
        r=rc.load_request(self.write_req(request()))
        with self.assertRaisesRegex(ValueError,"tree"): rc.verify_identity(r,HEAD,"f"*40)
    def test_stale_receipt_blocks(self):
        with self.assertRaisesRegex(ValueError,"stale"):
            rc.load_request(self.write_req(request(finished_at_epoch=int(time.time())-20000,max_age_seconds=10)))
    def test_failed_cloud_blocks(self):
        with self.assertRaisesRegex(ValueError,"not PASS"): rc.load_request(self.write_req(request(status="FAIL")))
    def test_partial_gate_matrix_blocks(self):
        q=request(); q["gpt_cloud"]["gates"]["lighthouse_desktop"]="UNKNOWN"
        with self.assertRaisesRegex(ValueError,"incomplete"): rc.load_request(self.write_req(q))
    def test_forbidden_artifact_blocks(self):
        (self.site/".env").write_text("x=y")
        with self.assertRaisesRegex(ValueError,"forbidden"): rc.validate_public_artifact(self.site)
    def test_symlink_blocks(self):
        target=self.root/"secret"; target.write_text("secret")
        (self.site/"link").symlink_to(target)
        with self.assertRaisesRegex(ValueError,"symlink"): rc.validate_public_artifact(self.site)
    def test_artifact_tamper_blocks(self):
        r=rc.load_request(self.write_req(request())); out=self.root/"manifest.json"
        rc.write_manifest(r,self.site,out); (self.site/"index.html").write_text("tampered")
        with self.assertRaisesRegex(ValueError,"digest"): rc.verify_manifest(out,self.site,HEAD)

class IntentionalProviderCanary(unittest.TestCase):\n    def test_intentional_red(self): self.fail("intentional provider gate canary")\n\nif __name__=="__main__": unittest.main(verbosity=2)
