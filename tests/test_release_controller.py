import importlib.util, json, tempfile, time, unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("rc",ROOT/"controller/release_controller.py")
rc=importlib.util.module_from_spec(spec); spec.loader.exec_module(rc)

HEAD="1"*40; TREE="2"*40; DIGEST="3"*64

def receipt(**overrides):
    r={
      "schema":1,
      "subject":{"repo":"ewgenij87snwork/yevgeniy-sorokin","head":HEAD,"tree":TREE},
      "status":"PASS",
      "started_at_epoch":int(time.time())-30,
      "finished_at_epoch":int(time.time()),
      "max_age_seconds":14400,
      "toolchain":dict(rc.REQUIRED_TOOLCHAIN),
      "gates":dict(rc.REQUIRED_GATES),
      "evidence":{k:DIGEST for k in rc.REQUIRED_EVIDENCE_KEYS},
    }
    r.update(overrides)
    return r

def request(r=None):
    r=receipt() if r is None else r
    return {
      "schema":2,
      "source_repo":"ewgenij87snwork/yevgeniy-sorokin",
      "source_head":HEAD,
      "source_tree":TREE,
      "gpt_cloud":{"receipt":r,"receipt_sha256":rc.receipt_digest(r)}
    }

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
        self.assertEqual(m["schema"],2); self.assertEqual(m["source_head"],HEAD); rc.verify_manifest(out,self.site,HEAD)
    def test_wrong_head_blocks(self):
        r=rc.load_request(self.write_req(request()))
        with self.assertRaisesRegex(ValueError,"head"): rc.verify_identity(r,"f"*40,TREE)
    def test_wrong_tree_blocks(self):
        r=rc.load_request(self.write_req(request()))
        with self.assertRaisesRegex(ValueError,"tree"): rc.verify_identity(r,HEAD,"f"*40)
    def test_stale_receipt_blocks(self):
        rr=receipt(started_at_epoch=int(time.time())-20000,finished_at_epoch=int(time.time())-19000,max_age_seconds=10)
        with self.assertRaisesRegex(ValueError,"stale"): rc.load_request(self.write_req(request(rr)))
    def test_future_receipt_blocks(self):
        rr=receipt(started_at_epoch=int(time.time())+500,finished_at_epoch=int(time.time())+600)
        with self.assertRaisesRegex(ValueError,"future"): rc.load_request(self.write_req(request(rr)))
    def test_failed_cloud_blocks(self):
        rr=receipt(status="FAIL")
        with self.assertRaisesRegex(ValueError,"not PASS"): rc.load_request(self.write_req(request(rr)))
    def test_partial_gate_matrix_blocks(self):
        rr=receipt(); rr["gates"]["lighthouse_desktop"]="UNKNOWN"
        with self.assertRaisesRegex(ValueError,"incomplete"): rc.load_request(self.write_req(request(rr)))
    def test_toolchain_drift_blocks(self):
        rr=receipt(); rr["toolchain"]["node"]="99.0.0"
        with self.assertRaisesRegex(ValueError,"toolchain"): rc.load_request(self.write_req(request(rr)))
    def test_partial_evidence_blocks(self):
        rr=receipt(); rr["evidence"].pop("full_log_sha256")
        with self.assertRaisesRegex(ValueError,"evidence set"): rc.load_request(self.write_req(request(rr)))
    def test_invalid_evidence_digest_blocks(self):
        rr=receipt(); rr["evidence"]["full_log_sha256"]="nope"
        with self.assertRaisesRegex(ValueError,"evidence digest"): rc.load_request(self.write_req(request(rr)))
    def test_receipt_subject_mismatch_blocks(self):
        rr=receipt(); rr["subject"]["head"]="f"*40
        with self.assertRaisesRegex(ValueError,"subject"): rc.load_request(self.write_req(request(rr)))
    def test_receipt_digest_tamper_blocks(self):
        q=request(); q["gpt_cloud"]["receipt"]["status"]="FAIL"
        with self.assertRaisesRegex(ValueError,"digest mismatch"): rc.load_request(self.write_req(q))
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

if __name__=="__main__": unittest.main(verbosity=2)
