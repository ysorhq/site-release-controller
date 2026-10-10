#!/usr/bin/env python3
import importlib.util, json, re, sys, tempfile, time
from pathlib import Path

if len(sys.argv)!=2:
    raise SystemExit("usage: trusted_pr_gate.py <candidate-root>")
candidate=Path(sys.argv[1]).resolve()
trusted_root=Path(__file__).resolve().parents[1]

# These two files are the trust anchor. Normal PRs may not alter them.
for rel in [Path(".github/workflows/controller-ci.yml"), Path("tests/trusted_pr_gate.py")]:
    a=(trusted_root/rel).read_bytes()
    b=(candidate/rel).read_bytes()
    if a!=b:
        raise SystemExit(f"BLOCKED: trust-anchor change requires explicit maintenance procedure: {rel}")

ci=(candidate/".github/workflows/controller-ci.yml").read_text()
release=(candidate/".github/workflows/release.yml").read_text()
if not re.search(r"(?m)^\s{2}pull_request_target:\s*$",ci):
    raise SystemExit("BLOCKED: controller CI must use pull_request_target")
if re.search(r"(?m)^\s{2}pull_request:\s*$",ci):
    raise SystemExit("BLOCKED: ordinary pull_request trigger may not replace trusted gate")
if "secrets." in ci:
    raise SystemExit("BLOCKED: controller PR gate may not reference secrets")
if "permissions:\n  contents: read" not in ci:
    raise SystemExit("BLOCKED: controller CI permissions drift")
if "environment: source-read" not in release or "environment: production" not in release:
    raise SystemExit("BLOCKED: release environment boundary missing")
marker="\n  deploy:\n"
if marker not in release:
    raise SystemExit("BLOCKED: deploy job boundary missing")
verify,deploy=release.split(marker,1)
for name in ["CLOUDFLARE_API_TOKEN","CLOUDFLARE_ACCOUNT_ID"]:
    if name in verify:
        raise SystemExit(f"BLOCKED: {name} leaked into verify-source job")
for name in ["PRIVATE_SOURCE_APP_ID","PRIVATE_SOURCE_APP_PRIVATE_KEY","WEBMCP_ORIGIN_TRIAL_TOKEN"]:
    if name in deploy:
        raise SystemExit(f"BLOCKED: {name} leaked into deploy job")
for required in [
 "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
 "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
 "persist-credentials: false",
 "permission-contents: read",
 "repository: ewgenij87snwork/yevgeniy-sorokin",
 "npm run audit:dependencies",
 "npx playwright install --with-deps chromium",
 "uses: ./source/.github/actions/site-quality-gates",
 "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
 "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131",
 "cloudflare/wrangler-action@da0e0dfe58b7a431659754fdf3f186c529afbe65",
]:
    if required not in release:
        raise SystemExit(f"BLOCKED: release invariant missing: {required}")

# Execute independent behavioral probes against candidate controller code.
module_path=candidate/"controller/release_controller.py"
spec=importlib.util.spec_from_file_location("candidate_rc",module_path)
rc=importlib.util.module_from_spec(spec); spec.loader.exec_module(rc)
expected={
 "dependency_security":"PASS","ssg":"PASS","typecheck":"PASS","unit":"PASS",
 "packaged_contracts":"PASS","playwright":"62/62","lighthouse_mobile":"33/33","lighthouse_desktop":"33/33",
}
if rc.REQUIRED_GATES!=expected:
    raise SystemExit("BLOCKED: GPT-cloud required gate matrix drift")

HEAD="1"*40; TREE="2"*40; RECEIPT="3"*64
def req():
    return {
      "schema":1,"source_repo":"ewgenij87snwork/yevgeniy-sorokin","source_head":HEAD,"source_tree":TREE,
      "gpt_cloud":{"status":"PASS","receipt_sha256":RECEIPT,"finished_at_epoch":int(time.time()),
                   "max_age_seconds":14400,"gates":dict(expected)}
    }
def expect_fail(label,fn):
    try: fn()
    except Exception: return
    raise SystemExit("BLOCKED: negative control passed unexpectedly: "+label)

with tempfile.TemporaryDirectory() as td:
    root=Path(td); request=root/"request.json"; site=root/"site"; site.mkdir()
    (site/"index.html").write_text("<!doctype html><title>ok</title>\n")
    request.write_text(json.dumps(req()))
    r=rc.load_request(request); rc.verify_identity(r,HEAD,TREE)
    expect_fail("wrong head",lambda:rc.verify_identity(r,"f"*40,TREE))
    expect_fail("wrong tree",lambda:rc.verify_identity(r,HEAD,"f"*40))
    q=req(); q["gpt_cloud"]["status"]="FAIL"; request.write_text(json.dumps(q))
    expect_fail("failed cloud",lambda:rc.load_request(request))
    q=req(); q["gpt_cloud"]["finished_at_epoch"]=int(time.time())-20000; q["gpt_cloud"]["max_age_seconds"]=10
    request.write_text(json.dumps(q)); expect_fail("stale receipt",lambda:rc.load_request(request))
    q=req(); q["gpt_cloud"]["gates"]["lighthouse_desktop"]="UNKNOWN"; request.write_text(json.dumps(q))
    expect_fail("partial evidence",lambda:rc.load_request(request))
    request.write_text(json.dumps(req())); r=rc.load_request(request)
    manifest=root/"manifest.json"; rc.write_manifest(r,site,manifest)
    (site/"index.html").write_text("tampered")
    expect_fail("artifact tamper",lambda:rc.verify_manifest(manifest,site,HEAD))
    (site/"index.html").write_text("ok"); (site/".env").write_text("x=y")
    expect_fail("forbidden artifact",lambda:rc.validate_public_artifact(site))

print("PASS: trusted controller gate")
