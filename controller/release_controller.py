#!/usr/bin/env python3
import argparse, hashlib, json, re, sys, time
from pathlib import Path

HEX40=re.compile(r"^[0-9a-f]{40}$")
HEX64=re.compile(r"^[0-9a-f]{64}$")
FORBIDDEN_NAMES={".env",".env.local",".env.production","package.json","package-lock.json","pnpm-lock.yaml","yarn.lock","wrangler.toml","wrangler.json","wrangler.jsonc"}
FORBIDDEN_SUFFIXES={".map",".ts",".tsx",".vue",".pem",".key"}
REQUIRED_GATES={
  "dependency_security":"PASS",
  "ssg":"PASS",
  "typecheck":"PASS",
  "unit":"PASS",
  "packaged_contracts":"PASS",
  "playwright":"62/62",
  "lighthouse_mobile":"33/33",
  "lighthouse_desktop":"33/33",
}
REQUIRED_TOOLCHAIN={
  "node":"24.21.0",
  "npm":"11.19.0",
  "playwright":"1.63.0",
  "lighthouse":"13.5.0",
  "platform":"linux-x64",
}
REQUIRED_EVIDENCE_KEYS={
  "bootstrap_manifest_sha256",
  "ci_contract_sha256",
  "dependency_audit_sha256",
  "full_log_sha256",
  "lighthouse_desktop_sha256",
  "lighthouse_mobile_sha256",
  "playwright_sha256",
  "source_snapshot_sha256",
  "ssg_sha256",
  "unit_sha256",
}

def sha256_bytes(data: bytes)->str:
    return hashlib.sha256(data).hexdigest()

def sha256_file(path: Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
    return h.hexdigest()

def canonical_json_bytes(value)->bytes:
    return json.dumps(value, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode("utf-8")

def receipt_digest(receipt:dict)->str:
    return sha256_bytes(canonical_json_bytes(receipt))

def artifact_digest(root: Path)->str:
    if not root.is_dir(): raise ValueError("artifact directory missing")
    rows=[]
    for p in sorted(root.rglob("*")):
        rel=p.relative_to(root).as_posix()
        if p.is_symlink(): raise ValueError(f"symlink forbidden: {rel}")
        if p.is_file(): rows.append(f"{rel}\0{sha256_file(p)}")
    return sha256_bytes(("\n".join(rows)+"\n").encode())

def validate_public_artifact(root: Path)->str:
    if not (root/"index.html").is_file(): raise ValueError("index.html missing")
    for p in root.rglob("*"):
        if not p.is_file(): continue
        rel=p.relative_to(root).as_posix()
        if p.name in FORBIDDEN_NAMES or p.suffix in FORBIDDEN_SUFFIXES:
            raise ValueError(f"forbidden public artifact: {rel}")
        if rel.startswith(".git/") or "/.git/" in rel:
            raise ValueError(f"git metadata forbidden: {rel}")
    return artifact_digest(root)

def load_request(path: Path)->dict:
    data=json.loads(path.read_text())
    if data.get("schema")!=2: raise ValueError("unsupported request schema")
    if data.get("source_repo")!="ewgenij87snwork/yevgeniy-sorokin": raise ValueError("wrong source repo")
    if not HEX40.fullmatch(data.get("source_head","")): raise ValueError("invalid source_head")
    if not HEX40.fullmatch(data.get("source_tree","")): raise ValueError("invalid source_tree")
    cloud=data.get("gpt_cloud") or {}
    receipt=cloud.get("receipt")
    if not isinstance(receipt,dict): raise ValueError("GPT cloud receipt missing")
    supplied=cloud.get("receipt_sha256","")
    if not HEX64.fullmatch(supplied): raise ValueError("invalid receipt digest")
    actual=receipt_digest(receipt)
    if actual!=supplied: raise ValueError("GPT cloud receipt digest mismatch")
    if receipt.get("schema")!=1: raise ValueError("unsupported GPT cloud receipt schema")
    subject=receipt.get("subject") or {}
    if subject!={"repo":data["source_repo"],"head":data["source_head"],"tree":data["source_tree"]}:
        raise ValueError("GPT cloud receipt subject mismatch")
    if receipt.get("status")!="PASS": raise ValueError("GPT cloud status is not PASS")
    if receipt.get("gates")!=REQUIRED_GATES: raise ValueError("required GPT cloud gate matrix incomplete")
    if receipt.get("toolchain")!=REQUIRED_TOOLCHAIN: raise ValueError("GPT cloud toolchain mismatch")
    evidence=receipt.get("evidence")
    if not isinstance(evidence,dict) or set(evidence)!=REQUIRED_EVIDENCE_KEYS:
        raise ValueError("GPT cloud evidence set incomplete")
    if any(not isinstance(v,str) or not HEX64.fullmatch(v) for v in evidence.values()):
        raise ValueError("GPT cloud evidence digest invalid")
    started=receipt.get("started_at_epoch")
    finished=receipt.get("finished_at_epoch")
    max_age=receipt.get("max_age_seconds",14400)
    if not isinstance(started,int) or started<=0: raise ValueError("invalid started_at_epoch")
    if not isinstance(finished,int) or finished<started: raise ValueError("invalid finished_at_epoch")
    if not isinstance(max_age,int) or max_age<1 or max_age>86400: raise ValueError("invalid max_age_seconds")
    now=int(time.time())
    if finished>now+300: raise ValueError("GPT cloud receipt finish time is in the future")
    if now-finished>max_age: raise ValueError("GPT cloud receipt is stale")
    return data

def verify_identity(req:dict, expected_head:str, expected_tree:str)->None:
    if req["source_head"]!=expected_head: raise ValueError("request/head mismatch")
    if req["source_tree"]!=expected_tree: raise ValueError("request/tree mismatch")

def write_manifest(req:dict, artifact:Path, output:Path)->dict:
    digest=validate_public_artifact(artifact)
    manifest={
      "schema":2,
      "source_repo":req["source_repo"],
      "source_head":req["source_head"],
      "source_tree":req["source_tree"],
      "gpt_receipt_sha256":req["gpt_cloud"]["receipt_sha256"],
      "artifact_sha256":digest,
    }
    output.write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n")
    return manifest

def verify_manifest(manifest_path:Path, artifact:Path, expected_head:str)->dict:
    m=json.loads(manifest_path.read_text())
    if m.get("schema")!=2: raise ValueError("bad manifest schema")
    if m.get("source_head")!=expected_head: raise ValueError("deploy/source mismatch")
    digest=validate_public_artifact(artifact)
    if m.get("artifact_sha256")!=digest: raise ValueError("artifact digest mismatch")
    return m

def main():
    ap=argparse.ArgumentParser()
    sub=ap.add_subparsers(dest="cmd",required=True)
    v=sub.add_parser("verify-request")
    v.add_argument("--request",required=True); v.add_argument("--head",required=True); v.add_argument("--tree",required=True)
    m=sub.add_parser("write-manifest")
    m.add_argument("--request",required=True); m.add_argument("--artifact",required=True); m.add_argument("--output",required=True)
    d=sub.add_parser("verify-deploy")
    d.add_argument("--manifest",required=True); d.add_argument("--artifact",required=True); d.add_argument("--head",required=True)
    args=ap.parse_args()
    try:
        if args.cmd=="verify-request":
            req=load_request(Path(args.request)); verify_identity(req,args.head,args.tree)
        elif args.cmd=="write-manifest":
            req=load_request(Path(args.request)); write_manifest(req,Path(args.artifact),Path(args.output))
        else:
            verify_manifest(Path(args.manifest),Path(args.artifact),args.head)
    except Exception as e:
        print(f"BLOCKED: {e}",file=sys.stderr); return 1
    print("PASS"); return 0
if __name__=="__main__": raise SystemExit(main())
