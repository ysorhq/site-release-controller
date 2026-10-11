#!/usr/bin/env python3
import argparse, hashlib, json, time
from pathlib import Path

FIXED_PROTECTED_PATHS=(
    "controller/workflow_surface_gate.py",
    "controller/release_controller.py",
)

def digest_file(path: Path)->str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def protected_surface_snapshot(root: Path):
    rows=[]
    workflows=root/".github/workflows"
    if workflows.exists():
        for p in sorted(workflows.rglob("*")):
            if p.is_file():
                rel=".github/workflows/"+p.relative_to(workflows).as_posix()
                rows.append((rel,digest_file(p)))
    for rel in FIXED_PROTECTED_PATHS:
        p=root/rel
        if not p.is_file():
            raise ValueError(f"protected controller file missing: {rel}")
        rows.append((rel,digest_file(p)))
    rows.sort()
    payload="".join(f"{p}\0{d}\n" for p,d in rows).encode()
    return dict(rows), hashlib.sha256(payload).hexdigest()

def changed_paths(a,b):
    return sorted(set(a)^set(b) | {k for k in set(a)&set(b) if a[k]!=b[k]})

def load_authorizations(path: Path):
    data=json.loads(path.read_text())
    if data.get("schema")!=2 or not isinstance(data.get("authorizations"),list):
        raise ValueError("invalid protected-surface authorization registry")
    return data["authorizations"]

def authorize(trusted_root:Path,candidate_root:Path,head_sha:str,now:int|None=None):
    now=int(time.time()) if now is None else now
    trusted,_=protected_surface_snapshot(trusted_root)
    candidate,digest=protected_surface_snapshot(candidate_root)
    changes=changed_paths(trusted,candidate)
    if not changes:
        return {"mode":"unchanged","digest":digest,"paths":[]}
    auths=load_authorizations(trusted_root/"maintenance/workflow-authorizations.json")
    for a in auths:
        if a.get("head_sha")!=head_sha: continue
        if a.get("protected_surface_sha256")!=digest: continue
        if sorted(a.get("changed_paths") or [])!=changes: continue
        exp=a.get("expires_at_epoch")
        if not isinstance(exp,int) or exp<now: continue
        if not a.get("reason"): continue
        return {"mode":"authorized","digest":digest,"paths":changes,"authorization":a}
    raise ValueError(
      "normal PR may not mutate protected controller surface without trusted-main exact authorization; "
      f"head={head_sha} digest={digest} paths={','.join(changes)}"
    )

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--trusted-root",required=True)
    ap.add_argument("--candidate-root",required=True)
    ap.add_argument("--head-sha",required=True)
    args=ap.parse_args()
    if len(args.head_sha)!=40 or any(c not in "0123456789abcdef" for c in args.head_sha):
        raise SystemExit("BLOCKED: invalid candidate head")
    try:
        out=authorize(Path(args.trusted_root),Path(args.candidate_root),args.head_sha)
    except Exception as e:
        raise SystemExit("BLOCKED: "+str(e))
    print("PASS:",out["mode"],out["digest"])
    if out["paths"]: print("protected paths:",", ".join(out["paths"]))

if __name__=="__main__": main()
