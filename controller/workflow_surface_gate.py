#!/usr/bin/env python3
import argparse, hashlib, json, time
from pathlib import Path

FIXED_PROTECTED_PATHS=(
    "controller/workflow_surface_gate.py",
    "controller/release_controller.py",
    "controller/release_v2.py",
    "tests/test_release_v2.py",
    "bootstrap-requests/transport-public.pem",
    "bootstrap-requests/current.json",
    "network-requests/current.json",
)
AUTH_MARKER="CONTROLLER_MAINTENANCE_V1"
AUTHORIZER_LOGIN="ewgenij87snwork"
MAX_AUTH_LIFETIME_SECONDS=14400

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

def parse_authorization_comment(body:str):
    lines=body.strip().splitlines()
    if len(lines)!=2 or lines[0].strip()!=AUTH_MARKER:
        return None
    try:
        data=json.loads(lines[1])
    except Exception:
        return None
    return data if isinstance(data,dict) else None

def load_trusted_comment_authorizations(path:Path):
    comments=json.loads(path.read_text())
    if not isinstance(comments,list):
        raise ValueError("invalid PR comments payload")
    out=[]
    for c in comments:
        if not isinstance(c,dict): continue
        user=c.get("user") or {}
        if user.get("login")!=AUTHORIZER_LOGIN: continue
        data=parse_authorization_comment(c.get("body") or "")
        if data is None: continue
        out.append(data)
    return out

def authorize(trusted_root:Path,candidate_root:Path,head_sha:str,comments_path:Path,now:int|None=None):
    now=int(time.time()) if now is None else now
    trusted,_=protected_surface_snapshot(trusted_root)
    candidate,digest=protected_surface_snapshot(candidate_root)
    changes=changed_paths(trusted,candidate)
    if not changes:
        return {"mode":"unchanged","digest":digest,"paths":[]}
    auths=load_trusted_comment_authorizations(comments_path)
    for a in auths:
        if a.get("head_sha")!=head_sha: continue
        if a.get("protected_surface_sha256")!=digest: continue
        if sorted(a.get("changed_paths") or [])!=changes: continue
        exp=a.get("expires_at_epoch")
        if not isinstance(exp,int) or exp<now or exp>now+MAX_AUTH_LIFETIME_SECONDS: continue
        if not isinstance(a.get("reason"),str) or not a["reason"].strip(): continue
        return {"mode":"authorized","digest":digest,"paths":changes,"authorization":a}
    raise ValueError(
      "normal PR may not mutate protected controller surface without exact owner-comment authorization; "
      f"head={head_sha} digest={digest} paths={','.join(changes)}"
    )

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--trusted-root",required=True)
    ap.add_argument("--candidate-root",required=True)
    ap.add_argument("--head-sha",required=True)
    ap.add_argument("--comments-file",required=True)
    args=ap.parse_args()
    if len(args.head_sha)!=40 or any(c not in "0123456789abcdef" for c in args.head_sha):
        raise SystemExit("BLOCKED: invalid candidate head")
    try:
        out=authorize(Path(args.trusted_root),Path(args.candidate_root),args.head_sha,Path(args.comments_file))
    except Exception as e:
        raise SystemExit("BLOCKED: "+str(e))
    print("PASS:",out["mode"],out["digest"])
    if out["paths"]: print("protected paths:",", ".join(out["paths"]))

if __name__=="__main__": main()
