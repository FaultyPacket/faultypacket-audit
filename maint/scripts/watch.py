#!/usr/bin/env python3
"""Fetch watched sources, compare against state/, emit changes.json. Never edits code."""
import hashlib, json, re, sys, urllib.request, pathlib, difflib
BASE = pathlib.Path(__file__).resolve().parent.parent
STATE = BASE / "state"

def fetch(src):
    data = json.dumps(src["post"]).encode() if "post" in src else None
    req = urllib.request.Request(src["url"], data=data, headers={"User-Agent":"faultypacket-watch/1","Content-Type":"application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")

def normalise(src, body):
    if src["kind"] == "json":
        j = json.loads(body)
        key, _, fields = src["select"].partition("[].")
        items = j.get(key) or []
        return "\n".join(sorted("@".join(str(it.get(f, "")) for f in fields.split("+")) for it in items))
    body = re.sub(r"<script.*?</script>|<style.*?</style>", "", body, flags=re.S)
    text = re.sub(r"<[^>]+>", " ", body)
    return "\n".join(l.strip() for l in re.sub(r"[ \t]+", " ", text).splitlines() if l.strip())

def main(cfg=BASE / "watch_sources.json", fetcher=fetch):
    STATE.mkdir(exist_ok=True)
    changes, errors = [], []
    for src in json.loads(pathlib.Path(cfg).read_text())["sources"]:
        try:
            new = normalise(src, fetcher(src))
        except Exception as e:
            errors.append({"id": src["id"], "error": str(e)}); continue
        f = STATE / f"{src['id']}.txt"
        old = f.read_text() if f.exists() else None
        if old is not None and hashlib.sha256(old.encode()).digest() != hashlib.sha256(new.encode()).digest():
            diff = "\n".join(list(difflib.unified_diff(old.splitlines(), new.splitlines(), "before", "after", lineterm=""))[:200])
            changes.append({"id": src["id"], "url": src["url"], "note": src.get("note", ""), "diff": diff})
        f.write_text(new)
    (BASE / "changes.json").write_text(json.dumps({"changes": changes, "errors": errors}, indent=1))
    print(f"{len(changes)} changed, {len(errors)} errors")
    return changes, errors

if __name__ == "__main__":
    main(*(sys.argv[1:2]))
