#!/usr/bin/env python3
"""Update maint/status.json streak and README badge line. Honest: unmaintained after N failed weeks."""
import json, pathlib, sys, datetime, re
BASE = pathlib.Path(__file__).resolve().parent.parent; N = 4
def main(ok: bool, readme=BASE.parent / "README.md"):
    p = BASE / "status.json"
    s = json.loads(p.read_text()) if p.exists() else {"fail_streak": 0}
    today = datetime.date.today().isoformat()
    if ok: s.update(fail_streak=0, last_verified=today)
    else: s["fail_streak"] += 1
    s["state"] = "verified" if ok else ("unmaintained" if s["fail_streak"] >= N else "degraded")
    p.write_text(json.dumps(s, indent=1))
    colour = {"verified":"brightgreen","degraded":"orange","unmaintained":"red"}[s["state"]]
    label = s.get("last_verified", "never").replace("-", "--")
    badge = f"![last verified](https://img.shields.io/badge/last_verified-{label}_{s['state']}-{colour})"
    t = readme.read_text() if readme.exists() else ""
    t = re.sub(r"<!--badge-->.*?<!--/badge-->", f"<!--badge-->{badge}<!--/badge-->", t, flags=re.S) if "<!--badge-->" in t else f"<!--badge-->{badge}<!--/badge-->\n" + t
    readme.write_text(t); print(s); return s
if __name__ == "__main__": main(sys.argv[1] == "ok")
