"""Deterministic synthetic mutations of the anonymised real records
(tests/corpus/real.jsonl -> tests/corpus/mutations.jsonl).  Each mutation is a
realistic edit people make by hand: tag reorders, case changes, whitespace,
historic tags, duplicate tags, bad values and URIs, SPF lookup blow-ups."""
import json, pathlib, random, re

CORPUS = pathlib.Path(__file__).resolve().parents[2] / "tests" / "corpus"
PER_KIND = {"dmarc": 90, "spf": 90, "mtasts": 60, "tlsrpt": 19}
SYN = {f"syn{i}.example|TXT": [f"v=spf1 ip4:192.0.2.{i} -all"] for i in range(1, 13)}


def tags(rec):
    return [p.strip() for p in rec.split(";") if p.strip()]


def dmarc_mut(rec, rnd):
    t = tags(rec)
    body = [x for x in t[1:]]
    names = [x.split("=", 1)[0].strip().lower() for x in body]
    out = {
        "upper_tag_names": "; ".join([t[0]] + [x.split("=", 1)[0].upper() + "=" + x.split("=", 1)[1] if "=" in x else x for x in body]),
        "spaced": " ; ".join([t[0]] + [x.replace("=", " = ", 1) for x in body]) + " ;",
        "compact": ";".join(x.replace(" ", "") for x in t),
        "reordered": "; ".join([t[0]] + sorted(body, key=lambda x: rnd.random())),
        "version_last": "; ".join(body + [t[0]]),
        "version_lower": rec.replace("DMARC1", "dmarc1", 1),
        "add_pct50": rec.rstrip("; ") + "; pct=50",
        "add_pct0": rec.rstrip("; ") + "; pct=0",
        "add_ri_rf": rec.rstrip("; ") + "; ri=3600; rf=afrf",
        "dup_p": rec.rstrip("; ") + "; p=none",
        "bad_p": re.sub(r"(?i)\bp\s*=\s*[^;]*", "p=rejected", rec, count=1) if "p" in names else rec.rstrip("; ") + "; p=rejected",
        "bad_sp": rec.rstrip("; ") + "; sp=block",
        "bad_adkim": rec.rstrip("; ") + "; adkim=strict",
        "bad_fo": rec.rstrip("; ") + "; fo=2",
        "t_y": rec.rstrip("; ") + "; t=y",
        "bad_t": rec.rstrip("; ") + "; t=yes",
        "psd_y": rec.rstrip("; ") + "; psd=y",
        "rua_https": re.sub(r"(?i)rua\s*=\s*[^;]*", "rua=https://reports.example.org/dmarc", rec, count=1),
        "rua_nohost": re.sub(r"(?i)rua\s*=\s*[^;]*", "rua=mailto:reports", rec, count=1),
        "rua_size": re.sub(r"(?i)(rua\s*=\s*mailto:[^;,!]+)", r"\1!10m", rec, count=1),
        "rua_empty": re.sub(r"(?i)rua\s*=\s*[^;]*", "rua=", rec, count=1),
        "drop_p": "; ".join([t[0]] + [x for x, n in zip(body, names) if n != "p"]),
        "drop_rua": "; ".join([t[0]] + [x for x, n in zip(body, names) if n != "rua"]),
        "unknown_tag": rec.rstrip("; ") + "; foo=bar",
        "no_equals": rec.rstrip("; ") + "; quarantine",
    }
    return out


def spf_mut(rec, rnd):
    terms = rec.split()[1:]
    body = [x for x in terms if not re.fullmatch(r"[+\-~?]?all", x, re.I)]
    v = "v=spf1"
    return {
        "upper": v + " " + " ".join(x.upper() for x in terms),
        "plus_all": " ".join([v] + body + ["+all"]),
        "neutral_all": " ".join([v] + body + ["?all"]),
        "no_all": " ".join([v] + body),
        "add_ptr": " ".join([v, "ptr"] + terms),
        "add_exp": " ".join([v] + terms + ["exp=explain.example"]),
        "dup_redirect": " ".join([v] + body + ["redirect=syn1.example", "redirect=syn2.example"]),
        "redirect_with_all": " ".join([v] + terms + ["redirect=syn1.example"]),
        "bad_cidr4": " ".join([v, "ip4:192.0.2.0/33"] + terms),
        "bad_ip6": " ".join([v, "ip6:2001:db8::zz"] + terms),
        "include_no_arg": " ".join([v, "include:"] + terms),
        "double_space": rec.replace(" ", "  "),
        "eleven_includes": " ".join([v] + [f"include:syn{i}.example" for i in range(1, 12)] + terms),
        "dual_cidr": " ".join([v, "a//64", "mx/24//64"] + terms),
        "macro": " ".join([v, "exists:%{i}._spf.syn1.example"] + terms),
        "unknown_mech": " ".join([v, "foo:bar.example"] + terms),
        "qualified_modifier": " ".join([v] + terms + ["-redirect=syn1.example"]),
        "after_all": " ".join([v] + terms + ["include:syn3.example"]),
        "joined_txt": " ".join([v] + body + ["-allverify=token"]),
    }


def sts_mut(rec, rnd):
    f = tags(rec)
    return {
        "id_long": "v=STSv1; id=" + "a" * 33,
        "id_dash": re.sub(r"id=([^;\s]*)", r"id=\1-x", rec),
        "no_id": "; ".join(x for x in f if not x.startswith("id=")),
        "extra_field": rec.rstrip("; ") + "; ext=1",
        "lower_v": rec.replace("STSv1", "stsv1", 1),
        "spaced": " ; ".join(f),
        "trailing": rec.rstrip("; ") + ";",
        "bad_field": rec.rstrip("; ") + "; =x",
    }


def tls_mut(rec, rnd):
    return {
        "https": "v=TLSRPTv1; rua=https://reports.example.org/tls",
        "both": "v=TLSRPTv1; rua=mailto:reports@example.org,https://reports.example.org/tls",
        "no_rua": "v=TLSRPTv1;",
        "bad_scheme": "v=TLSRPTv1; rua=ftp://reports.example.org/x",
        "space_uri": rec.replace("mailto:", "mailto: ", 1),
        "lower_v": rec.replace("TLSRPTv1", "tlsrptv1", 1),
        "no_semicolon_field": rec.rstrip("; ") + "; junk",
        "empty_item": rec.replace("rua=", "rua=,", 1),
    }


FUN = {"dmarc": dmarc_mut, "spf": spf_mut, "mtasts": sts_mut, "tlsrpt": tls_mut}


def main():
    rnd = random.Random(20261029)
    real = [json.loads(l) for l in open(CORPUS / "real.jsonl")]
    zone = json.load(open(CORPUS / "zone.json"))
    zone.update(SYN)
    json.dump(dict(sorted(zone.items())), open(CORPUS / "zone.json", "w"), indent=0)
    seen, n = set(), 0
    with open(CORPUS / "mutations.jsonl", "w") as f:
        for kind, k in PER_KIND.items():
            pool = [r for r in real if r["kind"] == kind]
            for r in rnd.sample(pool, min(k, len(pool))):
                for name, rec in FUN[kind](r["record"], rnd).items():
                    if (kind, rec) in seen or rec == r["record"]:
                        continue
                    seen.add((kind, rec))
                    f.write(json.dumps({"kind": kind, "record": rec, "domain": r["domain"], "mutation": name}) + "\n")
                    n += 1
    print(n, "mutations")


if __name__ == "__main__":
    main()
