"""Record the RFC review of each disagreement class in tests/corpus/reviewed.json.
Every rule below was decided by reading the RFC text cited in its note; records
that match no rule stay unreviewed and are NOT frozen as tests."""
import json, pathlib, re

CORPUS = pathlib.Path(__file__).resolve().parents[2] / "tests" / "corpus"
RULES = [
    # (kind, predicate(record, ours, checkdmarc), verdict, note)
    ("dmarc", lambda r, o, t: "bad_fo" in o["codes"] and t["valid"] and re.search(r"(?i)fo\s*=\s*[^;]*0[^;]*1|fo\s*=\s*[^;]*1[^;]*0", r),
     "ours-correct", "RFC 9989 4.8 dmarc-fo allows exactly one of 0/1 (RFC 7489 allowed both); invalid fo is discarded for the default"),
    ("dmarc", lambda r, o, t: "Duplicate" in t.get("detail", "") and o["valid"] and "duplicate_tag" in o["codes"],
     "rfc-silent", "RFC 9989 does not define duplicate tags; we warn and use the first value, checkdmarc rejects the record"),
    ("dmarc", lambda r, o, t: t["valid"] and not o["valid"] and set(c for c in o["codes"] if c.startswith("bad_")) <= {"bad_adkim", "bad_aspf", "bad_sp", "bad_fo", "bad_t", "bad_p", "bad_psd", "bad_np"} and any(c.startswith("bad_") for c in o["codes"]),
     "ours-correct", "RFC 9989 4.8 Table 2: value outside its ABNF rule (dmarc-rors / dmarc-request / dmarc-fo) is a syntax error, discarded for the default"),
    ("dmarc", lambda r, o, t: t.get("error") == "InvalidDMARCReportURI" and o["valid"] and "scheme_rua" in o["codes"],
     "ours-correct", "RFC 9989 4.6: URIs with unsupported schemes MUST be ignored; the other rua URIs still apply"),
    ("dmarc", lambda r, o, t: t.get("error") == "DMARCSyntaxError" and o["valid"] and ";;" in r.replace(" ", ""),
     "ours-correct", "RFC 9989 4.8: an empty tag is a syntax error that MUST be discarded; the record still applies (we warn)"),
    ("dmarc", lambda r, o, t: t["valid"] and not o["valid"] and any(c.startswith("bad_uri_") for c in o["codes"]),
     "ours-correct", "RFC 9989 4.8 dmarc-uri = URI (RFC 3986): a space inside a URI makes it invalid"),
    ("spf", lambda r, o, t: re.match(r"(?i)v=spf1(\s|$)", r) is not None and not r.startswith("v=spf1") and o["valid"],
     "ours-correct", "RFC 7208 4.5 version = \"v=spf1\" is an ABNF literal, case-insensitive per RFC 5234 2.3"),
    ("spf", lambda r, o, t: re.match(r"(?i)v=spf1\S", r) is not None and "no_record" in o["codes"],
     "ours-correct", "RFC 7208 4.5: the version section ends at SP or end of record, so this is not an SPF record (result none)"),
    ("spf", lambda r, o, t: "\n" in r and not o["valid"],
     "ours-correct", "RFC 7208 12: terms are separated by 1*SP; a line break joins terms into one invalid term"),
    ("spf", lambda r, o, t: re.search(r"(?i)\b(mx|a):[a-z0-9-]+(\s|/|$)", r) is not None and "syntax" in o["codes"] and t["valid"],
     "ours-correct", "RFC 7208 7.1 domain-end needs a dot and a toplabel; a single label is not a valid domain-spec"),
    ("spf", lambda r, o, t: t.get("error") == "SPFTooManyVoidDNSLookups" and "ptr" in o["codes"],
     "ours-correct", "RFC 7208 5.5: ptr lookups depend on the sender IP, so they cannot be counted as void statically"),
    ("spf", lambda r, o, t: re.search(r"(^|\s)[+\-~?][A-Za-z][A-Za-z0-9_.-]*=", r) is not None and "syntax" in o["codes"],
     "ours-correct", "RFC 7208 12: modifiers take no qualifier, so '-all...=x' / '-redirect=' is an invalid term (permerror)"),
    ("spf", lambda r, o, t: t["valid"] and not o["valid"] and "syntax" in o["codes"] and (re.search(r"\s[0-9a-f]{20,}(\s|$)", r) or "after_all" in o["codes"] or re.search(r"(?i)\sb081687c", r)),
     "ours-correct", "RFC 7208 4.6 / 5: a syntax error or unknown mechanism anywhere in the record, even after 'all', makes check_host() return permerror"),
    ("dmarc", lambda r, o, t: t["valid"] and "version" in o["codes"] and r.startswith('"'),
     "ours-correct", "RFC 9989 4.7: v=DMARC1 must be the first tag; a literal quote character before it means the record is ignored"),
    ("dmarc", lambda r, o, t: not t["valid"] and o["valid"] and "syntax" in o["codes"],
     "ours-correct", "RFC 9989 4.8: syntax errors in the remainder of the record MUST be discarded in favour of defaults; the record still applies, and we warn about the discarded part"),
    ("dmarc", lambda r, o, t: not t["valid"] and o["valid"] and set(o["codes"]) & {"scheme_rua", "scheme_ruf"},
     "ours-correct", "RFC 9989 4.6: report URIs without a supported scheme MUST be ignored; the record still applies"),
    ("dmarc", lambda r, o, t: not t["valid"] and o["valid"] and "unknown_tag" in o["codes"],
     "ours-correct", "RFC 9989 4.7/4.8: unknown tags MUST be ignored; the record still applies"),
    ("dmarc", lambda r, o, t: not t["valid"] and o["valid"] and "historic_pct" in o["codes"],
     "ours-correct", "RFC 9989 9.3: pct is historic and ignored, so a malformed pct value cannot invalidate the record"),
    ("spf", lambda r, o, t: t["valid"] and not o["valid"] and "syntax" in o["codes"] and re.search(r"(?i)\s-?(?:[~?+-]?all)\s+\S", r),
     "ours-correct", "RFC 7208 4.6 / 12: every term is parsed before evaluation; an unknown mechanism or a modifier name not starting with a letter (e.g. '_globalsign...=') is permerror even after 'all'"),
    ("tlsrpt", lambda r, o, t: not t["valid"] and not o["valid"], "agree", ""),
]


def main():
    rev = {}
    left = 0
    for line in open(CORPUS / "disagreements.jsonl"):
        x = json.loads(line)
        for kind, pred, verdict, note in RULES:
            if kind == x["kind"] and pred(x["record"], x["ours"], x["checkdmarc"]):
                rev[f"{x['kind']}:{x['record']}"] = {"verdict": verdict, "note": note}
                break
        else:
            left += 1
            print("UNREVIEWED", x["kind"], repr(x["record"][:140]), x["ours"]["codes"], x["checkdmarc"].get("error"))
    json.dump(rev, open(CORPUS / "reviewed.json", "w"), indent=0, sort_keys=True)
    print(len(rev), "reviewed;", left, "left unreviewed")


if __name__ == "__main__":
    main()
