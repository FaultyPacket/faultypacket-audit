"""Batch input: domains, URLs or email addresses -> deduped domain list."""
import ipaddress, re, urllib.parse


def extract_domain(raw):
    """URL, email, host:port or bare name -> lowercase ASCII (IDNA) domain.
    Raises ValueError."""
    s = raw.strip()
    if not s:
        raise ValueError("empty")
    if "://" in s:
        s = urllib.parse.urlsplit(s).netloc
    s = s.split("/")[0].split("?")[0].split("#")[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if s.startswith("["):
        raise ValueError("IP literal, not a domain")
    s = s.split(":")[0].rstrip(".").strip().lower()
    if not s:
        raise ValueError("no host")
    try:
        ipaddress.ip_address(s)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        raise ValueError("IP address, not a domain")
    try:
        s = s.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("invalid IDN")
    labels = s.split(".")
    if len(s) > 253 or len(labels) < 2 or not all(
            re.fullmatch(r"(?!-)[a-z0-9_-]{1,63}(?<!-)", l) for l in labels):
        raise ValueError("not a valid domain name")
    return s


def read_lines(lines):
    out = []
    for line in lines:
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def collect(args_domains, files, stdin, auto_stdin=False):
    """-> (domains in first-seen order, deduped; list of {input, error}).
    stdin is read for '-' in files, or when auto_stdin and it is not a TTY."""
    raw = list(args_domains)
    for f in files or []:
        if f == "-":
            raw += read_lines(stdin)
        else:
            with open(f, encoding="utf-8") as fh:
                raw += read_lines(fh)
    if auto_stdin and stdin is not None and not stdin.isatty():
        raw += read_lines(stdin)
    seen, domains, bad = set(), [], []
    for r in raw:
        try:
            d = extract_domain(r)
        except ValueError as e:
            bad.append({"input": r, "error": str(e)})
            continue
        if d not in seen:
            seen.add(d); domains.append(d)
    return domains, bad
