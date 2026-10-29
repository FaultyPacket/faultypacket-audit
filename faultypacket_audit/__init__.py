"""faultypacket-audit: cited, standards-current mail and DNS hygiene checks.

Library use:
    from faultypacket_audit import audit, load_rules, Resolver
    report = audit("example.com", Resolver(doh="https://cloudflare-dns.com/dns-query"), load_rules())

Checks are pure functions of (domain, resolver, rules, options); they never print.
"""
__version__ = "1.2.0"

from .core.resolver import Resolver, Cached          # noqa: E402
from .core.rules import load_rules                    # noqa: E402
from .audit import audit, CHECKS                      # noqa: E402

__all__ = ["__version__", "Resolver", "Cached", "load_rules", "audit", "CHECKS"]
