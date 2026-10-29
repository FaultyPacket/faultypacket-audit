# Contributing

Thanks for helping. Two rules keep this tool trustworthy:

1. **Every finding cites a source.** A new or changed rule goes in
   `faultypacket_audit/data/rules.json` with `source`, `url` and a `verified`
   date (YYYY-MM-DD). `python maint/scripts/check_rules.py` must pass.
2. **Tests run offline.** Use the fake zone in `tests/zone.py`; no live DNS in tests.

```
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt -e .
python maint/scripts/check_rules.py && python -m pytest -q
```

Rule changes bump `rules_version` (CalVer `YYYY.MM.DD.N`). Code changes that
alter the JSON shape must keep `schema/audit.schema.json` valid (fields may be
added within 1.x, not removed or renamed).

By contributing you agree your contribution is licensed under AGPL-3.0-or-later.
