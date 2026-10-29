# Alerts: `faultypacket-audit alert`

Run daily (cron or the GitHub Action). Each run snapshots the published SPF, DMARC, MTA-STS, TLS-RPT, BIMI and MX records plus the audit status, compares them with the previous run's `--state` file, and POSTs a webhook when:

- a record changed (a lookup error is never treated as a change), or
- a domain started failing (status became `error`, or a new error rule appeared).

The first run for a domain only records a baseline.

```
export FAULTYPACKET_WEBHOOK_URL=...   # from your secret store; never put it in a file in the repo
faultypacket-audit alert example.com example.org --state state.json --format slack   # or teams, json
faultypacket-audit alert example.com --state state.json --dry-run                   # print the payload
```

- The URL is read only from an environment variable (`--webhook-env NAME`, default `FAULTYPACKET_WEBHOOK_URL`). There is no command-line URL option, and the URL is never printed, even on errors. Only `https://` is accepted.
- Formats: `slack` (incoming webhook `{"text": ...}`), `teams` (Adaptive Card message for Workflows webhooks), `json` (`{"source", "title", "events": [...]}`).
- Exit 1 if there were events but posting failed or the variable is unset.

GitHub Action: set `alert-format: slack|teams|json`, pass the secret as `env: FAULTYPACKET_WEBHOOK_URL`, and persist `alert-state` with `actions/cache`. See `examples/alerts.yml`.
