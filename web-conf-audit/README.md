# Web Conf Audit

**What the web server config actually allows.** The fw-audit shape
applied to the web server: **Security Headers** sees what reaches
the browser — this reads *why*: the saved config that produced it.
nginx (main config, site configs, vhosts), Apache (apache2.conf,
vhosts) and `.htaccess` are recognized automatically and reviewed
passively — nothing runs as root, nothing is reloaded.

- **Directory listings** — `autoindex on` / `+Indexes`.
- **Version banners** — `server_tokens` (nginx defaults **on** when
  absent — the absent case is flagged), `ServerTokens` /
  `ServerSignature` (apache defaults Full / On).
- **TLS** — `ssl_protocols` / `SSLProtocol` and `ssl_ciphers` /
  `SSLCipherSuite` on the tls-audit scale: TLSv1/TLSv1.1 red,
  TLSv1.2 the floor, TLSv1.3 good; 3DES/RC4/NULL/EXPORT ciphers red
  (negations `!3DES` understood — they are the point).
- **PHP inside uploads** — a `location ~ \.php$` / `FilesMatch` that
  executes anywhere, with nothing keeping `uploads/` out of it: the
  upload-a-shell path. The safe shapes (a denied uploads location,
  `php_admin_flag engine off`) are recognized and praised.
- **Security headers** — which of the core six are actually
  `add_header`'d / `Header set`: the same list Security Headers
  grades — here it explains its zeroes.
- **Upload size** — `client_max_body_size` / `LimitRequestBody`
  absent (nginx 1m, apache unlimited) or huge.
- **Compression** — no `gzip`/`brotli` left on the table.
- **Proxy Host** — `proxy_pass` without `proxy_set_header Host`: the
  backend sees the wrong vhost.

## Using with PyShell

1. Bring the config file over from the server.
2. Pick a **Source** — one config, several, or a folder (every file
   is sniffed; non-config files are skipped with a note).
3. Press **Run** (⌘↩).

## Running standalone

```bash
python3 main.py --single-file site.conf
python3 main.py --mode folder --input-folder /etc/nginx/sites-enabled
```

## Result

- **Results tab** — a table (file · format · critical · warnings ·
  good · verdict) and the per-config report: flags with fixes, notes
  (the defaults that apply when a directive is absent), and "what
  good looks like".
- **Artifacts** — `report.md`, `findings.json`.

### Verdicts

🔴 critical flags (weak TLS protocols/ciphers) · 🟠 to tighten · 🟢
sane · ⚫ unrecognized. Unrecognized files are reported as such,
never interpreted.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are in the report |
| 1 | no config matched a web-server format |
| 2 | bad arguments (missing file, empty folder) |

## Layout

```
web-conf-audit/
├── pyshell.yaml      # manifest
├── main.py           # detect · parse nginx/apache · analyze · report
├── docs/             # EN + UA docs
└── tests/            # 11 tests: vulnerable + safe fixtures per format
```

## License

MIT — see the root [LICENSE](../LICENSE).
