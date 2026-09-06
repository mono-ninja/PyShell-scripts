# Web Conf Audit

What the web server config actually allows — the fw-audit shape for
the web server. Saved **nginx**, **Apache** and **.htaccess** files,
format detected automatically, reviewed passively: directory
listings, version banners (the absent-directive defaults included),
TLS protocols and ciphers on the tls-audit scale (negations
understood), PHP-inside-uploads (the safe shapes praised), the core
security headers Security Headers grades (its zeroes explained
here), upload size limits, compression, proxy Host mistakes.

The rules-vs-reality companion to Security Headers — nothing runs
as root, nothing is reloaded.

---

## Before running

1. Bring the config file(s) over from the server (`scp`, or paste
   into a file).
2. Pick a **Source** — one config, several, or a folder (recursive
   for subfolders); files that match no web-server format are noted
   as skipped.
3. No **Prepare Env** needed — stdlib only. Press **Run** (⌘↩).

## Fields

### Input

- **Source** — single / multiple / folder. The format of each file
  is detected from its content: nginx (`server {`, `location`,
  `ssl_protocols`…), apache (`<VirtualHost`, `<Directory`,
  `ServerTokens`…), `.htaccess` by filename or by its
  apache-directive content.
- `.htaccess` is reviewed with a context note: its rules apply to
  its folder and below; the main config still owns TLS and banners.

---

## Result

- **Results tab** — the table (file · format · critical · warnings
  · good · verdict) and the per-config report:
  - **listings / banners / tls / php-uploads / headers / uploads /
    proxy** — each flag with its fix; the *good* flags name the safe
    shape when it is found (a denied uploads location,
    `php_admin_flag engine off`, all six headers set).
  - **Notes** — the defaults that apply when a directive is absent
    (`server_tokens` defaults on, `ServerTokens` defaults Full,
    `client_max_body_size` defaults 1m, `LimitRequestBody`
    unlimited) — the honest "absent ≠ fine".
- **Artifacts** — `report.md`, `findings.json`.

### Verdicts

🔴 critical flags (TLSv1/TLSv1.1/weak ciphers enabled) · 🟠 to
tighten (listings, banners, php-in-uploads, missing headers, proxy
Host) · 🟢 sane · 🟡 see notes · ⚫ unrecognized.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | ran; findings are in the report |
| 1 | no config matched a web-server format |
| 2 | bad arguments: missing file, empty folder |

## Related

- **Security Headers** — what reaches the browser; this script
  explains its zeroes.
- **TLS Audit** — the live handshake; the config's protocol list is
  the other side of that truth.
- **FW Audit** — the same passive-config review for the firewall.
