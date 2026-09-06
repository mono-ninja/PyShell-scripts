# Mail Probe

Probes the **SMTP wire layer** of a mail domain — MX hosts, banners,
EHLO capabilities, STARTTLS with the certificate, AUTH mechanisms,
PTR records, and an opt-in relay probe. The wire-side sibling of
[Email DNS Audit](../../email-dns-audit) and
[DNSBL Check](../../dnsbl-check).

**One connection per MX host on port 25.** The relay probe (when on)
stops before DATA — **no mail is ever sent**.

---

## Before running

1. **Mail domain** — a domain you own or operate. Some steps look
   like what a scanner does; run them on yourself first, not on
   strangers.
2. Click **Prepare Env** — installs `dnspython`.
3. Press **Run** (⌘↩). If every connection fails, your network
   probably blocks outbound port 25 (common on residential ISPs) —
   run it from a server.

## Fields

### Target

- **Mail domain** — a bare domain (`example.com`), no scheme, no
  path. Its MX hosts are resolved; with no MX records, the A record
  is used as the implicit MX (RFC 5321) and reported as such.
- **Per-step timeout (s)** — each connection, EHLO, STARTTLS and DNS
  query.
- **Max MX hosts** — how many hosts to probe, most-preferred first
  (default 3).

### Relay

- **Relay probe (opt-in)** — **off by default.** When on: after the
  normal handshake, MAIL FROM a `postmaster@<your-domain>` sender and
  RCPT TO `postmaster@example.com` (an IANA-reserved domain — mail
  there goes nowhere even if a broken relay accepted), read the
  answer, RSET, quit. The sequence stops **before DATA** — no mail is
  sent, ever. A 2xx answer for the external recipient is the
  open-relay red flag; 5xx is the healthy rejection; 4xx (greylisting)
  is reported honestly as unclear.

---

## Result

- **Results tab** — the per-host table and the full report:
  - banner, STARTTLS availability, TLS version + cipher;
  - the certificate: subject, issuer, days to expiry, and the
    verification verdict — a failing chain is reported with its
    reason (the handshake is retried unverified so the facts still
    come back);
  - AUTH mechanisms advertised in EHLO;
  - PTR with forward-confirmation;
  - the relay verdict, when the probe ran.
- **Artifacts** — `findings.json`, `report.md`.

### Reading the findings

- **Open relay** (accepted external RCPT) — shut it down; spammers
  find open relays within days and blocklists follow. The report
  links [DNSBL Check](../../dnsbl-check) for the damage assessment.
- **No STARTTLS** — mail to that host crosses the internet in
  plaintext; **broken STARTTLS** (offered, handshake fails) is worse
  when clients require it.
- **Unverified certificate** — check the chain and names; the HTTPS
  side is [TLS Audit](../../tls-audit)'s territory.
- **Certificate expiring within 21 days** — flagged with the day
  count.
- **No PTR / not forward-confirmed** — informational; many receivers
  weigh it in spam scoring.

## Exit codes

- `0` — the probe ran; findings are results, not failures.
- `1` — no MX to probe, or no MX host accepted a connection.
- `2` — bad arguments.
