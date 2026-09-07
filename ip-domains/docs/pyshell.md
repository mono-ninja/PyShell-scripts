# IP → Domains

Finds domains that point to the same IP address by querying several open
sources. Passive reconnaissance: the script never touches the target itself,
only third-party APIs.

## Fields

- **Target IP** — an address in the format `93.184.216.34`. IPv4 only:
  IPv6 and CIDR ranges are not accepted (neither by the form nor by the CLI).
  It is passed as a positional argument and validated by a regex in the
  manifest, so the form will reject a hostname.
- **Sources** — which sources to query. crt.sh looks up domains in certificate
  SAN fields, HackerTarget and ViewDNS do reverse-IP lookups, Shodan searches
  its host database. crt.sh and HackerTarget are enabled by default. Notes worth
  knowing before you read the numbers:
    - crt.sh searches for certificates **issued for the IP literal itself**, not
      for domains hosted on it — it is a weak reverse-IP source. An empty crt.sh
      result does not mean "no domains", only "no certificates found for this IP".
    - HackerTarget's free tier caps a reply at **500 domains** and does not say
      so. Exactly 500 results means the list is cut, not complete. If it answers
      with prose instead (an exhausted quota, say), that line is shown as a
      status so the run is not mistaken for "nothing hosted here".
    - ViewDNS is **off by default**: its free endpoint now sits behind a
      Cloudflare challenge and answers 403 to every non-browser client, this
      script included. Enable it only if you know your access works.
- **Shodan API Key** — required only if Shodan is selected. Without it that
  source is simply skipped (with a status line), the rest keeps working.
- **Skip DNS verification** — by default every found domain is checked with a
  forward DNS lookup, and only those actually pointing to the target IP make it
  into the results. With this flag enabled you get the raw source output:
  faster, but with noise. In this mode `domains_unverified.csv` (a single
  column) is written instead of the verified `domains_verified.csv`.
- **Verification threads** — how many domains to resolve in parallel during
  verification. The default is 50. A higher value speeds up verification but
  puts load on the local resolver and the network. Below 1 is clamped to 1.
- **Max domains to verify** — a cap on the number of domains sent to
  verification. If the sources return more, the excess is discarded (with a
  status note) to stay within the timeout. The default is 5000.

## Shodan key

The value is stored in the system Keychain (service `com.pyshell.app`) and
passed to the script via the `SHODAN_API_KEY` environment variable. It never
appears in `argv` — otherwise the key would be visible to any process in
`ps aux`. After saving, the form shows not the value but a marker that the
secret is set.

## Result

A table in the **Results** tab and `.csv` / `.json` files in the artifacts tab.
`domains_raw.json` — found domains (cleaned, unverified); `domains_verified.csv`
— verification results (domain, IP, status), or `domains_unverified.csv` with a
single column if verification is disabled. The verified CSV is written as
domains resolve, so even a forced interruption leaves a partial file.
Artifacts are written to `PYSHELL_OUTPUT_DIR`, not next to the script.

## Before you run

Querying third-party APIs about someone else's IP from your own IP can look
like pre-attack reconnaissance. Only look up addresses you own or have written
permission to investigate.
