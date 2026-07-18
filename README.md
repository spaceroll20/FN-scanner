# FN-scanner
# scanner.py

A single-file CLI for basic recon: TCP port scanning, HTML page parsing, TLS/certificate inspection, and lightweight web vulnerability checks (missing security headers, allowed HTTP methods, cookie flags, optional SQL injection probe).

## ⚠️ Authorization required

Only run this against hosts you own or have **explicit written permission** to test. Port scanning and injection probes against systems you don't control can be illegal (e.g. under the U.S. Computer Fraud and Abuse Act or equivalent laws elsewhere) even if no damage occurs. This tool does no rate-limiting or stealth — it will be loud and easy to attribute to you.

## Requirements

- Python 3.7+
- No third-party dependencies (stdlib only: `argparse`, `concurrent.futures`, `html.parser`, `ssl`, `socket`, `urllib`)

## Installation

```bash
git clone https://github.com/spaceroll20/FN-scanner.git
cd FN-scanner
python3 scanner.py --help
```

No `pip install` needed.

## Usage

The tool has four subcommands: `port`, `html`, `https`, `exploit`.

### 1. Port scan

```bash
python3 scanner.py port <host> [--start N] [--end N] [--timeout SEC] [--workers N]
```

| Flag | Default | Description |
|---|---|---|
| `--start` | 1 | First port to scan |
| `--end` | 1024 | Last port to scan |
| `--timeout` | 1.0 | Per-connection timeout (seconds) |
| `--workers` | 100 | Concurrent threads |

```bash
python3 scanner.py port 192.168.1.10 --start 1 --end 65535 --workers 300
```

Does a TCP connect scan (no SYN/stealth scanning) using a thread pool. Reports which ports accepted a connection.

### 2. HTML fetch & parse

```bash
python3 scanner.py html <url> [--timeout SEC]
```

```bash
python3 scanner.py html https://example.com
```

Fetches the page, extracts `<title>`, all `<a href>` links, and all `<form>` elements (action + method). Prints the first 10 of each.

### 3. HTTPS / TLS inspection

```bash
python3 scanner.py https <target> [--timeout SEC]
```

```bash
python3 scanner.py https example.com
python3 scanner.py https https://example.com:8443
```

Connects over TLS and reports negotiated protocol version, cipher suite, certificate subject/issuer, expiry, validity, and SANs.

**Note:** certificate chain validation and hostname verification are intentionally disabled in this mode so it can inspect self-signed / misconfigured hosts. It does not mean the cert is trustworthy — see Known Issues below.

### 4. Exploit / misconfiguration checks

```bash
python3 scanner.py exploit <url> [--timeout SEC] [--sql-test]
```

```bash
python3 scanner.py exploit https://example.com/search?q=test --sql-test
```

Checks performed:
- `HEAD` request status
- `OPTIONS` request — flags if `TRACE` is in the allowed methods
- Missing security headers: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `X-XSS-Protection`, `Referrer-Policy`
- Server / X-Powered-By header disclosure
- `Set-Cookie` missing `HttpOnly` / `Secure`
- Optional (`--sql-test`): appends `' OR '1'='1` to the first query parameter and flags if the response body differs from baseline

## Example output

```
$ python3 scanner.py exploit https://example.com --sql-test
HEAD status: 200
Allowed methods: GET, HEAD, OPTIONS
Missing security header: content-security-policy
Missing security header: x-frame-options
Server header: nginx/1.18.0
SQL injection skipped: No query parameters to test
```

## Known limitations (read before you trust the output)

- **Port scan is TCP-connect only.** No UDP, no SYN scan, no service/version fingerprinting or banner grabbing. A closed vs filtered port both just show "not open" — you get no signal on firewalled ports.
- **`--workers 100+` against unfamiliar hosts can look like a DoS attempt** to IDS/IPS and will likely get you blocked or reported. There's no jitter, backoff, or rate limiting.
- **TLS verification is hard-disabled** (`CERT_NONE`, `check_hostname=False`) in `https_check`. It will silently connect to a MITM'd or spoofed cert and report it as if it were normal — the `valid_certificate` field only checks expiry date, not chain of trust. Don't confuse "valid_certificate: True" with "this cert is trustworthy."
- **The SQL injection check is a single blunt payload** (`' OR '1'='1`) diffed against baseline body length/content. It will miss blind/time-based/second-order injection, produces false positives on any page with dynamic content (timestamps, CSRF tokens, ads, A/B tests), and only tests the *first* query parameter. Treat a hit as "worth investigating manually," not "confirmed vulnerable."
- **No output format besides stdout text** — no JSON/CSV export, so piping into other tooling means you're parsing print statements.
- **Exceptions are swallowed broadly** (`except Exception`) in several places, which hides real errors (DNS failures, TLS handshake errors, etc.) behind generic messages.
- **No auth support** (no cookies/headers/bearer tokens for authenticated scans).

## License

Add your license of choice here.
