import argparse
import concurrent.futures
import html.parser
import ssl
import socket
import sys
import urllib.parse
import urllib.request
from datetime import datetime


class HtmlScanner(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = ""
        self.links = []
        self.forms = []
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        elif tag == "form":
            self.forms.append({
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "get").upper(),
            })
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data.strip()


def scan_port(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, True
    except Exception:
        return port, False


def scan_ports(host, start_port, end_port, timeout=1, workers=100):
    ports = range(start_port, end_port + 1)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_port, host, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                results.append(future.result())
            except Exception:
                results.append((port, False))
    return sorted(results)


def fetch_html(url, timeout=10):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Scanner)"
        }
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        content = response.read()
        charset = response.headers.get_content_charset() or "utf-8"
        try:
            text = content.decode(charset, errors="replace")
        except Exception:
            text = content.decode("utf-8", errors="replace")

        parser = HtmlScanner()
        parser.feed(text)

        return {
            "url": url,
            "status": response.status,
            "headers": dict(response.headers),
            "title": parser.title,
            "links": parser.links,
            "forms": parser.forms,
            "content_snippet": text[:200],
        }


def https_check(target, timeout=10):
    parsed = urllib.parse.urlparse(target if "//" in target else f"https://{target}")
    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        raise ValueError("Could not parse hostname for HTTPS check")

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ssl_context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            protocol = ssock.version()

            not_after = cert.get("notAfter")
            expiry = None
            valid = None
            if not_after:
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    valid = expiry > datetime.utcnow()
                except ValueError:
                    expiry = not_after

            alt_names = []
            for field in cert.get("subjectAltName", []):
                if field[0].lower() == "dns":
                    alt_names.append(field[1])

            return {
                "host": host,
                "port": port,
                "protocol": protocol,
                "cipher": cipher,
                "cert_subject": cert.get("subject", []),
                "cert_issuer": cert.get("issuer", []),
                "valid_until": expiry,
                "valid_certificate": valid,
                "subject_alt_names": alt_names,
            }


def exploit_scan(url, timeout=10, sql_test=False):
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme:
        raise ValueError("URL must include scheme, e.g. http:// or https://")

    def fetch(method):
        request = urllib.request.Request(
            url,
            method=method,
            headers={"User-Agent": "Mozilla/5.0 (Scanner)"},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return {
                "status": response.status,
                "headers": dict(response.headers),
                "body": response.read().decode("utf-8", errors="replace"),
            }

    findings = []
    try:
        head = fetch("HEAD")
        findings.append(("HEAD status", head["status"]))
    except Exception as exc:
        findings.append(("HEAD failure", str(exc)))
        head = None

    try:
        options = fetch("OPTIONS")
        allow = options["headers"].get("Allow", "")
        findings.append(("Allowed methods", allow))
        if "TRACE" in allow.upper():
            findings.append(("Warning", "TRACE method appears allowed"))
    except Exception as exc:
        findings.append(("OPTIONS failure", str(exc)))
        allow = ""

    if head:
        headers = {k.lower(): v for k, v in head["headers"].items()}
        security_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "x-xss-protection",
            "referrer-policy",
        ]
        for name in security_headers:
            if name not in headers:
                findings.append(("Missing security header", name))

        if "server" in headers:
            findings.append(("Server header", headers["server"]))
        if "x-powered-by" in headers:
            findings.append(("X-Powered-By header", headers["x-powered-by"]))

        cookie_header = headers.get("set-cookie", "")
        if cookie_header and "httponly" not in cookie_header.lower():
            findings.append(("Cookie issue", "Set-Cookie missing HttpOnly"))
        if cookie_header and "secure" not in cookie_header.lower() and parsed.scheme == "https":
            findings.append(("Cookie issue", "Set-Cookie missing Secure for HTTPS"))

    if sql_test and parsed.query:
        params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if params:
            payload = "' OR '1'='1"
            params[0] = (params[0][0], params[0][1] + payload)
            injected = parsed._replace(query=urllib.parse.urlencode(params)).geturl()
            try:
                with urllib.request.urlopen(urllib.request.Request(injected, headers={"User-Agent": "Mozilla/5.0 (Scanner)"}), timeout=timeout) as response:
                    body = response.read().decode("utf-8", errors="replace")
                    if head and body != head["body"]:
                        findings.append(("SQL injection check", f"Response changed for injected URL: {injected}"))
            except Exception as exc:
                findings.append(("SQL injection request failure", str(exc)))
        else:
            findings.append(("SQL injection skipped", "No query parameters to test"))

    return findings


def print_port_results(results):
    open_ports = [port for port, open_ in results if open_]
    print(f"Scanned {len(results)} ports")
    if open_ports:
        print("Open ports:")
        for port in open_ports:
            print(f"  - {port}")
    else:
        print("No open ports found")


def print_html_results(result):
    print(f"URL: {result['url']}")
    print(f"Status: {result['status']}")
    print(f"Title: {result['title']}")
    print(f"Links: {len(result['links'])}")
    for link in result['links'][:10]:
        print(f"  - {link}")
    print(f"Forms: {len(result['forms'])}")
    for form in result['forms'][:10]:
        print(f"  - method={form['method']} action={form['action']}")


def print_https_results(result):
    print(f"Host: {result['host']}")
    print(f"Port: {result['port']}")
    print(f"TLS version: {result['protocol']}")
    print(f"Cipher: {result['cipher']}")
    print(f"Valid certificate: {result['valid_certificate']}")
    print(f"Certificate expires: {result['valid_until']}")
    print(f"Subject Alt Names: {', '.join(result['subject_alt_names'])}")


def print_exploit_results(findings):
    if not findings:
        print("No findings")
        return
    for name, value in findings:
        print(f"{name}: {value}")


def main():
    parser = argparse.ArgumentParser(description="Port, HTML, HTTPS, and exploit scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    port_parser = subparsers.add_parser("port", help="Scan TCP ports")
    port_parser.add_argument("host", help="Target host or IP")
    port_parser.add_argument("--start", type=int, default=1, help="Start port")
    port_parser.add_argument("--end", type=int, default=1024, help="End port")
    port_parser.add_argument("--timeout", type=float, default=1.0, help="Connection timeout seconds")
    port_parser.add_argument("--workers", type=int, default=100, help="Concurrent worker threads")

    html_parser = subparsers.add_parser("html", help="Fetch and parse HTML from a URL")
    html_parser.add_argument("url", help="URL to fetch")
    html_parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout seconds")

    https_parser = subparsers.add_parser("https", help="Inspect HTTPS/TLS configuration")
    https_parser.add_argument("target", help="Hostname or URL to inspect")
    https_parser.add_argument("--timeout", type=float, default=10.0, help="Connection timeout seconds")

    exploit_parser = subparsers.add_parser("exploit", help="Run basic vulnerability checks")
    exploit_parser.add_argument("url", help="Target URL to check")
    exploit_parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout seconds")
    exploit_parser.add_argument("--sql-test", action="store_true", help="Run a basic SQL injection payload check")

    args = parser.parse_args()

    try:
        if args.command == "port":
            results = scan_ports(args.host, args.start, args.end, timeout=args.timeout, workers=args.workers)
            print_port_results(results)
        elif args.command == "html":
            result = fetch_html(args.url, timeout=args.timeout)
            print_html_results(result)
        elif args.command == "https":
            result = https_check(args.target, timeout=args.timeout)
            print_https_results(result)
        elif args.command == "exploit":
            findings = exploit_scan(args.url, timeout=args.timeout, sql_test=args.sql_test)
            print_exploit_results(findings)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()



