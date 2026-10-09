"""Build an AdGuard Home filter without contacting a DNS provider API."""
import ipaddress
import os
from pathlib import Path
import re
import urllib.request

DEFAULT_SOURCE = "https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/hosts"
DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize(value):
    return value.strip().lstrip("#").strip().lower()


def parse_hosts(data, excluded):
    skip = False
    for line in data.splitlines():
        line = line.strip()
        if line.startswith("#"):
            skip = normalize(line) in excluded
            continue
        if skip:
            continue
        fields = line.split("#", 1)[0].split()
        if not fields:
            continue
        try:
            address = ipaddress.ip_address(fields[0])
        except ValueError:
            if len(fields) != 1:
                raise ValueError(f"Invalid hosts line: {line}")
            address = None
            domains = fields
        else:
            domains = fields[1:]
        for domain in domains:
            domain = domain.lower().rstrip(".")
            if domain.startswith("www."):
                domain = domain[4:]
            if domain in {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "ip6-allnodes", "ip6-allrouters"}:
                continue
            if not DOMAIN.fullmatch(domain):
                raise ValueError(f"Invalid domain: {domain}")
            yield address, domain


def build_filter(redirect_data, block_data, sections=(), ignored=()):
    redirects = {}
    blocked = set()
    for data in redirect_data:
        for address, domain in parse_hosts(data, set(sections)):
            if address is None or address.is_unspecified or address.is_loopback:
                continue
            if any(domain == item or domain.endswith("." + item) for item in ignored):
                continue
            redirects.setdefault(domain, address)
    for data in block_data:
        for address, domain in parse_hosts(data, set(sections)):
            if address is None or address.is_unspecified or address.is_loopback:
                blocked.add(domain)
    if not redirects:
        raise ValueError("No redirect records found; refusing to replace the working filter")
    rules = ["! GeoHide redirects for AdGuard Home — generated, do not edit"]
    # dnsrewrite also returns NODATA for other record types: native AAAA/HTTPS
    # answers must not bypass a GeoHide IPv4 redirect.
    for domain, address in sorted(redirects.items()):
        kind = "A" if address.version == 4 else "AAAA"
        rules.append(f"||{domain}^$dnsrewrite=NOERROR;{kind};{address}")
    rules.extend(f"||{domain}^" for domain in sorted(blocked - redirects.keys()))
    # Exceptions are scoped to rewrites, so optional blocklists still apply.
    rules.extend(f"@@||{domain}^$dnsrewrite" for domain in sorted(set(ignored)))
    return "\n".join(rules) + "\n"


def download(url):
    if not url.startswith("https://"):
        raise ValueError("Sources must use HTTPS")
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read().decode("utf-8-sig")


def main():
    if os.environ.get("DONOR_DNS", "").strip():
        raise ValueError("DONOR_DNS is not supported in SELFHOSTED mode; clear it first")
    sections = Path("hosts_exclude").read_text().splitlines() if Path("hosts_exclude").exists() else []
    sections = {normalize(item) for item in sections if normalize(item)}
    ignored = [item.strip().lower().rstrip(".") for item in os.environ.get("EXCLUDE_REDIRECT", "").split(",") if item.strip()]
    if any(not DOMAIN.fullmatch(item) for item in ignored):
        raise ValueError("Invalid EXCLUDE_REDIRECT domain")
    redirect_urls = os.environ.get("REDIRECT", "").strip() or DEFAULT_SOURCE
    redirects = [download(url.strip()) for url in redirect_urls.split(",") if url.strip()]
    blocks = [download(url.strip()) for url in os.environ.get("BLOCK", "").split(",") if url.strip()]
    result = build_filter(redirects, blocks, sections, ignored)
    output = Path("selfhosted/geohide-filter.txt")
    temporary = output.with_suffix(".tmp")
    temporary.write_text(result, encoding="utf-8")
    temporary.replace(output)
    print(f"Generated {len(result.splitlines()) - 1} rules")


if __name__ == "__main__":
    main()
