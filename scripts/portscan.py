#!/usr/bin/env python3
"""portscan.py - a clean, threaded TCP port scanner with banner grabbing.

Standard library only. Built as a portfolio tool.

Scope & ethics
--------------
By default this tool only scans targets you own: loopback addresses and
RFC 1918 private ranges (10/8, 172.16/12, 192.168/16). Scanning any other
address requires the explicit flag ``--target-scope own`` - your assertion
that you own the target or have written permission to test it. Never scan
systems you do not own or lack permission for.
"""
from __future__ import annotations

import argparse
import csv
import html
import ipaddress
import json
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# Well-known service guesses for open ports (banner, when present, is better).
SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-alt",
}

PRIVATE_ONLY_MSG = (
    "refusing to scan {target}: not a loopback/private address. "
    "Only scan systems you own or have written permission to test. "
    "If this is your own host, pass --target-scope own."
)

# --- v2: service fingerprint signatures & probes ----------------------------
# Ordered banner signatures: (service label, compiled pattern). The first
# match wins, so specific rules (FTP vs SMTP, both of which greet with
# "220 ...") are distinguished by the keywords in the greeting itself.
# These are heuristics on the banner text, not protocol verification.
BANNER_SIGNATURES: list[tuple[str, re.Pattern]] = [
    ("ssh", re.compile(r"^SSH-\d", re.IGNORECASE)),
    ("http", re.compile(r"^HTTP/\d", re.IGNORECASE)),
    ("mysql", re.compile(r"(mysql|mariadb)", re.IGNORECASE)),
    ("ftp", re.compile(r"^220[ -].*(ftp|vsftpd|proftpd|filezilla)", re.IGNORECASE)),
    ("ftp", re.compile(r"^220.*\(vsFTPd", re.IGNORECASE)),
    ("smtp", re.compile(r"^220[ -].*(smtp|esmtp|mail|postfix|exim|sendmail)", re.IGNORECASE)),
    # A bare "220 ..." greeting with no FTP keywords is most often SMTP.
    ("smtp", re.compile(r"^220[ -]")),
    ("pop3", re.compile(r"^\+OK.*(pop3|dovecot)", re.IGNORECASE)),
    ("imap", re.compile(r"^\* OK.*imap", re.IGNORECASE)),
    # RDP answers an X.224 request with a TPKT header (0x03 0x00 ...), which
    # survives the text decode as control characters at the start.
    ("rdp", re.compile(r"^\x03\x00")),
]

# Probe table: what (if anything) to send a silent service on a given port.
# None means "the server speaks first - just listen". Before v2 every silent
# service got the same HTTP HEAD probe; v2 sends the RDP negotiation request
# on 3389 so an RDP host can answer with its TPKT header (see above).
SERVICE_PROBES: dict[int, bytes | None] = {
    21: None,    # FTP: server greets first
    22: None,    # SSH: server greets first
    25: None,    # SMTP: server greets first
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    110: None,   # POP3: server greets first
    143: None,   # IMAP: server greets first
    3306: None,  # MySQL: server sends a handshake packet first
    3389: (      # RDP: X.224 Connection Request (TPKT + negotiation)
        b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
    ),
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
}
DEFAULT_PROBE = b"HEAD / HTTP/1.0\r\n\r\n"

# Hard cap so a typo like 10.0.0.0/8 cannot queue millions of hosts.
MAX_TARGETS = 1024


def fingerprint_service(banner: str, port: int | None = None) -> str:
    """Label a service from its banner; fall back to the port-number hint.

    Returns "" when neither the banner nor the port gives a usable hint.
    """
    if banner:
        for label, pattern in BANNER_SIGNATURES:
            if pattern.search(banner):
                return label
    if port is not None:
        return SERVICE_HINTS.get(port, "")
    return ""


def is_scan_allowed(target: str, scope: str) -> bool:
    """Return True if the target is in scope.

    scope='private' (default): loopback + RFC1918 private addresses only.
    scope='own': user asserts ownership/written permission; any address.
    """
    if scope == "own":
        return True
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return False  # unresolvable / malformed hosts handled by caller
    # Explicit allow-list - deliberately NOT ip.is_private, which also
    # matches 169.254.0.0/16 (link-local), 192.0.2.0/24 (TEST-NET-1),
    # 198.18.0.0/15 (benchmarking) and 240.0.0.0/4 (reserved). None of
    # those should be scanned under the default scope.
    return any(ip in net for net in _ALLOWED_PRIVATE)


# Loopback + the three RFC1918 ranges, and nothing else.
_ALLOWED_PRIVATE = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def expand_targets(spec: str) -> list[str]:
    """Expand a target spec into a dedup'd list of IP strings.

    Accepts a single IP/hostname, a CIDR subnet (``127.0.0.0/30``) or a
    comma-separated mix of both. Every address in a CIDR block is expanded
    (network/broadcast included, the way small private subnets are scanned).
    Raises ValueError for unresolvable hosts, bad CIDR notation or specs
    that would scan more than ``MAX_TARGETS`` addresses.
    """
    targets: list[str] = []
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "/" in token:  # CIDR subnet
            try:
                network = ipaddress.ip_network(token, strict=False)
            except ValueError as exc:
                raise ValueError(f"bad subnet: {token!r}") from exc
            if network.num_addresses > MAX_TARGETS:
                raise ValueError(
                    f"subnet {token!r} has {network.num_addresses} addresses "
                    f"(max {MAX_TARGETS}) - narrow the range"
                )
            targets.extend(str(addr) for addr in network)
        else:  # single IP or hostname - resolved once, right here
            try:
                ipaddress.ip_address(token)  # already an IP: no DNS needed
                targets.append(token)
            except ValueError:
                try:
                    targets.append(socket.gethostbyname(token))
                except (socket.gaierror, UnicodeError) as exc:
                    raise ValueError(f"cannot resolve {token!r}") from exc
    if not targets:
        raise ValueError("no targets given")
    seen: set[str] = set()
    unique = [t for t in targets if not (t in seen or seen.add(t))]  # type: ignore[func-returns-value]
    return unique


def disallowed_targets(targets: list[str], scope: str) -> list[str]:
    """Return the subset of targets the scope guard rejects (empty if none)."""
    return [t for t in targets if not is_scan_allowed(t, scope)]


def check_targets(targets: list[str], scope: str) -> None:
    """Raise PermissionError naming any public target in a default-scope (private-only) run.

    Applies the scope guard to EVERY resolved target: a single public
    address refuses the whole run.
    """
    bad = disallowed_targets(targets, scope)
    if bad:
        raise PermissionError(
            PRIVATE_ONLY_MSG.format(target=", ".join(bad))
        )


def parse_ports(spec: str) -> list[int]:
    """Parse '80', '80,443', '1-1024', '22,80-82' into a sorted unique list."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if not (1 <= start <= end <= 65535):
                raise ValueError(f"bad range: {part!r}")
            ports.update(range(start, end + 1))
        else:
            port = int(part)
            if not 1 <= port <= 65535:
                raise ValueError(f"bad port: {part!r}")
            ports.add(port)
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


def grab_banner(sock: socket.socket, timeout: float, port: int | None = None) -> str:
    """Read a service banner; probe the peer if it waits silently.

    Chatty services (SSH, FTP, SMTP) speak up immediately. Quiet ones need a
    nudge - the probe is chosen per port from SERVICE_PROBES (RDP gets the
    X.224 negotiation request; everything unknown gets the benign HEAD probe).
    """
    # Short initial wait: chatty services speak first immediately.
    sock.settimeout(min(timeout, 0.3))
    try:
        data = sock.recv(1024)
    except (socket.timeout, OSError):
        data = b""
    if not data:
        # Quiet services speak only after we do.
        probe = SERVICE_PROBES.get(port, DEFAULT_PROBE) if port is not None \
            else DEFAULT_PROBE
        sock.settimeout(timeout)
        try:
            if probe:
                sock.sendall(probe)
            data = sock.recv(1024)
        except (socket.timeout, OSError):
            data = b""
    return data.decode("utf-8", "replace").strip().splitlines()[0] if data else ""


def scan_port(target: str, port: int, timeout: float) -> dict | None:
    """Return a result dict for an OPEN port, else None."""
    started = time.monotonic()
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            banner = grab_banner(sock, timeout, port)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    rtt_ms = round((time.monotonic() - started) * 1000, 1)
    return {
        "target": target,
        "port": port,
        "state": "open",
        "service": fingerprint_service(banner, port),
        "banner": banner[:200],
        "rtt_ms": rtt_ms,
    }


def scan(target: str, ports: list[int], timeout: float, threads: int) -> list[dict]:
    """Scan ports concurrently; return sorted results for open ports."""
    return scan_targets([target], ports, timeout, threads)


def scan_targets(
    targets: list[str], ports: list[int], timeout: float, threads: int
) -> list[dict]:
    """Scan every port on every target; results sorted by (target, port)."""
    jobs = [(t, p) for t in targets for p in ports]
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(scan_port, t, p, timeout): (t, p) for t, p in jobs}
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
    return sorted(results, key=lambda r: (r["target"], r["port"]))


def write_csv(path: str, results: list[dict]) -> None:
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=["target", "port", "state", "service", "banner", "rtt_ms"]
        )
        writer.writeheader()
        writer.writerows(results)


def write_json(path: str, results: list[dict], meta: dict) -> None:
    with open(path, "w") as fh:
        json.dump({"meta": meta, "results": results}, fh, indent=2)


def write_html(path: str, results: list[dict], meta: dict) -> None:
    """Write a self-contained HTML report (inline CSS only, no external assets)."""
    e = html.escape
    rows = "".join(
        "<tr><td>{target}</td><td>{port}</td><td>{state}</td><td>{service}</td>"
        "<td class=\"banner\">{banner}</td><td>{rtt}</td></tr>".format(
            target=e(r["target"]), port=r["port"], state=e(r["state"]),
            service=e(r["service"] or "-"), banner=e(r["banner"] or "-"),
            rtt=e(str(r["rtt_ms"])),
        )
        for r in results
    )
    targets = meta.get("targets") or [meta.get("target", "")]
    targets_html = "".join(f"<li>{e(t)}</li>" for t in targets)
    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Port scan report - {e(str(meta.get('target', '')))} (private scope)</title>
<style>
  body {{ font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
         margin: 2rem auto; max-width: 70rem; padding: 0 1rem;
         background: #0f172a; color: #e2e8f0; }}
  h1 {{ font-size: 1.4rem; }} h2 {{ font-size: 1.1rem; margin-top: 2rem; }}
  .meta, table {{ width: 100%; border-collapse: collapse; }}
  .meta td, table th, table td {{ border: 1px solid #334155; padding: .45rem .6rem;
         text-align: left; font-size: .85rem; vertical-align: top; }}
  .meta td:first-child {{ font-weight: 600; width: 11rem; background: #1e293b; }}
  table th {{ background: #1e293b; }}
  table tr:nth-child(even) td {{ background: #16213a; }}
  td.banner {{ font-family: ui-monospace, monospace; word-break: break-all; }}
  .private {{ display: inline-block; background: #f59e0b; color: #111827; font-size: .7rem;
         font-weight: 700; padding: .15rem .5rem; border-radius: .25rem;
         vertical-align: middle; }}
  footer {{ margin-top: 2rem; font-size: .75rem; color: #94a3b8; }}
</style>
</head>
<body>
<h1>Port scan report <span class="private">PRIVATE SCOPE</span></h1>
<h2>Summary</h2>
<table class="meta">
<tr><td>Target spec</td><td>{e(str(meta.get('target', '')))}</td></tr>
<tr><td>Targets scanned</td><td><ul>{targets_html}</ul></td></tr>
<tr><td>Ports scanned</td><td>{e(str(meta.get('ports_scanned', '')))}</td></tr>
<tr><td>Open ports</td><td>{len(results)}</td></tr>
<tr><td>Scope</td><td>{e(str(meta.get('scope', '')))}</td></tr>
<tr><td>Started (UTC)</td><td>{e(str(meta.get('started_utc', '')))}</td></tr>
<tr><td>Elapsed</td><td>{e(str(meta.get('elapsed_s', '')))} s</td></tr>
</table>
<h2>Open ports</h2>
<table>
<tr><th>Target</th><th>Port</th><th>State</th><th>Service</th><th>Banner</th><th>RTT (ms)</th></tr>
{rows if rows else "<tr><td colspan='6'>No open ports found.</td></tr>"}
</table>
<footer>Generated by portscan.py v2 - network inventory tool. Only scan systems you own
or have written permission to test.</footer>
</body>
</html>
"""
    with open(path, "w") as fh:
        fh.write(doc)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Threaded TCP port scanner with banner grabbing (network tool)."
    )
    parser.add_argument(
        "target",
        help="IP, hostname, CIDR subnet (e.g. 192.168.1.0/28) or "
             "comma-separated mix (e.g. '10.0.0.1,10.0.0.5')",
    )
    parser.add_argument(
        "--ports", default="1-1024",
        help="ports to scan: '80', '80,443', '1-1024', '22,80-82' (default 1-1024)",
    )
    parser.add_argument("--timeout", type=float, default=1.0, help="seconds per port")
    parser.add_argument("--threads", type=int, default=100, help="concurrent workers")
    parser.add_argument(
        "--target-scope", choices=["private", "own"], default="private",
        help="private-only scope (default): only loopback/private targets. own: you assert you "
             "own the target or have written permission to test it.",
    )
    parser.add_argument(
        "--output", default="scan",
        help="output file prefix (writes <prefix>.csv and <prefix>.json; "
             "plus <prefix>.html with --format html/--html)",
    )
    parser.add_argument(
        "--format", default="csv,json", dest="formats",
        help="comma-separated output formats: csv, json, html (default 'csv,json')",
    )
    parser.add_argument(
        "--html", action="store_true",
        help="also write an HTML report (<prefix>.html) alongside the rest",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        targets = expand_targets(args.target)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    bad = disallowed_targets(targets, args.target_scope)
    if bad:
        print("error: " + PRIVATE_ONLY_MSG.format(target=", ".join(bad)),
              file=sys.stderr)
        return 2
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    formats = {f.strip().lower() for f in args.formats.split(",")}
    if args.html:
        formats.add("html")
    bad_fmt = formats - {"csv", "json", "html"}
    if bad_fmt:
        print(f"error: unknown format(s): {', '.join(sorted(bad_fmt))}",
              file=sys.stderr)
        return 2

    meta = {
        "version": 2,
        "target": args.target,
        "targets": targets,
        "resolved": targets,
        "ports_scanned": len(ports),
        "scope": args.target_scope,
        "started_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    shown = targets[0] if len(targets) == 1 else f"{len(targets)} targets"
    print(f"[*] scanning {args.target} ({shown}) - {len(ports)} port(s)/target, "
          f"{args.threads} threads", flush=True)
    started = time.monotonic()
    results = scan_targets(targets, ports, args.timeout, args.threads)
    elapsed = time.monotonic() - started
    meta["elapsed_s"] = round(elapsed, 1)

    written = []
    if "csv" in formats:
        write_csv(args.output + ".csv", results)
        written.append(args.output + ".csv")
    if "json" in formats:
        write_json(args.output + ".json", results, meta)
        written.append(args.output + ".json")
    if "html" in formats:
        write_html(args.output + ".html", results, meta)
        written.append(args.output + ".html")

    for r in results:
        banner = f" - {r['banner']}" if r["banner"] else ""
        print(f"[+] {r['target']}:{r['port']:>5}/tcp open  {r['service']}{banner}")
    print(f"[*] {len(results)} open port(s) across {len(targets)} target(s) "
          f"in {elapsed:.1f}s → {' / '.join(written)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
