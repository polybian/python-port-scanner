# Architecture & Design Decisions

## Why a TCP connect scan (not a SYN scan)

- **Connect scan** uses the normal OS socket API (`socket.create_connection`):
  no root, no raw sockets, no packet crafting. Portable to any OS Python runs on.
- **SYN ("half-open") scan** needs raw sockets + elevated privileges and tools
  like Scapy or libpcap. It's what nmap does by default as root.
- Trade-off accepted: connect scans are louder in logs and slightly slower per
  port. For an *inventory/audit tool on systems you own*, loud and correct beats
  quiet and fragile.

## Threading model

- `ThreadPoolExecutor` with a configurable worker count (default 100).
- Port scanning is I/O-bound (almost all time is waiting on sockets), so
  threads beat processes here; the GIL is released during socket waits.
- Futures are collected with `as_completed` and results sorted by port at the
  end, so output is deterministic regardless of completion order.

## Banner grabbing strategy

Two-phase read per open port:
1. Listen briefly (0.3s): protocols that speak first (SSH, FTP, SMTP) reveal
   themselves immediately.
2. If silent, send a benign `HEAD / HTTP/1.0` probe and read again: HTTP and
   most web servers answer with a status line + Server header.

Banners give a *fingerprint*, not just a port-number guess: the same port 8080
can be a printer, Jenkins, or a camera, and the banner usually tells you which.

## Target validation (defense in depth, in code)

- Hostnames are resolved **once** (`gethostbyname`) and the *resolved IP* is
  what gets scope-checked: a DNS name can't smuggle a public target past the
  private-only default.
- Scope check uses the `ipaddress` module (`is_loopback` / `is_private`), not
  string matching on prefixes.

## Output formats

- **CSV**: for spreadsheets, ticketing systems, quick diffs between runs.
- **JSON with a `meta` block**: scan parameters + timestamp, so a result file
  is self-describing months later in an audit trail.

## Known limits

- No UDP scanning, no OS fingerprinting, no version detection beyond banners.
- Accuracy on high-latency WAN targets depends on `--timeout`; the defaults
  are tuned for LAN/private-network use.
- Service names for well-known ports are *hints* (`SERVICE_HINTS`); the banner
  is the source of truth when present.
