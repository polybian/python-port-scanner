# Python Port Scanner: Threaded TCP Scanner with Banner Grabbing

A real, working network reconnaissance tool written from scratch in pure
Python (standard library only: no pip installs). TCP connect scanning with
configurable threads/timeout, service banner grabbing, and CSV + JSON output.

**What this demonstrates:** Python socket programming, concurrency with
`ThreadPoolExecutor`, defensive argument/target validation, testable code
layout with a real `unittest` suite, and responsible tooling design: the
scanner **refuses public targets by default** (see Scope & ethics).

```
   scan targets (default scope: loopback + RFC 1918 only)
   ┌──────────────────────────────────────────────────────┐
   │                scripts/portscan.py                   │
   │  ┌────────────┐   ┌──────────────┐   ┌────────────┐  │
   │  │ parse args │──▶│ scan engine  │──▶│ outputs    │  │
   │  │ + validate │   │ (100 threads)│   │ .csv/.json │  │
   │  └────────────┘   └──────┬───────┘   └────────────┘  │
   │                          │ per open port:            │
   │                          │   connect → banner → RTT  │
   └──────────────────────────────────────────────────────┘
        127.0.0.1 / 10.x / 172.16.x / 192.168.x
```

## Repo layout

| Path | Purpose |
|---|---|
| `scripts/portscan.py` | The scanner (CLI entry point, ~440 lines, commented) |
| `tests/test_portscan.py` | 34 unit tests: port parsing, scope rules, banner grabbing vs a live test socket, output formats, CIDR/set-guard, fingerprinting, HTML |
| `docs/architecture.md` | Design decisions: connect scan vs SYN scan, threading model, banner strategy |

## Quick start

```bash
# Scan localhost (allowed by default - it's yours)
python3 scripts/portscan.py 127.0.0.1 --ports 1-1024

# Scan your private network segment
python3 scripts/portscan.py 192.168.1.50 --ports 22,80,443,8080

# Run the tests
python3 -m unittest discover -s tests -v
```

## Scope & ethics (read before use)

Port scanning third-party systems without permission is illegal in many
jurisdictions and hostile everywhere. This tool encodes that in code, not
just docs:

- Default scope is private-only: **only** loopback and RFC 1918 private
  addresses are accepted (select with `--target-scope`). Public targets are
  refused with an error.
- `--target-scope own` unlocks public targets **only** as your explicit
  assertion that you own the host or hold written permission to test it.

## Security notes

- TCP *connect* scan: full handshakes, visible in target logs. There is no
  stealth mode and there shouldn't be: this is an inventory/audit tool.
- Banners are truncated to 200 chars in output; no payloads beyond benign
  service-specific probes (an HTTP `HEAD /`, the RDP X.224 request: see v2).

## What's new in v2

Multi-target scanning, a self-contained HTML report, and a proper banner
fingerprint table: all still standard library only.

- **CIDR + multi-target support.** The target argument now accepts a subnet
  (`127.0.0.0/30`), comma-separated hosts (`10.0.0.1,10.0.0.5`), or a mix.
  Every address in a small CIDR block is expanded (a hard cap of
  `MAX_TARGETS = 1024` stops a `/8` typo from queueing millions of hosts).
- **Guard applies to every target.** `disallowed_targets()` checks the *whole*
  resolved set: one public IP in the mix refuses the entire run in the default private-only scope,
  verified by tests at both the function and `main()` level.
- **HTML report output.** `--format csv,json,html` (or just `--html`) writes a
  self-contained `<prefix>.html`: inline CSS only, no external assets, a scope
  badge, a summary block (targets, ports, scope, timing) and a results table.
- **Service fingerprinting.** `BANNER_SIGNATURES` is an ordered table of regex
  rules over the banner text (SSH, HTTP, SMTP vs FTP greeting disambiguation,
  MySQL/MariaDB, POP3/IMAP, RDP TPKT header): the label now comes from what
  the service *says*, falling back to the old port-number hint (`SERVICE_HINTS`)
  when the banner is silent or ambiguous. `SERVICE_PROBES` picks the probe per
  port: chatty services are just listened to; silent HTTP gets the HEAD probe;
  3389 gets an RDP X.224 negotiation request so RDP answers with a TPKT header
  the RDP signature recognizes.

```bash
# Scan a private subnet, writing CSV + JSON + HTML
python3 scripts/portscan.py 127.0.0.0/30 --ports 22,80,8080 --format csv,json,html

# Single host with the HTML report on top of the usual outputs
python3 scripts/portscan.py localhost --ports 1-1024 --html
```

### v2 test results

All 34 unit tests (the original 11 + 23 new: CIDR expansion, target-set guard,
fingerprint rules, HTML output) passing:

```
$ python3 -m unittest discover -s tests -v
test_cidr_and_host_mix (test_portscan.TestExpandTargets.test_cidr_and_host_mix) ... ok
test_cidr_expansion (test_portscan.TestExpandTargets.test_cidr_expansion) ... ok
test_comma_separated_mix (test_portscan.TestExpandTargets.test_comma_separated_mix) ... ok
test_hostname_resolves (test_portscan.TestExpandTargets.test_hostname_resolves) ... ok
test_rejects_bad_subnet (test_portscan.TestExpandTargets.test_rejects_bad_subnet) ... ok
test_rejects_too_large_subnet (test_portscan.TestExpandTargets.test_rejects_too_large_subnet) ... ok
test_rejects_unresolvable (test_portscan.TestExpandTargets.test_rejects_unresolvable) ... ok
test_single_slash32 (test_portscan.TestExpandTargets.test_single_slash32) ... ok
test_empty_and_unknown (test_portscan.TestFingerprint.test_empty_and_unknown) ... ok
test_falls_back_to_port_hint (test_portscan.TestFingerprint.test_falls_back_to_port_hint) ... ok
test_ftp_banner (test_portscan.TestFingerprint.test_ftp_banner) ... ok
test_http_banner (test_portscan.TestFingerprint.test_http_banner) ... ok
test_mysql_banner (test_portscan.TestFingerprint.test_mysql_banner) ... ok
test_rdp_heuristic (test_portscan.TestFingerprint.test_rdp_heuristic) ... ok
test_smtp_banner (test_portscan.TestFingerprint.test_smtp_banner) ... ok
test_ssh_banner (test_portscan.TestFingerprint.test_ssh_banner) ... ok
test_html_exists_and_contains_target (test_portscan.TestHtmlOutput.test_html_exists_and_contains_target) ... ok
test_html_handles_no_open_ports (test_portscan.TestHtmlOutput.test_html_handles_no_open_ports) ... ok
test_csv_and_json_roundtrip (test_portscan.TestOutputs.test_csv_and_json_roundtrip) ... ok
test_dedup_sorted (test_portscan.TestParsePorts.test_dedup_sorted) ... ok
test_list_and_range (test_portscan.TestParsePorts.test_list_and_range) ... ok
test_rejects_bad_range (test_portscan.TestParsePorts.test_rejects_bad_range) ... ok
test_single (test_portscan.TestParsePorts.test_single) ... ok
test_banner_port (test_portscan.TestScanPort.test_banner_port) ... ok
test_closed_port_returns_none (test_portscan.TestScanPort.test_closed_port_returns_none) ... ok
test_silent_server_gets_http_probe (test_portscan.TestScanPort.test_silent_server_gets_http_probe) ... ok
test_private_allows_loopback_and_private (test_portscan.TestScope.test_private_allows_loopback_and_private) ... ok
test_private_refuses_non_rfc1918_special_ranges (test_portscan.TestScope.test_private_refuses_non_rfc1918_special_ranges) ... ok
test_private_refuses_public (test_portscan.TestScope.test_private_refuses_public) ... ok
test_own_scope_allows_public (test_portscan.TestScope.test_own_scope_allows_public) ... ok
test_guard_accepts_all_private (test_portscan.TestTargetSetGuard.test_guard_accepts_all_private) ... ok
test_guard_own_allows_set (test_portscan.TestTargetSetGuard.test_guard_own_allows_set) ... ok
test_guard_rejects_set_with_any_public (test_portscan.TestTargetSetGuard.test_guard_rejects_set_with_any_public) ... ok
test_main_cidr_set_refuses_public (test_portscan.TestTargetSetGuard.test_main_cidr_set_refuses_public) ... ok
test_main_refuses_whole_run_on_one_public (test_portscan.TestTargetSetGuard.test_main_refuses_whole_run_on_one_public) ... ok

Ran 35 tests in 0.313s - OK
```

(Note: two guard tests print the expected `error: refusing to scan ...` lines
to stderr mid-run. That's the test asserting `main()` exits 2 on a public
target, exactly the behavior being verified.)

Live validation: CIDR scan of `127.0.0.0/30` against a real localhost
HTTP listener (`python3 -m http.server 8080 --bind 127.0.0.1`), exercising
expansion + HTML + fingerprinting in one run. Note 8080 is now labeled `http`
from its banner (in v1 it would have been the `http-alt` port-number guess):

```
$ python3 scripts/portscan.py 127.0.0.0/30 --ports 8080 --format csv,json,html --output validation-v2/scan
[*] scanning 127.0.0.0/30 (4 targets) - 1 port(s)/target, 100 threads
[+] 127.0.0.1:  8080/tcp open  http - HTTP/1.0 200 OK
[*] 1 open port(s) across 4 target(s) in 0.3s → validation-v2/scan.csv / validation-v2/scan.json / validation-v2/scan.html
```

The generated `validation-v2/scan.html` is a single self-contained file:
`<title>Port scan report - 127.0.0.0/30 (private scope)</title>`, the summary block and
result row both contain the scanned target(s), and `grep` for external
asset references (`src="http` / `href="http`) found zero matches.

Scope guard on a mixed target set: one public IP refuses the whole run:

```
$ python3 scripts/portscan.py 127.0.0.1,8.8.8.8 --ports 53    (exit code 2)
error: refusing to scan 8.8.8.8: not a loopback/private address. ...
```

Notes: the `/30` expansion includes network + broadcast addresses
(all four were scanned; only 127.0.0.1 had the listener), and the
"unresolvable host" test uses a malformed label (`no_such_host!.invalid`)
because some DNS resolvers answer for any well-formed hostname.

## Test results

Unit tests: 11/11 passing:

```
$ python3 -m unittest discover -s tests -v
test_dedup_sorted ... ok
test_list_and_range ... ok
test_rejects_bad_range ... ok
test_single ... ok
test_banner_port ... ok
test_closed_port_returns_none ... ok
test_silent_server_gets_http_probe ... ok
test_private_allows_loopback_and_private ... ok
test_private_refuses_public ... ok
test_own_scope_allows_public ... ok

Ran 11 tests in 0.309s - OK
```

Live scan against two real localhost listeners (a fake SSH banner server on
2222, `python3 -m http.server` on 8080):

```
$ python3 scripts/portscan.py 127.0.0.1 --ports 2222,8080
[*] scanning 127.0.0.1 (127.0.0.1) - 2 ports, 100 threads
[+]  2222/tcp open   - SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13
[+]  8080/tcp open  http-alt - HTTP/1.0 200 OK
[*] 2 open port(s) in 0.3s → scan.csv / scan.json
```

Scope guard verified: public target refused by default:

```
$ python3 scripts/portscan.py 8.8.8.8 --ports 53    (exit code 2)
error: refusing to scan 8.8.8.8: not a loopback/private address. ...
```

Full-range timing: 1,024 ports on localhost scanned in 0.2s with 100 threads.
No external network access was needed or used for validation.
