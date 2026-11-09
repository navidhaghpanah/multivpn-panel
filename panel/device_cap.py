"""Unique-IP device cap for dedicated per-user ports only.

Shadowsocks, the HTTPS proxy, and personal MTProto each listen on a port that
belongs to one account. Shared listeners (VLESS, VMess, Hysteria2, legacy
MTProto) are never touched: an iptables drop there would cut off other users.
TCP connection count is not a device count; this counts remote IPs.
"""
import ipaddress
import time
from pathlib import Path

COMMENT = "mvp-devcap"
MARKER = "__devcap:"
RULE = "__devcaprule:"


def _parse_proc(text, ipv6):
    found = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4 or parts[3] != "01":
            continue
        try:
            local, remote = parts[1], parts[2]
            laddr, lport = local.split(":")
            raddr, _rport = remote.split(":")
            port = int(lport, 16)
            if ipv6:
                raw = bytes.fromhex(laddr)
                groups = [raw[i:i + 4][::-1] for i in range(0, 16, 4)]
                ip = str(ipaddress.IPv6Address(b"".join(groups)))
            else:
                ip = str(ipaddress.IPv4Address(bytes.fromhex(laddr)[::-1]))
        except (ValueError, IndexError):
            continue
        found.append((port, ip))
    return found


def read_established():
    found = []
    for path, ipv6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        try:
            found.extend(_parse_proc(Path(path).read_text(encoding="utf-8", errors="replace"), ipv6))
        except OSError:
            continue
    return found


def _usable_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        return None
    return str(addr)


def _user_ports(user):
    ports = []
    if not isinstance(user, dict):
        return ports
    for key in ("ss_port", "http_port", "mtg_port"):
        try:
            port = int(user.get(key) or 0)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return ports


def plan_drops(users, old_snap, new_snap, limit, connections, now, grace=60):
    """Return {(ip, port)} that should be REJECTed. Records first-seen markers.

    Brand-new extra IPs stay during ``grace`` seconds so a roaming client is
    not dropped on the first sample. The newest ``limit`` IPs are kept.
    """
    try:
        limit = max(1, min(10, int(limit)))
    except (TypeError, ValueError):
        limit = 1
    now = float(now)
    by_port = {}
    for port, ip in connections or []:
        norm = _usable_ip(ip)
        if norm is None:
            continue
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        by_port.setdefault(port, [])
        if norm not in by_port[port]:
            by_port[port].append(norm)
    desired = set()
    for name, user in (users or {}).items():
        ports = _user_ports(user)
        if not ports:
            continue
        seen = []
        known = set()
        for port in ports:
            for ip in by_port.get(port, []):
                if ip not in known:
                    known.add(ip)
                    seen.append(ip)
        stamped = []
        for ip in seen:
            marker = "%s%s:%s" % (MARKER, name, ip)
            try:
                first = float(old_snap.get(marker))
            except (TypeError, ValueError):
                first = now
            new_snap[marker] = first
            stamped.append((first, ip))
        stamped.sort(key=lambda item: (item[0], item[1]), reverse=True)
        for first, ip in stamped[limit:]:
            if now - first < grace:
                continue
            for port in ports:
                desired.add((ip, port))
    return desired


def _rule_key(ip, port):
    return "%s%s:%s" % (RULE, ip, port)


def _previous_rules(old_snap):
    found = set()
    for key in old_snap or {}:
        if not str(key).startswith(RULE):
            continue
        ip, _, port_s = str(key)[len(RULE):].rpartition(":")
        try:
            found.add((ip, int(port_s)))
        except ValueError:
            continue
    return found


def _iptables(ip):
    return "ip6tables" if ":" in ip else "iptables"


def _reject_cmd(action, ip, port):
    return [
        _iptables(ip), action, "INPUT", "-p", "tcp", "-s", ip, "--dport", str(port),
        "-m", "comment", "--comment", COMMENT, "-j", "REJECT", "--reject-with", "tcp-reset",
    ]


def enforce(users, old_snap, new_snap, limit, run, connections=None, now=None, grace=60):
    """Install or remove mvp-devcap rejects. Never raises."""
    try:
        for key in list(new_snap):
            if str(key).startswith("__devcap"):
                new_snap.pop(key, None)
        if connections is None:
            connections = read_established()
        desired = plan_drops(
            users, old_snap, new_snap, limit, connections,
            time.time() if now is None else now, grace,
        )
        previous = _previous_rules(old_snap)
        for ip, port in sorted(previous - desired):
            run(_reject_cmd("-D", ip, port), timeout=5)
        for ip, port in sorted(desired - previous):
            run(_reject_cmd("-I", ip, port), timeout=5)
        for ip, port in desired:
            new_snap[_rule_key(ip, port)] = 1
    except Exception:
        return
