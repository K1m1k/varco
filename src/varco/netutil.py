# SPDX-License-Identifier: GPL-3.0-or-later
"""Packet parsing, DNS observation, reverse lookups and whois."""
import ipaddress
import os
import re
import secrets
import socket
import struct
import threading
import time

from . import _
from .util import is_private, read

MARK = 0x5E17          # packets sent by Varco itself (whois / reverse DNS) carry this mark
SO_MARK = 36

PROTO = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6", 132: "sctp"}


def parse_ip(p):
    """Parse an IPv4/IPv6 packet: protocol, addresses, ports and L4 offset."""
    if len(p) < 20:
        return None
    v = p[0] >> 4
    if v == 4:
        ihl = (p[0] & 15) * 4
        proto = p[9]
        src = socket.inet_ntop(socket.AF_INET, p[12:16])
        dst = socket.inet_ntop(socket.AF_INET, p[16:20])
        off = ihl
    elif v == 6 and len(p) >= 40:
        proto = p[6]
        src = socket.inet_ntop(socket.AF_INET6, p[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, p[24:40])
        off = 40
        while proto in (0, 43, 44, 60) and len(p) >= off + 8:
            if proto == 44:
                proto, off = p[off], off + 8
            else:
                proto, off = p[off], off + (p[off + 1] + 1) * 8
    else:
        return None
    sport = dport = None
    if proto in (6, 17, 132) and len(p) >= off + 4:
        sport, dport = struct.unpack("!HH", p[off:off + 4])
    return {"v": v, "proto": PROTO.get(proto, str(proto)), "src": src, "dst": dst,
            "sport": sport, "dport": dport, "off": off}


# ------------------------------------------------------------------ DNS

def _read_name(m, off):
    labels, jumped, end, hops = [], False, off, 0
    while True:
        if off >= len(m):
            raise ValueError("truncated DNS name")
        ln = m[off]
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(m):
                raise ValueError("truncated DNS pointer")
            if not jumped:
                end = off + 2
            jumped, off = True, ((ln & 0x3F) << 8) | m[off + 1]
            hops += 1
            if hops > 40:
                raise ValueError("DNS pointer loop")
            continue
        if ln == 0:
            if not jumped:
                end = off + 1
            break
        labels.append(m[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    return ".".join(labels).lower(), end


def parse_dns(m):
    """Return (questions, records); a record is (owner, type, data, ttl)."""
    if len(m) < 12:
        return [], []
    qd, an = struct.unpack("!HH", m[4:8])
    off, qnames, recs = 12, [], []
    for _i in range(qd):
        n, off = _read_name(m, off)
        off += 4
        qnames.append(n)
    for _i in range(an):
        n, off = _read_name(m, off)
        t, _c, ttl, rl = struct.unpack("!HHIH", m[off:off + 10])
        off += 10
        rd = m[off:off + rl]
        if t == 1 and rl == 4:
            recs.append((n, t, socket.inet_ntop(socket.AF_INET, rd), ttl))
        elif t == 28 and rl == 16:
            recs.append((n, t, socket.inet_ntop(socket.AF_INET6, rd), ttl))
        elif t in (5, 12):
            recs.append((n, t, _read_name(m, off)[0], ttl))
        off += rl
    return qnames, recs


# a DNS name as shown to the user and used in rules: letters, digits, '-', '_' and dots only.
# Anything else (control characters, spaces, '*') is refused, so a hostile answer can neither
# disturb a terminal nor look like a wildcard.
NAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


def valid_name(n):
    return bool(NAME_RE.match(n or ""))


def answer_chain(qnames, recs):
    """Addresses of an answer that really belong to the question: (ip, names, ttl).

    Only records reachable from the asked name through CNAMEs count. Extra records about
    other names, which a hostile server may add, are ignored."""
    if len(qnames) != 1 or not valid_name(qnames[0]):
        return []
    chain = [qnames[0]]
    changed = True
    while changed and len(chain) < 16:
        changed = False
        for n, t, d, _ttl in recs:
            if t == 5 and n in chain and d not in chain and valid_name(d):
                chain.append(d)
                changed = True
    return [(d, chain, ttl) for n, t, d, ttl in recs if t in (1, 28) and n in chain]


_resolv_cache = {"key": None, "ips": frozenset()}
_resolv_lock = threading.Lock()
RESOLV_FILES = ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf", "/run/NetworkManager/resolv.conf")


def resolvers(files=RESOLV_FILES):
    """DNS servers the system really uses: 'nameserver' lines of resolv.conf and, with
    systemd-resolved, of its upstream list. Re-read only when one of the files changes."""
    key = []
    for f in files:
        try:
            st = os.stat(f)
            key.append((f, st.st_mtime_ns, st.st_ino, st.st_size))
        except OSError:
            key.append((f, None))
    key = tuple(key)
    with _resolv_lock:
        if key == _resolv_cache["key"]:
            return _resolv_cache["ips"]
    ips = set()
    for f in files:
        try:
            with open(f) as fh:
                for line in fh:
                    p = line.split()
                    if len(p) >= 2 and p[0] == "nameserver":
                        try:
                            ips.add(str(ipaddress.ip_address(p[1].split("%")[0])))
                        except ValueError:
                            pass
        except OSError:
            pass
    with _resolv_lock:
        _resolv_cache["key"], _resolv_cache["ips"] = key, frozenset(ips)
    return frozenset(ips)


class DnsCache:
    """Which names the system really resolved to each IP, valid while the DNS TTL lasts
    (minimum 30 s: the time an application needs to connect after resolving).

    Answers are learned only when they come from one of the system's DNS servers, and only
    for the name that was asked: otherwise any program could make up a name (for example
    'deb.debian.org') for its own server and slip through the rules based on names."""

    def __init__(self, trusted=resolvers):
        self.lock = threading.Lock()
        self.map = {}
        self.trusted = trusted

    def feed(self, msg, src):
        """Learn from one DNS answer; src is the address it came from."""
        if src not in self.trusted():
            return
        try:
            qnames, recs = parse_dns(msg)
        except (ValueError, struct.error):
            return
        found = answer_chain(qnames, recs)
        if not found:
            return
        now = time.monotonic()
        with self.lock:
            for d, chain, ttl in found:
                exp = now + max(30, min(ttl, 86400))
                cur = {n: e for n, e in self.map.get(d, {}).items() if e > now}
                for n in chain:
                    cur[n] = max(cur.get(n, 0), exp)
                self.map[d] = cur
            if len(self.map) > 30000:
                self.map = {k: v for k, v in self.map.items() if max(v.values(), default=0) > now}

    def names(self, ip):
        now = time.monotonic()
        with self.lock:
            cur = self.map.get(ip, {})
            return [n for n, e in sorted(cur.items(), key=lambda kv: -kv[1]) if e > now]


def nameserver():
    for ip in sorted(resolvers(("/etc/resolv.conf",))):
        return ip
    return None


def marked_socket(fam, typ):
    s = socket.socket(fam, typ)
    s.setsockopt(socket.SOL_SOCKET, SO_MARK, MARK)
    return s


def dns_query(name, qtype, timeout=3.0):
    """Varco's own DNS query (only to find the whois servers)."""
    ns = nameserver()
    if not ns:
        return []
    qid = secrets.randbelow(65536)
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(x)]) + x.encode() for x in name.strip(".").split(".")) + b"\0"
    q += struct.pack("!HH", qtype, 1)
    s = marked_socket(socket.AF_INET6 if ":" in ns else socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.connect((ns, 53))          # answers from any other address are refused by the kernel
        s.send(q)
        m = s.recv(4096)
    except OSError:
        return []
    finally:
        s.close()
    if len(m) < 12 or struct.unpack("!H", m[:2])[0] != qid:
        return []
    try:
        return parse_dns(m)[1]
    except (ValueError, struct.error):
        return []


def whois_raw(server, query, timeout=6.0):
    ips = [d for _n, t, d, _ttl in dns_query(server, 1) if t == 1]
    if not ips:
        return ""
    s = marked_socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    out = b""
    try:
        s.connect((ips[0], 43))
        s.sendall((query + "\r\n").encode())
        while len(out) < 131072:
            b = s.recv(8192)
            if not b:
                break
            out += b
    except OSError:
        pass
    finally:
        s.close()
    return out.decode("utf-8", "replace")


ORG_KEYS = ["org-name", "OrgName", "Organization", "owner", "descr", "netname", "NetName"]


def whois_ip(ip):
    if is_private(ip):
        return _("local network / private address")
    t = whois_raw("whois.iana.org", ip)
    m = re.search(r"^refer:\s*(\S+)", t, re.M)
    if m:
        t = whois_raw(m.group(1), ip) or t
    org = None
    for k in ORG_KEYS:
        mm = re.search(r"^" + re.escape(k) + r":\s*(.+)$", t, re.M | re.I)
        if mm and mm.group(1).strip():
            org = mm.group(1).strip()
            break
    cc = re.search(r"^country:\s*([A-Za-z]{2})\b", t, re.M | re.I)
    org = printable(org)[:120] if org else None
    if not org and not cc:
        return _("unknown (no whois answer)")
    return f"{org or '?'} ({cc.group(1).upper() if cc else '?'})"


def printable(t):
    """Text from the network made safe to show: control characters become spaces."""
    return "".join(ch if ch.isprintable() else " " for ch in str(t)).strip()


# ------------------------------------------------------------ /proc/net

def hexip(h):
    b = bytes.fromhex(h)
    if len(b) == 4:
        return socket.inet_ntop(socket.AF_INET, b[::-1])
    b = b"".join(b[i:i + 4][::-1] for i in range(0, 16, 4))
    ip = socket.inet_ntop(socket.AF_INET6, b)
    if ip.startswith("::ffff:") and "." in ip:
        ip = ip[7:]
    return ip


def proc_net(proto, root="/proc"):
    """Rows of /proc/net/{tcp,udp}{,6}: (local_ip, local_port, remote_ip, remote_port, state, uid, inode)."""
    out = []
    for f in (f"{root}/net/{proto}", f"{root}/net/{proto}6"):
        try:
            with open(f) as fh:
                lines = fh.read().splitlines()[1:]
        except OSError:
            continue
        for ln in lines:
            p = ln.split()
            if len(p) < 10:
                continue
            la, lp = p[1].rsplit(":", 1)
            ra, rp = p[2].rsplit(":", 1)
            out.append((la, int(lp, 16), ra, int(rp, 16), int(p[3], 16), int(p[7]), int(p[9])))
    return out


def find_socket(proto, direction, lport):
    """Socket owning a local port: (inode, uid) or None. For inbound TCP only listening sockets count."""
    best = None
    for _la, lp, _ra, _rp, st, uid, ino in proc_net(proto):
        if lp != lport or not ino:
            continue
        if proto == "tcp":
            if direction == "in":
                score = 2 if st == 0x0A else 0
            else:
                score = 2 if st == 0x02 else (1 if st != 0x0A else 0)
        else:
            score = 1
        if score and (best is None or score > best[0]):
            best = (score, ino, uid)
    return (best[1], best[2]) if best else None


# ------------------------------------------------------------ interfaces

IFACE_KINDS = ("wifi", "mobile", "ethernet", "vpn", "virtual", "loopback", "other")
_iface_cache = {}
_iface_lock = threading.Lock()


def iface_kind(name, sysfs="/sys/class/net"):
    """Kind of network: wifi, mobile (WWAN, cellular modems, PPP), ethernet, vpn, virtual, loopback."""
    if not name:
        return "other"
    base = f"{sysfs}/{name}"
    try:
        dtype = int(read(f"{base}/type").strip())
    except ValueError:
        dtype = None
    uevent = read(f"{base}/uevent")
    devtype = re.search(r"^DEVTYPE=(\S+)", uevent, re.M)
    devtype = devtype.group(1) if devtype else ""
    if dtype == 772 or name == "lo":
        return "loopback"
    if os.path.isdir(f"{base}/wireless") or os.path.exists(f"{base}/phy80211") or devtype == "wlan":
        return "wifi"
    if devtype == "wwan" or name.startswith(("wwan", "ww", "rmnet", "qmimux", "ppp")) or dtype in (512, 519, 530):
        return "mobile"
    if name.startswith(("tun", "tap", "wg", "vpn", "tailscale", "zt")) or devtype == "wireguard" or dtype == 65534:
        return "vpn"
    if devtype in ("bridge", "veth", "vlan", "bond") or name.startswith(("docker", "virbr", "veth", "br-", "vnet",
                                                                          "lxc", "podman", "cni")):
        return "virtual"
    if dtype == 1:
        return "ethernet"
    return "other"


def iface_info(index):
    """(name, kind) of an interface index, cached for 10 s."""
    if not index:
        return "", "other"
    now = time.monotonic()
    with _iface_lock:
        hit = _iface_cache.get(index)
        if hit and hit[2] > now:
            return hit[0], hit[1]
    try:
        name = socket.if_indextoname(index)
    except OSError:
        name = f"if{index}"
    kind = iface_kind(name)
    with _iface_lock:
        _iface_cache[index] = (name, kind, now + 10)
    return name, kind


def listening_ports():
    """Local TCP ports in LISTEN state and bound UDP ports."""
    tcp = {lp for _la, lp, _ra, _rp, st, _u, _i in proc_net("tcp") if st == 0x0A}
    udp = {lp for _la, lp, _ra, _rp, _st, _u, _i in proc_net("udp")}
    return tcp, udp
