# SPDX-License-Identifier: GPL-3.0-or-later
"""Firewall engine: holds every new connection until a rule or the user decides.

Failure policy (fail-closed):
* a packet that cannot be handled is dropped, never accepted;
* if a critical thread dies the process exits, systemd restarts it, and meanwhile the
  nftables table (loaded again by ExecStartPre from failsafe.nft) has no queue reader,
  so new connections are dropped by the kernel;
* if the table disappears (for example 'nft flush ruleset') it is loaded again;
* a state change (kill switch, pause) is recorded only after nftables applied it.
"""
import concurrent.futures
import ipaddress
import os
import signal
import subprocess
import threading
import time
import traceback

from . import _, paths
from .netutil import MARK, DnsCache, find_socket, hexip, iface_info, listening_ports, parse_ip, proc_net, whois_ip
from .nfqueue import NF_ACCEPT, NF_DROP, NFQueue
from .procinfo import Procs, describe, start_time
from .rules import Rules, validate
from .util import RateLimit, boot_id, is_public, load_json_checked, log, now_hms, save_json, sd_notify
from .watchdog import Watchdog

TABLE = "varco"
Q_CONN, Q_DNS = 4242, 4243
EXIT_FATAL = 70

DEFAULT_CONFIG = {
    "decision_timeout": 120,       # seconds a connection waits for a decision before being blocked
    "killswitch_auto": "off",      # off | in | in_out
    "whois": False,                # true = ask whois who owns each new address (sends it to the registries)
    "watchdog": True,              # report programs that start
    "log_allowed": False,          # true = the journal also keeps every allowed connection (browsing history)
    "allow_dhcp": True,
    "allow_icmpv6_essential": True,
    "max_pending": 100,            # more waiting requests than this are blocked at once (flood protection)
}
SETTABLE = {"decision_timeout": int, "killswitch_auto": str, "whois": bool, "watchdog": bool, "log_allowed": bool,
            "max_pending": int}

CHOICES = ("allow-always", "allow-network", "allow-port", "allow-app", "allow-once",
           "deny-once", "deny-always", "deny-kill", "killswitch")
# for a connection whose program is unknown ('?') only rules tied to one host and port make
# sense: a wildcard rule would let through everything that cannot be identified
CHOICES_UNKNOWN = ("allow-always", "allow-network", "allow-once", "deny-once", "deny-always", "killswitch")


def nft_ruleset(cfg, ks, paused):
    """Text of the nftables transaction for a given state. Loaded atomically by 'nft -f'."""
    drop_table = f"add table inet {TABLE}\ndelete table inet {TABLE}\n"
    if paused and not ks:
        return drop_table
    i, o = [], []
    if not ks:
        # answers of a resolver on this computer (systemd-resolved, dnsmasq, unbound): observed
        # to learn names, never delayed ('bypass')
        i.append(f'iif "lo" udp sport 53 queue num {Q_DNS} bypass')
    i.append('iif "lo" accept')
    o.append('oif "lo" accept')
    chains = []
    if ks:
        mode = "killswitch"
        i.append("counter drop")
        o.append("counter drop")
        # the kill switch also isolates virtual machines and containers routed by this computer
        chains.append(("forward", "forward", ["counter drop"]))
    else:
        mode = "filter"
        i.append(f"ct state established udp sport 53 queue num {Q_DNS} bypass")
        i.append("ct state established,related accept")
        i.append("ct state invalid drop")
        o.append("ct state established,related accept")
        o.append(f"meta mark {MARK:#x} accept")
        if cfg.get("allow_dhcp", True):
            i.append("udp sport 67 udp dport 68 accept")
            i.append("udp sport 547 udp dport 546 accept")
            o.append("udp sport 68 udp dport 67 accept")
            o.append("udp sport 546 udp dport 547 accept")
        if cfg.get("allow_icmpv6_essential", True):
            i.append("icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, "
                     "mld-listener-query } accept")
            o.append("icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, "
                     "mld2-listener-report } accept")
        # no 'bypass': without a reader the kernel drops the packets (fail-closed)
        i.append(f"queue num {Q_CONN}")
        o.append(f"queue num {Q_CONN}")
    chains = [("input", "input", i), ("output", "output", o)] + chains
    ind = "\n\t\t"
    body = "".join(
        f"\tchain {name} {{\n\t\ttype filter hook {hook} priority -10; policy accept;\n"
        f"\t\tcomment \"varco:{mode}\"{ind}{ind.join(rules)}\n\t}}\n"
        for name, hook, rules in chains)
    return drop_table + f"table inet {TABLE} {{\n{body}}}\n"


def ptrace_scope():
    """kernel.yama.ptrace_scope: 0 means any program can read and change the memory of the other
    programs of the same user, and so make an approved program connect for it."""
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def failsafe_ruleset():
    """Table loaded by ExecStartPre: normal filtering with no reader on the queue, so every
    new connection is dropped until the daemon is up and decides."""
    return "#!/usr/sbin/nft -f\n# Generated by Varco. Loaded before varcod starts (fail-closed).\n" + \
        nft_ruleset(DEFAULT_CONFIG, False, False)


class Core:
    def __init__(self, nfq=None):
        self.lock = threading.RLock()
        self.load_config()
        self.rules = Rules(paths.RULES)
        self.dns = DnsCache()
        self.procs = Procs()
        self.pending, self.pkey, self.flows, self.quiet = {}, {}, {}, {}
        self.next_req = 1
        self.events_lock = threading.Lock()
        self.events_buf = []
        self.seq = 0
        self.whois_cache = {}
        self.lookups = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="lookup")
        self.log_limit = RateLimit(30, 200)
        self.overload_until = 0.0
        self.listen = (0.0, set(), set())
        self.threads = {}
        self.started = False
        self.boot = boot_id()
        st = load_json_checked(paths.STATE, {}, dict)
        self.ks = bool(st.get("killswitch"))
        self.ks_reason = st.get("killswitch_reason", "")
        # a pause never survives a restart of the computer: protection comes back by itself
        self.paused = bool(st.get("paused")) and st.get("paused_boot") == self.boot
        if st.get("paused") and not self.paused:
            log("protection was paused before the restart: resumed")
        self.nfq = nfq if nfq is not None else NFQueue()
        self.watchdog = Watchdog(self.emit) if self.cfg.get("watchdog", True) else None

    # ------------------------------------------------------------ configuration and state
    def load_config(self):
        cfg = dict(DEFAULT_CONFIG)
        cfg.update(load_json_checked(paths.CONFIG_DEFAULTS, {}, dict))
        cfg.update(load_json_checked(paths.CONFIG_OVERRIDES, {}, dict))
        if cfg.get("killswitch_auto") not in ("off", "in", "in_out"):
            cfg["killswitch_auto"] = "off"
        try:
            cfg["max_pending"] = max(10, min(1000, int(cfg.get("max_pending", 100))))
            cfg["decision_timeout"] = max(10, min(3600, int(cfg.get("decision_timeout", 120))))
        except (TypeError, ValueError):
            cfg["max_pending"], cfg["decision_timeout"] = 100, 120
        self.cfg = cfg

    def set_setting(self, key, value):
        if key not in SETTABLE:
            return False, _("unknown setting")
        try:
            value = SETTABLE[key](value)
        except (TypeError, ValueError):
            return False, _("invalid value")
        if key == "killswitch_auto" and value not in ("off", "in", "in_out"):
            return False, _("invalid value")
        if key == "decision_timeout" and not 10 <= value <= 3600:
            return False, _("invalid value")
        if key == "max_pending" and not 10 <= value <= 1000:
            return False, _("invalid value")
        with self.lock:
            ov = load_json_checked(paths.CONFIG_OVERRIDES, {}, dict)
            ov[key] = value
            save_json(paths.CONFIG_OVERRIDES, ov)
            self.cfg[key] = value
        return True, _("setting saved")

    def save_state(self):
        save_json(paths.STATE, {"killswitch": self.ks, "killswitch_reason": self.ks_reason,
                                "paused": self.paused, "paused_boot": self.boot if self.paused else None})

    # ------------------------------------------------------------ events
    def emit(self, ev):
        with self.events_lock:
            self.seq += 1
            ev["seq"] = self.seq
            self.events_buf.append(ev)
            if len(self.events_buf) > 3000:
                del self.events_buf[:1000]

    def events(self, since):
        with self.events_lock:
            if since > self.seq:          # the service restarted: the client starts over
                since = 0
            return self.seq, [e for e in self.events_buf if e["seq"] > since]

    def activity(self, c, verdict, reason, rule_id=None):
        if verdict == "allowed" and not self.cfg.get("log_allowed"):
            return
        if verdict != "pending" and not self.log_limit.allow():
            return   # flood: counted, summarized by housekeeping
        name = c["names"][0] if c.get("names") else ""
        log(f"{verdict.upper():8} {c['dir'].upper():3} {c['app']} (pid {c.get('pid') or '?'}) "
            f"{'->' if c['dir'] == 'out' else '<-'} {c['remote']}{' [' + name + ']' if name else ''} "
            f"port {c['port']}/{c['proto']} via {c.get('iface') or '?'} - {reason}"
            + (f" #{rule_id}" if rule_id else ""))
        self.emit({"ev": "activity", "ts": now_hms(), "verdict": verdict, "reason": reason, "rule": rule_id,
                   "c": {k: c.get(k) for k in ("dir", "app", "exe", "remote", "names", "port", "proto", "pid",
                                               "user", "iface", "iface_kind")}})

    # ------------------------------------------------------------ nftables
    def nft_text(self, ks=None, paused=None):
        return nft_ruleset(self.cfg, self.ks if ks is None else ks, self.paused if paused is None else paused)

    def apply_nft(self, ks=None, paused=None):
        r = subprocess.run([paths.NFT, "-f", "-"], input=self.nft_text(ks, paused), text=True,
                           capture_output=True, timeout=20)
        if r.returncode:
            raise RuntimeError("nft: " + r.stderr.strip())

    def table_ok(self):
        """True if the table in the kernel is the one this state needs."""
        r = subprocess.run([paths.NFT, "list", "table", "inet", TABLE], text=True, capture_output=True, timeout=20)
        if self.paused and not self.ks:
            return r.returncode != 0
        if r.returncode:
            return False
        mode = "killswitch" if self.ks else "filter"
        return f'"varco:{mode}"' in r.stdout and (self.ks or f"queue num {Q_CONN}" in r.stdout)

    def check_table(self):
        try:
            if self.table_ok():
                return
        except (OSError, subprocess.SubprocessError) as e:
            log(f"cannot check the nftables table: {e}")
            return
        log("WARNING: the nftables table was removed or changed by another program (for example "
            "'nft flush ruleset'): loading it again")
        with self.lock:
            self.apply_nft()
        self.emit({"ev": "tamper", "ts": now_hms()})

    # ------------------------------------------------------------ packets
    def drop_on_error(self, q, pktid):
        try:
            self.nfq.verdict(q, pktid, NF_DROP)
        except OSError as e:
            self.fatal(f"cannot send verdicts to the kernel: {e}")

    def on_packet(self, q, pktid, hook, payload, uid, indev=None, outdev=None):
        if q == Q_DNS:
            try:
                pk = parse_ip(payload)
                if pk and pk["proto"] == "udp":
                    self.dns.feed(payload[pk["off"] + 8:], pk["src"])
            except Exception:  # noqa: BLE001 - DNS observation must never block DNS
                pass
            self.send_verdict(q, pktid, NF_ACCEPT)
            return
        try:
            v = self.decide_packet(pktid, hook, payload, uid, indev, outdev)
        except Exception:  # noqa: BLE001
            log("internal error, packet dropped:\n" + traceback.format_exc())
            v = NF_DROP
        if v is not None:
            self.send_verdict(q, pktid, v)

    def send_verdict(self, q, pktid, v):
        try:
            self.nfq.verdict(q, pktid, v)
        except OSError as e:
            # a lost verdict leaves the packet stuck in the queue: restart cleanly instead
            self.fatal(f"cannot send verdicts to the kernel: {e}")

    def listening(self, proto, port):
        now = time.monotonic()
        t, tcp, udp = self.listen
        if now - t > 1.0:
            tcp, udp = listening_ports()
            self.listen = (now, tcp, udp)
        return port in (tcp if proto == "tcp" else udp)

    def identify(self, d, proto, local, lport, remote, rport, uid, ifindex):
        sk = find_socket(proto, d, lport) if proto in ("tcp", "udp") and lport else None
        pids = []
        if sk:
            pids = self.procs.owners(sk[0])
            if uid is None:
                uid = sk[1]
        iface, kind = iface_info(ifindex)
        c = {"dir": d, "proto": proto, "local": local, "lport": lport, "remote": remote, "rport": rport,
             "port": (rport if d == "out" else lport) or 0, "listening": bool(sk),
             "names": self.dns.names(remote), "iface": iface, "iface_kind": kind, "shared": []}
        c.update(describe(pids[0] if pids else None, uid))
        if len(pids) > 1:
            # the socket is held by several processes (inherited or passed): if they are different
            # programs nobody can tell which one sends, so no program rule may apply
            apps = {c["app"]}
            for p in pids[1:8]:
                apps.add(describe(p, uid)["app"])
            apps.discard("?")
            if len(apps) > 1:
                c["shared"] = sorted(apps)
                c["app"] = "?"
        return c

    def decide_packet(self, pktid, hook, payload, uid, indev=None, outdev=None):
        pk = parse_ip(payload)
        if not pk:
            return NF_DROP
        d = "out" if hook == 3 else "in"
        if d == "out":
            local, lport, remote, rport, ifindex = pk["src"], pk["sport"], pk["dst"], pk["dport"], outdev
        else:
            local, lport, remote, rport, ifindex = pk["dst"], pk["dport"], pk["src"], pk["sport"], indev
        fk = (d, pk["proto"], local, lport, remote, rport)
        now = time.monotonic()
        with self.lock:
            if self.ks:
                return NF_DROP
            if self.paused:
                return NF_ACCEPT
            f = self.flows.get(fk)
            if f and f[1] > now:
                return f[0]
        # inbound to a port where nothing listens (scans, floods): drop without further work
        if d == "in" and pk["proto"] in ("tcp", "udp") and lport and not self.listening(pk["proto"], lport):
            with self.lock:
                self.flows[fk] = (NF_DROP, now + 30)
            if self.log_limit.allow():
                iface, kind = iface_info(ifindex)
                self.activity({"dir": d, "app": "?", "remote": remote, "names": [], "port": lport,
                               "proto": pk["proto"], "iface": iface, "iface_kind": kind}, "blocked", "closed-port")
            return NF_DROP
        c = self.identify(d, pk["proto"], local, lport, remote, rport, uid, ifindex)
        with self.lock:
            if self.ks:
                return NF_DROP
            r = self.rules.match(c)
            if r:
                v = NF_ACCEPT if r.get("action") == "allow" else NF_DROP
                self.flows[fk] = (v, now + 120)
                self.activity(c, "allowed" if v else "blocked", "rule", r["id"])
                return v
            gk = (d, c["app"], c["proto"], remote, c["port"], c["iface_kind"])
            if self.quiet.get(gk, 0) > now:
                return NF_DROP
            if d == "in" and not c["listening"]:
                self.flows[fk] = (NF_DROP, now + 30)
                self.activity(c, "blocked", "closed-port")
                return NF_DROP
            rid = self.pkey.get(gk)
            if rid in self.pending:
                req = self.pending[rid]
                req["flows"].add(fk)
                if len(req["pkts"]) < 64:
                    req["pkts"].append(pktid)
                    return None
                return NF_DROP
            if len(self.pending) >= self.cfg["max_pending"]:
                # flood protection: too many open questions, block and tell the user once
                self.quiet[gk] = now + 30
                self.activity(c, "blocked", "overload")
                if now > self.overload_until:
                    self.overload_until = now + 10
                    self.emit({"ev": "overload", "ts": now_hms(), "pending": len(self.pending)})
                return NF_DROP
            rid = self.next_req
            self.next_req += 1
            req = {"id": rid, "c": c, "pkts": [pktid], "flows": {fk}, "gk": gk, "t": now,
                   "ts": now_hms(), "deadline": time.time() + self.cfg["decision_timeout"],
                   "who": None, "ptr": [], "what": ""}
            self.pending[rid] = req
            self.pkey[gk] = rid
            self.emit(self.request_event(req))
            self.activity(c, "pending", "request", rid)
            self.lookups.submit(self.lookup, rid, remote)
            mode = self.cfg.get("killswitch_auto", "off")
            if is_public(remote) and ((d == "in" and mode in ("in", "in_out")) or (d == "out" and mode == "in_out")):
                try:
                    self.set_killswitch(True, ("auto-in" if d == "in" else "auto-out") + f":{rid}:{remote}")
                except RuntimeError as e:
                    log(f"automatic kill switch failed: {e}")
            return None

    @staticmethod
    def request_event(req):
        return {"ev": "request", "id": req["id"], "ts": req["ts"], "deadline": req["deadline"], "c": req["c"],
                "who": req["who"], "ptr": req["ptr"], "what": req["what"]}

    def lookup(self, rid, ip):
        try:
            with self.lock:
                req = self.pending.get(rid)
                c = req["c"] if req else None
            if not c:
                return
            what = ""
            if self.watchdog and c["exe"] != "?":
                what = self.watchdog.dpkg.explain(c["exe"], c.get("script", ""))
            ptr, who = [], None          # reverse DNS is no longer queried: it only leaked addresses
            if self.cfg.get("whois"):
                hit = self.whois_cache.get(ip)
                if hit and time.monotonic() - hit[1] < 86400:
                    who = hit[0]
                else:
                    who = whois_ip(ip)
                    if len(self.whois_cache) > 5000:
                        self.whois_cache.clear()
                    self.whois_cache[ip] = (who, time.monotonic())
            with self.lock:
                req = self.pending.get(rid)
                if req:
                    req["who"], req["ptr"], req["what"] = who, ptr, what
            self.emit({"ev": "info", "id": rid, "who": who, "ptr": ptr, "what": what})
        except Exception:  # noqa: BLE001 - lookups are best effort
            log("lookup error:\n" + traceback.format_exc())

    def resolve(self, req, v, ttl):
        now = time.monotonic()
        pkts, req["pkts"] = req["pkts"], []
        for p in pkts:
            self.send_verdict(Q_CONN, p, v)
        for fk in req["flows"]:
            self.flows[fk] = (v, now + ttl)

    def _close(self, req, verdict, reason, rule_id=None, extra=None):
        ev = {"ev": "decided", "id": req["id"], "verdict": verdict, "reason": reason, "rule": rule_id}
        ev.update(extra or {})
        self.emit(ev)

    def decide(self, rid, choice, caller_uid=None):
        """Apply a user decision. caller_uid limits 'deny-kill' to the caller's own processes."""
        if choice not in CHOICES:
            return {"ok": False, "message": _("invalid choice")}
        with self.lock:
            req = self.pending.get(rid)
            if not req:
                return {"ok": False, "message": _("request #{id} not found (already decided or expired)").format(id=rid)}
            if req["c"]["app"] == "?" and choice not in CHOICES_UNKNOWN:
                return {"ok": False, "message": _("unknown program: only a rule for this host and port, or a "
                                                  "decision for this time, is possible")}
            del self.pending[rid]
            self.pkey.pop(req["gk"], None)
            c = req["c"]
            host = c["names"][0] if c["names"] else c["remote"]
            base = {"dir": c["dir"], "app": c["app"], "proto": c["proto"], "iface": "*", "note": f"request #{rid}"}
            rule = None
            if choice == "allow-always":
                rule = base | {"host": host, "port": c["port"], "action": "allow"}
            elif choice == "allow-network":
                kind = c.get("iface_kind", "other")
                rule = base | {"host": host, "port": c["port"], "action": "allow",
                               "iface": "*" if kind in ("other", "loopback") else "@" + kind}
            elif choice == "allow-port":
                rule = base | {"host": "*", "port": c["port"], "action": "allow"}
            elif choice == "allow-app":
                rule = base | {"proto": "*", "host": "*", "port": "*", "action": "allow"}
            elif choice == "deny-always":
                rule = base | {"host": host, "port": c["port"], "action": "deny"}
            allow = choice.startswith("allow")
            v = NF_ACCEPT if allow else NF_DROP
            if rule:
                rule = self.rules.add(rule)
            self.resolve(req, v, 300 if choice == "allow-once" else 120)
            if choice == "deny-once":
                self.quiet[req["gk"]] = time.monotonic() + 60
            extra, message = {}, (_("#{id}: allowed") if allow else _("#{id}: blocked")).format(id=rid)
            if rule:
                message += " · " + _("rule #{n} created").format(n=rule["id"])
            if choice == "deny-kill":
                pid = c.get("pid")
                ok, kmsg = self.kill(pid, caller_uid, c.get("start"))
                extra["killed"] = pid if ok else None
                message += " · " + kmsg
            self.activity(c, "allowed" if allow else "blocked", "user")
            self._close(req, "allowed" if allow else "blocked", "user", rule["id"] if rule else None, extra)
            if rule:
                self._apply_rules_to_pending()
        if choice == "killswitch":
            try:
                self.set_killswitch(True, f"user:{rid}")
                message += " · " + _("computer isolated")
            except RuntimeError as e:
                return {"ok": False, "message": _("kill switch could not be applied: {err}").format(err=e)}
        return {"ok": True, "message": message, "rule": rule["id"] if rule else None}

    def _apply_rules_to_pending(self):
        for oid, oreq in list(self.pending.items()):
            r = self.rules.match(oreq["c"])
            if r:
                del self.pending[oid]
                self.pkey.pop(oreq["gk"], None)
                ov = NF_ACCEPT if r.get("action") == "allow" else NF_DROP
                self.resolve(oreq, ov, 120)
                self._close(oreq, "allowed" if ov else "blocked", "rule", r["id"])

    def kill(self, pid, caller_uid=None, start=None):
        """Terminate a process. With 'start' (its start time) a different process that got the
        same pid in the meantime is never touched. A pidfd closes the remaining race."""
        if not pid or pid <= 1 or pid == os.getpid():
            return False, _("invalid process")
        try:
            fd = os.pidfd_open(pid)
        except (AttributeError, OSError) as e:
            if isinstance(e, ProcessLookupError):
                return False, _("process {pid} no longer exists").format(pid=pid)
            fd = None
        try:
            try:
                owner = os.stat(f"/proc/{pid}").st_uid
            except OSError:
                return False, _("process {pid} no longer exists").format(pid=pid)
            if start is not None and start_time(pid) != start:
                return False, _("process {pid} already ended (the number now belongs to another program): "
                                "nothing was terminated").format(pid=pid)
            if caller_uid not in (None, 0) and owner != caller_uid:
                return False, _("process {pid} belongs to another user: administrator password required").format(
                    pid=pid)
            try:
                if fd is not None:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                else:
                    os.kill(pid, signal.SIGKILL)
                return True, _("process {pid} terminated").format(pid=pid)
            except OSError as e:
                return False, _("cannot terminate {pid}: {err}").format(pid=pid, err=e.strerror)
        finally:
            if fd is not None:
                os.close(fd)

    def set_killswitch(self, on, reason=""):
        """Apply first, record after: if nftables fails nothing changes and the error is raised."""
        with self.lock:
            self.apply_nft(ks=on, paused=self.paused)
            self.ks = on
            self.ks_reason = reason if on else ""
            self.save_state()
            if on:
                # every waiting request is blocked AND closed: nothing stale stays in the interfaces
                for req in list(self.pending.values()):
                    self.resolve(req, NF_DROP, 5)
                    self._close(req, "blocked", "killswitch")
                self.pending.clear()
                self.pkey.clear()
                self.flows.clear()
        log(("KILL SWITCH ON: " + reason) if on else "kill switch off")
        self.emit({"ev": "killswitch", "on": on, "reason": self.ks_reason})

    def set_paused(self, on):
        with self.lock:
            self.apply_nft(ks=self.ks, paused=on)
            self.paused = on
            self.save_state()
            if on:
                for req in list(self.pending.values()):
                    self.resolve(req, NF_ACCEPT, 5)
                    self._close(req, "allowed", "paused")
                self.pending.clear()
                self.pkey.clear()
            self.flows.clear()
        log("PROTECTION PAUSED until resumed or until the computer restarts" if on else "protection resumed")
        self.emit({"ev": "paused", "on": on})

    # ------------------------------------------------------------ housekeeping and supervision
    def housekeeping_once(self, tick):
        now = time.monotonic()
        with self.lock:
            for rid, req in list(self.pending.items()):
                if time.time() > req["deadline"]:
                    del self.pending[rid]
                    self.pkey.pop(req["gk"], None)
                    self.resolve(req, NF_DROP, 5)
                    self.quiet[req["gk"]] = now + 30
                    self.activity(req["c"], "blocked", "timeout")
                    self._close(req, "blocked", "timeout")
            if len(self.flows) > 20000 or tick % 30 == 0:
                self.flows = {k: v for k, v in self.flows.items() if v[1] > now}
                self.quiet = {k: v for k, v in self.quiet.items() if v > now}
        n = self.log_limit.take_suppressed()
        if n:
            log(f"{n} log entries suppressed (too many connections per second)")
        if tick % 5 == 0:
            self.check_table()
        if self.watchdog and tick % 10 == 0:
            try:
                self.watchdog.save()
            except OSError as e:
                log(f"cannot save the list of known programs: {e}")

    def housekeeping(self):
        tick = 0
        while True:
            time.sleep(1)
            tick += 1
            self.housekeeping_once(tick)
            if all(t.is_alive() for t in self.threads.values()):
                sd_notify("WATCHDOG=1")    # systemd restarts the service if this stops

    def fatal(self, why):
        log(f"FATAL: {why}. Exiting: systemd restarts the service; new connections stay blocked meanwhile.")
        os._exit(EXIT_FATAL)

    def spawn(self, name, target, *args):
        def run():
            try:
                target(*args)
                self.fatal(f"thread {name} ended")
            except Exception:  # noqa: BLE001
                log(traceback.format_exc())
                self.fatal(f"thread {name} crashed")
        t = threading.Thread(target=run, daemon=True, name=name)
        self.threads[name] = t
        t.start()
        return t

    # ------------------------------------------------------------ queries
    def state(self):
        with self.lock:
            return {"killswitch": self.ks, "killswitch_reason": self.ks_reason, "paused": self.paused,
                    "pending": len(self.pending), "rules": len(self.rules.list), "settings": self.cfg,
                    "known_programs": len(self.watchdog.seen) if self.watchdog else 0,
                    "watchdog_running": bool(self.watchdog and self.watchdog.running()),
                    "invalid_rules": len(self.rules.invalid),
                    "ptrace_scope": ptrace_scope(),
                    "version": __import__("varco").VERSION}

    def pending_list(self):
        with self.lock:
            return [self.request_event(r) for r in self.pending.values()]

    def add_rule(self, r):
        if not isinstance(r, dict):
            return {"ok": False, "message": "invalid rule"}
        err = validate(r)
        if err:
            return {"ok": False, "message": err}
        with self.lock:
            rr = self.rules.add(r)
            self.flows.clear()
            self._apply_rules_to_pending()
        return {"ok": True, "message": _("rule #{n} added").format(n=rr["id"]), "rule": rr["id"]}

    def remove_rule(self, rid):
        with self.lock:
            ok = self.rules.remove(rid)
            self.flows.clear()
        return {"ok": ok, "message": _("rule removed") if ok else _("rule not found")}

    def connections(self):
        inode_pid = self.procs.scan()
        out, cache = [], {}
        for proto in ("tcp", "udp"):
            for la, lp, ra, rp, st, uid, ino in proc_net(proto):
                lip, rip = hexip(la), hexip(ra)
                listening = (proto == "tcp" and st == 0x0A) or (proto == "udp" and st == 0x07 and rp == 0)
                if listening:
                    if ipaddress.ip_address(lip).is_loopback:
                        continue
                    kind = "listening"
                elif st == 0x01:
                    if ipaddress.ip_address(rip).is_loopback:
                        continue
                    kind = "connected"
                else:
                    continue
                pid = (inode_pid.get(ino) or [None])[0]
                if pid not in cache:
                    cache[pid] = describe(pid, uid)
                info = cache[pid]
                out.append({"kind": kind, "proto": proto, "local": f"{lip}:{lp}",
                            "remote": "" if listening else f"{rip}:{rp}",
                            "names": [] if listening else self.dns.names(rip),
                            "pid": pid, "app": info["app"], "user": info["user"], "unit": info["unit"]})
        return out

    def reload(self):
        with self.lock:
            self.load_config()
            self.rules.load()
            self.flows.clear()
            self.apply_nft()

    # ------------------------------------------------------------ start
    def start(self):
        self.nfq.bind(Q_CONN, 256)
        self.nfq.bind(Q_DNS, 4096)
        self.apply_nft()                     # replaces the failsafe table loaded by ExecStartPre
        self.spawn("nfqueue", self.nfq.loop, self.on_packet, self.drop_on_error)
        self.spawn("housekeeping", self.housekeeping)
        if self.watchdog:
            self.watchdog.start()
        self.started = True
        state = "PAUSED" if self.paused else ("KILL SWITCH ON" if self.ks else "active")
        log(f"Varco running ({state}). Rules: {len(self.rules.list)}. "
            f"Automatic kill switch: {self.cfg.get('killswitch_auto')}")
        sd_notify(f"READY=1\nSTATUS=protection {state}")
