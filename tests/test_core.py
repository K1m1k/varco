# SPDX-License-Identifier: GPL-3.0-or-later
"""Engine tests, including the failure scenarios: the firewall must stay closed."""
import errno
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest

TMP = tempfile.mkdtemp()
os.environ["VARCO_ETC"] = os.path.join(TMP, "etc")
os.environ["VARCO_VAR"] = os.path.join(TMP, "var")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from varco import core, netutil, nfqueue, paths, procinfo, rules  # noqa: E402


class FakeQ:
    def __init__(self):
        self.v = []
        self.fail = False

    def verdict(self, q, p, v):
        if self.fail:
            raise OSError(errno.EPERM, "netlink gone")
        self.v.append((p, v))


class Fatal(Exception):
    pass


def dns_name(n):
    return b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\0"


def ipv4(src, dst, proto, sport, dport):
    return (bytes([0x45, 0, 0, 40, 0, 0, 0, 0, 64, proto, 0, 0]) + socket.inet_aton(src) + socket.inet_aton(dst)
            + struct.pack("!HH", sport, dport) + b"\0" * 16)


class TestParsing(unittest.TestCase):
    def test_ipv4(self):
        p = netutil.parse_ip(ipv4("192.168.1.10", "93.184.216.34", 6, 51000, 443))
        self.assertEqual((p["proto"], p["src"], p["dst"], p["sport"], p["dport"]),
                         ("tcp", "192.168.1.10", "93.184.216.34", 51000, 443))

    def test_ipv6(self):
        pkt = (bytes([0x60, 0, 0, 0, 0, 20, 6, 64]) + socket.inet_pton(socket.AF_INET6, "2001:db8::1")
               + socket.inet_pton(socket.AF_INET6, "2a00:1450::5") + struct.pack("!HH", 40000, 80) + b"\0" * 16)
        p = netutil.parse_ip(pkt)
        self.assertEqual((p["src"], p["dport"]), ("2001:db8::1", 80))

    def test_garbage_is_rejected(self):
        self.assertIsNone(netutil.parse_ip(b"\x00" * 10))
        self.assertIsNone(netutil.parse_ip(b"\x70" + b"\x00" * 50))

    def test_dns_cname_and_ttl(self):
        m = struct.pack("!HHHHHH", 1, 0x8180, 1, 2, 0, 0) + dns_name("www.example.com") + struct.pack("!HH", 1, 1)
        m += b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(dns_name("edge.cdn.net"))) + dns_name("edge.cdn.net")
        m += dns_name("edge.cdn.net") + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
        d = netutil.DnsCache(trusted=lambda: {"192.0.2.53"})
        d.feed(m, "192.0.2.53")
        self.assertEqual(d.names("93.184.216.34"), ["www.example.com", "edge.cdn.net"])
        real = netutil.time.monotonic
        netutil.time.monotonic = lambda: real() + 61
        try:
            self.assertEqual(d.names("93.184.216.34"), [])
        finally:
            netutil.time.monotonic = real

    def test_dns_pointer_loop_is_rejected(self):
        m = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c"
        with self.assertRaises(ValueError):
            netutil.parse_dns(m)

    def test_hexip(self):
        self.assertEqual(netutil.hexip("0100007F"), "127.0.0.1")
        self.assertEqual(netutil.hexip("0000000000000000FFFF00000100007F"), "127.0.0.1")

    def test_iface_kind(self):
        root = tempfile.mkdtemp()
        for name, files in {"wlp2s0": {"type": "1", "uevent": "DEVTYPE=wlan\n"},
                            "wwan0": {"type": "519", "uevent": "DEVTYPE=wwan\n"},
                            "enp1s0": {"type": "1", "uevent": ""},
                            "wg0": {"type": "65534", "uevent": "DEVTYPE=wireguard\n"},
                            "ppp0": {"type": "512", "uevent": ""}}.items():
            os.makedirs(f"{root}/{name}")
            for f, v in files.items():
                with open(f"{root}/{name}/{f}", "w") as fh:
                    fh.write(v)
        kinds = {n: netutil.iface_kind(n, root) for n in os.listdir(root)}
        self.assertEqual(kinds, {"wlp2s0": "wifi", "wwan0": "mobile", "enp1s0": "ethernet", "wg0": "vpn",
                                 "ppp0": "mobile"})


class TestNetlinkParsing(unittest.TestCase):
    def packet_msg(self, q, pktid, hook, payload, indev=None, outdev=None):
        a = nfqueue.NFQueue.attr
        attrs = a(nfqueue.NFQA_PACKET_HDR, struct.pack("!IHB", pktid, 0x0800, hook) + b"\0")
        if indev:
            attrs += a(nfqueue.NFQA_IFINDEX_INDEV, struct.pack("!I", indev))
        if outdev:
            attrs += a(nfqueue.NFQA_IFINDEX_OUTDEV, struct.pack("!I", outdev))
        attrs += a(nfqueue.NFQA_PAYLOAD, payload)
        body = struct.pack("=BB", 0, 0) + struct.pack("!H", q) + attrs
        return struct.pack("=IHHII", 16 + len(body), 3 << 8, 0, 1, 0) + body

    def test_parse_two_messages(self):
        data = self.packet_msg(4242, 7, 3, b"x" * 40, outdev=3) + self.packet_msg(4242, 8, 1, b"y" * 40, indev=2)
        got = list(nfqueue.NFQueue.parse(data))
        self.assertEqual([(g[1], g[2], g[5], g[6]) for g in got], [(7, 3, None, 3), (8, 1, 2, None)])

    def test_truncated_message_does_not_crash(self):
        data = self.packet_msg(4242, 7, 3, b"x" * 40)
        list(nfqueue.NFQueue.parse(data[:30]))
        list(nfqueue.NFQueue.parse(b"\xff" * 64))

    def test_loop_survives_callback_errors(self):
        q = nfqueue.NFQueue.__new__(nfqueue.NFQueue)
        msgs = [self.packet_msg(4242, 1, 3, b"x" * 40), self.packet_msg(4242, 2, 3, b"x" * 40)]

        class Sock:
            def recv(self, n):
                if msgs:
                    return msgs.pop(0)
                raise SystemExit
        q.s = Sock()
        dropped = []

        def cb(*a):
            raise ValueError("bug")
        with self.assertRaises(SystemExit):
            q.loop(cb, lambda qq, p: dropped.append(p))
        self.assertEqual(dropped, [1, 2])     # both packets dropped, loop kept running


class TestIdentity(unittest.TestCase):
    def test_inline_code_is_hashed(self):
        a = procinfo.app_identity("/usr/bin/python3.13", ["python3", "-c", "print(1)"], "/")
        b = procinfo.app_identity("/usr/bin/python3.13", ["python3", "-c", "print(2)"], "/")
        self.assertNotEqual(a, b)
        self.assertIn("sha256:", a)

    def test_shell_combined_flags(self):
        self.assertIn("sha256:", procinfo.app_identity("/usr/bin/bash", ["bash", "-lc", "curl x"], "/"))

    def test_script_and_stdin(self):
        self.assertEqual(procinfo.app_identity("/usr/bin/python3.13", ["python3", "s.py"], "/home/k"),
                         "/usr/bin/python3.13 /home/k/s.py")
        self.assertTrue(procinfo.app_identity("/usr/bin/bash", ["bash"], "/").endswith("(stdin)"))
        self.assertEqual(procinfo.app_identity("/usr/bin/curl", ["curl", "x"], "/"), "/usr/bin/curl")

    def test_suspicious(self):
        self.assertEqual(len(procinfo.suspicious("/tmp/kworker", "kworker", 1000)), 2)
        self.assertEqual(procinfo.suspicious("/usr/bin/true", "true", 1000), [])


class TestRules(unittest.TestCase):
    c = {"dir": "out", "app": "/usr/bin/curl", "proto": "tcp", "port": 443, "remote": "93.184.216.34",
         "names": ["www.example.com"], "iface": "wwan0", "iface_kind": "mobile"}

    def test_match(self):
        self.assertTrue(rules.rule_match({"dir": "out", "app": "/usr/bin/curl", "proto": "tcp",
                                          "host": "*.example.com", "port": 443}, self.c))
        self.assertTrue(rules.rule_match({"dir": "*", "app": "*", "proto": "*", "host": "93.184.0.0/16",
                                          "port": "*"}, self.c))
        self.assertFalse(rules.rule_match({"dir": "in", "app": "*", "proto": "*", "host": "*", "port": "*"}, self.c))

    def test_network_match(self):
        base = {"dir": "*", "app": "*", "proto": "*", "host": "*", "port": "*"}
        self.assertTrue(rules.rule_match(base | {"iface": "@mobile"}, self.c))
        self.assertFalse(rules.rule_match(base | {"iface": "@wifi"}, self.c))
        self.assertTrue(rules.rule_match(base | {"iface": "wwan*"}, self.c))
        self.assertTrue(rules.rule_match(base, self.c))          # old rules without iface: any network

    def test_validate(self):
        ok = {"dir": "out", "app": "*", "proto": "tcp", "host": "*", "port": 80, "action": "allow"}
        self.assertIsNone(rules.validate(ok))
        self.assertIsNotNone(rules.validate(ok | {"port": 99999}))
        self.assertIsNotNone(rules.validate(ok | {"iface": "@moon"}))
        self.assertIsNotNone(rules.validate(ok | {"iface": "wlan0; drop"}))
        self.assertIsNone(rules.validate(ok | {"iface": "@wifi"}))


class Base(unittest.TestCase):
    def setUp(self):
        os.makedirs(paths.VAR, exist_ok=True)
        for f in os.listdir(paths.VAR):
            os.remove(os.path.join(paths.VAR, f))
        self.core = self.make()

    def make(self):
        c = core.Core(nfq=FakeQ())
        c.applied = []
        c.apply_nft = lambda ks=None, paused=None: c.applied.append((ks, paused))
        c.cfg["whois"] = False
        c.watchdog = None
        c.fatal = self.fatal
        return c

    @staticmethod
    def fatal(why):
        raise Fatal(why)

    def connecting_socket(self, dst="10.255.255.1"):
        cl = socket.socket()
        cl.setblocking(False)
        try:
            cl.connect((dst, 443))
        except BlockingIOError:
            pass
        self.addCleanup(cl.close)
        return ipv4(cl.getsockname()[0], dst, 6, cl.getsockname()[1], 443)

    def listening_socket(self):
        srv = socket.socket()
        srv.bind(("0.0.0.0", 0))
        srv.listen()
        self.addCleanup(srv.close)
        return srv.getsockname()[1]


class TestEngine(Base):
    def test_hold_then_allow_always(self):
        pkt = self.connecting_socket()
        self.core.on_packet(core.Q_CONN, 100, 3, pkt, os.getuid())
        self.core.on_packet(core.Q_CONN, 101, 3, pkt, os.getuid())
        self.assertEqual(self.core.nfq.v, [])
        res = self.core.decide(1, "allow-always")
        self.assertTrue(res["ok"])
        self.assertEqual(self.core.nfq.v, [(100, 1), (101, 1)])
        self.core.flows.clear()
        self.core.on_packet(core.Q_CONN, 102, 3, pkt, os.getuid())
        self.assertEqual(self.core.nfq.v[-1], (102, 1))

    def test_allow_only_on_this_network(self):
        self.core.on_packet(core.Q_CONN, 1, 3, self.connecting_socket(), 0, None, 1)
        self.core.pending[1]["c"]["iface_kind"] = "wifi"
        self.core.decide(1, "allow-network")
        self.assertEqual(self.core.rules.list[-1]["iface"], "@wifi")
        self.core.on_packet(core.Q_CONN, 2, 3, self.connecting_socket("10.255.255.9"), 0)
        self.core.pending[2]["c"]["iface_kind"] = "other"
        self.core.decide(2, "allow-network")                    # unknown network type: any network
        self.assertEqual(self.core.rules.list[-1]["iface"], "*")

    def test_garbage_packet_is_dropped(self):
        self.core.on_packet(core.Q_CONN, 5, 3, b"\x00" * 10, 0)
        self.assertEqual(self.core.nfq.v[-1], (5, 0))

    def test_inbound_closed_port_fast_drop(self):
        self.core.on_packet(core.Q_CONN, 200, 1, ipv4("8.8.8.8", "10.0.0.2", 6, 5555, 1), None)
        self.assertEqual(self.core.nfq.v[-1], (200, 0))
        self.assertEqual(self.core.pending, {})

    def test_auto_killswitch_only_when_enabled(self):
        port = self.listening_socket()
        self.core.on_packet(core.Q_CONN, 201, 1, ipv4("8.8.8.8", "10.0.0.2", 6, 5555, port), None)
        self.assertFalse(self.core.ks)                 # default: off
        self.core.cfg["killswitch_auto"] = "in"
        self.core.on_packet(core.Q_CONN, 202, 1, ipv4("8.8.4.4", "10.0.0.2", 6, 5556, port), None)
        self.assertTrue(self.core.ks)
        self.core.on_packet(core.Q_CONN, 203, 3, self.connecting_socket(), 0)
        self.assertEqual(self.core.nfq.v[-1], (203, 0))

    def test_killswitch_closes_waiting_requests(self):
        self.core.on_packet(core.Q_CONN, 1, 3, self.connecting_socket(), 0)
        self.core.on_packet(core.Q_CONN, 2, 3, self.connecting_socket("10.255.255.2"), 0)
        self.assertEqual(len(self.core.pending), 2)
        self.core.set_killswitch(True, "manual")
        self.assertEqual(self.core.pending, {})
        self.assertEqual(self.core.pkey, {})
        self.assertEqual(sorted(self.core.nfq.v), [(1, 0), (2, 0)])
        closed = [e for e in self.core.events(0)[1] if e["ev"] == "decided"]
        self.assertEqual(sorted(e["id"] for e in closed), [1, 2])
        self.assertTrue(all(e["reason"] == "killswitch" for e in closed))
        self.assertEqual(self.core.decide(1, "allow-always")["ok"], False)

    def test_killswitch_isolates_forwarded_traffic(self):
        t = core.nft_ruleset(core.DEFAULT_CONFIG, True, False)
        self.assertIn("hook forward", t)
        self.assertNotIn("queue", t)
        self.assertNotIn("established", t)            # open connections are cut too

    def test_failsafe_table_blocks_without_reader(self):
        t = core.failsafe_ruleset()
        self.assertIn(f"queue num {core.Q_CONN}\n", t)
        self.assertNotIn(f"queue num {core.Q_CONN} bypass", t)
        self.assertIn(core.nft_ruleset(core.DEFAULT_CONFIG, False, False), t)

    def test_pause_lets_everything_through(self):
        self.core.set_paused(True)
        self.core.on_packet(core.Q_CONN, 300, 3, self.connecting_socket(), 0)
        self.assertEqual(self.core.nfq.v[-1], (300, 1))
        self.assertNotIn("queue", self.core.nft_text())

    def test_pause_does_not_survive_reboot(self):
        self.core.set_paused(True)
        self.assertTrue(self.make().paused)            # same boot: still paused
        st = json.load(open(paths.STATE))
        st["paused_boot"] = "another-boot"
        json.dump(st, open(paths.STATE, "w"))
        self.assertFalse(self.make().paused)           # after a restart of the computer: protected again

    def test_killswitch_survives_reboot(self):
        self.core.set_killswitch(True, "manual")
        self.assertTrue(self.make().ks)

    def test_killswitch_not_recorded_if_nft_fails(self):
        def broken(ks=None, paused=None):
            raise RuntimeError("nft: Operation not permitted")
        self.core.apply_nft = broken
        with self.assertRaises(RuntimeError):
            self.core.set_killswitch(True, "manual")
        self.assertFalse(self.core.ks)
        self.assertFalse(self.make().ks)
        with self.assertRaises(RuntimeError):
            self.core.set_paused(True)
        self.assertFalse(self.core.paused)

    def test_lost_verdict_is_fatal(self):
        self.core.nfq.fail = True
        with self.assertRaises(Fatal):
            self.core.on_packet(core.Q_CONN, 1, 3, b"\x00" * 10, 0)

    def test_crashing_thread_is_fatal(self):
        done = threading.Event()
        why = []

        def fatal(w):
            why.append(w)
            done.set()
        self.core.fatal = fatal
        self.core.spawn("t", lambda: 1 / 0)
        self.assertTrue(done.wait(2))
        self.assertIn("crashed", why[0])

    def test_flood_is_capped(self):
        self.core.cfg["max_pending"] = 10
        for i in range(15):
            self.core.on_packet(core.Q_CONN, 1000 + i, 3, self.connecting_socket("10.255.255.%d" % (i + 1)), 0)
        self.assertEqual(len(self.core.pending), 10)
        self.assertEqual([v for _p, v in self.core.nfq.v], [0] * 5)
        self.assertTrue(any(e["ev"] == "overload" for e in self.core.events(0)[1]))

    def test_unanswered_request_is_blocked(self):
        self.core.check_table = lambda: None
        self.core.on_packet(core.Q_CONN, 1, 3, self.connecting_socket(), 0)
        self.core.pending[1]["deadline"] = time.time() - 1
        self.core.housekeeping_once(1)
        self.assertEqual(self.core.nfq.v, [(1, 0)])

    def test_removed_table_is_loaded_again(self):
        self.core.table_ok = lambda: False
        self.core.check_table()
        self.assertTrue(self.core.applied)
        self.assertTrue(any(e["ev"] == "tamper" for e in self.core.events(0)[1]))

    def test_table_check(self):
        out = core.nft_ruleset(core.DEFAULT_CONFIG, False, False)

        class R:
            returncode = 0
            stdout = out
        real = core.subprocess.run
        core.subprocess.run = lambda *a, **k: R()
        try:
            self.assertTrue(self.core.table_ok())
            R.stdout = out.replace(f"queue num {core.Q_CONN}", "accept")
            self.assertFalse(self.core.table_ok())       # replaced by a permissive table
            R.returncode = 1
            self.assertFalse(self.core.table_ok())       # table gone
        finally:
            core.subprocess.run = real

    def test_events_and_settings(self):
        seq, _evs = self.core.events(0)
        self.core.set_killswitch(True, "test")
        _seq2, evs2 = self.core.events(seq)
        self.assertEqual([e["ev"] for e in evs2], ["killswitch"])
        self.assertFalse(self.core.set_setting("killswitch_auto", "maybe")[0])
        self.assertTrue(self.core.set_setting("killswitch_auto", "in")[0])
        self.assertEqual(self.make().cfg["killswitch_auto"], "in")


class TestVersions(unittest.TestCase):
    def test_versions_agree(self):
        import varco
        import varco_privacy
        with open(os.path.join(os.path.dirname(__file__), "..", "debian", "changelog")) as f:
            changelog = f.readline()
        self.assertEqual(varco.VERSION, varco_privacy.VERSION)
        self.assertIn(f"({varco.VERSION})", changelog)


if __name__ == "__main__":
    unittest.main()
