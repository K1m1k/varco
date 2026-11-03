# SPDX-License-Identifier: GPL-3.0-or-later
"""Ways around the firewall closed in 1.0.3, and the privacy defaults."""
import json
import os
import socket
import struct
import sys
import tempfile
import unittest

TMP = tempfile.mkdtemp()
os.environ.setdefault("VARCO_ETC", os.path.join(TMP, "etc"))
os.environ.setdefault("VARCO_VAR", os.path.join(TMP, "var"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from varco import core, helper, netutil, paths, procinfo, rules, texts  # noqa: E402
from test_core import Base, dns_name  # noqa: E402

PY = "/usr/bin/python3.13"


def answer(qname, records, qid=1):
    """DNS answer to one question; records: (owner, type, data)."""
    m = struct.pack("!HHHHHH", qid, 0x8180, 1, len(records), 0, 0) + dns_name(qname) + struct.pack("!HH", 1, 1)
    for owner, t, data in records:
        rd = dns_name(data) if t == 5 else socket.inet_aton(data)
        m += dns_name(owner) + struct.pack("!HHIH", t, 1, 300, len(rd)) + rd
    return m


class TestDnsTrust(unittest.TestCase):
    def setUp(self):
        self.d = netutil.DnsCache(trusted=lambda: {"192.0.2.53", "127.0.0.53"})

    def test_answer_from_an_unknown_server_is_ignored(self):
        # a program asks its own "DNS server" and makes up deb.debian.org -> its address
        self.d.feed(answer("deb.debian.org", [("deb.debian.org", 1, "203.0.113.66")]), "203.0.113.1")
        self.assertEqual(self.d.names("203.0.113.66"), [])

    def test_extra_records_about_other_names_are_ignored(self):
        m = answer("x.attacker.example", [("x.attacker.example", 1, "203.0.113.66"),
                                          ("deb.debian.org", 1, "203.0.113.66")])
        self.d.feed(m, "192.0.2.53")
        self.assertEqual(self.d.names("203.0.113.66"), ["x.attacker.example"])

    def test_cname_chain_is_followed(self):
        m = answer("www.example.com", [("www.example.com", 5, "edge.cdn.example"),
                                       ("edge.cdn.example", 1, "198.51.100.7"),
                                       ("unrelated.example", 1, "198.51.100.8")])
        self.d.feed(m, "127.0.0.53")
        self.assertEqual(sorted(self.d.names("198.51.100.7")), ["edge.cdn.example", "www.example.com"])
        self.assertEqual(self.d.names("198.51.100.8"), [])

    def test_names_with_strange_characters_are_refused(self):
        self.d.feed(answer("evil\x1b[2J.example", [("evil\x1b[2J.example", 1, "198.51.100.9")]), "192.0.2.53")
        self.assertEqual(self.d.names("198.51.100.9"), [])
        self.assertFalse(netutil.valid_name("*.debian.org"))
        self.assertTrue(netutil.valid_name("_dmarc.mail-1.example.org"))

    def test_resolvers_are_read_from_resolv_conf(self):
        d = tempfile.mkdtemp()
        a, b = os.path.join(d, "a"), os.path.join(d, "b")
        with open(a, "w") as f:
            f.write("# comment\nnameserver 127.0.0.53\noptions edns0\n")
        with open(b, "w") as f:
            f.write("nameserver 192.0.2.1\nnameserver fe80::1%wlan0\nnameserver bogus\n")
        self.assertEqual(netutil.resolvers((a, b)), {"127.0.0.53", "192.0.2.1", "fe80::1"})

    def test_dns_answers_on_loopback_are_observed(self):
        text = core.nft_ruleset(core.DEFAULT_CONFIG, False, False)
        self.assertLess(text.index(f'iif "lo" udp sport 53 queue num {core.Q_DNS} bypass'),
                        text.index('iif "lo" accept'))
        self.assertNotIn("sport 53", core.nft_ruleset(core.DEFAULT_CONFIG, True, False))


class TestDnsRule(unittest.TestCase):
    c = {"dir": "out", "app": "/usr/bin/curl", "proto": "udp", "port": 53, "remote": "192.0.2.53", "names": []}
    r = {"dir": "out", "app": "*", "proto": "*", "host": "@dns", "port": 53, "action": "allow"}

    def test_only_the_system_dns_servers(self):
        real = rules.resolvers
        rules.host_match.__defaults__ = (lambda: {"192.0.2.53"},)
        try:
            self.assertTrue(rules.rule_match(self.r, self.c))
            self.assertFalse(rules.rule_match(self.r, self.c | {"remote": "203.0.113.1"}))
        finally:
            rules.host_match.__defaults__ = (real,)
        self.assertIsNone(rules.validate(self.r))

    def test_dns_preset_is_limited(self):
        r = helper.preset_rules({"dns"})[0]
        self.assertEqual((r["app"], r["host"], r["port"]), ("*", "@dns", 53))
        self.assertTrue(all(x["host"] == "@dns" or x["app"] != "*" for x in helper.preset_rules({"dns", "system"})))

    def test_old_dns_preset_is_converted(self):
        path = os.path.join(tempfile.mkdtemp(), "rules.json")
        old = {"next_id": 3, "rules": [
            {"dir": "out", "app": "*", "proto": "*", "host": "*", "port": 53, "action": "allow",
             "iface": "*", "note": "preset: DNS", "id": 1},
            {"dir": "out", "app": "/usr/bin/dig", "proto": "*", "host": "*", "port": 53, "action": "allow",
             "iface": "*", "note": "mine", "id": 2}]}
        with open(path, "w") as f:
            json.dump(old, f)
        rs = rules.Rules(path)
        self.assertEqual([r["host"] for r in rs.list], ["@dns", "*"])     # the user's own rule is untouched
        with open(path) as f:
            self.assertEqual(json.load(f)["version"], rules.SCHEMA)


class TestRulesFile(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "rules.json")

    def test_damaged_file_is_set_aside_not_overwritten(self):
        with open(self.path, "w") as f:
            f.write('{"rules": [ broken')
        rs = rules.Rules(self.path)
        self.assertEqual(rs.list, [])
        aside = [f for f in os.listdir(os.path.dirname(self.path)) if ".damaged-" in f]
        self.assertEqual(len(aside), 1)
        with open(os.path.join(os.path.dirname(self.path), aside[0])) as f:
            self.assertIn("broken", f.read())

    def test_wrong_type_does_not_crash(self):
        with open(self.path, "w") as f:
            f.write("[1, 2, 3]")
        self.assertEqual(rules.Rules(self.path).list, [])

    def test_invalid_rules_are_kept_but_not_applied(self):
        good = {"dir": "out", "app": "*", "proto": "tcp", "host": "*", "port": 80, "action": "allow", "id": 1}
        bad = {"dir": "sideways", "app": "*", "proto": "tcp", "host": "*", "port": 80, "action": "allow", "id": 2}
        with open(self.path, "w") as f:
            json.dump({"version": 2, "next_id": 3, "rules": [good, bad]}, f)
        rs = rules.Rules(self.path)
        self.assertEqual([r["id"] for r in rs.list], [1])
        self.assertEqual(rs.invalid, [bad])
        rs.add(good | {"port": 81})
        with open(self.path) as f:
            d = json.load(f)
        self.assertEqual(d["invalid"], [bad])
        self.assertEqual(d["rules"][-1]["id"], 3)

    def test_no_wildcard_allow_for_unknown_programs(self):
        base = {"dir": "out", "app": "?", "proto": "udp", "host": "198.51.100.1", "port": 51820, "action": "allow"}
        self.assertIsNone(rules.validate(base))
        self.assertIsNotNone(rules.validate(base | {"host": "*"}))
        self.assertIsNotNone(rules.validate(base | {"port": "*"}))
        self.assertIsNone(rules.validate(base | {"port": "*", "action": "deny"}))
        self.assertIsNotNone(rules.validate(base | {"app": "/usr/bin/x\x1b[0m"}))


class TestIdentityHardening(unittest.TestCase):
    def test_options_before_the_script_change_the_identity(self):
        approved = procinfo.app_identity(PY, ["python3", "/home/k/backup.py"], "/")
        for argv in (["python3", "-X", "/home/k/backup.py", "evil.py"],
                     ["python3", "-W", "/home/k/backup.py", "evil.py"],
                     ["python3", "-u", "/home/k/backup.py"]):
            self.assertNotEqual(procinfo.app_identity(PY, argv, "/tmp"), approved, argv)

    def test_node_preloaded_module(self):
        approved = procinfo.app_identity("/usr/bin/node", ["node", "/home/k/app.js"], "/")
        evil = procinfo.app_identity("/usr/bin/node", ["node", "--require", "/home/k/app.js", "/tmp/e.js"], "/")
        self.assertNotEqual(evil, approved)
        self.assertTrue(evil.endswith("/tmp/e.js"))

    def test_option_values_are_not_taken_for_the_script(self):
        ident = procinfo.app_identity(PY, ["python3", "-W", "ignore", "tool.py"], "/srv")
        self.assertEqual(ident, f"{PY} -W ignore /srv/tool.py")
        self.assertEqual(procinfo.parse_interpreter(PY, ["python3", "-W", "ignore", "tool.py"], "/srv")[1],
                         "/srv/tool.py")

    def test_code_loading_variables(self):
        env = b"HOME=/home/k\0LD_PRELOAD=/tmp/x.so\0"
        tag = procinfo.inject_env(env, "/usr/bin/firefox-esr")
        self.assertTrue(tag.startswith("[env LD_PRELOAD sha256:"))
        self.assertNotEqual(tag, procinfo.inject_env(b"LD_PRELOAD=/tmp/y.so\0", "/usr/bin/firefox-esr"))
        # PYTHONPATH only matters to Python
        self.assertEqual(procinfo.inject_env(b"PYTHONPATH=/x\0", "/usr/bin/firefox-esr"), "")
        self.assertIn("PYTHONPATH", procinfo.inject_env(b"PYTHONPATH=/x\0", PY))
        self.assertEqual(procinfo.inject_env(b"PATH=/usr/bin\0", PY), "")
        ident = procinfo.app_identity("/usr/bin/firefox-esr", ["firefox"], "/", tag)
        self.assertNotEqual(ident, "/usr/bin/firefox-esr")

    def test_very_long_identity_is_hashed(self):
        ident = procinfo.app_identity(PY, ["python3"] + ["-v"] * 2000 + ["x.py"], "/")
        self.assertLessEqual(len(ident), procinfo.MAX_IDENTITY)
        self.assertIn("sha256:", ident)

    def test_control_characters_are_never_shown(self):
        self.assertEqual(texts.clean("a\x1b[2Jb‮"), "a?[2Jb?")
        self.assertEqual(procinfo.printable("x\ny"), "x?y")
        self.assertNotIn("\x1b", texts.program_name("/usr/bin/x\x1b]0;owned\x07"))
        self.assertEqual(netutil.printable("ACME\x1b[31m Corp"), "ACME [31m Corp")


class TestEngineHardening(Base):
    def test_shared_socket_is_unknown(self):
        pkt = self.connecting_socket()
        real_owners, real_describe = self.core.procs.owners, core.describe
        self.core.procs.owners = lambda ino: [111, 222]

        def fake_describe(pid, uid=None):
            d = real_describe(None, uid)
            d.update(pid=pid, exe="/usr/bin/x", app={111: "/tmp/malware", 222: "/usr/bin/firefox-esr"}[pid])
            return d
        core.describe = fake_describe
        try:
            self.core.on_packet(core.Q_CONN, 1, 3, pkt, os.getuid())
        finally:
            core.describe = real_describe
            self.core.procs.owners = real_owners
        c = self.core.pending[1]["c"]
        self.assertEqual(c["app"], "?")
        self.assertEqual(c["shared"], ["/tmp/malware", "/usr/bin/firefox-esr"])
        # no wildcard rule is possible for it, a rule for this host and port is
        self.assertFalse(self.core.decide(1, "allow-app")["ok"])
        self.assertIn(1, self.core.pending)                   # still waiting
        self.assertTrue(self.core.decide(1, "allow-always")["ok"])
        r = self.core.rules.list[-1]
        self.assertEqual((r["app"], r["host"], r["port"]), ("?", "10.255.255.1", 443))

    def test_kill_refuses_a_reused_pid(self):
        ok, msg = self.core.kill(os.getppid(), 0, start=-1)       # wrong start time: another process
        self.assertFalse(ok)
        self.assertTrue(os.path.exists(f"/proc/{os.getppid()}"))

    def test_privacy_defaults(self):
        self.assertFalse(core.DEFAULT_CONFIG["whois"])
        self.assertFalse(core.DEFAULT_CONFIG["log_allowed"])
        with open(os.path.join(os.path.dirname(__file__), "..", "data", "config.json")) as f:
            cfg = json.load(f)
        self.assertEqual({k: cfg[k] for k in core.DEFAULT_CONFIG}, core.DEFAULT_CONFIG)

    def test_damaged_state_does_not_stop_the_service(self):
        os.makedirs(paths.VAR, exist_ok=True)
        with open(paths.STATE, "w") as f:
            f.write("\x00garbage")
        c = self.make()
        self.assertFalse(c.ks)
        self.assertTrue(any(".damaged-" in f for f in os.listdir(paths.VAR)))

    def test_state_reports_health(self):
        st = self.core.state()
        for k in ("watchdog_running", "invalid_rules", "ptrace_scope"):
            self.assertIn(k, st)


if __name__ == "__main__":
    unittest.main()
