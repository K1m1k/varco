# SPDX-License-Identifier: GPL-3.0-or-later
"""Permanent allow/deny rules.

File format (rules.json), version 2:
    {"version": 2, "next_id": N, "rules": [...], "invalid": [...]}
'invalid' keeps rules that failed validation when the file was loaded (edited by hand,
damaged, or written by a future version): they are never applied and never thrown away.
"""
import fnmatch
import ipaddress
import re
import time

from .netutil import resolvers
from .util import load_json_checked, log, save_json

SCHEMA = 2
FIELDS = ("dir", "app", "proto", "host", "port", "action")
IFACE_KINDS = ("wifi", "mobile", "ethernet", "vpn", "virtual", "other")
IFACE_RE = re.compile(r"^(\*|@(" + "|".join(IFACE_KINDS) + r")|[A-Za-z0-9*?._-]{1,32})$")
ACTIONS = ("allow", "deny")
DIRS = ("in", "out", "*")
HOST_DNS = "@dns"      # the DNS servers the system is using right now (they change with the network)
UNKNOWN_APP = "?"      # a connection whose program could not be identified


def host_match(pat, ip, names, dns_servers=resolvers):
    if pat == "*":
        return True
    if pat == HOST_DNS:
        return ip in dns_servers()
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(pat, strict=False)
    except ValueError:
        pass
    pat = pat.lower()
    return any(fnmatch.fnmatchcase(n, pat) for n in names)


def iface_match(pat, name, kind):
    """'*' any network · '@wifi', '@mobile', '@ethernet', '@vpn'... a kind · otherwise a name pattern."""
    if not pat or pat == "*":
        return True
    if pat.startswith("@"):
        return kind == pat[1:]
    return fnmatch.fnmatchcase(name or "", pat)


def rule_match(r, c):
    if r.get("dir", "*") not in ("*", c["dir"]):
        return False
    if not iface_match(r.get("iface", "*"), c.get("iface", ""), c.get("iface_kind", "other")):
        return False
    if r.get("app", "*") not in ("*", c["app"]):
        return False
    if str(r.get("proto", "*")) not in ("*", c["proto"]):
        return False
    if str(r.get("port", "*")) not in ("*", str(c["port"])):
        return False
    return host_match(r.get("host", "*"), c["remote"], c.get("names", []))


def validate(r):
    """Return an error string, or None if the rule is valid."""
    if not isinstance(r, dict):
        return "invalid rule"
    for k in FIELDS:
        if k not in r:
            return f"missing field: {k}"
    if r["action"] not in ACTIONS or r["dir"] not in DIRS:
        return "invalid action or direction"
    if r["proto"] not in ("tcp", "udp", "*"):
        return "invalid protocol"
    if not IFACE_RE.match(str(r.get("iface", "*"))):
        return "invalid network"
    if not isinstance(r["app"], str) or not r["app"] or len(r["app"]) > 4096 or not r["app"].isprintable():
        return "invalid program"
    if not isinstance(r["host"], str) or not r["host"] or len(r["host"]) > 253 or not r["host"].isprintable() \
            or " " in r["host"]:
        return "invalid host"
    if r["port"] != "*":
        try:
            if isinstance(r["port"], bool) or not 0 <= int(r["port"]) <= 65535:
                raise ValueError
        except (TypeError, ValueError):
            return "invalid port"
    if r["app"] == UNKNOWN_APP and r["action"] == "allow" and (r["host"] == "*" or r["port"] == "*"):
        # would let through everything that cannot be identified
        return "a rule for an unknown program must name one host and one port"
    if "id" in r and (isinstance(r["id"], bool) or not isinstance(r["id"], int)):
        return "invalid id"
    return None


def migrate(d):
    """Bring a rules file written by an older version up to SCHEMA. Returns (data, changed)."""
    changed = False
    if d.get("version", 1) < 2:
        # 1.0.0-1.0.2: the DNS preset allowed every program to reach ANY server on port 53,
        # a free channel out of the computer. Now it is limited to the system's DNS servers.
        for r in d.get("rules", []):
            if isinstance(r, dict) and str(r.get("note", "")).startswith("preset: DNS") and r.get("app") == "*" \
                    and r.get("host") == "*" and str(r.get("port")) == "53" and r.get("action") == "allow":
                r["host"] = HOST_DNS
                log("rules: the DNS preset now allows only the system's DNS servers (was: any server)")
        d["version"] = 2
        changed = True
    return d, changed


class Rules:
    def __init__(self, path):
        self.path = path
        self.load()

    def load(self):
        d = load_json_checked(self.path, {}, dict)
        if d.get("version", 1) > SCHEMA:
            log(f"rules: {self.path} was written by a newer version (format {d.get('version')}): "
                "rules this version does not understand are not applied")
        d, changed = migrate(d)
        rules = d.get("rules", [])
        invalid = d.get("invalid", [])
        if not isinstance(rules, list):
            invalid, rules = invalid + [rules], []
        if not isinstance(invalid, list):
            invalid = [invalid]
        good, ids = [], set()
        for r in rules:
            err = validate(r) or (None if isinstance(r.get("id"), int) and r["id"] not in ids else "invalid id")
            if err:
                log(f"rules: rule not applied ({err}): {r!r:.200}")
                invalid.append(r)
                changed = True
                continue
            ids.add(r["id"])
            good.append(r)
        try:
            nxt = int(d.get("next_id", 1))
        except (TypeError, ValueError):
            nxt, changed = 1, True
        self.next = max([nxt] + [i + 1 for i in ids])
        self.list, self.invalid = good, invalid
        if changed:
            try:
                self.save()
            except OSError as e:
                log(f"rules: cannot save {self.path}: {e}")

    def save(self):
        d = {"version": SCHEMA, "next_id": self.next, "rules": self.list}
        if self.invalid:
            d["invalid"] = self.invalid
        save_json(self.path, d)

    def add(self, r):
        r = {k: r[k] for k in FIELDS} | {"iface": str(r.get("iface", "*")), "note": str(r.get("note", ""))[:200]}
        if r["port"] != "*":
            r["port"] = int(r["port"])
        r["id"] = self.next
        r["created"] = time.strftime("%Y-%m-%d %H:%M")
        self.next += 1
        self.list.append(r)
        self.save()
        return r

    def remove(self, rid):
        n = len(self.list)
        self.list = [r for r in self.list if r.get("id") != rid]
        if len(self.list) != n:
            self.save()
            return True
        return False

    def match(self, c):
        for action in ("deny", "allow"):
            for r in self.list:
                if r.get("action") == action and rule_match(r, c):
                    return r
        return None
