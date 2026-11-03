# SPDX-License-Identifier: GPL-3.0-or-later
"""Human-readable texts shared by the command line and the graphical interface."""
import os

from . import _

PORTS = {
    53: lambda: _("DNS - turns site names into addresses"),
    80: lambda: _("HTTP - unencrypted web pages"),
    443: lambda: _("HTTPS - encrypted websites and services"),
    853: lambda: _("encrypted DNS"),
    22: lambda: _("SSH - remote access"),
    123: lambda: _("NTP - clock synchronization"),
    67: lambda: _("DHCP - network address from the router"),
    68: lambda: _("DHCP - network address from the router"),
    5353: lambda: _("mDNS - discovery of devices on the local network"),
    1900: lambda: _("SSDP - discovery of devices on the local network"),
    993: lambda: _("IMAP - incoming mail"),
    465: lambda: _("SMTP - outgoing mail"),
    587: lambda: _("SMTP - outgoing mail"),
    3478: lambda: _("STUN - calls and video calls"),
}

NETWORKS = {
    "wifi": lambda: _("Wi-Fi"),
    "mobile": lambda: _("mobile network (WWAN)"),
    "ethernet": lambda: _("cable (Ethernet)"),
    "vpn": lambda: _("VPN"),
    "virtual": lambda: _("virtual network"),
    "loopback": lambda: _("this computer"),
    "other": lambda: _("other network"),
}

CHOICE_LETTERS = {
    "s": "allow-always", "w": "allow-network", "p": "allow-port", "t": "allow-app", "u": "allow-once",
    "d": "deny-once", "n": "deny-always", "k": "deny-kill", "x": "killswitch",
}


def clean(t):
    """Text from the network or from other programs made safe to print: control characters
    (terminal escape sequences, bidirectional overrides...) become '?'."""
    if t is None:
        return ""
    return "".join(ch if ch.isprintable() else "?" for ch in str(t))


def port_text(port, proto):
    d = PORTS.get(port)
    return _("port {port}/{proto}").format(port=port, proto=proto) + (f" ({d()})" if d else "")


def network_text(kind, name=""):
    label = NETWORKS.get(kind or "other", NETWORKS["other"])()
    return f"{label} ({name})" if name else label


def rule_network_text(pat):
    if not pat or pat == "*":
        return _("any network")
    if pat.startswith("@"):
        return network_text(pat[1:])
    return _("interface {name}").format(name=clean(pat))


def rule_host_text(host):
    if host == "@dns":
        return _("the DNS servers of this computer")
    return clean(host)


def program_name(app):
    """Short name of a program identity: 'firefox-esr', 'backup.py (python3.13)'..."""
    if not app or app == "?":
        return _("unknown program")
    app = clean(app)
    parts = app.split(" ", 1)
    base = os.path.basename(parts[0])
    if len(parts) > 1:
        rest = parts[1]
        if rest.startswith("/"):
            return f"{os.path.basename(rest)} ({base})"
        if rest == "(stdin)":
            return _("{name} (code from stdin)").format(name=base)
        return f"{base} {rest}"
    return base


def where(c):
    names = c.get("names") or []
    return f"{clean(names[0])} ({clean(c['remote'])})" if names else clean(c.get("remote", "?"))


def reason_text(reason, rule=None):
    return {
        "rule": _("rule #{n}").format(n=rule),
        "user": _("your decision"),
        "timeout": _("no answer in time"),
        "closed-port": _("inbound, no service listening"),
        "request": _("waiting for your decision (#{n})").format(n=rule),
        "paused": _("protection paused"),
        "overload": _("too many requests at once (flood protection)"),
        "killswitch": _("kill switch"),
    }.get(reason, reason)


def killswitch_reason(r):
    if not r:
        return ""
    kind, _sep, rest = r.partition(":")
    if kind == "auto-in":
        rid, _s, ip = rest.partition(":")
        return _("automatic: unapproved inbound connection from {ip} (request #{id})").format(ip=ip, id=rid)
    if kind == "auto-out":
        rid, _s, ip = rest.partition(":")
        return _("automatic: unapproved outbound connection to {ip} (request #{id})").format(ip=ip, id=rid)
    if kind == "user":
        return _("activated by you on request #{id}").format(id=rest)
    if kind == "manual":
        return _("activated by you")
    return r
