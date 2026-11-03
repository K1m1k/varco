# SPDX-License-Identifier: GPL-3.0-or-later
"""varco: command line interface."""
import argparse
import json
import os
import sys
import threading
import time

from gi.repository import GLib

from . import VERSION, _
from .client import Client, NotAuthorized, NotRunning
from .texts import (CHOICE_LETTERS, clean, killswitch_reason, network_text, port_text, program_name, reason_text,
                    rule_host_text, rule_network_text, where)

TTY = sys.stdout.isatty()
RED, GREEN, YELLOW, CYAN, DIM, BOLD = "1;31", "1;32", "1;33", "1;36", "2", "1"


def col(code, t):
    return f"\033[{code}m{t}\033[0m" if TTY else t
# every value that comes from the network or from another program goes through clean():
# a DNS name, a whois answer or a command line must not be able to drive the terminal


def die(msg, code=1):
    print(col(RED, msg), file=sys.stderr)
    sys.exit(code)


def show_request(ev):
    c = ev["c"]
    out = c["dir"] == "out"
    head = (col(YELLOW, _("OUTBOUND - the computer wants to connect out")) if out
            else col(RED, _("INBOUND - someone outside wants to connect to the computer")))
    lines = ["", col(BOLD, f"━━━ #{ev['id']}  {ev.get('ts', '')}  ") + head,
             f"  {_('Program')}: {col(BOLD, program_name(c.get('app')))}  ({clean(c.get('exe', '?'))})"]
    if c.get("cmd"):
        lines.append(f"  {_('Command')}: {clean(c['cmd'][:200])}")
    lines.append(f"  {_('Process')}: pid {c.get('pid') or '?'} · {_('user')} {clean(c.get('user', '?'))}"
                 + (f" · {_('started by')} {clean(c['parent'])}" if c.get("parent") else "")
                 + (f" · {_('service')} {clean(c['unit'])}" if c.get("unit") else ""))
    if c.get("shared"):
        lines.append(col(RED, "  " + _("Shared by different programs ({apps}): it is not possible to know which one "
                                       "sends it").format(apps=", ".join(program_name(a) for a in c["shared"][:4]))))
    elif c.get("app") == "?":
        lines.append(col(YELLOW, "  " + _("Unknown program: only s, w, u, n, d, x are possible")))
    if c.get("env"):
        lines.append(col(RED, "  " + _("Started with variables that load other code: {env}").format(
            env=clean(c["env"]))))
    lines.append(f"  {_('Remote') if out else _('From')}: {col(CYAN, where(c))} · {port_text(c['port'], c['proto'])}")
    lines.append(f"  {_('Network')}: {network_text(c.get('iface_kind'), c.get('iface'))}")
    if ev.get("what"):
        lines.append(f"  {_('What it is')}: {clean(ev['what'])}")
    if ev.get("who"):
        lines.append(f"  {_('Who it is')}: {clean(ev['who'])}")
    print("\n".join(lines))


CHOICES_HELP = _("""Choices (letter, plus the number if several requests are waiting, e.g. "s" or "s 12"):
  s = allow ALWAYS this program to this host and port
  w = allow ALWAYS, but only on this type of network (Wi-Fi, mobile, cable...)
  p = allow ALWAYS this program to any host on this port
  t = allow ALWAYS everything for this program
  u = allow only THIS time
  n = deny ALWAYS (creates a rule)
  d = deny this time
  k = deny and TERMINATE the process
  x = KILL SWITCH: isolate the computer from the network
Other: l = list waiting · ? = help · q = quit""")


def monitor(cl):
    pending = {}
    lock = threading.Lock()

    def say(t):
        with lock:
            print("\r" + t)
            print("> ", end="", flush=True)

    def poll():
        seq = 0
        for ev in cl.pending():
            pending[ev["id"]] = ev
            show_request(ev)
        seq, _evs = cl.events(0)
        while True:
            time.sleep(0.7)
            try:
                seq, evs = cl.events(seq)
            except Exception:
                say(col(RED, _("Connection to the service lost.")))
                os._exit(1)
            for ev in evs:
                t = ev["ev"]
                if t == "request":
                    pending[ev["id"]] = ev
                    with lock:
                        show_request(ev)
                        print(col(DIM, _("  choose: s p t u n d k x  (? = help)")))
                        print("> ", end="", flush=True)
                elif t == "info" and (ev.get("who") or ev.get("what")):
                    say(col(CYAN, f"  ↳ #{ev['id']} {clean(ev.get('who'))} · {clean(ev.get('what'))}"))
                elif t == "decided":
                    pending.pop(ev["id"], None)
                    ok = ev["verdict"] == "allowed"
                    say(col(GREEN if ok else RED, f"  #{ev['id']}: " + (_("allowed") if ok else _("blocked"))
                                                  + f" ({reason_text(ev['reason'], ev.get('rule'))})"))
                elif t == "activity" and ev["verdict"] != "pending":
                    c = ev["c"]
                    say(col(DIM, ev["ts"] + " ") + col(GREEN if ev["verdict"] == "allowed" else RED,
                        f"{_('allowed') if ev['verdict'] == 'allowed' else _('blocked'):10} {program_name(c['app'])} "
                        f"{'→' if c['dir'] == 'out' else '←'} {where(c)} :{c['port']}/{c['proto']} "
                        f"({reason_text(ev['reason'], ev.get('rule'))})"))
                elif t == "process" and ev["suspicious"]:
                    say(col(RED, _("SUSPICIOUS program: {app} (pid {pid}) - {why}").format(
                        app=clean(ev["app"]), pid=ev["pid"], why=clean("; ".join(ev["suspicious"])))))
                elif t == "killswitch" and ev["on"]:
                    say(col(RED, _("KILL SWITCH ON: computer isolated. {why}").format(why=killswitch_reason(ev["reason"]))))
                elif t == "tamper":
                    say(col(RED, _("WARNING: another program removed or changed the firewall table: "
                                   "Varco loaded it again.")))
                elif t == "overload":
                    say(col(RED, _("Too many connection requests at once: the extra ones are blocked.")))
                elif t == "paused":
                    say(col(YELLOW, _("Protection PAUSED") if ev["on"] else _("Protection resumed")))

    print(col(BOLD, "Varco - monitor") + "  (Ctrl+C / q)")
    print(CHOICES_HELP)
    threading.Thread(target=poll, daemon=True).start()
    try:
        while True:
            line = input("> ").strip().lower()
            if not line:
                continue
            if line in ("q", "quit", "exit"):
                break
            if line in ("?", "h", "help"):
                say(CHOICES_HELP)
                continue
            if line == "l":
                for ev in list(pending.values()):
                    with lock:
                        show_request(ev)
                if not pending:
                    say(_("No requests waiting."))
                continue
            parts = line.split()
            if parts[0] not in CHOICE_LETTERS:
                say(_("Unknown command. Type ? for help."))
                continue
            if len(parts) > 1:
                try:
                    rid = int(parts[1].lstrip("#"))
                except ValueError:
                    say(_("Invalid request number."))
                    continue
            elif len(pending) == 1:
                rid = next(iter(pending))
            elif parts[0] == "x":
                cl.killswitch(True)
                continue
            else:
                say(_("Several requests are waiting: add the number, e.g. '{c} {n}'").format(
                    c=parts[0], n=min(pending) if pending else 1))
                continue
            r = cl.decide(rid, CHOICE_LETTERS[parts[0]])
            say(col(GREEN if r.get("ok") else RED, "  " + clean(r.get("message", ""))))
    except (KeyboardInterrupt, EOFError):
        print()


def cmd_status(cl, a):
    st = cl.state()
    if st["paused"]:
        print(col(YELLOW, _("Protection: PAUSED (network free, no checks)")))
    elif st["killswitch"]:
        print(col(RED, _("Kill switch: ON - {why}").format(why=killswitch_reason(st["killswitch_reason"]))))
    else:
        print(col(GREEN, _("Protection: active")))
    print(_("Waiting requests: {n}").format(n=st["pending"]))
    print(_("Rules: {n}").format(n=st["rules"]))
    print(_("Known programs: {n}").format(n=st["known_programs"]))
    print(_("Automatic kill switch: {v}").format(v=st["settings"].get("killswitch_auto")))
    if st["settings"].get("watchdog") and not st.get("watchdog_running", True):
        print(col(RED, _("Process watchdog: STOPPED by an error (see 'varco log'); the firewall keeps working")))
    if st.get("invalid_rules"):
        print(col(YELLOW, _("Rules not applied because they are not valid: {n} (kept in rules.json)").format(
            n=st["invalid_rules"])))
    if st.get("ptrace_scope") == 0:
        print(col(YELLOW, _("Warning: any program can take control of the other programs of the same user "
                            "(ptrace). Fix: sudo /usr/libexec/varco/varco-helper ptrace on")))


def cmd_rules(cl, a):
    rules = cl.rules()
    if a.json:
        print(json.dumps(rules, indent=2, ensure_ascii=False))
        return
    if not rules:
        print(_("No rules: everything you do not approve is blocked."))
    for r in rules:
        act = col(GREEN, _("ALLOW")) if r["action"] == "allow" else col(RED, _("DENY"))
        d = {"out": _("out"), "in": _("in"), "*": _("both")}[r["dir"]]
        print(f"#{r['id']:<4} {act} {d:8} {clean(r['app'])}\n      host {rule_host_text(r['host'])}  "
              f"{_('port')} {r['port']}/{r['proto']}  · {rule_network_text(r.get('iface', '*'))}"
              + col(DIM, f"   ({clean(r.get('created', ''))} {clean(r.get('note', ''))})"))


def cmd_connections(cl, a):
    lst = cl.connections()
    if a.json:
        print(json.dumps(lst, indent=2, ensure_ascii=False))
        return
    for kind, title in (("listening", _("Services listening on the network")), ("connected", _("Active connections"))):
        sel = [x for x in lst if x["kind"] == kind]
        print(col(BOLD, f"\n== {title} ({len(sel)}) =="))
        for x in sel:
            names = f" [{', '.join(clean(n) for n in x['names'][:2])}]" if x["names"] else ""
            place = x["local"] if kind == "listening" else f"{x['local']} -> {x['remote']}{names}"
            print(f"  {x['proto']:3} {place}\n      {clean(x['app'])} (pid {x['pid'] or '?'}, {clean(x['user'])}"
                  + (f", {clean(x['unit'])}" if x["unit"] else "") + ")")


def parse_port(v):
    return v if v == "*" else int(v)


def main(argv=None):
    p = argparse.ArgumentParser(prog="varco", description=_("Interactive per-application firewall."))
    p.add_argument("--version", action="version", version=f"varco {VERSION}")
    sub = p.add_subparsers(dest="cmd", metavar=_("command"))
    sub.add_parser("status", help=_("show the protection status"))
    sub.add_parser("monitor", help=_("approve or block connections from the terminal"))
    s = sub.add_parser("rules", help=_("list rules"))
    s.add_argument("--json", action="store_true")
    s = sub.add_parser("connections", help=_("active connections and listening services"))
    s.add_argument("--json", action="store_true")
    s = sub.add_parser("add", help=_("add a rule"))
    s.add_argument("action", choices=["allow", "deny"])
    s.add_argument("dir", choices=["out", "in", "*"])
    s.add_argument("program", help=_("program path or *"))
    s.add_argument("host", help=_("IP, network, name (also *.example.org), @dns (the DNS servers of this "
                                  "computer) or *"))
    s.add_argument("port", type=parse_port, help=_("port number or *"))
    s.add_argument("proto", nargs="?", default="*", choices=["tcp", "udp", "*"])
    s.add_argument("--network", default="*", metavar=_("NETWORK"),
                   help=_("*, @wifi, @mobile, @ethernet, @vpn or an interface name (default: any)"))
    s = sub.add_parser("remove", help=_("remove a rule"))
    s.add_argument("id", type=lambda v: int(v.lstrip("#")))
    s = sub.add_parser("killswitch", help=_("isolate the computer from the network / reopen it"))
    s.add_argument("state", choices=["on", "off"])
    s = sub.add_parser("pause", help=_("pause protection (network free) / resume it"))
    s.add_argument("state", choices=["on", "off"])
    s = sub.add_parser("set", help=_("change a setting"))
    s.add_argument("key", choices=["decision_timeout", "killswitch_auto", "whois", "watchdog", "log_allowed",
                                   "max_pending"])
    s.add_argument("value")
    s = sub.add_parser("kill", help=_("terminate a process"))
    s.add_argument("pid", type=int)
    sub.add_parser("reload", help=_("reload configuration and rules"))
    sub.add_parser("log", help=_("follow the log (journal)"))
    a = p.parse_args(argv)
    if not a.cmd:
        p.print_help()
        return 0
    if a.cmd == "log":
        os.execvp("journalctl", ["journalctl", "-u", "varco.service", "-f", "-n", "50"])
    try:
        cl = Client()
        if a.cmd == "status":
            cmd_status(cl, a)
        elif a.cmd == "monitor":
            monitor(cl)
        elif a.cmd == "rules":
            cmd_rules(cl, a)
        elif a.cmd == "connections":
            cmd_connections(cl, a)
        elif a.cmd == "add":
            r = cl.add_rule({"action": a.action, "dir": a.dir, "app": a.program, "host": a.host, "port": a.port,
                             "proto": a.proto, "iface": a.network, "note": "cli"})
            print(r["message"])
        elif a.cmd == "remove":
            print(cl.remove_rule(a.id)["message"])
        elif a.cmd == "killswitch":
            cl.killswitch(a.state == "on")
            print(_("Kill switch ON: computer isolated") if a.state == "on" else _("Kill switch off: network reopened"))
        elif a.cmd == "pause":
            cl.pause(a.state == "on")
            print(_("Protection PAUSED") if a.state == "on" else _("Protection resumed"))
        elif a.cmd == "set":
            v = a.value
            if a.key in ("whois", "watchdog", "log_allowed"):
                v = v.lower() in ("1", "true", "yes", "on", "si", "sì")
            elif a.key in ("decision_timeout", "max_pending"):
                v = int(v)
            print(cl.set_setting(a.key, v)["message"])
        elif a.cmd == "kill":
            print(cl.kill(a.pid)["message"])
        elif a.cmd == "reload":
            cl.reload()
            print(_("Configuration and rules reloaded"))
    except GLib.Error as e:
        die(_("Cannot reach the system bus: {err}").format(err=e.message))
    except NotRunning:
        die(_("The Varco service is not running. If it is enabled, new connections stay blocked until it "
              "is back: see 'systemctl status varco'."))
    except NotAuthorized:
        die(_("Not authorized. Run the command with sudo."))
    return 0
