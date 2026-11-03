# SPDX-License-Identifier: GPL-3.0-or-later
"""varcod: system service. Runs the firewall engine and exposes it on the D-Bus system bus.
Every method call is authorized with polkit (root is always allowed)."""
import json
import os
import signal
import sys
import time

from gi.repository import Gio, GLib

from . import DBUS_IFACE, DBUS_NAME, DBUS_PATH, VERSION
from .core import Core
from .util import log

ACTION_MONITOR = "org.k1m1k.varco.monitor"
ACTION_DECIDE = "org.k1m1k.varco.decide"
ACTION_MANAGE = "org.k1m1k.varco.manage"

INTROSPECTION = f"""
<node>
  <interface name="{DBUS_IFACE}">
    <method name="GetState"><arg type="s" name="json" direction="out"/></method>
    <method name="GetEvents">
      <arg type="t" name="since" direction="in"/>
      <arg type="t" name="seq" direction="out"/>
      <arg type="s" name="json" direction="out"/>
    </method>
    <method name="GetPending"><arg type="s" name="json" direction="out"/></method>
    <method name="GetConnections"><arg type="s" name="json" direction="out"/></method>
    <method name="GetRules"><arg type="s" name="json" direction="out"/></method>
    <method name="Decide">
      <arg type="u" name="id" direction="in"/>
      <arg type="s" name="choice" direction="in"/>
      <arg type="s" name="json" direction="out"/>
    </method>
    <method name="SetKillSwitch">
      <arg type="b" name="on" direction="in"/>
      <arg type="s" name="json" direction="out"/>
    </method>
    <method name="SetPaused">
      <arg type="b" name="on" direction="in"/>
      <arg type="s" name="json" direction="out"/>
    </method>
    <method name="AddRule">
      <arg type="s" name="rule" direction="in"/>
      <arg type="s" name="json" direction="out"/>
    </method>
    <method name="RemoveRule">
      <arg type="u" name="id" direction="in"/>
      <arg type="s" name="json" direction="out"/>
    </method>
    <method name="SetSetting">
      <arg type="s" name="key" direction="in"/>
      <arg type="s" name="value" direction="in"/>
      <arg type="s" name="json" direction="out"/>
    </method>
    <method name="KillProcess">
      <arg type="i" name="pid" direction="in"/>
      <arg type="s" name="json" direction="out"/>
    </method>
    <method name="Reload"><arg type="s" name="json" direction="out"/></method>
    <property name="Version" type="s" access="read"/>
  </interface>
</node>
"""


class Service:
    def __init__(self, core):
        self.core = core
        self.bus = None
        self.auth_cache = {}

    # -------------------------------------------------------------- polkit
    def caller_uid(self, sender):
        r = self.bus.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                               "GetConnectionUnixUser", GLib.Variant("(s)", (sender,)), GLib.VariantType("(u)"),
                               Gio.DBusCallFlags.NONE, 2000, None)
        return r.unpack()[0]

    def authorize(self, sender, action, interactive, done):
        """Call done(authorized: bool, uid) asynchronously."""
        try:
            uid = self.caller_uid(sender)
        except GLib.Error:
            done(False, None)
            return
        if uid == 0:
            done(True, 0)
            return
        key = (sender, action)
        if self.auth_cache.get(key, 0) > time.monotonic():
            done(True, uid)
            return
        subject = ("system-bus-name", {"name": GLib.Variant("s", sender)})
        args = GLib.Variant("((sa{sv})sa{ss}us)", (subject, action, {}, 1 if interactive else 0, ""))

        def finished(bus, res):
            try:
                ok = bus.call_finish(res).unpack()[0][0]
            except GLib.Error as e:
                log(f"polkit: {e.message}")
                ok = False
            if ok and action != ACTION_MANAGE:
                now = time.monotonic()
                if len(self.auth_cache) > 500:      # every client connection has its own name
                    self.auth_cache = {k: t for k, t in self.auth_cache.items() if t > now}
                self.auth_cache[key] = now + 60
            done(ok, uid)

        self.bus.call("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority",
                      "org.freedesktop.PolicyKit1.Authority", "CheckAuthorization", args,
                      GLib.VariantType("((bba{ss}))"), Gio.DBusCallFlags.NONE, 300000, None, finished)

    # -------------------------------------------------------------- methods
    def action_for(self, method, params):
        if method in ("GetState", "GetEvents", "GetPending", "GetConnections", "GetRules"):
            return ACTION_MONITOR
        if method == "Decide":
            return ACTION_DECIDE
        if method == "SetKillSwitch":
            return ACTION_DECIDE if params[0] else ACTION_MANAGE   # isolating is easy, reopening needs care
        if method == "SetPaused":
            return ACTION_DECIDE if not params[0] else ACTION_MANAGE   # resuming is easy, pausing needs password
        if method == "KillProcess":
            return ACTION_DECIDE   # own processes only, unless the caller is root (checked in core.kill)
        return ACTION_MANAGE

    def run_method(self, method, p, uid):
        c = self.core
        if method == "GetState":
            return c.state()
        if method == "GetEvents":
            seq, evs = c.events(p[0])
            return seq, evs
        if method == "GetPending":
            return c.pending_list()
        if method == "GetConnections":
            return c.connections()
        if method == "GetRules":
            return c.rules.list
        if method == "Decide":
            return c.decide(int(p[0]), p[1], uid)
        if method == "SetKillSwitch":
            c.set_killswitch(bool(p[0]), "manual" if p[0] else "")
            return {"ok": True}
        if method == "SetPaused":
            c.set_paused(bool(p[0]))
            return {"ok": True}
        if method == "AddRule":
            return c.add_rule(json.loads(p[0]))
        if method == "RemoveRule":
            return c.remove_rule(int(p[0]))
        if method == "SetSetting":
            ok, msg = c.set_setting(p[0], json.loads(p[1]))
            if ok:
                c.reload()
            return {"ok": ok, "message": msg}
        if method == "KillProcess":
            ok, msg = c.kill(int(p[0]), uid)
            return {"ok": ok, "message": msg}
        if method == "Reload":
            c.reload()
            return {"ok": True}
        raise ValueError(method)

    def on_call(self, conn, sender, path, iface, method, params, inv):
        p = params.unpack()
        action = self.action_for(method, p)

        def done(ok, uid):
            if not ok:
                inv.return_dbus_error("org.k1m1k.Varco1.Error.NotAuthorized", "not authorized")
                return
            if method == "KillProcess" and uid != 0 and not self.owns(uid, p[0]):
                # someone else's process (or a system one): requires the administrator password
                self.authorize(sender, ACTION_MANAGE, True, lambda ok2, _u: finish(ok2, 0))
                return
            finish(True, uid)

        def finish(ok, uid):
            if not ok:
                inv.return_dbus_error("org.k1m1k.Varco1.Error.NotAuthorized", "not authorized")
                return
            try:
                res = self.run_method(method, p, uid)
            except Exception as e:  # report, never crash the firewall
                log(f"D-Bus {method}: {e!r}")
                inv.return_dbus_error("org.k1m1k.Varco1.Error.Failed", str(e))
                return
            if method == "GetEvents":
                inv.return_value(GLib.Variant("(ts)", (res[0], json.dumps(res[1], ensure_ascii=False))))
            else:
                inv.return_value(GLib.Variant("(s)", (json.dumps(res, ensure_ascii=False),)))

        self.authorize(sender, action, action == ACTION_MANAGE, done)

    @staticmethod
    def owns(uid, pid):
        try:
            return os.stat(f"/proc/{int(pid)}").st_uid == uid
        except (OSError, ValueError):
            return True   # gone: core.kill reports it

    def get_property(self, conn, sender, path, iface, prop):
        return GLib.Variant("s", VERSION) if prop == "Version" else None

    def on_bus(self, conn, name):
        self.bus = conn
        node = Gio.DBusNodeInfo.new_for_xml(INTROSPECTION)
        conn.register_object(DBUS_PATH, node.interfaces[0], self.on_call, self.get_property, None)

    def run(self):
        loop = GLib.MainLoop()
        Gio.bus_own_name(Gio.BusType.SYSTEM, DBUS_NAME, Gio.BusNameOwnerFlags.NONE, self.on_bus,
                         lambda *a: log("D-Bus name acquired: " + DBUS_NAME),
                         lambda *a: log("D-Bus name lost or not available: the firewall keeps working"))
        GLib.unix_signal_add(GLib.PRIORITY_HIGH, signal.SIGTERM, self.stop, loop)
        GLib.unix_signal_add(GLib.PRIORITY_HIGH, signal.SIGINT, self.stop, loop)
        GLib.unix_signal_add(GLib.PRIORITY_HIGH, signal.SIGHUP, lambda *a: (self.core.reload(), True)[1])
        loop.run()

    def stop(self, loop):
        if self.core.watchdog:
            self.core.watchdog.save()
        loop.quit()
        return False


def main():
    if os.geteuid() != 0:
        print("varcod must run as root", file=sys.stderr)
        return 1
    core = Core()
    core.start()
    Service(core).run()
    return 0
