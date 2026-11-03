# SPDX-License-Identifier: GPL-3.0-or-later
"""Synchronous D-Bus client of varcod (used by the command line tool)."""
import json

from gi.repository import Gio, GLib

from . import DBUS_IFACE, DBUS_NAME, DBUS_PATH


class NotRunning(Exception):
    pass


class NotAuthorized(Exception):
    pass


class Client:
    def __init__(self):
        self.bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)

    def call(self, method, sig=None, *args, timeout=330000):
        params = GLib.Variant(sig, args) if sig else None
        try:
            r = self.bus.call_sync(DBUS_NAME, DBUS_PATH, DBUS_IFACE, method, params, None,
                                   Gio.DBusCallFlags.ALLOW_INTERACTIVE_AUTHORIZATION, timeout, None)
        except GLib.Error as e:
            if "ServiceUnknown" in e.message or "NameHasNoOwner" in e.message:
                raise NotRunning() from e
            if "NotAuthorized" in e.message:
                raise NotAuthorized() from e
            raise
        v = r.unpack()
        if method == "GetEvents":
            return v[0], json.loads(v[1])
        return json.loads(v[0])

    def state(self):
        return self.call("GetState")

    def events(self, since):
        return self.call("GetEvents", "(t)", since)

    def pending(self):
        return self.call("GetPending")

    def connections(self):
        return self.call("GetConnections")

    def rules(self):
        return self.call("GetRules")

    def decide(self, rid, choice):
        return self.call("Decide", "(us)", rid, choice)

    def killswitch(self, on):
        return self.call("SetKillSwitch", "(b)", on)

    def pause(self, on):
        return self.call("SetPaused", "(b)", on)

    def add_rule(self, rule):
        return self.call("AddRule", "(s)", json.dumps(rule))

    def remove_rule(self, rid):
        return self.call("RemoveRule", "(u)", rid)

    def set_setting(self, key, value):
        return self.call("SetSetting", "(ss)", key, json.dumps(value))

    def kill(self, pid):
        return self.call("KillProcess", "(i)", pid)

    def reload(self):
        return self.call("Reload")
