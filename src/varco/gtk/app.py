# SPDX-License-Identifier: GPL-3.0-or-later
"""varco-gtk: application, connection to the service, desktop notifications.
Runs as the desktop user; every action is authorized by the service through polkit."""
import json
import os
import shutil
import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from .. import APP_ID, DBUS_IFACE, DBUS_NAME, DBUS_PATH, VERSION, _  # noqa: E402
from .. import paths  # noqa: E402
from ..texts import killswitch_reason, network_text, port_text, program_name, where  # noqa: E402

POLL_MS = 700
ERR_UNKNOWN = ("org.freedesktop.DBus.Error.ServiceUnknown", "org.freedesktop.DBus.Error.NameHasNoOwner")
ERR_AUTH = "org.k1m1k.Varco1.Error.NotAuthorized"


def remote_error(e):
    return Gio.dbus_error_get_remote_error(e) or ""


class Service:
    """Asynchronous calls to varcod. Callbacks receive (result, error_name, message)."""

    def __init__(self):
        self.proxy = Gio.DBusProxy.new_for_bus_sync(
            Gio.BusType.SYSTEM,
            Gio.DBusProxyFlags.DO_NOT_LOAD_PROPERTIES | Gio.DBusProxyFlags.DO_NOT_CONNECT_SIGNALS
            | Gio.DBusProxyFlags.DO_NOT_AUTO_START,
            None, DBUS_NAME, DBUS_PATH, DBUS_IFACE, None)

    def call(self, method, params=None, callback=None, timeout=330000):
        def done(proxy, res, _data):
            try:
                v = proxy.call_finish(res).unpack()
                result = (v[0], json.loads(v[1])) if method == "GetEvents" else json.loads(v[0])
                err = msg = None
            except GLib.Error as e:
                result, err, msg = None, remote_error(e) or "error", e.message
            if callback:
                callback(result, err, msg)
        self.proxy.call(method, params, Gio.DBusCallFlags.ALLOW_INTERACTIVE_AUTHORIZATION, timeout, None, done, None)


class Systemd:
    """Read-only view of the varco.service unit (allowed to every user)."""

    def __init__(self):
        self.bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)

    def _call(self, path, iface, method, params, rtype, cb):
        self.bus.call("org.freedesktop.systemd1", path, iface, method, params, GLib.VariantType(rtype),
                      Gio.DBusCallFlags.NONE, 5000, None, cb)

    def query(self, callback):
        """callback(active_state, unit_file_state); states are '' when unknown."""
        result = {}

        def got_file_state(bus, res):
            try:
                result["file"] = bus.call_finish(res).unpack()[0]
            except GLib.Error:
                result["file"] = ""
            self._call("/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "GetUnit",
                       GLib.Variant("(s)", ("varco.service",)), "(o)", got_unit)

        def got_unit(bus, res):
            try:
                path = bus.call_finish(res).unpack()[0]
            except GLib.Error:
                callback("inactive", result["file"])     # not loaded: inactive
                return
            self._call(path, "org.freedesktop.DBus.Properties", "Get",
                       GLib.Variant("(ss)", ("org.freedesktop.systemd1.Unit", "ActiveState")), "(v)", got_active)

        def got_active(bus, res):
            try:
                active = bus.call_finish(res).unpack()[0]
            except GLib.Error:
                active = ""
            callback(active, result["file"])

        self._call("/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "GetUnitFileState",
                   GLib.Variant("(s)", ("varco.service",)), "(s)", got_file_state)


class VarcoApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.add_main_option("background", 0, GLib.OptionFlags.NONE, GLib.OptionArg.NONE,
                             _("Start without opening the window (used at login)"), None)
        self.start_hidden = False
        self.window = None
        self.svc = None
        self.seq = 0
        self.polling = False
        # connecting | ok | off | denied | stopped (enabled but not running: network BLOCKED) | restarting
        self.status = "connecting"
        self.systemd = None
        self.unit_check = 0
        self.state = {}
        self.pending = {}
        self.rules = []
        self.activity = []
        self.processes = []

    # ------------------------------------------------------------------ lifecycle
    def do_handle_local_options(self, options):
        if options.contains("background"):
            self.start_hidden = True
        return -1

    def do_startup(self):
        Adw.Application.do_startup(self)
        self.hold()   # keep running in the background to deliver notifications
        for name, ptype, cb in (
            ("decide", "(us)", self.on_decide_action),
            ("show-request", "u", self.on_show_request),
            ("kill", "i", self.on_kill_action),
            ("show", None, lambda *a: self.present_window()),
            ("show-programs", None, lambda *a: self.present_window("programs")),
            ("show-requests", None, lambda *a: self.present_window("requests")),
            ("preferences", None, lambda *a: self.present_window() and self.window.show_preferences()),
            ("about", None, lambda *a: self.show_about()),
            ("service-on", None, lambda *a: self.present_window() and self.window.ask_enable()),
            ("service-off", None, lambda *a: self.present_window() and self.window.ask_disable()),
            ("uninstall", None, lambda *a: self.present_window() and self.window.ask_uninstall()),
            ("quit", None, lambda *a: self.quit_app()),
        ):
            a = Gio.SimpleAction.new(name, GLib.VariantType(ptype) if ptype else None)
            a.connect("activate", cb)
            self.add_action(a)
        self.set_accels_for_action("app.quit", ["<Control>q"])
        try:
            self.svc = Service()
            self.systemd = Systemd()
        except GLib.Error as e:
            print(f"varco-gtk: cannot reach the system bus: {e.message}", file=sys.stderr)
        GLib.timeout_add(POLL_MS, self.poll)
        self.poll()

    def do_activate(self):
        if self.start_hidden:
            self.start_hidden = False
            return
        self.present_window()

    def present_window(self, page=None):
        if self.window is None:
            from .window import MainWindow
            self.window = MainWindow(self)
        self.window.present()
        if page:
            self.window.stack.set_visible_child_name(page)
        return True

    def quit_app(self):
        if self.window:
            self.window.destroy()
        self.release()
        self.quit()

    def show_about(self):
        about = Adw.AboutDialog(
            application_name="Varco", application_icon=APP_ID, version=VERSION,
            developer_name="K1m1k", license_type=Gtk.License.GPL_3_0,
            website="https://github.com/K1m1k/varco",
            issue_url="https://github.com/K1m1k/varco/issues",
            comments=_("Interactive per-application firewall, process watchdog and privacy tools."))
        about.present(self.window)

    # ------------------------------------------------------------------ service
    def call(self, method, params=None, callback=None):
        if not self.svc:
            if callback:
                callback(None, "nobus", _("System bus not available"))
            return

        def done(res, err, msg):
            if err in ERR_UNKNOWN:
                self.service_down()
            if callback:
                callback(res, err, msg)
        self.svc.call(method, params, done)

    def service_down(self):
        """The service does not answer: ask systemd whether the network is blocked or free."""
        now = GLib.get_monotonic_time()
        if not self.systemd or now - self.unit_check < 2_500_000:
            return
        self.unit_check = now

        def got(active, file_state):
            if active in ("activating", "reloading", "deactivating"):
                self.set_status("restarting")
            elif file_state in ("enabled", "enabled-runtime") or active == "failed":
                self.set_status("stopped")      # failsafe table loaded: new connections are dropped
            else:
                self.set_status("off")
        self.systemd.query(got)

    def set_status(self, status):
        if status != self.status:
            self.status = status
            if status != "ok":
                for rid in list(self.pending):
                    self.withdraw_notification(f"req-{rid}")
                self.pending.clear()
            if self.window:
                self.window.refresh_all()

    def poll(self):
        if self.polling or not self.svc:
            return True
        self.polling = True

        def got(res, err, msg):
            self.polling = False
            if err:
                if err == ERR_AUTH:
                    self.set_status("denied")
                elif err not in ERR_UNKNOWN:
                    self.service_down()
                return
            seq, events = res
            if self.status != "ok" or seq < self.seq:
                self.seq = seq
                self.set_status("ok")
                self.reload_all()
                return
            self.seq = seq
            for ev in events:
                self.handle_event(ev)
        self.call("GetEvents", GLib.Variant("(t)", (self.seq,)), got)
        return True

    def reload_all(self):
        def got_state(res, err, msg):
            if res is not None:
                self.state = res
                if self.window:
                    self.window.refresh_state()

        def got_pending(res, err, msg):
            if res is None:
                return
            self.pending = {ev["id"]: ev for ev in res}
            for ev in res:
                self.notify_request(ev)
            if self.window:
                self.window.refresh_requests()
        self.call("GetState", None, got_state)
        self.call("GetPending", None, got_pending)
        self.load_rules()

    def load_rules(self):
        def got(res, err, msg):
            if res is not None:
                self.rules = res
                if self.window:
                    self.window.refresh_rules()
        self.call("GetRules", None, got)

    # ------------------------------------------------------------------ events
    def handle_event(self, ev):
        t = ev["ev"]
        w = self.window
        if t == "request":
            self.pending[ev["id"]] = ev
            self.notify_request(ev)
            if w:
                w.refresh_requests()
        elif t == "tamper":
            n = Gio.Notification.new(_("Firewall table restored"))
            n.set_body(_("Another program removed or changed the Varco rules. They were loaded again."))
            n.set_priority(Gio.NotificationPriority.HIGH)
            n.set_default_action("app.show")
            self.send_notification("tamper", n)
        elif t == "overload":
            if w:
                w.toast(_("Too many connection requests at once: the extra ones are blocked"))
        elif t == "info":
            req = self.pending.get(ev["id"])
            if req:
                req.update({k: ev[k] for k in ("who", "ptr", "what")})
                if w:
                    w.refresh_requests()
        elif t == "decided":
            self.pending.pop(ev["id"], None)
            self.withdraw_notification(f"req-{ev['id']}")
            if len(self.pending) <= 3:
                self.withdraw_notification("req-summary")
            if ev.get("rule"):
                self.load_rules()
            if w:
                w.refresh_requests()
        elif t == "activity":
            self.activity.insert(0, ev)
            del self.activity[400:]
            if w:
                w.add_activity(ev)
        elif t == "process":
            self.processes.insert(0, ev)
            del self.processes[300:]
            if ev["suspicious"]:
                n = Gio.Notification.new(_("Suspicious program started"))
                n.set_body(f"{program_name(ev['app'])} (pid {ev['pid']})\n" + "; ".join(ev["suspicious"]))
                n.set_priority(Gio.NotificationPriority.HIGH)
                n.set_icon(Gio.ThemedIcon.new("dialog-warning"))
                n.set_default_action("app.show-programs")
                n.add_button_with_target(_("Terminate"), "app.kill", GLib.Variant("i", ev["pid"]))
                self.send_notification(f"proc-{ev['pid']}", n)
            if w:
                w.add_process(ev)
        elif t in ("killswitch", "paused"):
            key = "killswitch" if t == "killswitch" else "paused"
            self.state[key] = ev["on"]
            if t == "killswitch":
                self.state["killswitch_reason"] = ev.get("reason", "")
                if ev["on"]:
                    n = Gio.Notification.new(_("Kill switch ON: computer isolated"))
                    n.set_body(killswitch_reason(ev.get("reason", "")))
                    n.set_priority(Gio.NotificationPriority.URGENT)
                    n.set_default_action("app.show")
                    self.send_notification("killswitch", n)
                else:
                    self.withdraw_notification("killswitch")
            if w:
                w.refresh_state()

    def notify_request(self, ev):
        if len(self.pending) > 3:
            # many requests together (for example right after turning protection on):
            # one summary instead of a flood of notifications
            n = Gio.Notification.new(_("{n} connections are waiting for your decision").format(n=len(self.pending)))
            n.set_body(_("Open Varco to decide."))
            n.set_priority(Gio.NotificationPriority.HIGH)
            n.set_icon(Gio.ThemedIcon.new(APP_ID))
            n.set_default_action("app.show-requests")
            self.send_notification("req-summary", n)
            return
        c = ev["c"]
        if c["dir"] == "out":
            title = _("{prog} wants to connect to the internet").format(prog=program_name(c.get("app")))
            body = f"{where(c)}\n{port_text(c['port'], c['proto'])} · {network_text(c.get('iface_kind'))}"
        else:
            title = _("Someone outside wants to connect to this computer")
            body = f"{where(c)} → {program_name(c.get('app'))}\n{port_text(c['port'], c['proto'])}"
        n = Gio.Notification.new(title)
        n.set_body(body)
        n.set_priority(Gio.NotificationPriority.URGENT)
        n.set_icon(Gio.ThemedIcon.new(APP_ID))
        n.set_default_action_and_target("app.show-request", GLib.Variant("u", ev["id"]))
        n.add_button_with_target(_("Allow always"), "app.decide", GLib.Variant("(us)", (ev["id"], "allow-always")))
        n.add_button_with_target(_("Only this time"), "app.decide", GLib.Variant("(us)", (ev["id"], "allow-once")))
        n.add_button_with_target(_("Block"), "app.decide", GLib.Variant("(us)", (ev["id"], "deny-once")))
        self.send_notification(f"req-{ev['id']}", n)

    # ------------------------------------------------------------------ actions
    def decide(self, rid, choice):
        def done(res, err, msg):
            text = (res or {}).get("message") or msg or ""
            if self.window:
                self.window.toast(text)
        self.call("Decide", GLib.Variant("(us)", (rid, choice)), done)

    def on_decide_action(self, action, param):
        rid, choice = param.unpack()
        self.decide(rid, choice)

    def on_show_request(self, action, param):
        self.present_window("requests")
        rid = param.unpack()
        if rid in self.pending:
            self.window.open_request(rid)

    def on_kill_action(self, action, param):
        self.kill(param.unpack())

    def kill(self, pid):
        def done(res, err, msg):
            text = (res or {}).get("message") or (_("Not authorized") if err == ERR_AUTH else msg or "")
            if self.window:
                self.window.toast(text)
        self.call("KillProcess", GLib.Variant("(i)", (pid,)), done)

    def run_privileged(self, argv, callback):
        """Run a privileged tool through pkexec; callback(ok, output)."""
        if not shutil.which("pkexec"):
            callback(False, _("pkexec is not installed"))
            return
        try:
            proc = Gio.Subprocess.new(["pkexec"] + argv,
                                      Gio.SubprocessFlags.STDOUT_PIPE | Gio.SubprocessFlags.STDERR_MERGE)
        except GLib.Error as e:
            callback(False, e.message)
            return

        def done(p, res):
            try:
                _ok, out, _err = p.communicate_utf8_finish(res)
            except GLib.Error as e:
                callback(False, e.message)
                return
            code = p.get_exit_status()
            if code in (126, 127) and not (out or "").strip():
                callback(False, _("Password not entered: operation cancelled."))
            else:
                callback(code == 0, (out or "").strip())
        proc.communicate_utf8_async(None, None, done)

    def anon_available(self):
        return os.path.exists(paths.ANON_TOOL)


def main(argv=None):
    app = VarcoApp()
    return app.run(argv if argv is not None else sys.argv)
