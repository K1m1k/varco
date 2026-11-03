# SPDX-License-Identifier: GPL-3.0-or-later
"""Main window and dialogs."""
import json
import time

from gi.repository import Adw, Gdk, Gio, GLib, Gtk

from .. import _, paths
from ..texts import (killswitch_reason, network_text, port_text, program_name, reason_text, rule_host_text,
                     rule_network_text, where)

ERR_AUTH = "org.k1m1k.Varco1.Error.NotAuthorized"


# ---------------------------------------------------------------------- helpers

def copy_text(widget, text):
    cb = widget.get_clipboard()
    try:
        cb.set(text)
    except (TypeError, AttributeError):
        cb.set_content(Gdk.ContentProvider.new_for_value(text))


def row(title, subtitle="", selectable=True, activatable=False):
    r = Adw.ActionRow()
    r.set_use_markup(False)
    r.set_title(title)
    if subtitle:
        r.set_subtitle(subtitle)
    r.set_title_selectable(selectable)
    r.set_subtitle_selectable(selectable)
    r.set_activatable(activatable)
    return r


def icon(name, css=None):
    i = Gtk.Image.new_from_icon_name(name)
    if css:
        i.add_css_class(css)
    return i


def button(label, css=None, cb=None, valign=Gtk.Align.CENTER):
    b = Gtk.Button(label=label, valign=valign)
    for c in (css or "").split():
        b.add_css_class(c)
    if cb:
        b.connect("clicked", lambda *_a: cb())
    return b


def boxed_list():
    lb = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
    lb.add_css_class("boxed-list")
    return lb


def page_scroller(child, maximum=960):
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=18, margin_bottom=18,
                  margin_start=12, margin_end=12)
    box.append(child)
    clamp = Adw.Clamp(maximum_size=maximum, child=box)
    sw = Gtk.ScrolledWindow(child=clamp, vexpand=True)
    sw.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    return sw


def text_dialog(parent, title, text):
    """Dialog showing a selectable, copyable text (errors, details)."""
    d = Adw.Dialog(title=title, content_width=640, content_height=420)
    tv = Adw.ToolbarView()
    hb = Adw.HeaderBar()
    copy = button(_("Copy"), "flat", lambda: (copy_text(d, text), None))
    hb.pack_start(copy)
    tv.add_top_bar(hb)
    lab = Gtk.Label(label=text, selectable=True, wrap=True, xalign=0, yalign=0,
                    margin_top=12, margin_bottom=12, margin_start=12, margin_end=12)
    lab.add_css_class("monospace")
    tv.set_content(Gtk.ScrolledWindow(child=lab, vexpand=True))
    d.set_child(tv)
    d.present(parent)


def confirm(parent, heading, body, ok_label, destructive, callback):
    d = Adw.AlertDialog(heading=heading, body=body)
    d.add_response("cancel", _("Cancel"))
    d.add_response("ok", ok_label)
    d.set_response_appearance("ok", Adw.ResponseAppearance.DESTRUCTIVE if destructive
                              else Adw.ResponseAppearance.SUGGESTED)
    d.set_default_response("cancel")
    d.set_close_response("cancel")
    d.connect("response", lambda _d, r: callback() if r == "ok" else None)
    d.present(parent)
    return d


def request_title(c):
    if c["dir"] == "out":
        return _("{prog} → {dest}").format(prog=program_name(c.get("app")), dest=where(c))
    return _("{src} → {prog}").format(src=where(c), prog=program_name(c.get("app")))


# ---------------------------------------------------------------------- request dialog

class RequestDialog(Adw.Dialog):
    def __init__(self, win, ev):
        super().__init__(title=_("Request #{id}").format(id=ev["id"]), content_width=620)
        self.win, self.ev, self.rid = win, ev, ev["id"]
        c = ev["c"]
        out = c["dir"] == "out"
        tv = Adw.ToolbarView()
        hb = Adw.HeaderBar()
        hb.pack_start(button(_("Copy details"), "flat", self.copy_details))
        tv.add_top_bar(hb)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14, margin_top=12, margin_bottom=18,
                      margin_start=18, margin_end=18)
        head = Gtk.Label(wrap=True, xalign=0)
        head.add_css_class("title-2")
        head.add_css_class("warning" if out else "error")
        head.set_text(_("{prog} wants to connect to the internet").format(prog=program_name(c.get("app"))) if out
                      else _("Someone outside wants to connect to this computer"))
        box.append(head)

        grp = boxed_list()
        if out:
            grp.append(row(_("Destination"), where(c)))
        else:
            grp.append(row(_("From"), f"{where(c)} ({_('port')} {c.get('rport')})"))
            grp.append(row(_("To"), program_name(c.get("app"))))
        grp.append(row(_("Service"), port_text(c["port"], c["proto"])))
        grp.append(row(_("Network"), network_text(c.get("iface_kind"), c.get("iface"))))
        self.who_row = row(_("Who it is"), ev.get("who") or _("looking it up…"))
        grp.append(self.who_row)
        grp.append(row(_("Program"), c.get("exe", "?")))
        self.what_row = row(_("What it is"), ev.get("what") or "…")
        grp.append(self.what_row)
        details = _("user {user}, pid {pid}").format(user=c.get("user", "?"), pid=c.get("pid") or "?")
        if c.get("parent"):
            details += ", " + _("started by {p}").format(p=c["parent"])
        if c.get("unit"):
            details += ", " + _("service {u}").format(u=c["unit"])
        grp.append(row(_("Process"), details))
        if c.get("cmd"):
            grp.append(row(_("Command"), c["cmd"][:300]))
        box.append(grp)

        if c["port"] == 53:
            box.append(self.note(_("This is the request to find the addresses of websites (DNS). "
                                   "Without it browsing does not work: it is usually allowed always."), "accent"))
        if "(stdin)" in (c.get("app") or ""):
            box.append(self.note(_("Code read from standard input (for example 'curl … | sh'). "
                                   "Do not allow it if you do not know what it is."), "error"))
        unknown = c.get("app") == "?"
        if c.get("shared"):
            box.append(self.note(_("The connection belongs to several different programs at once ({apps}): "
                                   "it is not possible to know which one sends it. Allow it only if you expect it.")
                                 .format(apps=", ".join(program_name(a) for a in c["shared"][:4])), "error"))
        elif unknown:
            box.append(self.note(_("The program could not be identified: only a rule for this address and port, "
                                   "or a decision for this time, is possible."), "warning"))
        if c.get("env"):
            box.append(self.note(_("The program was started with variables that make it load other code "
                                   "({env}). If you did not set them yourself, block it.").format(env=c["env"]),
                                 "error"))

        btns = Gtk.Box(spacing=8, homogeneous=True)
        btns.append(button(_("Allow always"), "suggested-action pill", lambda: self.decide("allow-always")))
        btns.append(button(_("Only this time"), "pill", lambda: self.decide("allow-once")))
        btns.append(button(_("Block"), "destructive-action pill", lambda: self.decide("deny-once")))
        box.append(btns)

        menu = Gio.Menu()
        if c.get("iface_kind") not in (None, "other", "loopback"):
            menu.append(_("Allow always, but only on {net}").format(net=network_text(c.get("iface_kind"))),
                        f"app.decide((uint32 {self.rid}, 'allow-network'))")
        menu.append(_("Block always (create a rule)"), f"app.decide((uint32 {self.rid}, 'deny-always'))")
        if not unknown:
            if out:
                menu.append(_("Allow this program to any site on port {p}").format(p=c["port"]),
                            f"app.decide((uint32 {self.rid}, 'allow-port'))")
            else:
                menu.append(_("Allow anyone on port {p}").format(p=c["port"]),
                            f"app.decide((uint32 {self.rid}, 'allow-port'))")
            menu.append(_("Allow everything for this program"), f"app.decide((uint32 {self.rid}, 'allow-app'))")
            menu.append(_("Block and close the program"), f"app.decide((uint32 {self.rid}, 'deny-kill'))")
        menu.append(_("Isolate the computer from the network"), f"app.decide((uint32 {self.rid}, 'killswitch'))")
        more = Gtk.MenuButton(label=_("Other choices"), menu_model=menu, halign=Gtk.Align.CENTER)
        more.add_css_class("flat")
        box.append(more)
        self.timer = Gtk.Label(xalign=1)
        self.timer.add_css_class("dim-label")
        box.append(self.timer)
        tv.set_content(Gtk.ScrolledWindow(child=box, propagate_natural_height=True, max_content_height=640))
        self.set_child(tv)
        self.tick()
        self.tick_id = GLib.timeout_add_seconds(1, self.tick)
        self.connect("closed", self.on_closed)

    @staticmethod
    def note(text, css):
        lab = Gtk.Label(label=text, wrap=True, xalign=0)
        lab.add_css_class(css)
        frame = Gtk.Frame(child=lab)
        lab.set_margin_top(8)
        lab.set_margin_bottom(8)
        lab.set_margin_start(10)
        lab.set_margin_end(10)
        return frame

    def tick(self):
        left = int(self.ev.get("deadline", time.time()) - time.time())
        self.timer.set_text(_("If you do not decide, it will be blocked in {n} s").format(n=max(0, left)))
        return left > 0

    def update(self, ev):
        self.ev = ev
        if ev.get("who"):
            self.who_row.set_subtitle(ev["who"])
        elif "who" in ev and ev.get("who") is None and not self.win.app.state.get("settings", {}).get("whois", True):
            self.who_row.set_subtitle(_("lookup turned off"))
        if ev.get("what"):
            self.what_row.set_subtitle(ev["what"])

    def decide(self, choice):
        self.win.app.decide(self.rid, choice)

    def copy_details(self):
        c = self.ev["c"]
        lines = [f"{_('Request')}: #{self.rid} {c['dir']}", f"{_('Program')}: {c.get('app')}",
                 f"{_('Command')}: {c.get('cmd', '')}", f"{_('User')}: {c.get('user')}", f"PID: {c.get('pid')}",
                 f"{_('Started by')}: {c.get('parent', '')}", f"{_('Service')}: {c.get('unit', '')}",
                 f"{_('Remote')}: {where(c)} {_('port')} {c.get('rport')}",
                 f"{_('Port')}: {c['port']}/{c['proto']}", f"{_('Who it is')}: {self.ev.get('who') or ''}",
                 f"{_('What it is')}: {self.ev.get('what') or ''}"]
        copy_text(self, "\n".join(lines))
        self.win.toast(_("Details copied"))

    def on_closed(self, *_a):
        GLib.source_remove(self.tick_id)
        self.win.dialogs.pop(self.rid, None)


# ---------------------------------------------------------------------- main window

class MainWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="Varco", default_width=1000, default_height=720)
        self.app = app
        self.dialogs = {}
        self.settings_lock = False
        self.set_icon_name("org.k1m1k.Varco")
        self.connect("close-request", self.on_close)

        self.toasts = Adw.ToastOverlay()
        tv = Adw.ToolbarView()
        hb = Adw.HeaderBar()
        self.stack = Adw.ViewStack()
        hb.set_title_widget(Adw.ViewSwitcher(stack=self.stack, policy=Adw.ViewSwitcherPolicy.WIDE))

        self.pause_btn = Gtk.Button()
        self.pause_btn.connect("clicked", lambda *_a: self.toggle_pause())
        hb.pack_start(self.pause_btn)
        menu = Gio.Menu()
        menu.append(_("Preferences"), "app.preferences")
        sec = Gio.Menu()
        sec.append(_("Turn protection on"), "app.service-on")
        sec.append(_("Turn protection off (stop the service)"), "app.service-off")
        sec.append(_("Uninstall Varco…"), "app.uninstall")
        menu.append_section(None, sec)
        sec2 = Gio.Menu()
        sec2.append(_("About Varco"), "app.about")
        sec2.append(_("Quit"), "app.quit")
        menu.append_section(None, sec2)
        hb.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu, tooltip_text=_("Menu")))
        self.ks_btn = Gtk.Button()
        self.ks_btn.connect("clicked", lambda *_a: self.toggle_killswitch())
        hb.pack_end(self.ks_btn)
        tv.add_top_bar(hb)

        self.banner = Adw.Banner()
        self.banner.connect("button-clicked", lambda *_a: self.banner_action())
        tv.add_top_bar(self.banner)

        self.build_requests()
        self.build_activity()
        self.build_programs()
        self.build_connections()
        self.build_rules()
        self.build_privacy()
        self.stack.connect("notify::visible-child-name", lambda *_a: self.on_page())

        bar = Adw.ViewSwitcherBar(stack=self.stack)
        tv.add_bottom_bar(bar)
        tv.set_content(self.stack)
        self.toasts.set_child(tv)
        self.set_content(self.toasts)

        bp = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 700sp"))
        bp.add_setter(bar, "reveal", True)
        bp.add_setter(hb, "title-widget", None)
        self.add_breakpoint(bp)

        for ev in app.activity[::-1]:
            self.add_activity(ev)
        for ev in app.processes[::-1]:
            self.add_process(ev)
        GLib.timeout_add_seconds(5, self.auto_refresh)
        self.refresh_all()

    def on_close(self, *_a):
        self.set_visible(False)   # keep running in the background for notifications
        return True

    def toast(self, text):
        if text:
            self.toasts.add_toast(Adw.Toast(title=GLib.markup_escape_text(text), timeout=4))

    def report(self, res, err, msg, ok_text=None):
        if err == ERR_AUTH:
            self.toast(_("Not authorized"))
        elif err:
            text_dialog(self, _("Error"), msg or err)
        else:
            self.toast((res or {}).get("message") or ok_text)

    # ------------------------------------------------------------------ state
    def refresh_all(self):
        self.refresh_state()
        self.refresh_requests()
        self.refresh_rules()

    def refresh_state(self):
        st, status = self.app.state, self.app.status
        paused, ks = st.get("paused"), st.get("killswitch")
        self.pause_btn.set_visible(status == "ok")
        self.ks_btn.set_visible(status == "ok")
        self.pause_btn.set_child(Adw.ButtonContent(
            icon_name="media-playback-start-symbolic" if paused else "media-playback-pause-symbolic",
            label=_("Resume protection") if paused else _("Pause")))
        for css in ("suggested-action", "destructive-action"):
            self.ks_btn.remove_css_class(css)
            self.pause_btn.remove_css_class(css)
        if paused:
            self.pause_btn.add_css_class("suggested-action")
        self.ks_btn.set_label(_("Reopen network") if ks else _("Isolate computer"))
        self.ks_btn.add_css_class("suggested-action" if ks else "destructive-action")
        self.ks_btn.set_tooltip_text(_("Kill switch: block all network traffic immediately"))
        if status == "off":
            self.banner.set_title(_("Protection is OFF: the network is not checked"))
            self.banner.set_button_label(_("Turn on…"))
            self.banner.set_revealed(True)
        elif status == "stopped":
            self.banner.set_title(_("The service stopped: for safety new connections are BLOCKED"))
            self.banner.set_button_label(_("Restart"))
            self.banner.set_revealed(True)
        elif status == "restarting":
            self.banner.set_title(_("The service is restarting… new connections wait"))
            self.banner.set_button_label(None)
            self.banner.set_revealed(True)
        elif status == "denied":
            self.banner.set_title(_("Not authorized: Varco can only be used from the active desktop session"))
            self.banner.set_button_label(None)
            self.banner.set_revealed(True)
        elif ks:
            self.banner.set_title(_("KILL SWITCH ON: the computer is isolated. {why}").format(
                why=killswitch_reason(st.get("killswitch_reason", ""))))
            self.banner.set_button_label(_("Reopen network"))
            self.banner.set_revealed(True)
        elif paused:
            self.banner.set_title(_("PROTECTION PAUSED: the network is free and not checked"))
            self.banner.set_button_label(_("Resume"))
            self.banner.set_revealed(True)
        else:
            self.banner.set_revealed(False)
        self.refresh_privacy()
        self.load_settings_rows()

    def banner_action(self):
        st, status = self.app.state, self.app.status
        if status == "off":
            self.ask_enable()
        elif status == "stopped":
            self.app.run_privileged([paths.HELPER, "restart"], lambda ok, out: self.toast(_("Service restarted"))
                                    if ok else text_dialog(self, _("Error"), out))
        elif st.get("killswitch"):
            self.toggle_killswitch()
        elif st.get("paused"):
            self.toggle_pause()

    def toggle_pause(self):
        if self.app.state.get("paused"):
            self.app.call("SetPaused", GLib.Variant("(b)", (False,)),
                          lambda r, e, m: self.report(r, e, m, _("Protection resumed")))
        else:
            confirm(self, _("Pause protection?"),
                    _("The network becomes free: no connection is checked until you resume. "
                      "The administrator password is required."),
                    _("Pause"), True,
                    lambda: self.app.call("SetPaused", GLib.Variant("(b)", (True,)),
                                          lambda r, e, m: self.report(r, e, m, _("Protection paused"))))

    def toggle_killswitch(self):
        if self.app.state.get("killswitch"):
            self.app.call("SetKillSwitch", GLib.Variant("(b)", (False,)),
                          lambda r, e, m: self.report(r, e, m, _("Network reopened")))
        else:
            confirm(self, _("Isolate the computer?"),
                    _("All network traffic stops immediately on every network (Wi-Fi, mobile, cable, VPN), "
                      "including connections already open and virtual machines or containers. "
                      "To stop a single connection use “Block” instead. "
                      "Reopening requires the administrator password."),
                    _("Isolate"), True,
                    lambda: self.app.call("SetKillSwitch", GLib.Variant("(b)", (True,)),
                                          lambda r, e, m: self.report(r, e, m, _("Computer isolated"))))

    # ------------------------------------------------------------------ service on/off, uninstall
    def ask_enable(self):
        d = Adw.AlertDialog(heading=_("Turn protection on"),
                            body=_("From now on every new connection, outgoing or incoming, waits for your "
                                   "permission. At first many requests will appear: approve the programs you use."))
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        dns = Gtk.CheckButton(label=_("Allow DNS requests (port 53), only towards the DNS servers of this "
                                      "computer"), active=True)
        system = Gtk.CheckButton(label=_("Allow essential system services (clock, Debian updates, "
                                         "connectivity check)"), active=True)
        autokill = Gtk.CheckButton(label=_("Isolate the computer by itself if someone from the internet tries to "
                                           "connect to a program that is listening (strict)"), active=False)
        ptrace = Gtk.CheckButton(label=_("Stop programs from taking control of other programs (ptrace, "
                                         "recommended: otherwise a program can make an approved one connect)"),
                                 active=True)
        box.append(dns)
        box.append(system)
        box.append(ptrace)
        box.append(autokill)
        d.set_extra_child(box)
        d.add_response("cancel", _("Cancel"))
        d.add_response("ok", _("Turn on"))
        d.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)
        d.set_close_response("cancel")

        def resp(_d, r):
            if r != "ok":
                return
            args = [paths.HELPER, "enable"] + (["dns"] if dns.get_active() else []) \
                + (["system"] if system.get_active() else []) + (["ptrace"] if ptrace.get_active() else []) \
                + (["autokill"] if autokill.get_active() else [])
            self.app.run_privileged(args, lambda ok, out: self.toast(_("Protection on")) if ok
                                    else text_dialog(self, _("Error"), out))
        d.connect("response", resp)
        d.present(self)

    def ask_disable(self):
        confirm(self, _("Turn protection off?"),
                _("The Varco service stops and the network is no longer checked, also after restarting."),
                _("Turn off"), True,
                lambda: self.app.run_privileged([paths.HELPER, "disable"],
                                                lambda ok, out: self.toast(_("Protection off")) if ok
                                                else text_dialog(self, _("Error"), out)))

    def ask_uninstall(self):
        def done(ok, out):
            if ok:
                self.app.quit_app()
            else:
                text_dialog(self, _("Error"), out)
        confirm(self, _("Uninstall Varco?"),
                _("The Varco packages are removed with everything they created: rules, settings, service. "
                  "The privacy module restores the original identifiers. The network becomes free."),
                _("Uninstall"), True,
                lambda: self.app.run_privileged([paths.HELPER, "uninstall"], done))

    # ------------------------------------------------------------------ requests page
    def build_requests(self):
        self.req_empty = Adw.StatusPage(icon_name="security-high-symbolic", title=_("Protection active"),
                                        description=_("Nothing is waiting for your decision. Connections not "
                                                      "covered by your rules will appear here and as notifications."))
        self.req_list = boxed_list()
        self.req_list.connect("row-activated", lambda _l, r: self.open_request(r.rid))
        self.req_stack = Gtk.Stack()
        self.req_stack.add_named(self.req_empty, "empty")
        self.req_stack.add_named(page_scroller(self.req_list), "list")
        self.req_page = self.stack.add_titled_with_icon(self.req_stack, "requests", _("Requests"),
                                                        "dialog-question-symbolic")

    def refresh_requests(self):
        self.req_list.remove_all()
        pending = sorted(self.app.pending.values(), key=lambda e: e["id"])
        for ev in pending:
            c = ev["c"]
            r = row(request_title(c), " · ".join(x for x in (port_text(c["port"], c["proto"]),
                                                             network_text(c.get("iface_kind")), ev.get("who"))
                                                    if x), selectable=False, activatable=True)
            r.rid = ev["id"]
            r.add_prefix(icon("go-up-symbolic" if c["dir"] == "out" else "go-down-symbolic",
                              "warning" if c["dir"] == "out" else "error"))
            r.add_suffix(button(_("Allow always"), "suggested-action",
                                lambda rid=ev["id"]: self.app.decide(rid, "allow-always")))
            r.add_suffix(button(_("Block"), "destructive-action",
                                lambda rid=ev["id"]: self.app.decide(rid, "deny-once")))
            r.add_suffix(icon("go-next-symbolic"))
            self.req_list.append(r)
            if ev["id"] in self.dialogs:
                self.dialogs[ev["id"]].update(ev)
        for rid, d in list(self.dialogs.items()):
            if rid not in self.app.pending:
                d.close()
        self.req_stack.set_visible_child_name("list" if pending else "empty")
        self.req_page.set_badge_number(len(pending))
        self.req_page.set_needs_attention(bool(pending))
        if self.app.status != "ok":
            self.req_empty.set_icon_name("security-low-symbolic")
            self.req_empty.set_title({"off": _("Protection off"), "stopped": _("Network blocked: service stopped"),
                                      "restarting": _("Restarting…")}.get(self.app.status, _("Not connected")))
        else:
            self.req_empty.set_icon_name("security-high-symbolic")
            self.req_empty.set_title(_("Protection active"))

    def open_request(self, rid):
        ev = self.app.pending.get(rid)
        if not ev:
            return
        if rid in self.dialogs:
            self.dialogs[rid].present(self)
            return
        d = RequestDialog(self, ev)
        self.dialogs[rid] = d
        d.present(self)

    # ------------------------------------------------------------------ activity page
    def build_activity(self):
        self.act_list = boxed_list()
        self.act_rows = []
        intro = Gtk.Label(label=_("Every new connection: allowed, blocked or waiting. The most recent first."),
                          xalign=0, wrap=True)
        intro.add_css_class("dim-label")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.append(intro)
        box.append(self.act_list)
        self.stack.add_titled_with_icon(page_scroller(box), "activity", _("Activity"), "view-list-symbolic")

    def add_activity(self, ev):
        c = ev["c"]
        verdict = ev["verdict"]
        label = {"allowed": _("allowed"), "blocked": _("blocked"), "pending": _("waiting")}[verdict]
        r = row(request_title(c) + f" :{c['port']}/{c['proto']}",
                f"{ev['ts']} · {label} · {reason_text(ev['reason'], ev.get('rule'))} · "
                f"{network_text(c.get('iface_kind'), c.get('iface'))}")
        r.add_prefix(icon({"allowed": "emblem-ok-symbolic", "blocked": "action-unavailable-symbolic",
                           "pending": "content-loading-symbolic"}[verdict],
                          {"allowed": "success", "blocked": "error", "pending": "warning"}[verdict]))
        self.act_list.prepend(r)
        self.act_rows.insert(0, r)
        while len(self.act_rows) > 300:
            self.act_list.remove(self.act_rows.pop())

    # ------------------------------------------------------------------ programs page
    def build_programs(self):
        self.proc_list = boxed_list()
        self.proc_list.connect("row-activated", lambda _l, r: self.process_details(r.ev))
        self.proc_rows = []
        intro = Gtk.Label(label=_("Programs started on this computer that were never seen before (NEW) or that "
                                  "behave in an unusual way (SUSPICIOUS). Suspicious is a hint to check, "
                                  "not a proof of malware."), xalign=0, wrap=True)
        intro.add_css_class("dim-label")
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.append(intro)
        box.append(self.proc_list)
        self.proc_page = self.stack.add_titled_with_icon(page_scroller(box), "programs", _("Programs"),
                                                         "application-x-executable-symbolic")

    def add_process(self, ev):
        tag = _("SUSPICIOUS") if ev["suspicious"] else _("NEW")
        r = row(f"{tag} · {program_name(ev['app'])}", f"{ev['ts']} · {ev['what']} · {ev['user']} · pid {ev['pid']}",
                selectable=False, activatable=True)
        r.ev = ev
        r.add_prefix(icon("dialog-warning-symbolic" if ev["suspicious"] else "list-add-symbolic",
                          "error" if ev["suspicious"] else "accent"))
        r.add_suffix(button(_("Terminate"), "flat", lambda pid=ev["pid"]: self.ask_kill(ev)))
        self.proc_list.prepend(r)
        self.proc_rows.insert(0, r)
        while len(self.proc_rows) > 300:
            self.proc_list.remove(self.proc_rows.pop())
        if ev["suspicious"]:
            self.proc_page.set_needs_attention(True)

    def ask_kill(self, ev):
        confirm(self, _("Terminate the program?"),
                f"{ev['app']} (pid {ev['pid']})", _("Terminate"), True, lambda: self.app.kill(ev["pid"]))

    def process_details(self, ev):
        lines = [f"{_('Program')}: {ev['app']}", f"{_('What it is')}: {ev['what']}",
                 f"{_('Command')}: {ev.get('cmd', '')}", f"{_('User')}: {ev['user']}   PID: {ev['pid']}",
                 f"{_('Started by')}: {ev.get('parent') or '?'}", f"{_('Service')}: {ev.get('unit') or '-'}"]
        if ev["suspicious"]:
            lines += ["", _("WHY IT IS SUSPICIOUS:")] + [f"- {m}" for m in ev["suspicious"]]
            lines += ["", _("It is a hint to check, not a proof that the program is harmful.")]
        text_dialog(self, program_name(ev["app"]), "\n".join(lines))

    # ------------------------------------------------------------------ connections page
    def build_connections(self):
        self.listen_list = boxed_list()
        self.conn_list = boxed_list()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        top = Gtk.Box(spacing=6)
        lab = Gtk.Label(label=_("What is connected now and which services accept connections from the network."),
                        xalign=0, wrap=True, hexpand=True)
        lab.add_css_class("dim-label")
        top.append(lab)
        top.append(button(_("Refresh"), "flat", self.load_connections))
        box.append(top)
        for title, lb in ((_("Listening on the network"), self.listen_list), (_("Active connections"), self.conn_list)):
            h = Gtk.Label(label=title, xalign=0)
            h.add_css_class("heading")
            box.append(h)
            box.append(lb)
        self.stack.add_titled_with_icon(page_scroller(box), "connections", _("Connections"),
                                        "network-transmit-receive-symbolic")

    def load_connections(self):
        def got(res, err, msg):
            if res is None:
                return
            self.listen_list.remove_all()
            self.conn_list.remove_all()
            for x in res:
                names = f" [{x['names'][0]}]" if x.get("names") else ""
                sub = (x["local"] if x["kind"] == "listening" else f"{x['local']} → {x['remote']}{names}")
                sub += f" · {x['proto']} · {x['user']}" + (f" · {x['unit']}" if x.get("unit") else "")
                r = row(program_name(x["app"]), sub)
                (self.listen_list if x["kind"] == "listening" else self.conn_list).append(r)
        if self.app.status == "ok":
            self.app.call("GetConnections", None, got)

    def auto_refresh(self):
        if self.get_visible() and self.stack.get_visible_child_name() == "connections":
            self.load_connections()
        return True

    def on_page(self):
        name = self.stack.get_visible_child_name()
        if name == "connections":
            self.load_connections()
        elif name == "privacy":
            self.refresh_privacy(force=True)
        elif name == "programs":
            self.proc_page.set_needs_attention(False)

    # ------------------------------------------------------------------ rules page
    def build_rules(self):
        self.rule_list = boxed_list()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        top = Gtk.Box(spacing=6)
        lab = Gtk.Label(label=_("Your permanent decisions. Whatever is not covered here is asked or blocked."),
                        xalign=0, wrap=True, hexpand=True)
        lab.add_css_class("dim-label")
        top.append(lab)
        top.append(button(_("Add rule…"), "flat", self.add_rule_dialog))
        box.append(top)
        box.append(self.rule_list)
        self.stack.add_titled_with_icon(page_scroller(box), "rules", _("Rules"), "view-list-bullet-symbolic")

    def refresh_rules(self):
        self.rule_list.remove_all()
        if not self.app.rules:
            self.rule_list.append(row(_("No rules yet"), _("Rules are created when you choose “Allow always” "
                                                          "or “Block always”."), selectable=False))
        for r in self.app.rules:
            allow = r["action"] == "allow"
            d = {"out": _("outbound"), "in": _("inbound"), "*": _("both directions")}[r["dir"]]
            title = (_("ALLOW") if allow else _("DENY")) + " · " + (program_name(r["app"]) if r["app"] != "*"
                                                                    else _("all programs"))
            sub = " · ".join([_("host {h}").format(h=rule_host_text(r["host"]) if r["host"] != "*" else _("any")),
                              _("port {p}").format(p=r["port"] if r["port"] != "*" else _("any")),
                              r["proto"], d, rule_network_text(r.get("iface", "*")), f"#{r['id']}",
                              r.get("created", "")])
            ro = row(title, sub)
            ro.add_prefix(icon("emblem-ok-symbolic" if allow else "action-unavailable-symbolic",
                               "success" if allow else "error"))
            delete = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER,
                                tooltip_text=_("Delete rule"))
            delete.add_css_class("flat")
            delete.connect("clicked", lambda _b, rule=r: self.ask_delete_rule(rule))
            ro.add_suffix(delete)
            self.rule_list.append(ro)

    def ask_delete_rule(self, r):
        confirm(self, _("Delete rule #{n}?").format(n=r["id"]),
                f"{r['action']} {r['app']} → {r['host']} : {r['port']}/{r['proto']}", _("Delete"), True,
                lambda: self.app.call("RemoveRule", GLib.Variant("(u)", (r["id"],)),
                                      lambda res, e, m: (self.report(res, e, m), self.app.load_rules())))

    def add_rule_dialog(self):
        d = Adw.Dialog(title=_("New rule"), content_width=520)
        tv = Adw.ToolbarView()
        tv.add_top_bar(Adw.HeaderBar())
        page = Adw.PreferencesPage()
        grp = Adw.PreferencesGroup(description=_("Use * for “any”. The program is the full path, "
                                                 "for example /usr/bin/curl."))
        action = Adw.ComboRow(title=_("Action"), model=Gtk.StringList.new([_("Allow"), _("Deny")]))
        direction = Adw.ComboRow(title=_("Direction"),
                                 model=Gtk.StringList.new([_("Outbound"), _("Inbound"), _("Both")]))
        prog = Adw.EntryRow(title=_("Program"), text="*")
        host = Adw.EntryRow(title=_("Host, network or name (*.example.org)"), text="*")
        port = Adw.EntryRow(title=_("Port"), text="*")
        proto = Adw.ComboRow(title=_("Protocol"), model=Gtk.StringList.new(["*", "tcp", "udp"]))
        nets = [("*", _("Any network")), ("@wifi", _("Wi-Fi")), ("@mobile", _("mobile network (WWAN)")),
                ("@ethernet", _("cable (Ethernet)")), ("@vpn", _("VPN"))]
        net = Adw.ComboRow(title=_("Network"), model=Gtk.StringList.new([n[1] for n in nets]))
        for w in (action, direction, prog, host, port, proto, net):
            grp.add(w)
        page.add(grp)
        save = button(_("Add"), "suggested-action pill", None, Gtk.Align.CENTER)
        save.set_halign(Gtk.Align.CENTER)
        save.set_margin_bottom(18)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        box.append(page)
        box.append(save)
        tv.set_content(box)
        d.set_child(tv)

        def do_save(*_a):
            p = port.get_text().strip() or "*"
            rule = {"action": ["allow", "deny"][action.get_selected()],
                    "dir": ["out", "in", "*"][direction.get_selected()],
                    "app": prog.get_text().strip() or "*", "host": host.get_text().strip() or "*",
                    "port": p if p == "*" else (int(p) if p.isdigit() else -1),
                    "proto": ["*", "tcp", "udp"][proto.get_selected()], "iface": nets[net.get_selected()][0],
                    "note": "gtk"}

            def done(res, err, msg):
                self.report(res, err, msg)
                if res and res.get("ok"):
                    self.app.load_rules()
                    d.close()
            self.app.call("AddRule", GLib.Variant("(s)", (json.dumps(rule),)), done)
        save.connect("clicked", do_save)
        d.present(self)

    # ------------------------------------------------------------------ privacy page
    def build_privacy(self):
        self.priv_stack = Gtk.Stack()
        missing = Adw.StatusPage(icon_name="security-medium-symbolic", title=_("Privacy module not installed"),
                                 description=_("The optional varco-privacy package randomizes the MAC address, "
                                               "uses a generic computer name, regenerates the machine-id and hides "
                                               "hardware serial numbers. Everything can be undone."))
        inst = button(_("Install the privacy module"), "suggested-action pill", self.install_anon)
        inst.set_halign(Gtk.Align.CENTER)
        missing.set_child(inst)
        self.priv_stack.add_named(missing, "missing")

        self.priv_page = Adw.PreferencesPage()
        g = Adw.PreferencesGroup(title=_("Protections"),
                                 description=_("Each change asks for the administrator password."))
        self.sw_mac = Adw.SwitchRow(title=_("Random MAC address"),
                                    subtitle=_("Routers and Wi-Fi networks no longer see the real address"))
        self.sw_hw = Adw.SwitchRow(title=_("Hide hardware serial numbers"),
                                   subtitle=_("Programs see generic values for motherboard, UUID and disks"))
        self.sw_mac.connect("notify::active", lambda *_a: self.priv_switch(self.sw_mac, "mac"))
        self.sw_hw.connect("notify::active", lambda *_a: self.priv_switch(self.sw_hw, "hardware"))
        g.add(self.sw_mac)
        g.add(self.sw_hw)
        self.row_host = row(_("Computer name"), "", selectable=True)
        self.row_host.add_suffix(button(_("Use “debian”"), "flat", lambda: self.anon(["hostname", "debian"])))
        g.add(self.row_host)
        self.row_mid = row(_("machine-id"), "", selectable=True)
        self.row_mid.add_suffix(button(_("Regenerate"), "flat", lambda: self.anon(["machine-id"])))
        g.add(self.row_mid)
        self.priv_page.add(g)
        g2 = Adw.PreferencesGroup(title=_("What this computer exposes"))
        self.priv_info = boxed_list()
        g2.add(self.priv_info)
        self.priv_page.add(g2)
        g3 = Adw.PreferencesGroup()
        rest = button(_("Restore all original values"), "destructive-action pill", lambda: confirm(
            self, _("Restore all original values?"), _("MAC address, computer name, machine-id and serial numbers "
                                                      "go back to the original values."),
            _("Restore"), True, lambda: self.anon(["restore"])))
        rest.set_halign(Gtk.Align.CENTER)
        g3.add(rest)
        self.priv_page.add(g3)
        self.priv_stack.add_named(self.priv_page, "ok")
        self.stack.add_titled_with_icon(self.priv_stack, "privacy", _("Privacy"), "security-medium-symbolic")
        self.priv_loaded = 0

    def install_anon(self):
        """The privacy module is not in the Debian archive: the user picks its .deb file."""
        fd = Gtk.FileDialog(title=_("Choose the file varco-privacy_….deb"), modal=True)
        flt = Gtk.FileFilter()
        flt.set_name(_("Varco privacy package"))
        flt.add_pattern("varco-privacy_*.deb")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(flt)
        fd.set_filters(filters)
        fd.set_default_filter(flt)

        def chosen(dlg, res):
            try:
                gf = dlg.open_finish(res)
            except GLib.Error:
                return              # cancelled
            path = gf.get_path() if gf else None
            if not path:
                return
            self.app.run_privileged([paths.HELPER, "install-privacy", path], lambda ok, out: (
                self.refresh_privacy(force=True) if ok else text_dialog(self, _("Error"), out)))
        fd.open(self, None, chosen)

    def refresh_privacy(self, force=False):
        if not self.app.anon_available():
            self.priv_stack.set_visible_child_name("missing")
            return
        self.priv_stack.set_visible_child_name("ok")
        if not force and time.monotonic() - self.priv_loaded < 30:
            return
        self.priv_loaded = time.monotonic()
        try:
            proc = Gio.Subprocess.new([paths.ANON_TOOL, "status", "--json"], Gio.SubprocessFlags.STDOUT_PIPE)
        except GLib.Error:
            return

        def done(p, res):
            try:
                _ok, out, _e = p.communicate_utf8_finish(res)
                st = json.loads(out)
            except (GLib.Error, ValueError):
                return
            self.show_privacy(st)
        proc.communicate_utf8_async(None, None, done)

    def show_privacy(self, st):
        self.settings_lock = True
        self.sw_mac.set_active(st["mac_random"])
        self.sw_hw.set_active(st["hardware_masked"])
        self.settings_lock = False
        self.row_host.set_subtitle(st["hostname"] + ("  ✔ " + _("changed") if st["hostname_changed"] else ""))
        self.row_mid.set_subtitle((st["machine_id"] or "?") + ("  ✔ " + _("changed") if st["machine_id_changed"]
                                                                 else ""))
        self.priv_info.remove_all()
        for i in st["interfaces"]:
            changed = i["current"].lower() != i["permanent"].lower()
            self.priv_info.append(row(_("Network card {n}").format(n=i["name"]),
                                      _("current {c} · original {p}").format(c=i["current"], p=i["permanent"])
                                      + (" · ✔ " + _("changed") if changed else "")))
        for k, d in st["dmi"].items():
            tag = _("masked") if d["masked"] else (_("visible to all programs") if d["world_readable"]
                                                    else _("readable by root only"))
            self.priv_info.append(row(k, f"{d['value'] or '—'} · {tag}"))
        self.priv_info.append(row(_("Disks"), _("{n} names with model and serial number in /dev/disk/by-id "
                                                "(cannot be changed by software)").format(n=len(st["disks"]))))
        self.priv_info.append(row(_("IPv6 temporary addresses"), _("on") if st["ipv6_privacy"] else _("off")))
        for m in st.get("mobile_modems", []):
            self.priv_info.append(row(_("Mobile modem {name}").format(name=m),
                                      _("The operator always sees the IMEI and the SIM: they cannot be hidden by "
                                        "software. The MAC address does not apply to mobile networks.")))
        if not st.get("networkmanager", True):
            self.sw_mac.set_subtitle(_("Without NetworkManager the new address applies from the next restart"))
        if st.get("popcon"):
            self.priv_info.append(row(_("popularity-contest"),
                                      _("sends your list of packages to Debian every week")))

    def priv_switch(self, sw, what):
        if self.settings_lock:
            return
        if what == "mac":
            self.anon(["mac", "random" if sw.get_active() else "off"])
        else:
            self.anon(["hardware", "on" if sw.get_active() else "off"])

    def anon(self, args):
        def done(ok, out):
            if ok:
                self.toast(out.splitlines()[0] if out else _("Done"))
            elif out:
                text_dialog(self, _("Error"), out)
            self.refresh_privacy(force=True)
        self.app.run_privileged([paths.ANON_TOOL] + args, done)

    # ------------------------------------------------------------------ preferences
    def show_preferences(self):
        d = Adw.PreferencesDialog()
        page = Adw.PreferencesPage()
        g = Adw.PreferencesGroup(title=_("Firewall"), description=_("Changes ask for the administrator password."))
        self.p_ks = Adw.ComboRow(title=_("Automatic kill switch"),
                                 subtitle=_("Isolate the computer by itself when an unapproved connection arrives"),
                                 model=Gtk.StringList.new([_("Off"), _("Inbound connections from the internet"),
                                                           _("Also outbound connections (very strict)")]))
        self.p_timeout = Adw.SpinRow.new_with_range(10, 3600, 10)
        self.p_timeout.set_title(_("Time to decide (seconds)"))
        self.p_timeout.set_subtitle(_("After this time an unanswered connection is blocked"))
        self.p_whois = Adw.SwitchRow(title=_("Find out who is on the other side (whois)"),
                                     subtitle=_("When off, Varco itself never sends anything on the network"))
        self.p_watchdog = Adw.SwitchRow(title=_("Process watchdog"),
                                        subtitle=_("Report new and suspicious programs (applies after restarting "
                                                   "the service)"))
        self.p_log = Adw.SwitchRow(title=_("Record allowed connections"),
                                   subtitle=_("When off, only blocked connections are recorded"))
        for w in (self.p_ks, self.p_timeout, self.p_whois, self.p_watchdog, self.p_log):
            g.add(w)
        page.add(g)
        d.add(page)
        self.load_settings_rows()
        self.p_ks.connect("notify::selected", lambda *_a: self.set_setting(
            "killswitch_auto", ["off", "in", "in_out"][self.p_ks.get_selected()]))
        self.p_timeout.connect("notify::value", lambda *_a: self.set_setting(
            "decision_timeout", int(self.p_timeout.get_value())))
        self.p_whois.connect("notify::active", lambda *_a: self.set_setting("whois", self.p_whois.get_active()))
        self.p_watchdog.connect("notify::active", lambda *_a: self.set_setting("watchdog",
                                                                               self.p_watchdog.get_active()))
        self.p_log.connect("notify::active", lambda *_a: self.set_setting("log_allowed", self.p_log.get_active()))
        d.present(self)

    def load_settings_rows(self):
        s = self.app.state.get("settings")
        if not s or not hasattr(self, "p_ks"):
            return
        self.settings_lock = True
        self.p_ks.set_selected({"off": 0, "in": 1, "in_out": 2}.get(s.get("killswitch_auto"), 1))
        self.p_timeout.set_value(s.get("decision_timeout", 120))
        self.p_whois.set_active(s.get("whois", True))
        self.p_watchdog.set_active(s.get("watchdog", True))
        self.p_log.set_active(s.get("log_allowed", True))
        self.settings_lock = False

    def set_setting(self, key, value):
        if self.settings_lock:
            return

        def done(res, err, msg):
            self.report(res, err, msg)
            self.app.call("GetState", None, lambda r, e, m: (r is not None and self.app.state.update(r),
                                                             self.load_settings_rows()))
        self.app.call("SetSetting", GLib.Variant("(ss)", (key, json.dumps(value))), done)
