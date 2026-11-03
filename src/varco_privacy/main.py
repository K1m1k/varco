# SPDX-License-Identifier: GPL-3.0-or-later
"""varco-privacy: random MAC address, generic hostname, new machine-id, masking of
hardware serial numbers.

Safety model
* Every change is first recorded in a journal (state.json) together with the ORIGINAL
  values, written atomically (temporary file, fsync, rename, fsync of the directory).
  Only then the system is modified. An interruption at any point leaves enough
  information to restore.
* 'restore' undoes each recorded change, VERIFIES the result, and removes a change from
  the journal only after it was verified. It can be run any number of times.
* Package removal runs 'restore' and stops if it fails, so original values are never lost.
"""
import argparse
import gettext
import glob
import json
import os
import re
import shutil
import socket
import subprocess
import sys

from . import VERSION

_ = gettext.translation("varco", os.environ.get("VARCO_LOCALEDIR", "/usr/share/locale"),
                        fallback=True).gettext

ROOT = os.environ.get("VARCO_PRIVACY_ROOT", "")   # tests only: operate on a fake root, run no commands
TEST = bool(ROOT)
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}

VAR = ROOT + "/var/lib/varco-privacy"
STATE = VAR + "/state.json"
NM_CONF = ROOT + "/etc/NetworkManager/conf.d/99-varco-privacy.conf"
LINK_DROPIN = ROOT + "/etc/systemd/network/99-default.link.d/varco-privacy.conf"
OLD_LINK = ROOT + "/etc/systemd/network/10-varco-privacy.link"
HOSTNAME = ROOT + "/etc/hostname"
HOSTS = ROOT + "/etc/hosts"
MACHINE_ID = ROOT + "/etc/machine-id"
DBUS_ID = ROOT + "/var/lib/dbus/machine-id"
MASK_UNIT = "varco-mask.service"
MASK_RUN = "/run/varco-mask"
FAKE_SERIAL = "To Be Filled By O.E.M."
FAKE_UUID = "03000200-0400-0500-0006-000700080009"
ORDER = ("hardware", "mac", "hostname", "machine_id")
COMMANDS = []      # commands that would run (tests)
FAKE_ENABLED = set()   # tests: units "enabled" by the fake systemctl
FAIL = set()           # tests: commands (tuples) that must fail


class Failed(Exception):
    pass


# ------------------------------------------------------------------ low level

def read(p):
    try:
        with open(p) as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return None


def write_atomic(path, text, mode=0o644, owner=None):
    """Crash-safe write. An existing file keeps its permissions and owner unless they are given."""
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    if os.path.exists(path):
        st = os.stat(path)
        if mode is None:
            mode = st.st_mode & 0o7777
        if owner is None:
            owner = (st.st_uid, st.st_gid)
    mode = 0o644 if mode is None else mode
    tmp = f"{path}.varco-tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        if owner is not None and os.geteuid() == 0:
            os.chown(tmp, owner[0], owner[1])
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def remove(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        return
    dfd = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def run(*cmd):
    if TEST:
        COMMANDS.append(cmd)
        if cmd in FAIL:
            return subprocess.CompletedProcess(list(cmd), 1, "", "simulated failure")
        if cmd[:2] == ("systemctl", "enable"):
            FAKE_ENABLED.add(cmd[2])
        elif cmd[:2] == ("systemctl", "disable"):
            FAKE_ENABLED.discard(cmd[2])
        elif cmd[:2] == ("systemctl", "is-enabled"):
            return subprocess.CompletedProcess(list(cmd), 0, "enabled\n" if cmd[2] in FAKE_ENABLED else
                                               "disabled\n", "")
        return subprocess.CompletedProcess(list(cmd), 0, "", "")
    try:
        return subprocess.run(list(cmd), capture_output=True, text=True, env=ENV, timeout=120)
    except (OSError, subprocess.SubprocessError) as e:
        return subprocess.CompletedProcess(list(cmd), 127, "", str(e))


OUR_MARK = "# Created by varco-privacy"


def snapshot(path):
    """What a file was before we touched it: None if it did not exist."""
    if not os.path.lexists(path):
        return None
    st = os.lstat(path)
    if not os.path.isfile(path) or os.path.islink(path):
        raise Failed(_("{path} exists and is not a regular file: nothing was changed").format(path=path))
    content = read(path)
    if content is None:
        raise Failed(_("{path} cannot be read: nothing was changed").format(path=path))
    return {"content": content, "mode": st.st_mode & 0o7777, "uid": st.st_uid, "gid": st.st_gid}


def put_back(path, snap):
    """Restore a file exactly as recorded (or remove it if it did not exist), then verify."""
    if snap is None:
        remove(path)
        if os.path.lexists(path):
            raise Failed(_("{path} could not be removed").format(path=path))
        return
    write_atomic(path, snap["content"], snap["mode"], (snap["uid"], snap["gid"]))
    st = os.stat(path)
    if read(path) != snap["content"] or st.st_mode & 0o7777 != snap["mode"] or \
            (os.geteuid() == 0 and (st.st_uid, st.st_gid) != (snap["uid"], snap["gid"])):
        raise Failed(_("{path} could not be restored").format(path=path))


def load_state():
    txt = read(STATE)
    if txt is None:
        return {"version": 1, "changes": {}}
    try:
        st = json.loads(txt)
        if not isinstance(st, dict) or not isinstance(st.setdefault("changes", {}), dict):
            raise ValueError("unexpected content")
        return st
    except ValueError as e:
        # never guess: a damaged journal must be looked at, not overwritten
        raise Failed(_("the journal {path} is damaged: {err}").format(path=STATE, err=e)) from e


def save_state(st):
    os.makedirs(VAR, mode=0o700, exist_ok=True)
    write_atomic(STATE, json.dumps(st, indent=2) + "\n", 0o600)


def has_networkmanager():
    if TEST:
        return os.path.isdir(ROOT + "/etc/NetworkManager")
    return os.path.isdir("/etc/NetworkManager") and shutil.which("NetworkManager", path=ENV["PATH"]) is not None


def mounted(p):
    for line in (read("/proc/self/mountinfo") or "").splitlines():
        f = line.split()
        if len(f) > 4 and f[4] == p:
            return True
    return False


def our_mounts():
    out = []
    for line in (read("/proc/self/mountinfo") or "").splitlines():
        f = line.split()
        if len(f) > 4 and "/varco-mask/" in f[3] and f[4].startswith("/sys/"):
            out.append(f[4])
    return out


def interfaces():
    out = []
    r = subprocess.run(["ip", "-j", "-d", "link"], capture_output=True, text=True, env=ENV) \
        if shutil.which("ip", path=ENV["PATH"]) else None
    try:
        for x in json.loads(r.stdout if r else "[]"):
            if x.get("link_type") == "ether" and x.get("ifname") != "lo" and "linkinfo" not in x:
                wifi = os.path.isdir(f"/sys/class/net/{x['ifname']}/wireless")
                out.append({"name": x["ifname"], "current": x.get("address", "?"),
                            "permanent": x.get("permaddr") or x.get("address", "?"),
                            "kind": "wifi" if wifi else "ethernet"})
    except (ValueError, KeyError):
        pass
    return out


def mobile_modems():
    """Cellular modems (WWAN): the operator always sees IMEI and SIM, nothing can hide them."""
    names = set(os.listdir("/sys/class/wwan")) if os.path.isdir("/sys/class/wwan") else set()
    for n in (os.listdir("/sys/class/net") if os.path.isdir("/sys/class/net") else []):
        if n.startswith(("wwan", "rmnet", "ppp")):
            names.add(n)
    return sorted(names)


def hardware_targets():
    """Kernel files exposing serial numbers: (path, fake value)."""
    t = []
    dmi = "/sys/devices/virtual/dmi/id"
    for f, v in (("product_serial", FAKE_SERIAL), ("board_serial", FAKE_SERIAL), ("chassis_serial", FAKE_SERIAL),
                 ("product_uuid", FAKE_UUID), ("board_asset_tag", "Default string"),
                 ("chassis_asset_tag", "Default string")):
        t.append((f"{dmi}/{f}", v + "\n"))
    for f in ("/sys/firmware/dmi/tables/DMI", "/sys/firmware/dmi/tables/smbios_entry_point"):
        t.append((f, ""))
    for f in glob.glob("/sys/class/nvme/*/serial"):
        t.append((os.path.realpath(f), "0000000000\n"))
    for pat in ("/sys/block/*/wwid", "/sys/block/*/device/wwid", "/sys/block/*/device/serial",
                "/sys/block/*/device/vpd_pg80", "/sys/block/*/device/vpd_pg83"):
        for f in glob.glob(pat):
            t.append((os.path.realpath(f), ""))
    return [(p, v) for p, v in dict(t).items() if os.path.exists(p)]


# ------------------------------------------------------------------ hostname

def current_hostname():
    return (read(HOSTNAME) or "").strip().splitlines()[0] if (read(HOSTNAME) or "").strip() else ""


def hosts_line():
    for line in (read(HOSTS) or "").splitlines():
        if line.split()[:1] == ["127.0.1.1"]:
            return line
    return None


def set_hosts_line(new):
    """Replace only the 127.0.1.1 line (new=None removes it): other entries are never touched."""
    lines, done = [], False
    for line in (read(HOSTS) or "").splitlines():
        if line.split()[:1] == ["127.0.1.1"]:
            if new is not None and not done:
                lines.append(new)
                done = True
            continue
        lines.append(line)
    if new is not None and not done:
        lines.insert(1 if lines else 0, new)
    write_atomic(HOSTS, "\n".join(lines) + "\n", None)


def set_hostname(name):
    if not TEST and shutil.which("hostnamectl", path=ENV["PATH"]):
        run("hostnamectl", "set-hostname", name)
    write_atomic(HOSTNAME, name + "\n", None)
    if not TEST:
        run("hostname", name)


def apply_hostname(st, name):
    ch = st["changes"].get("hostname")
    if ch is None:
        st["changes"]["hostname"] = {"original": current_hostname(), "hosts_line": hosts_line()}
        save_state(st)                                   # journal first
    set_hostname(name)
    set_hosts_line(f"127.0.1.1\t{name}")


def restore_hostname(ch):
    orig = ch["original"]
    if orig:
        set_hostname(orig)
    set_hosts_line(ch.get("hosts_line"))
    if orig and current_hostname() != orig:
        raise Failed(_("computer name still differs from the original '{name}'").format(name=orig))
    if hosts_line() != ch.get("hosts_line"):
        raise Failed(_("/etc/hosts could not be restored"))
    return _("computer name '{name}'").format(name=orig)


# ------------------------------------------------------------------ machine-id

def apply_machine_id(st):
    if "machine_id" not in st["changes"]:
        dbus = read(DBUS_ID) if os.path.isfile(DBUS_ID) and not os.path.islink(DBUS_ID) else None
        st["changes"]["machine_id"] = {"etc": read(MACHINE_ID), "dbus": dbus}
        save_state(st)
    new = os.urandom(16).hex()
    write_atomic(MACHINE_ID, new + "\n", 0o444)
    if st["changes"]["machine_id"]["dbus"] is not None:
        write_atomic(DBUS_ID, new + "\n", 0o444)
    return new


def restore_machine_id(ch):
    if ch.get("etc") is not None:
        write_atomic(MACHINE_ID, ch["etc"], 0o444)
        if read(MACHINE_ID) != ch["etc"]:
            raise Failed(_("/etc/machine-id could not be restored"))
    if ch.get("dbus") is not None:
        write_atomic(DBUS_ID, ch["dbus"], 0o444)
        if read(DBUS_ID) != ch["dbus"]:
            raise Failed(_("/var/lib/dbus/machine-id could not be restored"))
    return _("original machine-id (fully active after a restart)")


# ------------------------------------------------------------------ MAC address

def apply_mac(st, mode):
    nm = has_networkmanager()
    if not nm and mode == "stable":
        raise Failed(_("Without NetworkManager only the 'random' mode is available."))
    target = NM_CONF if nm else LINK_DROPIN
    prev = st["changes"].get("mac")
    if prev is None:
        # journal first, with the exact previous content of the file we are going to write
        st["changes"]["mac"] = {"method": "nm" if nm else "udev", "mode": mode,
                                "files": {target: snapshot(target)}}
    else:
        prev["mode"] = mode
        prev.setdefault("files", {})
        if target not in prev["files"]:
            prev["files"][target] = snapshot(target)
    save_state(st)
    if nm:
        val = "random" if mode == "random" else "stable"
        write_atomic(NM_CONF, f"""{OUR_MARK}. Removed by: varco-privacy restore
[device-varco-privacy]
wifi.scan-rand-mac-address=yes

[connection-varco-privacy]
ethernet.cloned-mac-address={val}
wifi.cloned-mac-address={val}
ipv4.dhcp-client-id=mac
ipv6.dhcp-duid=ll
ipv6.ip6-privacy=2
# the computer name is not announced to the router (DHCP) nor to the local network (LLMNR)
ipv4.dhcp-send-hostname=false
ipv6.dhcp-send-hostname=false
connection.llmnr=0
""")
        r = run("systemctl", "restart", "NetworkManager.service")
        return _("Random MAC address on: connections reconnect with the new address.") if r.returncode == 0 \
            else _("Random MAC address configured; it applies when the network reconnects.")
    # Without NetworkManager: a drop-in for the default link policy. Interfaces configured by
    # other .link files keep their own settings, and names never change.
    write_atomic(LINK_DROPIN, f"{OUR_MARK}\n[Link]\nMACAddressPolicy=random\n")
    return _("Random MAC address on from the next restart.")


def restore_mac(ch):
    files = ch.get("files")
    if files is None:            # journal written by 1.0.1: those files were always ours
        files = {f: None for f in (NM_CONF, LINK_DROPIN) if (read(f) or "").startswith(OUR_MARK)}
    for path, snap in files.items():
        put_back(path, snap)
    try:
        os.rmdir(os.path.dirname(LINK_DROPIN))
    except OSError:
        pass
    if ch.get("method") == "nm":
        run("systemctl", "reload-or-restart", "NetworkManager.service")
        return _("original MAC address")
    return _("original MAC address (from the next restart)")


# ------------------------------------------------------------------ hardware serial numbers

def mask():
    os.makedirs(MASK_RUN, mode=0o755, exist_ok=True)
    n = 0
    for i, (p, v) in enumerate(hardware_targets()):
        if mounted(p):
            continue
        fake = f"{MASK_RUN}/f{i}"
        with open(fake, "w") as f:
            f.write(v)
        os.chmod(fake, 0o444)
        if run("mount", "--bind", fake, p).returncode == 0:
            n += 1
    return n


def unmask():
    for p in our_mounts():
        run("umount", "-l", p)
    shutil.rmtree(MASK_RUN, ignore_errors=True)


def unit_enabled():
    return run("systemctl", "is-enabled", MASK_UNIT).stdout.strip() == "enabled"


def apply_hardware(st):
    """Never claim a protection that is not active: verify the boot unit and every mask,
    and undo everything if something did not work."""
    st["changes"]["hardware"] = {"on": True}
    save_state(st)
    problem = None
    r = run("systemctl", "enable", MASK_UNIT)
    if r.returncode != 0 or not unit_enabled():
        problem = _("the masking service could not be enabled: {err}").format(
            err=(r.stderr or r.stdout).strip() or "systemctl")
    else:
        targets = hardware_targets() if not TEST else []
        if not targets and not TEST:
            restore_hardware(st["changes"]["hardware"])
            del st["changes"]["hardware"]
            save_state(st)
            return 0
        n = mask() if not TEST else 0
        masked = set(our_mounts()) if not TEST else set()
        missing = [p for p, _v in targets if p not in masked]
        if missing:
            problem = _("{n} of {total} serial numbers could not be masked: {paths}").format(
                n=len(missing), total=len(targets), paths=", ".join(missing[:3]))
    if problem:
        try:
            restore_hardware(st["changes"]["hardware"])
            del st["changes"]["hardware"]
            save_state(st)
        except (Failed, OSError) as e:
            problem += " · " + _("undo failed: {err}").format(err=e)
        raise Failed(problem + " · " + _("nothing was left active."))
    return n


def restore_hardware(ch):
    run("systemctl", "disable", MASK_UNIT)
    unmask()
    if not TEST and our_mounts():
        raise Failed(_("some serial numbers are still masked"))
    if unit_enabled():
        raise Failed(_("the masking service is still enabled"))
    return _("hardware serial numbers")


RESTORERS = {"hardware": restore_hardware, "mac": restore_mac, "hostname": restore_hostname,
             "machine_id": restore_machine_id}


def verify():
    """Check that every change recorded in the journal is really active (used after a restart)."""
    st = load_state()
    problems = []
    ch = st["changes"]
    if "hardware" in ch:
        if not unit_enabled():
            problems.append(_("the masking service is not enabled"))
        if not TEST:
            masked = set(our_mounts())
            missing = [p for p, _v in hardware_targets() if p not in masked]
            if missing:
                problems.append(_("{n} serial numbers are not masked").format(n=len(missing)))
    if "mac" in ch:
        target = NM_CONF if ch["mac"].get("method") == "nm" else LINK_DROPIN
        if not (read(target) or "").startswith(OUR_MARK):
            problems.append(_("the MAC address configuration is missing: {path}").format(path=target))
    if "hostname" in ch and current_hostname() == ch["hostname"]["original"]:
        problems.append(_("the computer name is the original one"))
    if "machine_id" in ch and read(MACHINE_ID) == ch["machine_id"].get("etc"):
        problems.append(_("the machine-id is the original one"))
    for p in problems:
        print(_("NOT active: {what}").format(what=p), file=sys.stderr)
    if not problems:
        print(_("Every recorded change is active: {what}").format(what=", ".join(sorted(ch)) or "-"))
    return 1 if problems else 0


def restore(only=None, quiet=False):
    """Undo recorded changes; each one leaves the journal only after it was verified."""
    st = load_state()
    done, errors = [], []
    for key in ORDER:
        if key not in st["changes"] or (only and key != only):
            continue
        try:
            done.append(RESTORERS[key](st["changes"][key]))
        except (Failed, OSError) as e:
            errors.append(f"{key}: {e}")
            continue
        del st["changes"][key]
        save_state(st)
    # file of the 1.0.0 layout, never journaled: removed only if it is really ours
    if (read(OLD_LINK) or "").startswith(OUR_MARK):
        remove(OLD_LINK)
    if done:
        print(_("Restored: {what}.").format(what=", ".join(done)))
    elif not quiet and not errors:
        print(_("Nothing to restore."))
    for e in errors:
        print(_("NOT restored: {err}").format(err=e), file=sys.stderr)
    if errors:
        print(_("The original values are kept in {path}: run 'varco-privacy restore' again "
                "after fixing the problem.").format(path=STATE), file=sys.stderr)
        return 1
    return 0


# ------------------------------------------------------------------ status

def status():
    """What identifies this computer. Works without root (values readable only by root are omitted)."""
    try:
        changes = load_state()["changes"] if os.access(STATE, os.R_OK) or not os.path.exists(STATE) else None
    except Failed:
        changes = None
    dmi = {}
    for f in ("sys_vendor", "product_name", "board_name", "bios_version", "product_serial", "board_serial",
              "chassis_serial", "product_uuid"):
        p = f"/sys/devices/virtual/dmi/id/{f}"
        if os.path.exists(p):
            v = read(p)
            dmi[f] = {"value": v.strip() if v else None, "world_readable": bool(os.stat(p).st_mode & 0o004),
                      "masked": mounted(p)}
    disks = sorted(d for d in os.listdir("/dev/disk/by-id") if "-part" not in d) \
        if os.path.isdir("/dev/disk/by-id") else []
    cpu = re.search(r"^model name\s*:\s*(.+)$", read("/proc/cpuinfo") or "", re.M)
    mac_state = "nm" if os.path.exists(NM_CONF) else ("udev" if os.path.exists(LINK_DROPIN) else None)
    return {
        "hostname": socket.gethostname(),
        "hostname_changed": None if changes is None else "hostname" in changes,
        "machine_id": (read(MACHINE_ID) or "").strip() or None,
        "machine_id_changed": None if changes is None else "machine_id" in changes,
        "mac_random": mac_state is not None,
        "mac_mode": mac_state,
        "networkmanager": has_networkmanager(),
        "interfaces": interfaces(),
        "mobile_modems": mobile_modems(),
        "dmi": dmi,
        "hardware_masked": bool(our_mounts()) or (changes is not None and "hardware" in changes),
        "disks": disks,
        "cpu": cpu.group(1) if cpu else None,
        "ipv6_privacy": (read("/proc/sys/net/ipv6/conf/default/use_tempaddr") or "").strip() == "2",
        "popcon": 'PARTICIPATE="yes"' in (read("/etc/popularity-contest.conf") or ""),
        "pending_changes": None if changes is None else sorted(changes),
    }


def print_status(st):
    ok, no = "✔", "✘"
    print(_("What identifies this computer") + "\n")
    print(f"{ok if st['hostname_changed'] else '•'} " + _("Computer name: {v}").format(v=st["hostname"]))
    print("    " + _("sent to the router via DHCP and visible on the local network"))
    print(f"{ok if st['machine_id_changed'] else '•'} " + _("machine-id: {v}").format(v=st["machine_id"] or "?"))
    print("    " + _("unique system identifier, readable by every program"))
    print(f"{ok if st['mac_random'] else no} " + _("Random MAC address: {v}").format(
        v=_("on") if st["mac_random"] else _("off")))
    for i in st["interfaces"]:
        changed = i["current"].lower() != i["permanent"].lower()
        print(f"    {i['name']:12} {i['current']}  ({_('original')} {i['permanent']})  "
              + (_("changed") if changed else _("original")))
    for m in st["mobile_modems"]:
        print("• " + _("Mobile modem {name}: the operator always sees the IMEI and the SIM; they cannot be "
                       "hidden by software").format(name=m))
    print(f"{ok if st['hardware_masked'] else no} " + _("Hardware serial numbers masked: {v}").format(
        v=_("yes") if st["hardware_masked"] else _("no")))
    for k, d in st["dmi"].items():
        tag = _("masked") if d["masked"] else (_("visible to all") if d["world_readable"] else _("root only"))
        print(f"    {k:15} {(d['value'] or '')[:40]:40} [{tag}]")
    print("    " + _("The real serial numbers are stored in the firmware: software can only hide them."))
    print("• " + _("Disks: {n} names with model and serial number in /dev/disk/by-id (cannot be changed)").format(
        n=len(st["disks"])))
    print(f"{ok if st['ipv6_privacy'] else no} " + _("IPv6 temporary addresses: {v}").format(
        v=_("on") if st["ipv6_privacy"] else _("off")))
    if st["popcon"]:
        print(f"{no} " + _("popularity-contest sends your package list to Debian every week"))
    print("\n" + _("Note: on the web a computer is recognized mostly by the browser fingerprint."))


# ------------------------------------------------------------------ main

def main(argv=None):
    p = argparse.ArgumentParser(prog="varco-privacy",
                                description=_("Reduce the identifiers this computer exposes."))
    p.add_argument("--version", action="version", version=f"varco-privacy {VERSION}")
    sub = p.add_subparsers(dest="cmd", metavar=_("command"))
    s = sub.add_parser("status", help=_("show what identifies this computer"))
    s.add_argument("--json", action="store_true")
    s = sub.add_parser("mac", help=_("random MAC address"))
    s.add_argument("mode", choices=["random", "stable", "off"])
    s = sub.add_parser("hostname", help=_("generic computer name"))
    s.add_argument("name", nargs="?", default="debian")
    sub.add_parser("machine-id", help=_("new machine-id"))
    s = sub.add_parser("hardware", help=_("mask hardware serial numbers"))
    s.add_argument("state", choices=["on", "off"])
    sub.add_parser("all", help=_("everything above"))
    s = sub.add_parser("restore", help=_("put every original value back"))
    s.add_argument("--quiet", action="store_true")
    sub.add_parser("verify", help=_("check that every recorded change is really active"))
    sub.add_parser("mask-boot", help=argparse.SUPPRESS)
    sub.add_parser("unmask-boot", help=argparse.SUPPRESS)
    a = p.parse_args(argv)
    if a.cmd in (None, "status"):
        st = status()
        if getattr(a, "json", False):
            print(json.dumps(st, ensure_ascii=False))
        else:
            print_status(st)
        return 0
    if os.geteuid() != 0 and not TEST:
        print(_("This operation requires root."), file=sys.stderr)
        return 1
    try:
        if a.cmd == "restore":
            return restore(quiet=a.quiet)
        if a.cmd == "verify":
            return verify()
        if a.cmd == "mask-boot":
            if "hardware" in load_state()["changes"]:
                mask()
            return 0
        if a.cmd == "unmask-boot":
            unmask()
            return 0
        st = load_state()
        if a.cmd == "mac":
            if a.mode == "off":
                return restore(only="mac")
            print(apply_mac(st, a.mode))
        elif a.cmd == "hostname":
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,62}", a.name):
                print(_("Invalid name: letters, digits and hyphens only."), file=sys.stderr)
                return 2
            apply_hostname(st, a.name)
            print(_("Computer name is now: {name}").format(name=a.name))
            print(_("Some open programs may need to be restarted."))
        elif a.cmd == "machine-id":
            new = apply_machine_id(st)
            print(_("New machine-id: {v}. Restart the computer so that every program uses it.").format(v=new))
        elif a.cmd == "hardware":
            if a.state == "off":
                return restore(only="hardware")
            n = apply_hardware(st)
            if n == 0 and not TEST:
                print(_("This computer exposes no hardware serial numbers to mask: nothing was changed."))
                return 0
            print(_("{n} identifiers masked (DMI serial numbers, UUID, SMBIOS tables, disk serials).").format(n=n))
            print(_("They stay masked after restarting. If a firmware update tool stops working, turn this off."))
        elif a.cmd == "all":
            print(apply_mac(st, "random"))
            apply_hostname(st, "debian")
            apply_machine_id(st)
            apply_hardware(st)
            print(_("Everything applied. Restart the computer to complete the change."))
        else:
            return 2
    except Failed as e:
        print(str(e), file=sys.stderr)
        return 1
    except OSError as e:
        print(_("Error: {err}. Nothing is lost: 'varco-privacy restore' puts back what was changed.").format(
            err=e), file=sys.stderr)
        return 1
    return 0
