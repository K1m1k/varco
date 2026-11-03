# SPDX-License-Identifier: GPL-3.0-or-later
"""varco-helper: privileged actions started through pkexec (polkit action
org.k1m1k.varco.helper). Arguments are validated strictly: this is a root entry point."""
import os
import re
import shutil
import subprocess
import sys
import tempfile

from . import VERSION, paths
from .rules import HOST_DNS, Rules

SYSTEM_PROGRAMS = [
    # (executable, proto, host, port)
    ("/usr/lib/systemd/systemd-resolved", "*", "*", 53),
    ("/usr/lib/systemd/systemd-resolved", "tcp", "*", 853),
    ("/usr/lib/systemd/systemd-timesyncd", "udp", "*", 123),
    ("/usr/sbin/chronyd", "udp", "*", 123),
    ("/usr/sbin/NetworkManager", "tcp", "*", 80),
    ("/usr/lib/apt/methods/http", "tcp", "*.debian.org", 80),
    ("/usr/lib/apt/methods/http", "tcp", "*.debian.org", 443),
]
# local resolvers that forward to the network themselves: with the DNS preset they may reach
# any DNS server (programs only talk to them, on this computer)
LOCAL_RESOLVERS = ("/usr/lib/systemd/systemd-resolved", "/usr/sbin/dnsmasq", "/usr/sbin/unbound")
PACKAGES = ("varco", "varco-gtk", "varco-privacy")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": os.environ.get("LANG", "C.UTF-8"),
       "DEBIAN_FRONTEND": "noninteractive"}
PTRACE_CONF = "/etc/sysctl.d/60-varco-ptrace.conf"
ANON_DEB = re.compile(r"^varco-privacy_[0-9A-Za-z.+~-]+_all\.deb$")


def run(*cmd):
    return subprocess.run(list(cmd), env=ENV).returncode


def preset_rules(names):
    rules = []
    if "dns" in names:
        # every program may ask the DNS servers the system uses (whatever network it is on),
        # never an arbitrary server: port 53 must not be a free way out of the computer
        rules.append({"dir": "out", "app": "*", "proto": "*", "host": HOST_DNS, "port": 53, "action": "allow",
                      "note": "preset: DNS"})
        for exe in LOCAL_RESOLVERS:
            if os.path.exists(exe):
                rules.append({"dir": "out", "app": os.path.realpath(exe), "proto": "*", "host": "*", "port": 53,
                              "action": "allow", "note": "preset: DNS (local resolver)"})
    if "system" in names:
        for exe, proto, host, port in SYSTEM_PROGRAMS:
            if os.path.exists(exe):
                rules.append({"dir": "out", "app": os.path.realpath(exe), "proto": proto, "host": host,
                              "port": port, "action": "allow", "note": "preset: system"})
    return rules


def key(r):
    return r["dir"], r["app"], r["proto"], r["host"], str(r["port"])


def service_active():
    return subprocess.run([paths.SYSTEMCTL, "is-active", "--quiet", "varco.service"], env=ENV).returncode == 0


def add_rules(rules):
    """Add rules without losing any: through the running service (it owns rules.json while it
    runs and would overwrite a direct change), or directly in the file when it is stopped."""
    if service_active():
        from .client import Client
        cl = Client()
        have = {key(r) for r in cl.rules()}
        for r in rules:
            if key(r) not in have:
                res = cl.add_rule(r)
                if not res.get("ok"):
                    print(res.get("message"), file=sys.stderr)
        return
    store = Rules(paths.RULES)
    have = {key(r) for r in store.list}
    for r in rules:
        if key(r) not in have:
            store.add(r)


def set_ptrace(on):
    """kernel.yama.ptrace_scope=1: a program may only debug its own children. Without it any
    program can take over another one of the same user, for example an approved browser."""
    if on:
        os.makedirs(os.path.dirname(PTRACE_CONF), exist_ok=True)
        with open(PTRACE_CONF, "w") as f:
            f.write("# Written by Varco (varco-helper enable ptrace).\n"
                    "# Programs may only debug their own children: one program cannot take over another.\n"
                    "kernel.yama.ptrace_scope = 1\n")
        return run("sysctl", "-q", "-w", "kernel.yama.ptrace_scope=1")
    if os.path.exists(PTRACE_CONF):
        os.unlink(PTRACE_CONF)
        run("sysctl", "-q", "--system")
    return 0


def set_override(k, value):
    if service_active():
        from .client import Client
        Client().set_setting(k, value)
        return
    from .util import load_json_checked, save_json
    ov = load_json_checked(paths.CONFIG_OVERRIDES, {}, dict)
    ov[k] = value
    save_json(paths.CONFIG_OVERRIDES, ov)


def enable(presets):
    add_rules(preset_rules(presets))
    if "ptrace" in presets:
        set_ptrace(True)
    run(paths.SYSTEMCTL, "reset-failed", "varco.service")
    return run(paths.SYSTEMCTL, "enable", "--now", "varco.service")


def restart():
    run(paths.SYSTEMCTL, "reset-failed", "varco.service")
    return run(paths.SYSTEMCTL, "restart", "varco.service")


def disable():
    rc = run(paths.SYSTEMCTL, "disable", "--now", "varco.service")
    subprocess.run([paths.NFT, "delete", "table", "inet", "varco"], capture_output=True)
    return rc


def installed(pkg):
    r = subprocess.run(["dpkg-query", "-W", "-f=${Status}", pkg], capture_output=True, text=True, env=ENV)
    return r.returncode == 0 and "installed" in r.stdout and "not-installed" not in r.stdout


def deb_field(path, field):
    r = subprocess.run(["dpkg-deb", "-f", path, field], capture_output=True, text=True, env=ENV)
    return r.stdout.strip() if r.returncode == 0 else None


def install_privacy(src=None):
    """Install the privacy module. It is not in the Debian archive, so normally the user picks
    its .deb file. The file is copied into a private root-only folder first and checked there:
    the user's copy could be swapped by another program after the password was given."""
    if src is None:
        return run("apt-get", "install", "-y", "varco-privacy")
    if not ANON_DEB.match(os.path.basename(src)) or not os.path.isabs(src):
        print("not a varco-privacy package file", file=sys.stderr)
        return 2
    tmp = tempfile.mkdtemp(prefix="varco-install-", dir="/run" if os.path.isdir("/run") else None)
    try:
        dst = os.path.join(tmp, os.path.basename(src))
        try:
            fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as e:
            print(f"cannot open {src}: {e.strerror}", file=sys.stderr)
            return 2
        with os.fdopen(fd, "rb") as fin:
            if not os.path.isfile(f"/proc/self/fd/{fin.fileno()}") or os.fstat(fin.fileno()).st_size > 64 << 20:
                print("not a regular package file", file=sys.stderr)
                return 2
            with open(dst, "wb") as fout:
                shutil.copyfileobj(fin, fout)
        if deb_field(dst, "Package") != "varco-privacy":
            print("the file is not the varco-privacy package", file=sys.stderr)
            return 2
        ver = deb_field(dst, "Version")
        if ver != VERSION:
            print(f"the package is version {ver}, Varco is version {VERSION}: use the file of the same version",
                  file=sys.stderr)
            return 2
        os.chmod(tmp, 0o755)        # apt's download user must be able to read it
        os.chmod(dst, 0o644)
        return run("apt-get", "install", "-y", "--no-install-recommends", dst)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


USAGE = ("usage: varco-helper enable [dns] [system] [ptrace] [autokill] | restart | disable | "
         "ptrace on|off | install-privacy [FILE.deb] | uninstall")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if os.geteuid() != 0:
        print("varco-helper must run as root (via pkexec)", file=sys.stderr)
        return 1
    if not argv:
        print(USAGE, file=sys.stderr)
        return 2
    cmd, args = argv[0], argv[1:]
    if cmd == "enable" and set(args) <= {"dns", "system", "ptrace", "autokill"}:
        if "autokill" in args:
            set_override("killswitch_auto", "in")
        return enable(set(args))
    if cmd == "restart" and not args:
        return restart()
    if cmd == "disable" and not args:
        return disable()
    if cmd == "ptrace" and args in (["on"], ["off"]):
        return set_ptrace(args[0] == "on")
    if cmd == "install-privacy" and len(args) <= 1:
        return install_privacy(args[0] if args else None)
    if cmd == "uninstall" and not args:
        disable()
        set_ptrace(False)
        pkgs = [p for p in PACKAGES if installed(p)]
        return run("apt-get", "purge", "-y", *pkgs) if pkgs else 0
    print("invalid arguments", file=sys.stderr)
    return 2
