# SPDX-License-Identifier: GPL-3.0-or-later
"""Who is a process: executable, command, user, systemd unit, Debian package, suspicious traits."""
import hashlib
import os
import re
import threading

from . import _
from .util import read, username

INTERP = re.compile(r"^(python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|node|nodejs|bash|sh|dash|zsh|"
                    r"java|php[0-9.]*|lua[0-9.]*|tclsh[0-9.]*)$")
STDIN_TAG = "(stdin)"


class Procs:
    """Maps socket inodes to the processes holding them, by scanning /proc/*/fd.

    A socket can be held by several processes at once (inherited across fork/exec or
    passed over a UNIX socket): every holder is returned, so the caller can refuse to
    trust a socket shared by different programs."""

    def __init__(self):
        self.lock = threading.Lock()
        self.map = {}

    def scan(self):
        m = {}
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            d = f"/proc/{pid}/fd"
            try:
                fds = os.listdir(d)
            except OSError:
                continue
            for fd in fds:
                try:
                    lk = os.readlink(f"{d}/{fd}")
                except OSError:
                    continue
                if lk.startswith("socket:["):
                    holders = m.setdefault(int(lk[8:-1]), [])
                    if int(pid) not in holders:
                        holders.append(int(pid))
        with self.lock:
            self.map = m
        return m

    def owners(self, inode):
        """Live processes holding a socket inode (possibly more than one)."""
        with self.lock:
            pids = [p for p in self.map.get(inode, []) if os.path.exists(f"/proc/{p}")]
        if pids:
            return pids
        return self.scan().get(inode, [])

    def pid_of(self, inode):
        pids = self.owners(inode)
        return pids[0] if pids else None



# Variables that make a program load or run code chosen by whoever started it. A program
# approved by a rule but started with one of these could be running someone else's code,
# so they become part of its identity (names and a hash of the values). The first group
# matters for every program, the others only for their own interpreter.
INJECT_ENV_ALL = ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "GTK_MODULES", "GTK_PATH", "GIO_EXTRA_MODULES",
                  "GST_PLUGIN_PATH", "QT_PLUGIN_PATH")
INJECT_ENV_INTERP = {
    "python": ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"),
    "perl": ("PERL5LIB", "PERL5OPT", "PERLLIB"),
    "ruby": ("RUBYOPT", "RUBYLIB"),
    "node": ("NODE_OPTIONS", "NODE_PATH"),
    "bash": ("BASH_ENV",),
    "java": ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH"),
    "lua": ("LUA_PATH", "LUA_CPATH"),
    "php": ("PHPRC", "PHP_INI_SCAN_DIR"),
}
INJECT_ENV = INJECT_ENV_ALL + tuple(v for vs in INJECT_ENV_INTERP.values() for v in vs)


def interp_family(exe):
    base = os.path.basename(exe).replace(" (deleted)", "")
    if base == "nodejs":
        return "node"
    for k in INJECT_ENV_INTERP:
        if base.startswith(k):
            return k
    return None


def inject_env(environ, exe=""):
    """'[env NAME,NAME sha256:…]' for the code-injecting variables set in a process, or ''."""
    watch = set(INJECT_ENV_ALL) | set(INJECT_ENV_INTERP.get(interp_family(exe), ()))
    found = {}
    for item in environ.split(b"\0"):
        k, sep, v = item.partition(b"=")
        name = k.decode("ascii", "replace")
        if sep and v and name in watch:
            found[name] = v
    if not found:
        return ""
    h = hashlib.sha256(b"\0".join(k.encode() + b"=" + found[k] for k in sorted(found))).hexdigest()[:16]
    return f"[env {','.join(sorted(found))} sha256:{h}]"


MAX_IDENTITY = 1024

# options that take the next argument as their value, per interpreter (so the value is not
# mistaken for the script; it stays part of the identity anyway)
ARG_OPTS = {
    "python": {"-W", "-X", "--check-hash-based-pycs"},
    "node": {"-r", "--require", "--import", "--loader", "--experimental-loader", "--env-file", "-C",
             "--conditions", "--input-type"},
    "ruby": {"-I", "-r", "-E", "-C"},
    "bash": {"-o", "-O", "+o", "+O", "--rcfile", "--init-file"},
    "java": {"-cp", "-classpath", "--class-path", "-p", "--module-path", "--add-modules", "-javaagent"},
}


def arg_opts(exe):
    base = os.path.basename(exe).replace(" (deleted)", "")
    for k, v in ARG_OPTS.items():
        if base.startswith(k) or (k == "node" and base == "nodejs") or \
                (k == "bash" and base in ("sh", "dash", "zsh")):
            return v
    return set()


def parse_interpreter(exe, args, cwd):
    """(options, target) of an interpreter command line, or None if exe is not an interpreter.
    target is the absolute script path, '-m module', '-c sha256:…' or None (code from stdin)."""
    if exe == "?" or not INTERP.match(os.path.basename(exe).replace(" (deleted)", "")):
        return None
    opts, it, target, takes = [], iter(args[1:]), None, arg_opts(exe)
    for a in it:
        if a in ("-m", "-jar"):
            target = f"{a} {next(it, '')}".rstrip()
            break
        if a in ("--eval", "--print") or (a.startswith("-") and not a.startswith("--") and a[-1] in "ceEp"):
            code = next(it, "")
            target = f"{a} sha256:{hashlib.sha256(code.encode()).hexdigest()[:16]}"
            break
        if a == "-":
            break
        if a.startswith("-") or a in takes:
            opts.append(a)
            if a in takes:
                opts.append(next(it, ""))
            continue
        if not os.path.isabs(a) and cwd:
            a = os.path.join(cwd, a)
        target = os.path.normpath(a)
        break
    return opts, target


def app_identity(exe, args, cwd, env_tag=""):
    """Identity used by rules.

    For interpreters it includes the script (or module, or a hash of inline code) AND every
    option written before it: 'python3 -X /approved.py other.py' runs other.py, so it must
    not look like '/approved.py'. Variables that inject code (LD_PRELOAD...) are added too."""
    ident = exe
    parsed = parse_interpreter(exe, args, cwd)
    if parsed:
        opts, target = parsed
        ident = " ".join([exe] + opts + [target or STDIN_TAG])
    if env_tag:
        ident = f"{ident} {env_tag}"
    if len(ident) > MAX_IDENTITY:
        ident = f"{exe} sha256:{hashlib.sha256(ident.encode()).hexdigest()[:32]}"
    return ident


def start_time(pid):
    """Start time of a process (clock ticks since boot): tells it apart from a later process
    that got the same pid."""
    stat = read(f"/proc/{pid}/stat")
    try:
        return int(stat.rsplit(")", 1)[1].split()[19])
    except (IndexError, ValueError):
        return None


def printable(t):
    """Text safe to show anywhere: control characters (terminal escapes...) become '?'."""
    return "".join(ch if ch.isprintable() else "?" for ch in str(t))


def describe(pid, uid=None):
    info = {"pid": pid, "exe": "?", "cmd": "", "user": username(uid) if uid is not None else "?",
            "uid": uid, "unit": "", "parent": "", "app": "?", "start": None, "env": "", "script": ""}
    if not pid:
        return info
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        exe = "?"
    args = [a.decode("utf-8", "replace") for a in read(f"/proc/{pid}/cmdline", True).split(b"\0") if a]
    info["exe"], info["cmd"] = exe, printable(" ".join(args))[:400]
    m = re.search(r"^Uid:\s*(\d+)", read(f"/proc/{pid}/status"), re.M)
    if m:
        info["uid"] = int(m.group(1))
        info["user"] = username(info["uid"])
    stat = read(f"/proc/{pid}/stat")
    if ")" in stat:
        try:
            ppid = int(stat.rsplit(")", 1)[1].split()[1])
            info["parent"] = f"{printable(read(f'/proc/{ppid}/comm').strip()) or '?'} (pid {ppid})"
        except (IndexError, ValueError):
            pass
    info["start"] = start_time(pid)
    for line in read(f"/proc/{pid}/cgroup").splitlines():
        if line.startswith("0::"):
            parts = [x for x in line[3:].split("/") if x]
            units = [x for x in parts if x.endswith((".service", ".scope"))]
            info["unit"] = printable(units[-1] if units else (parts[-1] if parts else ""))
    try:
        cwd = os.readlink(f"/proc/{pid}/cwd")
    except OSError:
        cwd = None
    info["env"] = inject_env(read(f"/proc/{pid}/environ", True), exe)
    info["app"] = app_identity(exe, args, cwd, info["env"])
    parsed = parse_interpreter(exe, args, cwd)
    info["script"] = parsed[1] if parsed and parsed[1] and parsed[1].startswith("/") else ""
    return info


class Dpkg:
    """Which Debian package owns a file, and what that package is (reads /var/lib/dpkg)."""

    def __init__(self, root="/var/lib/dpkg"):
        self.root = root
        self.lock = threading.Lock()
        self.mtime = None
        self.cache = {}
        self.desc = {}

    def _refresh(self):
        try:
            mt = os.stat(f"{self.root}/status").st_mtime
        except OSError:
            return
        if mt == self.mtime:
            return
        self.mtime, self.cache, self.desc = mt, {}, {}
        pkg = None
        for line in read(f"{self.root}/status").splitlines():
            if line.startswith("Package: "):
                pkg = line[9:].strip()
            elif line.startswith("Description: ") and pkg:
                self.desc[pkg] = line[13:].strip()

    def owner(self, path):
        if not path or not path.startswith("/"):
            return None
        with self.lock:
            self._refresh()
            if path in self.cache:
                return self.cache[path]
            cands = {path, os.path.realpath(path)}
            for c in list(cands):
                cands.add(c[4:] if c.startswith("/usr/") else "/usr" + c)
            needles = ["\n" + c + "\n" for c in cands]
            found = None
            try:
                files = os.listdir(f"{self.root}/info")
            except OSError:
                files = []
            for f in files:
                if not f.endswith(".list"):
                    continue
                txt = "\n" + read(f"{self.root}/info/{f}") + "\n"
                if any(n in txt for n in needles):
                    found = f[:-5].split(":")[0]
                    break
            self.cache[path] = found
            return found

    def description(self, pkg):
        return self.desc.get(pkg, "")

    def explain(self, exe, script=""):
        """Plain-language description of a program."""
        pkg = self.owner(exe.replace(" (deleted)", ""))
        spkg = self.owner(script) if script.startswith("/") else None
        main = spkg or pkg
        if main:
            return _("Debian package '{pkg}': {desc}").format(pkg=main, desc=self.description(main))
        if script and pkg:
            return _("script {script} (not from a package) run by '{pkg}'").format(script=script, pkg=pkg)
        if exe.startswith(("/usr/local/", "/opt/")):
            return _("installed by hand (not from a Debian package)")
        return _("does NOT belong to any Debian package")


KTHREAD_NAMES = re.compile(r"^(kworker|kthreadd|ksoftirqd|kswapd|migration|rcu_|watchdog|irq/|jbd2|kauditd|khugepaged)")
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/run/shm/")


def suspicious(exe, comm, uid, script="", env=""):
    """Heuristic warnings: things worth checking, not proof of malware."""
    reasons = []
    if exe.endswith(" (deleted)"):
        reasons.append(_("its executable was deleted from disk after it started"))
    clean = exe.replace(" (deleted)", "")
    if clean.startswith(TEMP_DIRS):
        reasons.append(_("it runs from a temporary folder"))
    if any(part.startswith(".") for part in clean.split("/")[1:]):
        reasons.append(_("it runs from a hidden file or folder"))
    if clean.startswith("/memfd:"):
        reasons.append(_("it runs only in memory (memfd), without a file on disk"))
    if KTHREAD_NAMES.match(comm or ""):
        reasons.append(_("it calls itself '{name}' like a kernel thread, but it is a normal program").format(name=comm))
    if script.startswith(TEMP_DIRS):
        reasons.append(_("the script it runs is in a temporary folder"))
    if env:
        reasons.append(_("it was started with variables that load other code ({env})").format(env=env))
    if uid == 0:
        try:
            st = os.stat(clean)
            if st.st_uid != 0 or st.st_mode & 0o022:
                reasons.append(_("it runs as root but its file can be modified by normal users"))
        except OSError:
            pass
        if clean.startswith("/home/"):
            reasons.append(_("it runs as root from a home folder"))
    return reasons
