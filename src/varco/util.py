# SPDX-License-Identifier: GPL-3.0-or-later
"""Small shared helpers."""
import ipaddress
import json
import os
import pwd
import sys
import threading
import time

_loglock = threading.Lock()


def log(msg):
    """Log to stdout: under systemd this ends up in the journal."""
    with _loglock:
        print(msg, file=sys.stdout, flush=True)


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def load_json_checked(path, default, kind):
    """Like load_json, for files Varco itself keeps (rules, state, settings).

    A missing file gives the default. A damaged file, or one holding the wrong kind of data,
    is never silently replaced: it is renamed to '<name>.damaged-<date>' (so nothing is lost
    when the default is saved later), the problem is logged, and the default is returned."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, kind):
            return data
        err = f"expected {kind.__name__}, found {type(data).__name__}"
    except FileNotFoundError:
        return default
    except (OSError, ValueError) as e:
        err = str(e)
    bad = f"{path}.damaged-{time.strftime('%Y%m%d-%H%M%S')}"
    try:
        os.replace(path, bad)
        log(f"WARNING: {path} is damaged ({err}): kept as {bad}, starting from the defaults")
    except OSError as e:
        log(f"WARNING: {path} is damaged ({err}) and cannot be set aside ({e}): using the defaults")
    return default


def write_atomic(path, text, mode=0o600):
    """Write a file so that after a crash or power loss it holds either the old or the new
    content, never a partial one: temporary file, fsync, rename, fsync of the directory."""
    d = os.path.dirname(path) or "."
    tmp = f"{path}.tmp-{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
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


def save_json(path, data):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    write_atomic(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def sd_notify(msg):
    """systemd notification (READY=1, WATCHDOG=1, STATUS=...). No-op outside systemd."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    import socket
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(addr)
            s.sendall(msg.encode())
        return True
    except OSError:
        return False


def boot_id():
    return read("/proc/sys/kernel/random/boot_id").strip()


class RateLimit:
    """Token bucket: allow() is True at most `rate` times per second (burst `burst`)."""

    def __init__(self, rate, burst):
        self.rate, self.burst = rate, burst
        self.tokens, self.t = burst, time.monotonic()
        self.suppressed = 0
        self.lock = threading.Lock()

    def allow(self):
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.burst, self.tokens + (now - self.t) * self.rate)
            self.t = now
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            self.suppressed += 1
            return False

    def take_suppressed(self):
        with self.lock:
            n, self.suppressed = self.suppressed, 0
            return n


def read(path, binary=False):
    try:
        with open(path, "rb" if binary else "r") as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return b"" if binary else ""


def username(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, TypeError):
        return str(uid) if uid is not None else "?"


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_global and not a.is_multicast
    except ValueError:
        return False


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
    except ValueError:
        return False


def now_hms():
    return time.strftime("%H:%M:%S")
