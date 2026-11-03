# SPDX-License-Identifier: GPL-3.0-or-later
"""Process watchdog: the kernel reports every program start (proc connector)."""
import os
import queue
import socket
import struct
import threading
import traceback

from . import paths
from .procinfo import Dpkg, describe, suspicious
from .util import load_json_checked, log, now_hms, read, save_json

NETLINK_CONNECTOR = 11
CN_IDX_PROC = 1
PROC_CN_MCAST_LISTEN = 1
PROC_EVENT_EXEC = 2


class Watchdog:
    def __init__(self, emit):
        self.emit = emit
        self.dpkg = Dpkg()
        self.q = queue.Queue(maxsize=20000)
        data = load_json_checked(paths.SEEN, None, list)
        self.first_run = data is None
        self.seen = set(data or [])
        self.dirty = False
        self.lock = threading.Lock()
        self.threads = []

    def running(self):
        """False if a watchdog thread stopped (the firewall keeps working; the user is told)."""
        return bool(self.threads) and all(t.is_alive() for t in self.threads)

    def baseline(self):
        """First start: programs already running are considered known."""
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                try:
                    self.seen.add(describe(int(pid))["app"])
                except Exception:
                    pass
        self.seen.discard("?")
        self.dirty = True

    def save(self):
        with self.lock:
            if not self.dirty:
                return
            self.dirty = False
            data = sorted(self.seen)
        save_json(paths.SEEN, data)

    def listen(self):
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
        s.bind((0, CN_IDX_PROC))
        cn = struct.pack("=IIIIHH", CN_IDX_PROC, 1, 0, 0, 4, 0) + struct.pack("=I", PROC_CN_MCAST_LISTEN)
        s.send(struct.pack("=IHHII", 16 + len(cn), 3, 0, 0, 0) + cn)  # NLMSG_DONE
        while True:
            try:
                data, (sender, _groups) = s.recvfrom(65536)
            except OSError:
                continue
            if sender != 0:
                continue      # only the kernel reports program starts; anything else is forged
            off = 0
            while off + 16 <= len(data):
                ln = struct.unpack_from("=I", data, off)[0]
                if ln < 16:
                    break
                ev = data[off + 36:off + ln]   # nlmsghdr (16) + cn_msg (20)
                if len(ev) >= 24 and struct.unpack_from("=I", ev)[0] == PROC_EVENT_EXEC:
                    try:
                        self.q.put_nowait(struct.unpack_from("=ii", ev, 16)[1])
                    except queue.Full:
                        pass
                off += (ln + 3) & ~3

    def work(self):
        while True:
            pid = self.q.get()
            try:
                self.handle(pid)
            except Exception:
                log("watchdog error:\n" + traceback.format_exc())

    def handle(self, pid):
        info = describe(pid)
        if info["exe"] == "?":
            return
        comm = read(f"/proc/{pid}/comm").strip()
        exe = info["exe"]
        script = info["script"]
        reasons = suspicious(exe, comm, info["uid"], script, info["env"])
        with self.lock:
            new = info["app"] not in self.seen
            if new:
                self.seen.add(info["app"])
                self.dirty = True
        if not (new or reasons):
            return
        what = self.dpkg.explain(exe, script)
        log(("SUSPICIOUS " if reasons else "NEW ") + f"program {info['app']} (pid {pid}, {info['user']}) - {what}"
            + (" - " + "; ".join(reasons) if reasons else ""))
        self.emit({"ev": "process", "ts": now_hms(), "pid": pid, "name": comm, "app": info["app"],
                   "cmd": info["cmd"], "user": info["user"], "uid": info["uid"], "unit": info["unit"],
                   "parent": info["parent"], "what": what, "new": new, "suspicious": reasons})

    def start(self):
        """The watchdog is useful but not critical: if it fails the firewall keeps working."""
        if self.first_run:
            self.baseline()
            try:
                self.save()
            except OSError as e:
                log(f"watchdog: cannot save known programs: {e}")

        def guarded(fn, name):
            def run():
                try:
                    fn()
                except Exception:  # noqa: BLE001
                    log(f"watchdog ({name}) stopped, the firewall keeps working:\n" + traceback.format_exc())
            t = threading.Thread(target=run, daemon=True, name=name)
            self.threads.append(t)
            t.start()
        guarded(self.listen, "proc-connector")
        guarded(self.work, "watchdog")

