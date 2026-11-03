# SPDX-License-Identifier: GPL-3.0-or-later
"""Minimal NFQUEUE client over netlink, with no external libraries."""
import errno
import os
import socket
import struct
import threading

from .util import log

NETLINK_NETFILTER = 12
NFNL_SUBSYS_QUEUE = 3
NFQNL_MSG_PACKET, NFQNL_MSG_VERDICT, NFQNL_MSG_CONFIG = 0, 1, 2
# nfqueue configuration attributes
NFQA_CFG_CMD, NFQA_CFG_PARAMS, NFQA_CFG_QUEUE_MAXLEN, NFQA_CFG_MASK, NFQA_CFG_FLAGS = 1, 2, 3, 4, 5
NFQNL_CFG_CMD_BIND = 1
NFQNL_COPY_PACKET = 2
NFQA_CFG_F_GSO, NFQA_CFG_F_UID_GID = 4, 8
# packet attributes
NFQA_PACKET_HDR, NFQA_VERDICT_HDR = 1, 2
NFQA_IFINDEX_INDEV, NFQA_IFINDEX_OUTDEV = 5, 6
NFQA_PAYLOAD, NFQA_UID = 10, 16
NLM_F_REQUEST, NLM_F_ACK = 1, 4
NLMSG_ERROR = 2

NF_DROP, NF_ACCEPT = 0, 1
QUEUE_MAXLEN = 8192   # when full the kernel DROPS packets (no fail-open flag is ever set)


class NFQueue:
    def __init__(self):
        self.s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
        try:
            self.s.setsockopt(socket.SOL_SOCKET, 33, 8 << 20)  # SO_RCVBUFFORCE
        except OSError:
            self.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
        try:
            self.s.setsockopt(270, 5, 1)  # SOL_NETLINK, NETLINK_NO_ENOBUFS
        except OSError:
            pass
        self.s.bind((0, 0))
        self.seq = 0
        self.wlock = threading.Lock()

    @staticmethod
    def attr(t, d):
        a = struct.pack("=HH", 4 + len(d), t) + d
        return a + b"\0" * (-len(a) % 4)

    def msg(self, mtype, q, attrs, flags):
        self.seq = (self.seq + 1) & 0xFFFFFFFF
        body = struct.pack("=BB", 0, 0) + struct.pack("!H", q) + attrs
        return struct.pack("=IHHII", 16 + len(body), (NFNL_SUBSYS_QUEUE << 8) | mtype, flags, self.seq, 0) + body

    def cfg(self, q, attrs):
        with self.wlock:
            self.s.send(self.msg(NFQNL_MSG_CONFIG, q, attrs, NLM_F_REQUEST | NLM_F_ACK))
        while True:
            data = self.s.recv(65536)
            off = 0
            while off + 16 <= len(data):
                ln, typ = struct.unpack_from("=IH", data, off)
                if typ == NLMSG_ERROR:
                    err = struct.unpack_from("=i", data, off + 16)[0]
                    if err:
                        raise OSError(-err, os.strerror(-err) + f" (queue {q})")
                    return
                off += max(16, (ln + 3) & ~3)

    def bind(self, q, copy):
        self.cfg(q, self.attr(NFQA_CFG_CMD, struct.pack("!BBH", NFQNL_CFG_CMD_BIND, 0, 0)))
        self.cfg(q, self.attr(NFQA_CFG_PARAMS, struct.pack("!IB", copy, NFQNL_COPY_PACKET)))
        self.cfg(q, self.attr(NFQA_CFG_QUEUE_MAXLEN, struct.pack("!I", QUEUE_MAXLEN)))
        flags = NFQA_CFG_F_GSO | NFQA_CFG_F_UID_GID
        self.cfg(q, self.attr(NFQA_CFG_FLAGS, struct.pack("!I", flags)) + self.attr(NFQA_CFG_MASK, struct.pack("!I", flags)))

    def verdict(self, q, pktid, v):
        """Send a verdict. Retries briefly on transient errors; raises if it still fails
        (the caller treats that as fatal: a lost verdict would leave the packet queued)."""
        for attempt in range(3):
            try:
                with self.wlock:
                    self.s.send(self.msg(NFQNL_MSG_VERDICT, q,
                                         self.attr(NFQA_VERDICT_HDR, struct.pack("!II", v, pktid)), NLM_F_REQUEST))
                return
            except OSError as e:
                if e.errno not in (errno.ENOBUFS, errno.EAGAIN, errno.EINTR) or attempt == 2:
                    raise

    @staticmethod
    def parse(data):
        """Yield (queue, packet_id, hook, payload, uid, indev, outdev) for each packet message."""
        off = 0
        while off + 16 <= len(data):
            ln, typ = struct.unpack_from("=IH", data, off)
            if ln < 16:
                break
            if typ == (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET and off + 20 <= len(data):
                q = struct.unpack_from("!H", data, off + 18)[0]
                a, end = off + 20, min(off + ln, len(data))
                pktid = hook = uid = indev = outdev = None
                payload = b""
                while a + 4 <= end:
                    al, at = struct.unpack_from("=HH", data, a)
                    if al < 4:
                        break
                    at &= 0x3FFF
                    v = data[a + 4:a + al]
                    if at == NFQA_PACKET_HDR and len(v) >= 7:
                        pktid, _hw, hook = struct.unpack("!IHB", v[:7])
                    elif at == NFQA_PAYLOAD:
                        payload = v
                    elif at == NFQA_UID and len(v) >= 4:
                        uid = struct.unpack("!I", v[:4])[0]
                    elif at == NFQA_IFINDEX_INDEV and len(v) >= 4:
                        indev = struct.unpack("!I", v[:4])[0]
                    elif at == NFQA_IFINDEX_OUTDEV and len(v) >= 4:
                        outdev = struct.unpack("!I", v[:4])[0]
                    a += (al + 3) & ~3
                if pktid is not None:
                    yield q, pktid, hook, payload, uid, indev, outdev
            off += (ln + 3) & ~3

    def loop(self, cb, fail_verdict):
        """Read packets forever. cb() exceptions never stop the loop: the packet is dropped."""
        while True:
            try:
                data = self.s.recv(1 << 18)
            except OSError as e:
                if e.errno in (errno.ENOBUFS, errno.EINTR, errno.EAGAIN):
                    log(f"netlink: {e} (packets lost are dropped by the kernel)")
                    continue
                raise
            for q, pktid, hook, payload, uid, indev, outdev in self.parse(data):
                try:
                    cb(q, pktid, hook, payload, uid, indev, outdev)
                except Exception as e:  # noqa: BLE001 - must keep the firewall alive
                    log(f"packet handling error: {e!r}: dropping packet")
                    fail_verdict(q, pktid)
