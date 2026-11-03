# Varco - interactive per-application firewall and process watchdog
# Copyright (C) 2026 K1m1k
# SPDX-License-Identifier: GPL-3.0-or-later
"""Varco: interactive per-application firewall for Debian."""
import gettext
import os

VERSION = "1.0.3"
APP_ID = "org.k1m1k.Varco"
DBUS_NAME = "org.k1m1k.Varco1"
DBUS_PATH = "/org/k1m1k/Varco1"
DBUS_IFACE = "org.k1m1k.Varco1"

LOCALEDIR = os.environ.get("VARCO_LOCALEDIR", "/usr/share/locale")
_t = gettext.translation("varco", LOCALEDIR, fallback=True)
_ = _t.gettext
ngettext = _t.ngettext
