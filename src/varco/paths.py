# SPDX-License-Identifier: GPL-3.0-or-later
"""File system locations (FHS). Overridable through the environment for tests."""
import os

ETC = os.environ.get("VARCO_ETC", "/etc/varco")
VAR = os.environ.get("VARCO_VAR", "/var/lib/varco")

CONFIG_DEFAULTS = os.path.join(ETC, "config.json")      # conffile managed by dpkg
CONFIG_OVERRIDES = os.path.join(VAR, "settings.json")    # changes made from the GUI/CLI
RULES = os.path.join(VAR, "rules.json")
STATE = os.path.join(VAR, "state.json")
SEEN = os.path.join(VAR, "known-programs.json")

NFT = "/usr/sbin/nft"
SYSTEMCTL = "/usr/bin/systemctl"
HELPER = "/usr/libexec/varco/varco-helper"
ANON_TOOL = "/usr/sbin/varco-privacy"
