# SPDX-License-Identifier: GPL-3.0-or-later
"""The privacy module on a fake root: changes are journaled, restore is verified and
idempotent, interruptions never lose the original values."""
import importlib
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def fresh_root(nm=True):
    root = tempfile.mkdtemp()
    os.makedirs(f"{root}/etc/systemd/network")
    os.makedirs(f"{root}/var/lib/dbus")
    if nm:
        os.makedirs(f"{root}/etc/NetworkManager/conf.d")
    with open(f"{root}/etc/hostname", "w") as f:
        f.write("myhost\n")
    with open(f"{root}/etc/hosts", "w") as f:
        f.write("127.0.0.1\tlocalhost\n127.0.1.1\tmyhost\n::1\tlocalhost ip6-localhost\n")
    with open(f"{root}/etc/machine-id", "w") as f:
        f.write("0123456789abcdef0123456789abcdef\n")
    with open(f"{root}/var/lib/dbus/machine-id", "w") as f:
        f.write("0123456789abcdef0123456789abcdef\n")
    return root


def load(root):
    os.environ["VARCO_PRIVACY_ROOT"] = root
    import varco_privacy.main as m
    return importlib.reload(m)


def read(p):
    with open(p) as f:
        return f.read()


class TestPrivacy(unittest.TestCase):
    def setUp(self):
        self.root = fresh_root()
        self.addCleanup(shutil.rmtree, self.root)
        self.m = load(self.root)
        self.orig = {p: read(self.root + p) for p in ("/etc/hostname", "/etc/hosts", "/etc/machine-id",
                                                      "/var/lib/dbus/machine-id")}

    def assert_original(self):
        for p, v in self.orig.items():
            self.assertEqual(read(self.root + p), v, p)

    def test_all_then_restore(self):
        self.assertEqual(self.m.main(["all"]), 0)
        self.assertEqual(read(self.root + "/etc/hostname"), "debian\n")
        self.assertNotEqual(read(self.root + "/etc/machine-id"), self.orig["/etc/machine-id"])
        self.assertTrue(os.path.exists(self.m.NM_CONF))
        conf = read(self.m.NM_CONF)
        self.assertIn("ipv4.dhcp-send-hostname=false", conf)       # the name is not sent to the router
        self.assertIn("ipv6.dhcp-send-hostname=false", conf)
        self.assertEqual(self.m.main(["restore"]), 0)
        self.assert_original()
        self.assertFalse(os.path.exists(self.m.NM_CONF))
        self.assertEqual(json.loads(read(self.m.STATE))["changes"], {})

    def test_restore_is_idempotent(self):
        self.m.main(["hostname", "pc1"])
        self.m.main(["hostname", "pc2"])          # second change keeps the FIRST original
        self.assertEqual(self.m.main(["restore"]), 0)
        self.assertEqual(self.m.main(["restore"]), 0)
        self.assert_original()

    def test_hosts_edits_made_later_are_kept(self):
        self.m.main(["hostname", "debian"])
        with open(self.root + "/etc/hosts", "a") as f:
            f.write("192.168.1.10\tnas\n")
        self.m.main(["restore"])
        hosts = read(self.root + "/etc/hosts")
        self.assertIn("127.0.1.1\tmyhost", hosts)
        self.assertIn("192.168.1.10\tnas", hosts)

    def test_interrupted_change_can_be_restored(self):
        # crash right after the journal was written, before /etc/hostname changed
        st = self.m.load_state()
        real = self.m.set_hostname
        self.m.set_hostname = lambda name: (_ for _ in ()).throw(OSError("power loss"))
        with self.assertRaises(OSError):
            self.m.apply_hostname(st, "debian")
        self.m.set_hostname = real
        self.assertIn("hostname", json.loads(read(self.m.STATE))["changes"])
        m2 = load(self.root)                       # "after reboot": a new process
        self.assertEqual(m2.main(["restore"]), 0)
        self.assert_original()

    def test_failed_restore_keeps_originals(self):
        self.m.main(["machine-id"])
        changed = read(self.root + "/etc/machine-id")
        real = self.m.write_atomic

        def broken(path, text, mode=0o644):
            if path.endswith("/etc/machine-id"):
                raise OSError("read-only file system")
            return real(path, text, mode)
        self.m.write_atomic = broken
        self.assertEqual(self.m.restore(), 1)
        self.assertIn("machine_id", json.loads(read(self.m.STATE))["changes"])   # originals kept
        self.assertEqual(read(self.root + "/etc/machine-id"), changed)
        self.m.write_atomic = real
        self.assertEqual(self.m.restore(), 0)
        self.assert_original()

    def test_journal_with_wrong_shape_is_refused(self):
        os.makedirs(self.m.VAR, exist_ok=True)
        with open(self.m.STATE, "w") as f:
            f.write("[1, 2]")
        with self.assertRaises(self.m.Failed):
            self.m.load_state()
        self.assertEqual(read(self.m.STATE), "[1, 2]")

    def test_damaged_journal_is_never_overwritten(self):
        self.m.main(["hostname", "debian"])
        with open(self.m.STATE, "w") as f:
            f.write("{broken")
        self.assertEqual(self.m.main(["hostname", "other"]), 1)
        self.assertEqual(read(self.m.STATE), "{broken")

    def test_without_networkmanager(self):
        root = fresh_root(nm=False)
        self.addCleanup(shutil.rmtree, root)
        m = load(root)
        self.assertEqual(m.main(["mac", "stable"]), 1)        # not possible without NetworkManager
        self.assertEqual(m.main(["mac", "random"]), 0)
        self.assertTrue(os.path.exists(m.LINK_DROPIN))
        self.assertFalse(os.path.exists(root + "/etc/systemd/network/10-varco-privacy.link"))
        self.assertEqual(m.main(["mac", "off"]), 0)
        self.assertFalse(os.path.exists(m.LINK_DROPIN))
        self.assertEqual(json.loads(read(m.STATE))["changes"], {})

    def test_hardware_journal(self):
        self.assertEqual(self.m.main(["hardware", "on"]), 0)
        self.assertIn("hardware", json.loads(read(self.m.STATE))["changes"])
        self.assertIn(("systemctl", "enable", "varco-mask.service"), self.m.COMMANDS)
        self.assertEqual(self.m.main(["hardware", "off"]), 0)
        self.assertNotIn("hardware", json.loads(read(self.m.STATE))["changes"])

    def test_existing_networkmanager_file_is_restored_exactly(self):
        conf = self.m.NM_CONF
        os.makedirs(os.path.dirname(conf), exist_ok=True)
        with open(conf, "w") as f:
            f.write("[connection]\nwifi.powersave=2\n")
        os.chmod(conf, 0o600)
        self.assertEqual(self.m.main(["mac", "random"]), 0)
        self.assertIn("varco-privacy", read(conf))
        self.assertEqual(self.m.main(["restore"]), 0)
        self.assertEqual(read(conf), "[connection]\nwifi.powersave=2\n")
        self.assertEqual(os.stat(conf).st_mode & 0o777, 0o600)

    def test_existing_link_dropin_is_restored_exactly(self):
        root = fresh_root(nm=False)
        self.addCleanup(shutil.rmtree, root)
        m = load(root)
        os.makedirs(os.path.dirname(m.LINK_DROPIN))
        with open(m.LINK_DROPIN, "w") as f:
            f.write("[Link]\nMTUBytes=1400\n")
        self.assertEqual(m.main(["mac", "random"]), 0)
        self.assertEqual(m.main(["mac", "off"]), 0)
        self.assertEqual(read(m.LINK_DROPIN), "[Link]\nMTUBytes=1400\n")

    def test_foreign_file_with_old_name_is_not_deleted(self):
        with open(self.m.OLD_LINK, "w") as f:
            f.write("[Match]\nName=eth0\n")
        self.m.main(["hostname", "x"])
        self.m.main(["restore"])
        self.assertTrue(os.path.exists(self.m.OLD_LINK))

    def test_journal_from_1_0_1_is_restored(self):
        self.m.save_state({"version": 1, "changes": {"mac": {"method": "nm", "mode": "random"}}})
        with open(self.m.NM_CONF, "w") as f:
            f.write(self.m.OUR_MARK + ". old\n")
        self.assertEqual(self.m.main(["restore"]), 0)
        self.assertFalse(os.path.exists(self.m.NM_CONF))

    def test_hardware_enable_failure_is_undone(self):
        self.m.FAIL.add(("systemctl", "enable", "varco-mask.service"))
        self.assertEqual(self.m.main(["hardware", "on"]), 1)
        self.assertNotIn("hardware", json.loads(read(self.m.STATE))["changes"])
        self.assertNotIn("varco-mask.service", self.m.FAKE_ENABLED)

    def test_hardware_not_really_enabled_is_undone(self):
        self.m.FAIL.add(("systemctl", "is-enabled", "varco-mask.service"))
        self.assertEqual(self.m.main(["hardware", "on"]), 1)
        self.assertNotIn("hardware", json.loads(read(self.m.STATE))["changes"])

    def test_verify(self):
        self.m.main(["mac", "random"])
        self.m.main(["hardware", "on"])
        self.assertEqual(self.m.main(["verify"]), 0)
        os.remove(self.m.NM_CONF)                       # someone deleted our file
        self.assertEqual(self.m.main(["verify"]), 1)

    def test_no_dependency_on_main_package(self):
        src = read(os.path.join(os.path.dirname(__file__), "..", "src", "varco_privacy", "main.py"))
        self.assertNotIn("from varco ", src)
        self.assertNotIn("import varco\n", src)


if __name__ == "__main__":
    unittest.main()
