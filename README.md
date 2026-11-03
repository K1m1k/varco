# Varco

Interactive per-application firewall, process watchdog and privacy tools for Debian.

Varco holds every **new** network connection, outgoing or incoming, until a rule
or the user allows or blocks it. For each request it shows:

- **who asks**: executable, command line, user, systemd unit, parent process, and the
  Debian package the program belongs to;
- **where it goes**: the remote address, the name the system really resolved for it, the
  service behind the port, and optionally who owns the address (whois).

Decisions are made from desktop notifications (*Allow always*, *Only this time*, *Block*),
from the GTK 4 / libadwaita window, or from the terminal.

## Packages

| Package | Contents |
|---|---|
| `varco` | service `varcod`, command `varco`, polkit and D-Bus policy |
| `varco-gtk` | graphical interface, notifications, autostart |
| `varco-privacy` | optional: random MAC address, generic hostname, new machine-id, hidden serial numbers |

## Features

- Rules per program, host (address, network, or resolved name such as `*.debian.org`),
  port and protocol.
- Interpreters are identified by script, module or a hash of inline code: approving
  `python3 backup.py` does not approve any other Python program.
- Every network is covered: Wi-Fi, mobile broadband (WWAN), Ethernet, VPN. The network
  of each request is shown, and rules can be limited to a kind of network (for example
  *allow only on Wi-Fi*, to keep a program off a metered mobile connection).
- Kill switch: isolates the computer immediately from every network, including connections
  already open, virtual machines and containers. It is manual, or optionally automatic when
  an unapproved connection from the internet reaches a listening service.
- Pause and resume.
- Fail-closed in real conditions: a dead, hung or broken daemon, a removed firewall table
  or a flood never open the network. See [SECURITY.md](SECURITY.md).
- Watchdog: reports programs never seen before and programs with suspicious traits.
  These reports are hints to check, not proof of malware.

## Install

### Build the packages

Run these steps on Debian 13 (trixie):

```sh
sudo apt install build-essential debhelper gettext devscripts lintian
dpkg-buildpackage -us -uc -b
lintian ../varco_*.changes
```

### Install them

```sh
sudo apt install ../varco_1.0.3_all.deb ../varco-gtk_1.0.3_all.deb ../varco-privacy_1.0.3_all.deb
```

Without internet, the dependencies can come from the Debian 13 DVD 1 image: put
`tools/installa-offline.sh` next to the three `.deb` files and run it as root
(`sh installa-offline.sh /path/to/debian-13…-DVD-1.iso`). It checks the image against
`SHA512SUMS`, uses it as the only package source and leaves the apt sources untouched.

The service is **not** started at installation, because it would block every connection
before you can approve anything. Open *Varco* from the applications menu and press
**Turn on…**. Then choose whether to pre-approve DNS (only towards the DNS servers of the
computer), the essential system services, and the ptrace protection (a program can no
longer take control of another one, for example of an approved browser).

## Uninstall

Use *Uninstall Varco…* in the menu of the window, or run:

```sh
sudo apt purge varco varco-gtk varco-privacy
```

Purging removes rules, settings and state. The privacy module restores the original
identifiers before it is removed. Dependencies installed only for Varco can be
removed with `sudo apt autoremove`; check the list before confirming.

## Files

| Path | Purpose |
|---|---|
| `/etc/varco/config.json` | default settings (conffile) |
| `/var/lib/varco/` | rules, settings changed from the interfaces, state, known programs |
| `/usr/share/varco/` | program code |
| log | `journalctl -u varco` |

## Testing in a virtual machine

The system test proves the failure behaviour on a real Debian 13. It restarts the machine
several times, so run it only in a **disposable** virtual machine (GNOME Boxes or
virt-manager, both free).

1. Install the three packages in the VM.
2. Run, as root, from the source folder:

   ```sh
   sh debian/tests/system
   ```

3. When it says so, restart the VM and run the same command again. It ends with
   `ALL CHECKS PASSED`, or stops at the first `FAIL` and shows the service log.

With autopkgtest:

```sh
autopkgtest varco_*.changes -- qemu debian-trixie.img
```

## Development

```sh
make check          # unit tests
make lint           # ruff and shellcheck, if installed
make pot            # update the translation template
```

Every push runs the unit tests, the linters and a package build on Debian 13 (GitHub
Actions, `.github/workflows/ci.yml`).

The version is written in `debian/changelog`, `src/varco/__init__.py` and
`src/varco_privacy/__init__.py`: a unit test fails if they differ.

Code is under `src/`, the Debian packaging under `debian/`, translations under `po/`.
See [SECURITY.md](SECURITY.md) for the security design and its limits.

## License

GPL-3.0-or-later.

---

## Guida rapida in italiano

1. **Installa.** Installa i tre pacchetti `.deb` (vedi *Install*).
2. **Attiva.** Apri **Varco** dal menu delle applicazioni e premi **Attiva…**. Lascia
   spuntate le opzioni proposte (DNS, servizi di sistema, protezione ptrace), così il PC
   continua a funzionare ed è più difficile aggirare il firewall.
3. **Decidi.** Quando un programma vuole collegarsi compare una notifica con **Consenti
   sempre**, **Solo questa volta** e **Blocca**. Un clic sulla notifica apre tutti i dettagli.
4. **Isola.** Il pulsante rosso **Isola il computer** blocca subito tutta la rete. Per
   riaprire serve la password.
5. **Disinstalla.** Dal menu della finestra scegli **Disinstalla Varco…**. Toglie tutto
   e ripristina gli identificativi originali.
