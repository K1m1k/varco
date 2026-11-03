# Security design

This document describes how Varco handles privileges, what it protects against, and
what it does not.

## Components and privileges

| Component | Runs as | Privileges |
|---|---|---|
| `varcod` | root, systemd service | capabilities limited to `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`, `CAP_KILL` |
| `varco-gtk` | desktop user | none: asks the service over D-Bus |
| `varco` (CLI) | caller | none: asks the service over D-Bus |
| `varco-helper` | root via `pkexec` | turns the service on or off, optional ptrace hardening, installs or removes Varco packages; arguments are a fixed whitelist |
| `varco-privacy` | root via `pkexec`, or the boot unit | changes identifiers; status works without root |

### systemd hardening of `varcod`

The unit `varco.service` uses these settings:

- `CapabilityBoundingSet` (the four capabilities listed above), with no ambient capabilities and `NoNewPrivileges`.
- `ProtectSystem=strict`, with write access only to `StateDirectory=varco`.
- `ProtectHome=read-only`, `PrivateDevices`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`.
- `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute`.
- `SystemCallArchitectures=native`, `SystemCallFilter=@system-service`.
- `RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6`.

The kernel modules are loaded by `ExecStartPre=+modprobe`, outside the sandbox.

`varcod` is still root. The sandbox limits the damage a bug could do, but it is
containment, not full isolation.

## Interfaces and authorization

The service listens on **no network port** and creates no world-writable socket. Its only
interface is the D-Bus **system bus** name `org.k1m1k.Varco1`, which only root may own.

Every method call is authorized by **polkit** against the caller's bus name. Root is always
allowed.

| polkit action | Methods | Default for the active session |
|---|---|---|
| `org.k1m1k.varco.monitor` | read state, events, requests, rules, connections | allowed |
| `org.k1m1k.varco.decide` | allow/block a request, turn the kill switch **on**, resume from pause, kill **own** processes | allowed |
| `org.k1m1k.varco.manage` | pause, kill switch **off**, add/remove rules, settings, kill other users' processes | administrator password (kept for a few minutes) |
| `org.k1m1k.varco.helper` | `varco-helper` (service on/off, packages) | administrator password |
| `org.k1m1k.varco.privacy` | `varco-privacy` changes | administrator password |

Inactive and remote sessions get nothing without the password.

### Known limit: desktop-level approvals

Like every interactive firewall with a desktop interface (OpenSnitch included), a program
that already runs as the desktop user can try to approve its own connection. It could do this
through the `decide` action or by activating a notification button.

The actions that open the network for everybody require the administrator password: pause,
kill switch off, and arbitrary rules from the rule editor. Through `decide`, a malicious program
at user level can approve, at most, a request that is already waiting. That includes the
permanent rule tied to that request's own program (*Allow always*, *Allow everything for this
program*).

Users who want the strictest setup can change the `decide` action to `auth_admin_keep` with a
polkit rule.

### Known limit: programs of the same user can control each other

On Debian `kernel.yama.ptrace_scope` is `0` by default: a program can read and change the
memory of any other program of the same user, and make an approved program (a browser, for
example) connect for it. When protection is turned on, Varco offers to set it to `1`
(`/etc/sysctl.d/60-varco-ptrace.conf`, written by `varco-helper ptrace on`): a
program may then only debug its own children. `varco status` warns when it is `0`.

## Firewall behaviour

- **Table and hooks.** `inet varco` hooks `input` and `output` at priority −10, on every
  interface: Wi-Fi, mobile broadband (WWAN, PPP), Ethernet, VPN. Loopback,
  established/related traffic, DHCP and essential ICMPv6 neighbour discovery are accepted.
  Every other new packet goes to NFQUEUE 4242, with no `bypass` and no fail-open flag.
- **Interface in rules.** The interface and its kind (`wifi`, `mobile`, `ethernet`, `vpn`)
  are part of every request and can be part of a rule. For example, *allow only on Wi-Fi*
  keeps a program off a metered mobile connection.
- **Kill switch.** It replaces the table with `drop` on `input`, `output` and `forward`. Every
  network is isolated, including connections already open and the traffic routed to virtual
  machines and containers. *Block* in a request stops only that connection.
- **Automatic kill switch.** It is **off** by default. It is offered as an explicit choice when
  protection is turned on.

### Fail-closed in real conditions

| Situation | What happens |
|---|---|
| Daemon killed or crashed | The table stays loaded and the queue has no reader: the kernel drops new connections. systemd restarts the daemon (`Restart=always`). |
| Daemon hung | `Type=notify` + `WatchdogSec=30`: no heartbeat → systemd kills and restarts it. Meanwhile the queue fills and the kernel drops. |
| A critical thread dies, or a verdict cannot be sent | The process exits on purpose (exit 70) and is restarted. A packet whose handling fails is dropped. |
| Daemon cannot start (bug, missing dependency) | `ExecStartPre` loads `failsafe.nft` (the same filtering, generated from the same code) before the daemon. New connections are dropped. |
| Too many crashes | `StartLimitBurst=10` in 120 s: systemd gives up, the failsafe table stays loaded and the interface shows *"service stopped: new connections are BLOCKED"* with a *Restart* button. |
| Another program removes the table (`nft flush ruleset`, `/etc/nftables.conf`, firewalld) or replaces it | Checked every 5 s by content: loaded again, logged, user notified. |
| nftables refuses a change | Kill switch and pause are recorded only after `nft` applied them; otherwise the state is unchanged and the error is reported. |
| NFQUEUE full | The kernel drops (no fail-open flag). |
| Flood (scan, many programs) | Inbound to closed ports: dropped before any work. Waiting requests capped (`max_pending`, default 100). Lookups run in a pool of 4 threads. Logging is rate-limited. Notifications are summarized. |
| Restart with kill switch on | The kill switch is applied again at boot before the network starts (`Before=network-pre.target`). |
| Restart while paused | The pause ends: protection is back after every restart. |
| Package removed while protection is on | `prerm` stops the service, disables it and deletes the table: the network is free. |

A clean `systemctl stop` leaves the table loaded, which is fail-closed. Turning protection off
from the interface (or with `varco-helper disable`) stops the service and deletes the table.

### DNS observation and the service's own traffic

- **DNS observation.** DNS answers are copied through NFQUEUE 4243 (with `bypass`, so DNS
  never depends on Varco) to learn which names the system really resolved. A name is
  valid only for the TTL of its record (minimum 30 s).
- **Only trusted answers.** An answer is learned only if it comes from one of the DNS servers
  the system uses (`/etc/resolv.conf`, `/run/systemd/resolve/resolv.conf`,
  `/run/NetworkManager/resolv.conf`; answers of a local resolver over loopback count too),
  and only for the name that was asked, following its CNAME chain. Extra records about other
  names are ignored, and names with characters outside letters, digits, `-`, `_` and dots
  are refused. Without this, a program could make up an answer such as
  `deb.debian.org → its own server` and pass the rules based on names.
- **DNS preset.** *Allow DNS* allows every program to reach only the DNS servers in use
  (`host: "@dns"`, re-read when the network changes), plus the local resolvers
  (systemd-resolved, dnsmasq, unbound) to any server. Before 1.0.3 it allowed any server on
  port 53, a free way out of the computer: old rules are converted automatically.
- **No reverse DNS.** Varco no longer asks the PTR name of each address: it was never
  shown and only told the DNS server every address contacted.
- **Varco's own traffic.** It is only whois, marked with `0x5e17`. whois is **off by
  default**: when on, every new public address is sent, unencrypted, to whois.iana.org and
  to the regional registry. With `"whois": false` Varco sends nothing.

## Process identification

Process identification uses `/proc/net/{tcp,udp}{,6}` and the `/proc/*/fd` socket inodes.

- **Interpreters.** For interpreters the identity includes the script, the module, or a
  SHA-256 prefix of inline code (`-c`, `-e`, `--eval`), **and every option written before
  it**: `python3 -X /approved.py other.py` runs `other.py`, so it is not taken for
  `/approved.py`; the same for `node --require …`. Code read from standard input is shown
  explicitly as such.
- **Code-loading variables.** `LD_PRELOAD`, `PYTHONPATH`, `NODE_OPTIONS` and the similar
  variables listed in `procinfo.INJECT_ENV` make an approved program run other code. When a
  program has them, their names and a hash of their values become part of its identity: the
  existing rules do not apply, and the request shows them.
- **Shared sockets.** A socket can be held by several processes (inherited across
  `fork`/`exec`, or passed over a UNIX socket). If the holders are different programs,
  nobody can tell which one sends: the connection is treated as coming from an unknown
  program, and only rules with `app: "*"` apply.
- **Unknown programs.** A permanent *allow* rule for an unknown program (`?`) must name one
  host and one port: a wildcard would let through everything that cannot be identified.
- **Terminating a process.** *Block and close the program* checks the start time of the
  process and uses a pidfd, so a different process that got the same pid is never killed.

## Process watchdog

The watchdog reads program starts from the kernel proc connector. It reports programs that:

- were never seen before;
- run from temporary or hidden locations, or have a deleted executable or none on disk
  (memfd);
- pretend to be kernel threads;
- run as root from user-writable files or home folders.

These are heuristics: they produce hints, not verdicts.

## Privacy module

The module is designed so that original identifiers are never lost:

- **Journal first.** Before any change, the original values go into
  `/var/lib/varco-privacy/state.json`. The file is written atomically: temporary file,
  `fsync`, rename, `fsync` of the directory. Only then is the system modified. An
  interruption at any point, including a power cut, leaves what is needed to restore.
- **Verified restore.** `restore` undoes each change, **verifies** the result, and drops the
  change from the journal only after the verification. It can be repeated any number of
  times.
- **Installing the module from the window.** It is not in the Debian archive: the user picks
  its `.deb`. `varco-helper` copies it into a root-only folder, checks the package name
  and version there, and installs that copy, so the file cannot be swapped after the password
  was given.
- **Removal.** Removing the package runs `restore`. If that fails, the removal **stops** with
  an explanation, unless `VARCO_PRIVACY_FORCE_REMOVE=1` is set. `purge` never deletes a
  journal that still holds unrestored originals.
- **`/etc/hosts`.** Only the `127.0.1.1` line is changed and restored. Other entries, including
  ones added later, are untouched.
- **MAC address without NetworkManager.** The module writes a drop-in for `99-default.link`.
  Interfaces configured by other `.link` files keep their settings, and names never change.
- **Self-contained.** The module does not depend on the code of the main package, so restore
  works even if that package is broken or gone.
- **Hardware serial numbers.** They are hidden with bind mounts over the `/sys` files, also at
  boot, only while the journal says so. The firmware values are not modified. Disk names in
  `/dev/disk/by-id` remain visible.
- **Mobile modems.** The operator always sees the IMEI and the SIM, and software cannot hide
  them. The module only reports their presence.

## Privacy of Varco itself

- whois is off by default; reverse DNS lookups were removed.
- `log_allowed` is off by default: the journal keeps blocked and waiting connections, not the
  list of every site the computer reached.
- Names, whois answers, command lines and program names are shown with control characters
  replaced, so they cannot drive a terminal (escape sequences) or fake text.
- The privacy module also stops NetworkManager from sending the computer name to the router
  (DHCP) and from answering LLMNR queries on the local network.

## Robustness

- **Errors.** Errors in packet handling drop the packet, never accept it. Errors in a D-Bus
  method are returned to the caller and logged; they do not stop the firewall.
- **Damaged files.** A rules, state or settings file that cannot be read is renamed to
  `<name>.damaged-<date>` and logged, never silently replaced. Rules that are not valid are
  kept under `invalid` in `rules.json` and never applied. `rules.json` carries a format
  version, so later versions can convert it.
- **Rules changed while running.** `varco-helper` adds its rules through the running
  service, which owns `rules.json`; `systemctl reload varco` reloads everything.
- **Restarts.** State (kill switch, pause) is kept across restarts. On package upgrade a
  running service is restarted; a stopped one stays stopped.
- **Installation.** Installing the package never starts the service, so `apt` cannot cut the
  network in the middle of an installation.

## Tests

- **Unit tests (`make check`).** They cover parsing of hostile input, the netlink loop
  surviving errors, rule matching, every failure path of the engine (lost verdict, crashed
  thread, nftables refusing a change, removed or altered table, flood, timeout, pause and
  kill switch across restarts), and the privacy module (interruption, failed restore,
  damaged journal, no NetworkManager).
- **System test (`debian/tests/system`).** It runs as root in a disposable virtual machine and
  restarts the machine between phases. It proves the table of *Fail-closed in real
  conditions* and the restore guarantees on a real Debian 13. It runs in autopkgtest or by
  hand.

## Out of scope

- Traffic forwarded to containers or virtual machines (the `forward` hook).
- A program that already runs as root: it can stop any firewall.
- Browser fingerprinting.

## Reporting a vulnerability

Open a private security advisory at <https://github.com/K1m1k/varco/security/advisories/new>.
