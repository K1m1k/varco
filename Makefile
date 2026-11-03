# Varco - build and install (used by debian/rules through debhelper)
PREFIX ?= /usr
DESTDIR ?=
PYTHON ?= python3
SHARE = $(DESTDIR)$(PREFIX)/share
LINGUAS = $(shell cat po/LINGUAS)
MOS = $(patsubst %,build/locale/%/LC_MESSAGES/varco.mo,$(LINGUAS))

all: $(MOS) build/failsafe.nft

# the table loaded by systemd before the daemon starts: generated from the same code
build/failsafe.nft: src/varco/core.py
	mkdir -p build
	$(PYTHON) -c 'import sys; sys.path.insert(0, "src"); from varco.core import failsafe_ruleset; print(failsafe_ruleset(), end="")' > $@

build/locale/%/LC_MESSAGES/varco.mo: po/%.po
	mkdir -p $(dir $@)
	msgfmt --check -o $@ $<

pot:
	xgettext --language=Python --from-code=UTF-8 --keyword=_ --add-comments=TRANSLATORS \
		--package-name=varco --msgid-bugs-address=https://github.com/K1m1k/varco/issues \
		-o po/varco.pot $(shell cat po/POTFILES)

check:
	$(PYTHON) -m unittest discover -s tests -v

# static checks: skipped (with a note) when the tool is not installed
lint:
	@if command -v ruff >/dev/null; then ruff check --select E,F,W,B --ignore E501 src bin tests; \
	else echo "ruff not installed: skipped"; fi
	@if command -v shellcheck >/dev/null; then shellcheck -s sh debian/tests/smoke debian/tests/system \
		debian/*.postinst debian/*.prerm debian/*.postrm tools/installa-offline.sh; \
	else echo "shellcheck not installed: skipped"; fi

install: all
	# Python modules (private, not a public library)
	for d in varco varco/gtk varco_privacy; do \
		install -d $(SHARE)/varco/$$d; \
		install -m 644 src/$$d/*.py $(SHARE)/varco/$$d/; \
	done
	# programs
	install -D -m 755 bin/varcod $(DESTDIR)$(PREFIX)/sbin/varcod
	install -D -m 755 bin/varco $(DESTDIR)$(PREFIX)/bin/varco
	install -D -m 755 bin/varco-gtk $(DESTDIR)$(PREFIX)/bin/varco-gtk
	install -D -m 755 bin/varco-helper $(DESTDIR)$(PREFIX)/libexec/varco/varco-helper
	install -D -m 755 bin/varco-privacy $(DESTDIR)$(PREFIX)/sbin/varco-privacy
	install -D -m 644 build/failsafe.nft $(SHARE)/varco/failsafe.nft
	# system integration
	install -D -m 644 data/varco.service $(DESTDIR)$(PREFIX)/lib/systemd/system/varco.service
	install -D -m 644 data/varco-mask.service $(DESTDIR)$(PREFIX)/lib/systemd/system/varco-mask.service
	install -D -m 644 data/org.k1m1k.Varco1.conf $(SHARE)/dbus-1/system.d/org.k1m1k.Varco1.conf
	install -D -m 644 data/org.k1m1k.varco.policy $(SHARE)/polkit-1/actions/org.k1m1k.varco.policy
	install -D -m 644 data/org.k1m1k.varco.privacy.policy $(SHARE)/polkit-1/actions/org.k1m1k.varco.privacy.policy
	install -D -m 644 data/config.json $(DESTDIR)/etc/varco/config.json
	# desktop
	install -D -m 644 data/org.k1m1k.Varco.desktop $(SHARE)/applications/org.k1m1k.Varco.desktop
	install -D -m 644 data/org.k1m1k.Varco-autostart.desktop $(DESTDIR)/etc/xdg/autostart/org.k1m1k.Varco-autostart.desktop
	install -D -m 644 data/org.k1m1k.Varco.metainfo.xml $(SHARE)/metainfo/org.k1m1k.Varco.metainfo.xml
	install -D -m 644 data/org.k1m1k.Varco.svg $(SHARE)/icons/hicolor/scalable/apps/org.k1m1k.Varco.svg
	# translations
	for l in $(LINGUAS); do \
		install -D -m 644 build/locale/$$l/LC_MESSAGES/varco.mo $(SHARE)/locale/$$l/LC_MESSAGES/varco.mo; \
	done

clean:
	rm -rf build
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

.PHONY: all pot check lint install clean
