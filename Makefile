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

.PHONY: all pot check lint install clean
