# Makefile for mercury
#

# definitions for colorized output
COLOR_RED    = "\033[0;31m"
COLOR_GREEN  = "\033[0;32m"
COLOR_YELLOW = "\033[0;33m"
COLOR_OFF    = "\033[0m"

INSTALL = /usr/bin/install -c
INSTALLDATA = /usr/bin/install -c -m 644

.PHONY: mercury
mercury:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo $(COLOR_RED) "error: run ./configure before running make (src/Makefile is missing)" $(COLOR_OFF)
else
	cd src && $(MAKE)
endif

.PHONY: install install-no-systemd
install: install-mercury install-resources install-etc-config install-systemd
install-nosystemd: install-mercury install-resources install-etc-config

.PHONY: install-mercury
install-mercury:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo $(COLOR_RED) "error: run ./configure before running make (src/Makefile is missing)" $(COLOR_OFF)
else
	cd src && $(MAKE) install
	$(INSTALLDATA) mercury /usr/share/bash-completion/completions/ # note: completion script has same name as binary
endif

.PHONY: install-resources
install-resources:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo $(COLOR_RED) "error: run ./configure before running make (src/Makefile is missing)" $(COLOR_OFF)
else
	cd resources && $(MAKE) install
endif

# leave this variable empty; we want to force the user to set it, as a
# reminder that they should create a usable local configuration
MERCURY_CFG =
.PHONY: install-etc-config
install-etc-config:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo $(COLOR_RED) "error: run ./configure before running make (src/Makefile is missing)" $(COLOR_OFF)
else
ifneq ($(MERCURY_CFG),)
	$(INSTALL) -d /etc/mercury
	$(INSTALLDATA) $(MERCURY_CFG) /etc/mercury/mercury.cfg
else
	@echo $(COLOR_RED) "error: you must specify the configuration file; run as 'make install MERCURY_CFG=filename'" $(COLOR_OFF)
	@echo $(COLOR_RED) "where 'filename' is the configuration file you want to use for this installation.  You can" $(COLOR_OFF)
	@echo $(COLOR_RED) "use mercury.cfg as a template, but you *must* change the interface line to the appropriate" $(COLOR_OFF)
	@echo $(COLOR_RED) "network interface for your system.  (Use 'cat /proc/net/dev' to see Linux interfaces.)"     $(COLOR_OFF)
	@/bin/false
endif
endif

.PHONY: install-systemd
install-systemd: install-etc-config
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo $(COLOR_RED) "error: run ./configure before running make (src/Makefile is missing)" $(COLOR_OFF)
else
	$(INSTALLDATA) install_mercury/mercury.service /etc/systemd/system/
	systemctl start mercury
	systemctl enable mercury
endif

.PHONY: install-nonroot
install-nonroot:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo $(COLOR_RED) "error: run ./configure before running make (src/Makefile is missing)" $(COLOR_OFF)
else
	cd src && $(MAKE) install-nonroot
	cd resources && $(MAKE) install-nonroot
endif

.PHONY: uninstall
uninstall: uninstall-mercury uninstall-systemd

.PHONY: uninstall-mercury
uninstall-mercury:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo $(COLOR_RED) "error: run ./configure before running make (src/Makefile is missing)" $(COLOR_OFF)
else
	rm -f  /etc/mercury/mercury.cfg
	rm -rf /etc/mercury
	cd src && $(MAKE) uninstall
	cd resources && $(MAKE) uninstall
endif

.PHONY: uninstall-systemd
uninstall-systemd:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo $(COLOR_RED) "error: run ./configure before running make (src/Makefile is missing)" $(COLOR_OFF)
else
	systemctl stop mercury
	systemctl disable mercury
	rm /etc/systemd/system/mercury.service
	userdel mercury
endif

# the target libs builds three versions of libmerc.so, and copies them
# to the folder libs/
.PHONY: libs
libs:
	$(MAKE) --directory=src clean
	$(MAKE) --directory=src libmerc
	$(MAKE) --directory=src clean
	$(MAKE) --directory=src debug-libmerc
	$(MAKE) --directory=src clean
	$(MAKE) --directory=src unstripped-libmerc

.PHONY: test
test:
	cd src && $(MAKE) test

.PHONY: doc
doc: doc/mercury.pdf

doc/mercury.pdf:
	doxygen
	cd doc/latex; make; mv refman.pdf ../mercury.pdf

.PHONY: clean
clean:
	for file in Makefile README.md configure.ac Doxyfile; do if [ -e "$$file~" ]; then rm -f "$$file~" ; fi; done
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo $(COLOR_RED) "error: run ./configure before running make (src/Makefile is missing)" $(COLOR_OFF)
	@/bin/false
else
	cd src && $(MAKE) clean
	cd test && $(MAKE) clean
	rm -rf doc/latex
endif

.PHONY: distclean
distclean: clean
	rm -rf autom4te.cache config.log config.status
	rm -f lib/*.so
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo $(COLOR_RED) "error: run ./configure before running make (src/Makefile is missing)" $(COLOR_OFF)
	@/bin/false
else
	cd src  && $(MAKE) distclean
	cd test && $(MAKE) distclean
	cd resources && $(MAKE) distclean
endif

.PHONY: package-deb
package-deb: mercury
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo $(COLOR_RED) "error: run ./configure before running make (src/Makefile is missing)" $(COLOR_OFF)
else
	./build_pkg.sh -t deb 
endif

.PHONY: package-rpm
package-rpm: mercury
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo $(COLOR_RED) "error: run ./configure before running make (src/Makefile is missing)" $(COLOR_OFF)
else
	./build_pkg.sh -t rpm
endif

.PHONY: format
format:
	./utils/indent_files.sh src/*.{c,h} src/python-inference/*.py python/*.py python/*/*.py python/*/*/*.py

.PHONY: increment-patchlevel increment-minor-version increment-major-version
increment-patchlevel:
	cd src; make increment-patchlevel

increment-minor-version:
	cd src; make increment-minor-version

increment-major-version:
	cd src; make increment-major-version

# EOF
