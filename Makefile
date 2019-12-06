# Makefile for mercury
#

INSTALL = /usr/bin/install -c
INSTALLDATA = /usr/bin/install -c -m 644

.PHONY: mercury
mercury:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo "error: run ./configure before running make (src/Makefile is missing)"
else
	cd src && $(MAKE)
endif

.PHONY: install install-no-systemd
install: install-mercury install-resources install-etc-config install-systemd
install-nosystemd: install-mercury install-resources install-etc-config

.PHONY: install-mercury
install-mercury:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo "error: run ./configure before running make (src/Makefile is missing)"
else
	cd src && $(MAKE) install
endif

.PHONY: install-resources
install-resources:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo "error: run ./configure before running make (src/Makefile is missing)"
else
	cd resources && $(MAKE) install
endif

.PHONY: install-etc-config
install-etc-config:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo "error: run ./configure before running make (src/Makefile is missing)"
else
	$(INSTALL) -d /etc/mercury
	$(INSTALLDATA) mercury.cfg /etc/mercury
endif

.PHONY: install-systemd
install-systemd:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo "error: run ./configure before running make (src/Makefile is missing)"
else
	$(INSTALLDATA) install_mercury/mercury.service /etc/systemd/system/
	systemctl start mercury
	systemctl enable mercury
endif

.PHONY: uninstall
uninstall: uninstall-mercury uninstall-systemd 

.PHONY: uninstall-mercury
uninstall-mercury:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo "error: run ./configure before running make (src/Makefile is missing)"
else
	rm -f  /etc/mercury/mercury.cfg
	rm -rf /etc/mercury
	cd src && $(MAKE) uninstall
	cd resources && $(MAKE) uninstall
endif

.PHONY: uninstall-systemd
uninstall-systemd:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo "error: run ./configure before running make (src/Makefile is missing)"
else
	systemctl stop mercury
	systemctl disable mercury
	rm /etc/systemd/system/mercury.service
endif


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
	@echo "error: run ./configure before running make (src/Makefile is missing)"
	@/bin/false
else
	cd src && $(MAKE) clean
	cd test && $(MAKE) clean
	rm -rf doc/latex
endif

.PHONY: distclean
distclean: clean
	rm -rf autom4te.cache config.log config.status
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo "error: run ./configure before running make (src/Makefile is missing)"
	@/bin/false
else
	cd src  && $(MAKE) distclean
	cd test && $(MAKE) distclean
	cd resources && $(MAKE) distclean
endif

.PHONY: format
format:
	git ls-tree --full-tree --name-only -r HEAD | egrep '\.(py|c|h)$$' | xargs ./utils/indent_files.sh

# EOF
