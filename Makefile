# Makefile for mercury
#

INSTALL = /usr/bin/install -c
INSTALLDATA = /usr/bin/install -c -m 644

.PHONY: mercury test install 
mercury:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo "error: run ./configure before running make (src/Makefile is missing)"
else
	cd src && $(MAKE)
endif

.PHONY: install
install: install-mercury install-resources

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

# EOF
