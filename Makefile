# Makefile for mercury
#

.PHONY: mercury test install
mercury:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo "error: run ./configure before running make (src/Makefile is missing)"
else
	cd src && $(MAKE)
endif

install:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo "error: run ./configure before running make (src/Makefile is missing)"
else
	cd src && $(MAKE) install
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
endif

.PHONY: format
format:
	git ls-tree --full-tree --name-only -r HEAD | egrep '\.(py|c|h)$$' | xargs ./utils/indent_files.sh

# EOF
