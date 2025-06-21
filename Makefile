# Makefile for mercury
#

export OPTFLAGS

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
install: install-mercury install-etc-config
install-nosystemd: install-mercury install-etc-config

.PHONY: install-mercury
install-mercury:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo $(COLOR_RED) "error: run ./configure before running make (src/Makefile is missing)" $(COLOR_OFF)
else
	cd src && $(MAKE) install
	$(INSTALLDATA) mercury /usr/share/bash-completion/completions/ # note: completion script has same name as binary
endif

MERCURY_CFG = mercury.cfg
.PHONY: install-etc-config
install-etc-config:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo $(COLOR_RED) "error: run ./configure before running make (src/Makefile is missing)" $(COLOR_OFF)
else
ifneq ($(MERCURY_CFG),)
	$(INSTALL) -d /etc/mercury
	$(INSTALLDATA) $(MERCURY_CFG) /etc/mercury/mercury.cfg
else
	@echo $(COLOR_RED) "error: no configuration file specified; run as 'make install MERCURY_CFG=filename'" $(COLOR_OFF)
	@false
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
endif

.PHONY: install-certtools
install-certtools:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo $(COLOR_RED) "error: run ./configure before running make (src/Makefile is missing)" $(COLOR_OFF)
else
	cd src && $(MAKE) install-certtools
endif

.PHONY: uninstall
uninstall: uninstall-mercury uninstall-systemd uninstall-certtools

.PHONY: uninstall-mercury
uninstall-mercury:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo $(COLOR_RED) "error: run ./configure before running make (src/Makefile is missing)" $(COLOR_OFF)
else
	rm -f  /etc/mercury/mercury.cfg
	rm -rf /etc/mercury
	cd src && $(MAKE) uninstall
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

.PHONY: uninstall-certtools
uninstall-certtools:
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo $(COLOR_RED) "error: run ./configure before running make (src/Makefile is missing)" $(COLOR_OFF)
else
	cd src && $(MAKE) uninstall-certtools
endif

# the target libs builds three versions of libmerc.so, and copies them
# to the folder libs/
.PHONY: libs
libs:
	$(MAKE) --directory=src clean
	$(MAKE) --directory=src stripped-libmerc
	$(MAKE) --directory=src clean
	$(MAKE) --directory=src debug-libmerc
	$(MAKE) --directory=src clean
	$(MAKE) --directory=src unstripped-libmerc

.PHONY: test
test: test-coverage
	cd src && $(MAKE) test

.PHONY: test-coverage
test-coverage:
	mkdir -p coverage

	$(MAKE) --directory=src COVERAGE_ENABLED=1 use_fsanitize=no run_unit_test > /dev/null
	lcov -q --directory . --capture --output-file ./coverage/mercury_unit_tests_1.info
	echo "Successfully created coverage file for unit tests!"
	make clean-helper > /dev/null
	
	$(MAKE) --directory=src/libmerc COVERAGE_ENABLED=1 use_fsanitize=no libmerc.so > /dev/null
	$(MAKE) --directory=unit_tests COVERAGE_ENABLED=1 use_fsanitize=no libmerc_driver_tls_only > /dev/null
	$(MAKE) --directory=unit_tests run_libmerc_tls_only_tests > /dev/null
	lcov -q --directory . --capture --output-file ./coverage/mercury_libmerc_driver_tls_only.info
	echo "Successfully created coverage file for libmerc driver tls tests!"
	make clean-helper > /dev/null

	$(MAKE) --directory=src/libmerc COVERAGE_ENABLED=1 use_fsanitize=no libmerc.so > /dev/null
	$(MAKE) --directory=unit_tests COVERAGE_ENABLED=1 use_fsanitize=no libmerc_driver_multiprotocol > /dev/null
	$(MAKE) --directory=unit_tests run_libmerc_multiprotocol_tests > /dev/null
	lcov -q --directory . --capture --output-file ./coverage/mercury_libmerc_driver_multiprotocol.info
	echo "Successfully created coverage file for libmerc driver multiprotocol tests!"
	make clean-helper > /dev/null

	$(MAKE) --directory=src COVERAGE_ENABLED=1 use_fsanitize=no mercury > /dev/null
	$(MAKE) --directory=test COVERAGE_ENABLED=1 clean comp analysis cert-check memcheck json-validity-test stats > /dev/null
	lcov -q --directory . --capture --output-file ./coverage/mercury_unit_tests_2.info
	echo "Successfully created coverage file for other unit tests!"
	make clean-helper > /dev/null

	$(MAKE) --directory=test COVERAGE_ENABLED=1 fuzz-test > /dev/null
	find . -name "*.profraw" | xargs -I {} sh -c 'llvm-profdata merge -sparse "{}" -o $$(dirname "{}")/default.profdata'
	find . -name "*exec" | xargs -I {} sh -c 'llvm-cov export -format=lcov --instr-profile $$(dirname "{}")/default.profdata {} > $$(dirname "{}")/default.info'
	find ./test/fuzz -name "*.info" | sed 's/\(\S\+\)/--add-tracefile \1/g' | xargs lcov --output-file ./coverage/mercury_fuzz_test_1.info > /dev/null
	lcov -q --directory ./src --capture --output-file ./coverage/mercury_fuzz_test_2.info
	echo "Successfully created coverage file for fuzz tests!!"
	make clean-helper > /dev/null

	lcov --add-tracefile ./coverage/mercury_unit_tests_1.info --add-tracefile ./coverage/mercury_libmerc_driver_tls_only.info --add-tracefile ./coverage/mercury_libmerc_driver_multiprotocol.info --add-tracefile ./coverage/mercury_unit_tests_2.info --add-tracefile ./coverage/mercury_fuzz_test_1.info --add-tracefile ./coverage/mercury_fuzz_test_2.info --output-file ./coverage/mercury_total.info 2>&1 | grep -v "function data mismatch"
	lcov -q --remove ./coverage/mercury_total.info '/usr/include/*' '*/src/libmerc/rapidjson/*' '*/unit_tests/*' '*/test/fuzz/*' -o ./coverage/mercury_filtered_coverage.info
	genhtml --no-function-coverage --output-directory coverage_html_report ./coverage/mercury_filtered_coverage.info
	echo "Successfully created coverage report!"

.PHONY: test_strict
test_strict:
	cd src && $(MAKE) test

.PHONY: test_libmerc_so
test_libmerc_so: unit_tests
	cd test && $(MAKE) test_libmerc_so

.PHONY: unit_tests
unit_tests:
	cd unit_tests && $(MAKE)

.PHONY: coverage_report
coverage_report: clean
	cd unit_tests && $(MAKE) libmerc_driver_coverage
	cd unit_tests && $(MAKE) run
	cd unit_tests && gcovr -r ../src/libmerc

.PHONY: doc
doc: doc/mercury.pdf sphinx

doc/mercury.pdf:
	doxygen
	cd doc/latex; make; mv refman.pdf ../mercury.pdf

.PHONY: sphinx sphinx-clean
sphinx:
	cd doc/sphinx && $(MAKE) html

sphinx-clean:
	cd doc/sphinx && $(MAKE) clean

.PHONY:
clean: sphinx-clean
	for file in Makefile README.md configure.ac Doxyfile; do if [ -e "$$file~" ]; then rm -f "$$file~" ; fi; done
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo $(COLOR_RED) "error: run ./configure before running make (src/Makefile is missing)" $(COLOR_OFF)
	@false
else
	$(MAKE) clean-helper
	rm -rf doc/latex
	rm -rf coverage coverage_html_report
	rm -rf coverage
endif

.PHONY: distclean
distclean: clean
ifneq ($(wildcard src/Makefile), src/Makefile)
	@echo $(COLOR_RED) "error: run ./configure before running make (src/Makefile is missing)" $(COLOR_OFF)
	@false
else
	cd src  && $(MAKE) distclean
	cd test && $(MAKE) distclean
	rm -rf autom4te.cache config.log config.status Makefile_helper.mk
	rm -f lib/*.so
endif

.PHONY: clean-helper
clean-helper:
	find . -name "*.gcda" -delete
	find . -name "*.gcno" -delete
	find . -name "*.gcov" -delete
	cd src && $(MAKE) clean
	cd test && $(MAKE) clean
	cd unit_tests && $(MAKE) clean

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
	echo $(COLOR_GREEN) "created git tag; ready for 'git push origin <tagname>'"

increment-minor-version:
	cd src; make increment-minor-version
	echo $(COLOR_GREEN) "created git tag; ready for 'git push origin <tagname>'"

increment-major-version:
	cd src; make increment-major-version
	echo $(COLOR_GREEN) "created git tag; ready for 'git push origin <tagname>'"

# EOF
