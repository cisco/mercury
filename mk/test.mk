# mk/test.mk -- test execution and the unit_test binary
#
# Included by the top-level Makefile.  Defines .PHONY targets for every test suite
# except test-libmerc (see test_libmerc.mk) and test-cython (see
# cython.mk).  Also builds unit_test and libmerc_test as part of
# 'make all' via TEST_TARGETS.
#
# When to edit:
#   - Adding a new test: define a .PHONY target (test-foo), write the
#     recipe, add test-foo to the 'test' prerequisite list, and add a
#     one-line description to the Test section in 'make help'.
#   - Each subtest should use its own directory under $(TESTDIR)/<name>/
#     with rm -rf + mkdir -p pre-cleanup for isolation.
#   - Adding a new test binary: append to TEST_TARGETS and add its
#     build rule.

# ===================================================================
# Variables
# ===================================================================

TEST_TARGETS := \
  $(BIN)/unit_test \
  $(BIN)/libmerc_test  # legacy tool, superseded by test-libmerc drivers

# Absolute paths to built artifacts (for passing to scripts/recipes)
_mercury       := $(abspath $(BIN)/mercury)
_batch_gcd     := $(abspath $(BIN)/batch_gcd)
_libmerc_so    := $(abspath $(LIB)/libmerc.so)
_libmerc_a     := $(abspath $(LIB)/libmerc.a)
_libdir        := $(abspath $(LIB))

# ===================================================================
# Public targets
# ===================================================================

# --- test (umbrella) --------------------------------------------------
#
# 'make test' runs the subtests listed as prerequisites below.
#
# Tests that require special environments (root, clang, AFL, etc.)
# are defined after the ====== separator and must be invoked separately.
#
# .omitted.*.flag = skipped for missing dependencies (e.g., jq), not platform
# inapplicability (e.g., memcheck on macOS or with SANITIZE is fine).

.PHONY: test
test: all unittest test-comp test-analysis test-cert-check \
      test-json-validity test-stats test-memcheck test-cython test-libmerc
	@if find $(TESTDIR) -maxdepth 1 -name '.omitted.*.flag' 2>/dev/null | grep -q .; then \
	  printf '$(COLOR_GREEN)  passed all tests that could be performed$(COLOR_OFF)\n'; \
	  printf '$(COLOR_YELLOW)  warning: some tests were skipped:\n'; \
	  find $(TESTDIR) -maxdepth 1 -name '.omitted.*.flag' | sort | \
	    sed 's|.*/\.omitted\.||; s|\.flag$$||; s|^|    |'; \
	  printf '$(COLOR_OFF)'; \
	else \
	  printf '$(COLOR_GREEN)  passed all tests$(COLOR_OFF)\n'; \
	fi

# --- unittest ---------------------------------------------------------

$(OBJ)/src/unit_test.o: CXXFLAGS := $(filter-out -DNDEBUG,$(CXXFLAGS))

$(BIN)/unit_test: LDLIBS := -lcrypto -lz
$(BIN)/unit_test: $(call objects,src/unit_test.cpp src/libmerc/asn1/oid.cc)
	$(LINK)

.PHONY: unittest
unittest: $(BIN)/unit_test
	cd src && $(abspath $(BIN)/unit_test)
	@printf '$(COLOR_GREEN)  passed unit tests$(COLOR_OFF)\n'

# --- Fingerprint comparison tests (comp) ------------------------------
#
# Declarative pattern rules: auto-discover expected outputs in
# test/data/, generate actual outputs in $(TESTDIR)/comp/, diff.
# Parallelizes automatically under -j.
#
# How it works:
#
#   For each test/data/foo.pcap that has a corresponding test/data/foo.fp,
#   .mcap, or .json, the test generates the output from the pcap and diffs
#   it against the expected file.  If they differ, the test fails.
#   To add a new test case, just drop a .pcap and its expected output
#   into test/data/.

_COMP_SRCDIR := test/data
_COMP_OUTDIR := $(TESTDIR)/comp

# Discover inputs from expected-output files present in source tree.
_FP_EXPECTED   := $(wildcard $(_COMP_SRCDIR)/*.fp)
_MCAP_EXPECTED := $(wildcard $(_COMP_SRCDIR)/*.mcap)
_JSON_EXPECTED := $(filter $(patsubst %.pcap,%.json,$(wildcard $(_COMP_SRCDIR)/*.pcap)),\
                           $(wildcard $(_COMP_SRCDIR)/*.json))

_FP_COMPS   := $(patsubst $(_COMP_SRCDIR)/%.fp,$(_COMP_OUTDIR)/%.fp-comp,$(_FP_EXPECTED))
_MCAP_COMPS := $(patsubst $(_COMP_SRCDIR)/%.mcap,$(_COMP_OUTDIR)/%.mcap-comp,$(_MCAP_EXPECTED))
_JSON_COMPS := $(patsubst $(_COMP_SRCDIR)/%.json,$(_COMP_OUTDIR)/%.json-comp,$(_JSON_EXPECTED))

# FP chain: pcap -> json -> fp -> diff
$(_COMP_OUTDIR)/%.json: $(_COMP_SRCDIR)/%.pcap $(BIN)/mercury FORCE | $(_COMP_OUTDIR)
	$(call QUIET,TEST,$@)$(_mercury) -r $< -f $@ --reassembly --metadata --raw-features=all

$(_COMP_OUTDIR)/%.fp: $(_COMP_OUTDIR)/%.json
	$(Q)jq .fingerprints.tls $< | grep -v null | tr -d '"' > $@

$(_COMP_OUTDIR)/%.fp-comp: $(_COMP_OUTDIR)/%.fp
	$(Q)diff $< $(_COMP_SRCDIR)/$(notdir $<)

# MCAP chain: pcap -> mcap -> diff
$(_COMP_OUTDIR)/%.mcap: $(_COMP_SRCDIR)/%.pcap $(BIN)/mercury FORCE | $(_COMP_OUTDIR)
	$(call QUIET,TEST,$@)$(_mercury) -r $< --reassembly -w $@

$(_COMP_OUTDIR)/%.mcap-comp: $(_COMP_OUTDIR)/%.mcap
	$(Q)diff $< $(_COMP_SRCDIR)/$(notdir $<)

# JSON chain: pcap -> json -> diff (reuses the .json rule above)
$(_COMP_OUTDIR)/%.json-comp: $(_COMP_OUTDIR)/%.json
	$(Q)diff $< $(_COMP_SRCDIR)/$(notdir $<)

$(_COMP_OUTDIR):
	@mkdir -p $@

.PHONY: test-comp
# Conditional prereqs: comp targets only when jq is available.
test-comp: $(BIN)/mercury $(if $(filter yes,$(HAVE_JQ)),$(_FP_COMPS) $(_MCAP_COMPS) $(_JSON_COMPS))
	@rm -f $(TESTDIR)/.omitted.test-comp.flag
ifeq ($(HAVE_JQ),yes)
	@echo "--- fingerprint comparison tests ---"
	@printf '$(COLOR_GREEN)  passed comparison tests$(COLOR_OFF)\n'
else
	@printf '$(COLOR_YELLOW)  omitting comparison tests; jq unavailable$(COLOR_OFF)\n'
	@mkdir -p $(TESTDIR) && touch $(TESTDIR)/.omitted.test-comp.flag
endif

# --- Analysis test ----------------------------------------------------

.PHONY: test-analysis
test-analysis: $(BIN)/mercury
	@rm -f $(TESTDIR)/.omitted.test-analysis.flag
ifeq ($(HAVE_PYTHON_JSONSCHEMA),yes)
	@echo "--- analysis test ---"
	@rm -rf $(TESTDIR)/analysis
	@mkdir -p $(TESTDIR)/analysis
	@cd test && $(_mercury) -r data/top-https.pcap \
	  -f $(abspath $(TESTDIR)/analysis)/output.json \
	  -a --resources=data/resources-test.tgz
	@cd test && $(PYTHON) json-test.py $(abspath $(TESTDIR)/analysis)/output.json
	@printf '$(COLOR_GREEN)  passed analysis test$(COLOR_OFF)\n'
else
	@printf '$(COLOR_YELLOW)  omitting analysis test; python3 or jsonschema unavailable$(COLOR_OFF)\n'
	@mkdir -p $(TESTDIR) && touch $(TESTDIR)/.omitted.test-analysis.flag
endif

# --- Certificate check ------------------------------------------------

.PHONY: test-cert-check
test-cert-check: $(BIN)/mercury
	@rm -f $(TESTDIR)/.omitted.test-cert-check.flag
ifeq ($(HAVE_PYTHON_CRYPTOGRAPHY),yes)
	@echo "--- certificate tests ---"
	@rm -rf $(TESTDIR)/cert-check
	@mkdir -p $(TESTDIR)/cert-check
	@cd test && $(_mercury) -r data/top-https.pcap \
	  -f $(abspath $(TESTDIR)/cert-check)/output.json --reassembly && \
	  $(PYTHON) certificate-test.py $(abspath $(TESTDIR)/cert-check)/output.json \
	    --complete 96 --partial 0
	@cd test && $(_mercury) -r data/top_100_fingerprints.pcap \
	  -f $(abspath $(TESTDIR)/cert-check)/output.json --reassembly && \
	  $(PYTHON) certificate-test.py $(abspath $(TESTDIR)/cert-check)/output.json \
	    --complete 164 --partial 0
	@cd test && $(_mercury) -r data/test_decrypt.pcap \
	  -f $(abspath $(TESTDIR)/cert-check)/output.json && \
	  $(PYTHON) certificate-test.py $(abspath $(TESTDIR)/cert-check)/output.json \
	    --complete 6 --partial 1
	@printf '$(COLOR_GREEN)  passed certificate tests$(COLOR_OFF)\n'
else
	@printf '$(COLOR_YELLOW)  omitting certificate test; python3 or cryptography unavailable$(COLOR_OFF)\n'
	@mkdir -p $(TESTDIR) && touch $(TESTDIR)/.omitted.test-cert-check.flag
endif

# --- JSON validity test -----------------------------------------------

.PHONY: test-json-validity
test-json-validity: $(BIN)/mercury
	@rm -f $(TESTDIR)/.omitted.test-json-validity.flag
ifeq ($(HAVE_JQ),yes)
	@echo "--- JSON validity test ---"
	@cd test && MERCURY=$(_mercury) \
	  ./mercury-json-validity-check.sh --dns-json --certs-json \
	    --metadata --nonselected-tcp-data --nonselected-udp-data \
	    --raw-features=all
	@printf '$(COLOR_GREEN)  passed JSON validity test$(COLOR_OFF)\n'
else
	@printf '$(COLOR_YELLOW)  omitting JSON validity test; jq unavailable$(COLOR_OFF)\n'
	@mkdir -p $(TESTDIR) && touch $(TESTDIR)/.omitted.test-json-validity.flag
endif

# --- Stats test -------------------------------------------------------

.PHONY: test-stats
test-stats: $(BIN)/mercury
	@rm -f $(TESTDIR)/.omitted.test-stats.flag
ifeq ($(HAVE_PYTHON3),yes)
	@echo "--- stats tests ---"
	@rm -rf $(TESTDIR)/stats
	@mkdir -p $(TESTDIR)/stats
	@cd test && \
	  $(_mercury) -r data/top-https.pcap \
	    -f $(abspath $(TESTDIR)/stats)/output.json --metadata \
	    -a --resources=data/resources-test.tgz \
	    --stats=$(abspath $(TESTDIR)/stats)/stats
	@cd $(TESTDIR)/stats && \
	  $(PYTHON) $(abspath test/compare-stats.py) \
	    -m $(abspath $(TESTDIR)/stats)/output.json \
	    -s stats.json.gz
	@cd test && \
	  $(_mercury) -r data/new-stats-telemetry-test.pcap \
	    -f $(abspath $(TESTDIR)/stats)/output.json --metadata \
	    -a --resources=data/resources-test.tgz \
	    --stats=$(abspath $(TESTDIR)/stats)/stats --certs-json
	@cd $(TESTDIR)/stats && \
	  $(PYTHON) $(abspath test/compare-stats.py) \
	    -m $(abspath $(TESTDIR)/stats)/output.json \
	    -s stats.json.gz
	@rm -f $(TESTDIR)/stats/statsfile* $(TESTDIR)/stats/tempstats.json
	@cd test && \
	  $(_mercury) -r data/quic_tls_http.pcap \
	    -f $(abspath $(TESTDIR)/stats)/output.json --metadata \
	    -a --resources=data/resources-test.tgz \
	    --stats=$(abspath $(TESTDIR)/stats)/statsfile --stats-time=1 -p 10
	@cd $(TESTDIR)/stats && \
	  $(PYTHON) $(abspath test/compare-stats.py) \
	    -m $(abspath $(TESTDIR)/stats)/output.json \
	    -s statsfile -a
	@printf '$(COLOR_GREEN)  passed stats tests$(COLOR_OFF)\n'
else
	@printf '$(COLOR_YELLOW)  omitting stats test; python3 unavailable$(COLOR_OFF)\n'
	@mkdir -p $(TESTDIR) && touch $(TESTDIR)/.omitted.test-stats.flag
endif

# --- Memcheck ---------------------------------------------------------

.PHONY: test-memcheck
test-memcheck: $(BIN)/mercury
	@rm -f $(TESTDIR)/.omitted.test-memcheck.flag
ifneq ($(SANITIZE),)
	@printf '$(COLOR_GREEN)  skipping memcheck; incompatible with SANITIZE=$(SANITIZE)$(COLOR_OFF)\n'
else ifeq ($(HAVE_VALGRIND),yes)
	@echo "--- memcheck ---"
	@rm -rf $(TESTDIR)/memcheck
	@mkdir -p $(TESTDIR)/memcheck
	cd test && valgrind --trace-children=yes --leak-check=full \
	  --show-leak-kinds=all $(_mercury) -r data/top-https.pcap \
	  -f $(abspath $(TESTDIR)/memcheck)/output.json \
	  -a --resources=data/resources-test.tgz \
	  2> $(abspath $(TESTDIR)/memcheck)/valgrind.log
	grep "ERROR SUMMARY: 0" $(TESTDIR)/memcheck/valgrind.log
	@printf '$(COLOR_GREEN)  passed memcheck$(COLOR_OFF)\n'
else ifeq ($(IS_MACOS),yes)
	@printf '$(COLOR_GREEN)  skipping memcheck; valgrind not well-supported on macOS$(COLOR_OFF)\n'
else
	@printf '$(COLOR_YELLOW)  skipping memcheck; valgrind unavailable$(COLOR_OFF)\n'
	@mkdir -p $(TESTDIR) && touch $(TESTDIR)/.omitted.test-memcheck.flag
endif

# ===================================================================
# Special-environment and manual targets
# ===================================================================
#
# Targets below are NOT part of the full test suite ('make test').
# They require special environments (e.g., root, clang, AFL, GMP) or
# are intended for manual / CI-only invocation.

# --- Batch GCD test (declarative) -------------------------------------
#
# Same declarative pattern as test-comp above (see "How it works" there).
# Suffixes:
#   - .bgcd-in   = input (in source tree)
#   - .bgcd-out  = expected output (in source tree)
#   - .bgcd-tout = generated test output (under $(TESTDIR)/batch-gcd/)

_BGCD_SRCDIR := test/batch_gcd
_BGCD_OUTDIR := $(TESTDIR)/batch-gcd
_BGCD_INPUTS := $(wildcard $(_BGCD_SRCDIR)/*.bgcd-in)
_BGCD_COMPS  := $(patsubst $(_BGCD_SRCDIR)/%.bgcd-in,$(_BGCD_OUTDIR)/%.bgcd-comp,$(_BGCD_INPUTS))

# PEM inputs need --cert-file; non-PEM use stdin.
# More-specific %.pem.bgcd-tout matches first (shortest-stem rule).
$(_BGCD_OUTDIR)/%.pem.bgcd-tout: $(_BGCD_SRCDIR)/%.pem.bgcd-in $(BIN)/batch_gcd FORCE | $(_BGCD_OUTDIR)
	$(call QUIET,TEST,$@)$(_batch_gcd) --cert-file $< > $@

$(_BGCD_OUTDIR)/%.bgcd-tout: $(_BGCD_SRCDIR)/%.bgcd-in $(BIN)/batch_gcd FORCE | $(_BGCD_OUTDIR)
	$(call QUIET,TEST,$@)$(_batch_gcd) < $< > $@

$(_BGCD_OUTDIR)/%.bgcd-comp: $(_BGCD_OUTDIR)/%.bgcd-tout
	$(Q)diff $< $(_BGCD_SRCDIR)/$(notdir $(<:.bgcd-tout=.bgcd-out))

$(_BGCD_OUTDIR):
	@mkdir -p $@

.PHONY: test-batch-gcd
# Conditional prereqs: comp targets only when GMP is available.
test-batch-gcd: $(if $(filter yes,$(HAVE_GMP)),$(_BGCD_COMPS))
ifeq ($(HAVE_GMP),yes)
	@printf '$(COLOR_GREEN)  passed batch GCD tests$(COLOR_OFF)\n'
else
	@printf '$(COLOR_YELLOW)  omitting batch GCD test; libgmp unavailable$(COLOR_OFF)\n'
endif

# --- Fuzz test --------------------------------------------------------
#
# Fuzz tests require clang++ (libFuzzer is LLVM-only) and an
# ASan-instrumented libmerc.a so the fuzzer can detect bugs inside
# libmerc.  The recipe forces CXX=clang++ CC=clang SANITIZE=address
# for the .a build regardless of the caller's variant.
#
# Seed corpus is copied from test/fuzz/ into TESTDIR so that all
# generated sources, executables, logs, and grown corpus land
# out-of-source.

_fuzz_build_type := $(if $(filter Coverage,$(BUILD_TYPE)),Coverage,Debug)
_fuzz_variant := $(_fuzz_build_type)+address
_fuzz_a := $(abspath build/$(_fuzz_variant)/lib/libmerc.a)

.PHONY: test-fuzz
test-fuzz:
ifeq ($(IS_MACOS),yes)
	@printf '$(COLOR_YELLOW)  skipping fuzz test; currently requires Linux (libFuzzer runtime + /proc)$(COLOR_OFF)\n'
else ifeq ($(HAVE_CLANGPP),yes)
	@echo "--- fuzz tests ---"
	@printf '$(COLOR_YELLOW)  note: forcing $(_fuzz_build_type)+clang+ASan+O1 (libFuzzer requires LLVM+ASan)$(COLOR_OFF)\n'
	@rm -rf $(TESTDIR)/fuzz
	@mkdir -p $(TESTDIR)
	@cp -R test/fuzz $(TESTDIR)/fuzz
	$(MAKE) BUILD_TYPE=$(_fuzz_build_type) \
	  CXX=clang++ CC=clang SANITIZE=address OPTFLAGS=-O1 \
	  PLATFORM_FLAGS='$(filter-out -fno-gnu-unique,$(PLATFORM_FLAGS))' \
	  build/$(_fuzz_variant)/lib/libmerc.a
	cd $(TESTDIR)/fuzz && \
	  LIBMERC_A=$(_fuzz_a) \
	  LIBMERC_FOLDER=$(abspath src/libmerc)/ \
	  ./generate_fuzz_test.sh -n none -t 200 -r 1000000000 \
	    $(if $(filter yes,$(OPENSSL_V3_0_OR_NEWER)),-v true) \
	    $(if $(filter yes,$(OPENSSL_V1_1_OR_NEWER)),-s true) \
	    $(if $(filter Coverage,$(BUILD_TYPE)),-c 1)
	@printf '$(COLOR_GREEN)  passed fuzz test$(COLOR_OFF)\n'
else
	@printf '$(COLOR_YELLOW)  clang++ unavailable; skipping fuzz test$(COLOR_OFF)\n'
endif

# --- PDU verifier (test-pdu) -------------------------------------------
#
# Builds pdu_verifier dynamically linked against libmerc.so to exercise
# the shared library build, and runs it on PCAP files in the directory
# specified by PCAP_DIR (required).
#
# Note: pdu_verifier.cc has pre-existing source errors (uses removed
# packet<65536> template, pcap type mismatches) and will not compile
# until the source is updated.
#
# Usage:
#   make test-pdu PCAP_DIR=/path/to/pcaps

_pdu_verifier := $(abspath $(BIN)/pdu_verifier)

$(BIN)/pdu_verifier: CXXFLAGS += -Isrc -Isrc/libmerc
$(BIN)/pdu_verifier: LDLIBS := -lcrypto -ldl -lz
$(BIN)/pdu_verifier: $(call objects,unit_tests/pdu_verifier.cc) $(LIB)/libmerc.so
	$(LINK)

.PHONY: test-pdu
test-pdu: $(BIN)/pdu_verifier
ifeq ($(PCAP_DIR),)
	@printf '$(COLOR_YELLOW)  error: PCAP_DIR unspecified (run as '\''make test-pdu PCAP_DIR=/path/to/pcaps'\'')$(COLOR_OFF)\n'
	@false
else
	@echo "--- PDU verification tests ---"
	@LIBMERC_DIR=$(_libdir) VERIFIER=$(_pdu_verifier) PCAP_DIR=$(PCAP_DIR) \
	  test/pdu_test.sh
	@printf '$(COLOR_GREEN)  passed PDU verification tests$(COLOR_OFF)\n'
endif

# --- Live capture test (requires root + IFNAME) -----------------------

# Drop-root flag: if running via sudo, let mercury drop to the
# invoking user; otherwise stay as root.
ifeq ($(SUDO_UID),)
  _DROP_ROOT := -u root
else
  _DROP_ROOT :=
endif

.PHONY: test-capture
test-capture: $(BIN)/mercury
ifeq ($(IFNAME),)
	@printf '$(COLOR_YELLOW)  error: IFNAME unspecified (run as '\''make test-capture IFNAME=eth0'\'')$(COLOR_OFF)\n'
	@false
else ifneq ($(shell id -u),0)
	@printf '$(COLOR_YELLOW)  error: capture test must be run as root$(COLOR_OFF)\n'
	@false
else
	@echo "--- capture test ---"
	@rm -rf $(TESTDIR)/capture
	@mkdir -p $(TESTDIR)/capture
	$(_mercury) -c $(IFNAME) $(_DROP_ROOT) -f $(abspath $(TESTDIR)/capture)/output.json & echo $$! > $(TESTDIR)/capture/mercury.PID
	test/capture/https-test-driver.sh
	while kill $$(cat $(TESTDIR)/capture/mercury.PID); do echo "waiting for mercury to halt"; sleep 1; done
ifeq ($(HAVE_PYTHON_JSONSCHEMA),yes)
	cd test && $(PYTHON) json-test.py $(abspath $(TESTDIR)/capture)/output.json
endif
	@printf '$(COLOR_GREEN)  passed capture test$(COLOR_OFF)\n'
endif

# --- Dummy-interface capture test (requires root + tcpreplay) ---------

.PHONY: test-dummy-capture
test-dummy-capture: $(BIN)/mercury
ifneq ($(shell id -u),0)
	@printf '$(COLOR_YELLOW)  error: dummy-capture test must be run as root$(COLOR_OFF)\n'
	@false
else ifeq ($(HAVE_TCPREPLAY),yes)
	@echo "--- dummy interface capture test ---"
	@rm -rf $(TESTDIR)/dummy-capture
	@mkdir -p $(TESTDIR)/dummy-capture
	ip link add dummy0 type dummy || true
	ip link set dev dummy0 up || true
	$(_mercury) -c dummy0 $(_DROP_ROOT) -f $(abspath $(TESTDIR)/dummy-capture)/output.json & echo $$! > $(TESTDIR)/dummy-capture/mercury.PID
	sleep 2
	tcpreplay -t -i dummy0 test/data/top-https.pcap
	while kill $$(cat $(TESTDIR)/dummy-capture/mercury.PID); do echo "waiting for mercury to halt"; sleep 1; done
	bash -c "diff <(jq . $(abspath $(TESTDIR)/dummy-capture)/output.json | grep -v event_start) <(jq . test/data/top-https.json | grep -v event_start)"
ifeq ($(HAVE_PYTHON_JSONSCHEMA),yes)
	cd test && $(PYTHON) json-test.py $(abspath $(TESTDIR)/dummy-capture)/output.json
endif
	@printf '$(COLOR_GREEN)  passed dummy interface capture test$(COLOR_OFF)\n'
else
	@printf '$(COLOR_YELLOW)  omitting dummy-capture test; tcpreplay unavailable$(COLOR_OFF)\n'
endif

# --- AFL fuzz test ----------------------------------------------------

_AFL_FUZZ_CMD := --metadata --dns-json --certs-json --analysis -f /dev/null

.PHONY: test-afl-fuzz
test-afl-fuzz: $(TESTDIR)/afl-mercury
	@mkdir -p $(TESTDIR)/afl_findings
	cd test && afl-fuzz -i afl_data -o $(abspath $(TESTDIR))/afl_findings \
	  $(abspath $(TESTDIR))/afl-mercury -r @@ $(_AFL_FUZZ_CMD)

# Build mercury with AFL instrumentation.
$(TESTDIR)/afl-mercury:
ifeq ($(HAVE_AFL),yes)
	@echo "building AFL-instrumented mercury with afl-g++"
	$(MAKE) CXX=afl-g++ CC=afl-g++ $(BIN)/mercury
	@mkdir -p $(dir $@)
	cp $(BIN)/mercury $@
else
	@printf '$(COLOR_YELLOW)  afl unavailable; cannot build afl-mercury$(COLOR_OFF)\n'
	@false
endif

# --- Coverage report (lcov) ------------------------------------------
#
# Builds everything under BUILD_TYPE=Coverage, runs the test suite
# in stages, captures lcov data after each stage, merges, and
# generates an HTML report.
#
# Usage:
#   make test-coverage
#
# Output:
#   build/Coverage/coverage/           .info trace files
#   build/Coverage/coverage_report/    HTML report

_cov_dir := build/Coverage/coverage
_cov_rpt := build/Coverage/coverage_report
_cov_make = $(MAKE) BUILD_TYPE=Coverage

_cov_capture_flags := --rc geninfo_unexecuted_blocks=1 --ignore-errors mismatch,mismatch
_cov_merge_flags := --ignore-errors mismatch,mismatch
_cov_filter_flags := --ignore-errors unused,unused
_cov_genhtml_flags := --function-coverage --demangle-cpp --legend --sort \
  --show-navigation --hierarchical --highlight --missed --num-spaces 4 --precision 1

# Internal target: runs inside the Coverage variant.
.PHONY: _run-coverage
_run-coverage: $(BIN)/unit_test $(BIN)/mercury $(LIB)/libmerc.so
	@mkdir -p $(_cov_dir)
	@# --- Stage 1: unit tests ---
	find build/Coverage* -name '*.gcda' -delete 2>/dev/null || true
	cd src && $(abspath $(BIN)/unit_test)
	lcov -q $(_cov_capture_flags) --directory build/Coverage --capture --output-file $(_cov_dir)/unit_tests.info
	@printf '$(COLOR_GREEN)  captured unit test coverage$(COLOR_OFF)\n'
	@# --- Stage 2: libmerc tests via test driver (tls-only) ---
	find build/Coverage* -name '*.gcda' -delete
	$(_cov_make) VISIBILITY=default STATIC_CFG=tls _run-libmerc-tls-only
	lcov -q $(_cov_capture_flags) --directory build --capture --output-file $(_cov_dir)/libmerc_tls.info
	@printf '$(COLOR_GREEN)  captured libmerc tls driver coverage$(COLOR_OFF)\n'
	@# --- Stage 3: libmerc tests via test driver (multiprotocol + fdc + l7-metadata) ---
	find build/Coverage* -name '*.gcda' -delete
	$(_cov_make) VISIBILITY=default _run-libmerc-test-drivers
	lcov -q $(_cov_capture_flags) --directory build --capture --output-file $(_cov_dir)/libmerc_multi.info
	@printf '$(COLOR_GREEN)  captured libmerc driver coverage$(COLOR_OFF)\n'
	@# --- Stage 4: full test suite ---
	find build/Coverage* -name '*.gcda' -delete
	$(_cov_make) test-comp test-analysis test-cert-check test-json-validity test-stats test-memcheck
	lcov -q $(_cov_capture_flags) --directory build/Coverage --capture --output-file $(_cov_dir)/test_suite.info
	@printf '$(COLOR_GREEN)  captured test suite coverage$(COLOR_OFF)\n'
	@# --- Merge and report ---
	lcov $(_cov_merge_flags) \
	  --add-tracefile $(_cov_dir)/unit_tests.info \
	  --add-tracefile $(_cov_dir)/libmerc_tls.info \
	  --add-tracefile $(_cov_dir)/libmerc_multi.info \
	  --add-tracefile $(_cov_dir)/test_suite.info \
	  --output-file $(_cov_dir)/total.info
	lcov -q $(_cov_filter_flags) --remove $(_cov_dir)/total.info \
	  '*/rapidjson/*' \
	  '*/unit_tests/*' \
	  '/usr/*' \
	  -o $(_cov_dir)/filtered.info
	@_branch=$$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown); \
	 _commit=$$(git rev-parse --short HEAD 2>/dev/null || echo unknown); \
	 genhtml \
	  --output-directory $(_cov_rpt) \
	  --title "mercury ($$_branch @ $$_commit)" \
	  --header-title "Mercury Test Coverage" \
	  $(_cov_genhtml_flags) \
	  $(_cov_dir)/filtered.info
	@printf '\n$(COLOR_GREEN)  ══════════════════════════════════════════$(COLOR_OFF)\n'
	@printf '$(COLOR_GREEN)  Coverage report: %s/index.html$(COLOR_OFF)\n' $(_cov_rpt)
	@printf '$(COLOR_GREEN)  ══════════════════════════════════════════$(COLOR_OFF)\n'
	@lcov --summary $(_cov_dir)/filtered.info 2>&1 | \
	  sed 's/^/  /' | grep -E 'lines|functions'
	@printf '$(COLOR_GREEN)  ══════════════════════════════════════════$(COLOR_OFF)\n'

# Top-level entry point: self-invokes with BUILD_TYPE=Coverage.
.PHONY: test-coverage
test-coverage:
	$(_cov_make) _run-coverage

# Fuzz-inclusive coverage uses the same lcov flow as test-coverage,
# with one extra test-fuzz stage.
_cov_fuzz_dir := build/Coverage/coverage_fuzz
_cov_fuzz_rpt := build/Coverage/coverage_report_fuzz

# Internal target: runs all coverage stages plus fuzz tests.
.PHONY: _run-coverage-fuzz
_run-coverage-fuzz: $(BIN)/unit_test $(BIN)/mercury $(LIB)/libmerc.so
	@mkdir -p $(_cov_fuzz_dir)
	@# --- Stage 1: unit tests ---
	find build/Coverage* -name '*.gcda' -delete 2>/dev/null || true
	cd src && $(abspath $(BIN)/unit_test)
	lcov -q $(_cov_capture_flags) --directory build/Coverage --capture --output-file $(_cov_fuzz_dir)/unit_tests.info
	@printf '$(COLOR_GREEN)  captured unit test coverage$(COLOR_OFF)\n'
	@# --- Stage 2: libmerc tests via test driver (tls-only) ---
	find build/Coverage* -name '*.gcda' -delete
	$(_cov_make) VISIBILITY=default STATIC_CFG=tls _run-libmerc-tls-only
	lcov -q $(_cov_capture_flags) --directory build --capture --output-file $(_cov_fuzz_dir)/libmerc_tls.info
	@printf '$(COLOR_GREEN)  captured libmerc tls driver coverage$(COLOR_OFF)\n'
	@# --- Stage 3: libmerc tests via test driver (multiprotocol + fdc + l7-metadata) ---
	find build/Coverage* -name '*.gcda' -delete
	$(_cov_make) VISIBILITY=default _run-libmerc-test-drivers
	lcov -q $(_cov_capture_flags) --directory build --capture --output-file $(_cov_fuzz_dir)/libmerc_multi.info
	@printf '$(COLOR_GREEN)  captured libmerc driver coverage$(COLOR_OFF)\n'
	@# --- Stage 4: full test suite ---
	find build/Coverage* -name '*.gcda' -delete
	$(_cov_make) test-comp test-analysis test-cert-check test-json-validity test-stats test-memcheck
	lcov -q $(_cov_capture_flags) --directory build/Coverage --capture --output-file $(_cov_fuzz_dir)/test_suite.info
	@printf '$(COLOR_GREEN)  captured test suite coverage$(COLOR_OFF)\n'
	@# --- Stage 5: fuzz tests ---
	find build/Coverage* -name '*.gcda' -delete
	@# test-fuzz itself returns success for unsupported platforms/toolchains;
	@# a nonzero exit here is treated as an actual fuzz test failure.
	$(_cov_make) test-fuzz
	@fuzz_info=$(_cov_fuzz_dir)/fuzz.info; \
	  rm -f $$fuzz_info; \
	  if lcov -q $(_cov_capture_flags) --directory build --capture --output-file $$fuzz_info 2>/dev/null && [ -s $$fuzz_info ]; then \
	    printf '$(COLOR_GREEN)  captured fuzz test coverage$(COLOR_OFF)\n'; \
	  else \
	    rm -f $$fuzz_info; \
	    printf '$(COLOR_YELLOW)  no fuzz coverage captured$(COLOR_OFF)\n'; \
	  fi
	@# --- Merge and report ---
	@fuzz_trace=$(_cov_fuzz_dir)/fuzz.info; \
	  fuzz_arg=; \
	  if [ -s $$fuzz_trace ]; then fuzz_arg="--add-tracefile $$fuzz_trace"; fi; \
	  lcov $(_cov_merge_flags) \
	  --add-tracefile $(_cov_fuzz_dir)/unit_tests.info \
	  --add-tracefile $(_cov_fuzz_dir)/libmerc_tls.info \
	  --add-tracefile $(_cov_fuzz_dir)/libmerc_multi.info \
	  --add-tracefile $(_cov_fuzz_dir)/test_suite.info \
	  $$fuzz_arg \
	  --output-file $(_cov_fuzz_dir)/total.info
	lcov -q $(_cov_filter_flags) --remove $(_cov_fuzz_dir)/total.info \
	  '*/rapidjson/*' \
	  '*/unit_tests/*' \
	  '*/test/fuzz/*' \
	  '/usr/*' \
	  -o $(_cov_fuzz_dir)/filtered.info
	@_branch=$$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown); \
	 _commit=$$(git rev-parse --short HEAD 2>/dev/null || echo unknown); \
	 genhtml \
	  --output-directory $(_cov_fuzz_rpt) \
	  --title "mercury+fuzz ($$_branch @ $$_commit)" \
	  --header-title "Mercury Test Coverage (with Fuzz)" \
	  $(_cov_genhtml_flags) \
	  $(_cov_fuzz_dir)/filtered.info
	@printf '\n$(COLOR_GREEN)  ══════════════════════════════════════════$(COLOR_OFF)\n'
	@printf '$(COLOR_GREEN)  Coverage report: %s/index.html$(COLOR_OFF)\n' $(_cov_fuzz_rpt)
	@printf '$(COLOR_GREEN)  ══════════════════════════════════════════$(COLOR_OFF)\n'
	@lcov --summary $(_cov_fuzz_dir)/filtered.info 2>&1 | \
	  sed 's/^/  /' | grep -E 'lines|functions'
	@printf '$(COLOR_GREEN)  ══════════════════════════════════════════$(COLOR_OFF)\n'

# Top-level entry point for coverage with fuzz tests.
.PHONY: test-coverage-fuzz
test-coverage-fuzz:
	$(_cov_make) _run-coverage-fuzz

# ===================================================================
# Build rules
# ===================================================================

# --- libmerc_test (legacy compile check) ------------------------------
# C tool that exercises libmerc.so interactively; superseded by the
# test-libmerc drivers but retained as a compile-time check for the C API.
# Not run by any test target (cf. 'make test-libmerc').

$(OBJ)/src/libmerc_test.o: src/libmerc_test.c
	@mkdir -p $(dir $@)
	$(call QUIET,CC,$@)$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

$(BIN)/libmerc_test: LDLIBS := -pthread -lz -lcrypto
$(BIN)/libmerc_test: $(OBJ)/src/libmerc_test.o $(LIB)/libmerc.so
	@mkdir -p $(dir $@)
	$(call QUIET,LINK,$@)$(CC) $(CFLAGS) $< $(LDFLAGS) $(LIB)/libmerc.so $(LDLIBS) -o $@
	@printf '$(COLOR_GREEN)  to run manually: LD_LIBRARY_PATH=%s %s$(COLOR_OFF)\n' $(_libdir) $@
