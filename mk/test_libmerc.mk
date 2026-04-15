# mk/test_libmerc.mk -- end-to-end tests for libmerc.so
#
# Included by Makefile2.  Testing libmerc.so requires two things:
#
#   1. A build of libmerc.so.
#   2. A test driver binary that dlopen()s and exercises it.
#
# Edit this file when adding or removing either of those.
#
# To add a new test source file, append its .cc to the appropriate
# source list (_DRV_MULTI, _DRV_TLS_ONLY, _DRV_FDC, or _DRV_UTIL).
#
# To add a new driver — a separate executable for tests needing a
# different libmerc.so build — add a source list, a build rule, and
# a run step in _run-libmerc-drivers.  (The current split into
# separate drivers is historical; they may be consolidated.)
#
# Usage (the top-level target handles the variant self-invocation):
#   make -f Makefile2 test-libmerc
#
# Or invoke a specific variant manually:
#   make -f Makefile2 BUILD_TYPE=Debug SANITIZE=address OPTFLAGS=-O2 \
#       VISIBILITY=default _run-libmerc-drivers
#   make -f Makefile2 BUILD_TYPE=Debug SANITIZE=address OPTFLAGS=-O2 \
#       VISIBILITY=default STATIC_CFG=tls _run-libmerc-tls-driver
#
# Notes on the manual examples above:
#   - VISIBILITY=default is required (tech debt): the test drivers
#     access internal symbols that the default build hides.
#   - STATIC_CFG=tls is a deprecated variant retained for test coverage
#     but will be removed in the future.
#   - OPTFLAGS=-O2 overrides Debug's -O0 so the PCAP-processing tests
#     finish in reasonable time while still getting ASan and assertions.

# --- Targets built by 'make all' -------------------------------------
# Only libmerc_util can be built in the default variant; the Catch2
# drivers require VISIBILITY=default (a different variant).

LIBMERC_TEST_TARGETS := $(BIN)/libmerc_util

# --- Library path env var (macOS vs Linux) ----------------------------

ifeq ($(IS_MACOS),yes)
  _lib_path_var := DYLD_LIBRARY_PATH
else
  _lib_path_var := LD_LIBRARY_PATH
  _stdfslib := -lstdc++fs
endif

# --- Source file lists ------------------------------------------------

_drv_dir := unit_tests

_DRV_BASE := \
  $(_drv_dir)/catch2main.cc \
  $(_drv_dir)/libmerc_driver_helper.cc \
  $(_drv_dir)/libmerc_fixture.cc

_DRV_TLS_ONLY := $(_DRV_BASE) \
  $(_drv_dir)/general_info_test.cc \
  $(_drv_dir)/libmerc_flow_test.cc \
  $(_drv_dir)/libmerc_tlsdb_test.cc \
  $(_drv_dir)/libmerc_driver.cc

_DRV_MULTI := $(_DRV_BASE) \
  $(_drv_dir)/libmerc_dbmultiprotocol_test.cc \
  $(_drv_dir)/performance_test.cc \
  $(_drv_dir)/functional_unit_test.cc

_DRV_FDC := $(_DRV_BASE) \
  $(_drv_dir)/libmerc_driver_fdc.cc

_DRV_UTIL := $(_DRV_BASE) \
  $(_drv_dir)/libmerc_util_behavior_test.cc

# --- Common flags for all drivers -------------------------------------

_DRV_CXXFLAGS = $(CXXFLAGS) -UNDEBUG -I src -I src/libmerc \
  -DLIBMERC_SO_PATH='"$(abspath $(LIB)/libmerc.so)"' \
  -DLIBMERC_SO_ALT_PATH='"$(abspath $(LIB)/libmerc_alt.so)"'

_DRV_LDLIBS := -pthread -lcrypto -ldl -lz

# --- libmerc_util -----------------------------------------------------
# Command-line tool that dlopen()s libmerc.so and processes PCAPs;
# primarily used for FDC (Full Data Capture) testing.  Exercised as
# a subprocess by libmerc_util_behavior_test below.
#
# Tech debt: libmerc_util #includes internal libmerc headers for its --fdc code
# path (eth.h, ip.h, tcpip.h, udp.h, and transitively l7m.hpp).  On GCC at -O0,
# those headers instantiate templates with unresolved symbols that would require
# linking libmerc.a.  We force -O2 and compile directly so the build works
# regardless of the variant's optimization level.

$(BIN)/libmerc_util: src/libmerc_util.cc src/pcap_file_io.c
	@mkdir -p $(dir $@)
	$(call QUIET,LINK,$@)$(CXX) $(CXXFLAGS) -O2 $^ $(LDFLAGS) $(_DRV_LDLIBS) -o $@

# --- Driver targets ---------------------------------------------------
# Link against the variant's .so, built with VISIBILITY=default (tech
# debt) so internal symbols are accessible to tests.  Only tls_only
# needs libmerc_alt.so for the dual-instance test in
# libmerc_flow_test.cc.

$(BIN)/libmerc_driver_tls_only: $(LIB)/libmerc.so $(LIB)/libmerc_alt.so
	@mkdir -p $(dir $@)
	$(call QUIET,LINK,$@)$(CXX) $(_DRV_CXXFLAGS) $(_DRV_TLS_ONLY) \
	  $(LDFLAGS) -L$(_libdir) $(LIB)/libmerc.so $(_DRV_LDLIBS) -o $@

$(BIN)/libmerc_driver_multiprotocol: $(LIB)/libmerc.so
	@mkdir -p $(dir $@)
	$(call QUIET,LINK,$@)$(CXX) $(_DRV_CXXFLAGS) $(_DRV_MULTI) \
	  $(LDFLAGS) -L$(_libdir) $(LIB)/libmerc.so $(_DRV_LDLIBS) -o $@

$(BIN)/libmerc_driver_fdc: $(LIB)/libmerc.so
	@mkdir -p $(dir $@)
	$(call QUIET,LINK,$@)$(CXX) $(_DRV_CXXFLAGS) $(_DRV_FDC) \
	  $(LDFLAGS) -L$(_libdir) $(LIB)/libmerc.so $(_DRV_LDLIBS) -o $@

$(BIN)/libmerc_util_behavior_test: $(LIB)/libmerc.so $(BIN)/libmerc_util
	@mkdir -p $(dir $@)
	$(call QUIET,LINK,$@)$(CXX) $(_DRV_CXXFLAGS) $(_DRV_UTIL) \
	  $(LDFLAGS) -L$(_libdir) $(LIB)/libmerc.so $(_DRV_LDLIBS) $(_stdfslib) -o $@

# --- Test sandbox (inside the build directory) ------------------------
# Drivers use hardcoded relative paths ("./pcaps/", "../test/data/",
# "../src/libmerc_util").  We create a sandbox under the build variant
# with symlinks that satisfy those expectations, keeping the source
# tree pristine.  Layout:
#
#   build/<variant>/drv/
#     sandbox/              <- cwd when tests run
#       pcaps/              -> unit_tests/pcaps
#       debug-libs/
#         libmerc.so.0      -> lib/libmerc.so
#     test/data/
#       resources-test.tgz  -> test/data/resources-test.tgz
#     src/
#       libmerc_util        -> bin/libmerc_util

_drv_root := build/$(_variant)/drv
_drv_cwd  := $(_drv_root)/sandbox

# Pre-clean + create the sandbox tree.  Called at the start of every
# run so leftover files from a previous (possibly failed) run are gone.
_drv_sandbox_setup = \
	rm -rf $(_drv_root) && \
	mkdir -p $(_drv_cwd)/debug-libs $(_drv_root)/test/data $(_drv_root)/src && \
	ln -s $(abspath unit_tests/pcaps) $(_drv_cwd)/pcaps && \
	ln -s $(_libdir)/libmerc.so $(_drv_cwd)/debug-libs/libmerc.so.0 && \
	ln -s $(abspath test/data/resources-test.tgz) $(_drv_root)/test/data/resources-test.tgz && \
	ln -s $(abspath $(BIN)/libmerc_util) $(_drv_root)/src/libmerc_util

# --- Internal run targets (called by self-invocation) -----------------
# These expect to be invoked with VISIBILITY=default (and optionally
# STATIC_CFG=tls); see test-libmerc below for the self-invocation.

.PHONY: _run-libmerc-tls-driver
_run-libmerc-tls-driver: $(BIN)/libmerc_driver_tls_only test/data/resources-test.tgz
	@$(_drv_sandbox_setup)
	@echo "running libmerc tls-only end-to-end tests"
	cd $(_drv_cwd) && $(_lib_path_var)=$(_libdir):./debug-libs \
	  $(abspath $(BIN)/libmerc_driver_tls_only) -s
	@printf '$(COLOR_GREEN)  passed libmerc tls-only tests$(COLOR_OFF)\n'

.PHONY: _run-libmerc-drivers
_run-libmerc-drivers: $(BIN)/libmerc_driver_multiprotocol \
                      $(BIN)/libmerc_driver_fdc \
                      $(BIN)/libmerc_util_behavior_test \
                      test/data/resources-test.tgz
	@$(_drv_sandbox_setup)
	@ln -s $(_libdir)/libmerc.so $(_drv_cwd)/debug-libs/libmerc_multiprotocol.so
	@echo "running libmerc multiprotocol end-to-end tests"
	cd $(_drv_cwd) && $(_lib_path_var)=$(_libdir):./debug-libs \
	  $(abspath $(BIN)/libmerc_driver_multiprotocol) -s
	@echo "running libmerc fdc end-to-end tests"
	cd $(_drv_cwd) && $(_lib_path_var)=$(_libdir):./debug-libs \
	  $(abspath $(BIN)/libmerc_driver_fdc) -s
	@echo "running libmerc_util behavior tests"
	cd $(_drv_cwd) && $(_lib_path_var)=$(_libdir):./debug-libs \
	  $(abspath $(BIN)/libmerc_util_behavior_test) -s
	@printf '$(COLOR_GREEN)  passed libmerc end-to-end tests$(COLOR_OFF)\n'

# --- Top-level test-libmerc (self-invoking) ---------------------------

.PHONY: test-libmerc
test-libmerc:
	@echo "--- libmerc end-to-end tests (multiprotocol + fdc + util) ---"
	@printf '$(COLOR_YELLOW)  note: forcing VISIBILITY=default for multiprotocol libmerc.so$(COLOR_OFF)\n'
	$(MAKE) -f Makefile2 BUILD_TYPE=$(BUILD_TYPE) SANITIZE=$(SANITIZE) \
	  VISIBILITY=default OPTFLAGS='$(OPTFLAGS)' _run-libmerc-drivers
	@echo ""
	@echo "--- libmerc end-to-end tests (tls-only, STATIC_CFG=tls) ---"
	@printf '$(COLOR_YELLOW)  note: forcing VISIBILITY=default STATIC_CFG=tls for tls-only libmerc.so$(COLOR_OFF)\n'
	$(MAKE) -f Makefile2 BUILD_TYPE=$(BUILD_TYPE) SANITIZE=$(SANITIZE) \
	  VISIBILITY=default STATIC_CFG=tls OPTFLAGS='$(OPTFLAGS)' _run-libmerc-tls-driver
	@printf '$(COLOR_GREEN)  passed all libmerc end-to-end tests$(COLOR_OFF)\n'
