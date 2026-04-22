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
# different libmerc.so build — add a source list, a build rule, a
# _run-libmerc-<name> target, and add it to _run-libmerc-test-drivers.
# (The current split into separate drivers is historical; they may
# be consolidated.)
#
# Usage:
#   make -f Makefile2 test-libmerc                # all libmerc tests
#   make -f Makefile2 test-libmerc-multiprotocol  # multiprotocol only
#   make -f Makefile2 test-libmerc-fdc            # FDC only
#   make -f Makefile2 test-libmerc-l7-metadata    # L7 metadata only
#   make -f Makefile2 test-libmerc-tls-only       # TLS-only only
#   make -f Makefile2 -j libmerc-test-drivers     # build test drivers (no run)
#
# Notes:
#   - VISIBILITY=default is required (tech debt): the test drivers
#     access internal symbols that the default build hides.  The
#     public targets handle the self-invocation automatically.
#   - STATIC_CFG=tls is a deprecated variant retained for test coverage
#     but will be removed in the future.

# ===================================================================
# Variables
# ===================================================================

# --- Targets built by 'make all' -------------------------------------
# Only libmerc_util can be built in the default variant; the libmerc.so
# test drivers require VISIBILITY=default (a different variant).

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
  $(_drv_dir)/doctest_main.cc \
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

_DRV_EXTRA_CXXFLAGS = -UNDEBUG -I src -I src/libmerc \
  -DLIBMERC_SO_PATH='"$(abspath $(LIB)/libmerc.so)"' \
  -DLIBMERC_SO_ALT_PATH='"$(abspath $(LIB)/libmerc_alt.so)"'

_DRV_LDLIBS := -pthread -lcrypto -ldl -lz

# ===================================================================
# Public targets
# ===================================================================

# --- Top-level test-libmerc (self-invoking) ---------------------------

.PHONY: test-libmerc
test-libmerc:
	@echo "--- libmerc end-to-end tests (multiprotocol + fdc + l7-metadata) ---"
	@printf '$(COLOR_YELLOW)  note: forcing VISIBILITY=default for libmerc.so$(COLOR_OFF)\n'
	$(MAKE) -f Makefile2 VISIBILITY=default _run-libmerc-test-drivers
	@echo ""
	@echo "--- libmerc end-to-end tests (tls-only, STATIC_CFG=tls) ---"
	@printf '$(COLOR_YELLOW)  note: forcing VISIBILITY=default STATIC_CFG=tls for tls-only libmerc.so$(COLOR_OFF)\n'
	$(MAKE) -f Makefile2 VISIBILITY=default STATIC_CFG=tls _run-libmerc-tls-only
	@printf '$(COLOR_GREEN)  passed all libmerc end-to-end tests$(COLOR_OFF)\n'

# --- Per-driver public convenience targets ----------------------------

.PHONY: test-libmerc-multiprotocol
test-libmerc-multiprotocol:
	$(MAKE) -f Makefile2 VISIBILITY=default _run-libmerc-multiprotocol

.PHONY: test-libmerc-fdc
test-libmerc-fdc:
	$(MAKE) -f Makefile2 VISIBILITY=default _run-libmerc-fdc

.PHONY: test-libmerc-l7-metadata
test-libmerc-l7-metadata:
	$(MAKE) -f Makefile2 VISIBILITY=default _run-libmerc-l7-metadata

.PHONY: test-libmerc-tls-only
test-libmerc-tls-only:
	$(MAKE) -f Makefile2 VISIBILITY=default STATIC_CFG=tls _run-libmerc-tls-only

# --- Build all drivers (no run) ---------------------------------------

.PHONY: libmerc-test-drivers
libmerc-test-drivers:
	$(MAKE) -f Makefile2 VISIBILITY=default _build-libmerc-test-drivers
	$(MAKE) -f Makefile2 VISIBILITY=default STATIC_CFG=tls _build-libmerc-tls-test-driver

# ===================================================================
# Internal targets
# ===================================================================

# --- Per-driver test sandboxes ----------------------------------------
# Drivers use hardcoded relative paths ("./pcaps/", "../test/data/",
# "../src/libmerc_util").  Each driver gets its own sandbox directory
# under the build variant so that parallel runs (-j) don't race.
#
# Layout (for driver "foo"):
#
#   build/<variant>/drv/foo/
#     sandbox/              <- cwd when tests run
#       pcaps/              -> unit_tests/pcaps
#       debug-libs/
#         libmerc.so.0      -> lib/libmerc.so
#     test/data/
#       resources-test.tgz  -> test/data/resources-test.tgz

# $(1) = driver name (e.g. multiprotocol, fdc, l7-metadata, tls-only)
_drv_root_for = build/$(_variant)/drv/$(1)
_drv_cwd_for  = $(call _drv_root_for,$(1))/sandbox

# Pre-clean + create the sandbox tree.  Called at the start of every
# run so leftover files from a previous (possibly failed) run are gone.
# Target-specific symlinks (libmerc_multiprotocol.so, src/libmerc_util)
# are added by the individual run targets that need them.
define _sandbox_setup # $(1) = driver name
	rm -rf $(call _drv_root_for,$(1)) && \
	mkdir -p $(call _drv_cwd_for,$(1))/debug-libs \
	         $(call _drv_root_for,$(1))/test/data && \
	ln -s $(abspath unit_tests/pcaps) $(call _drv_cwd_for,$(1))/pcaps && \
	ln -s $(_libdir)/libmerc.so $(call _drv_cwd_for,$(1))/debug-libs/libmerc.so.0 && \
	ln -s $(abspath test/data/resources-test.tgz) $(call _drv_root_for,$(1))/test/data/resources-test.tgz
endef

# --- Build-only helpers -----------------------------------------------

.PHONY: _build-libmerc-test-drivers
_build-libmerc-test-drivers: $(BIN)/libmerc_driver_multiprotocol \
                             $(BIN)/libmerc_driver_fdc \
                             $(BIN)/libmerc_util_behavior_test

.PHONY: _build-libmerc-tls-test-driver
_build-libmerc-tls-test-driver: $(BIN)/libmerc_driver_tls_only

# --- Per-driver run targets -------------------------------------------
# Each target has its own sandbox and explicit prerequisites.  They are
# invoked with VISIBILITY=default (and in one case STATIC_CFG=tls) via
# the public targets below or the umbrella _run-libmerc-test-drivers.

.PHONY: _run-libmerc-multiprotocol
_run-libmerc-multiprotocol: $(BIN)/libmerc_driver_multiprotocol \
                            $(LIB)/libmerc.so \
                            test/data/resources-test.tgz
	@$(call _sandbox_setup,multiprotocol)
	@ln -s $(_libdir)/libmerc.so $(call _drv_cwd_for,multiprotocol)/debug-libs/libmerc_multiprotocol.so
	@echo "running libmerc multiprotocol tests"
	cd $(call _drv_cwd_for,multiprotocol) && $(_lib_path_var)=$(_libdir):./debug-libs \
	  $(abspath $(BIN)/libmerc_driver_multiprotocol) -s
	@printf '$(COLOR_GREEN)  passed libmerc multiprotocol tests$(COLOR_OFF)\n'

.PHONY: _run-libmerc-fdc
_run-libmerc-fdc: $(BIN)/libmerc_driver_fdc \
                  $(LIB)/libmerc.so \
                  test/data/resources-test.tgz
	@$(call _sandbox_setup,fdc)
	@echo "running libmerc fdc tests"
	cd $(call _drv_cwd_for,fdc) && $(_lib_path_var)=$(_libdir):./debug-libs \
	  $(abspath $(BIN)/libmerc_driver_fdc) -s
	@printf '$(COLOR_GREEN)  passed libmerc fdc tests$(COLOR_OFF)\n'

.PHONY: _run-libmerc-l7-metadata
_run-libmerc-l7-metadata: $(BIN)/libmerc_util_behavior_test \
                          $(LIB)/libmerc.so \
                          $(BIN)/libmerc_util \
                          test/data/resources-test.tgz
	@$(call _sandbox_setup,l7-metadata)
	@ln -s $(_libdir)/libmerc.so $(call _drv_cwd_for,l7-metadata)/debug-libs/libmerc_multiprotocol.so
	@mkdir -p $(call _drv_root_for,l7-metadata)/src
	@ln -s $(abspath $(BIN)/libmerc_util) $(call _drv_root_for,l7-metadata)/src/libmerc_util
	@echo "running libmerc l7-metadata tests"
	cd $(call _drv_cwd_for,l7-metadata) && $(_lib_path_var)=$(_libdir):./debug-libs \
	  $(abspath $(BIN)/libmerc_util_behavior_test) -s
	@printf '$(COLOR_GREEN)  passed libmerc l7-metadata tests$(COLOR_OFF)\n'

.PHONY: _run-libmerc-tls-only
_run-libmerc-tls-only: $(BIN)/libmerc_driver_tls_only \
                       $(LIB)/libmerc.so \
                       $(LIB)/libmerc_alt.so \
                       test/data/resources-test.tgz
	@$(call _sandbox_setup,tls-only)
	@echo "running libmerc tls-only tests"
	cd $(call _drv_cwd_for,tls-only) && $(_lib_path_var)=$(_libdir):./debug-libs \
	  $(abspath $(BIN)/libmerc_driver_tls_only) -s
	@printf '$(COLOR_GREEN)  passed libmerc tls-only tests$(COLOR_OFF)\n'

# --- Umbrella run target (prerequisite-only, no recipe) ---------------
# Parallelizes the three default-variant drivers under -j.  tls-only
# is excluded — it needs a separate $(MAKE) with STATIC_CFG=tls.

.PHONY: _run-libmerc-test-drivers
_run-libmerc-test-drivers: _run-libmerc-multiprotocol \
                           _run-libmerc-fdc \
                           _run-libmerc-l7-metadata

# ===================================================================
# Build rules
# ===================================================================

# --- libmerc_util -----------------------------------------------------
# Command-line tool that dlopen()s libmerc.so and processes PCAPs;
# primarily used for FDC (Full Data Capture) testing.  Exercised as
# a subprocess by libmerc_util_behavior_test below.
#
# Tech debt: libmerc_util #includes internal libmerc headers for its --fdc code
# path (eth.h, ip.h, tcpip.h, udp.h, and transitively l7m.hpp).  On GCC at -O0,
# those headers instantiate templates with unresolved symbols that would require
# linking libmerc.a.  We force -O2 so the build works regardless of
# the variant's optimization level.
#
# The objects are placed in a private subdirectory (_libmerc_util_obj/) so the
# -O2 override does not collide with the shared pcap_file_io.o used by mercury,
# which must honour the variant's own optimization level.

_UTIL_OBJ := $(OBJ)/_libmerc_util_obj

$(_UTIL_OBJ)/%.o: %.cc $(_stamp)
	@mkdir -p $(dir $@)
	$(call QUIET,CXX,$@)$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@

$(_UTIL_OBJ)/%.o: %.c $(_stamp)
	@mkdir -p $(dir $@)
	$(call QUIET,CXX,$@)$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@

$(BIN)/libmerc_util: CXXFLAGS += -UNDEBUG -O2
$(BIN)/libmerc_util: LDLIBS := $(_DRV_LDLIBS)
$(BIN)/libmerc_util: $(_UTIL_OBJ)/src/libmerc_util.o $(_UTIL_OBJ)/src/pcap_file_io.o
	@printf '$(COLOR_YELLOW)  note: forcing -O2 for libmerc_util (link workaround)$(COLOR_OFF)\n'
	$(LINK)


# --- Driver targets ---------------------------------------------------
# Drivers link and dlopen the variant's libmerc.so, which must be built with
# VISIBILITY=default so internal symbols are accessible to tests.  The link step
# is tech debt (should be dlopen-only), as is the visibility requirement.
# libmerc_alt.so and libmerc_util are order-only prerequisites: needed at
# runtime but not passed to the linker.

# links libmerc.so; dlopen()s libmerc.so and libmerc_alt.so
$(BIN)/libmerc_driver_tls_only: CXXFLAGS += $(_DRV_EXTRA_CXXFLAGS)
$(BIN)/libmerc_driver_tls_only: LDLIBS := $(_DRV_LDLIBS)
$(BIN)/libmerc_driver_tls_only: | $(LIB)/libmerc_alt.so
$(BIN)/libmerc_driver_tls_only: $(call objects,$(_DRV_TLS_ONLY)) $(LIB)/libmerc.so
	$(LINK)

# links and dlopen()s libmerc.so
$(BIN)/libmerc_driver_multiprotocol: CXXFLAGS += $(_DRV_EXTRA_CXXFLAGS)
$(BIN)/libmerc_driver_multiprotocol: LDLIBS := $(_DRV_LDLIBS)
$(BIN)/libmerc_driver_multiprotocol: $(call objects,$(_DRV_MULTI)) $(LIB)/libmerc.so
	$(LINK)

# links and dlopen()s libmerc.so
$(BIN)/libmerc_driver_fdc: CXXFLAGS += $(_DRV_EXTRA_CXXFLAGS)
$(BIN)/libmerc_driver_fdc: LDLIBS := $(_DRV_LDLIBS)
$(BIN)/libmerc_driver_fdc: $(call objects,$(_DRV_FDC)) $(LIB)/libmerc.so
	$(LINK)

# links and dlopen()s libmerc.so; runs libmerc_util as a subprocess
$(BIN)/libmerc_util_behavior_test: CXXFLAGS += $(_DRV_EXTRA_CXXFLAGS)
$(BIN)/libmerc_util_behavior_test: LDLIBS := $(_DRV_LDLIBS) $(_stdfslib)
$(BIN)/libmerc_util_behavior_test: | $(BIN)/libmerc_util
$(BIN)/libmerc_util_behavior_test: $(call objects,$(_DRV_UTIL)) $(LIB)/libmerc.so
	$(LINK)
