# mk/cython.mk -- mercury-python (Cython extension + wheel)
#
# Included by Makefile2.  Builds the mercury-python Cython extension
# by linking against the prebuilt libmerc.a, and packages it as a
# pip-installable wheel.
#
# When to edit:
#   - Cython source or packaging files change: update _cython_srcs.
#   - Build flags need filtering: update _cython_cflags.
#
# Source files are copied to a per-variant build tree so that (a) the
# source directory stays clean, and (b) parallel builds for different
# variants never collide.
#
# The wheel is built via PEP 517 (pip wheel) rather than the deprecated
# 'python setup.py' CLI.  setup2.py is installed as setup.py in the
# build copy.  The .so is extracted from the wheel for PYTHONPATH-based
# testing and manual use.

CYTHON_DIR   := src/cython
CYTHON_BUILD := build/$(_variant)/cython
CYTHON_SRC   := $(CYTHON_BUILD)/src
CYTHON_LIB   := $(CYTHON_BUILD)/lib
CYTHON_DIST  := $(CYTHON_BUILD)/dist

# Files to track for rebuild decisions.
_cython_srcs := $(CYTHON_DIR)/mercury.pyx $(CYTHON_DIR)/setup2.py \
                $(CYTHON_DIR)/pyproject.toml $(CYTHON_DIR)/_version.py \
                $(CYTHON_DIR)/README.md $(CYTHON_DIR)/LICENSE

# --- Sanitizer guard --------------------------------------------------
#
# Sanitizers (other than UBSan) install interceptors at process startup.
# When Python dlopen()s our .so it's too late, so we skip cython
# entirely whenever a non-UBSan sanitizer is active.  UBSan uses
# inline checks and works fine under dlopen().

_skip_cython := $(if $(filter-out undefined,$(subst $(comma), ,$(SANITIZE))),yes)

# --- Targets ----------------------------------------------------------

.PHONY: cython test-cython

_cython_stamp := $(CYTHON_BUILD)/.stamp

cython: $(_cython_stamp)

$(_cython_stamp): $(LIB)/libmerc.a $(_cython_srcs)
ifeq ($(_skip_cython),yes)
	@printf '$(COLOR_YELLOW)  skipping cython build (incompatible sanitizer)$(COLOR_OFF)\n'
else ifeq ($(CAN_BUILD_CYTHON),yes)
	$(Q)mkdir -p '$(abspath $(CYTHON_SRC))' '$(abspath $(CYTHON_LIB))' \
	             '$(abspath $(CYTHON_DIST))'
	$(Q)cp $(CYTHON_DIR)/mercury.pyx  $(CYTHON_DIR)/pyproject.toml \
	       $(CYTHON_DIR)/_version.py  $(CYTHON_DIR)/README.md \
	       $(CYTHON_DIR)/LICENSE       '$(abspath $(CYTHON_SRC))/'
	$(Q)cp $(CYTHON_DIR)/setup2.py    '$(abspath $(CYTHON_SRC))/setup.py'
	$(Q)rm -f '$(abspath $(CYTHON_DIST))'/*.whl
	$(call QUIET,WHEEL,$(CYTHON_DIST)/)cd '$(abspath $(CYTHON_SRC))' && \
	  CC='$(CXX)' CXX='$(CXX)' \
	  ENV_CFLAGS='$(call _escape_sq,$(CXXFLAGS))' \
	  ENV_LDFLAGS='$(call _escape_sq,$(LDFLAGS))' \
	  LIBMERC_A='$(abspath $(LIB)/libmerc.a)' \
	  MERCURY_DIR='$(abspath .)' \
	  $(PYTHON) -m pip wheel --no-build-isolation --no-deps \
	    -w '$(abspath $(CYTHON_DIST))' . \
	  $(if $(filter 0,$(V)),> /dev/null)
	@# extract .so from wheel (using Python zipfile; not all CI images have unzip)
	$(Q)$(PYTHON) -c "import zipfile, glob; \
	  whl = glob.glob('$(abspath $(CYTHON_DIST))/*.whl')[0]; \
	  z = zipfile.ZipFile(whl); \
	  [z.extract(n, '$(abspath $(CYTHON_LIB))') for n in z.namelist() if n.endswith('.so')]"
	$(Q)touch '$@'
else
	@printf '$(COLOR_YELLOW)  skipping cython build (missing Cython/wheel/setuptools)$(COLOR_OFF)\n'
endif

test-cython: $(_cython_stamp)
	@rm -f $(TESTDIR)/.omitted.test-cython.flag
ifeq ($(_skip_cython),yes)
	@printf '$(COLOR_YELLOW)  skipping cython test (incompatible sanitizer)$(COLOR_OFF)\n'
	@mkdir -p $(TESTDIR) && touch $(TESTDIR)/.omitted.test-cython.flag
else ifeq ($(CAN_BUILD_CYTHON),yes)
	cd $(CYTHON_DIR) && \
	  PYTHONDONTWRITEBYTECODE=1 \
	  PYTHONPATH='$(abspath $(CYTHON_LIB))'"$${PYTHONPATH:+:$$PYTHONPATH}" \
	  $(PYTHON) mercury_python_test.py
	@printf '$(COLOR_GREEN)  passed cython interface tests$(COLOR_OFF)\n'
else
	@printf '$(COLOR_YELLOW)  omitting cython test; missing Cython/wheel/setuptools$(COLOR_OFF)\n'
	@mkdir -p $(TESTDIR) && touch $(TESTDIR)/.omitted.test-cython.flag
endif
