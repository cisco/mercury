# mk/rules.mk -- compilation engine
#
# Included by Makefile2.  Provides compiler/linker flags, variant
# directory layout, pattern rules, and canned recipes used by every
# other mk/ file.
#
# When to edit:
#   - Adding a new BUILD_TYPE (e.g., MinSizeRel): add FLAGS_<type>
#     and update the Variant flags section in Makefile2 'make help'.
#   - Changing warning/hardening flags: edit BASE_FLAGS.
#   - Adding a new variant axis (like SANITIZE, VISIBILITY): add the
#     toggle block and append to _variant.
#
# Provides:
#   $(BASE_FLAGS)                      -- flags shared by C and C++ compilations
#   $(BASE_CXXFLAGS), $(BASE_CFLAGS)   -- language-specific base flags
#   $(CXXFLAGS), $(CFLAGS), $(LDFLAGS) -- final assembled flags
#   $(OPTFLAGS)                        -- user-supplied optional flags (appended last)
#   $(DEPFLAGS)                        -- -MMD -MP for auto-dependency tracking
#   $(BIN), $(LIB), $(OBJ), $(TESTDIR) -- variant output directories
#   $(call objects,SRCS)               -- maps source paths to .o paths
#   LINK, LINK_SO, LINK_A              -- canned recipes for link steps
#   Pattern rules for .c/.cc/.cpp -> .o with $(DEPFLAGS) dependency tracking
#
# Quiet / verbose output (a la Linux Kbuild):
#   make          -- quiet summary lines (default)
#   make V=1      -- full command lines

# ===================================================================
# Global directives
# ===================================================================

# Remove targets whose recipe exits non-zero (prevents stale partial files).
.DELETE_ON_ERROR:

# Never auto-delete intermediate files; clean already does rm -rf build/
.SECONDARY:

# ===================================================================
# Variables
# ===================================================================

# --- Quiet / verbose mode ---------------------------------------------
V ?= 0
ifeq ($(V),0)
  Q       := @
  QUIET   = @printf '  %-7s %s\n' $(1) $(2);
else
  Q       :=
  QUIET   =
endif

# --- Color output -----------------------------------------------------
COLOR_GREEN  := \033[0;32m
COLOR_YELLOW := \033[0;33m
COLOR_OFF    := \033[0m

# --- Base flags (all variants) ----------------------------------------
# CXXFLAGS is passed to both compile and link steps intentionally;
# splitting would risk forgetting a flag with link semantics.

BASE_FLAGS := -Wall -Wextra                    # [compile]
BASE_FLAGS += -Wformat -Wformat-security       # [compile]
BASE_FLAGS += -Wmissing-noreturn               # [compile]
BASE_FLAGS += -Wno-deprecated                  # [compile]
BASE_FLAGS += -Wno-deprecated-declarations     # [compile]
BASE_FLAGS += -Wno-long-long                   # [compile]
BASE_FLAGS += -Wno-missing-braces              # [compile]
BASE_FLAGS += -Wunreachable-code               # [compile]
BASE_FLAGS += -fPIC                            # [compile+link]
BASE_FLAGS += -fno-builtin-calloc              # [compile]
BASE_FLAGS += -fno-builtin-free                # [compile]
BASE_FLAGS += -fno-builtin-malloc              # [compile]
BASE_FLAGS += -fno-builtin-realloc             # [compile]
BASE_FLAGS += -fno-omit-frame-pointer          # [compile]
BASE_FLAGS += -fvisibility=hidden              # [compile+link]

BASE_CXXFLAGS := -std=c++17 $(BASE_FLAGS)
BASE_CXXFLAGS += -Wno-narrowing                # [compile]
BASE_CXXFLAGS += -Wno-psabi                    # [compile]
BASE_CXXFLAGS += -fno-rtti                     # [compile+link]

BASE_CFLAGS := -std=c11 $(BASE_FLAGS)

# --- Validate BUILD_TYPE ----------------------------------------------
ifeq ($(filter $(BUILD_TYPE),$(VALID_BUILD_TYPES)),)
  $(error Unknown BUILD_TYPE='$(BUILD_TYPE)'. Valid: $(VALID_BUILD_TYPES))
endif

# --- Sanitizer toggle -------------------------------------------------
SANITIZE ?=
comma := ,

ifneq ($(SANITIZE),)
  _variant := $(BUILD_TYPE)+$(subst $(comma),+,$(SANITIZE))
  SANITIZE_FLAGS := -fsanitize=$(SANITIZE)
  SANITIZE_LDFLAGS  := -fsanitize=$(SANITIZE)
  ifneq ($(filter memory,$(SANITIZE)),)
    SANITIZE_FLAGS += -fsanitize-memory-track-origins
  endif
else
  _variant := $(BUILD_TYPE)
  SANITIZE_FLAGS :=
  SANITIZE_LDFLAGS  :=
endif

# --- Symbol visibility override (tech debt) ---------------------------
# The production build uses -fvisibility=hidden (set in BASE_FLAGS).
# The libmerc test driver needs -fvisibility=default so internal
# symbols are accessible.  Use VISIBILITY=default for those builds;
# the long-term goal is to eliminate this requirement.
VISIBILITY ?=

ifneq ($(VISIBILITY),)
  _variant := $(_variant)+vis$(VISIBILITY)
  VIS_FLAGS := -fvisibility=$(VISIBILITY)
else
  VIS_FLAGS :=
endif

# --- Static config select (compile-time, deprecated) -----------------
# STATIC_CFG compiles a fixed protocol selection into libmerc.
# Superseded by run-time config; retained for the tls-only test driver.
STATIC_CFG ?=

ifneq ($(STATIC_CFG),)
  _variant := $(_variant)+staticcfg$(STATIC_CFG)
  STATIC_CFG_FLAGS := -DSTATIC_CFG_SELECT='"$(STATIC_CFG)"'
else
  STATIC_CFG_FLAGS :=
endif

# --- Output directories -----------------------------------------------
OBJ     := build/$(_variant)/obj
LIB     := build/$(_variant)/lib
BIN     := build/$(_variant)/bin
TESTDIR := build/$(_variant)/test

# --- Assemble flags ---------------------------------------------------
OPTFLAGS ?=
EXTRA_LDFLAGS ?=

CXXFLAGS := $(BASE_CXXFLAGS) $(FLAGS_$(BUILD_TYPE)) $(SANITIZE_FLAGS) \
            $(VIS_FLAGS) $(STATIC_CFG_FLAGS) \
            $(PLATFORM_FLAGS) $(CDEFS) $(VERSION_FLAGS) $(OPTFLAGS)
CFLAGS   := $(BASE_CFLAGS) $(FLAGS_$(BUILD_TYPE)) $(SANITIZE_FLAGS) \
            $(VIS_FLAGS) $(STATIC_CFG_FLAGS) \
            $(PLATFORM_FLAGS) $(CDEFS) $(VERSION_FLAGS) $(OPTFLAGS)
LDFLAGS  := $(LDFLAGS_$(BUILD_TYPE)) $(SANITIZE_LDFLAGS) $(PLATFORM_LDFLAGS) $(EXTRA_LDFLAGS)

# --- Source-to-object mapping -----------------------------------------
define _src_to_obj
$(patsubst %.c,$(OBJ)/%.o,$(patsubst %.cc,$(OBJ)/%.o,$(patsubst %.cpp,$(OBJ)/%.o,$(1))))
endef
objects = $(call _src_to_obj,$(1))

# --- Auto-dependency flags --------------------------------------------
DEPFLAGS := -MMD -MP

# --- Toolchain stamp (detect flag/compiler changes) -------------------
# Records the toolchain "signature" (identifying string, not
# cryptographic) for this variant.  If any tracked variable changes
# between invocations, the stamp updates and all objects in this
# variant rebuild.
#
# Already encoded in _variant (safe):  BUILD_TYPE, SANITIZE, VISIBILITY, STATIC_CFG
# From mk/config.mk (safe):            PLATFORM_FLAGS, CDEFS, VERSION_FLAGS
# Signed here (invisible overrides):   CC, CXX, AR, OPTFLAGS, EXTRA_LDFLAGS

_toolchain_sig := CC=$(CC) CXX=$(CXX) AR=$(AR) OPTFLAGS=$(OPTFLAGS) EXTRA_LDFLAGS=$(EXTRA_LDFLAGS)
_stamp := build/$(_variant)/.toolchain.stamp

# ===================================================================
# Rules and canned recipes
# ===================================================================

# --- FORCE (unconditional rebuild prerequisite) -----------------------
# Any rule listing FORCE as a prerequisite always re-runs its recipe.
.PHONY: FORCE
FORCE:

# --- Toolchain stamp rule ---------------------------------------------
_escape_sq = $(subst ','\'',$(1)) # escape single quotes for shell '...' string

# Updates the stamp only when the signature changes; objects depend on it.
$(_stamp): FORCE
	@mkdir -p $(dir $@)
	@printf '%s\n' '$(call _escape_sq,$(_toolchain_sig))' > "$@.$$$$"; \
	  if cmp -s "$@.$$$$" "$@" 2>/dev/null; then \
	    rm -f "$@.$$$$"; \
	  elif [ -f "$@" ]; then \
	    printf '  %-7s %s (toolchain changed)\n' STAMP "$@"; \
	    printf '          was: %s\n' "$$(cat "$@")"; \
	    printf '          now: %s\n' "$$(cat "$@.$$$$")"; \
	    mv -f "$@.$$$$" "$@"; \
	  else \
	    mv -f "$@.$$$$" "$@"; \
	    printf '  %-7s %s (new toolchain)\n' STAMP "$@"; \
	    printf '          %s\n' "$$(cat "$@")"; \
	  fi

# --- Compilation rules (with auto-deps) -------------------------------
$(OBJ)/%.o: %.cc $(_stamp)
	@mkdir -p $(dir $@)
	$(call QUIET,CXX,$@)$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@

# Many .c files include C++ headers; compile as C++ intentionally.
$(OBJ)/%.o: %.c $(_stamp)
	@mkdir -p $(dir $@)
	$(call QUIET,CXX,$@)$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@

$(OBJ)/%.o: %.cpp $(_stamp)
	@mkdir -p $(dir $@)
	$(call QUIET,CXX,$@)$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@

# --- Canned link recipes ----------------------------------------------
# Each link target sets its own LDLIBS via a target-specific variable,
# then invokes one of these.  CXXFLAGS is passed intentionally — see
# [compile+link] annotations in the base flags section above.
#
# Example:
#   $(BIN)/foo: LDLIBS := -lcrypto -lz
#   $(BIN)/foo: $(objects)
#   	$(LINK)

define LINK
	@mkdir -p $(dir $@)
	$(call QUIET,LINK,$@)$(CXX) $(CXXFLAGS) $^ $(LDFLAGS) $(LDLIBS) -o $@
endef

define LINK_SO
	@mkdir -p $(dir $@)
	$(call QUIET,LINK,$@)$(CXX) $(CXXFLAGS) -shared -fPIC $(SONAME_FLAG) $^ $(LDFLAGS) $(LDLIBS) -o $@
endef

define LINK_A
	@mkdir -p $(dir $@)
	$(call QUIET,AR,$@)$(AR) rcs $@ $^
endef

# Compile+link a single source file ($<) into a binary.
define CXX_LINK
	@mkdir -p $(dir $@)
	$(call QUIET,CXX+LD,$@)$(CXX) $(CXXFLAGS) $(DEPFLAGS) $< $(LDFLAGS) $(LDLIBS) -o $@
endef

# --- Auto-dependency inclusion ----------------------------------------
-include $(shell find $(OBJ) -name '*.d' 2>/dev/null)
