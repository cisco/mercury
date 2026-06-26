# mk/tools.mk -- standalone programs and development tools
#
# Every binary listed in TOOL_TARGETS is built by 'all', and
# automatically gets a short-name alias (e.g. 'make cert_analyze').
# To add a new tool:
#   1. Append $(BIN)/your_tool to TOOL_TARGETS
#   2. Add a build rule below
#   3. Add a one-line description to the Tools section in 'make help'

# ===================================================================
# Variables
# ===================================================================

TOOL_TARGETS := \
  $(BIN)/archive_reader \
  $(BIN)/cbor \
  $(BIN)/cert_analyze \
  $(BIN)/classify \
  $(BIN)/cms \
  $(BIN)/decode \
  $(BIN)/intercept_server \
  $(BIN)/libmerc_util \
  $(BIN)/os_identifier \
  $(BIN)/pcap \
  $(BIN)/pcap_filter \
  $(BIN)/string

ifneq ($(IS_MACOS),yes)
  TOOL_TARGETS += $(BIN)/tls_scanner
endif
ifeq ($(HAVE_GMP),yes)
  TOOL_TARGETS += $(BIN)/batch_gcd
endif

# Certtools subset (used by certtools and install-certtools aliases).
CERTTOOLS := $(BIN)/cert_analyze
ifneq ($(IS_MACOS),yes)
  CERTTOOLS += $(BIN)/tls_scanner
endif
ifeq ($(HAVE_GMP),yes)
  CERTTOOLS += $(BIN)/batch_gcd
endif

# ===================================================================
# Public targets
# ===================================================================

.PHONY: tools
tools: $(TOOL_TARGETS)

.PHONY: certtools
certtools: $(CERTTOOLS)

# Auto-generate short-name aliases (e.g. 'make cert_analyze') from TOOL_TARGETS.
_TOOL_NAMES := $(notdir $(TOOL_TARGETS))
.PHONY: $(_TOOL_NAMES)
$(foreach t,$(TOOL_TARGETS),$(eval $(notdir $(t)): $(t)))

# ===================================================================
# Build rules
# ===================================================================

# archive_reader — archive (gzip/tar) reader
$(BIN)/archive_reader: LDLIBS := -lz -lcrypto
$(BIN)/archive_reader: $(call objects,src/archive_reader.cc)
	$(LINK)

# batch_gcd — batch GCD for RSA moduli (needs libgmp)
$(BIN)/batch_gcd: LDLIBS := -pthread -lgmpxx -lgmp
$(BIN)/batch_gcd: $(call objects,src/batch_gcd.cc src/libmerc/asn1/oid.cc)
	$(LINK)

# cbor — CBOR encoder/decoder
$(BIN)/cbor: $(call objects,src/cbor.cpp)
	$(LINK)

# cert_analyze — X.509 certificate analysis
$(BIN)/cert_analyze: LDLIBS := -pthread -lcrypto
$(BIN)/cert_analyze: $(call objects,src/cert_analyze.cc src/libmerc/asn1/oid.cc)
	$(LINK)

# classify — protocol classifier using libmerc.a
$(BIN)/classify: LDLIBS := -pthread -lcrypto -lz
$(BIN)/classify: $(call objects,src/classify.cpp) $(LIB)/libmerc.a
	$(LINK)

# cms — CMS/PKCS#7 parser
$(BIN)/cms: LDLIBS := -lcrypto
$(BIN)/cms: $(call objects,src/cms.cpp src/libmerc/asn1/oid.cc)
	$(LINK)

# decode — hex/binary decoder
$(BIN)/decode: $(call objects,src/decode.cc)
	$(LINK)

# intercept — intercept_server + intercept.so (phony convenience target)
.PHONY: intercept
intercept: $(BIN)/intercept_server $(LIB)/intercept.so

# intercept_server — TLS interception server
$(BIN)/intercept_server: $(call objects,src/intercept_server.cc)
	$(LINK)

# intercept.so — LD_PRELOAD TLS interception library (Linux only;
# requires libnspr4-dev and libgnutls28-dev).  Compiles intercept.cc
# and pkt_proc.cc directly in the link step, matching the original recipe.
$(LIB)/intercept.so: $(LIB)/libmerc.a
	@mkdir -p $(dir $@)
	$(call QUIET,LINK,$@)$(CXX) $(CXXFLAGS) -D_GNU_SOURCE -I/usr/include/nspr/ \
	  src/intercept.cc src/libmerc/pkt_proc.cc \
	  -fPIC -shared $(LIB)/libmerc.a \
	  $(LDFLAGS) -lssl -lnspr4 -lgnutls -o $@

# libmerc_util — PCAP analysis tool using libmerc.so (via dlopen)
#
# Tech debt: pcap_file_io.c #includes pkt_processing.h, which transitively
# pulls in internal libmerc headers (http.h, global_config.h, smb2.h,
# asn1/oid.h).  On GCC at -O0, those headers instantiate templates with
# unresolved symbols that would require linking libmerc.a.  We force -O2
# so the build works regardless of the variant's optimization level.
#
# The objects are placed in a private subdirectory (_libmerc_util_obj/) so the
# -O2 override does not collide with the shared pcap_file_io.o used by mercury,
# which must honour the variant's own optimization level.

_UTIL_OBJ := $(OBJ)/_libmerc_util_obj

$(_UTIL_OBJ)/%.o: %.cc $(_toolchain_stamp)
	@mkdir -p $(dir $@)
	$(call QUIET,CXX,$@)$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@

$(_UTIL_OBJ)/%.o: %.c $(_toolchain_stamp)
	@mkdir -p $(dir $@)
	$(call QUIET,CXX,$@)$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@

$(BIN)/libmerc_util: CXXFLAGS += -UNDEBUG -O2
$(BIN)/libmerc_util: LDLIBS := -pthread -lcrypto -ldl -lz
$(BIN)/libmerc_util: $(_UTIL_OBJ)/src/libmerc_util.o $(_UTIL_OBJ)/src/pcap_file_io.o
	@printf '$(COLOR_YELLOW)  note: forcing -O2 for libmerc_util (link workaround)$(COLOR_OFF)\n'
	$(LINK)

# os_identifier — OS identification from network traffic
$(OBJ)/src/os_identifier.o: CXXFLAGS += -Isrc/libmerc
$(BIN)/os_identifier: LDLIBS := -lz
$(BIN)/os_identifier: $(call objects,src/os_identifier.cc)
	$(LINK)

# pcap — PCAP file reader and packet dumper
$(BIN)/pcap: $(call objects,src/pcap.cc)
	$(LINK)

# pcap_filter — PCAP filtering using libmerc.a
$(BIN)/pcap_filter: LDLIBS := -lz -lcrypto -pthread
$(BIN)/pcap_filter: $(call objects,src/pcap_filter.cc src/pcap_file_io.c) $(LIB)/libmerc.a
	$(LINK)

# string — string utilities
$(BIN)/string: $(call objects,src/string.cc)
	$(LINK)

# tls_scanner — TLS scanner (Linux only)
$(BIN)/tls_scanner: LDLIBS := -pthread -lssl -lcrypto -lz
$(BIN)/tls_scanner: $(call objects,src/tls_scanner.cc) $(LIB)/libmerc.a
	$(LINK)

# ===================================================================
# Development workflow targets
# ===================================================================

# cppcheck — cppcheck static analysis
.PHONY: cppcheck
cppcheck:
	cppcheck --language=c++ --std=c++17 --force --enable=all \
	  -URAPIDJSON_DOXYGEN_RUNNING \
	  --template='{file}:{line}:{severity}:{message}' \
	  $(MERCURY_SRCS) $(LIBMERC_SRCS) \
	  -isrc/libmerc/rapidjson/

# cppclean — find unused includes, functions, and forward declarations
# in libmerc sources.  The if/then wrapper handles known parse failures
# (e.g. tcp.h, rapidjson headers).
.PHONY: cppclean
cppclean:
	rm -f cppclean_report.txt
	for F in $(LIBMERC_SRCS) $$(find src/libmerc -maxdepth 2 -name '*.h' -o -name '*.hpp' | sort); do \
	  if cppclean "$$F" >> cppclean_report.txt; then : ; fi; \
	done
	@printf '$(COLOR_GREEN)  cppclean report: cppclean_report.txt$(COLOR_OFF)\n'

# format — run code formatter
.PHONY: format
format:
	./utils/indent_files.sh src/*.c src/*.h src/python-inference/*.py \
	  python/*.py python/*/*.py python/*/*/*.py

# compiler-version — print compiler version string
.PHONY: compiler-version
compiler-version:
	$(CXX) --version

# increment-{patchlevel,minor-version,major-version} — bump VERSION and commit.
# Requires _major, _minor, _patch from mk/config.mk.

define increment_version
	echo $(2) > VERSION
	echo "__version__ = '$(2)'" > src/cython/_version.py
	sed -i.bak "s/__version__ = '.*'/__version__ = '$(2)'/" src/cython/mercury.pyx && rm src/cython/mercury.pyx.bak
	git add VERSION doc/CHANGELOG.md src/cython/_version.py src/cython/mercury.pyx
	git commit -m "$(3): $(1) -> $(2)"
	@echo ""
	@printf '$(COLOR_GREEN)  Version bumped: $(1) -> $(2). Next steps:$(COLOR_OFF)\n'
	@echo "  1. Push current branch (not dev): git push"
	@echo "  2. Create PR to merge current branch into dev, then merge"
	@echo "  3. Trigger one-click release: Actions -> [EMU] Promote & Tag Release -> Run workflow"
endef

.PHONY: increment-patchlevel increment-minor-version increment-major-version
increment-patchlevel:
	$(call increment_version,$(_major).$(_minor).$(_patch),$(_major).$(_minor).$(shell expr $(_patch) + 1),incrementing patchlevel)

increment-minor-version:
	$(call increment_version,$(_major).$(_minor).$(_patch),$(_major).$(shell expr $(_minor) + 1).0,incrementing minor version)

increment-major-version:
	$(call increment_version,$(_major).$(_minor).$(_patch),$(shell expr $(_major) + 1).0.0,incrementing major version)
