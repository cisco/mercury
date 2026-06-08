# mk/libmerc.mk -- libmerc source list and library targets
#
# Included by the top-level Makefile.  Defines LIBMERC_SRCS (the complete list of
# source files compiled into libmerc) and the .a / .so library targets.
#
# When to edit:
#   - Adding a new source file to libmerc: append it to LIBMERC_SRCS.
#   - Adding a new SIMD specialization: add the source under the
#     appropriate PLATFORM guard and set per-file ISA flags.

# ===================================================================
# Variables
# ===================================================================

LCTRIE_SRCS := \
  src/libmerc/lctrie/lctrie_bgp.cc

LIBMERC_SRCS := \
  src/libmerc/addr.cc \
  src/libmerc/bencode.cc \
  src/libmerc/config_generator.cc \
  src/libmerc/http.cc \
  src/libmerc/libmerc.cc \
  src/libmerc/pkt_proc.cc \
  src/libmerc/smb2.cc \
  src/libmerc/utils.cc \
  src/libmerc/asn1/oid.cc \
  $(LCTRIE_SRCS)

# --- Platform-specific SIMD sources -----------------------------------

ifeq ($(HAVE_XSIMD),yes)
  ifeq ($(PLATFORM),intel)
    LIBMERC_SRCS += src/libmerc/softmax_avx.cc \
                    src/libmerc/softmax_avx2.cc \
                    src/libmerc/softmax_sse2.cc
  endif
  ifeq ($(PLATFORM),arm)
    LIBMERC_SRCS += src/libmerc/softmax_neon.cc
  endif
endif

# ===================================================================
# Public targets
# ===================================================================

.PHONY: libmerc
libmerc: $(LIB)/libmerc.a $(LIB)/libmerc.so

# ===================================================================
# Build rules
# ===================================================================

# --- Per-file ISA flags for x86 SIMD sources --------------------------

$(OBJ)/src/libmerc/softmax_sse2.o: CXXFLAGS += -msse2
$(OBJ)/src/libmerc/softmax_avx.o:  CXXFLAGS += -mavx
$(OBJ)/src/libmerc/softmax_avx2.o: CXXFLAGS += -mavx2

# --- Library targets --------------------------------------------------

$(LIB)/libmerc.a: $(call objects,$(LIBMERC_SRCS))
	$(LINK_A)

$(LIB)/libmerc.so: LDLIBS := -lz -lcrypto
$(LIB)/libmerc.so: $(call objects,$(LIBMERC_SRCS))
	$(LINK_SO)

# libmerc_alt.so: same objects, different soname.  Used by the
# double-bind test (loading two libmerc .so files simultaneously).
$(LIB)/libmerc_alt.so: LDLIBS := -lz -lcrypto
$(LIB)/libmerc_alt.so: $(call objects,$(LIBMERC_SRCS))
	$(LINK_SO)
