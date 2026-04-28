# mk/mercury.mk -- mercury binary
#
# Included by the top-level Makefile.  Builds the mercury packet-processing binary
# from MERCURY_SRCS, linked against libmerc.a.
#
# When to edit:
#   - Adding a new source file to the mercury binary: append to
#     MERCURY_SRCS.
#   - Adding a new capture backend: add the source files under the
#     appropriate HAVE_* platform guard.

# ===================================================================
# Variables
# ===================================================================

MERCURY_SRCS := \
  src/mercury.c \
  src/config.cpp \
  src/json_file_io.c \
  src/output.c \
  src/pcap_file_io.c \
  src/pcap_reader.c \
  src/pkt_processing.cc

ifeq ($(HAVE_TPACKET_V3),yes)
  MERCURY_SRCS += src/af_packet_v3.c src/signal_handling_linux.c
else ifeq ($(HAVE_LIBPCAP_CAPTURE),yes)
  MERCURY_SRCS += src/pcap_live.c src/signal_handling_stub.c
else
  MERCURY_SRCS += src/capture.c src/signal_handling_stub.c
endif

# ===================================================================
# Public targets
# ===================================================================

.PHONY: mercury
mercury: $(BIN)/mercury

.PHONY: setcap
setcap: $(BIN)/mercury
	sudo setcap cap_net_raw,cap_net_admin,cap_dac_override+eip $<

# ===================================================================
# Build rules
# ===================================================================

$(BIN)/mercury: LDLIBS := -pthread $(PCAP_LIBS) -lz -lcrypto
$(BIN)/mercury: $(call objects,$(MERCURY_SRCS)) $(LIB)/libmerc.a
	$(LINK)
ifneq ($(IS_MACOS),yes)
	@printf '$(COLOR_GREEN)  for live capture: sudo setcap cap_net_raw,cap_net_admin,cap_dac_override+eip %s$(COLOR_OFF)\n' $@
endif
