#!/bin/bash
#
# pdu_test.sh
#
# runs pdu_verifier on packet capture files
# definitions for colorized output
COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[0;33m"
COLOR_OFF="\033[0m"

VERIFIER=${VERIFIER:-../unit_tests/pdu_verifier}

# Set the platform-specific dynamic library search path so the
# dynamically linked pdu_verifier can find libmerc.so at runtime.
# Callers (e.g. Makefile2) pass LIBMERC_DIR; fall back to the
# in-tree libmerc location for manual runs.
LIBMERC_DIR=${LIBMERC_DIR:-../src/libmerc/}
case "$(uname)" in
    Darwin) export DYLD_LIBRARY_PATH="${LIBMERC_DIR}${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" ;;
    *)      export LD_LIBRARY_PATH="${LIBMERC_DIR}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ;;
esac

echo "LIBMERC_DIR=$LIBMERC_DIR"

# check to make sure that we have the executable, library, and
# directory (set through environment variable) that we need

if [ -x "$VERIFIER" ]; then
    echo "using executable $VERIFIER"
else
    echo "error: executable $VERIFIER not found"
    exit 1
fi

if [[ -z "${PCAP_DIR}" ]]; then
    echo "error: environment variable PCAP_DIR not set"
    exit 1
else
    echo "using PCAP_DIR=$PCAP_DIR"
fi

if [ -d "$PCAP_DIR" ]; then
    echo "found directory $PCAP_DIR"
else
    echo "error: directory $PCAP_DIR not found"
    exit 1
fi

# run verifier on all PCAP files in PCAP_DIR, and track which tests
# passed/failed
#
passed=""
failed=""
error="false"
for prefix in tls.client_hello http.request quic dns; do
#    if [ -e $PCAP_DIR/$prefix.*.pcap ]; then
        for f in $PCAP_DIR/$prefix.*.pcap; do
            echo
            echo "verifying packets in $f"
            $VERIFIER -r $f -f $prefix
            retval=$?
            if [ "$retval" = 0 ]; then
                passed="$passed $(basename $f)"
            else
                failed="$failed $(basename $f)"
                error="true"
            fi
        done
#    fi
done

echo "passed: $passed"
echo "failed: $failed"

if [ ! "$error" = "false" ]; then
    echo -e $COLOR_RED "error: one or more tests failed" $COLOR_OFF
    exit 1
else
    echo -e $COLOR_GREEN "success: all tests passed" $COLOR_OFF
fi

# EOF
