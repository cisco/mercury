# configure.ac for mercury
#
AC_CONFIG_MACRO_DIR([m4])
AC_INIT([mercury], 1.0)
AC_USE_SYSTEM_EXTENSIONS
#AC_PROG_CC
AC_PROG_CXX
AC_CANONICAL_HOST
# Update lib and include paths for Apple Silicon
case $host_os in
    darwin* )
        AC_SUBST(IS_MACOS,yes)
        if [[ $(uname -m) == 'arm64' ]]; then
            CFLAGS="$CFLAGS -I/opt/homebrew/include -I/opt/local/include"
            CXXFLAGS="$CXXFLAGS -I/opt/homebrew/include -I/opt/local/include"
            LDFLAGS="$LDFLAGS -L/opt/homebrew/lib -L/opt/local/lib"
            AC_MSG_WARN([Configuring for Apple Silicon])
            AC_SUBST(IS_MACOS_ARM,yes)
        fi
        ;;

esac
AX_CHECK_COMPILE_FLAG([-fno-gnu-unique], [AC_SUBST([USE_NO_GNU_UNIQUE],yes)], [AC_SUBST([USE_NO_GNU_UNIQUE],no)] , [-Werror])
AX_CHECK_COMPILE_FLAG([-fsanitize=address], [AC_SUBST([USE_FSANITIZE],yes)], [AC_SUBST([USE_FSANITIZE],no)] , [-Werror])
AC_CHECK_HEADERS([linux/if_packet.h])
AC_CHECK_MEMBER([struct tpacket_req3.tp_block_size],[AC_SUBST(HAVE_TPACKET_V3,yes)],[AC_MSG_WARN([Linux AF_PACKET's TPACKET V3 is not available])],[[#include <linux/if_packet.h>]])
#AC_CHECK_MEMBER([struct tpacket_req3.tp_block_size],[],[AC_MSG_FAILURE([Linux AF_PACKET's TPACKET V3 is required, but not available])],[[#include <linux/if_packet.h>]])
AC_CHECK_FUNCS([gettimeofday])
AC_CHECK_FUNCS([memset]) 
AC_CHECK_FUNCS([mkdir]) 
AC_CHECK_FUNCS([munmap])
AC_CHECK_FUNCS([socket]) 
AC_CHECK_FUNCS([strerror]) 
AC_CHECK_FUNCS([strtol]) 
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([stddef.h])
AC_CHECK_HEADERS([sys/ioctl.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([x86intrin.h])
AC_CHECK_TYPES([ptrdiff_t])
AC_FUNC_MALLOC 
AC_FUNC_MMAP 
#AC_FUNC_STRNLEN 
AC_PREREQ 
#AC_PROG_INSTALL 
#AC_PROG_MAKE_SET 
AC_TYPE_INT32_T 
AC_TYPE_INT64_T 
AC_TYPE_PID_T 
AC_TYPE_SIZE_T 
AC_TYPE_SSIZE_T 
AC_TYPE_UID_T 
AC_TYPE_UINT16_T 
AC_TYPE_UINT32_T 
AC_TYPE_UINT64_T 
AC_TYPE_UINT8_T
AC_CHECK_PROGS(PY, python3 python python2)
AC_CHECK_HEADERS(zlib.h, [], [AC_ERROR([A working zlib is required])])
AC_SEARCH_LIBS(deflate, z, [], [AC_ERROR([A working zlib is required])])
AC_SEARCH_LIBS(HMAC_CTX_new, crypto, [AC_SUBST([OPENSSL_NEWER],yes)], [AC_SUBST([OPENSSL_NEWER],no)])
AC_CHECK_PROG(PYTHON3,python3,yes)
AS_IF([test "x$PYTHON3" = xyes],
    [AC_DEFINE([HAVE_PYTHON3], [1], [python3 is available.])])
#
AS_IF([test "x$PYTHON3" = xyes],
    [AS_IF([python3 ./package_test.py],
           [AC_SUBST(HAVE_JSONSCHEMA,yes)],
           [AC_MSG_WARN([python3 package jsonschema not found; test/Makefile will not work, install with 'pip3 install jsonschema'])])],
    [])
#AC_ARG_ENABLE(python, AS_HELP_STRING([--disable-python], [omit embedded python analysis engine]), [], [AC_CHECK_PROG(PIP3,pip3,yes)])
#AS_IF([test "x$PIP3" = xyes],
#    [AC_CHECK_HEADERS([pcap.h], [], [AC_MSG_ERROR([pcap.h not found; lipcap-dev seems not to be installed])])])
#AS_IF([test "x$PIP3" = xyes],
#    [AC_CONFIG_COMMANDS([pip3], [pip3 install cython ujson pyasn])])
AC_CHECK_PROG(TCPREPLAY,tcpreplay,yes)
AC_CHECK_PROG(JQ,jq,yes)
AC_CHECK_PROG(WGET,wget,yes)
AC_CHECK_PROG(VALGRIND,valgrind,yes)
AC_CHECK_PROG(HAVE_AFL,afl-g++,yes)
AC_CHECK_PROG(CLANGPP, clang++, yes)
AC_CHECK_PROG(LLVM,llvm-link,yes)
AS_IF([test "x$TCPREPLAY" = xyes],
    [],
    [AC_MSG_WARN([tcpreplay not found; test/Makefile dummy-capture test will not work])])
AS_IF([test "x$JQ" = xyes],
    [],
    [AC_MSG_WARN([jq not found; test/Makefile comparison test will not work])])
AS_IF([test "x$WGET" = xyes],
    [],
    [AC_MSG_WARN([wget not found; test/capture script will not work])])
AS_IF([test "x$VALGRIND" = xyes],
    [],
    [AC_MSG_WARN([valgrind not found; test/Makefile memcheck test will not work])])
AS_IF([test "x$USE_FSANITIZE" = xyes],
    [],
    [AC_MSG_WARN([-fsanitize not supported; debug targets will not use address sanitization])])
AS_IF([test "x$CLANGPP" = xyes],
    [],
    [AC_MSG_WARN([clang++ not found; make fuzz-test will not work])])
AS_IF([test "x$LLVM" = xyes],
    [],
    [AC_MSG_WARN([llvm not found; make fuzz-test may not work])])
AC_CONFIG_FILES(src/libmerc/Makefile src/cython/Makefile src/Makefile test/Makefile unit_tests/Makefile resources/Makefile Makefile_helper.mk install_mercury/mercury.service)
AC_OUTPUT
