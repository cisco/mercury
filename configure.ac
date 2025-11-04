# configure.ac for mercury
#
AC_CONFIG_MACRO_DIR([m4])
AC_INIT([mercury], 1.0)
AC_USE_SYSTEM_EXTENSIONS
#AC_PROG_CC
AC_PROG_CXX
AC_CANONICAL_HOST
AC_MSG_CHECKING([for platform architecture])
case "$host_cpu" in
    i?86 | x86_64)
        PLATFORM="intel"
        AC_MSG_RESULT([Intel-compatible ($host_cpu)])
        ;;
    arm* | aarch64)
        PLATFORM="arm"
        AC_MSG_RESULT([ARM-compatible ($host_cpu)])
        ;;
    *)
        PLATFORM="unknown"
        AC_MSG_WARN([Unknown architecture: $host_cpu])
        ;;
esac
AC_SUBST([PLATFORM])

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
AC_CHECK_FUNCS([gettid], [AC_DEFINE([HAVE_GETTID], [1], [Define if gettid exists.])])
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
AC_CHECK_HEADERS(zlib.h, [], [AC_MSG_ERROR([A working zlib is required])])
AC_SEARCH_LIBS(deflate, z, [], [AC_MSG_ERROR([A working zlib is required])])
# Check for OpenSSL version and set appropriate flags
# First check for OpenSSL 3.0+ (EVP_MAC_fetch function)
AC_SEARCH_LIBS(EVP_MAC_fetch, crypto, [
    AC_MSG_NOTICE([OpenSSL 3.0+ detected - using EVP_MAC API])
    AC_SUBST([OPENSSL_V1_1_OR_NEWER],yes)
    AC_SUBST([OPENSSL_V3_0_OR_NEWER],yes)
], [
    # If not OpenSSL 3.0+, check for OpenSSL 1.1.0+ (HMAC_CTX_new function)
    AC_SEARCH_LIBS(HMAC_CTX_new, crypto, [
        AC_MSG_NOTICE([OpenSSL 1.1.0+ detected - using HMAC_CTX_new API])
        AC_SUBST([OPENSSL_V1_1_OR_NEWER],yes)
        AC_SUBST([OPENSSL_V3_0_OR_NEWER],no)
    ], [
        # Legacy OpenSSL < 1.1.0
        AC_MSG_NOTICE([Legacy OpenSSL < 1.1.0 detected - using deprecated HMAC API])
        AC_SUBST([OPENSSL_V1_1_OR_NEWER],no)
        AC_SUBST([OPENSSL_V3_0_OR_NEWER],no)
    ])
])

###############################################################################
# Check for Python3 and packages
###############################################################################
AC_CHECK_PROGS(PY, python3 python)
AC_CHECK_PROG(HAVE_PYTHON3,python3,yes)
# Check for Python packages using the custom macro below.
# Usage: CHECK_PYTHON_PACKAGE([OUTPUT_VARIABLE], [reason description], [packagename], [importname(optional)])
# Output: OUTPUT_VARIABLE=yes or no.
AC_DEFUN([CHECK_PYTHON_PACKAGE],[
    if test "x$4" != "x"; then
        IMPORTNAME=$4
    else
        IMPORTNAME=$3
    fi
    AC_MSG_CHECKING([for python package $3])
    AS_IF([python3 -c "import $IMPORTNAME" 2>/dev/null], [
        AC_MSG_RESULT(yes)
        AC_SUBST([$1],yes)
    ], [
        AC_MSG_RESULT(no)
        AC_SUBST([$1],no)
        AC_MSG_WARN([python package '$3' not found (needed for $2).  Install with 'python3 -m pip install $3'])
    ])
])
AS_IF([test "x$HAVE_PYTHON3" = xyes], [
    # Python-assisted testing of C++ code
    CHECK_PYTHON_PACKAGE([HAVE_PYTHON_JSONSCHEMA],['make test'],[jsonschema])
    CHECK_PYTHON_PACKAGE([HAVE_PYTHON_CRYPTOGRAPHY],['make test'],[cryptography])

    # Mercury Cython package
    CHECK_PYTHON_PACKAGE([HAVE_PYTHON_CYTHON],[Cython package],[Cython])
    CHECK_PYTHON_PACKAGE([HAVE_PYTHON_WHEEL],[Cython package],[wheel])
    CHECK_PYTHON_PACKAGE([HAVE_PYTHON_SETUPTOOLS],[Cython package],[setuptools])

    # Auto-generated documentation
    CHECK_PYTHON_PACKAGE([HAVE_PYTHON_SPHINX],[generating docs],[sphinx])
    CHECK_PYTHON_PACKAGE([HAVE_PYTHON_SPHINX_RTD_THEME],[generating docs],[sphinx-rtd-theme],[sphinx_rtd_theme])
    CHECK_PYTHON_PACKAGE([HAVE_PYTHON_SPHINX_AUTODOC_TYPEHINTS],[generating docs],[sphinx-autodoc-typehints],[sphinx_autodoc_typehints])
    CHECK_PYTHON_PACKAGE([HAVE_PYTHON_BREATHE],[generating docs],[breathe])

    # Composite variables
    AS_IF([test "x$HAVE_PYTHON_CYTHON" = xyes -a "x$HAVE_PYTHON_WHEEL" = xyes -a "x$HAVE_PYTHON_SETUPTOOLS" = xyes], [
        AC_SUBST([CAN_BUILD_CYTHON_PACKAGE],yes)
    ], [
        AC_SUBST([CAN_BUILD_CYTHON_PACKAGE],no)
        AC_MSG_WARN([Cython package building will be disabled due to missing dependencies])
    ])
    AS_IF([test "x$HAVE_PYTHON_JSONSCHEMA" = xyes -a "x$HAVE_PYTHON_CRYPTOGRAPHY" = xyes -a \
                "x$CAN_BUILD_CYTHON_PACKAGE" = xyes], [
        AC_SUBST([CAN_RUN_ALL_TESTS],yes)
    ], [
        AC_SUBST([CAN_RUN_ALL_TESTS],no)
        AC_MSG_WARN(['make test' will be partially disabled due to missing dependencies])
    ])
    AS_IF([test "x$HAVE_PYTHON_SPHINX" = xyes -a "x$HAVE_PYTHON_SPHINX_RTD_THEME" = xyes -a \
                "x$HAVE_PYTHON_SPHINX_AUTODOC_TYPEHINTS" = xyes -a "x$HAVE_PYTHON_BREATHE" = xyes], [
        AC_SUBST([CAN_BUILD_DOCS],yes)
    ], [
        AC_SUBST([CAN_BUILD_DOCS],no)
        AC_MSG_WARN(['make doc' will fail due to missing dependencies])
    ])
], [AC_MSG_WARN([python3 not found; make test, make doc, and building the Cython package will not work])])

###############################################################################
# Check for other command line tools
###############################################################################
AC_CHECK_PROG(TCPREPLAY,tcpreplay,yes)
AC_CHECK_PROG(JQ,jq,yes)
AC_CHECK_PROG(WGET,wget,yes)
AC_CHECK_PROG(VALGRIND,valgrind,yes)
AC_CHECK_PROG(HAVE_AFL,afl-g++,yes)
AC_CHECK_PROG(CLANGPP, clang++, yes)
AC_CHECK_PROG(LLVM,llvm-link,yes)
AC_CHECK_PROG(LCOV, lcov, yes)
AC_CHECK_PROG(HAVE_DOXYGEN,doxygen,yes)
AC_CHECK_PROG(HAVE_DOT,dot,yes)
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
AS_IF([test "x$LCOV" = xyes],
    [],
    [AC_MSG_WARN([lcov not found; make test-coverage and test-coverage-fuzz will not work])])
AS_IF([test "x$HAVE_DOXYGEN" = xyes],
    [],
    [AC_MSG_WARN([doxygen not found; make doc will not work])])
AS_IF([test "x$HAVE_DOT" = xyes],
    [],
    [AC_MSG_WARN([dot (from graphviz) not found; make doc will not work])])

AC_CONFIG_FILES(src/libmerc/Makefile src/cython/Makefile src/Makefile test/Makefile unit_tests/Makefile Makefile_helper.mk install_mercury/mercury.service)
AC_OUTPUT
