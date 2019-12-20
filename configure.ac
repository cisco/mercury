# configure.ac for mercury
#
AC_INIT([mercury], 1.0)
AC_USE_SYSTEM_EXTENSIONS
#AC_PROG_CC
AC_PROG_CXX
AC_CHECK_HEADERS([linux/if_packet.h])
#AC_CHECK_MEMBER([struct tpacket_req3.tp_snaplen],[],[AC_MSG_FAILURE([Linux AF_PACKET's TPACKET V3 is required, but not available])],[[#include <linux/if_packet.h>]])
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
AC_CHECK_PROG(PYTHON3,python3,yes)
AS_IF([test "x$PYTHON3" = xyes],
    [AC_DEFINE([HAVE_PYTHON3], [1], [python3 is available.])])
#
AS_IF([test "x$PYTHON3" = xyes],
    [AS_IF([python3 ./package_test.py],
           [AC_SUBST(HAVE_JSONSCHEMA,yes)],
           [AC_MSG_WARN([python package jsonschema (required for 'make test') not found; install with 'pip3 install jsonschema'])])],
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
AS_IF([test "x$TCPREPLAY" = xyes],
    [],
    [AC_MSG_NOTICE([tcpreplay not found; test/Makefile dummy-capture test will not work])])
AS_IF([test "x$JQ" = xyes],
    [],
    [AC_MSG_NOTICE([jq not found; test/Makefile comparison test will not work])])
AS_IF([test "x$WGET" = xyes],
    [],
    [AC_MSG_NOTICE([wget not found; test/capture script will not work])])
AS_IF([test "x$VALGRIND" = xyes],
    [],
    [AC_MSG_NOTICE([valgrind not found; test/Makefile memcheck test will not work])])
AC_CONFIG_FILES(src/Makefile test/Makefile resources/Makefile install_mercury/mercury.service)
AC_OUTPUT
