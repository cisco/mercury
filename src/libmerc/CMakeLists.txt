cmake_minimum_required(VERSION 3.12)
project(libmerc)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_VERBOSE_MAKEFILE on)
# no installing
set(CMAKE_SKIP_INSTALL_RULES TRUE)
set(CMAKE_CXX_FLAGS "${CXXFLAGS} ${CFLAGS} ${CMAKE_CXX_FLAGS}")

## CMake Configuration options:
#
# Usage: cmake -DFOO=x -DBAR=y ...
#
#  LIBMERC_ONLY=TRUE : build only libmerc src and skip asn1 build by using prebuilt oid.cc oid.h
#  TARGET_MAC_ARCH=x86_64 : build for macOS x86_64 or arm64 (replace value with arm64)
#  ZLIB_ROOT=path : Custom zlib dir (containing include/zlib.h and lib/libz.* or lib/zlib.lib)
#  OPENSSL_ROOT_DIR=path : Custom OpenSSL dir (containing include/openssl/*.h and lib/libcrypto.*)
#  OPENSSL_CUSTOM_LIB_DIR=path : Custom OpenSSL library-only dir (containing libcrypto.*)
#
# Note: OpenSSL has two options.  If your OpenSSL installation follows the
# standard directory layout where a single top-level directory contains both
# include/openssl/*.h and lib/libcrypto.*, you can provide a path to that
# top-level directory via OPENSSL_ROOT_DIR (as specified in
# https://cmake.org/cmake/help/latest/module/FindOpenSSL.html).  If your OpenSSL
# installation does NOT follow the standard layout, you can specify the exact
# directory that contains just the compiled library itself (libcrypto.*) using
# OPENSSL_CUSTOM_LIB_DIR.


## Platform checks

message(STATUS "Platform - ${CMAKE_SYSTEM_NAME}")
message(STATUS "Architecture - ${CMAKE_SYSTEM_PROCESSOR}")

# Operating System Selection
if(${CMAKE_SYSTEM_NAME} MATCHES Windows)
    set(IS_WIN TRUE)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES Darwin)
    if(${CMAKE_SYSTEM_PROCESSOR} MATCHES arm64)
        set(IS_MAC_ARM TRUE)
    endif()
endif()

# Processor Architecture Selection
if(DEFINED TARGET_MAC_ARCH)  # Explicit target architecture: may not match host system
    # Use the target architecture specified by build script
    if(TARGET_MAC_ARCH MATCHES "x86_64")
        set(INTEL_PLATFORM TRUE)
        message(STATUS "Target platform: Intel x86_64 (specified by TARGET_MAC_ARCH)")
    elseif(TARGET_MAC_ARCH MATCHES "arm64")
        set(ARM_PLATFORM TRUE)
        message(STATUS "Target platform: ARM64 (specified by TARGET_MAC_ARCH)")
    endif()
else()
    # Fall back to system processor detection
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64|i.86)$")
        set(INTEL_PLATFORM TRUE)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64|armv7)$")
        set(ARM_PLATFORM TRUE)
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "^armv7$")
            set(ARMV7_PLATFORM TRUE)
        endif()
    endif()
    message(STATUS "Target platform: ${CMAKE_SYSTEM_PROCESSOR} (auto-detected)")
endif()


## Platform specific paths (only if Homebrew is installed)
if(IS_MAC_ARM)
    if(IS_DIRECTORY "/opt/homebrew")
        message(STATUS "Homebrew detected: adding /opt/homebrew to search paths")
        link_directories("/opt/homebrew/lib")
        include_directories("/opt/homebrew/include")
        if(NOT DEFINED OPENSSL_ROOT_DIR)
            message(STATUS "Using /opt/homebrew to find OpenSSL")
            set(OPENSSL_ROOT_DIR "/opt/homebrew")
        endif()
        if(NOT DEFINED ZLIB_ROOT)
            message(STATUS "Using /opt/homebrew/opt/zlib to find zlib")
            set(ZLIB_ROOT "/opt/homebrew/opt/zlib")
        endif()
    endif()
endif()


## Find external libraries
message(STATUS "Library search paths (CMAKE_PREFIX_PATH): ${CMAKE_PREFIX_PATH}")

# Custom OpenSSL path handling (for build script compatibility)
if(DEFINED OPENSSL_CUSTOM_LIB_DIR)
    message(STATUS "Using custom OpenSSL library path: ${OPENSSL_CUSTOM_LIB_DIR}")
    link_directories(${OPENSSL_CUSTOM_LIB_DIR})
    set(OpenSSL_FOUND TRUE)
else()
    # OpenSSL: https://cmake.org/cmake/help/latest/module/FindOpenSSL.html
    # If find_package succeeds, several variables will be set:
    # OpenSSL_FOUND, OPENSSL_INCLUDE_DIR, OPENSSL_CRYPTO_LIBRARY, OPENSSL_VERSION
    find_package(OpenSSL REQUIRED COMPONENTS Crypto)
    if(OpenSSL_FOUND)
        message(STATUS "OpenSSL include path: ${OPENSSL_INCLUDE_DIR}")
        message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
    endif()
endif()

# Zlib: https://cmake.org/cmake/help/latest/module/FindZLIB.html
# If find_package succeeds, these variables will be set:
# ZLIB_FOUND, ZLIB_INCLUDE_DIRS, ZLIB_LIBRARIES
find_package(ZLIB REQUIRED)
if(ZLIB_FOUND)
    message(STATUS "zlib include path: ${ZLIB_INCLUDE_DIRS}")
    set(HAVE_ZLIB_H 1)
endif()


## checks and configure

# headers
include(CheckIncludeFiles)
check_include_files(linux/if_packet.h  HAVE_IF_PACKET_H)
check_include_files(arpa/inet.h        HAVE_INET_H)
check_include_files(fcntl.h            HAVE_FCNTL_H)
check_include_files(stddef.h           HAVE_STDDEF_H)
check_include_files(sys/ioctl.h        HAVE_IOCTL_H)
check_include_files(sys/socket.h       HAVE_SOCKET_H)
check_include_files(sys/time.h         HAVE_TIME_H)
check_include_files(x86intrin.h        HAVE_X86INTRIN_H)
if(${HAVE_X86INTRIN_H})
    add_compile_definitions(HAVE_X86INTRIN_H=1)
endif()

# functions
include(CheckFunctionExists)
check_function_exists(gettimeofday    HAVE_GETTIMEOFDAY)
check_function_exists(memset          HAVE_MEMSET)
check_function_exists(mkdir           HAVE_MKDIR)
check_function_exists(munmap          HAVE_MUNMAP)
check_function_exists(socket          HAVE_SOCKET)
check_function_exists(strerror        HAVE_STRERROR)
check_function_exists(strtol          HAVE_STRTOL)
check_function_exists(malloc          HAVE_MALLOC)
check_function_exists(mmap            HAVE_MMAP)

# type checks
include(CheckTypeSize)
check_type_size("int32_t"    SIZE_INT32_T)
check_type_size("int64_t"    SIZE_INT64_T)
check_type_size("pid_t"      SIZE_PID_T)
check_type_size("size_t"     SIZE_SIZE_T)
check_type_size("ssize_t"    SIZE_SSIZE_T)
check_type_size("uid_t"      SIZE_UID_T)
check_type_size("uint16_t"   SIZE_UINT16_T)
check_type_size("uint32_t"   SIZE_UIN32_T)
check_type_size("uint64_t"   SIZE_UINT64_T)
check_type_size("uint8_t"    SIZE_UINT8_T)
check_type_size("ptrdiff_t"  SIZE_PTRDIFF_T)

if(DEFINED OPENSSL_CUSTOM_LIB_DIR)
    message(STATUS "Assuming newer libcrypto functions (>= 1.1.0) for custom OpenSSL")
    add_compile_definitions(SSLNEW)
else()
    # libcrypto version checks
    include(CheckSymbolExists)
    set(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(CMAKE_REQUIRED_LIBRARIES OpenSSL::Crypto)
    check_symbol_exists("HMAC_CTX_new" "openssl/hmac.h" HAVE_HMAC_CTX_NEW)
    check_symbol_exists("HMAC_CTX_init" "openssl/hmac.h" HAVE_HMAC_CTX_INIT)
    if(HAVE_HMAC_CTX_NEW)
        message(STATUS "Switching to newer libcrypto functions (>= 1.1.0)")
        add_compile_definitions(SSLNEW)
    elseif(HAVE_HMAC_CTX_INIT)
        message(STATUS "Switching to legacy libcrypto functions (< 1.1.0)")
    else()
        message(FATAL_ERROR "OpenSSL libcrypto HMAC_CTX_* functions not found")
    endif()
endif()

# program checks
# TODO: add program checks for python3, valgrind etc.
find_package(Git)
if(Git_FOUND)
    message(STATUS "Git found at ${GIT_EXECUTABLE}")
else()
    message(WARNING "Git not found, make distclean might not work")
endif()

## end checks and configure


## recursive subdirectories
if (NOT LIBMERC_ONLY)
    add_subdirectory(asn1)
endif()
add_subdirectory(lctrie)
add_subdirectory(xsimd)

## link paths
#

## include paths
include_directories(asn1)
include_directories(lctrie)
include_directories(rapidjson)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/xsimd/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})


## libmerc source files
set(libmerc_src
    ${CMAKE_CURRENT_SOURCE_DIR}/asn1/oid.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/asn1/oid.h
    analysis.cc
    addr.cc
    dns.cc
    http.cc
    libmerc.cc
    match.cc
    pkt_proc.cc
    ssh.cc
    tls.cc
    utils.cc
    wireguard.cc
    config_generator.cc
    smb2.cc
    bencode.cc
)

# Platform-specific SIMD files
if(INTEL_PLATFORM)
    if(IS_WIN)
        list(APPEND libmerc_src
            softmax_sse2.cc
        )
        set_source_files_properties(softmax_sse2.cc PROPERTIES COMPILE_FLAGS "-msse2")
    else()
        list(APPEND libmerc_src
            softmax_sse2.cc
            softmax_avx.cc
            softmax_avx2.cc
        )
        set_source_files_properties(softmax_sse2.cc PROPERTIES COMPILE_FLAGS "-msse2")
        set_source_files_properties(softmax_avx.cc  PROPERTIES COMPILE_FLAGS "-mavx")
        set_source_files_properties(softmax_avx2.cc PROPERTIES COMPILE_FLAGS "-mavx2")
    endif()
elseif(ARM_PLATFORM)
    list(APPEND libmerc_src softmax_neon.cc)
    if(ARMV7_PLATFORM)
        set_source_files_properties(softmax_neon.cc PROPERTIES COMPILE_FLAGS "-mfpu=neon")
    endif()
endif()

## default libmerc compile options
if(IS_WIN)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        message(STATUS "Debug build")
        set(LIBMERC_COMPILE_OPT
                /std:c++17
                /Wall
                # TODO: fill up the rest of the options
                /permissive-)
    else()
        set(LIBMERC_COMPILE_OPT
            /std:c++17
            /Ot
            /O2
            /Wall
            # TODO: fill up the rest of the options
            /permissive-)
    endif()
else()
    set(LIBMERC_COMPILE_OPT
        --std=c++17
        -O3
        -Wall -Wextra -Wno-deprecated ${CDEFS} ${MSV}
        -Wno-missing-braces
        -Wno-narrowing
        -shared
        -fPIC
        -DDONT_USE_STDERR
        -fno-rtti
        -Wformat
        -Wformat-security
        -Wno-deprecated-declarations
        -Wno-long-long
        -Wmissing-noreturn
        -Wunreachable-code
        -fvisibility=hidden
        -DNDEBUG
        -fno-builtin-malloc
        -fno-builtin-calloc
        -fno-builtin-realloc
        -fno-builtin-free
)
endif()

## check compiler flags availablity
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag(-fno-gnu-unique use_no_gnu_unique)
if(use_no_gnu_unique)
    add_compile_options(-fno-gnu-unique)
else()
    message(STATUS "no support for use_no_gnu_unique")
endif()
check_cxx_compiler_flag(-fsanitize=address addr_sanitizer_avail)
if(addr_sanitizer_avail)
    message(STATUS "-fsanitize=address - supported")
else()
    message(STATUS "no address sanitizer support")
endif()

## TARGET : libmerc (shared) {
add_library(libmerc SHARED ${libmerc_src})
target_link_directories(libmerc PUBLIC lctrie ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(libmerc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${ZLIB_INCLUDE_DIRS})
target_link_libraries(libmerc PUBLIC lctrie xsimd ZLIB::ZLIB)
if(DEFINED OPENSSL_CUSTOM_LIB_DIR)
    target_link_libraries(libmerc PUBLIC crypto)
else()
    target_link_libraries(libmerc PUBLIC OpenSSL::Crypto)
endif()
add_dependencies(libmerc lctrie)
if (NOT LIBMERC_ONLY)
    add_dependencies(libmerc asn1)
endif()
target_compile_options(libmerc PUBLIC ${LIBMERC_COMPILE_OPT})
target_compile_definitions(libmerc PUBLIC -DNDEBUG -DDONT_USE_STDERR)
#target_link_options(libmerc PUBLIC  -lz -lcrypto)
#target_compile_definitions(libmerc PRIVATE SSLNEW)
set_target_properties(libmerc PROPERTIES PREFIX "")
#set_target_properties(libmerc PROPERTIES PREFIX "" OUTPUT_NAME "libmerc.so.0")
# }

## TARGET : libmerc_static (static) {
add_library(libmerc_static STATIC ${libmerc_src})
target_link_directories(libmerc_static PUBLIC lctrie ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(libmerc_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${ZLIB_INCLUDE_DIRS})
target_link_libraries(libmerc_static PUBLIC lctrie xsimd ZLIB::ZLIB)
if(DEFINED OPENSSL_CUSTOM_LIB_DIR)
    target_link_libraries(libmerc_static PUBLIC crypto)
else()
    target_link_libraries(libmerc_static PUBLIC OpenSSL::Crypto)
endif()
add_dependencies(libmerc_static lctrie)
if(NOT LIBMERC_ONLY)
    add_dependencies(libmerc_static asn1)
endif()
target_compile_options(libmerc_static PUBLIC ${LIBMERC_COMPILE_OPT})
target_compile_definitions(libmerc_static PUBLIC -DNDEBUG -DDONT_USE_STDERR)
#target_link_options(libmerc PUBLIC  -lz -lcrypto)
#target_compile_definitions(libmerc PRIVATE SSLNEW)
set_target_properties(libmerc_static PROPERTIES PREFIX "")
#set_target_properties(libmerc PROPERTIES PREFIX "" OUTPUT_NAME "libmerc.so.0")
# }

## TARGET cbor {
set(cbor_src
    ../cbor.cpp
)
add_executable(cbor ${cbor_src})
target_compile_options(cbor PUBLIC ${LIBMERC_COMPILE_OPT} -UDONT_USE_STDERR)
target_link_libraries(cbor ZLIB::ZLIB )
# }


## TARGET : distclean {
if(IS_WIN)
    set(tmp_files asn1\\Makefile asn1\\oid.cc asn1\\oid.h lctrie\\Makefile)
else()
    set(tmp_files asn1/Makefile asn1/oid.cc asn1/oid.h lctrie/Makefile)
endif()
add_custom_target(distclean
    COMMAND
        ${GIT_EXECUTABLE} clean -xfd && ${GIT_EXECUTABLE} restore ${tmp_files}
        # TODO update command for windows with
        # COMMAND cmd /c "${CMAKE_EXECUTABLE}" clean -xfd
)
# }
#set(CMAKE_OSX_ARCHITECTURES "arm64;x86_64")
#set_target_properties(libmerc_mac_o PROPERTIES CMAKE_OSX_ARCHITECTURES "arm64;x86_64")
#target_compile_options(libmerc_mac_o PUBLIC ${LIBMERC_COMPILE_OPT} "SHELL:-arch arm64" "SHELL:-arch x86_64")
#target_link_options(libmerc_mac_o PRIVATE  -lz -lcrypto "SHELL:-arch arm64" "SHELL:-arch x86_64")
# }
