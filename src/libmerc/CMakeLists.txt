cmake_minimum_required(VERSION 3.10)
project(libmerc)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set( CMAKE_VERBOSE_MAKEFILE on )
set(CMAKE_CXX_FLAGS "${CXXFLAGS} ${CFLAGS} ${CMAKE_CXX_FLAGS}")


## platform checks
message(STATUS "Platform - ${CMAKE_SYSTEM_NAME}")
message(STATUS "Architecture - ${CMAKE_SYSTEM_PROCESSOR}")

if(${CMAKE_SYSTEM_NAME} MATCHES Darwin)
    set(is_mac TRUE)
    if(${CMAKE_SYSTEM_PROCESSOR} MATCHES arm64)
        set(is_mac_arm TRUE)
    endif()
elseif(${CMAKE_SYSTEM_NAME} MATCHES Windows)
    set(is_win TRUE)
endif()

## universal mac binary
# if cmake -Dmac_arch=universal
if(NOT DEFINED mac_arch)
    message(STATUS "mac_arch - ${CMAKE_SYSTEM_PROCESSOR}")
elseif(mac_arch MATCHES universal)
    set(CMAKE_OSX_ARCHITECTURES "arm64;x86_64")
    message(STATUS "mac_arch - ${mac_arch}")
endif()

## optional lib paths
set(opt_library_path "")

## exported / cmake options
# custom openssl path
if(DEFINED openssl_path)
    link_directories(${openssl_path})
    set(custom_ssl_path "${openssl_path}")
endif()

## Platform specific paths
if(is_mac_arm)
    link_directories(/opt/homebrew/lib)
    include_directories(/opt/homebrew/include)
    set(opt_ssl_path "/opt/homebrew/lib")
endif()

## checks and configure
# headers
INCLUDE(CheckIncludeFiles)
CHECK_INCLUDE_FILES(linux/if_packet.h  HAVE_IF_PACKET_H)
CHECK_INCLUDE_FILES(arpa/inet.h        HAVE_INET_H)
CHECK_INCLUDE_FILES(fcntl.h            HAVE_FCNTL_H)
CHECK_INCLUDE_FILES(stddef.h           HAVE_STDDEF_H)
CHECK_INCLUDE_FILES(sys/ioctl.h        HAVE_IOCTL_H)
CHECK_INCLUDE_FILES(sys/socket.h       HAVE_SOCKET_H)
CHECK_INCLUDE_FILES(sys/time.h         HAVE_TIME_H)
CHECK_INCLUDE_FILES(x86intrin.h        HAVE_X86INTRIN_H)
if(${HAVE_X86INTRIN_H})
    add_compile_definitions(HAVE_X86INTRIN_H=1)
endif()
CHECK_INCLUDE_FILES(zlib.h             HAVE_ZLIB_H)
if(NOT ${HAVE_ZLIB_H})
    message(FATAL_ERROR "A working zlib is required")
endif()

# functions
INCLUDE(CheckFunctionExists)
CHECK_FUNCTION_EXISTS(gettimeofday    HAVE_GETTIMEOFDAY)
CHECK_FUNCTION_EXISTS(memset          HAVE_MEMSET)
CHECK_FUNCTION_EXISTS(mkdir           HAVE_MKDIR)
CHECK_FUNCTION_EXISTS(munmap          HAVE_MUNMAP)
CHECK_FUNCTION_EXISTS(socket          HAVE_SOCKET)
CHECK_FUNCTION_EXISTS(strerror        HAVE_STRERROR)
CHECK_FUNCTION_EXISTS(strtol          HAVE_STRTOL)
CHECK_FUNCTION_EXISTS(malloc          HAVE_MALLOC)
CHECK_FUNCTION_EXISTS(mmap            HAVE_MMAP)

# type checks
INCLUDE(CheckTypeSize)
CHECK_TYPE_SIZE("int32_t"    SIZE_INT32_T)
CHECK_TYPE_SIZE("int64_t"    SIZE_INT64_T)
CHECK_TYPE_SIZE("pid_t"      SIZE_PID_T)
CHECK_TYPE_SIZE("size_t"     SIZE_SIZE_T)
CHECK_TYPE_SIZE("ssize_t"    SIZE_SSIZE_T)
CHECK_TYPE_SIZE("uid_t"      SIZE_UID_T)
CHECK_TYPE_SIZE("uint16_t"   SIZE_UINT16_T) 
CHECK_TYPE_SIZE("uint32_t"   SIZE_UIN32_T) 
CHECK_TYPE_SIZE("uint64_t"   SIZE_UINT64_T) 
CHECK_TYPE_SIZE("uint8_t"    SIZE_UINT8_T)
CHECK_TYPE_SIZE("ptrdiff_t"  SIZE_PTRDIFF_T)

# check symbol
INCLUDE (CheckSymbolExists)
#CHECK_SYMBOL_EXISTS("ptrdiff_t" "cstddef.h;stddef.h" HAVE_PTRDIFF_T)

# library checks
INCLUDE (CheckLibraryExists)

CHECK_LIBRARY_EXISTS(z deflate "" HAVE_ZLIB)
if(NOT HAVE_ZLIB)
    message(FATAL_ERROR "A working zlib is required")
endif()

# libcrypto checks
# precedence to custom crypto path
if(DEFINED openssl_path)
    CHECK_LIBRARY_EXISTS(crypto HMAC_CTX_new "${custom_ssl_path}" HAVE_CUSTOM_CRYPTO_NEW)
    CHECK_LIBRARY_EXISTS(crypto HMAC_CTX_init "${custom_ssl_path}" HAVE_CUSTOM_CRYPTO_OLD)
elseif(is_mac_arm)
    CHECK_LIBRARY_EXISTS(crypto HMAC_CTX_new "${opt_ssl_path}" HAVE_ARM_CRYPTO_NEW)
    CHECK_LIBRARY_EXISTS(crypto HMAC_CTX_init "${opt_ssl_path}" HAVE_ARM_CRYPTO_OLD)
else()
    CHECK_LIBRARY_EXISTS(crypto HMAC_CTX_new "" HAVE_CRYPTO_NEW)
    CHECK_LIBRARY_EXISTS(crypto HMAC_CTX_init "" HAVE_CRYPTO_OLD)
endif()

if(HAVE_CRYPTO_NEW OR HAVE_CUSTOM_CRYPTO_NEW OR HAVE_ARM_CRYPTO_NEW)
    message(STATUS "Switching to new libcrypto functions")
    add_compile_definitions(-DSSLNEW)
elseif(HAVE_CRYPTO_OLD OR HAVE_CUSTOM_CRYPTO_OLD OR HAVE_ARM_CRYPTO_OLD)
    message(STATUS "Switching to legacy libcrypto functions")
else()
    message(FATAL_ERROR "libcrypto not found")
endif()

# program checks
# TODO: add program checks for python3, valngrind etc.

## end checks and configure


## recursive subdirectories
add_subdirectory(asn1)
add_subdirectory(lctrie)


## link paths
#

## include paths
include_directories(asn1)
include_directories(lctrie)
include_directories(rapidjson)


## libmerc source files
set(libmerc_src 
    ${CMAKE_CURRENT_SOURCE_DIR}/asn1/oid.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/asn1/oidc.h
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
    asn1.cc
    config_generator.cc
    smb2.cc
    bencode.cc
)

## default libmerc compile options
set(libmerc_compile_opt
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

## check compiler flags availablity
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG(-fno-gnu-unique use_no_gnu_unique)
if(use_no_gnu_unique)
    add_compile_options(-fno-gnu-unique)
else()
    message(STATUS "no support for use_no_gnu_unique") 
endif()
CHECK_CXX_COMPILER_FLAG(-fsanitize=address addr_sanitizer_avail)
if(addr_sanitizer_avail)
    message(STATUS "-fsanitize=address - supported")
else()
    message(STATUS "no address sanitizer support") 
endif()

## TARGET : libmerc {
add_library(libmerc SHARED ${libmerc_src})
target_link_directories(libmerc PUBLIC lctrie)
target_link_libraries(libmerc PUBLIC lctrie)
add_dependencies(libmerc lctrie asn1)
target_compile_options(libmerc PUBLIC ${libmerc_compile_opt})
target_link_options(libmerc PRIVATE  -lz -lcrypto)
target_compile_definitions(libmerc PRIVATE -DSSLNEW)
# }

#set(CMAKE_OSX_ARCHITECTURES "arm64;x86_64")
#set_target_properties(libmerc_mac_o PROPERTIES CMAKE_OSX_ARCHITECTURES "arm64;x86_64")
#target_compile_options(libmerc_mac_o PUBLIC ${libmerc_compile_opt} "SHELL:-arch arm64" "SHELL:-arch x86_64")
#target_link_options(libmerc_mac_o PRIVATE  -lz -lcrypto "SHELL:-arch arm64" "SHELL:-arch x86_64")
# }