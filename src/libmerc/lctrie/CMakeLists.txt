cmake_minimum_required(VERSION 3.12)
project(lctrie)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_EXTENSIONS OFF)  # c++17 not gnu++17
set(CMAKE_VERBOSE_MAKEFILE ON)

# CMake automatically adds optimization and debug flags based on CMAKE_BUILD_TYPE.
# Typical values for CMAKE_BUILD_TYPE: Debug, Release, RelWithDebInfo, MinSizeRel.
# These flags are added to CMAKE_CXX_FLAGS_<CONFIG> variables:
#   Windows (MSVC):
#     CMAKE_CXX_FLAGS_DEBUG: /MDd /Zi /Ob0 /Od /RTC1 (no optimization, runtime checks)
#     CMAKE_CXX_FLAGS_RELEASE: /MD /O2 /Ob2 /DNDEBUG (optimize for speed)
#     CMAKE_CXX_FLAGS_RELWITHDEBINFO: /MD /Zi /O2 /Ob1 /DNDEBUG (optimize with debug symbols)
#     CMAKE_CXX_FLAGS_MINSIZEREL: /MD /O1 /Ob1 /DNDEBUG (optimize for size)
#   Linux/Mac (GCC/Clang):
#     CMAKE_CXX_FLAGS_DEBUG: -g (debug symbols only)
#     CMAKE_CXX_FLAGS_RELEASE: -O3 -DNDEBUG (aggressive optimization)
#     CMAKE_CXX_FLAGS_RELWITHDEBINFO: -O2 -g -DNDEBUG (optimize with debug symbols)
#     CMAKE_CXX_FLAGS_MINSIZEREL: -Os -DNDEBUG (optimize for size)

if(IS_WIN)
    add_compile_options(/W3 ${OPTFLAGS})
else()
    add_compile_options(-Wall -Wpedantic -Wextra -fPIC ${OPTFLAGS})
endif()

# Display the complete flags that will be used on the command line:
# CMake combines: CMAKE_CXX_FLAGS + CMAKE_CXX_FLAGS_<CONFIG> + target flags
if(CMAKE_BUILD_TYPE)
    string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
    message(STATUS "lctrie CMAKE_BUILD_TYPE = ${CMAKE_BUILD_TYPE}")
    message(STATUS "lctrie CMAKE_CXX_FLAGS (base) = ${CMAKE_CXX_FLAGS}")
    message(STATUS "lctrie CMAKE_CXX_FLAGS_${BUILD_TYPE_UPPER} (config) = ${CMAKE_CXX_FLAGS_${BUILD_TYPE_UPPER}}")
    message(STATUS "lctrie Combined command line flags: ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BUILD_TYPE_UPPER}}")
else()
    message(STATUS "lctrie CMAKE_BUILD_TYPE not set (using compiler defaults)")
    message(STATUS "lctrie CMAKE_CXX_FLAGS (base) = ${CMAKE_CXX_FLAGS}")
endif()

set(lctrie_src
    lctrie.c
    lctrie_bgp.c
    lctrie_ip.c)
set_source_files_properties(${lctrie_src} PROPERTIES LANGUAGE CXX)
add_library(lctrie STATIC ${lctrie_src})

set(lctrie_test_src
    ${lctrie_src}
    lctrie_test.c)
set_source_files_properties(${lctrie_test_src} PROPERTIES LANGUAGE CXX)
#add_executable(lctrie_test ${lctrie_test_src})

# the depends section might not work as it takes src not targets
# use add_dependency() instead
add_custom_target(lctrie_lib
    DEPENDS
        lctrie)
