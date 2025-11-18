cmake_minimum_required(VERSION 3.10)
project(asn1)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_VERBOSE_MAKEFILE ON)

# Check for windows and set some paths to prevent VScode and other prefix appending
if (IS_WIN)
    set(CMAKE_BINARY_DIR ${CMAKE_CURRENT_SOURCE_DIR})
    set(EXECUTABLE_OUTPUT_PATH {CMAKE_CURRENT_SOURCE_DIR})
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    set(CMAKE_BUILD_FILES_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    set(CMAKE_MSVCIDE_RUN_PATH ${CMAKE_CURRENT_SOURCE_DIR})
endif()

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
    add_compile_options(-Wall -Wpedantic -Wextra ${OPTFLAGS})
endif()

# Display the complete flags that will be used on the command line:
# CMake combines: CMAKE_CXX_FLAGS + CMAKE_CXX_FLAGS_<CONFIG> + target flags
if(CMAKE_BUILD_TYPE)
    string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
    message(STATUS "asn1 CMAKE_BUILD_TYPE = ${CMAKE_BUILD_TYPE}")
    message(STATUS "asn1 CMAKE_CXX_FLAGS (base) = ${CMAKE_CXX_FLAGS}")
    message(STATUS "asn1 CMAKE_CXX_FLAGS_${BUILD_TYPE_UPPER} (config) = ${CMAKE_CXX_FLAGS_${BUILD_TYPE_UPPER}}")
    message(STATUS "asn1 Combined command line flags: ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BUILD_TYPE_UPPER}}")
else()
    message(STATUS "asn1 CMAKE_BUILD_TYPE not set (using compiler defaults)")
    message(STATUS "asn1 CMAKE_CXX_FLAGS (base) = ${CMAKE_CXX_FLAGS}")
endif()

add_executable(oidc oidc.cc)

##win
#execute_process(COMMAND CMD /c echo bar OUTPUT_VARIABLE FOO)
##linux
#execute_process(COMMAND echo bar OUTPUT_VARIABLE FOO)

#set(asn_files "a" "b" "c")
file(GLOB asn1_files ${CMAKE_CURRENT_SOURCE_DIR}/*.asn1)
list(SORT asn1_files)

if (IS_WIN)
    set(oid_exec_cmd cmd /c "cd /D ${CMAKE_CURRENT_SOURCE_DIR} && $<TARGET_FILE:oidc> ${asn1_files}")
else()
    set(oid_exec_cmd oidc ${asn1_files})
endif()
add_custom_target(
        oid
    COMMAND
        ${oid_exec_cmd}
    DEPENDS
        oidc)

add_custom_target(asn1 ALL
    DEPENDS
        oid)
