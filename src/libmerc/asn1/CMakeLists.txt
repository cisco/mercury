cmake_minimum_required(VERSION 3.10)
project(asn1)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set( CMAKE_VERBOSE_MAKEFILE on )

# Check for windows and set some paths to prevent VScode and other prefix appending
if (IS_WIN)
    set(CMAKE_BINARY_DIR ${CMAKE_CURRENT_SOURCE_DIR})
    set(EXECUTABLE_OUTPUT_PATH {CMAKE_CURRENT_SOURCE_DIR})
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    set(CMAKE_BUILD_FILES_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    set(CMAKE_MSVCIDE_RUN_PATH ${CMAKE_CURRENT_SOURCE_DIR})
endif()

if(IS_WIN)
    set(CMAKE_CXX_FLAGS "${CXXFLAGS} ${CMAKE_CXX_FLAGS} /std:c++17 /Wall /Ot /O2 ${OPTFLAGS}")
else()
    set(CMAKE_CXX_FLAGS "${CXXFLAGS} ${CMAKE_CXX_FLAGS} --std=c++17 -Wall -Wpedantic -Wextra -O2 ${OPTFLAGS}")
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
