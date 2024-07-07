cmake_minimum_required(VERSION 3.10)
project(asn1)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set( CMAKE_VERBOSE_MAKEFILE on )
set(CMAKE_CXX_FLAGS "${CXXFLAGS} ${CMAKE_CXX_FLAGS} --std=c++17 -Wall -Wpedantic -Wextra -O2 ${OPTFLAGS}")

add_executable(oidc oidc.cc)

##win
#execute_process(COMMAND CMD /c echo bar OUTPUT_VARIABLE FOO)
##linux
#execute_process(COMMAND echo bar OUTPUT_VARIABLE FOO)

#set(asn_files "a" "b" "c")
file(GLOB asn1_files ${CMAKE_CURRENT_SOURCE_DIR}/*.asn1)
list(SORT asn1_files)

add_custom_command(OUTPUT 
        oidc.h
    COMMAND
        #${CMAKE_COMMAND} -E oidc ${${CMAKE_COMMAND} -E sort ${${CMAKE_COMMAND} -E ls *.asn1}}
        #${CMAKE_COMMAND} -E ./oidc 
        oidc ${asn1_files} 
    DEPENDS
        oidc)

add_custom_target(asn1 ALL
    DEPENDS
        oidc.h)