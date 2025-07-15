cmake_minimum_required(VERSION 3.10)
project(lctrie)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set( CMAKE_VERBOSE_MAKEFILE on )
if(is_win)
    # no need of -fPIC
    set(CMAKE_CXX_FLAGS "${CXXFLAGS} ${CFLAGS} ${CMAKE_CXX_FLAGS} /std:c++17 /Wall /Ot /O2 ${OPTFLAGS}")
else()
    set(CMAKE_CXX_FLAGS "${CXXFLAGS} ${CFLAGS} ${CMAKE_CXX_FLAGS} --std=c++17 -Wall -Wpedantic -Wextra -g -ggdb -Wall -O3 -fPIC ${OPTFLAGS}")
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