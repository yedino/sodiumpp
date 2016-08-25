cmake_minimum_required (VERSION 2.6)
project (sodiumpp)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -g")

if(CYGWIN)
	add_definitions(-D_GLIBCXX_USE_CXX11_ABI=0)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(Sodium REQUIRED)

include_directories(SYSTEM
    ${SODIUM_INCLUDE_DIR}
)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/sodiumpp/include
)

set(cxx-sources
    sodiumpp/sodiumpp.cpp
    sodiumpp/z85/z85.c
    sodiumpp/z85/z85_impl.cpp
    sodiumpp/locked_string.cpp
)

file(GLOB cxx-headers
    "${CMAKE_CURRENT_SOURCE_DIR}/sodiumpp/include/*.h"
)

set(MODULE_NAME sodiumpp)

if(SODIUMPP_STATIC)
    add_library(${MODULE_NAME} STATIC ${cxx-sources} ${cxx-headers})
else()
    add_library(${MODULE_NAME} SHARED ${cxx-sources} ${cxx-headers})
endif()

target_link_libraries(sodiumpp
    PUBLIC
    ${SODIUM_LIBRARY}
)

if(SODIUMPP_EXAMPLE)
    add_executable(example sodiumpp/example.cpp)
    target_link_libraries(example ${MODULE_NAME} ${SODIUMLIB})
endif()

if(SODIUMPP_TEST)
    add_executable(tests sodiumpp/test.cpp)
    target_link_libraries(tests ${MODULE_NAME} ${SODIUMLIB})
endif()

install(DIRECTORY sodiumpp/include/sodiumpp DESTINATION include)
install_targets(/lib ${MODULE_NAME})
