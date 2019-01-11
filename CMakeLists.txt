cmake_minimum_required(VERSION 3.10)

project(twofish)

set(CMAKE_CXX_STANDARD 17)

option(TWOFISH_SHARED_LIB "build as shared library" OFF)
option(UNIT_TEST_BUILD "build unit tests" ON)

enable_testing()

file(COPY tests/ DESTINATION test/)

if(UNIT_TEST_BUILD)
    add_subdirectory(unitTest)
endif(UNIT_TEST_BUILD)

set(SRC keyInstance.cpp twofish.cpp)
set(TWOFISH_INCLUDE platform.h twofish.h table.h)

if(TWOFISH_SHARED_LIB)
    add_library(${PROJECT_NAME} SHARED ${SRC} ${TWOFISH_INCLUDE})
else()
    add_library(${PROJECT_NAME} STATIC ${SRC} ${TWOFISH_INCLUDE})
endif(TWOFISH_SHARED_LIB)

unset(UNIT_TEST_BUILD CACHE)

add_executable(run main.cpp)
target_link_libraries(run ${PROJECT_NAME} )
add_test(FirstTest run)
