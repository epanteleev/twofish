cmake_minimum_required(VERSION 3.10)

project(twofish)

#option(BUILD_SHARED_LIBS "build as shared library" ON)
#option(BUILD_TEST ON)

#if(${BUILD_TEST})
    enable_testing()
#endif()

#add_definitions(" -march=core2 -fno-align-functions -fno-align-labels -mfpmath=sse -msse4.1 -finline-functions --param l2-cache-size=512 -fomit-frame-pointer -pipe -Wno-all")



add_subdirectory(unitTest)

set(SRC keyInstance.cpp twofish.cpp)
set(INCLUDE platform.h twofish.h table.h)


add_library(${PROJECT_NAME} SHARED ${SRC} ${INCLUDE})


add_executable(run main.cpp)
target_link_libraries(run ${PROJECT_NAME} )
add_test(FirstTest run)


