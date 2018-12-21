cmake_minimum_required(VERSION 3.10)

project(twofish)
add_definitions(" -march=core2 -fno-align-functions -fno-align-labels -mfpmath=sse -msse4.1 -finline-functions --param l2-cache-size=512 -fomit-frame-pointer -pipe -Wno-all")
add_subdirectory(unitTests)
add_library(libtwofish SHARED keyInstance.cpp platform.h twofish.cpp twofish.h table.h)
add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} libtwofish)
