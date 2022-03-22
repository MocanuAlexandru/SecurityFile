cmake_minimum_required(VERSION 3.10)
project(sfile)

set(CMAKE_CXX_STANDARD 17)

add_executable(sfile sfile.cpp
              ../libraries/sha256/sha256.cpp ../libraries/sha256/sha256.h)
include_directories(../libraries/httplib)
include_directories(../libraries/sha256)
target_link_libraries(sfile -Wno-main)
