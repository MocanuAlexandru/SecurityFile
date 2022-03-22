cmake_minimum_required(VERSION 3.10)

project(SecurityFile)
Set(CMAKE_CXX_STANDARD 17)

include_directories(../libraries/myLibrary)
include_directories(../libraries/sha256)
include_directories(../libraries/httplib)
file(GLOB SOURCES
        ../libraries/myLibrary/*.cpp
        ../libraries/sha256/*.cpp
        )
add_executable(SecurityFile SecurityFile.cpp ${SOURCES})

target_link_libraries(SecurityFile
        libpq.so
        libpqxx.so
        -pthread
        -Wno-main
        )
