cmake_minimum_required(VERSION 2.8)

project(minisign C)

option(VERIFY_ONLY "verify-only" OFF)

include(CheckLibraryExists)

find_library(LIB_SODIUM NAMES sodium REQUIRED)

add_executable(minisign
               src/minisign.c src/base64.c src/helpers.c src/get_line.c)

target_link_libraries(minisign ${LIB_SODIUM})

install(TARGETS minisign DESTINATION bin)
