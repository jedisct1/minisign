cmake_minimum_required(VERSION 2.8)

project(minisign C)

include(CheckLibraryExists)

IF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE MinSizeRel CACHE STRING "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel." FORCE)
ENDIF(NOT CMAKE_BUILD_TYPE)

find_library(LIB_SODIUM NAMES sodium REQUIRED)

add_executable(minisign
               src/minisign.c src/base64.c src/helpers.c src/get_line.c)

target_link_libraries(minisign ${LIB_SODIUM})

install(TARGETS minisign DESTINATION bin)
