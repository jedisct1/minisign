cmake_minimum_required(VERSION 2.8)

project(minisign C)

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "minisign")
set(CPACK_PACKAGE_VENDOR "Frank Denis")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "2")
set(CPACK_PACKAGE_VERSION_PATCH "0")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")
set(CPACK_SOURCE_IGNORE_FILES "/build/;minisign.key;minisign.pub;a.out;/.git/;~$;${CPACK_SOURCE_IGNORE_FILES}")
set(CPACK_PACKAGE_EXECUTABLES "minisign" "minisign")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE MinSizeRel CACHE STRING "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel." FORCE)
endif(NOT CMAKE_BUILD_TYPE)

include(CPack)
include(CheckLibraryExists)

find_library(LIB_SODIUM NAMES sodium REQUIRED)

add_executable(minisign
               src/minisign.c src/base64.c src/helpers.c src/get_line.c)

target_link_libraries(minisign ${LIB_SODIUM})

install(TARGETS minisign DESTINATION bin)
