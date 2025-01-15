cmake_minimum_required(VERSION 3.10)

project(minisign C)

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "minisign")
set(CPACK_PACKAGE_VENDOR "Frank Denis")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "12")
set(CPACK_PACKAGE_VERSION_PATCH "0")
set(
  CPACK_SOURCE_PACKAGE_FILE_NAME
  "${CMAKE_PROJECT_NAME}-${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}"
  )
set(
  CPACK_SOURCE_IGNORE_FILES
  "/build/;minisign.key;minisign.pub;a.out;/.git/;~$;${CPACK_SOURCE_IGNORE_FILES}"
  )
set(CPACK_PACKAGE_EXECUTABLES "minisign" "minisign")

if(NOT CMAKE_BUILD_TYPE)
  set(
    CMAKE_BUILD_TYPE
    MinSizeRel
    CACHE
      STRING
      "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
      FORCE)
endif(NOT CMAKE_BUILD_TYPE)

include(CPack)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_ALL_SOURCE -D_GNU_SOURCE")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
if(BUILD_STATIC_EXECUTABLES)
  set(STATIC_LIBSODIUM on)
  if (NOT APPLE)
    set(CMAKE_EXE_LINKER_FLAGS -static)
  endif (NOT APPLE)
endif(BUILD_STATIC_EXECUTABLES)

add_executable(minisign
               src/base64.c
               src/get_line.c
               src/helpers.c
               src/minisign.c)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSODIUM libsodium)

if(STATIC_LIBSODIUM)
  if(BUILD_STATIC_EXECUTABLES)
    set_target_properties(minisign PROPERTIES LINK_SEARCH_START_STATIC 1)
    set_target_properties(minisign PROPERTIES LINK_SEARCH_END_STATIC 1)
  endif()
  set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
endif()

find_path(SODIUM_INCLUDE_DIR sodium.h HINTS ${LIBSODIUM_INCLUDE_DIRS} /usr/local/include /opt/local/include /opt/include)
find_library(SODIUM_LIBRARY NAMES sodium HINTS ${LIBSODIUM_LIBRARY_DIRS} /usr/local/lib /opt/local/lib /opt/lib)

if(STATIC_LIBSODIUM)
  set(LIBSODIUM_CFLAGS_OTHER ${LIBSODIUM_STATIC_CFLAGS_OTHER})
  set(LIBSODIUM_LDFLAGS_OTHER ${LIBSODIUM_STATIC_LDFLAGS_OTHER})
endif()

target_include_directories(minisign PUBLIC ${SODIUM_INCLUDE_DIR})
target_compile_options(minisign PUBLIC ${LIBSODIUM_CFLAGS} ${LIBSODIUM_CFLAGS_OTHER})
target_link_libraries(minisign ${SODIUM_LIBRARY} ${LIBSODIUM_LDFLAGS_OTHER})

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
if(THREADS_HAVE_PTHREAD_ARG)
  target_compile_options(minisign PUBLIC "-pthread")
endif(THREADS_HAVE_PTHREAD_ARG)
if(CMAKE_THREAD_LIBS_INIT)
  target_link_libraries(minisign "${CMAKE_THREAD_LIBS_INIT}")
endif(CMAKE_THREAD_LIBS_INIT)

if (NOT MSVC AND CMAKE_STRIP)
  add_custom_command(TARGET minisign POST_BUILD
    COMMAND ${CMAKE_STRIP} ${STRIP_FLAGS} $<TARGET_FILE:minisign>)
endif(NOT MSVC AND CMAKE_STRIP)

install(TARGETS minisign DESTINATION bin)

include(GNUInstallDirs)

install(FILES "share/man/man1/minisign.1"
        DESTINATION "${CMAKE_INSTALL_MANDIR}/man1"
        COMPONENT doc)
