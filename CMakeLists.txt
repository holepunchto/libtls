cmake_minimum_required(VERSION 3.25)

project(tls C CXX)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

if(NOT TARGET ssl)
  if(MSVC)
    set(OPENSSL_NO_ASM ON)
  endif()

  add_subdirectory(vendor/boringssl EXCLUDE_FROM_ALL)
endif()

add_library(tls OBJECT)

set_target_properties(
  tls
  PROPERTIES
  C_STANDARD 99
  POSITION_INDEPENDENT_CODE ON
)

target_sources(
  tls
  INTERFACE
    include/tls.h
  PRIVATE
    src/tls.c
)

target_include_directories(
  tls
  PUBLIC
    include
)

target_link_libraries(
  tls
  PUBLIC
    ssl
)

add_library(tls_shared SHARED)

set_target_properties(
  tls_shared
  PROPERTIES
  OUTPUT_NAME tls
  WINDOWS_EXPORT_ALL_SYMBOLS ON
)

target_link_libraries(
  tls_shared
  PUBLIC
    tls
)

add_library(tls_static STATIC)

set_target_properties(
  tls_static
  PROPERTIES
  OUTPUT_NAME tls
  PREFIX lib
)

target_link_libraries(
  tls_static
  PUBLIC
    tls
)

install(TARGETS tls_shared tls_static)

install(FILES include/tls.h DESTINATION include)

if(PROJECT_IS_TOP_LEVEL)
  enable_testing()

  add_subdirectory(test)
endif()
