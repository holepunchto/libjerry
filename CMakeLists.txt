cmake_minimum_required(VERSION 3.25)

find_package(cmake-fetch REQUIRED PATHS node_modules/cmake-fetch)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

project(js C)

add_library(v8 INTERFACE)
add_library(c++ INTERFACE)
add_library(js OBJECT)

fetch_package("github:holepunchto/libjs" SOURCE_DIR js)
fetch_package("github:holepunchto/libpath")
fetch_package("github:holepunchto/libintrusive")

set(JERRY_EXTERNAL_CONTEXT ON CACHE BOOL "Enable external context support" FORCE)
set(JERRY_FUNCTION_TO_STRING ON CACHE BOOL "Enable function.toString() support" FORCE)
set(JERRY_PROMISE_CALLBACK ON CACHE BOOL "Enable promise event callback support" FORCE)
set(JERRY_ERROR_MESSAGES ON CACHE BOOL "Enable error message support" FORCE)
set(JERRY_CPOINTER_32_BIT ON CACHE BOOL "Enable 32-bit pointer support" FORCE)
set(JERRY_MEM_STATS ON CACHE BOOL "Enable memory statistics support" FORCE)
set(JERRY_LINE_INFO ON CACHE BOOL "Enable stacktrace support" FORCE)

fetch_package("github:jerryscript-project/jerryscript@3.0.0")

set_target_properties(
  js
  PROPERTIES
  C_STANDARD 99
  POSITION_INDEPENDENT_CODE ON
)

target_sources(
  js
  PRIVATE
    src/js.c
)

target_include_directories(
  js
  INTERFACE
    include
  PUBLIC
    ${js}/include
  PRIVATE
    $<TARGET_PROPERTY:jerry-core,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:uv,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:utf,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:path,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:intrusive,INTERFACE_INCLUDE_DIRECTORIES>
)

add_library(js_shared SHARED)

set_target_properties(
  js_shared
  PROPERTIES
  OUTPUT_NAME js
  WINDOWS_EXPORT_ALL_SYMBOLS ON
)

target_sources(
  js_shared
  PRIVATE
    $<TARGET_OBJECTS:jerry-core>
)

target_link_libraries(
  js_shared
  PUBLIC
    jerry-core
    uv
    utf_shared
    path_shared
  PRIVATE
    js
)

add_library(js_static STATIC)

set_target_properties(
  js_static
  PROPERTIES
  OUTPUT_NAME js
  PREFIX lib
)

target_sources(
  js_static
  PRIVATE
    $<TARGET_OBJECTS:jerry-core>
)

target_link_libraries(
  js_static
  PUBLIC
    jerry-core
    uv_a
    utf_static
    path_static
  PRIVATE
    js
)

install(TARGETS js_shared js_static)

if(PROJECT_IS_TOP_LEVEL)
  enable_testing()

  add_subdirectory(test)
endif()
