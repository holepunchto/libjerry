cmake_minimum_required(VERSION 4.0)

find_package(cmake-fetch REQUIRED PATHS node_modules/cmake-fetch)
find_package(cmake-prelude REQUIRED PATHS node_modules/cmake-prelude)
find_package(cmake-test REQUIRED PATHS node_modules/cmake-test)

project(js LANGUAGES C VERSION 0.0.0)

set(JERRY_EXTERNAL_CONTEXT ON CACHE BOOL "Enable external context support" FORCE)
set(JERRY_FUNCTION_TO_STRING ON CACHE BOOL "Enable function.toString() support" FORCE)
set(JERRY_SNAPSHOT_SAVE ON CACHE BOOL "Enable saving snapshots" FORCE)
set(JERRY_SNAPSHOT_EXEC ON CACHE BOOL "Enable executing snapshots" FORCE)
set(JERRY_PROMISE_CALLBACK ON CACHE BOOL "Enable promise event callback support" FORCE)
set(JERRY_ERROR_MESSAGES ON CACHE BOOL "Enable error message support" FORCE)
set(JERRY_CPOINTER_32_BIT ON CACHE BOOL "Enable 32-bit pointer support" FORCE)
set(JERRY_MEM_STATS ON CACHE BOOL "Enable memory statistics support" FORCE)

fetch_package("github:holepunchto/libpath")
fetch_package("github:holepunchto/libintrusive")

fetch_package(
  "github:jerryscript-project/jerryscript@3.0.0"
  PATCHES
    patches/01-remove-deprecated-enum-conversions.patch
    patches/02-remove-archive-variables.patch
    patches/03-fix-unterminated-string-initialization.patch
    patches/04-support-symbols-as-weak-keys.patch
    patches/05-propagate-exceptions-from-delete.patch
    patches/06-arraybuffer-user-data.patch
)

add_library_targets(
  js
  FEATURES
    c_std_99
  SOURCES
    src/js.c
  LINK
    utf::<TYPE>
    PRIVATE
      path::<TYPE>
      intrusive::headers
    EMBED
      jerry-core
    STATIC
      uv_a
    SHARED
      uv
  EXPORT OFF
)

fetch_package("github:holepunchto/libjs" SOURCE_DIR js)

add_test_subdirectory(test)
