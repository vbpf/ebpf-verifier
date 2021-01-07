# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT
cmake_minimum_required(VERSION 3.10)
project(ebpf_verifier)

if (IS_DIRECTORY "${PROJECT_SOURCE_DIR}/.git")
  # Install Git pre-commit hook
  file(COPY scripts/pre-commit scripts/commit-msg
       DESTINATION "${PROJECT_SOURCE_DIR}/.git/hooks")
endif ()

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR
    "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  set(CMAKE_CXX_STANDARD 17)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
  # MSVC's C++17 standard option doesn't actually support all the C++17
  # features we use, but its "latest" option does.  However, cmake can't
  # deal with that here, so we set it below.
endif()

find_package(Boost REQUIRED)

option(USE_GMP "Use GMP for multiprecision integer support")

include_directories(./external)
include_directories(./src)
include_directories(${Boost_INCLUDE_DIRS})
link_directories(${Boost_LIBRARY_DIRS})

if (USE_GMP)
  find_library(GMP REQUIRED)
  include_directories(${GMP_LIB_INCLUDE_DIRS})
  link_directories(${GMP_LIB_LIBRARY_DIRS})
endif ()

file(GLOB LIB_SRC
        "./src/*.cpp"
        "./src/gpl/*.cpp"
        "./src/crab/*.cpp"
        "./src/crab_utils/*.cpp"
        )

file(GLOB ALL_TEST
        "./src/test/*.cpp"
        )

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR
    "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  set(COMMON_FLAGS -Wall -Wfatal-errors -DSIZEOF_VOID_P=8 -DSIZEOF_LONG=8)
  set(DEBUG_FLAGS -O0 -g3)
  set(RELEASE_FLAGS -O2 -flto)
  set(SANITIZE_FLAGS -fsanitize=address -O1 -fno-omit-frame-pointer)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++latest")
endif ()

if (USE_GMP)
  set(COMMON_FLAGS ${COMMON_FLAGS} -DBIGNUMS_GMP)
endif()

add_library(ebpfverifier ${LIB_SRC})
add_executable(check src/main/check.cpp src/main/linux_verifier.cpp)
add_executable(tests ${ALL_TEST})

set_target_properties(check
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/..")

set_target_properties(tests
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/..")

target_compile_options(ebpfverifier PRIVATE ${COMMON_FLAGS})
target_compile_options(ebpfverifier PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_FLAGS}>")
target_compile_options(ebpfverifier PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_FLAGS}>")
target_compile_options(ebpfverifier PUBLIC "$<$<CONFIG:SANITIZE>:${SANITIZE_FLAGS}>")

target_compile_options(check PRIVATE ${COMMON_FLAGS})
target_compile_options(check PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_FLAGS}>")
target_compile_options(check PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_FLAGS}>")
target_compile_options(check PUBLIC "$<$<CONFIG:SANITIZE>:${SANITIZE_FLAGS}>")
target_link_libraries(check PRIVATE ebpfverifier)

if (USE_GMP)
  target_link_libraries(check PRIVATE gmp)
endif()

target_compile_options(tests PRIVATE ${COMMON_FLAGS})
target_compile_options(tests PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_FLAGS}>")
target_compile_options(tests PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_FLAGS}>")
target_compile_options(tests PUBLIC "$<$<CONFIG:SANITIZE>:${SANITIZE_FLAGS}>")
target_link_libraries(tests PRIVATE ebpfverifier)

if (USE_GMP)
  target_link_libraries(tests PRIVATE gmp)
endif()
