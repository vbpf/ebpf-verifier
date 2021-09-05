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
  find_package(Boost REQUIRED)
  set(CMAKE_CXX_STANDARD 17)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
  find_program(NUGET nuget)
  if (NOT NUGET)
    message("ERROR: You must first install nuget.exe from https://www.nuget.org/downloads")
  else ()
    exec_program(${NUGET} ARGS install "Boost" -Version 1.75.0 -ExcludeVersion -OutputDirectory ${CMAKE_BINARY_DIR}/packages)
  endif()
  set(Boost_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/packages/boost/lib/native/include)

  # MSVC's C++17 standard option doesn't actually support all the C++17
  # features we use, but its "latest" option does.  However, cmake can't
  # deal with that here, so we set it below.
endif ()

include_directories(./external)
include_directories(./external/ELFIO)
include_directories(./src)
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${YAML_CPP_INCLUDE_DIRS})
link_directories(${Boost_LIBRARY_DIRS})

find_package(yaml-cpp REQUIRED)

file(GLOB LIB_SRC
        "./src/*.cpp"
        "./src/crab/*.cpp"
        "./src/crab_utils/*.cpp"
        "./src/linux/gpl/*.cpp"
        "./src/linux/linux_platform.cpp"
        )

file(GLOB ALL_TEST
        "./src/test/test.cpp"
        "./src/test/test_loop.cpp"
        "./src/test/test_marshal.cpp"
        "./src/test/test_termination.cpp"
        "./src/test/test_verify.cpp"
        "./src/test/test_yaml.cpp"
        )

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR
    "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  set(COMMON_FLAGS -Wall -Wfatal-errors -DSIZEOF_VOID_P=8 -DSIZEOF_LONG=8)

  set(RELEASE_FLAGS -O2 -flto -ffat-lto-objects)

  set(DEBUG_FLAGS -O0 -g3 -fno-omit-frame-pointer)

  set(SANITIZE_FLAGS -fsanitize=address -O1 -fno-omit-frame-pointer)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++latest")
endif ()

add_library(ebpfverifier ${LIB_SRC})
add_executable(check src/main/check.cpp src/main/linux_verifier.cpp)
add_executable(tests ${ALL_TEST})
add_executable(run_yaml src/main/run_yaml.cpp)

set_target_properties(check
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/..")

set_target_properties(tests
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/..")

set_target_properties(run_yaml
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/..")

target_compile_options(ebpfverifier PRIVATE ${COMMON_FLAGS})
target_compile_options(ebpfverifier PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_FLAGS}>")
target_compile_options(ebpfverifier PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_FLAGS}>")
target_compile_options(ebpfverifier PUBLIC "$<$<CONFIG:SANITIZE>:${SANITIZE_FLAGS}>")

set_property(TARGET ebpfverifier PROPERTY VS_PACKAGE_REFERENCES "Boost_1.75.5")

# CMake derives a Visual Studio project GUID from the file path but can be overridden via a property
# (see https://gitlab.kitware.com/cmake/cmake/-/commit/c85367f4).  Using a non-constant GUID
# can cause problems if other projects/repos want to reference the ebpfverifier vcxproj file,
# so we force a constant GUID here.
set(ebpfverifier_GUID_CMAKE "7d5b4e68-c0fa-3f86-9405-f6400219b440" CACHE INTERNAL "Project GUID")

target_compile_options(check PRIVATE ${COMMON_FLAGS})
target_compile_options(check PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_FLAGS}>")
target_compile_options(check PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_FLAGS}>")
target_compile_options(check PUBLIC "$<$<CONFIG:SANITIZE>:${SANITIZE_FLAGS}>")
target_link_libraries(check PRIVATE ebpfverifier)

target_compile_options(tests PRIVATE ${COMMON_FLAGS})
target_compile_options(tests PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_FLAGS}>")
target_compile_options(tests PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_FLAGS}>")
target_compile_options(tests PUBLIC "$<$<CONFIG:SANITIZE>:${SANITIZE_FLAGS}>")
target_link_libraries(tests PRIVATE ebpfverifier)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

target_link_libraries(tests PRIVATE Threads::Threads)

target_link_libraries(ebpfverifier PRIVATE ${YAML_CPP_LIBRARIES})
target_compile_options(ebpfverifier PRIVATE ${COMMON_FLAGS})

target_link_libraries(run_yaml PRIVATE ebpfverifier)
