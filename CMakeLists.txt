# Copyright (c) Prevail Verifier contributors.
# SPDX-License-Identifier: MIT
cmake_minimum_required(VERSION 3.10)
project(ebpf_verifier)

include(FetchContent)
FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        ac93f1943762f6fc92f0dc5bac0d720a33a27530
)
FetchContent_MakeAvailable(Catch2)

if (IS_DIRECTORY "${PROJECT_SOURCE_DIR}/.git")
  # Install Git pre-commit hook
  file(COPY scripts/pre-commit scripts/commit-msg
       DESTINATION "${PROJECT_SOURCE_DIR}/.git/hooks")
endif ()

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR
    "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
  find_package(yaml-cpp REQUIRED)
  find_package(Boost REQUIRED)
  set(CMAKE_CXX_STANDARD 20)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
  list(APPEND CMAKE_CONFIGURATION_TYPES FuzzerDebug)
  list(REMOVE_DUPLICATES CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_CONFIGURATION_TYPES "${CMAKE_CONFIGURATION_TYPES}" CACHE STRING
      "Add the configurations that we need"
      FORCE)
  set(CMAKE_EXE_LINKER_FLAGS_FUZZERDEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG}")
  set(CMAKE_SHARED_LINKER_FLAGS_FUZZERDEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG}")
  set(CMAKE_C_FLAGS_FUZZERDEBUG "${CMAKE_C_FLAGS_DEBUG} /fsanitize-coverage=inline-bool-flag /fsanitize-coverage=edge /fsanitize-coverage=trace-cmp /fsanitize-coverage=trace-div /ZH:SHA_256")
  set(CMAKE_CXX_FLAGS_FUZZERDEBUG "${CMAKE_CXX_FLAGS_DEBUG} /fsanitize-coverage=inline-bool-flag /fsanitize-coverage=edge /fsanitize-coverage=trace-cmp /fsanitize-coverage=trace-div /ZH:SHA_256")

  find_program(NUGET nuget)
  if (NOT NUGET)
    message("ERROR: You must first install nuget.exe from https://www.nuget.org/downloads")
  else ()
    execute_process(COMMAND ${NUGET} ARGS install "Boost" -Version 1.81.0 -ExcludeVersion -OutputDirectory ${CMAKE_BINARY_DIR}/packages)
    set(BOOST_VERSION 1.81.0)
  endif()
  set(Boost_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/packages/boost/lib/native/include)
  set(Boost_LIBRARY_DIRS ${CMAKE_BINARY_DIR}/packages/boost_filesystem-vc143/lib/native)

  # MSVC's "std:c++20" option is the current standard that supports all the C++17
  # features we use. However, cmake can't deal with that here, so we set it below.

  set(EXTERNAL_INSTALL_LOCATION ${CMAKE_BINARY_DIR}/packages/yaml-cpp)
  include(ExternalProject)
  ExternalProject_Add(yaml-cpp
          GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
          GIT_TAG "yaml-cpp-0.7.0"
          GIT_SHALLOW true
          CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${EXTERNAL_INSTALL_LOCATION}
                     -DYAML_MSVC_SHARED_RT=ON
                     -DYAML_CPP_BUILD_TESTS=OFF
                     -DYAML_CPP_BUILD_TOOLS=OFF
          )
  set(YAML_CPP_LIBRARIES ${EXTERNAL_INSTALL_LOCATION}/lib/yaml-cpp$<$<CONFIG:DEBUG>:d>.lib)
  set(YAML_CPP_INCLUDE_DIRS ${EXTERNAL_INSTALL_LOCATION}/include/)
endif ()

include_directories(./external)
include_directories(./external/ELFIO)
include_directories(./src)
include_directories(./external/libbtf)
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${YAML_CPP_INCLUDE_DIRS})
link_directories(${Boost_LIBRARY_DIRS})

file(GLOB LIB_SRC
        "./src/*.cpp"
        "./src/crab/*.cpp"
        "./src/crab_utils/*.cpp"
        "./src/linux/gpl/*.cpp"
        "./src/linux/linux_platform.cpp"
        )

file(GLOB ALL_TEST
        "./src/test/test.cpp"
        "./src/test/test_conformance.cpp"
        "./src/test/test_loop.cpp"
        "./src/test/test_marshal.cpp"
        "./src/test/test_print.cpp"
        "./src/test/test_termination.cpp"
        "./src/test/test_verify.cpp"
        "./src/test/test_wto.cpp"
        "./src/test/test_yaml.cpp"
        )

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR
    "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
  set(COMMON_FLAGS -Wall -Wfatal-errors -DSIZEOF_VOID_P=8 -DSIZEOF_LONG=8)

  set(RELEASE_FLAGS -O2 -flto=auto -ffat-lto-objects)

  set(DEBUG_FLAGS -O0 -g3 -fno-omit-frame-pointer)

  set(SANITIZE_FLAGS -fsanitize=address -O1 -fno-omit-frame-pointer)
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++20")
endif ()

add_library(ebpfverifier ${LIB_SRC})

add_executable(check src/main/check.cpp src/main/linux_verifier.cpp)
add_executable(tests ${ALL_TEST})
add_executable(run_yaml src/main/run_yaml.cpp)
add_executable(conformance_check src/test/conformance_check.cpp)

set_target_properties(check
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/..")

set_target_properties(tests
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/..")

set_target_properties(run_yaml
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/..")

set_target_properties(conformance_check
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/..")

add_dependencies(tests conformance_check)

target_compile_options(ebpfverifier PRIVATE ${COMMON_FLAGS})
target_compile_options(ebpfverifier PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_FLAGS}>")
target_compile_options(ebpfverifier PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_FLAGS}>")
target_compile_options(ebpfverifier PUBLIC "$<$<CONFIG:SANITIZE>:${SANITIZE_FLAGS}>")

add_subdirectory("external/bpf_conformance/src")
add_subdirectory("external/libbtf")

# CMake derives a Visual Studio project GUID from the file path but can be overridden via a property
# (see https://gitlab.kitware.com/cmake/cmake/-/commit/c85367f4).  Using a non-constant GUID
# can cause problems if other projects/repos want to reference the ebpfverifier vcxproj file,
# so we force a constant GUID here.
set(ebpfverifier_GUID_CMAKE "7d5b4e68-c0fa-3f86-9405-f6400219b440" CACHE INTERNAL "Project GUID")
set(yaml-cpp_GUID_CMAKE "98d56b8a-d8eb-3d98-b8ee-c83696b4d58a" CACHE INTERNAL "Project GUID")

target_compile_options(check PRIVATE ${COMMON_FLAGS})
target_compile_options(check PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_FLAGS}>")
target_compile_options(check PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_FLAGS}>")
target_compile_options(check PUBLIC "$<$<CONFIG:SANITIZE>:${SANITIZE_FLAGS}>")
target_link_libraries(check PRIVATE ebpfverifier)

message("Boost_LIBRARY_DIRS: ${Boost_LIBRARY_DIRS}")
target_compile_options(tests PRIVATE ${COMMON_FLAGS})
target_compile_options(tests PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_FLAGS}>")
target_compile_options(tests PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_FLAGS}>")
target_compile_options(tests PUBLIC "$<$<CONFIG:SANITIZE>:${SANITIZE_FLAGS}>")
target_link_libraries(tests PRIVATE ebpfverifier)
target_link_libraries(tests PRIVATE bpf_conformance)
target_link_libraries(tests PRIVATE ${CMAKE_DL_LIBS})

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

target_link_libraries(tests PRIVATE Threads::Threads)
target_link_libraries(tests PRIVATE Catch2::Catch2WithMain)

target_link_libraries(ebpfverifier PRIVATE ${YAML_CPP_LIBRARIES})
target_link_libraries(ebpfverifier PRIVATE libbtf)
target_compile_options(ebpfverifier PRIVATE ${COMMON_FLAGS})

target_link_libraries(run_yaml PRIVATE ebpfverifier)
target_link_libraries(conformance_check PRIVATE ebpfverifier)
