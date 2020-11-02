cmake_minimum_required(VERSION 3.10)
project(ebpf_verifier)

set(CMAKE_CXX_STANDARD 17)

find_package(Boost REQUIRED)

find_library(GMP REQUIRED)

include_directories(./external)
include_directories(./src)
include_directories(${GMP_LIB_INCLUDE_DIRS})
include_directories(${Boost_INCLUDE_DIRS})
link_directories(${GMP_LIB_LIBRARY_DIRS})
link_directories(${Boost_LIBRARY_DIRS})

file(GLOB ALL_SRC
        "./src/*.cpp"
        "./src/crab/*.cpp"
        "./src/crab_types/*.cpp"
        )

file(GLOB ALL_TEST
        "src/test/*.cpp"
        )

set(COMMON_FLAGS -Wall -Wfatal-errors -DSIZEOF_VOID_P=8 -DSIZEOF_LONG=8)
set(DEBUG_FLAGS -O0 -g3)
set(RELEASE_FLAGS -O2 -flto)
set(SANITIZE_FLAGS -fsanitize=address -O1 -fno-omit-frame-pointer)

add_executable(check src/main/check.cpp ${ALL_SRC})
add_executable(test ${ALL_TEST} ${ALL_SRC})

set_target_properties(check
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/..")


set_target_properties(test
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/..")


target_compile_options(check PRIVATE ${COMMON_FLAGS})
target_compile_options(check PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_FLAGS}>")
target_compile_options(check PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_FLAGS}>")
target_compile_options(check PUBLIC "$<$<CONFIG:SANITIZE>:${SANITIZE_FLAGS}>")

target_link_libraries(check PRIVATE gmp)


target_compile_options(test PRIVATE ${COMMON_FLAGS})
target_compile_options(test PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_FLAGS}>")
target_compile_options(test PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_FLAGS}>")
target_compile_options(test PUBLIC "$<$<CONFIG:SANITIZE>:${SANITIZE_FLAGS}>")

target_link_libraries(test PRIVATE gmp)
