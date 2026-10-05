cmake_minimum_required(VERSION 3.24)
project(QuantComm C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Strict warnings: warnings are defects in crypto-adjacent code.
add_compile_options(-Wall -Wextra -Werror -Wpedantic)

include(CTest)

add_subdirectory(third_party/unity)
add_subdirectory(tests/c)
