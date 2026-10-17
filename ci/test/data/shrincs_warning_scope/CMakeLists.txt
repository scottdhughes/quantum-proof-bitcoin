# Copyright (c) 2026 The PQBTC Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

cmake_minimum_required(VERSION 3.22)
project(shrincs_warning_scope LANGUAGES C CXX)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(core_interface INTERFACE)
target_compile_options(core_interface INTERFACE -Wall -Wextra -Werror -Wunreachable-code)

# Exercise the actual source-level settings, not a copy of the vendor flags.
add_subdirectory("${PQBTC_SOURCE_DIR}/src/crypto" crypto)

add_library(unreachable_control OBJECT unreachable_control.c)
target_link_libraries(unreachable_control PRIVATE core_interface)
add_library(warnings_control OBJECT warnings_control.c)
target_link_libraries(warnings_control PRIVATE core_interface)
