# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
project(forwarding_policy C)

add_executable(forwarding_policy
  main.c
  ../../apps/gateway/src/forwarding_policy.c)
target_include_directories(forwarding_policy PRIVATE
  ../../apps/gateway/src)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/test_common.cmake)
lichen_test_target(forwarding_policy)
enable_testing()
add_test(NAME forwarding_policy COMMAND forwarding_policy)
