# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(hmi_led_test C)

# Common test config (sanitizers + hardening + CONFIG_* defaults)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(hmi_led_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/hmi/hmi_led.c
)
target_include_directories(hmi_led_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/hmi/include
)

# Apply sanitizers and hardening
lichen_test_target(hmi_led_test)

include(CTest)
add_test(NAME hmi_led COMMAND hmi_led_test)
