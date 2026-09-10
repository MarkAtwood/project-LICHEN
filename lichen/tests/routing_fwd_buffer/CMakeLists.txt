# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(routing_fwd_buffer)

find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(VECTOR_JSON ${CMAKE_CURRENT_LIST_DIR}/../../../test/vectors/forwarding_buffer.json)
set(GENERATED_HEADER ${CMAKE_CURRENT_BINARY_DIR}/forwarding_buffer_vectors.h)
execute_process(
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_LIST_DIR}/gen_vectors.py
          ${VECTOR_JSON} ${GENERATED_HEADER}
  RESULT_VARIABLE GENERATOR_RESULT
  ERROR_VARIABLE GENERATOR_ERROR
)
if(NOT GENERATOR_RESULT EQUAL 0)
  message(FATAL_ERROR "forwarding-buffer vector generation failed: ${GENERATOR_ERROR}")
endif()

target_sources(app PRIVATE src/main.c)
target_include_directories(app PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
