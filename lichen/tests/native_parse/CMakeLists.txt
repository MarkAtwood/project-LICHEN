# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(native_parse)

zephyr_compile_definitions(LICHEN_NATIVE_TEST_PARSE=1 LICHEN_NATIVE_TEST_TX=1)

# CONFIG_LICHEN_NATIVE is deliberately left off: it depends on
# UART_INTERRUPT_DRIVEN, which native_sim cannot satisfy (the ptty driver
# never selects SERIAL_SUPPORT_INTERRUPT), so the library would drop out and
# lichen/native.h would vanish (project-LICHEN-worker6-5zbn). This suite only
# exercises the parse/encode test hooks and the captured TX path — it never
# opens a UART — so compile native.c directly into the app instead. The buffer
# sizing symbols below are only defined when CONFIG_LICHEN_NATIVE is on.
target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../lib/native/native.c)
target_include_directories(app PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/../../lib/native/include
	${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/hal/include
)
target_compile_definitions(app PRIVATE
	CONFIG_LICHEN_NATIVE_RX_BUF_SIZE=1024
	CONFIG_LICHEN_NATIVE_RX_STACK_SIZE=2048
	CONFIG_LICHEN_NATIVE_TX_BUF_SIZE=1024
)
target_sources(app PRIVATE src/main.c)
