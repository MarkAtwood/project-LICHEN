# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN Zephyr module CMake extension

add_subdirectory(../drivers drivers)
add_subdirectory(../subsys subsys)

# L2 integration from bridge-zephyr (Zephyr network stack integration)
add_subdirectory(../../../firmware/bridge-zephyr/subsys bridge-zephyr-subsys)
