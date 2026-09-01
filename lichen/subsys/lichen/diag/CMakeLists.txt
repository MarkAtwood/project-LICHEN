# SPDX-License-Identifier: GPL-3.0-or-later

# Hardware diagnostics event ring + fleet detectors - Zephyr build

zephyr_include_directories(include)

zephyr_library_sources(
  lichen_diag.c
  asymmetric_link.c
  rf_path_asymmetry.c
  pps_monitor.c
  gps_uart_monitor.c
  dio1_timeout.c
)
