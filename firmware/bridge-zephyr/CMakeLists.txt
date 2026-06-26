cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(lichen_bridge)

# Include LICHEN subsystems
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR})
add_subdirectory(subsys)

target_sources(app PRIVATE src/main.c)

# Include headers from subsystems
target_include_directories(app PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/subsys/lichen
)
