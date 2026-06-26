cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(lora_ping)

target_sources(app PRIVATE src/main.c)

# Include the Renode LoRa driver directly since module loading is broken
if(CONFIG_LORA_LICHEN_RENODE)
  target_sources(app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../drivers/lora/lora_renode.c)
endif()
