if(CONFIG_LORA_LICHEN_SIM OR CONFIG_LORA_LICHEN_RENODE)
  add_subdirectory(lora)
endif()
add_subdirectory_ifdef(CONFIG_LORA_LOOPBACK lora_loopback)
