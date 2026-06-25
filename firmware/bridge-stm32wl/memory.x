/* STM32WLE5JC memory layout */
MEMORY
{
  /* STM32WLE5JC has 256KB flash, 64KB RAM */
  /* No bootloader reservation - direct flash */
  FLASH : ORIGIN = 0x08000000, LENGTH = 256K
  RAM   : ORIGIN = 0x20000000, LENGTH = 64K
}
