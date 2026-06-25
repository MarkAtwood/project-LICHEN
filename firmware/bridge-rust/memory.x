/* RAK4631 memory layout - with Adafruit bootloader */
MEMORY
{
  /* Bootloader occupies first 152K (0x26000) */
  FLASH : ORIGIN = 0x00026000, LENGTH = 872K
  RAM   : ORIGIN = 0x20000000, LENGTH = 256K
}
