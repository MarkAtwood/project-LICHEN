// SPDX-License-Identifier: Apache-2.0
// Minimal STM32WL RCC stub for Renode - returns clocks ready
// ponytail: just enough to get Zephyr booted, not full RCC emulation

using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Logging;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public class STM32WL_RCC : IDoubleWordPeripheral, IKnownSize
    {
        public STM32WL_RCC()
        {
            // CR: HSI ready (bit 10), HSE ready (bit 17), PLL ready (bit 25)
            cr = 0x02020400;
            // CFGR: system clock from HSI
            cfgr = 0x00000000;
            // BDCR: LSERDY (bit 1)
            bdcr = 0x00000002;
            // CSR: LSIRDY (bit 1) + reset flags
            csr = 0x0C000002;
            // CCIPR: peripheral clock selection
            ccipr = 0x00000000;
        }

        public uint ReadDoubleWord(long offset)
        {
            switch (offset)
            {
                case 0x00:  // CR
                    return cr;
                case 0x08:  // CFGR
                    return cfgr;
                case 0x0C:  // PLLCFGR
                    return 0x00000000;
                case 0x18:  // CIER (interrupt enable)
                    return 0x00000000;
                case 0x1C:  // CIFR (interrupt flag)
                    return 0x00000000;
                case 0x58:  // AHB1ENR
                case 0x5C:  // AHB2ENR
                case 0x60:  // AHB3ENR
                case 0x68:  // APB1ENR1
                case 0x6C:  // APB1ENR2
                case 0x70:  // APB2ENR
                case 0x78:  // AHB1SMENR
                    return 0xFFFFFFFF;  // Everything enabled
                case 0x88:  // CCIPR (peripheral clock selection)
                    return ccipr;
                case 0x90:  // BDCR (backup domain control)
                    return bdcr;
                case 0x94:  // CSR
                    return csr;
                case 0x108: // EXTCFGR (extended clock config)
                    return 0x00030000;  // Prescalers ready
                default:
                    this.Log(LogLevel.Debug, "RCC read from unhandled offset 0x{0:X}", offset);
                    return 0x00000000;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch (offset)
            {
                case 0x00:  // CR
                    cr = value | 0x02020400;  // Keep ready bits set
                    break;
                case 0x08:  // CFGR
                    // Mirror SW bits [1:0] to SWS bits [3:2] (instant clock switch)
                    cfgr = (value & ~0xCu) | ((value & 0x3) << 2);
                    break;
                case 0x88:  // CCIPR
                    ccipr = value;
                    break;
                case 0x90:  // BDCR
                    bdcr = value;
                    // If LSEON (bit 0) set, also set LSERDY (bit 1)
                    if ((value & 0x1) != 0)
                        bdcr |= 0x2;
                    // If LSESYSEN (bit 7) set, also set LSESYSRDY (bit 11)
                    if ((value & 0x80) != 0)
                        bdcr |= 0x800;
                    break;
                case 0x94:  // CSR
                    // If LSION (bit 0) set, also set LSIRDY (bit 1)
                    if ((value & 0x1) != 0)
                        csr = value | 0x0C000002;
                    else
                        csr = (value & 0xFFFF) | 0x0C000000;  // Keep reset flags
                    break;
                default:
                    this.Log(LogLevel.Debug, "RCC write 0x{0:X8} to offset 0x{1:X}", value, offset);
                    break;
            }
        }

        public void Reset()
        {
            cr = 0x02020400;
            cfgr = 0x00000000;
            bdcr = 0x00000002;
            csr = 0x0C000002;
            ccipr = 0x00000000;
        }

        public long Size => 0x400;

        private uint cr;
        private uint cfgr;
        private uint bdcr;
        private uint csr;
        private uint ccipr;
    }
}
