// SPDX-License-Identifier: Apache-2.0
// Minimal STM32WL PWR stub for Renode
// ponytail: just enough to pass power checks, no actual power management

using Antmicro.Renode.Core;
using Antmicro.Renode.Core.Structure.Registers;
using Antmicro.Renode.Peripherals.Bus;
using Antmicro.Renode.Logging;

namespace Antmicro.Renode.Peripherals.Miscellaneous
{
    public class STM32WL_PWR : IDoubleWordPeripheral, IKnownSize
    {
        public STM32WL_PWR()
        {
            cr1 = 0x00000200;  // VOS ready
            cr2 = 0x00000000;
            sr1 = 0x00000000;  // No flags
            sr2 = 0x00000008;  // VOSF=0 (VOS ready), REGLPF=0 (main regulator active)
        }

        public uint ReadDoubleWord(long offset)
        {
            switch (offset)
            {
                case 0x00:  // CR1
                    return cr1;
                case 0x04:  // CR2
                    return cr2;
                case 0x08:  // CR3
                    return 0x00008000;  // EIWUL=1 (internal wakeup enabled)
                case 0x0C:  // CR4
                    return 0x00000000;
                case 0x10:  // SR1
                    return sr1;
                case 0x14:  // SR2
                    return sr2;
                case 0x18:  // SCR (write-only clear register)
                    return 0x00000000;
                case 0x20:  // PUCRA-PUCRH (pull-up control)
                case 0x24:
                case 0x28:
                case 0x2C:
                case 0x30:
                case 0x34:
                    return 0x00000000;
                case 0x40:  // PDCRA-PDCRH (pull-down control)
                case 0x44:
                case 0x48:
                case 0x4C:
                case 0x50:
                case 0x54:
                    return 0x00000000;
                case 0x80:  // C2CR1
                    return 0x00000000;
                case 0x84:  // C2CR3
                    return 0x00000000;
                case 0x88:  // EXTSCR
                    return 0x00000000;
                default:
                    this.Log(LogLevel.Debug, "PWR read from offset 0x{0:X}", offset);
                    return 0x00000000;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch (offset)
            {
                case 0x00:  // CR1
                    cr1 = value;
                    break;
                case 0x04:  // CR2
                    cr2 = value;
                    break;
                case 0x18:  // SCR - clear flags, just ignore
                    break;
                default:
                    this.Log(LogLevel.Debug, "PWR write 0x{0:X8} to offset 0x{1:X}", value, offset);
                    break;
            }
        }

        public void Reset()
        {
            cr1 = 0x00000200;
            cr2 = 0x00000000;
            sr1 = 0x00000000;
            sr2 = 0x00000008;
        }

        public long Size => 0x400;

        private uint cr1;
        private uint cr2;
        private uint sr1;
        private uint sr2;
    }
}
