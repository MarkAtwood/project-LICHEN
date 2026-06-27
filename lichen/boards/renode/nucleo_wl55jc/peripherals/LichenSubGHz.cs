// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The contributors to the LICHEN project
//
// Minimal SubGHz peripheral that bridges to lichen-sim via TCP socket.
// ponytail: no real register emulation, just TX/RX command interface.
//
// Memory map (relative to base 0x58010000):
//   0x000: TX_LEN (write, 2 bytes) - payload length to send
//   0x004: TX_TRIGGER (write, 4 bytes) - any write triggers TX
//   0x008: TX_STATUS (read, 4 bytes) - 0=idle, 1=busy, 2=done, 3=fail
//   0x00C: TX_AIRTIME (read, 4 bytes) - last TX airtime in us
//   0x010: RX_STATUS (read, 4 bytes) - 0=empty, 1=packet available
//   0x014: RX_LEN (read, 2 bytes) - received payload length
//   0x018: RX_RSSI (read, 2 bytes signed) - RSSI in dBm
//   0x01C: RX_SNR (read, 2 bytes signed) - SNR * 10
//   0x020: RX_CONSUME (write, 4 bytes) - any write consumes RX packet
//   0x024: CONNECT (write, 4 bytes) - any write triggers socket connect
//   0x100-0x1FF: TX_BUFFER (256 bytes)
//   0x200-0x2FF: RX_BUFFER (256 bytes)

using System;
using System.Net.Sockets;
using Antmicro.Renode.Core;
using Antmicro.Renode.Logging;
using Antmicro.Renode.Peripherals.Bus;

namespace Antmicro.Renode.Peripherals.Wireless
{
    public class LichenSubGHz : IDoubleWordPeripheral, IBytePeripheral, IKnownSize
    {
        public LichenSubGHz(IMachine machine, string simHost = "127.0.0.1", int simPort = 5555)
        {
            this.machine = machine;
            this.simHost = simHost;
            this.simPort = simPort;
            txBuffer = new byte[256];
            rxBuffer = new byte[256];
            Reset();
        }

        public long Size => 0x300;

        // Allow runtime port override from Renode script
        public int SimPort
        {
            get => simPort;
            set
            {
                Disconnect();
                simPort = value;
                this.Log(LogLevel.Info, "SimPort set to {0}", value);
            }
        }

        public void Reset()
        {
            txLen = 0;
            txStatus = 0;
            txAirtime = 0;
            rxStatus = 0;
            rxLen = 0;
            rxRssi = 0;
            rxSnr = 0;
            Array.Clear(txBuffer, 0, txBuffer.Length);
            Array.Clear(rxBuffer, 0, rxBuffer.Length);
            Disconnect();
        }

        public uint ReadDoubleWord(long offset)
        {
            switch (offset)
            {
                case 0x008: return txStatus;
                case 0x00C: return txAirtime;
                case 0x010:
                    PollRx();
                    return rxStatus;
                case 0x014: return rxLen;
                case 0x018: return (uint)(short)rxRssi;
                case 0x01C: return (uint)(short)rxSnr;
                default:
                    if (offset >= 0x100 && offset < 0x200)
                        return ReadBufferWord(txBuffer, offset - 0x100);
                    if (offset >= 0x200 && offset < 0x300)
                        return ReadBufferWord(rxBuffer, offset - 0x200);
                    return 0;
            }
        }

        public void WriteDoubleWord(long offset, uint value)
        {
            switch (offset)
            {
                case 0x000:
                    txLen = (ushort)(value & 0xFF);
                    break;
                case 0x004:
                    TriggerTx();
                    break;
                case 0x020:
                    ConsumeRx();
                    break;
                case 0x024:
                    Connect();
                    break;
                default:
                    if (offset >= 0x100 && offset < 0x200)
                        WriteBufferWord(txBuffer, offset - 0x100, value);
                    break;
            }
        }

        public byte ReadByte(long offset)
        {
            if (offset >= 0x100 && offset < 0x200)
                return txBuffer[offset - 0x100];
            if (offset >= 0x200 && offset < 0x300)
                return rxBuffer[offset - 0x200];
            return (byte)(ReadDoubleWord(offset & ~3) >> (int)((offset & 3) * 8));
        }

        public void WriteByte(long offset, byte value)
        {
            if (offset >= 0x100 && offset < 0x200)
            {
                txBuffer[offset - 0x100] = value;
                return;
            }
            WriteDoubleWord(offset & ~3, value);
        }

        private void Connect()
        {
            if (socket != null && socket.Connected)
                return;

            try
            {
                socket?.Close();
                socket = new TcpClient();
                socket.NoDelay = true;
                socket.ReceiveTimeout = 100; // Short timeout for non-blocking RX poll
                socket.Connect(simHost, simPort);
                stream = socket.GetStream();
                this.Log(LogLevel.Info, "Connected to lichen-sim at {0}:{1}", simHost, simPort);
            }
            catch (Exception e)
            {
                this.Log(LogLevel.Warning, "Failed to connect: {0}", e.Message);
                socket = null;
                stream = null;
            }
        }

        private void Disconnect()
        {
            stream = null;
            socket?.Close();
            socket = null;
        }

        private void TriggerTx()
        {
            if (stream == null)
            {
                Connect();
                if (stream == null)
                {
                    this.Log(LogLevel.Warning, "TX failed: not connected");
                    txStatus = 3; // fail
                    return;
                }
            }

            txStatus = 1; // busy
            this.Log(LogLevel.Debug, "TX: {0} bytes", txLen);

            try
            {
                // Build TX message: [len:4][type:1][payload_len:2][payload]
                var msgLen = 3 + txLen;
                var msg = new byte[4 + msgLen];
                WriteLE32(msg, 0, (uint)msgLen);
                msg[4] = 0x10; // MSG_TX
                WriteLE16(msg, 5, txLen);
                Array.Copy(txBuffer, 0, msg, 7, txLen);

                stream.Write(msg, 0, msg.Length);

                // Read response
                var resp = ReadMessage();
                if (resp != null && resp.Length >= 5 && resp[0] == 0x11) // TX_DONE
                {
                    txAirtime = ReadLE32(resp, 1);
                    txStatus = 2; // done
                    this.Log(LogLevel.Debug, "TX done, airtime={0}us", txAirtime);
                }
                else
                {
                    txStatus = 3; // fail
                    this.Log(LogLevel.Warning, "TX failed: bad response");
                }
            }
            catch (Exception e)
            {
                this.Log(LogLevel.Warning, "TX error: {0}", e.Message);
                txStatus = 3;
                Disconnect();
            }
        }

        private void PollRx()
        {
            if (rxStatus == 1) // Already have packet
                return;

            if (stream == null)
                return;

            try
            {
                // Send RX_POLL: [len:4][type:1]
                var msg = new byte[5];
                WriteLE32(msg, 0, 1);
                msg[4] = 0x20; // RX_POLL
                stream.Write(msg, 0, msg.Length);

                var resp = ReadMessage();
                if (resp != null && resp.Length >= 1)
                {
                    if (resp[0] == 0x21) // RX_OK
                    {
                        rxLen = ReadLE16(resp, 1);
                        Array.Copy(resp, 3, rxBuffer, 0, Math.Min(rxLen, (ushort)256));
                        var rssiOffset = 3 + rxLen;
                        rxRssi = (short)ReadLE16(resp, rssiOffset);
                        rxSnr = (short)ReadLE16(resp, rssiOffset + 2);
                        rxStatus = 1;
                        this.Log(LogLevel.Debug, "RX: {0} bytes, RSSI={1}", rxLen, rxRssi);
                    }
                    // else RX_EMPTY (0x23)
                }
            }
            catch (SocketException)
            {
                // Timeout is expected for non-blocking poll
            }
            catch (Exception e)
            {
                this.Log(LogLevel.Debug, "RX poll error: {0}", e.Message);
            }
        }

        private void ConsumeRx()
        {
            rxStatus = 0;
            rxLen = 0;
        }

        private byte[] ReadMessage()
        {
            // Read 4-byte length prefix
            var lenBuf = new byte[4];
            int read = 0;
            while (read < 4)
            {
                int n = stream.Read(lenBuf, read, 4 - read);
                if (n <= 0) return null;
                read += n;
            }

            int len = (int)ReadLE32(lenBuf, 0);
            if (len == 0) return new byte[0];
            if (len > 1024) return null; // sanity limit

            var data = new byte[len];
            read = 0;
            while (read < len)
            {
                int n = stream.Read(data, read, len - read);
                if (n <= 0) return null;
                read += n;
            }
            return data;
        }

        private static void WriteLE16(byte[] buf, int offset, ushort value)
        {
            buf[offset] = (byte)(value & 0xFF);
            buf[offset + 1] = (byte)((value >> 8) & 0xFF);
        }

        private static void WriteLE32(byte[] buf, int offset, uint value)
        {
            buf[offset] = (byte)(value & 0xFF);
            buf[offset + 1] = (byte)((value >> 8) & 0xFF);
            buf[offset + 2] = (byte)((value >> 16) & 0xFF);
            buf[offset + 3] = (byte)((value >> 24) & 0xFF);
        }

        private static ushort ReadLE16(byte[] buf, int offset)
        {
            return (ushort)(buf[offset] | (buf[offset + 1] << 8));
        }

        private static uint ReadLE32(byte[] buf, int offset)
        {
            return (uint)(buf[offset] | (buf[offset + 1] << 8) |
                         (buf[offset + 2] << 16) | (buf[offset + 3] << 24));
        }

        private uint ReadBufferWord(byte[] buf, long offset)
        {
            if (offset + 4 > buf.Length) return 0;
            return ReadLE32(buf, (int)offset);
        }

        private void WriteBufferWord(byte[] buf, long offset, uint value)
        {
            if (offset + 4 > buf.Length) return;
            WriteLE32(buf, (int)offset, value);
        }

        private readonly IMachine machine;
        private readonly string simHost;
        private int simPort;
        private readonly byte[] txBuffer;
        private readonly byte[] rxBuffer;

        private TcpClient socket;
        private NetworkStream stream;

        private ushort txLen;
        private uint txStatus;
        private uint txAirtime;
        private uint rxStatus;
        private ushort rxLen;
        private short rxRssi;
        private short rxSnr;
    }
}
