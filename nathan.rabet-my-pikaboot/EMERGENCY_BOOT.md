# Emergency boot protocol

## Introduction

The emergency boot protocol is a protocol that allows you to download a kernel for emergency booting. This protocol is useful if your internal kernel is corrupted or if you want to boot a another kernel.

## `emergency_server.py` explained

The `emergency_server.py` script is a Python script that allows you to upload a kernel to the bootloader. This script is used by the `emergency_boot` command.

This secion will not explain how to use the `emergency_server.py` script (which is explained in the [HOWTO.md](HOWTO.md) file). Instead, this section will explain how the script works.

## Protocol explaination

The protocol is like a _tiny-TCP_ network over serial.

The server split the file to send into chunks and then send them to the bootloader using packets.

### Packet format

Here is a C struct that represents a packet:

```c
struct emergency_packet
{
    u8 ctrl_c;
    u64 size;
    u32 crc;
    char data[PACKET_MAX_SIZE];
};
```

### Acknowledgment

The protocol uses acknowledgment to ensure that the pairs receive the packets correctly.

A packet is considered as acknowledged if its CRC32 is correct and if the `ctrl_c` field is set to `NUL`. Else, the packet is considered as not acknowledged (`NAK`).

If a pair receives a `NAK`, it will resend the packet until it receives an `ACK`.

### `ctrl_c` field

The `ctrl_c` field is used to communicate acknowledgment.

When a packet is sent, the `ctrl_c` field is set to `NUL` (the only exception is the first hello packet, which set `ctrl_c` to `ENQ`).

### `size` field

The `size` field is used to communicate the size of the data field.

It can be between 0 and `PACKET_MAX_SIZE`. If the `size` field is not in this range, the packet is considered as `NAK`.

### `crc` field

The `crc` field is used to communicate the CRC32 of the data field.

It is used to ensure that the data field is not corrupted.

### `data[]` field

The `data[]` field is used to communicate the data.

It size is `size` bytes.

## Protocol example

Let's say you want to send a file of `n` bytes on a serial port.

1. The server sends a hello packet to the bootloader :
   - `ctrl_c` is set to `ENQ`
   - `size` is set to 0
   - `crc` is set to `crc32(0)`
   - `data[]` is empty

2. The bootloader receives the hello packet and sends an `ACK` packet :

   - `ctrl_c` is set to `ACK`
   - `size` is set to 0
   - `crc` is set to `crc32(0)`
   - `data[]` is empty

3. The server (after receiving the `ACK` packet) sends the size of the file :

   - `ctrl_c` is set to `NUL`
   - `size` is set to `sizeof(u64)`
   - `crc` is set to `crc32(data, size)`
   - `data[]` is set to `n` (as a `u64`)

4. The bootloader receives the size packet and sends an `ACK` packet :

   - `ctrl_c` is set to `ACK`
   - `size` is set to 0
   - `crc` is set to `crc32(0)`
   - `data[]` is empty

    > This file size is used to permit the bootloader to allocate the memory needed to store the file.

5. The server (after receiving the `ACK` packet) sends the file in chunks of `PACKET_MAX_SIZE` bytes until the file is fully sent :

   - `ctrl_c` is set to `NUL`
   - `size` is set to `min(PACKET_MAX_SIZE, n - i * PACKET_MAX_SIZE)` (where `i` is the chunk number)
   - `crc` is set to `crc32(data, size)`
   - `data[]` contains the chunk of data

    > Of course every packet need to be acknowledged.

6. The bootloader receives the last chunk and sends an `EOT` packet to terminate the transmission :
   - `ctrl_c` is set to `EOT`
   - `size` is set to 0
   - `crc` is set to `crc32(0)`
   - `data[]` is empty
