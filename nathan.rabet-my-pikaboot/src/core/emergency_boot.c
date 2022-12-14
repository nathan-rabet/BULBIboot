#include "emergency_boot.h"

#include "ascii.h"
#include "asm.h"
#include "crc32.h"
#include "int.h"
#include "kassert.h"
#include "kstring.h"
#include "linux_boot.h"
#include "number.h"
#include "uart.h"

#define PACKET_MAX_SIZE 2048

const unsigned char soh = SOH;

// Packed struct
struct emergency_packet
{
    u8 ctrl_c;
    u64 size;
    u32 crc;
    char data[PACKET_MAX_SIZE];
} __attribute__((packed));

static void send_packet(volatile uart_t *emergency_uart, u8 ctrl_c,
                        const unsigned char *buf, u64 size)
{
    struct emergency_packet packet = {
        .ctrl_c = ctrl_c, .size = size, .crc = crc32(buf, size), .data = { 0 }
    };
    memcpy(packet.data, buf, size);
    uart_write((unsigned char *)&packet,
               sizeof(u8) + sizeof(u64) + sizeof(u32) + size, emergency_uart);
}

static struct emergency_packet receive_packet(volatile uart_t *emergency_uart)
{
    struct emergency_packet packet = { 0 };

    // Get the size of the packet
    u64 size = 0;
    while (size < (sizeof(struct emergency_packet) - sizeof(packet.data)))
        size += uart_read((unsigned char *)&packet + size,
                          sizeof(u8) + sizeof(u64) + sizeof(u32) - size,
                          emergency_uart);
    u64 packet_data_size = packet.size;

    // Get the data of the packet
    size = 0;
    while (size < packet_data_size)
        size += uart_read((unsigned char *)packet.data + size, packet_data_size,
                          emergency_uart);

    // Ask for the packet again if the CRC is incorrect
    while (crc32(packet.data, packet.size) != packet.crc)
    {
        send_packet(emergency_uart, NAK, NULL, 0);
        packet = receive_packet(emergency_uart);
    }

    send_packet(emergency_uart, ACK, NULL, 0);
    return packet;
}

static u64 initiate_file_transfer(volatile uart_t *emergency_uart)
{
    struct emergency_packet hello_packet = receive_packet(emergency_uart);

    // Check if the hello packet is correct
    if (hello_packet.ctrl_c != ENQ)
        return (u64)-1;

    struct emergency_packet file_size_packet = receive_packet(emergency_uart);

    return *((u64 *)file_size_packet.data);
}

static void receive_file(volatile uart_t *emergency_uart, u64 file_size)
{
    // unsigned char transfered_file[file_size];
    unsigned char *transfered_file = linux_get_kernel_addr();
    u64 transfered_file_size = 0;

    // -------------------------------------------------------------------------
    // WAIT FOR FILE PACKET
    // -------------------------------------------------------------------------
    struct emergency_packet file_packet = { 0 };
    while (file_packet.ctrl_c != EOT && transfered_file_size < file_size)
    {
        file_packet = receive_packet(emergency_uart);

        // Check if the file packet is the last one
        if (file_packet.ctrl_c == EOT)
            break;

        // Copy the file packet data into the transfered file
        memcpy(transfered_file + transfered_file_size, file_packet.data,
               file_packet.size);

        transfered_file_size += file_packet.size;
    }

    // -------------------------------------------------------------------------
    // PRINT FILE CRC
    // -------------------------------------------------------------------------
    u32 crc = crc32(transfered_file, transfered_file_size);

    uart_write((unsigned char *)"CRC: ", 5, emergency_uart);
    uart_write((unsigned char *)itoa64hex(crc), 10, emergency_uart);
    uart_write((unsigned char *)CRLF, sizeof(CRLF), emergency_uart);

    // -------------------------------------------------------------------------
    // BOOT LINUX KERNEL
    // -------------------------------------------------------------------------
    linux_boot();
}

void emergency_boot(void)
{
    volatile uart_t *emergency_uart = (volatile uart_t *)UART0_BOARD_ADDR;

    // Setup UART (in case of misconfiguration)
    pl011_setup(emergency_uart);

    // Disable interrupts
    uart_disable_interrupts(emergency_uart);

    u64 file_size = initiate_file_transfer(emergency_uart);
    if (file_size != (u64)-1)
        receive_file(emergency_uart, file_size);

    // Re-setup UART
    pl011_setup(emergency_uart);
}
