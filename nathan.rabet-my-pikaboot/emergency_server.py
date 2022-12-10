#!/usr/bin/env python3

import sys
import os
import serial
import struct
import zlib

PACKET_SIZE = 1024

EOT = 4
ENQ = 5
ACK = 6
BEL = 7
NAK = 21

class EmergencyPacket:
    def __init__(self, ctrl_c:int, size:int, crc:int, data:bytes):
        self.ctrl_c = ctrl_c
        self.size = size
        self.crc = crc
        self.data = data

        if (zlib.crc32(data) != crc):
            self.ctrl_c = NAK
    
    def to_bytes(self):
        # < = little endian
        # B = unsigned char
        # Q = unsigned long long
        # I = unsigned int
        packet = struct.pack("<B", self.ctrl_c)
        packet += struct.pack("<Q", self.size)
        packet += struct.pack("<I", self.crc)
        packet += self.data
        return packet

def send_packet(device:serial.Serial, data:bytes, ctrl_c:int = 0) -> None:
    assert(len(data) <= PACKET_SIZE)
    
    packet = EmergencyPacket(ctrl_c, len(data), zlib.crc32(data), data)
    device.write(packet.to_bytes())

def safe_send_packet(device:serial.Serial, data:bytes, ctrl_c:int = 0) -> None:
    while True:
        send_packet(device, data, ctrl_c)
        packet = receive_packet(device)
        if packet.ctrl_c == ACK:
            break

def receive_packet(device:serial.Serial) -> EmergencyPacket:
    ctrl_c = int.from_bytes(device.read(1), byteorder='little')
    size = int.from_bytes(device.read(8), byteorder='little')
    crc = int.from_bytes(device.read(4), byteorder='little')
    data = device.read(size)

    return EmergencyPacket(ctrl_c, size, crc, data)


if __name__ == "__main__":
    args = sys.argv

    # If args are not 3, exit
    if len(args) != 3:
        print("Usage: ./emergency_send.py <device> <file>".format(args[0]))
        exit(1)

    # Get the arguments
    device:serial.Serial = serial.Serial(args[1], 115200)
    file = open(args[2], 'rb')

    # Get file total size
    file.seek(0, os.SEEK_END)
    file_size:int = file.tell()
    file.seek(0, os.SEEK_SET)

    ################################################################################
    # SEND HELLO PACKET
    ################################################################################

    # Send hello packet : "Hello emergency" + \x01 (char)
    print("Sending hello packet")
    safe_send_packet(device, b"", ENQ)

    ################################################################################
    # SEND FILE SIZE
    ################################################################################
    print("Sending file size")
    # Send the file size (little endian u64)
    safe_send_packet(device, struct.pack("<Q", file_size))

    ################################################################################
    # FILE SENDING LOOP
    ################################################################################
    print("Sending file")
    exit = False
    while not exit:

        # Read PACKET_SIZE bytes from the file
        data = file.read(PACKET_SIZE)

        # If the data is empty, send EOT
        if len(data) == 0:
            send_packet(device, b"", EOT) # 4 = EOT
            exit = True
        # If the data is not empty, send the data
        else:
            safe_send_packet(device, data)

    file.close()
