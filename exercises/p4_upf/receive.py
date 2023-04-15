#!/usr/bin/python3
# SPDX-FileCopyrightText: 2022-present Intel Corporation
# SPDX-License-Identifier: Apache-2.0

# Script used in Exercise 3 that sniffs packets and prints on screen whether
# they are GTP encapsulated or not.

import signal
import sys

from scapy.layers.inet import IP ,UDP, Ether
from scapy.contrib import gtp
from scapy.sendrecv import sniff
from scapy.all import get_if_list

pkt_count = 0


def handle_pkt(pkt, ex):
    global pkt_count
    pkt_count = pkt_count + 1
    if gtp.GTP_U_Header in pkt:
        is_gtp_encap = True
    else:
        is_gtp_encap = False

    print("[%d] %d bytes: Mac %s -> %s IP %s -> %s, is_gtp_encap=%s\n\t%s" % (
        pkt_count, len(pkt), pkt[Ether].src, pkt[Ether].dst, pkt[IP].src, pkt[IP].dst,
        is_gtp_encap, pkt.summary()))


    if is_gtp_encap and ex:
        exit()


print("Will print a line for each UDP packet received...")


def handle_timeout(signum, frame):
    print("Timeout! Did not receive any GTP packet")
    exit(1)

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


exitOnSuccess = False
if len(sys.argv) > 1 and sys.argv[1] == "-e":
    # wait max 10 seconds or exit
    signal.signal(signal.SIGALRM, handle_timeout)
    signal.alarm(10)
    exitOnSuccess = True

iface = get_if()

sniff(count=0, iface = iface, filter="udp", store=False, prn=lambda x: handle_pkt(x, exitOnSuccess))
