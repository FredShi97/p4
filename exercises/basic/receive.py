#!/usr/bin/python3
# SPDX-FileCopyrightText: 2022-present Intel Corporation
# SPDX-License-Identifier: Apache-2.0

# Script used in Exercise 3 that sniffs packets and prints on screen whether
# they are GTP encapsulated or not.

import signal
import sys
import os
from scapy.layers.inet import IP ,UDP
from scapy.contrib import gtp
from scapy.sendrecv import sniff


pkt_count = 0


def handle_pkt(pkt, ex):
    global pkt_count
    pkt_count = pkt_count + 1
    if gtp.GTP_U_Header in pkt:
        is_gtp_encap = True
    else:
        is_gtp_encap = False

    print("[%d] %d bytes: %s -> %s, is_gtp_encap=%s\n\t%s" % (
        pkt_count, len(pkt), pkt[IP].src, pkt[IP].dst,
        is_gtp_encap, pkt.summary()))

    if is_gtp_encap and ex:
        exit()


print("Will print a line for each UDP packet received...")


def handle_timeout(signum, frame):
    print("Timeout! Did not receive any GTP packet")
    exit(1)


exitOnSuccess = False
if len(sys.argv) > 1 and sys.argv[1] == "-e":
    # wait max 10 seconds or exit
    signal.signal(signal.SIGALRM, handle_timeout)
    signal.alarm(10)
    exitOnSuccess = True
ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
iface = ifaces[0]
print("sniffing on %s" % iface)

sniff(count=0, store=False, filter="udp",
      prn=lambda x: handle_pkt(x, exitOnSuccess))
