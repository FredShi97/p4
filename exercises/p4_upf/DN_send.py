#!/usr/bin/python3
# SPDX-FileCopyrightText: 2022-present Intel Corporation
# SPDX-License-Identifier: Apache-2.0

# Script used in Exercise 8.
# Send downlink packets to UE address.
import argparse

from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send, sendp
from scapy.contrib import gtp
from scapy.layers.l2 import Ether
from scapy.all import get_if_hwaddr, get_if_list

gNB_ADDR = "172.16.1.99"
UPF_ADDR = "172.16.1.254"
UE_ADDR = "192.168.0.1"
DN_ADDR = "172.16.4.1"

RATE = 5  # packets per second
PAYLOAD = ' '.join(['hello'])

#parser = argparse.ArgumentParser(description='Send UDP packets to the given IPv4 address')
#parser.add_argument('ipv4_dst', type=str, help="Destination IPv4 address")
#args = parser.parse_args()

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

GTP = gtp.GTP_U_Header(teid=1)
ETHER = Ether(dst="4e:97:ec:04:c7:f9")
iface = get_if()

print("Sending %d UDP packets per second to ..." % (RATE))

pkt = ETHER/IP(src=DN_ADDR, dst=UE_ADDR) / UDP(sport=10053, dport=10053)/PAYLOAD
sendp(pkt, iface=iface, inter=1.0 / RATE, loop=True, verbose=True)
