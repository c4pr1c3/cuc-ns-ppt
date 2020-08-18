#! /usr/bin/env python
# arping: arpings a network

import sys
from scapy.all import srp, Ether, ARP, conf


if len(sys.argv) != 2:
    print("Usage: arping <net>\n  eg: arping 192.168.56.1/24")
    sys.exit(1)

conf.verb = 0

pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=sys.argv[1])
ans, unans = srp(pkt, timeout=2)

for snd, rcv in ans:
    print("{} {}".format(rcv.src, rcv.psrc))
