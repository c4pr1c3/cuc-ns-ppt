#!/usr/bin/env python

import sys
import threading
import ipaddress
from scapy.all import ICMP, IP, sr1
from queue import Queue

if len(sys.argv) < 2:
    print("Usage: icmping <host> [icmp_type] [icmp_code]\n")
    print("eg: icmping 192.168.56.0/24")
    print("eg: icmping 192.168.56.0/24 13 0")
    print("eg: icmping 192.168.56.0/24 15 0")
    print("eg: icmping 192.168.56.0/24 17 0")
    sys.exit(1)

network = sys.argv[1]
if len(sys.argv) < 3:
    icmp_type = 8
else:
    icmp_type = int(sys.argv[2])

if len(sys.argv) < 4:
    icmp_code = 0
else:
    icmp_code = int(sys.argv[3])

max_threads = 100
ip_net = ipaddress.ip_network(network)
all_hosts = list(ip_net.hosts())
live_count = 0

print('Sweeping Network with ICMP: {} type={}/code={}'.format(network, icmp_type, icmp_code))


def pingsweep(ip):
    host = str(all_hosts[ip])
    resp = sr1(
        IP(dst=str(host))/ICMP(type=icmp_type, code=icmp_code),
        timeout=2,
        verbose=0,
    )

    if resp is None:
        # print(f"{host} is down or not responding.")
        return 0
    elif (
        int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]
    ):
        # print(f"{host} is blocking ICMP.")
        return 0
    else:
        print(f"{host} is responding.")
        return 1


def threader():
    while True:
        worker = q.get()
        pingsweep(worker)
        q.task_done()


q = Queue()

for x in range(max_threads):
    t = threading.Thread(target=threader)
    t.daemon = True
    t.start()

for worker in range(len(all_hosts)):
    q.put(worker)

q.join()
