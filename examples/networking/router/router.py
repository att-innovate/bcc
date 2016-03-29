#!/usr/bin/env python
"""
bpf router
    - Hooks at Traffic Control (ingress queue) in Kernel using eBPF
    * ARP
    * ICMP

USAGE: sudo python ping_reply.py
"""

from bcc import BPF
from pyroute2 import IPRoute, IPDB, protocols
import sys

ipr = IPRoute()
ipdb = IPDB(nl=ipr)
ifc = ipdb.interfaces.p2p1

b = BPF(src_file="router.c")
pr = b.load_func("parse_pkt", BPF.SCHED_ACT)
ipr.tc("add", "ingress", ifc.index, "ffff:")
action = {"kind": "bpf", "fd": pr.fd, "name": pr.name, "action": "ok"}
ipr.tc("add-filter", "u32", ifc.index, ":1", parent="ffff:", action=[action],
    protocol=protocols.ETH_P_ALL, classid=1, target=0x10000, keys=['0x0/0x0+0'])

try:
    print "All Ready..."
    b.trace_print()
except KeyboardInterrupt:
    print "Ending Demo..."
finally:
    ipr.tc("del", "ingress", ifc.index, "ffff:")
    ipdb.release()
