#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw, Ether, Padding
from scapy.layers.inet import _IPOption_HDR

IPV4_PROTOCOL_TCP = 6
IPV4_PROTOCOL_UDP = 17

def populate_hot_flow_rule(p):
    rule = "table_add is_hot_flow NoAction %s %s %d %d %d =>" % (p["srcIP"], p["dstIP"], p["proto"], p["srcPort"], p["dstPort"])
    print rule
    cmd = 'echo \"%s\" | ~/behavioral-model/targets/simple_switch/sswitch_CLI' % rule
    os.system(cmd)

pkt_5_tuple = {}
def handle_pkt(pkt):
    global cnt, empty, pkt_5_tuple
    pkt.show()
    hexdump(pkt)

    pkt_5_tuple["srcIP"] = pkt[IP].src
    pkt_5_tuple["dstIP"] = pkt[IP].dst
    pkt_5_tuple["proto"] = pkt[IP].proto

    if pkt[IP].proto == IPV4_PROTOCOL_TCP:
        pkt_5_tuple["srcPort"] = pkt[TCP].sport
        pkt_5_tuple["dstPort"] = pkt[TCP].dport
    else:
        pkt_5_tuple["srcPort"] = pkt[UDP].sport
        pkt_5_tuple["dstPort"] = pkt[UDP].dport

    print pkt_5_tuple
    populate_hot_flow_rule(pkt_5_tuple)

def main():
    ifaces = filter(lambda i: 'veth10' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = 'veth10',
        prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
