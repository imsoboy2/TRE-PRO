#!/usr/bin/env python
import sys
import struct
import os
import time

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw, Ether, Padding
from scapy.layers.inet import _IPOption_HDR

IPV4_PROTOCOL_TCP = 6
IPV4_PROTOCOL_UDP = 17
bucket_size = 65536
hash_base = 0
hash_max = bucket_size - 1
num_of_entries = 524288
cnt = 0
hot_flow_set = set()

SHIM_TCP = 77
SHIM_UDP = 78

class custom_hdr(Packet):
    """Custom Header"""
    name = 'custom_hdr'
    fields_desc = [
        BitField('bitmap', 0, 10),
        BitField('dstIP', 0, 32),
        BitField('reserved', 0, 6)
    ]

bind_layers(IP, UDP, proto=SHIM_UDP)
bind_layers(IP, TCP, proto=SHIM_TCP)

bind_layers(UDP, custom_hdr)
bind_layers(TCP, custom_hdr)

def populate_hot_flow_rule(p):
    global hash_base, hash_max, cnt
    hot_flow = p["srcIP"] + p["dstIP"] + str(p["proto"]) + str(p["srcPort"]) + str(p["dstPort"])
    if hot_flow in hot_flow_set: return
    if num_of_entries <= hash_base: return

    cnt += 1
    print(cnt, "th flow")

    rule = "table_add is_hot_flow tre_flag_on %s %s %d %d %d => %d %d 0x0A0A0001" % (p["srcIP"], p["dstIP"], p["proto"], p["srcPort"], p["dstPort"], hash_base, hash_max)
    print rule
    cmd = 'echo \"%s\" | /home/p4/behavioral-model/targets/simple_switch/sswitch_CLI --thrift-port 9090' % rule
    time.sleep(0.5)
    os.system(cmd)
    hash_base += bucket_size
    hash_max += bucket_size
    hot_flow_set.add(hot_flow)

pkt_5_tuple = {}
def handle_pkt(pkt):
    global empty, pkt_5_tuple
    # pkt.show()
    # hexdump(pkt)

    pkt_5_tuple["srcIP"] = pkt[IP].src
    pkt_5_tuple["dstIP"] = pkt[IP].dst
    pkt_5_tuple["proto"] = pkt[IP].proto

    if pkt[IP].proto == IPV4_PROTOCOL_TCP:
        pkt_5_tuple["srcPort"] = pkt[TCP].sport
        pkt_5_tuple["dstPort"] = pkt[TCP].dport
    elif pkt[IP].proto == IPV4_PROTOCOL_UDP:
        pkt_5_tuple["srcPort"] = pkt[UDP].sport
        pkt_5_tuple["dstPort"] = pkt[UDP].dport
    elif pkt[IP].proto == SHIM_TCP:
        pkt_5_tuple["srcPort"] = pkt[TCP].sport
        pkt_5_tuple["dstPort"] = pkt[TCP].dport
    elif pkt[IP].proto == SHIM_UDP:
        pkt_5_tuple["srcPort"] = pkt[UDP].sport
        pkt_5_tuple["dstPort"] = pkt[UDP].dport

    print pkt_5_tuple
    populate_hot_flow_rule(pkt_5_tuple)

def main():
    ifaces = filter(lambda i: 'veth11' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = 'veth11',
        prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
