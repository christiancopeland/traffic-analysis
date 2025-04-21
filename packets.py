import scapy
from scapy.all import *

from collections import Counter


def get_pkts(iface: str = 'wlp9s0', count: int = 1000, loadFile: str = None, debug: bool = False):
    if loadFile:
        packets = rdpcap(loadFile)
    else:
        packets = sniff(iface=iface,count=100)
        wrpcap('captured_packets.pcap', packets)
    if debug:
        # Debug: Print packets captured 
        print(f"*"*20,"Packets Captured","*"*20)
        for packet in packets:
            print(packet.summary())
        print(f"*"*56)
    return packets


def analyze_pkts(pkts):
    protocol_count = Counter()
    for pkt in pkts:
        # Analyze traffic type
        if TCP in pkt:
            protocol_count['TCP'] += 1
        elif UDP in pkt:
            protocol_count['UDP'] += 1
        elif 'mDNS Qry' in str(pkt):
            protocol_count['mDNS_Query'] += 1
        elif 'mDNS Ans' in str(pkt):
            protocol_count['mDNS_Answer'] += 1
        elif 'ICMPv6ND_NS' in str(pkt):
            protocol_count["ICMPv6_Neighbor_Solicitation"] += 1
        elif 'ICMPv6 Neighbor Discovery - Neighbor Advertisement' in str(pkt):
            protocol_count["ICMP_Neighbor_Advertisement"] += 1
        elif ARP in pkt:
            protocol_count['ARP'] += 1
        elif 'LLC' and 'STP' in str(pkt):
            protocol_count['LLC/STP'] += 1
        elif 'LLC' and 'SNAP' in str(pkt):
            protocol_count['LLC/SNAP'] += 1
        else:
            protocol_count['Other'] += 1
    print(f"Protocol Count: {protocol_count}")
    return protocol_count