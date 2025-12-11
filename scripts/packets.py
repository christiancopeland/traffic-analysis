import scapy
from scapy.all import *
import requests
import logging
import socket

from collections import Counter


logging.basicConfig(
    filename="network_log.log",  
    level=logging.DEBUG,  
    format="%(asctime)s - %(levelname)s - %(message)s", 
)
logger = logging.getLogger(__name__)

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

def save_packets_to_pcap(packets, filename):
    from scapy.utils import wrpcap
    wrpcap(filename, packets)


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

def url_lookup(ip_set):
    ip_list = list(ip_set)
    url_map = {}
    import socket 
    try:
        for ip in ip_list:
            hostname = socket.gethostbyaddr(ip)
            url_map[ip] = hostname
        return url_map
    except Exception as e:
        logger.error(f"Error in packets.url_lookup(): {e}")

def batch_ip_lookup(ip_set):
    # Convert set to list for JSON serialization
    ip_list = list(ip_set)
    print(f"List of ips being sent: {ip_list}")
    # Optionally: filter out local/multicast
    def is_public(ip):
        # Very basic filter; for production use ipaddress module
        return not (ip.startswith("10.") or
                    ip.startswith("192.168.") or
                    ip.startswith("172.16.") or
                    ip.startswith("172.17.") or
                    ip.startswith("172.18.") or
                    ip.startswith("172.19.") or
                    ip.startswith("172.20.") or
                    ip.startswith("172.21.") or
                    ip.startswith("172.22.") or
                    ip.startswith("172.23.") or
                    ip.startswith("172.24.") or
                    ip.startswith("172.25.") or
                    ip.startswith("172.26.") or
                    ip.startswith("172.27.") or
                    ip.startswith("172.28.") or
                    ip.startswith("172.29.") or
                    ip.startswith("172.30.") or
                    ip.startswith("172.31.") or
                    ip.startswith("127.") or
                    ip.startswith("224.") or
                    ip.startswith("255."))
    # Remove non-public IPs
    ip_list = [ip for ip in ip_list if is_public(ip)]
    print(f"List of ips being sent: {ip_list}")
    if not ip_list:
        return {}
    endpoint = "http://ip-api.com/batch?fields=status,country,city,regionName,zip,lat,lon,isp,org,as,query"
    headers = {"Content-Type": "application/json"}  # Make sure to set explicit header
    response = requests.post(endpoint, json=ip_list, headers=headers)
    print(f"IP Metadata Response: {response.raw}")
    if response.status_code != 200:
        print(f"[ip-api ERROR] HTTP {response.status_code}: {response.text}")
        return {}
    try:
        data = response.json()
        print(data)
    except Exception as e:
        print(f"[ip-api ERROR] Failed to parse JSON: {e}")
        print(f"Response content: {response.text[:200]}")
        return {}
    logger.debug(f"IP-API Results for IP Metadata: {response.json()}")
    return {item["query"]: item for item in data if item.get("status") == "success"}