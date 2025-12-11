import requests 
import logging
import json


from scapy.all import *

logging.basicConfig(
    filename="network_log.log", 
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s", 
)
logger = logging.getLogger(__name__) 

class llm():
    def __init__(self):
        self.model = "qwen2.5-coder:14b"
        self.stream = False
        self.url = "http://127.0.0.1:11434/api/chat"

    def packet_report(self, pkts, traffic_counter, edges):
        """Generate a useful english description of the packets captured"""
        
        system_message = """


    You are a senior network traffic analyst and expert in packet-level analytics. Your job is to review live network traffic and produce actionable, administrator-focused reports in clear, professional English. Your report should:

        Identify and describe the most active nodes, significant connections, and protocol use.

        Highlight any unusual, suspicious, or potentially malicious activity, such as traffic spikes, scanning, DDoS patterns, or protocol anomalies.

        Suggest any security or performance optimizations based on observed data.

        Present findings in Markdown, organized into the following sections:

           - Summary

           - Key Nodes and Activity

           - Unusual or Suspicious Patterns

           - Recommendations

           - Details and Observations

        Reference the supplied traffic_counter and network edges in your analysis.

        Avoid jargon; make the report accessible for both technical and non-technical readers.


        """
        packet_str = ""
        for pkt in pkts:
            packet_str += f"\n{pkt.summary()}"

        logger.debug(f"Packet Summaries: {packet_str}")

        packet_message = f"Here is a counter of the different traffic types: {traffic_counter}. Here is the packet payload: {packet_str}. Here are the edges in the network, representing connections: {edges}. Please describe what is happening on the network, point out the main nodes in the network, and anything particular you notice. Be verbose in your description. Provide information that would be helpful for a network administrator, but readable to a lamen."

        messages = [{"role": "system", "content": system_message}, {"role": "user", "content": packet_message}]

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": self.stream
        }
        try:
            response = requests.post(self.url, json=payload)
        except Exception as e:
            logger.error(f"Error sending request to llm server in llm.packet_report(): {e}")

        result = response.json()
        logger.debug(f"Response from model in packet_report(): {result}")

        if result.get("message", {}).get("content"):
            content = result["message"]["content"]
            return content
        else:
            logger.error(f"Error getting content from request result in llm.packet_report: {e}")
