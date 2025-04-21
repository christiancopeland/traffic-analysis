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
        You are an expert packet analyser and descriptor. 
        Your mission is to take a payload of packets and provide
        an english description of the traffic. You should explain what 
        nodes in the network are doing, how they are interacting, and why.

        Always respond in markdown format
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
