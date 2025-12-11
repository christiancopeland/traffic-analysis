# Network Traffic Analyzer Architecture

## System Flow
```
┌─────────────────────────────────────────────────────────────┐
│                    CAPTURE LAYER                             │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Scapy Packet Sniffer                                │   │
│  │  • Captures raw network packets                      │   │
│  │  • Filters by protocol                               │   │
│  │  • Extracts source/destination IPs, ports, protocols│   │
│  └────────────────┬─────────────────────────────────────┘   │
└───────────────────┼──────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────┐
│                  ANALYSIS LAYER                              │
│                                                              │
│  ┌─────────────────────┐  ┌─────────────────────────────┐  │
│  │  Protocol Analyzer  │  │  Network Graph Builder      │  │
│  │  • TCP/UDP/ICMP     │  │  • Nodes: IP addresses      │  │
│  │  • Port analysis    │  │  • Edges: Communications    │  │
│  │  • Statistics       │  │  • NetworkX graph structure │  │
│  └─────────────────────┘  └─────────────────────────────┘  │
└───────────────────┬──────────────────┬───────────────────────┘
                    │                  │
                    ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│                  INTELLIGENCE LAYER                          │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  LLM Analysis Engine (Ollama)                        │   │
│  │  • Receives packet summary statistics                │   │
│  │  • Generates natural language insights               │   │
│  │  • Identifies anomalies and patterns                 │   │
│  └──────────────────────────────────────────────────────┘   │
└───────────────────┬──────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────┐
│               VISUALIZATION LAYER (Dash)                     │
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────┐    │
│  │  Network    │  │  Protocol   │  │   AI-Generated   │    │
│  │  Graph      │  │  Pie Chart  │  │   Markdown       │    │
│  │  (Plotly)   │  │             │  │   Report         │    │
│  └─────────────┘  └─────────────┘  └──────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                    ┌──────────────┐
                    │  Web Browser │
                    │ (Port 8050)  │
                    └──────────────┘
```

## Data Flow Example

**Scenario:** Detecting a port scan

1. **Capture (Scapy):**
```
Packet 1: 192.168.1.100:54321 → 192.168.1.50:22 [SYN]
Packet 2: 192.168.1.100:54322 → 192.168.1.50:23 [SYN]
Packet 3: 192.168.1.100:54323 → 192.168.1.50:80 [SYN]
... (100 more sequential port attempts)
```

2. **Analysis (NetworkX):**
```python
# Build graph
G.add_edge("192.168.1.100", "192.168.1.50", ports_scanned=103)

# Calculate metrics
degree_centrality["192.168.1.100"] = 0.85  # High - scanning many ports
```

3. **Intelligence (LLM):**
```
Input to LLM: "Source IP 192.168.1.100 connected to 103 different ports on 
192.168.1.50 over 30 seconds. All connections TCP SYN only, no established 
connections."

LLM Output: "ALERT: Potential port scanning activity detected. Source 
192.168.1.100 performed reconnaissance on 192.168.1.50, attempting 
connections to 103 sequential ports. This pattern is consistent with 
automated scanning tools (nmap, masscan). Recommend: (1) Check if source 
IP is authorized scanning tool, (2) Review firewall logs for additional 
activity, (3) Consider blocking source if unauthorized."
```

4. **Visualization:**
- Graph shows large node (192.168.1.50) with many incoming edges from scanner
- Pie chart shows TCP SYN packets = 95% of traffic
- Report displays LLM alert in Markdown

## Security Operations Relevance

This architecture mirrors SOC workflows:

1. **Capture = EDR/Network Sensors:** Collect raw telemetry
2. **Analysis = SIEM Correlation:** Process and enrich data
3. **Intelligence = Threat Intel Feeds:** Contextualize findings
4. **Visualization = Analyst Dashboard:** Present actionable insights
