
---

# Network Traffic Analyzer Dashboard

This project is an interactive dashboard for capturing, analyzing, and visually exploring local network packet traffic. It integrates packet sniffing, protocol analysis, network graph visualization, and AI-powered packet reporting—all accessible through a web dashboard.

---

## Features

- **Live Packet Capture:** Sniffs network packets in real-time or loads from PCAP files.
- **Protocol Analysis:** Summarizes and displays protocol usage (TCP, UDP, ARP, etc.).
- **Network Graphs:** Visualizes network nodes and connections using NetworkX and Plotly.
- **AI-Powered Analysis:** Automatic English-language summaries of your network traffic using an LLM (Large Language Model).
- **Interactive Dashboard:** Dash web app for intuitive exploration and insights.

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/christiancopeland/traffic-analysis.git
cd traffic-analysis
```

### 2. Install Dependencies

It is recommended to use [Miniconda](https://docs.conda.io/en/latest/miniconda.html) or [Anaconda](https://www.anaconda.com/products/distribution):

```bash
# Create and activate the environment (replace with your environment setup as needed)
conda create -n scapy python=3.10
conda activate scapy
pip install -r requirements.txt
```

Or, if you use `requirements.txt`:
```bash
pip install -r requirements.txt
```

**Required dependencies include:**  
- scapy  
- dash  
- networkx  
- matplotlib  
- numpy  
- requests 

*(add any others you have in requirements.txt)*

---

### 3. Run the Application

**To start the dashboard:**

```bash
chmod +x run.sh
./run.sh
```
Or, run manually:

```bash
python gen_network_diagram.py -pc 100 -i  -g True -p True
```

- `-pc`: Number of packets to capture (e.g., 100)
- `-i`: Network interface (e.g., `wlp9s0` or `eth0`)
- `-g`: Whether to show the network graph (`True`/`False`)
- `-p`: Whether to show the protocol pie chart (`True`/`False`)

---

## Usage

- Open your web browser and navigate to [http://127.0.0.1:8050](http://127.0.0.1:8050)
- Explore the **network graph** and **protocol pie chart**
- Review the **AI-generated packet report** in Markdown format for high-level insights

---

## Requirements

- Python 3.8+
- Root permissions (needed for packet sniffing)
- Local LLM server available at `http://127.0.0.1:11434/api/chat` (see [`llm.py`])
- [Scapy](https://scapy.net), [Dash](https://dash.plotly.com/), [NetworkX](https://networkx.org/), [Matplotlib](https://matplotlib.org/), [Requests](https://docs.python-requests.org/)

---

## Project Structure

```
.
├── gen_network_diagram.py   # Main dashboard application
├── packets.py               # Packet capture and protocol analysis
├── llm.py                   # LLM request and report generation
├── utils.py                 # Helper functions (argument parsing, etc.)
├── visualization.py         # Graph drawing and chart plotting
├── requirements.txt         # Python dependencies
├── run.sh                   # Shell script to start the app
└── network_log.log          # Log file
```

---

## Notes

- **Root/Sudo required:** Packet sniffing needs elevated privileges.
- **LLM Server:** You must have an LLM server (such as Ollama or OpenAI-compliant API) running locally on port 11434.
- **Network Interface:** Adjust the `-i` flag for your system’s network device (`ifconfig`/`ip a` to list interfaces).
- **Safety:** Only capture packets on networks you have authorization for.

---
