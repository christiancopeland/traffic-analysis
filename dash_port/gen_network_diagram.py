import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scripts')))


# Internal Imports
from visualization import generate_graph, generate_nodes_edges, draw_graph, create_protocol_pie_chart
from packets import get_pkts, analyze_pkts, save_packets_to_pcap, batch_ip_lookup, url_lookup
from utils import get_args, networkx_to_plotly
from llm import llm

import networkx as nx
import matplotlib.pyplot as plt
import dash 
from dash import dcc, html, Output, Input, State
import numpy as np 
import logging 
import time
import hashlib
import threading
from collections import deque
import json



# ========================
# Setup & Configuration
# ========================
logging.basicConfig(
    filename="network_log.log",  
    level=logging.DEBUG,  
    format="%(asctime)s - %(levelname)s - %(message)s", 
)
logger = logging.getLogger(__name__)

args = get_args()
debug = args.debug
loadPcap = args.pcap
pktCount = args.packetCount
interface = args.interface
graph = args.graph 
packetAnal = args.packetAnal

llm = llm()
app = dash.Dash(__name__)

# ========================
# Global State Management
# ========================
class AppState:
    def __init__(self):
        self.latest_packets = []
        self.llm_report_cache = "No report generated yet"
        self.current_data_hash = None
        self.llm_queue = deque()
        self.lock = threading.Lock()
        
        # New visualization cache fields
        self.cached_figure = None
        self.cached_pie_chart = None
        self.cached_analysis = {
            "traffic_counter": {},
            "edges": []
        }

app_state = AppState()

# ========================
# Background Services
# ========================
def background_capture_service(interface, pktCount=100, interval=30):
    """Continuously captures packets and saves to in-memory buffer"""
    while True:
        try:
            new_packets = get_pkts(iface=interface, count=pktCount)
            with app_state.lock:
                app_state.latest_packets = new_packets
                if debug:
                    save_packets_to_pcap(new_packets, "latest_capture.pcap")
            logger.info(f"Captured {len(new_packets)} packets")
        except Exception as e:
            logger.error(f"Capture error: {str(e)}")
        time.sleep(interval)

# Start background capture if not in pcap mode
if not loadPcap and interface:
    capture_thread = threading.Thread(
        target=background_capture_service,
        args=(interface, pktCount),
        daemon=True
    )
    capture_thread.start()

# ========================
# Dashboard Layout
# ========================
app.layout = html.Div([
    html.Button("Refresh", id="refresh-btn", n_clicks=0),
    dcc.Store(id='analysis-cache'),
    dcc.Loading([
        dcc.Graph(id='network-graph'), 
        html.P("Protocol Counts:"), 
        html.Img(id="pie-chart", style={'width': '50%'}),
        html.P("Packet Report:"),
        dcc.Markdown(id="packet-report-markdown")
    ])
])

# ========================
# Core Callbacks
# ========================
@app.callback(
    [Output("network-graph", "figure"),
     Output("pie-chart", "src"),
     Output("analysis-cache", "data")],
    [Input("refresh-btn", "n_clicks")]
)
def update_visualizations(n_clicks):
    """Handles visual updates and triggers LLM processing"""
    with app_state.lock:
        packets = app_state.latest_packets.copy()
    
    if not packets:
        return dash.no_update
    
    # Generate data fingerprint
    data_hash = hashlib.sha256(
        b"".join([bytes(p) for p in packets])
    ).hexdigest()
    
    # Return cached results if data hasn't changed
    if data_hash == app_state.current_data_hash:
        return dash.no_update
        
    # Process packets
    traffic_type_counter = analyze_pkts(packets)
    nodes, edges = generate_nodes_edges(packets)
    ip_url_map = url_lookup(nodes)
    ip_metadata = batch_ip_lookup(nodes)
    print(f"IP Metadata: {ip_metadata}")
    G, pos, edge_weights = generate_graph(nodes, edges)
    pie_chart_img = create_protocol_pie_chart(traffic_type_counter)
    
    # Update caches
    with app_state.lock:
        app_state.current_data_hash = data_hash
        app_state.cached_figure = networkx_to_plotly(G, ip_metadata, ip_url_map)
        app_state.cached_pie_chart = pie_chart_img
        app_state.cached_analysis = {
            "traffic_counter": traffic_type_counter,
            "edges": edges,
            "data_hash": data_hash
        }
    
    # Start LLM processing
    threading.Thread(target=process_llm_report, args=(packets.copy(), traffic_type_counter, edges)).start()
    
    return (
        app_state.cached_figure,
        app_state.cached_pie_chart,
        json.dumps(app_state.cached_analysis)
    )

def process_llm_report(packets, traffic_counter, edges):
    """Background LLM report generation"""
    try:
        report = llm.packet_report(packets, traffic_counter, edges)
        with app_state.lock:
            app_state.llm_report_cache = report
    except Exception as e:
        logger.error(f"LLM error: {str(e)}")


@app.callback(
    Output("packet-report-markdown", "children"),
    [Input("analysis-cache", "modified_timestamp")],
    [State("analysis-cache", "data")]
)
def update_llm_report(ts, data):
    """Updates report when new analysis data exists"""
    if not data:
        return "No report available"
    
    try:
        data = json.loads(data)
        if data.get("data_hash") != app_state.current_data_hash:
            return app_state.llm_report_cache
    except:
        return app_state.llm_report_cache
    
    return app_state.llm_report_cache


    # Process LLM report in background
    def generate_report():
        try:
            report = llm.packet_report(
                current_job["packets"],
                current_job["traffic_counter"],
                current_job["edges"]
            )
            with app_state.lock:
                app_state.llm_report_cache = report
        except Exception as e:
            logger.error(f"LLM error: {str(e)}")
            
    if app_state.llm_queue:
        threading.Thread(target=generate_report).start()
        app_state.llm_queue.pop()  # Remove processed job
    
    return app_state.llm_report_cache

# ========================
# Main Execution
# ========================
if __name__ == '__main__':
    app.run(debug=True)