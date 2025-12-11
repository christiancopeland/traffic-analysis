# Internal Imports
from visualization import generate_graph, generate_nodes_edges, draw_graph, create_protocol_pie_chart
from packets import get_pkts, analyze_pkts
from utils import get_args, networkx_to_plotly
from llm import llm

import networkx as nx
import matplotlib.pyplot as plt
import dash 
from dash import dcc, html, Output, Input
import numpy as np 
import logging 
import time 


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

app.layout = html.Div([
    html.Button("Refresh", id="refresh-btn", n_clicks=0),
    dcc.Loading([
    dcc.Graph(id='network-graph'), 
    html.P("Protocol Counts:"), 
    html.Img(id="pie-chart", style={'width': '50%'}),
    html.P("Packet Report:"),
    dcc.Markdown(id="packet-report-markdown")])
    ])

@app.callback(
    Output("network-graph", "figure"),
    Output("pie-chart", "src"),
    Output("packet-report-markdown", "children"),
    Input("refresh-btn", "n_clicks")
)

def update_dashboard(n_clicks):
    start = time.time()
    if loadPcap:
        packets = get_pkts(iface=interface, loadFile=loadPcap, debug=debug)
    else:
        packets = get_pkts(iface=interface, count=pktCount)
        t_packets = time.time()
        print(f"Packet Capture Speed: {t_packets - start}s")

    # Extract relevant packet attributes
    traffic_type_counter = analyze_pkts(packets)
    logger.debug(f"Traffic Type Counter Output: \n{traffic_type_counter}\n")
    t_analysis = time.time()
    print(f"Traffic Analysis Speed: {t_analysis - start}")

    pie_chart_img = create_protocol_pie_chart(traffic_type_counter)
    pie_time = time.time()
    print(f"Pie Chart Speed: {pie_time - start}")

    nodes, edges = generate_nodes_edges(packets)
    logger.debug(f"Nodes:\n{nodes}\nEdges:\n{edges}\n")
    node_edge_time = time.time()
    print(f"Node and Edge Speed: {node_edge_time - start}")

    packet_report = llm.packet_report(packets, traffic_type_counter, edges)
    report_time = time.time()
    print(f"LLM Report Time: {report_time - start}")

    G, pos, edge_weights = generate_graph(nodes, edges)
    logger.debug(f"Graph Object:\n{G}\nPos Object:\n{pos}\nEdge Weights Object:\n{edge_weights}\n")
    graph_time = time.time()
    print(f"Graph Generation Time: {graph_time - start}")

    plt.figure(figsize=(12, 8))

    # draw_graph(G, pos, edge_weights)
    return networkx_to_plotly(G), pie_chart_img, packet_report





if __name__ == '__main__':

    app.run(debug=True)
