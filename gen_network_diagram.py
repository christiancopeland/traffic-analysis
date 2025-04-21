# Internal Imports
from visualization import generate_graph, generate_nodes_edges, draw_graph, create_protocol_pie_chart
from packets import get_pkts, analyze_pkts
from utils import get_args, networkx_to_plotly
from llm import llm

import networkx as nx
import matplotlib.pyplot as plt
import dash 
from dash import dcc, html
import numpy as np 
import logging 


logging.basicConfig(
    filename="network_log.log",  
    level=logging.DEBUG,  
    format="%(asctime)s - %(levelname)s - %(message)s", 
)
logger = logging.getLogger(__name__)  



if __name__ == '__main__':
    args = get_args()
    debug = args.debug
    loadPcap = args.pcap
    pktCount = args.packetCount
    interface = args.interface
    graph = args.graph 
    packetAnal = args.packetAnal

    llm = llm()

    if loadPcap:
        packets = get_pkts(iface=interface, loadFile=loadPcap, debug=debug)

    packets = get_pkts(iface=interface, count=pktCount)

    # Extract relevant packet attributes
    traffic_type_counter = analyze_pkts(packets)
    logger.debug(f"Traffic Type Counter Output: \n{traffic_type_counter}\n")

    nodes, edges = generate_nodes_edges(packets)
    logger.debug(f"Nodes:\n{nodes}\nEdges:\n{edges}\n")

    packet_report = llm.packet_report(packets, traffic_type_counter, edges)

    G, pos, edge_weights = generate_graph(nodes, edges)
    logger.debug(f"Graph Object:\n{G}\nPos Object:\n{pos}\nEdge Weights Object:\n{edge_weights}\n")

    plt.figure(figsize=(12, 8))

    draw_graph(G, pos, edge_weights)

    app = dash.Dash(__name__)

    pie_chart_img = create_protocol_pie_chart(traffic_type_counter)

    app.layout = html.Div([
        dcc.Graph(id='network-graph', figure=networkx_to_plotly(G)), 
        html.P("Protocol Counts:"), 
        html.Img(src=pie_chart_img, style={'width': '50%'}),
        html.P("Packet Report:"),
        dcc.Markdown(packet_report, style={})])

    app.run(debug=True)
