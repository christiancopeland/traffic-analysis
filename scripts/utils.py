import argparse
import re 
import logging 
from io import BytesIO
import traceback
import matplotlib.pyplot as plt 
import tempfile 
import os

import networkx as nx
import plotly.graph_objects as go

logging.basicConfig(
    filename="network_log.log",  
    level=logging.DEBUG,  
    format="%(asctime)s - %(levelname)s - %(message)s", 
)
logger = logging.getLogger(__name__)

def get_args():
    parser = argparse.ArgumentParser(prog="A simple network diagramming and traffic analysis tool")
    parser.add_argument("-d", '--debug', dest='debug', help="Specify whether you want debug printing in the terminal", type=bool)
    parser.add_argument('-lf', '--load_file', dest='pcap', help="Specify a pcap file you want to generate from instead of performing a new capture", type=str)
    parser.add_argument('-pc', '--packet_count', dest='packetCount', help="Specify number of packets you want to capture", type=int)
    parser.add_argument('-i', '--interface', dest='interface', help="Specify the interface you want to sniff packets from if not using a previously generated pcap file", type=str)
    parser.add_argument('-g', '--graph', dest='graph', help="Specify whether you want to graph or not", type=bool)
    parser.add_argument('-p', '--packet_anal', dest='packetAnal', help="Specify whether you want to run packet analysis", type=bool)
    args = parser.parse_args()
    return args


def scrape_byte_string(pkt):
    pattern = r"b'([^']*)'"
    match = re.search(pattern, pkt)
    if match:
        print(f"Extracted Node: {match.group(1)}")



def networkx_to_plotly(G, ip_metadata, url_map):
    # Extract positions for nodes
    pos = nx.spring_layout(G)  # You can use other layouts like nx.circular_layout(G)
    node_x = []
    node_y = []
    node_labels = []
    node_hovers = []

    # Iterate over nodes
    for node, (x, y) in pos.items():
        node_x.append(x)
        node_y.append(y)
        node_labels.append(str(node))  # Node label
        meta = ip_metadata.get(str(node), {})
        url = url_map[str(node)]
        hover = f"<b>IP:</b> {str(node)}"
        if meta:
            hover += f"<br><b>URL:</b> {url[0]}"
            hover += f"<br><b>City:</b> {meta.get('city','')}"
            hover += f"<br><b>Region:</b> {meta.get('regionName','')}"
            hover += f"<br><b>Country:</b> {meta.get('country','')}"
            hover += f"<br><b>ISP:</b> {meta.get('isp','')}"
            hover += f"<br><b>Org:</b> {meta.get('org','')}"
            hover += f"<br><b>ASN:</b> {meta.get('as','')}"
            
        node_hovers.append(hover)

    # Create edge traces
    edge_x = []
    edge_y = []
    for edge in G.edges:
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])  # None separates line segments
        edge_y.extend([y0, y1, None])

    # Create edge trace
    edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=0.5, color='#888'), hoverinfo='none', mode='lines')

    # Create node trace
    node_trace = go.Scatter(
        x=node_x, 
        y=node_y, 
        mode='markers+text', 
        text=node_labels, 
        textposition="top center", 
        hovertext=node_hovers,
        hoverinfo="text",
        marker=dict(
            showscale=True, 
            colorscale='YlGnBu', 
            size=10, 
            colorbar=dict(
                thickness=15, 
                title='Node Connections', 
                xanchor='left',), 
                color=[],))

    # Map color to degree (number of edges per node)
    node_adjacencies = []
    for node in G.nodes:
        node_adjacencies.append(len(list(G.adj[node])))
    node_trace.marker.color = node_adjacencies

    # Combine edge and node traces into a Plotly figure
    fig = go.Figure(
        data=[edge_trace, node_trace],
        # data=[edge_trace],
        layout=go.Layout(
            title='Network Graph',
            # titlefont_size=16,
            showlegend=False,
            hovermode='closest',
            margin=dict(b=40, l=40, r=40, t=40),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                    ))
    return fig  


def create_graph_image(G):
    logger.debug("Starting create_graph_image.")
    buf = BytesIO()
    try:
        plt.figure(figsize=(20,12), dpi=500)
        nx.draw_networkx(G, with_labels=True, node_color="#87ceeb", edge_color='#333', font_size=16, node_size=1200)
        plt.axis('off')
        plt.tight_layout()
        plt.savefig(buf, format="png", bbox_inches="tight", pad_inches=0.15)
        plt.close()
        buf.seek(0)
        logger.debug("Graph drawn and image saved to buffer.")

        # Save to a temporary file
        tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
        logger.debug(f"Writing to tmp file: {tmp_file.name}")
        tmp_file.write(buf.read())
        tmp_file.flush()
        tmp_file.close()
        logger.debug(f"Image written and tmp file closed: {tmp_file.name}")
        return tmp_file.name  # Return the file path
    except Exception as e:
        logger.error(f"Error creating graph image: {e}\n{traceback.format_exc()}")
        raise