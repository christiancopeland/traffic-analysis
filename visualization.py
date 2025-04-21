from io import BytesIO 
import base64
import networkx as nx
from scapy.all import IP
import plotly.graph_objects as go
import matplotlib.pyplot as plt

from utils import scrape_byte_string



def generate_nodes_edges(pkts):
    nodes = set()
    edges = []
    for pkt in pkts:
        scrape_byte_string(str(pkt))
        # print(f"Packet Summary: {pkt.summary()}")
        # print(f"Packet Layers: {pkt.layers()}")
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            nodes.update([src, dst])  # Add unique nodes
            edges.append((src, dst))  # Create edges

        # print(nodes)
        # print(edges)
    return nodes, edges

def generate_graph(nodes, edges):
    # Step 2: Create a Network Graph
    G = nx.DiGraph()  # Use a directed graph
    G.add_nodes_from(nodes)  # Add nodes
    for src, dst in edges:
        if G.has_edge(src, dst):
            G[src][dst]['weight'] += 1  # Increment traffic count
        else:
            G.add_edge(src, dst, weight=1)  # Add new edge with initial weight

    # Step 3: Visualize the Network Graph
    pos = nx.spring_layout(G)  # Layout for positioning the graph
    edge_weights = [G[u][v]['weight'] for u, v in G.edges()]

    if len(edge_weights) == 0:  # Handle empty graphs
        print("[Error] No edges in the graph. Cannot visualize network diagram.")
        exit(1)
    return G, pos, edge_weights

def draw_graph(G, pos, edge_weights):
    # Draw nodes
    nx.draw_networkx_nodes(G, pos, node_size=700, node_color='lightblue')
    nx.draw_networkx_labels(G, pos)

    # Draw edges with weights
    edge_collection = (nx.draw_networkx_edges(G, pos, edge_color=edge_weights, edge_cmap=plt.cm.Blues, edge_vmin=0, edge_vmax=max(edge_weights)))


def create_protocol_pie_chart(protocol_count):
    # Create a Matplotlib figure
    fig, ax = plt.subplots()
    ax.pie(protocol_count.values(), labels=protocol_count.keys(), autopct='%1.1f%%', colors=plt.cm.Pastel1.colors)
    ax.set_title("Protocol Distribution")

    # Save the figure as a base64-encoded image
    buf = BytesIO()
    plt.savefig(buf, format="png")
    buf.seek(0)
    encoded_image = base64.b64encode(buf.read()).decode("utf-8")
    buf.close()
    plt.close(fig)  # Close the figure to save memory
    return f"data:image/png;base64,{encoded_image}"

