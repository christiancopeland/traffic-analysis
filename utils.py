import argparse
import re 

import networkx as nx
import plotly.graph_objects as go



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



def networkx_to_plotly(G):
    # Extract positions for nodes
    pos = nx.spring_layout(G)  # You can use other layouts like nx.circular_layout(G)
    node_x = []
    node_y = []
    node_labels = []

    # Iterate over nodes
    for node, (x, y) in pos.items():
        node_x.append(x)
        node_y.append(y)
        node_labels.append(str(node))  # Node label

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
    node_trace = go.Scatter(x=node_x, y=node_y, mode='markers+text', text=node_labels, textposition="top center", marker=dict(showscale=True, colorscale='YlGnBu', size=10, colorbar=dict(thickness=15, title='Node Connections', xanchor='left',), color=[],))

    # Map color to degree (number of edges per node)
    node_adjacencies = []
    for node in G.nodes:
        node_adjacencies.append(len(list(G.adj[node])))
    node_trace.marker.color = node_adjacencies

    # Combine edge and node traces into a Plotly figure
    fig = go.Figure(data=[edge_trace, node_trace],
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