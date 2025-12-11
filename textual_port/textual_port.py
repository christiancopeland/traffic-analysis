
# External Imports
import time
import asyncio
import threading
import logging
import matplotlib.pyplot as plt 
import networkx as nx 
from io import BytesIO
import tempfile 
import os
import traceback
import sys 
import subprocess


from tabulate import tabulate

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Button, Static, Markdown, TextArea
from textual.containers import Vertical, Horizontal
from textual.reactive import reactive

from PIL import Image as PILImage
from textual_imageview.viewer import ImageViewer

# Internal Imports
from scripts.packets import get_pkts, analyze_pkts
from scripts.visualization import generate_nodes_edges, create_protocol_pie_chart
from scripts.llm import llm
from scripts.utils import create_graph_image


logging.basicConfig(
    filename="network_log.log",  
    level=logging.DEBUG,  
    format="%(asctime)s - %(levelname)s - %(message)s", 
)
logger = logging.getLogger(__name__)


class DashboardState:
    def __init__(self):
        self.latest_packets = []
        self.counter = {}
        self.nodes = set()
        self.edges = []
        self.lock = threading.Lock()
        self.llm_busy = False 
        self.llm_lock = threading.Lock()


class NetTrafficApp(App):
    """Terminal UI for Live Network Traffic Dashboard"""
    CSS_PATH = "../styles.css"
    mode = reactive("live")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state = DashboardState()
        self.background_thread = None
        self.last_graph_path = None
        self.blank_img = PILImage.new("RGB", (480, 320), color="black")
        self.image_viewer = ImageViewer(self.blank_img)
        self.graph_container = None

    def compose(self) -> ComposeResult:
        yield Header()
        yield Horizontal(
            Button("Refresh", id="refresh"),
            Button("Open Graph Externally", id="open-externally"),
            Button("Exit", id="exit")
        )
        yield Static("Network Traffic Dashboard", id="title")
        yield Static("Network Graph:", id="graph-title")  # ← Moved out of image container!
        yield Horizontal(
            Vertical(
                self.image_viewer,
                id="image-container"
            ),
            Vertical(
                Static("Protocol Breakdown:", id="proto-title"),
                TextArea("Pie/Bar Chart Here", id="chart-panel"), markup=False
            ),
            classes="main-row"
        )
        yield Vertical(
            Static("Packet Report:", id="report-title"),
            Markdown("No report yet...", id="report-panel")
        )
        yield Footer()
    
    def update_graph_panel(self, G):
        img_path = create_graph_image(G)
        logger.debug(f"Graph image written to: {img_path}")
        if not os.path.isfile(img_path):
            logger.error(f"Image file does not exist: {img_path}")
        else:
            logger.debug(f"Image file exists: {img_path} (size: {os.path.getsize(img_path)} bytes)")
        image_container = self.query_one("#image-container", Vertical)
        avail_width, avail_height = image_container.size
        char_width, char_height = avail_width, avail_height
        img_w = char_width * 2
        img_h = char_height * 4
        with PILImage.open(img_path) as img:
            target_size = (960, 540)
            pil_img = img.convert("RGB").resize((img_w, img_h))
        logger.debug(f"PIL Image loaded: {pil_img}")
        if self.last_graph_path and os.path.exists(self.last_graph_path):
            try:
                os.remove(self.last_graph_path)
                logger.debug(f"Removed previous temporary graph image file: {self.last_graph_path}")
            except Exception as e:
                logger.error(f"Error removing last network graph tmp file: {e}\n{traceback.format_exc()}")
        self.last_graph_path = img_path

        try:
            logger.debug(f"Setting viewer.image with PIL image object: {pil_img}")
            new_viewer = ImageViewer(pil_img)

            for child in list(image_container.children):
                child.remove()
            image_container.mount(new_viewer)
            self.image_viewer = new_viewer
            logger.debug("ImageViewer.image set successfully")
        except Exception as e:
            logger.error(f"Failed to update ImageViewer: {e}\n{traceback.format_exc()}")

    def post_packet_update(self):
        # Thread-safe: Called by background thread after capturing
        with self.state.lock:
            nodes = self.state.nodes
            edges = self.state.edges
            logger.debug(f"Nodes: {nodes}")
            logger.debug(f"Edges: {edges}")
        if nodes and edges:
            logger.debug("Nodes and edges found, constructing graph.")
            G = nx.DiGraph()
            G.add_nodes_from(nodes)
            G.add_edges_from(edges)
        
            self.update_graph_panel(G)
        else:
            logger.info("No nodes/edges to draw; Not updating ImageViewer.")

        # Update chart panel
        proto_rows = [(k, v) for k, v in self.state.counter.items()]
        proto_str = tabulate(proto_rows, headers=["Protocol", "Count"], tablefmt="rounded_grid")
        self.query_one("#chart-panel", TextArea).text = proto_str
        logger.debug("Updated chart-panel with protocol counts")

        try:
                
            # Update report panel
            self.query_one("#report-panel", Markdown).update(
                "[Packet data updated. Click refresh for LLM report.]"
            )
            logger.debug("Updated report-panel with new markdown")

        except Exception as e:
            logger.error(f"Error updating report-panel: {e}\n{traceback.format_exc()}")

# ===== LLM Functions =====
    def refresh_dashboard_llm(self):
        with self.state.llm_lock:
            if self.state.llm_busy:
                self.query_one("#report-panel", Markdown).update(
                    "[LLM report is currently running, please wait...]")
                return 
            self.state.llm_busy = True
        # Run in a background thread since LLM call may be slow
        threading.Thread(target=self.generate_llm_report, daemon=True).start()

    def generate_llm_report(self):
        try:
            with self.state.lock:
                pkts = self.state.latest_packets.copy()
                counter = dict(self.state.counter)
                nodes = self.state.nodes
                edges = self.state.edges

            if not pkts:
                report = "[No packets available for report.]"
            else:
                try:
                    packet_llm = llm()
                    report = packet_llm.packet_report(pkts, counter, edges)
                except Exception as e:
                    report = f"[LLM report error: {e}]"
            # Schedule the update on the UI thread
            self.call_from_thread(self.update_llm_report, report)
        finally:
            with self.state.llm_lock:
                self.state.llm_busy = False
        
    def update_llm_report(self, report_md):
        self.query_one("#report-panel", Markdown).update(report_md)
# ===== LLM Functions =====

    def background_capture(self, iface:str='wlp9s0', count=10, interval=15):
        while True:
            try:
                pkts = get_pkts(iface=iface, count=count)
                logger.debug(f"Captured {count} packets.")
                counter = analyze_pkts(pkts)
                logger.debug(f"Packet protocol counter successfully generated: {counter}")
                nodes, edges = generate_nodes_edges(pkts)
                with self.state.lock:
                    self.state.latest_packets = pkts
                    self.state.counter = counter
                    self.state.nodes = nodes
                    self.state.edges = edges
            except Exception as e:
                # You may want to add logging here
                logger.error(f"Error in background_capture(): {e}")
                raise
            # Now update the UI from the thread
            app.call_from_thread(app.post_packet_update)
            time.sleep(interval)

    def open_graph_externally(self):
        if not self.last_graph_path or not os.path.exists(self.last_graph_path):
            self.query_one("#report-panel", Markdown).update(
                f"[Error: No graph image available to open.]"
            )
            logger.warning("Tried to open graph externally but file does not exist.")
            return
        try:
            if sys.platform.startswith("darwin"):  # macOS
                subprocess.Popen(["open", self.last_graph_path])
            elif os.name == "nt":  # Windows
                os.startfile(self.last_graph_path)
            elif os.name == "posix":  # Linux/BSD
                subprocess.Popen(["xdg-open", self.last_graph_path])
            else:
                self.query_one("#report-panel", Markdown).update(
                    f"[Error: Unsupported OS for external viewer.]"
                )
                logger.error("Unsupported OS for opening external viewer.")
        except Exception as e:
            self.query_one("#report-panel", Markdown).update(
                f"[Error: Could not open external image viewer: {e}]"
            )
            logger.error(f"Failed to open graph image externally: {e}")


    async def on_mount(self):
        if not self.background_thread:
            logger.debug("Starting background packet capture thread.")
            self.background_thread = threading.Thread(
                target=self.background_capture,
                args=('wlp9s0', 10, 15),
                daemon=True
            )
            self.background_thread.start()
            logger.debug("Background packet capture thread started!")


    async def on_button_pressed(self, event):
        if event.button.id == "refresh":
            await self.refresh_dashboard()
            self.refresh_dashboard_llm()
        elif event.button.id == "open-externally":
            self.open_graph_externally()
        elif event.button.id == "exit":
            await self.action_quit()

    async def refresh_dashboard(self):
        self.post_packet_update()


if __name__ == "__main__":
    app = NetTrafficApp()
    app.run()
