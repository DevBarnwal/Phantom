#!/usr/bin/env python3
"""
gui.py
Main GUI application for the packet sniffer.

Upgrades in this version:
  1. Color-coded rows  — each protocol gets a distinct tag color
  2. Search / filter bar — live search by IP, protocol, or keyword
  3. Packet detail popup — double-click any row for full layer breakdown
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import logging
from packet_sniffer import PacketSniffer
from packet_analyzer import PacketAnalyzer
from config import (
    DEFAULT_WINDOW_SIZE, DEFAULT_WINDOW_MIN_SIZE, PACKET_QUEUE_UPDATE_INTERVAL,
    PACKET_DISPLAY_COLUMNS, PROTOCOL_FILTERS, SUPPORTED_FILE_TYPES
)

logger = logging.getLogger(__name__)

# ── 1. COLOR MAP ────────────────────────────────────────────────────────────
# Each protocol maps to (background, foreground).
# These work well on both light and dark Tk themes.
PROTOCOL_COLORS = {
    "HTTPS":  ("#1a3a5c", "#7ec8f7"),   # dark blue  / light blue text
    "HTTP":   ("#1a3a5c", "#7ec8f7"),
    "TCP":    ("#1c3a5c", "#90caf9"),
    "UDP":    ("#1a3d2b", "#80cfa0"),   # dark green / light green text
    "DNS":    ("#3d3010", "#f9d45a"),   # dark amber / yellow text
    "ICMP":   ("#3a1f00", "#ffaa55"),   # dark orange / orange text
    "ARP":    ("#2a1040", "#c084fc"),   # dark purple / lavender text
    "OTHER":  ("#2a2a2a", "#aaaaaa"),   # dark gray  / muted text
}


class SnifferGUI:
    """Main GUI application for packet sniffing and analysis."""

    def __init__(self, root):
        self.root = root
        self.sniffer = PacketSniffer()
        self.packet_count = 0

        # Stores ALL captured packet_info dicts so search can re-filter them
        self._all_packets = []

        self._setup_window()
        self._create_widgets()
        self._setup_row_colors()
        self._setup_bindings()

        # Start GUI update loop
        self.root.after(PACKET_QUEUE_UPDATE_INTERVAL, self._update_gui)

        logger.info("GUI initialized successfully")

    # ── WINDOW SETUP ────────────────────────────────────────────────────────

    def _setup_window(self):
        """Configure main window properties."""
        self.root.title("Advanced Packet Sniffer & Analyzer")
        self.root.geometry(DEFAULT_WINDOW_SIZE)
        self.root.minsize(*DEFAULT_WINDOW_MIN_SIZE)
        self.root.resizable(True, True)

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(2, weight=1)   # row 2 is now the tree (search bar is row 1)

    # ── WIDGET CREATION ─────────────────────────────────────────────────────

    def _create_widgets(self):
        self._create_control_frame()    # row 0
        self._create_search_bar()       # row 1  ← NEW
        self._create_main_frame()       # row 2
        self._create_status_frame()     # row 3

    def _create_control_frame(self):
        """Control panel — interface, filter dropdown, action buttons."""
        ctrl_frame = ttk.LabelFrame(self.root, text="Capture Controls", padding=10)
        ctrl_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=5)
        ctrl_frame.columnconfigure(1, weight=1)
        ctrl_frame.columnconfigure(3, weight=1)

        ttk.Label(ctrl_frame, text="Interface:").grid(row=0, column=0, sticky="w", padx=(0, 5))

        self.interface_var = tk.StringVar()
        interfaces = self.sniffer.get_interfaces()
        self.interface_combo = ttk.Combobox(
            ctrl_frame,
            textvariable=self.interface_var,
            values=interfaces,
            state="readonly",
            width=30
        )
        self.interface_combo.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        if interfaces:
            self.interface_combo.current(0)

        ttk.Label(ctrl_frame, text="Filter:").grid(row=0, column=2, sticky="w", padx=(0, 5))

        self.filter_var = tk.StringVar(value="ALL")
        self.filter_combo = ttk.Combobox(
            ctrl_frame,
            textvariable=self.filter_var,
            values=list(PROTOCOL_FILTERS.keys()),
            state="readonly",
            width=10
        )
        self.filter_combo.grid(row=0, column=3, sticky="ew", padx=(0, 10))

        button_frame = ttk.Frame(ctrl_frame)
        button_frame.grid(row=0, column=4, sticky="e")

        self.start_btn = ttk.Button(
            button_frame,
            text="Start Capture",
            command=self._start_capture,
            style="Accent.TButton"
        )
        self.start_btn.pack(side="left", padx=2)

        self.stop_btn = ttk.Button(
            button_frame,
            text="Stop Capture",
            command=self._stop_capture,
            state="disabled"
        )
        self.stop_btn.pack(side="left", padx=2)

        self.clear_btn = ttk.Button(
            button_frame,
            text="Clear",
            command=self._clear_packets
        )
        self.clear_btn.pack(side="left", padx=2)

        self.save_btn = ttk.Button(
            button_frame,
            text="Save PCAP",
            command=self._save_packets
        )
        self.save_btn.pack(side="left", padx=2)

    # ── 2. SEARCH BAR ───────────────────────────────────────────────────────

    def _create_search_bar(self):
        """Live search bar — filters the displayed packet list instantly."""
        search_frame = ttk.Frame(self.root)
        search_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 4))
        search_frame.columnconfigure(1, weight=1)

        ttk.Label(search_frame, text="Search:").grid(row=0, column=0, sticky="w", padx=(0, 6))

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self._on_search_change)

        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.grid(row=0, column=1, sticky="ew")

        clear_btn = ttk.Button(search_frame, text="✕", width=3,
                               command=lambda: self.search_var.set(""))
        clear_btn.grid(row=0, column=2, padx=(4, 0))

    def _on_search_change(self, *_):
        """Re-render the treeview whenever the search text changes."""
        self._redraw_tree()

    def _redraw_tree(self):
        """Clear the treeview and re-insert packets that match the current search."""
        query = self.search_var.get().lower().strip()

        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)

        for pkt in self._all_packets:
            if self._packet_matches_search(pkt, query):
                self._insert_packet_row(pkt)

    def _packet_matches_search(self, pkt, query):
        """Return True if any visible field contains the query string."""
        if not query:
            return True
        haystack = " ".join([
            pkt.get("timestamp", ""),
            pkt.get("src", ""),
            pkt.get("dst", ""),
            pkt.get("protocol", ""),
            str(pkt.get("length", "")),
            pkt.get("info", ""),
        ]).lower()
        return query in haystack

    # ── MAIN FRAME / TREEVIEW ───────────────────────────────────────────────

    def _create_main_frame(self):
        main_frame = ttk.Frame(self.root)
        main_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)
        self._create_packet_tree(main_frame)

    def _create_packet_tree(self, parent):
        tree_frame = ttk.Frame(parent)
        tree_frame.grid(row=0, column=0, sticky="nsew")
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        columns = list(PACKET_DISPLAY_COLUMNS.keys())
        self.packet_tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        for col, cfg in PACKET_DISPLAY_COLUMNS.items():
            self.packet_tree.heading(col, text=col.upper(),
                                     command=lambda c=col: self._sort_column(c, False))
            self.packet_tree.column(col, width=cfg["width"], anchor=cfg["anchor"])

        v_scroll = ttk.Scrollbar(tree_frame, orient="vertical",
                                 command=self.packet_tree.yview)
        h_scroll = ttk.Scrollbar(tree_frame, orient="horizontal",
                                 command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=v_scroll.set,
                                   xscrollcommand=h_scroll.set)

        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")

    # ── 1. ROW COLOR TAGS ───────────────────────────────────────────────────

    def _setup_row_colors(self):
        """Register a Treeview tag for every protocol color."""
        for proto, (bg, fg) in PROTOCOL_COLORS.items():
            self.packet_tree.tag_configure(proto, background=bg, foreground=fg)

    def _protocol_tag(self, protocol: str) -> str:
        """Return the tag name to use for a given protocol string."""
        return protocol if protocol in PROTOCOL_COLORS else "OTHER"

    # ── STATUS BAR ──────────────────────────────────────────────────────────

    def _create_status_frame(self):
        status_frame = ttk.Frame(self.root)
        status_frame.grid(row=3, column=0, sticky="ew", padx=10, pady=5)
        status_frame.columnconfigure(1, weight=1)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var).grid(
            row=0, column=0, sticky="w")

        self.count_var = tk.StringVar(value="Packets: 0")
        ttk.Label(status_frame, textvariable=self.count_var).grid(
            row=0, column=2, sticky="e")

    # ── BINDINGS ────────────────────────────────────────────────────────────

    def _setup_bindings(self):
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.packet_tree.bind("<Double-1>", self._on_packet_double_click)

    # ── CAPTURE CONTROL ─────────────────────────────────────────────────────

    def _start_capture(self):
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Error", "Please select a network interface.")
            return

        protocol_filter = self.filter_var.get()
        bpf_filter = PROTOCOL_FILTERS.get(protocol_filter, "")

        if self.sniffer.start_capture(interface, bpf_filter):
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.interface_combo.config(state="disabled")
            self.status_var.set(f"Capturing on {interface} ({protocol_filter})")
            self._clear_display()
            logger.info(f"Started capture on {interface} with filter: {protocol_filter}")
        else:
            messagebox.showerror("Error", "Failed to start packet capture.")

    def _stop_capture(self):
        self.sniffer.stop_capture()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.interface_combo.config(state="readonly")
        self.status_var.set("Capture stopped")
        logger.info("Capture stopped by user")

    def _clear_packets(self):
        if messagebox.askyesno("Clear Packets", "Clear all captured packets?"):
            self.sniffer.clear_data()
            self._clear_display()
            self.status_var.set("Packets cleared")
            logger.info("Packets cleared by user")

    def _clear_display(self):
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        self._all_packets.clear()
        self.packet_count = 0
        self.count_var.set("Packets: 0")

    def _save_packets(self):
        if not self.sniffer.captured_packets:
            messagebox.showinfo("No Packets", "No packets to save.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=SUPPORTED_FILE_TYPES,
            title="Save Captured Packets"
        )
        if filename:
            success, message, count = self.sniffer.save_packets(filename)
            if success:
                messagebox.showinfo("Success", message)
            else:
                messagebox.showerror("Error", message)

    # ── GUI UPDATE LOOP ─────────────────────────────────────────────────────

    def _update_gui(self):
        """Pull new packets from the sniffer queue every 100 ms."""
        packets = self.sniffer.get_packets()

        if packets:
            current_filter = self.filter_var.get()
            query = self.search_var.get().lower().strip()

            for pkt in packets:
                if PacketAnalyzer.matches_filter(pkt, current_filter):
                    self._all_packets.append(pkt)          # always store
                    if self._packet_matches_search(pkt, query):
                        self._insert_packet_row(pkt)       # show if matches search

            stats = self.sniffer.get_statistics()
            self.count_var.set(
                f"Packets: {stats['packet_count']}  "
                f"(Stored: {stats['stored_packets']},  "
                f"Queue: {stats['queue_size']})"
            )

        self.root.after(PACKET_QUEUE_UPDATE_INTERVAL, self._update_gui)

    def _insert_packet_row(self, pkt):
        """Insert one packet into the treeview with its protocol color tag."""
        values = (
            pkt["timestamp"],
            pkt["src"],
            pkt["dst"],
            pkt["protocol"],
            pkt["length"],
            pkt["info"],
        )
        tag = self._protocol_tag(pkt["protocol"])
        self.packet_tree.insert("", "end", values=values, tags=(tag,))
        self.packet_count += 1

        # Auto-scroll only when search is empty (user is watching live traffic)
        if not self.search_var.get():
            children = self.packet_tree.get_children()
            if children:
                self.packet_tree.see(children[-1])

    # kept for backwards compatibility with old code that called this
    def _add_packet_to_display(self, pkt):
        self._insert_packet_row(pkt)

    # ── COLUMN SORT (bonus) ─────────────────────────────────────────────────

    def _sort_column(self, col, reverse):
        """Sort treeview rows by clicked column header."""
        col_keys = list(PACKET_DISPLAY_COLUMNS.keys())
        col_index = col_keys.index(col)

        data = [
            (self.packet_tree.set(child, col), child)
            for child in self.packet_tree.get_children("")
        ]
        # Try numeric sort, fall back to string
        try:
            data.sort(key=lambda t: float(t[0]), reverse=reverse)
        except ValueError:
            data.sort(key=lambda t: t[0].lower(), reverse=reverse)

        for index, (_, child) in enumerate(data):
            self.packet_tree.move(child, "", index)

        # Toggle sort direction on next click
        self.packet_tree.heading(
            col, command=lambda: self._sort_column(col, not reverse)
        )

    # ── 3. PACKET DETAIL POPUP ──────────────────────────────────────────────

    def _on_packet_double_click(self, event):
        """Show a full detail window for the double-clicked packet."""
        selection = self.packet_tree.selection()
        if not selection:
            return

        # Get the row values from the treeview
        item = selection[0]
        values = self.packet_tree.item(item, "values")
        if not values:
            return

        # Find the matching packet_info dict so we can show the raw Scapy layers
        timestamp, src, dst, protocol, length, info = values
        matched_pkt = None
        for p in self._all_packets:
            if (p["timestamp"] == timestamp and
                    p["src"] == src and
                    p["dst"] == dst and
                    p["protocol"] == protocol):
                matched_pkt = p
                break

        self._show_detail_window(values, matched_pkt)

    def _show_detail_window(self, values, pkt_info):
        """Open a Toplevel window with full packet details."""
        timestamp, src, dst, protocol, length, info = values

        win = tk.Toplevel(self.root)
        win.title(f"Packet Detail — {protocol}  {src} → {dst}")
        win.geometry("700x500")
        win.resizable(True, True)

        # ── Summary section ────────────────────────────────────────────────
        summary_frame = ttk.LabelFrame(win, text="Summary", padding=8)
        summary_frame.pack(fill="x", padx=10, pady=(10, 4))

        fields = [
            ("Time",     timestamp),
            ("Source",   src),
            ("Destination", dst),
            ("Protocol", protocol),
            ("Length",   f"{length} bytes"),
            ("Info",     info),
        ]
        for row_i, (label, value) in enumerate(fields):
            ttk.Label(summary_frame, text=label + ":",
                      font=("", 9, "bold")).grid(
                row=row_i, column=0, sticky="w", padx=(0, 10), pady=1)
            ttk.Label(summary_frame, text=value).grid(
                row=row_i, column=1, sticky="w", pady=1)

        # ── Layer breakdown ────────────────────────────────────────────────
        layers_frame = ttk.LabelFrame(win, text="Layer Breakdown", padding=8)
        layers_frame.pack(fill="both", expand=True, padx=10, pady=4)

        text_widget = tk.Text(layers_frame, wrap="word", font=("Courier", 10),
                              state="disabled", relief="flat",
                              bg="#1e1e1e", fg="#d4d4d4",
                              insertbackground="white")
        scroll = ttk.Scrollbar(layers_frame, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scroll.set)

        text_widget.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        # Build the detail text
        detail_lines = []

        if pkt_info and pkt_info.get("packet") is not None:
            raw = pkt_info["packet"]
            # Walk every Scapy layer
            layer = raw
            layer_num = 1
            while layer:
                layer_name = layer.__class__.__name__
                detail_lines.append(f"{'─'*60}")
                detail_lines.append(f"  Layer {layer_num}: {layer_name}")
                detail_lines.append(f"{'─'*60}")
                for field_name, field_val in layer.fields.items():
                    detail_lines.append(f"    {field_name:<22} = {field_val}")
                detail_lines.append("")
                layer = layer.payload if layer.payload else None
                # Stop at Raw/Padding to avoid noise
                if layer and layer.__class__.__name__ in ("Raw", "Padding", "NoPayload"):
                    raw_bytes = bytes(layer)
                    detail_lines.append(f"{'─'*60}")
                    detail_lines.append(f"  Layer {layer_num+1}: Raw Payload  ({len(raw_bytes)} bytes)")
                    detail_lines.append(f"{'─'*60}")
                    detail_lines.append("  Hex:")
                    # Hex dump, 16 bytes per line
                    for i in range(0, len(raw_bytes), 16):
                        chunk = raw_bytes[i:i+16]
                        hex_part = " ".join(f"{b:02x}" for b in chunk)
                        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                        detail_lines.append(f"    {i:04x}  {hex_part:<48}  {asc_part}")
                    break
                layer_num += 1
        else:
            # Fallback: just show the summary values
            detail_lines.append("Raw packet data not available.")
            detail_lines.append("")
            detail_lines.append(f"  Protocol  : {protocol}")
            detail_lines.append(f"  Source    : {src}")
            detail_lines.append(f"  Dest      : {dst}")
            detail_lines.append(f"  Length    : {length} bytes")
            detail_lines.append(f"  Info      : {info}")

        text_widget.config(state="normal")
        text_widget.insert("end", "\n".join(detail_lines))
        text_widget.config(state="disabled")

        # ── Close button ───────────────────────────────────────────────────
        ttk.Button(win, text="Close", command=win.destroy).pack(pady=6)

    # ── CLOSE HANDLER ───────────────────────────────────────────────────────

    def _on_close(self):
        if self.sniffer.is_running:
            if messagebox.askyesno("Quit", "Stop capture and quit?"):
                self.sniffer.stop_capture()
                self.root.destroy()
        else:
            self.root.destroy()


# ── ENTRY POINT ─────────────────────────────────────────────────────────────

def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    root = tk.Tk()
    app = SnifferGUI(root)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()