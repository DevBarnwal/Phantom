#!/usr/bin/env python3
"""
gui.py
Main GUI application for the packet sniffer.

Upgrades in this version:
  1. Color-coded rows       — each protocol gets a distinct tag color
  2. Search / filter bar    — live search by IP, protocol, or keyword
  3. Packet detail popup    — double-click any row for full layer breakdown
  4. Column sorting         — click any header to sort
  5. Live stats side panel  — pie chart + bar chart, updates every second
  6. GeoIP column + tooltip — flag/country/city column, hover for full details
  7. Export dropdown        — single button → PCAP / CSV / JSON
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import logging
from collections import defaultdict

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from packet_sniffer import PacketSniffer
from packet_analyzer import PacketAnalyzer
from geo_lookup import GeoLookup
from exporter import export_pcap, export_csv, export_json
from config import (
    DEFAULT_WINDOW_SIZE, DEFAULT_WINDOW_MIN_SIZE, PACKET_QUEUE_UPDATE_INTERVAL,
    PACKET_DISPLAY_COLUMNS, PROTOCOL_FILTERS, SUPPORTED_FILE_TYPES
)

logger = logging.getLogger(__name__)

# ── PROTOCOL COLORS ──────────────────────────────────────────────────────────
PROTOCOL_COLORS = {
    "HTTPS":  ("#1a3a5c", "#7ec8f7"),
    "HTTP":   ("#1a3a5c", "#7ec8f7"),
    "TCP":    ("#1c3a5c", "#90caf9"),
    "UDP":    ("#1a3d2b", "#80cfa0"),
    "DNS":    ("#3d3010", "#f9d45a"),
    "ICMP":   ("#3a1f00", "#ffaa55"),
    "ARP":    ("#2a1040", "#c084fc"),
    "OTHER":  ("#2a2a2a", "#aaaaaa"),
}

CHART_COLORS = {
    "HTTPS": "#7ec8f7", "HTTP":  "#90caf9", "TCP":   "#4a90d9",
    "UDP":   "#80cfa0", "DNS":   "#f9d45a", "ICMP":  "#ffaa55",
    "ARP":   "#c084fc", "OTHER": "#888888",
}

CHART_REFRESH_MS = 1000

# ── TREEVIEW COLUMNS (adds GEO after DST) ────────────────────────────────────
DISPLAY_COLUMNS = dict(PACKET_DISPLAY_COLUMNS)
_ordered = list(DISPLAY_COLUMNS.items())
_dst_idx = [i for i, (k, _) in enumerate(_ordered) if k == "dst"]
_insert_at = _dst_idx[0] + 1 if _dst_idx else len(_ordered)
_ordered.insert(_insert_at, ("geo", {"width": 200, "anchor": "w"}))
DISPLAY_COLUMNS = dict(_ordered)

# File type filters per format
_FILETYPES = {
    "pcap": [("PCAP files", "*.pcap"), ("All files", "*.*")],
    "csv":  [("CSV files",  "*.csv"),  ("All files", "*.*")],
    "json": [("JSON files", "*.json"), ("All files", "*.*")],
}


class SnifferGUI:
    """Main GUI application for packet sniffing and analysis."""

    def __init__(self, root):
        self.root = root
        self.sniffer = PacketSniffer()
        self.packet_count = 0
        self._all_packets = []
        self._proto_counts = defaultdict(int)

        self._geo = GeoLookup()
        if not self._geo.available:
            logger.warning("GeoIP unavailable — column will show '🌐 Unknown'")

        self._tooltip_win = None
        self._tooltip_after_id = None

        self._setup_window()
        self._create_widgets()
        self._setup_row_colors()
        self._setup_bindings()

        self.root.after(PACKET_QUEUE_UPDATE_INTERVAL, self._update_gui)
        self.root.after(CHART_REFRESH_MS, self._refresh_charts)

        logger.info("GUI initialized successfully")

    # ── WINDOW ───────────────────────────────────────────────────────────────

    def _setup_window(self):
        self.root.title("Advanced Packet Sniffer & Analyzer")
        self.root.geometry("1500x720")
        self.root.minsize(1100, 580)
        self.root.resizable(True, True)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(2, weight=1)

    # ── WIDGETS ──────────────────────────────────────────────────────────────

    def _create_widgets(self):
        self._create_control_frame()
        self._create_search_bar()
        self._create_main_frame()
        self._create_status_frame()

    # ── CONTROL FRAME ────────────────────────────────────────────────────────

    def _create_control_frame(self):
        ctrl_frame = ttk.LabelFrame(self.root, text="Capture Controls", padding=10)
        ctrl_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=5)
        ctrl_frame.columnconfigure(1, weight=1)
        ctrl_frame.columnconfigure(3, weight=1)

        ttk.Label(ctrl_frame, text="Interface:").grid(
            row=0, column=0, sticky="w", padx=(0, 5))
        self.interface_var = tk.StringVar()
        interfaces = self.sniffer.get_interfaces()
        self.interface_combo = ttk.Combobox(
            ctrl_frame, textvariable=self.interface_var,
            values=interfaces, state="readonly", width=30)
        self.interface_combo.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        if interfaces:
            self.interface_combo.current(0)

        ttk.Label(ctrl_frame, text="Filter:").grid(
            row=0, column=2, sticky="w", padx=(0, 5))
        self.filter_var = tk.StringVar(value="ALL")
        self.filter_combo = ttk.Combobox(
            ctrl_frame, textvariable=self.filter_var,
            values=list(PROTOCOL_FILTERS.keys()), state="readonly", width=10)
        self.filter_combo.grid(row=0, column=3, sticky="ew", padx=(0, 10))

        btn_frame = ttk.Frame(ctrl_frame)
        btn_frame.grid(row=0, column=4, sticky="e")

        self.start_btn = ttk.Button(btn_frame, text="Start Capture",
                                    command=self._start_capture)
        self.start_btn.pack(side="left", padx=2)

        self.stop_btn = ttk.Button(btn_frame, text="Stop Capture",
                                   command=self._stop_capture, state="disabled")
        self.stop_btn.pack(side="left", padx=2)

        self.clear_btn = ttk.Button(btn_frame, text="Clear",
                                    command=self._clear_packets)
        self.clear_btn.pack(side="left", padx=2)

        # ── 7. EXPORT DROPDOWN ───────────────────────────────────────────────
        # A ttk.Menubutton shows "Export ▾" and reveals PCAP / CSV / JSON
        self._export_menu_btn = ttk.Menubutton(
            btn_frame, text="Export ▾", direction="below")
        self._export_menu_btn.pack(side="left", padx=2)

        export_menu = tk.Menu(self._export_menu_btn, tearoff=False)
        export_menu.add_command(
            label="💾  Save as PCAP",
            command=lambda: self._export("pcap"))
        export_menu.add_command(
            label="📊  Save as CSV",
            command=lambda: self._export("csv"))
        export_menu.add_command(
            label="📋  Save as JSON",
            command=lambda: self._export("json"))
        export_menu.add_separator()
        export_menu.add_command(
            label="📦  Export All Formats",
            command=self._export_all)

        self._export_menu_btn["menu"] = export_menu

    # ── SEARCH BAR ───────────────────────────────────────────────────────────

    def _create_search_bar(self):
        search_frame = ttk.Frame(self.root)
        search_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 4))
        search_frame.columnconfigure(1, weight=1)
        ttk.Label(search_frame, text="Search:").grid(
            row=0, column=0, sticky="w", padx=(0, 6))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self._on_search_change)
        ttk.Entry(search_frame, textvariable=self.search_var).grid(
            row=0, column=1, sticky="ew")
        ttk.Button(search_frame, text="✕", width=3,
                   command=lambda: self.search_var.set("")).grid(
            row=0, column=2, padx=(4, 0))

    # ── MAIN FRAME ───────────────────────────────────────────────────────────

    def _create_main_frame(self):
        main_frame = ttk.Frame(self.root)
        main_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=0)
        main_frame.rowconfigure(0, weight=1)
        self._create_packet_tree(main_frame)
        self._create_chart_panel(main_frame)

    # ── TREEVIEW ─────────────────────────────────────────────────────────────

    def _create_packet_tree(self, parent):
        tree_frame = ttk.Frame(parent)
        tree_frame.grid(row=0, column=0, sticky="nsew")
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        columns = list(DISPLAY_COLUMNS.keys())
        self.packet_tree = ttk.Treeview(
            tree_frame, columns=columns,
            show="headings", selectmode="browse")

        for col, cfg in DISPLAY_COLUMNS.items():
            label = "GEO" if col == "geo" else col.upper()
            self.packet_tree.heading(
                col, text=label,
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

    # ── CHART PANEL ──────────────────────────────────────────────────────────

    def _create_chart_panel(self, parent):
        chart_frame = ttk.LabelFrame(parent, text="Protocol Statistics", padding=6)
        chart_frame.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        bg = "#1e1e1e"
        self._fig = plt.Figure(figsize=(4.2, 7), dpi=90, facecolor=bg)
        self._fig.subplots_adjust(hspace=0.45, top=0.95, bottom=0.08,
                                  left=0.12, right=0.95)
        gs = gridspec.GridSpec(2, 1, figure=self._fig, height_ratios=[1.1, 1])
        self._ax_pie = self._fig.add_subplot(gs[0])
        self._ax_pie.set_facecolor(bg)
        self._ax_bar = self._fig.add_subplot(gs[1])
        self._ax_bar.set_facecolor(bg)
        self._canvas = FigureCanvasTkAgg(self._fig, master=chart_frame)
        self._canvas.get_tk_widget().pack(fill="both", expand=True)
        self._draw_charts()

    def _draw_charts(self):
        bg = "#1e1e1e"
        if self._proto_counts:
            sorted_items = sorted(self._proto_counts.items(),
                                  key=lambda x: x[1], reverse=True)
            if len(sorted_items) > 7:
                top = sorted_items[:7]
                other = sum(v for _, v in sorted_items[7:])
                if other:
                    top.append(("OTHER", other))
                labels, sizes = zip(*top)
            else:
                labels, sizes = zip(*sorted_items)
        else:
            labels, sizes = ("No data",), (1,)

        colors = [CHART_COLORS.get(l, "#888888") for l in labels]

        self._ax_pie.clear()
        self._ax_pie.set_facecolor(bg)
        self._ax_pie.set_title("Distribution", color="#cccccc", fontsize=9, pad=6)
        if labels == ("No data",):
            self._ax_pie.pie([1], colors=["#333333"],
                             wedgeprops={"linewidth": 0.5, "edgecolor": "#444"})
            self._ax_pie.text(0, 0, "Waiting…", ha="center", va="center",
                              color="#666666", fontsize=8)
        else:
            _, _, autotexts = self._ax_pie.pie(
                sizes, labels=labels, colors=colors,
                autopct=lambda p: f"{p:.1f}%" if p > 4 else "",
                startangle=140,
                wedgeprops={"linewidth": 0.6, "edgecolor": "#1e1e1e"},
                textprops={"fontsize": 7.5, "color": "#cccccc"})
            for at in autotexts:
                at.set_fontsize(7); at.set_color("#ffffff")

        self._ax_bar.clear()
        self._ax_bar.set_facecolor(bg)
        self._ax_bar.set_title("Packet Counts", color="#cccccc", fontsize=9, pad=6)
        if labels != ("No data",):
            x_pos = range(len(labels))
            bars = self._ax_bar.bar(x_pos, sizes, color=colors,
                                    edgecolor="#1e1e1e", linewidth=0.5)
            for bar, val in zip(bars, sizes):
                self._ax_bar.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + max(sizes) * 0.02,
                    str(val), ha="center", va="bottom",
                    color="#cccccc", fontsize=7)
            self._ax_bar.set_xticks(list(x_pos))
            self._ax_bar.set_xticklabels(labels, rotation=30, ha="right",
                                          fontsize=7.5, color="#cccccc")
            self._ax_bar.tick_params(axis="y", colors="#666666", labelsize=7)
            self._ax_bar.spines["top"].set_visible(False)
            self._ax_bar.spines["right"].set_visible(False)
            for s in ["bottom", "left"]:
                self._ax_bar.spines[s].set_color("#444444")
            self._ax_bar.yaxis.set_major_locator(
                plt.MaxNLocator(integer=True, nbins=5))
            self._ax_bar.set_ylim(0, max(sizes) * 1.18)
        else:
            self._ax_bar.text(0.5, 0.5, "Waiting for packets…",
                              ha="center", va="center",
                              transform=self._ax_bar.transAxes,
                              color="#666666", fontsize=8)
            self._ax_bar.set_xticks([]); self._ax_bar.set_yticks([])
            for s in self._ax_bar.spines.values(): s.set_visible(False)

        self._canvas.draw_idle()

    def _refresh_charts(self):
        self._draw_charts()
        self.root.after(CHART_REFRESH_MS, self._refresh_charts)

    # ── ROW COLORS ───────────────────────────────────────────────────────────

    def _setup_row_colors(self):
        for proto, (bg, fg) in PROTOCOL_COLORS.items():
            self.packet_tree.tag_configure(proto, background=bg, foreground=fg)

    def _protocol_tag(self, protocol: str) -> str:
        return protocol if protocol in PROTOCOL_COLORS else "OTHER"

    # ── STATUS BAR ───────────────────────────────────────────────────────────

    def _create_status_frame(self):
        status_frame = ttk.Frame(self.root)
        status_frame.grid(row=3, column=0, sticky="ew", padx=10, pady=5)
        status_frame.columnconfigure(1, weight=1)

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var).grid(
            row=0, column=0, sticky="w")

        geo_status = ("🌍 GeoIP active" if self._geo.available
                      else "⚠️  GeoIP unavailable — add GeoLite2-City.mmdb")
        self._geo_status_var = tk.StringVar(value=geo_status)
        ttk.Label(status_frame, textvariable=self._geo_status_var).grid(
            row=0, column=1, sticky="w", padx=20)

        self.count_var = tk.StringVar(value="Packets: 0")
        ttk.Label(status_frame, textvariable=self.count_var).grid(
            row=0, column=2, sticky="e")

    # ── BINDINGS ─────────────────────────────────────────────────────────────

    def _setup_bindings(self):
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.packet_tree.bind("<Double-1>", self._on_packet_double_click)
        self.packet_tree.bind("<Motion>",   self._on_mouse_motion)
        self.packet_tree.bind("<Leave>",    self._hide_tooltip)

    # ── TOOLTIP ──────────────────────────────────────────────────────────────

    def _on_mouse_motion(self, event):
        item = self.packet_tree.identify_row(event.y)
        if not item:
            self._hide_tooltip()
            return
        if self._tooltip_after_id:
            self.root.after_cancel(self._tooltip_after_id)
        self._tooltip_after_id = self.root.after(
            400, lambda: self._show_tooltip(event, item))

    def _show_tooltip(self, event, item):
        self._hide_tooltip()
        values = self.packet_tree.item(item, "values")
        if not values:
            return
        col_keys = list(DISPLAY_COLUMNS.keys())
        try:
            src = values[col_keys.index("src")]
            dst = values[col_keys.index("dst")]
        except (ValueError, IndexError):
            return

        src_lines = self._geo.tooltip_lines(src)
        dst_lines = self._geo.tooltip_lines(dst)
        lines = (["─"*38, "  SOURCE", "─"*38] + src_lines +
                 ["", "─"*38, "  DESTINATION", "─"*38] + dst_lines)

        tip = tk.Toplevel(self.root)
        tip.wm_overrideredirect(True)
        tip.wm_attributes("-topmost", True)
        tk.Label(tip, text="\n".join(lines), justify="left",
                 font=("Courier", 9), bg="#1a1a2e", fg="#e0e0e0",
                 relief="solid", borderwidth=1, padx=10, pady=8).pack()
        tip.wm_geometry(f"+{event.x_root+16}+{event.y_root+10}")
        self._tooltip_win = tip

    def _hide_tooltip(self, event=None):
        if self._tooltip_after_id:
            self.root.after_cancel(self._tooltip_after_id)
            self._tooltip_after_id = None
        if self._tooltip_win:
            try:
                self._tooltip_win.destroy()
            except Exception:
                pass
            self._tooltip_win = None

    # ── SEARCH ───────────────────────────────────────────────────────────────

    def _on_search_change(self, *_):
        self._redraw_tree()

    def _redraw_tree(self):
        query = self.search_var.get().lower().strip()
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        for pkt in self._all_packets:
            if self._packet_matches_search(pkt, query):
                self._insert_packet_row(pkt)

    def _packet_matches_search(self, pkt, query):
        if not query:
            return True
        haystack = " ".join([
            pkt.get("timestamp", ""), pkt.get("src", ""),
            pkt.get("dst", ""),       pkt.get("protocol", ""),
            str(pkt.get("length", "")), pkt.get("info", ""),
            pkt.get("geo_summary", ""),
        ]).lower()
        return query in haystack

    # ── CAPTURE CONTROL ──────────────────────────────────────────────────────

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

    def _clear_packets(self):
        if messagebox.askyesno("Clear Packets", "Clear all captured packets?"):
            self.sniffer.clear_data()
            self._clear_display()
            self.status_var.set("Packets cleared")

    def _clear_display(self):
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        self._all_packets.clear()
        self._proto_counts.clear()
        self.packet_count = 0
        self.count_var.set("Packets: 0")
        self._draw_charts()

    # ── 7. EXPORT ────────────────────────────────────────────────────────────

    def _export(self, fmt: str):
        """Show save dialog and export in the chosen format."""
        if not self._all_packets:
            messagebox.showinfo("No Packets", "No packets to export.")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            filetypes=_FILETYPES[fmt],
            title=f"Export as {fmt.upper()}",
            initialfile=f"capture.{fmt}",
        )
        if not filename:
            return

        if fmt == "pcap":
            ok, msg, count = export_pcap(self._all_packets, filename)
        elif fmt == "csv":
            ok, msg, count = export_csv(self._all_packets, self._geo, filename)
        elif fmt == "json":
            ok, msg, count = export_json(self._all_packets, self._geo, filename)
        else:
            return

        if ok:
            messagebox.showinfo("Export Successful", msg)
            self.status_var.set(f"Exported {count} packets → {fmt.upper()}")
        else:
            messagebox.showerror("Export Failed", msg)

    def _export_all(self):
        """Export to all three formats at once — user picks a folder."""
        if not self._all_packets:
            messagebox.showinfo("No Packets", "No packets to export.")
            return

        folder = filedialog.askdirectory(title="Choose folder for exported files")
        if not folder:
            return

        import os
        base = os.path.join(folder, "capture")
        results = []

        ok, msg, _ = export_pcap(self._all_packets, f"{base}.pcap")
        results.append(f"PCAP: {'✓' if ok else '✗'} {msg}")

        ok, msg, _ = export_csv(self._all_packets, self._geo, f"{base}.csv")
        results.append(f"CSV:  {'✓' if ok else '✗'} {msg}")

        ok, msg, _ = export_json(self._all_packets, self._geo, f"{base}.json")
        results.append(f"JSON: {'✓' if ok else '✗'} {msg}")

        messagebox.showinfo("Export All Complete", "\n".join(results))
        self.status_var.set("Exported all formats to folder")

    # ── GUI UPDATE LOOP ──────────────────────────────────────────────────────

    def _update_gui(self):
        packets = self.sniffer.get_packets()
        if packets:
            current_filter = self.filter_var.get()
            query = self.search_var.get().lower().strip()
            for pkt in packets:
                if PacketAnalyzer.matches_filter(pkt, current_filter):
                    pkt["geo_summary"] = self._geo.summary(pkt.get("src", ""))
                    self._all_packets.append(pkt)
                    self._proto_counts[pkt.get("protocol", "OTHER")] += 1
                    if self._packet_matches_search(pkt, query):
                        self._insert_packet_row(pkt)

            stats = self.sniffer.get_statistics()
            self.count_var.set(
                f"Packets: {stats['packet_count']}  "
                f"(Stored: {stats['stored_packets']},  "
                f"Queue: {stats['queue_size']})")

        self.root.after(PACKET_QUEUE_UPDATE_INTERVAL, self._update_gui)

    def _insert_packet_row(self, pkt):
        geo = pkt.get("geo_summary") or self._geo.summary(pkt.get("src", ""))
        col_keys = list(DISPLAY_COLUMNS.keys())
        value_map = {
            "time":  pkt["timestamp"],
            "src":   pkt["src"],
            "dst":   pkt["dst"],
            "geo":   geo,
            "proto": pkt["protocol"],
            "len":   pkt["length"],
            "info":  pkt["info"],
        }
        values = tuple(value_map.get(k, "") for k in col_keys)
        tag = self._protocol_tag(pkt["protocol"])
        self.packet_tree.insert("", "end", values=values, tags=(tag,))
        self.packet_count += 1
        if not self.search_var.get():
            children = self.packet_tree.get_children()
            if children:
                self.packet_tree.see(children[-1])

    def _add_packet_to_display(self, pkt):
        self._insert_packet_row(pkt)

    # ── COLUMN SORT ──────────────────────────────────────────────────────────

    def _sort_column(self, col, reverse):
        data = [(self.packet_tree.set(child, col), child)
                for child in self.packet_tree.get_children("")]
        try:
            data.sort(key=lambda t: float(t[0]), reverse=reverse)
        except ValueError:
            data.sort(key=lambda t: t[0].lower(), reverse=reverse)
        for index, (_, child) in enumerate(data):
            self.packet_tree.move(child, "", index)
        self.packet_tree.heading(
            col, command=lambda: self._sort_column(col, not reverse))

    # ── PACKET DETAIL POPUP ──────────────────────────────────────────────────

    def _on_packet_double_click(self, event):
        self._hide_tooltip()
        selection = self.packet_tree.selection()
        if not selection:
            return
        values = self.packet_tree.item(selection[0], "values")
        if not values:
            return
        col_keys = list(DISPLAY_COLUMNS.keys())
        val_map = dict(zip(col_keys, values))
        timestamp = val_map.get("time", "")
        src       = val_map.get("src", "")
        dst       = val_map.get("dst", "")
        protocol  = val_map.get("proto", "")
        length    = val_map.get("len", "")
        info      = val_map.get("info", "")
        geo       = val_map.get("geo", "")

        matched_pkt = None
        for p in self._all_packets:
            if (p["timestamp"] == timestamp and p["src"] == src
                    and p["dst"] == dst and p["protocol"] == protocol):
                matched_pkt = p
                break
        self._show_detail_window(
            (timestamp, src, dst, protocol, length, info, geo), matched_pkt)

    def _show_detail_window(self, values, pkt_info):
        timestamp, src, dst, protocol, length, info, geo = values

        win = tk.Toplevel(self.root)
        win.title(f"Packet Detail — {protocol}  {src} → {dst}")
        win.geometry("750x580")
        win.resizable(True, True)

        summary_frame = ttk.LabelFrame(win, text="Summary", padding=8)
        summary_frame.pack(fill="x", padx=10, pady=(10, 4))
        for row_i, (lbl, val) in enumerate([
            ("Time", timestamp), ("Source", src), ("Destination", dst),
            ("GeoIP (src)", geo), ("Protocol", protocol),
            ("Length", f"{length} bytes"), ("Info", info),
        ]):
            ttk.Label(summary_frame, text=lbl + ":",
                      font=("", 9, "bold")).grid(
                row=row_i, column=0, sticky="w", padx=(0, 10), pady=1)
            ttk.Label(summary_frame, text=val).grid(
                row=row_i, column=1, sticky="w", pady=1)

        geo_frame = ttk.LabelFrame(win, text="GeoIP Details", padding=8)
        geo_frame.pack(fill="x", padx=10, pady=4)
        geo_text = tk.Text(geo_frame, height=6, wrap="none",
                           font=("Courier", 9), relief="flat",
                           bg="#1a1a2e", fg="#e0e0e0", state="disabled")
        geo_text.pack(fill="x")
        src_lines = self._geo.tooltip_lines(src)
        dst_lines = self._geo.tooltip_lines(dst)
        geo_content = ("SOURCE\n" + "\n".join(src_lines) +
                       "\n\nDESTINATION\n" + "\n".join(dst_lines))
        geo_text.config(state="normal")
        geo_text.insert("end", geo_content)
        geo_text.config(state="disabled")

        layers_frame = ttk.LabelFrame(win, text="Layer Breakdown", padding=8)
        layers_frame.pack(fill="both", expand=True, padx=10, pady=4)
        text_widget = tk.Text(layers_frame, wrap="word", font=("Courier", 10),
                              state="disabled", relief="flat",
                              bg="#1e1e1e", fg="#d4d4d4")
        scroll = ttk.Scrollbar(layers_frame, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scroll.set)
        text_widget.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        detail_lines = []
        if pkt_info and pkt_info.get("packet") is not None:
            raw = pkt_info["packet"]
            layer, layer_num = raw, 1
            while layer:
                name = layer.__class__.__name__
                detail_lines += [f"{'─'*60}",
                                 f"  Layer {layer_num}: {name}", f"{'─'*60}"]
                for fn, fv in layer.fields.items():
                    detail_lines.append(f"    {fn:<22} = {fv}")
                detail_lines.append("")
                layer = layer.payload if layer.payload else None
                if layer and layer.__class__.__name__ in ("Raw", "Padding", "NoPayload"):
                    raw_bytes = bytes(layer)
                    detail_lines += [f"{'─'*60}",
                                     f"  Layer {layer_num+1}: Raw Payload ({len(raw_bytes)} bytes)",
                                     f"{'─'*60}", "  Hex:"]
                    for i in range(0, len(raw_bytes), 16):
                        chunk = raw_bytes[i:i+16]
                        hp = " ".join(f"{b:02x}" for b in chunk)
                        ap = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                        detail_lines.append(f"    {i:04x}  {hp:<48}  {ap}")
                    break
                layer_num += 1
        else:
            detail_lines = ["Raw packet data not available.", "",
                            f"  Protocol : {protocol}", f"  Source   : {src}",
                            f"  Dest     : {dst}", f"  Length   : {length} bytes",
                            f"  Info     : {info}"]

        text_widget.config(state="normal")
        text_widget.insert("end", "\n".join(detail_lines))
        text_widget.config(state="disabled")
        ttk.Button(win, text="Close", command=win.destroy).pack(pady=6)

    # ── CLOSE ────────────────────────────────────────────────────────────────

    def _on_close(self):
        self._hide_tooltip()
        if self.sniffer.is_running:
            if messagebox.askyesno("Quit", "Stop capture and quit?"):
                self.sniffer.stop_capture()
                self._geo.close()
                self.root.destroy()
        else:
            self._geo.close()
            self.root.destroy()
        plt.close("all")


# ── ENTRY POINT ──────────────────────────────────────────────────────────────

def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    root = tk.Tk()
    app = SnifferGUI(root)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        logger.info("Interrupted")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()