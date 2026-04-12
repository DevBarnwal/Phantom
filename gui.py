#!/usr/bin/env python3
"""
gui.py
Main GUI application for the packet sniffer.
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

class SnifferGUI:
    """Main GUI application for packet sniffing and analysis."""
    
    def __init__(self, root):
        self.root = root
        self.sniffer = PacketSniffer()
        self.packet_count = 0
        
        self._setup_window()
        self._create_widgets()
        self._setup_bindings()
        
        # Start GUI update loop
        self.root.after(PACKET_QUEUE_UPDATE_INTERVAL, self._update_gui)
        
        logger.info("GUI initialized successfully")
    
    def _setup_window(self):
        """Configure main window properties."""
        self.root.title("Advanced Packet Sniffer & Analyzer")
        self.root.geometry(DEFAULT_WINDOW_SIZE)
        self.root.minsize(*DEFAULT_WINDOW_MIN_SIZE)
        self.root.resizable(True, True)
        
        # Configure grid weights for responsive design
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
    
    def _create_widgets(self):
        """Create and arrange GUI widgets."""
        # Control frame
        self._create_control_frame()
        
        # Main content frame
        self._create_main_frame()
        
        # Status frame
        self._create_status_frame()
    
    def _create_control_frame(self):
        """Create control panel with interface selection and buttons."""
        ctrl_frame = ttk.LabelFrame(self.root, text="Capture Controls", padding=10)
        ctrl_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=5)
        ctrl_frame.columnconfigure(1, weight=1)
        ctrl_frame.columnconfigure(3, weight=1)
        
        # Interface selection
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
        
        # Protocol filter
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
        
        # Buttons
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
    
    def _create_main_frame(self):
        """Create main content area with packet list."""
        main_frame = ttk.Frame(self.root)
        main_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)
        
        # Create treeview with scrollbars
        self._create_packet_tree(main_frame)
    
    def _create_packet_tree(self, parent):
        """Create packet display treeview with scrollbars."""
        # Create frame for treeview and scrollbars
        tree_frame = ttk.Frame(parent)
        tree_frame.grid(row=0, column=0, sticky="nsew")
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        # Configure columns
        columns = list(PACKET_DISPLAY_COLUMNS.keys())
        self.packet_tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )
        
        # Configure column headings and widths
        for col, config in PACKET_DISPLAY_COLUMNS.items():
            self.packet_tree.heading(col, text=col.upper())
            self.packet_tree.column(
                col, 
                width=config["width"], 
                anchor=config["anchor"]
            )
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.packet_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.packet_tree.xview)
        
        self.packet_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Grid layout
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
    
    def _create_status_frame(self):
        """Create status bar."""
        status_frame = ttk.Frame(self.root)
        status_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=5)
        status_frame.columnconfigure(1, weight=1)
        
        # Status label
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(status_frame, textvariable=self.status_var)
        status_label.grid(row=0, column=0, sticky="w")
        
        # Packet count
        self.count_var = tk.StringVar(value="Packets: 0")
        count_label = ttk.Label(status_frame, textvariable=self.count_var)
        count_label.grid(row=0, column=2, sticky="e")
    
    def _setup_bindings(self):
        """Setup event bindings."""
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        
        # Bind double-click on packet for details (future enhancement)
        self.packet_tree.bind("<Double-1>", self._on_packet_double_click)
    
    def _start_capture(self):
        """Start packet capture."""
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Error", "Please select a network interface.")
            return
        
        # Get BPF filter based on selection
        protocol_filter = self.filter_var.get()
        bpf_filter = PROTOCOL_FILTERS.get(protocol_filter, "")
        
        # Start capture
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
        """Stop packet capture."""
        self.sniffer.stop_capture()
        
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.interface_combo.config(state="readonly")
        
        self.status_var.set("Capture stopped")
        logger.info("Capture stopped by user")
    
    def _clear_packets(self):
        """Clear all captured packets."""
        if messagebox.askyesno("Clear Packets", "Clear all captured packets?"):
            self.sniffer.clear_data()
            self._clear_display()
            self.status_var.set("Packets cleared")
            logger.info("Packets cleared by user")
    
    def _clear_display(self):
        """Clear packet display."""
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        self.packet_count = 0
        self.count_var.set("Packets: 0")
    
    def _save_packets(self):
        """Save captured packets to file."""
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
    
    def _update_gui(self):
        """Update GUI with new packets (called periodically)."""
        packets = self.sniffer.get_packets()
        
        if packets:
            current_filter = self.filter_var.get()
            
            for packet_info in packets:
                # Apply UI filter
                if PacketAnalyzer.matches_filter(packet_info, current_filter):
                    self._add_packet_to_display(packet_info)
            
            # Update statistics
            stats = self.sniffer.get_statistics()
            self.count_var.set(f"Packets: {stats['packet_count']} "
                             f"(Stored: {stats['stored_packets']}, "
                             f"Queue: {stats['queue_size']})")
        
        # Schedule next update
        self.root.after(PACKET_QUEUE_UPDATE_INTERVAL, self._update_gui)
    
    def _add_packet_to_display(self, packet_info):
        """Add a packet to the display tree."""
        values = (
            packet_info["timestamp"],
            packet_info["src"],
            packet_info["dst"], 
            packet_info["protocol"],
            packet_info["length"],
            packet_info["info"]
        )
        
        self.packet_tree.insert("", "end", values=values)
        self.packet_count += 1
        
        # Auto-scroll to bottom
        children = self.packet_tree.get_children()
        if children:
            self.packet_tree.see(children[-1])
    
    def _on_packet_double_click(self, event):
        """Handle double-click on packet (placeholder for future packet details view)."""
        selection = self.packet_tree.selection()
        if selection:
            # Future: Show detailed packet information in popup
            messagebox.showinfo("Packet Details", "Detailed packet view coming soon!")
    
    def _on_close(self):
        """Handle application close."""
        if self.sniffer.is_running:
            if messagebox.askyesno("Quit", "Stop capture and quit?"):
                self.sniffer.stop_capture()
                self.root.destroy()
        else:
            self.root.destroy()

def main():
    """Main function to run the GUI application."""
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and run GUI
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