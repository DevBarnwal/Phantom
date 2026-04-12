#!/usr/bin/env python3
"""
packet_sniffer.py
Core packet sniffing functionality using Scapy.
"""

import threading
import queue
import logging
from scapy.all import sniff, get_if_list, wrpcap
from packet_analyzer import PacketAnalyzer
from config import MAX_DISPLAYED_PACKETS

logger = logging.getLogger(__name__)

class PacketSniffer:
    """Handles packet capture and management."""
    
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.captured_packets = []
        self.sniffer_thread = None
        self.stop_event = threading.Event()
        self.is_running = False
        self.packet_count = 0
        self._lock = threading.Lock()
    
    def get_interfaces(self):
        """
        Get list of available network interfaces.
        
        Returns:
            list: Available network interfaces
        """
        try:
            interfaces = get_if_list()
            logger.info(f"Found {len(interfaces)} network interfaces")
            return interfaces
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
            return []
    
    def start_capture(self, interface, bpf_filter=""):
        """
        Start packet capture on specified interface.
        
        Args:
            interface (str): Network interface to capture on
            bpf_filter (str): BPF filter string
        """
        if self.is_running:
            logger.warning("Sniffer is already running")
            return False
        
        if not interface:
            logger.error("No interface specified")
            return False
        
        logger.info(f"Starting capture on interface: {interface}")
        if bpf_filter:
            logger.info(f"Using BPF filter: {bpf_filter}")
        
        # Clear previous data
        self.clear_data()
        
        # Start sniffer thread
        self.stop_event.clear()
        self.is_running = True
        self.sniffer_thread = threading.Thread(
            target=self._sniff_packets,
            args=(interface, bpf_filter),
            daemon=True
        )
        self.sniffer_thread.start()
        return True
    
    def stop_capture(self):
        """Stop packet capture."""
        if not self.is_running:
            logger.warning("Sniffer is not running")
            return
        
        logger.info("Stopping packet capture")
        self.stop_event.set()
        self.is_running = False
        
        # Wait for thread to finish
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=2.0)
            if self.sniffer_thread.is_alive():
                logger.warning("Sniffer thread did not stop gracefully")
    
    def _sniff_packets(self, interface, bpf_filter):
        """
        Internal method to run packet sniffing in separate thread.
        
        Args:
            interface (str): Network interface
            bpf_filter (str): BPF filter string
        """
        try:
            logger.info("Packet sniffing started")
            sniff(
                iface=interface,
                prn=self._packet_callback,
                store=False,
                filter=bpf_filter if bpf_filter else None,
                stop_filter=lambda x: self.stop_event.is_set()
            )
            logger.info("Packet sniffing stopped")
        except Exception as e:
            logger.error(f"Error during packet sniffing: {e}")
        finally:
            self.is_running = False
    
    def _packet_callback(self, packet):
        """
        Callback function called for each captured packet.
        
        Args:
            packet: Scapy packet object
        """
        try:
            # Analyze packet
            packet_info = PacketAnalyzer.extract_packet_info(packet)
            
            if packet_info:
                with self._lock:
                    # Add to queue for GUI processing
                    self.packet_queue.put(packet_info)
                    
                    # Store packet for saving
                    self.captured_packets.append(packet)
                    
                    # Limit memory usage
                    if len(self.captured_packets) > MAX_DISPLAYED_PACKETS:
                        self.captured_packets.pop(0)
                    
                    self.packet_count += 1
                    
        except Exception as e:
            logger.warning(f"Error processing packet: {e}")
    
    def get_packets(self):
        """
        Get packets from queue for GUI processing.
        
        Returns:
            list: List of packet information dictionaries
        """
        packets = []
        try:
            while True:
                packet_info = self.packet_queue.get_nowait()
                packets.append(packet_info)
        except queue.Empty:
            pass
        
        return packets
    
    def save_packets(self, filename):
        """
        Save captured packets to file.
        
        Args:
            filename (str): Output filename
            
        Returns:
            tuple: (success: bool, message: str, count: int)
        """
        if not self.captured_packets:
            return False, "No packets to save", 0
        
        try:
            with self._lock:
                packets_to_save = self.captured_packets.copy()
            
            wrpcap(filename, packets_to_save)
            count = len(packets_to_save)
            message = f"Successfully saved {count} packets to {filename}"
            logger.info(message)
            return True, message, count
            
        except Exception as e:
            error_msg = f"Error saving packets: {e}"
            logger.error(error_msg)
            return False, error_msg, 0
    
    def clear_data(self):
        """Clear all captured data."""
        with self._lock:
            # Clear queue
            try:
                while True:
                    self.packet_queue.get_nowait()
            except queue.Empty:
                pass
            
            # Clear stored packets
            self.captured_packets.clear()
            self.packet_count = 0
            
        logger.info("Cleared all captured data")
    
    def get_statistics(self):
        """
        Get capture statistics.
        
        Returns:
            dict: Statistics including packet count, running status, etc.
        """
        with self._lock:
            return {
                "packet_count": self.packet_count,
                "stored_packets": len(self.captured_packets),
                "is_running": self.is_running,
                "queue_size": self.packet_queue.qsize()
            }