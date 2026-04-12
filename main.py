
"""
main.py
Entry point for the Advanced Packet Sniffer application.

Requirements:
    pip install scapy

Run as root/administrator for packet capture privileges.
"""

import sys
import os
import logging
from pathlib import Path

def check_requirements():
    """Check if required dependencies are available."""
    try:
        import scapy
        return True
    except ImportError:
        print("Error: Scapy is required but not installed.")
        print("Install it with: pip install scapy")
        return False

def check_privileges():
    """Check if running with appropriate privileges for packet capture."""
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:  # Unix-like systems
        return os.geteuid() == 0

def setup_logging():
    """Setup logging configuration."""
    log_dir = Path.home() / ".packet_sniffer" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    
    log_file = log_dir / "sniffer.log"
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info("Logging initialized")
    return logger

def main():
    """Main entry point for the application."""
    print("Advanced Packet Sniffer & Analyzer")
    print("=" * 40)
    
    # Setup logging
    logger = setup_logging()
    
    # Check requirements
    if not check_requirements():
        sys.exit(1)
    
    # Check privileges
    if not check_privileges():
        print("\nWarning: Running without administrator/root privileges.")
        print("Some network interfaces may not be accessible.")
        print("For full functionality, run as administrator/root.")
        
        response = input("\nContinue anyway? (y/N): ").lower().strip()
        if response not in ['y', 'yes']:
            print("Exiting...")
            sys.exit(0)
    
    try:
        # Add current directory to Python path
        current_dir = os.path.dirname(os.path.abspath(__file__))
        if current_dir not in sys.path:
            sys.path.insert(0, current_dir)
        
        # Import and run GUI
        try:
            from gui import main as gui_main
        except ImportError as e:
            print(f"Import error: {e}")
            print("Make sure all required files are in the same directory:")
            print("- main.py")
            print("- gui.py") 
            print("- packet_sniffer.py")
            print("- packet_analyzer.py")
            print("- config.py")
            sys.exit(1)
            
        logger.info("Starting GUI application")
        gui_main()
        
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        logger.info("Application interrupted by user")
        sys.exit(0)
        
    except Exception as e:
        print(f"Error starting application: {e}")
        logger.error(f"Error starting application: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()