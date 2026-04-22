"""
main.py
Entry point for Phantom — Network Intelligence & Threat Monitor

Requirements:
    pip install -r requirements.txt

Run as root/administrator for packet capture privileges.
"""

import sys
import os
import logging
from pathlib import Path


def check_requirements():
    """Check if required dependencies are available."""
    missing = []

    try:
        import scapy
    except ImportError:
        missing.append("scapy")

    try:
        import matplotlib
    except ImportError:
        missing.append("matplotlib")

    if missing:
        print(f"Error: Missing required packages: {', '.join(missing)}")
        print("Install with: pip install -r requirements.txt")
        return False

    return True


def check_privileges():
    """Check if running with appropriate privileges for packet capture."""
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    else:  # Unix-like
        return os.geteuid() == 0


def setup_logging():
    """Setup logging configuration."""
    log_dir = Path.home() / ".phantom" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)

    log_file = log_dir / "phantom.log"

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
    """Main entry point for Phantom."""
    print("👻 Phantom — Network Intelligence & Threat Monitor")
    print("=" * 50)

    logger = setup_logging()

    if not check_requirements():
        sys.exit(1)

    if not check_privileges():
        print("\nWarning: Running without administrator/root privileges.")
        print("Some network interfaces may not be accessible.")
        print("For full functionality, run as administrator/root.\n")

        response = input("Continue anyway? (y/N): ").lower().strip()
        if response not in ['y', 'yes']:
            print("Exiting...")
            sys.exit(0)

    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        if current_dir not in sys.path:
            sys.path.insert(0, current_dir)

        try:
            from gui import main as gui_main
        except ImportError as e:
            print(f"Import error: {e}")
            print("Make sure all required files are in the same directory:")
            print("  - main.py")
            print("  - gui.py")
            print("  - packet_sniffer.py")
            print("  - packet_analyzer.py")
            print("  - threat_detector.py")
            print("  - geo_lookup.py")
            print("  - exporter.py")
            print("  - report_generator.py")
            print("  - config.py")
            sys.exit(1)

        logger.info("Starting Phantom GUI")
        gui_main()

    except KeyboardInterrupt:
        print("\nPhantom interrupted by user")
        logger.info("Application interrupted by user")
        sys.exit(0)

    except Exception as e:
        print(f"Error starting Phantom: {e}")
        logger.error(f"Error starting application: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()