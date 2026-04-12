
"""
setup.py
Setup script to verify installation and file structure.
"""

import os
import sys
from pathlib import Path

def check_files():
    """Check if all required files are present."""
    required_files = [
        'main.py',
        'gui.py',
        'packet_sniffer.py', 
        'packet_analyzer.py',
        'config.py',
        'requirements.txt'
    ]
    
    current_dir = Path.cwd()
    missing_files = []
    
    print("Checking required files...")
    for file in required_files:
        file_path = current_dir / file
        if file_path.exists():
            print(f"✓ {file}")
        else:
            print(f"✗ {file} - MISSING")
            missing_files.append(file)
    
    return missing_files

def check_imports():
    """Check if all modules can be imported."""
    print("\nChecking module imports...")
    
    modules = [
        ('scapy', 'scapy.all'),
        ('tkinter', 'tkinter'),
        ('threading', 'threading'),
        ('queue', 'queue'),
        ('logging', 'logging')
    ]
    
    import_errors = []
    
    for name, module in modules:
        try:
            __import__(module)
            print(f"✓ {name}")
        except ImportError as e:
            print(f"✗ {name} - {e}")
            import_errors.append(name)
    
    return import_errors

def main():
    """Main setup verification."""
    print("Packet Sniffer Setup Verification")
    print("=" * 35)
    
    # Check files
    missing_files = check_files()
    
    # Check imports
    import_errors = check_imports()
    
    print("\n" + "=" * 35)
    
    if missing_files:
        print("❌ Setup Issues Found:")
        print(f"Missing files: {', '.join(missing_files)}")
        print("\nPlease ensure all files are in the same directory.")
        return False
    
    if import_errors:
        print("❌ Import Issues Found:")
        print(f"Missing modules: {', '.join(import_errors)}")
        print("\nInstall missing modules with:")
        print("pip install -r requirements.txt")
        return False
    
    print("✅ Setup verification completed successfully!")
    print("\nYou can now run the application with:")
    print("python main.py")
    
    if os.name != 'nt':  # Unix-like systems
        print("or with administrator privileges:")
        print("sudo python main.py")
    else:  # Windows
        print("Make sure to run as Administrator for full functionality.")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)