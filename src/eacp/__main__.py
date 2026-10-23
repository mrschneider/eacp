"""
EACP Module Main Entry Point:
Allows running EACP directly via `python3 -m eacp` or `python3 -m eacp.relay`.
"""

import sys
from .relay import main as relay_main

def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] in ("--help", "-h"):
        print("EACP: Enterprise Agentic Communication Protocol (Microkernel Reference Implementation)")
        print("\nCommands:")
        print("  python3 -m eacp.relay [OPTIONS]   Run EACP Push Relay Daemon")
        print("\nRun 'python3 -m eacp.relay --help' for daemon options.")
        return

    # Default to running Relay daemon
    relay_main()

if __name__ == "__main__":
    main()
