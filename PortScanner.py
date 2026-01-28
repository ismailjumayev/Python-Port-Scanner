"""
Project: Multi-Threaded Network Scanner & Vulnerability Detector
Author: [Ismail Jumayev]
Date: 2026
Description:
    A Python-based Red Team tool that performs TCP connect scans,
    automates service version detection (Banner Grabbing), and
    identifies basic vulnerabilities using a signature database.
"""

import socket
import threading
import argparse
from datetime import datetime

# --- VULNERABILITY DATABASE ---
# A dictionary containing signatures of known vulnerable services.
# Key: Service Version String | Value: Vulnerability Description
VULN_DB = {
    "vsFTPd 2.3.4": "CRITICAL: Backdoor Command Execution (Metasploitable)",
    "Apache 2.2.8": "WARNING: Legacy Version - Potential Remote Code Execution",
    "Telnet": "RISK: Unencrypted Communication (Sniffing Risk)",
    "Microsoft-IIS/6.0": "CRITICAL: Buffer Overflow Risk (Old Server)",
}


# --- SCANNING ENGINE ---
def scan_port(target_ip, port):
    """
    Scans a specific port on the target IP.
    If open, it attempts to grab the service banner and check for vulnerabilities.
    """
    try:
        # Initialize the socket: IPv4 (AF_INET) and TCP (SOCK_STREAM)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set a timeout to prevent hanging on filtered ports
        s.settimeout(1.5)

        # Attempt to connect to the port
        # connect_ex returns 0 if successful, error code otherwise
        result = s.connect_ex((target_ip, port))

        if result == 0:
            # --- HTTP TRIGGER ---
            # Web servers (Port 80) usually wait for a client request.
            # We send a basic HTTP GET request to provoke a response.
            if port == 80:
                http_payload = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
                s.send(http_payload.encode())

            # --- BANNER GRABBING ---
            try:
                # Receive up to 4096 bytes of data
                banner_raw = s.recv(4096).decode(errors='ignore').strip()

                # Format the output for readability
                output_msg = f"[+] Port {port:<5} OPEN"

                if port == 80:
                    # Special parsing for HTTP headers to keep output clean
                    lines = banner_raw.split('\n')
                    print(f"{output_msg} : Web Server Detected")
                    for line in lines:
                        if "Server:" in line or "X-Powered-By:" in line:
                            print(f"      |_ {line.strip()}")
                else:
                    # For other services (FTP, SSH, etc.)
                    if banner_raw:
                        print(f"{output_msg} : {banner_raw}")
                    else:
                        print(f"{output_msg} : (No Banner)")

                # --- VULNERABILITY CHECK ---
                # Compare the grabbed banner against our database
                for signature in VULN_DB:
                    if signature in banner_raw:
                        print(f"\t[!!!] ALERT: {VULN_DB[signature]}")

            except Exception:
                # If the socket is open but sends no data
                print(f"[+] Port {port:<5} OPEN : (No Response/Timeout)")

        # Always close the socket resource
        s.close()

    except Exception:
        pass  # Ignore general errors (network unreachable, etc.)


# --- MAIN CONTROLLER ---
if __name__ == "__main__":
    # Setup Command Line Arguments (CLI)
    parser = argparse.ArgumentParser(description="Advanced Python Port Scanner & Vuln Detector")

    parser.add_argument("-t", "--target", required=True, help="Target IP Address (e.g., 192.168.1.5)")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port Range to Scan (Default: 1-1000)")

    args = parser.parse_args()

    # Assign arguments to variables
    target_ip = args.target

    try:
        start_port, end_port = map(int, args.ports.split('-'))
    except ValueError:
        print("Error: Ports must be in format start-end (e.g., 20-100)")
        exit()

    # Print Banner
    print(f"\n{'=' * 60}")
    print(f" TARGET ADDRESS : {target_ip}")
    print(f" PORT RANGE     : {start_port} - {end_port}")
    print(f" STARTED AT     : {str(datetime.now())}")
    print(f"{'=' * 60}\n")

    # --- THREADING LOOP ---
    threads = []

    for port in range(start_port, end_port + 1):
        # Create a new thread for each port
        t = threading.Thread(target=scan_port, args=(target_ip, port))
        threads.append(t)
        t.start()

    # Wait for all threads to complete (optional, keeps the prompt clean)
    for t in threads:
        t.join()

    print(f"\n[*] Scan completed successfully.")