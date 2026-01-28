# 🛡️ Python Multi-Threaded Port & Vulnerability Scanner

A custom network reconnaissance tool built with Python. It automates host discovery, port enumeration, service version detection (Banner Grabbing), and basic vulnerability identification by mapping gathered data against a local threat database.

This project was developed to demonstrate proficiency in **Network Socket Programming**, **Multi-threading**, and **Offensive Security Reconnaissance** techniques.

## 🚀 Key Features

* **Multi-Threaded Architecture:** Scans thousands of ports in seconds using Python's `threading` module to overcome blocking I/O operations.
* **Service Fingerprinting (Banner Grabbing):** Establishes connections to open ports (FTP, SSH, Telnet) to retrieve service version headers.
* **Intelligent HTTP Analysis:** Sends valid `GET` requests to Web Servers (Port 80) to extract specific server headers, handling protocol differences.
* **Automated Vulnerability Detection:** Cross-references grabbed service banners with a dictionary of known vulnerable versions (e.g., detecting `vsFTPd 2.3.4` backdoors).
* **CLI Interface:** Professional command-line argument parsing using `argparse`.

## 🛠️ Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/ismailjumayev/Python-Port-Scanner.git](https://github.com/ismailjumayev/Python-Port-Scanner.git)
    ```
2.  **Navigate to the directory:**
    ```bash
    cd Python-Port-Scanner
    ```
3.  **Run the tool** (No external dependencies required, built with Standard Library):
    ```bash
    python scanner.py -h
    ```

## 💻 Usage Examples

**Basic Scan (Default ports 1-1000):**
```bash
python scanner.py -t 192.168.1.5

Custom Range Scan:

python scanner.py -t 192.168.1.5 -p 20-100

📸 Sample Output
Scanning a deliberately vulnerable machine (Metasploitable):
============================================================
 TARGET ADDRESS : 192.168.229.129
 PORT RANGE     : 20 - 100
 STARTED AT     : 2026-01-28 14:30:00
============================================================

[+] Port 21    OPEN : 220 (vsFTPd 2.3.4)
    [!!!] ALERT: CRITICAL: Backdoor Command Execution (Metasploitable)
[+] Port 22    OPEN : SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
[+] Port 23    OPEN : (No Banner)
    [!!!] ALERT: RISK: Unencrypted Communication (Sniffing Risk)
[+] Port 80    OPEN : Web Server Detected
      |_ Server: Apache/2.2.8 (Ubuntu) DAV/2
      |_ X-Powered-By: PHP/5.2.4-2ubuntu5.10
      
[*] Scan completed successfully.

⚠️ Disclaimer
This tool is created for educational purposes and authorized security testing only.
Scanning networks or machines without explicit permission is illegal and unethical.
The author accepts no responsibility for unauthorized use.

