 # Packet Sniffer & Traffic Analyzer

 A python-based network packet sniffer that captures and analyzes live network traffic

 ## Features
 - Capture Live TCP, UDP, ICMP network traffic
 - Displays source and destination IPs and ports with timestamps
 - Detects and alerts on suspicious ports (HTTP, TELENT, FTP, RDP, etc.)
 - Smart alerting - only fires once per unique connction, no spam
 - Clean shutdown summary showing total alerts triggered

 ## Screenshots
 ```
=======================================================
  Packet Sniffer & Traffic Analyzer
  Started: 2026-03-18 16:42:56
=======================================================

  [16:42:56] [TCP]  192.168.1.30:64474 → 162.159.135.234:443
  [16:42:57] [UDP]  192.168.1.15:68 → 255.255.255.255:67
  ⚠️  [16:41:42] [ALERT] TCP 172.184.91.3 → 192.168.1.30:80 | HTTP - Unencrypted web traffic!

=======================================================
  Capture stopped.
  Total alerts triggered: 1
=======================================================
```

## Requirements
```bash
pip install scappy
pip install pywin32
```
Also requires [Npcap](https://npcap.com/#download) installed with WinPcap compatibility mode enabled.

## How to Run
```bash
git clone https://github.com/LuisVazquez6/packet-sniffer-traffic-analyzer.git
cd packet-sniffer-traffic-analyzer
python sniffer.py
```

> Must be run as Administrator on Windows fro packet capture permissions.

## Alerts Triggered On
- Port 80 — HTTP (unencrypted web traffic)
- Port 21 — FTP (unencrypted file transfer)
- Port 23 — Telnet (unencrypted remote login)
- Port 445 — SMB (common ransomware target)
- Port 3389 — RDP (remote desktop brute force target)
- Port 4444 — Metasploit default backdoor
- Port 1337 — Common hacker/backdoor port

## What I Learned
- How to capture and parse live network packets using Scapy
- How TCP, UDP, and ICMP protocols differ at the packet level
- How to identify suspicious and insecure network traffic
- How real tools like Wireshark work under the hood

## Disclaimer
This tool is for educational purposes only. Only capture traffic on networks you own or have explicit permission to monitor.