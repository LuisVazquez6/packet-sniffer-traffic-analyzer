from scapy.all import sniff, IP, TCP, UDP, ICMP  # import scapy tools and protocol layers
from datetime import datetime                      # import datetime to timestamp each packet

# --- Banner ---
print("=" * 55)
print("  Packet Sniffer & Traffic Analyzer")
print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 55 + "\n")

# --- Suspicious port definitions ---
# these are ports that are commonly exploited or insecure
suspicious_ports = {
    23: "TELNET - Unencrypted remote login!",
    21: "FTP - Unencrypted file transfer!",
    80: "HTTP - Unencrypted web traffic!",
    445: "SMB - Common ransomware target!",
    3389: "RDP - Remote desktop, brute force target!",
    4444: "Metasploit default backdoor port!",
    1337: "Common hacker/backdoor port!"
}

# counter to track how many alerts have fired
# keep track of IPs we already alerted on so we dont spam
alerted_ips = set()

def check_suspicious(src, dst, port, protocol):
    global alert_count

    if port in suspicious_ports:
        # create a unique key for this src+dst+port combination
        alert_key = f"{src}:{dst}:{port}"

        # only alert if we havent seen this combination before
        if alert_key not in alerted_ips:
            alerted_ips.add(alert_key)
            alert_count += 1
            reason = suspicious_ports[port]
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"  ⚠️  [{timestamp}] [ALERT] {protocol} {src} → {dst}:{port} | {reason}")

def process_packet(packet):   # runs every time a packet is captured
    
    if not packet.haslayer(IP):   # ignore non-IP packets
        return

    src = packet[IP].src   # source IP
    dst = packet[IP].dst   # destination IP
    timestamp = datetime.now().strftime('%H:%M:%S')

    if packet.haslayer(TCP):
        sport = packet[TCP].sport   # source port
        dport = packet[TCP].dport   # destination port
        print(f"  [{timestamp}] [TCP]  {src}:{sport} → {dst}:{dport}")

        # check both source and destination ports for suspicious activity
        check_suspicious(src, dst, dport, "TCP")
        check_suspicious(src, dst, sport, "TCP")

    elif packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        print(f"  [{timestamp}] [UDP]  {src}:{sport} → {dst}:{dport}")

        # check both ports for suspicious activity
        check_suspicious(src, dst, dport, "UDP")
        check_suspicious(src, dst, sport, "UDP")

    elif packet.haslayer(ICMP):
        print(f"  [{timestamp}] [ICMP] {src} → {dst}")

# --- Start capturing ---
# capture packets until CTRL+C is pressed
try:
    sniff(prn=process_packet, store=0)
except KeyboardInterrupt:   # when user presses CTRL+C
    print(f"\n{'=' * 55}")
    print(f"  Capture stopped.")
    print(f"  Total alerts triggered: {alert_count}")
    print(f"{'=' * 55}")