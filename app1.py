from scapy.all import rdpcap
import pandas as pd

# Define your rules
HIGH_TRAFFIC_THRESHOLD = 1000
UNUSUAL_IPS = {"192.168.0.100", "10.0.0.5"}
UNUSUAL_PORTS = {137, 5678}

def convert_pcap_to_csv(pcap_file_path, csv_file_path):
    # Read all packets from PCAP file
    packets = rdpcap(pcap_file_path)
    
    # Prepare a list to hold packet details
    packet_data = []
    
    for packet in packets:
        packet_info = {
            'employee id':1,
            'timestamp': packet.time,
            'src_ip': packet['IP'].src if packet.haslayer('IP') else None,
            'dst_ip': packet['IP'].dst if packet.haslayer('IP') else None,
            'src_port': packet.sport if packet.haslayer('TCP') or packet.haslayer('UDP') else None,
            'dst_port': packet.dport if packet.haslayer('TCP') or packet.haslayer('UDP') else None,
            'protocol': packet['IP'].proto if packet.haslayer('IP') else None,
            'packet_size': len(packet),
           
        }
        packet_data.append(packet_info)
    
    # Convert the list of packet details into a DataFrame
    df = pd.DataFrame(packet_data)
    
    # Save the DataFrame to a CSV file
    df.to_csv(csv_file_path, index=False)
    print(f"Data saved to {csv_file_path}")

def apply_rules_from_csv(csv_file_path):
    df = pd.read_csv(csv_file_path)
    traffic_volume = {}
    anomalies = []

    for index, row in df.iterrows():
        src_ip = row['src_ip']
        dst_ip = row['dst_ip']
        src_port = row['src_port']
        dst_port = row['dst_port']
        
        # Rule 1: High Traffic Volume
        if src_ip not in traffic_volume:
            traffic_volume[src_ip] = 0
        traffic_volume[src_ip] += 1

        if traffic_volume[src_ip] > HIGH_TRAFFIC_THRESHOLD:
            anomalies.append(f"High traffic volume detected from IP: {src_ip}")

        # Rule 2: New IP Addresses
        if src_ip in UNUSUAL_IPS:
            anomalies.append(f"Unusual IP address detected: {src_ip}")

        if dst_ip in UNUSUAL_IPS:
            anomalies.append(f"Unusual IP address detected: {dst_ip}")

        # Rule 3: Unusual Ports
        if src_port in UNUSUAL_PORTS:
            anomalies.append(f"Unusual source port detected: {src_port}")

        if dst_port in UNUSUAL_PORTS:
            anomalies.append(f"Unusual destination port detected: {dst_port}")

    return anomalies

def process_pcap(file_path, csv_file_path):
    print("Converting PCAP to CSV...")
    convert_pcap_to_csv(file_path, csv_file_path)
    
    print("Processing CSV file...")
    anomalies = apply_rules_from_csv(csv_file_path)
    print("Packet processing complete.")
    return anomalies

if __name__ == "__main__":
    pcap_file_path = 'data/capture.pcap'
    csv_file_path = 'data/packets1.csv'
    
    anomalies = process_pcap(pcap_file_path, csv_file_path)
    for anomaly in anomalies:
        print(anomaly)
    
    if not anomalies:
        print("No anomalies detected.")
    print("Analysis complete.")



