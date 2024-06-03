import sys
from scapy.all import *

def packet_callback(packet):
    if IP in packet:
        ip_packet = packet[IP]
        src_ip = ip_packet.src
        dst_ip = ip_packet.dst
        protocol = ip_packet.proto
        payload = packet.getlayer(Raw)
        
        output_data = f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}\n"
        
        if payload:
            payload_data = payload.load.decode('utf-8', 'ignore')
            output_data += "Payload Data:\n"
            output_data += payload_data + "\n"
            
            if protocol == 6 and payload_data.startswith("GET") or payload_data.startswith("HTTP"):
                # HTTP packet
                # You can further process and analyze HTTP payloads here
                print("HTTP Request/Response detected:")
                print(payload_data)
        
        with open("packet_log.txt", "a", encoding="utf-8") as output_file:
            output_file.write(output_data)

def start_sniffing(interface, count=0):
    print(f"Sniffing {count} packets on interface {interface}...")
    sniff(iface=interface, prn=packet_callback, count=count)

if __name__ == "__main__":
    interface = input("Enter the name of the interface to sniff (e.g., eth0): ")
    packet_count = int(input("Enter the number of packets to capture (enter 0 for continuous sniffing): "))
    
    # Redirect standard output to a file
    sys.stdout = open("output_log.txt", "w", encoding="utf-8")
    
    print("Output file 'output_log.txt' has been created.")
    
    start_sniffing(interface, packet_count)