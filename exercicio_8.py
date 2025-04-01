from scapy.all import *
from scapy.layers.inet import IP, TCP, Ether
import time

def packet_analyzer(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        
        print(f"\n[📦] Pacote IP | Origem: {src_ip} | Destino: {dst_ip} | Protocolo: {proto}")
        
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            print(f"[🔌] TCP | Porta Origem: {src_port} | Porta Destino: {dst_port} | Flags: {flags}")

def packet_modifier(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        modified_packet = packet.copy()
        modified_packet[IP].src = "192.168.1.100"  
        modified_packet[TCP].sport = 12345        
        return modified_packet
    return packet

def packet_injector(target_ip, target_port, count=3):
    print(f"\n[⚡] Injetando {count} pacotes TCP SYN em {target_ip}:{target_port}")
    for _ in range(count):
        send(IP(dst=target_ip)/TCP(dport=target_port, flags="S"), verbose=0)
        time.sleep(0.5)

def main():
    interface = conf.iface  
    print(f"[🔍] Iniciando captura na interface: {interface}")
    
    sniff_thread = AsyncSniffer(prn=packet_analyzer, store=False)
    sniff_thread.start()
    
    packet_injector("8.8.8.8", 80)
    
    time.sleep(30)
    sniff_thread.stop()
    print("\n[✅] Captura finalizada.")

if __name__ == "__main__":
    main()