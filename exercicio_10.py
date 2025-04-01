from scapy.all import *
from scapy.layers.inet import IP, TCP
import time

class TrafficMonitor:
    def __init__(self, interface=None):
        self.interface = interface if interface else conf.iface
        self.traffic_stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'bytes_transferred': 0,
            'connections': {}
        }
        self.running = False

    def packet_handler(self, packet):
        if not self.running:
            return
            
        self.traffic_stats['total_packets'] += 1
        
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            size = len(packet)
            
            self.traffic_stats['bytes_transferred'] += size
            
            if packet.haslayer(TCP):
                self.traffic_stats['tcp_packets'] += 1
                self._track_connection(src, dst, packet[TCP].sport, packet[TCP].dport, size)
            elif packet.haslayer(UDP):
                self.traffic_stats['udp_packets'] += 1

    def _track_connection(self, src, src_port, dst, dst_port, size):
        conn_key = (src, src_port, dst, dst_port)
        if conn_key not in self.traffic_stats['connections']:
            self.traffic_stats['connections'][conn_key] = {
                'start_time': time.time(),
                'bytes': 0,
                'packets': 0
            }
        self.traffic_stats['connections'][conn_key]['bytes'] += size
        self.traffic_stats['connections'][conn_key]['packets'] += 1

    def start_monitoring(self, duration=30):
        print(f"[🚀] Iniciando monitoramento na interface {self.interface}")
        print("[📊] Pressione Ctrl+C para parar...\n")
        
        self.running = True
        start_time = time.time()
        
        try:
            sniff(iface=self.interface, prn=self.packet_handler, store=False, timeout=duration)
        except KeyboardInterrupt:
            pass
            
        self.running = False
        self.display_stats(time.time() - start_time)

    def display_stats(self, duration):
        print("\n[📊] Estatísticas de Tráfego:")
        print(f"  - Tempo de monitoramento: {duration:.2f} segundos")
        print(f"  - Pacotes totais: {self.traffic_stats['total_packets']}")
        print(f"  - Pacotes TCP: {self.traffic_stats['tcp_packets']}")
        print(f"  - Pacotes UDP: {self.traffic_stats['udp_packets']}")
        print(f"  - Bytes transferidos: {self.traffic_stats['bytes_transferred']}")
        
        print("\n[🔗] Conexões ativas:")
        for conn, data in self.traffic_stats['connections'].items():
            src_ip, src_port, dst_ip, dst_port = conn
            print(f"  {src_ip}:{src_port} → {dst_ip}:{dst_port}")
            print(f"    - Pacotes: {data['packets']}")
            print(f"    - Bytes: {data['bytes']}")
            print(f"    - Duração: {time.time() - data['start_time']:.2f}s\n")

if __name__ == "__main__":
    monitor = TrafficMonitor()
    monitor.start_monitoring(duration=60)