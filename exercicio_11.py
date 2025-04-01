from scapy.all import *
from scapy.layers.l2 import ARP, Ether
import time
from collections import defaultdict

class ARPSpoofDetector:
    def __init__(self, interface=None, check_interval=5):
        self.interface = interface if interface else conf.iface
        self.check_interval = check_interval
        self.arp_table = defaultdict(list)
        self.running = False

    def arp_monitor(self, packet):
        if packet.haslayer(ARP):
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            self.arp_table[ip].append((mac, time.time()))

    def detect_spoofing(self):
        while self.running:
            time.sleep(self.check_interval)
            for ip in list(self.arp_table.keys()):
                mac_list = self.arp_table[ip]
                if len(mac_list) > 1:
                    unique_macs = {mac for mac, _ in mac_list}
                    if len(unique_macs) > 1:
                        print(f"[⚠️] ALERTA DE ARP SPOOFING DETECTADO!")
                        print(f"    IP: {ip}")
                        print(f"    MACs associados: {', '.join(unique_macs)}")
                        print(f"    Hora da detecção: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.arp_table.clear()

    def start(self):
        print(f"[🔍] Iniciando detecção de ARP Spoofing na interface {self.interface}")
        print(f"[⏱] Verificando a cada {self.check_interval} segundos")
        print("[🛑] Pressione Ctrl+C para parar...\n")
        
        self.running = True
        sniff_thread = AsyncSniffer(iface=self.interface, prn=self.arp_monitor, store=False)
        sniff_thread.start()
        self.detect_spoofing()
        sniff_thread.stop()

if __name__ == "__main__":
    try:
        detector = ARPSpoofDetector(check_interval=3)
        detector.start()
    except KeyboardInterrupt:
        print("\n[🛑] Monitoramento encerrado pelo usuário")