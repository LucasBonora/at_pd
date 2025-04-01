from scapy.all import *
from scapy.layers.inet import IP, TCP
import ipaddress

def port_scan(target_ip, ports, timeout=2):
    print(f"\n[🔍] Escaneando {target_ip}...")
    open_ports = []
    
    for port in ports:
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=timeout, verbose=0)
        
        if response and response.haslayer(TCP):
            if response[TCP].flags == 0x12:  )
                open_ports.append(port)
                print(f"[✅] Porta {port} ABERTA")
            elif response[TCP].flags == 0x14:  
                print(f"[❌] Porta {port} FECHADA")
        else:
            print(f"[⚠️] Porta {port} FILTRADA (sem resposta)")
    
    return open_ports

def validate_ip(target_ip):
    try:
        ipaddress.ip_address(target_ip)
        return True
    except ValueError:
        return False

def main():
    target_ip = input("Digite o IP alvo: ")
    if not validate_ip(target_ip):
        print("[❌] IP inválido!")
        return
    
    port_range = input("Digite as portas (ex: 80 ou 20-100): ")
    
    try:
        if "-" in port_range:
            start, end = map(int, port_range.split("-"))
            ports = range(start, end+1)
        else:
            ports = [int(port_range)]
    except ValueError:
        print("[❌] Formato de porta inválido!")
        return
    
    open_ports = port_scan(target_ip, ports)
    print(f"\n[📊] Resumo: Portas abertas em {target_ip} → {open_ports}")

if __name__ == "__main__":
    main()