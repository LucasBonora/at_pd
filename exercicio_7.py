import pcapy

def packet_callback(header, data):
    print(f"Pacote capturado (Tamanho: {header.getlen()} bytes)")

device = "Ethernet"  
sniffer = pcapy.open_live(device, 65536, True, 100)
sniffer.setfilter("tcp port 80")  

print(f"Capturando pacotes em {device}...")
sniffer.loop(0, packet_callback)

