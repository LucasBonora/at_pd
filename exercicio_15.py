import nmap
import asyncio
from concurrent.futures import ThreadPoolExecutor

class PortScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    def sync_scan(self, target, ports='1-1024', arguments='-sS -T4'):
        """Varredura síncrona de portas"""
        print(f"\n[🔍] Iniciando varredura SÍNCRONA em {target}")
        self.nm.scan(hosts=target, ports=ports, arguments=arguments)
        
        for host in self.nm.all_hosts():
            print(f"\n[🎯] Host: {host} ({self.nm[host].hostname()})")
            print(f"[📡] Estado: {self.nm[host].state()}")
            
            for proto in self.nm[host].all_protocols():
                print(f"\n[📊] Protocolo: {proto}")
                ports = self.nm[host][proto].keys()
                
                for port in sorted(ports):
                    state = self.nm[host][proto][port]['state']
                    service = self.nm[host][proto][port]['name']
                    print(f"  → Porta {port}: {state} ({service})")

    async def async_scan(self, targets, ports='1-1024', arguments='-sS -T4'):
        """Varredura assíncrona de múltiplos hosts"""
        print(f"\n[⚡] Iniciando varredura ASSÍNCRONA para {len(targets)} hosts")
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            loop = asyncio.get_event_loop()
            tasks = [
                loop.run_in_executor(
                    executor,
                    self.nm.scan,
                    host,
                    ports,
                    arguments
                )
                for host in targets
            ]
            
            for response in await asyncio.gather(*tasks):
                for host in self.nm.all_hosts():
                    print(f"\n[🎯] Host: {host} - {self.nm[host].state()}")
                    print(f"  Portas abertas: {list(self.nm[host]['tcp'].keys())}")

def main():
    scanner = PortScanner()
    
    scanner.sync_scan('127.0.0.1', '22-443')
    
    asyncio.run(scanner.async_scan(['127.0.0.1', '192.168.1.1'], '80,443'))

if __name__ == "__main__":
    main()