import dns.resolver
import dns.reversename
import argparse

def dns_query(domain, record_type='A'):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        print(f"\n[🔍] Registros {record_type} para {domain}:")
        for rdata in answers:
            print(f"  → {rdata.to_text()}")
    except Exception as e:
        print(f"[❌] Erro na consulta {record_type}: {e}")

def reverse_lookup(ip):
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, 'PTR')
        print(f"\n[🔄] Reverse DNS para {ip}:")
        for rdata in answers:
            print(f"  → {rdata.to_text()}")
    except Exception as e:
        print(f"[❌] Erro no reverse lookup: {e}")

def main():
    parser = argparse.ArgumentParser(description="Ferramenta de Análise DNS")
    parser.add_argument("-d", "--domain", help="Domínio para pesquisa")
    parser.add_argument("-i", "--ip", help="IP para reverse lookup")
    args = parser.parse_args()

    if args.domain:
        dns_query(args.domain, 'A')
        dns_query(args.domain, 'MX')
        dns_query(args.domain, 'NS')
    
    if args.ip:
        reverse_lookup(args.ip)

if __name__ == "__main__":
    main()