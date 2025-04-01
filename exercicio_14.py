import requests
import argparse
from concurrent.futures import ThreadPoolExecutor

def load_wordlist(wordlist_path):
    with open(wordlist_path, 'r') as f:
        return [line.strip() for line in f]

def test_endpoint(base_url, path, timeout=5):
    try:
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        response = requests.get(url, timeout=timeout)
        
        if response.status_code == 200:
            print(f"[+] {url} (Status: {response.status_code})")
            return (url, response.status_code, len(response.content))
        elif response.status_code in [403, 401]:
            print(f"[?] {url} (Acesso restrito: {response.status_code})")
        elif response.status_code == 404:
            pass  
        else:
            print(f"[!] {url} (Status incomum: {response.status_code})")
            
    except Exception as e:
        print(f"[-] Erro ao testar {path}: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Web Fuzzer")
    parser.add_argument("-u", "--url", required=True, help="URL base (ex: http://site.com)")
    parser.add_argument("-w", "--wordlist", required=True, help="Caminho para wordlist")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Número de threads")
    args = parser.parse_args()

    print(f"\n[🔍] Iniciando fuzzing em {args.url}")
    print(f"[📖] Usando wordlist: {args.wordlist}")
    print(f"[⚡] Threads: {args.threads}\n")

    wordlist = load_wordlist(args.wordlist)
    found = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(test_endpoint, args.url, path) for path in wordlist]
        for future in futures:
            result = future.result()
            if result:
                found.append(result)

    print("\n[📊] Resumo:")
    for url, status, size in found:
        print(f"  → {url} (Status: {status}, Tamanho: {size} bytes)")

if __name__ == "__main__":
    main()