import sys
import socket
import json
import subprocess
import re
import os
import wafw00f
import concurrent.futures

def load_well_known_ports(filename):
    try:
        with open(filename, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"Arquivo {filename} não encontrado.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Erro ao decodificar o arquivo {filename}.")
        sys.exit(1)

WELL_KNOWN_PORTS_TCP = load_well_known_ports("wktcp.json")
WELL_KNOWN_PORTS_UDP = load_well_known_ports("wkudp.json")

def port_scan(host, porta):
    s = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        result = s.connect_ex((host, porta))
        status = "Aberta" if result == 0 else "Fechada"
    except socket.timeout:
        status = "Filtrada"
    except Exception:
        status = "Filtrada"
    finally:
        s.close()
    
    service = next((item["name"] for item in WELL_KNOWN_PORTS_TCP if item["port"] == porta), "Desconhecido")
    print(f"Porta {porta} [TCP] {status} - Serviço: {service}")

def udp_scan(host, porta):
    s = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1)
    try:
        s.sendto(b"\x00", (host, porta))
        s.recvfrom(1024)
        status = "Aberta"
    except socket.timeout:
        status = "Filtrada"
    except ConnectionRefusedError:
        status = "Fechada"
    except Exception:
        status = "Filtrada"
    finally:
        s.close()
    
    service = next((item["name"] for item in WELL_KNOWN_PORTS_UDP if item["port"] == porta), "Desconhecido")
    print(f"Porta {porta} [UDP] {status} - Serviço: {service}")

def find_connected_devices():
    print("Procurando dispositivos na rede...")
    try:
        result = subprocess.check_output(["ip", "neigh"], universal_newlines=True)
        ips = re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", result)
        return list(set(ips))
    except subprocess.CalledProcessError:
        print("Erro ao buscar dispositivos na rede.")
        return []

def forward_lookup():
    dominio = input("Digite o domínio (ex: google.com): ")
    try:
        ip = socket.gethostbyname(dominio)
        print(f"{dominio} → {ip}")
    except socket.gaierror:
        print("Não foi possível resolver o domínio.")

def reverse_lookup():
    ip = input("Digite o IP (ex: 8.8.8.8): ")
    try:
        dominio = socket.gethostbyaddr(ip)[0]
        print(f"{ip} → {dominio}")
    except socket.herror:
        print("Não foi possível encontrar o domínio para esse IP.")

def dns_menu():
    while True:
        print("\n--- DNS Lookup ---")
        print("1. Forward Lookup")
        print("2. Reverse Lookup")
        print("3. Voltar")
        opcao = input("Escolha uma opção: ")

        if opcao == "1":
            forward_lookup()
        elif opcao == "2":
            reverse_lookup()
        elif opcao == "3":
            break
        else:
            print("Opção inválida. Tente novamente.")

def wafw00f_scan():
    url = input("Digite a URL do site para verificar o WAF (ex: http://example.com): ")
    try:
        result = subprocess.check_output(["wafw00f", url], universal_newlines=True)
        print(result)
    except subprocess.CalledProcessError:
        print("Erro ao verificar o site com WAFW00F.")

def resolve_subdomain(subdomain):
    try:
        ip = socket.gethostbyname(subdomain)
        return subdomain, ip
    except (socket.gaierror, socket.timeout):
        return None

def subdomain_enum():
    alvo = input("Digite o domínio principal (ex: example.com): ").strip()
    wordlist_path = input("Caminho para o arquivo com subdomínios: ").strip()

    if not os.path.exists(wordlist_path):
        print("Arquivo de wordlist não encontrado.")
        return

    print("Enumerando subdomínios... Isso pode levar alguns minutos.")

    with open(wordlist_path, "r") as file:
        subdomains = [f"{line.strip()}.{alvo}" for line in file if line.strip()]

    encontrados = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(resolve_subdomain, sub) for sub in subdomains]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                encontrados.append(result)

    if encontrados:
        print("\nSubdomínios encontrados:")
        for sub, ip in encontrados:
            print(f"{sub} → {ip}")
    else:
        print("Nenhum subdomínio encontrado.")

def nmap_vuln_scan():
    alvo = input("Digite o IP ou domínio para escanear com Nmap: ")
    print("Executando Nmap com script de vulnerabilidades (-sV --script vuln)...")
    try:
        subprocess.run(["nmap", "-sV", "--script", "vuln", alvo])
    except FileNotFoundError:
        print("Nmap não encontrado. Certifique-se de que está instalado e no PATH.")
    except Exception as e:
        print(f"Ocorreu um erro ao executar o Nmap: {e}")

def portscanner_menu():
    while True:
        print("\n--- Port Scanner ---")
        print("1. Escanear portas TCP")
        print("2. Escanear portas UDP")
        print("3. Encontrar dispositivos conectados à rede Wi-Fi")
        print("4. Voltar")
        opcao = input("Escolha uma opção: ")

        if opcao == "1":
            protocolo = "TCP"
            scan_func = port_scan
            well_known_ports = WELL_KNOWN_PORTS_TCP
        elif opcao == "2":
            protocolo = "UDP"
            scan_func = udp_scan
            well_known_ports = WELL_KNOWN_PORTS_UDP
        elif opcao == "3":
            devices = find_connected_devices()
            if not devices:
                print("Nenhum dispositivo encontrado.")
                continue
            print("Dispositivos encontrados:")
            for device in devices:
                print(device)
            continue
        elif opcao == "4":
            break
        else:
            print("Opção inválida. Tente novamente.")
            continue

        host = input("Digite o endereço IP ou domínio: ")
        try:
            family = socket.AF_INET6 if ':' in host else socket.AF_INET
            host_ip = socket.getaddrinfo(host, None, family)[0][4][0]
            portas = input(f"Digite a porta ou um range para escaneamento {protocolo} (ex: 80 ou 20-25), 'all' para todas ou 'wk' para portas conhecidas (Well-Known): ")
            if portas == "all":
                for porta in range(1, 65536):
                    scan_func(host_ip, porta)
            elif "-" in portas:
                start_port, end_port = map(int, portas.split("-"))
                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    print("Range de portas inválido.")
                else:
                    for porta in range(start_port, end_port + 1):
                        scan_func(host_ip, porta)
            elif portas == "wk":
                for item in well_known_ports:
                    scan_func(host_ip, item["port"])
            else:
                porta = int(portas)
                scan_func(host_ip, porta)
        except ValueError:
            print("Entrada inválida. Digite um número ou um intervalo válido.")
        except socket.gaierror:
            print("Host inválido, tente novamente.")

def main():
    while True:
        print("\n=== Ferramentas de Hacking ===")
        print("1. Port Scanner")
        print("2. DNS Lookup")
        print("3. Verificar Firewall com WAFW00F")
        print("4. Enumeração de Subdomínios")
        print("5. Scan de Vulnerabilidades com Nmap")
        print("6. Sair")
        opcao = input("Escolha uma opção: ")

        if opcao == "1":
            portscanner_menu()
        elif opcao == "2":
            dns_menu()
        elif opcao == "3":
            wafw00f_scan()
        elif opcao == "4":
            subdomain_enum()
        elif opcao == "5":
            nmap_vuln_scan()
        elif opcao == "6":
            print("Saindo...")
            sys.exit(0)
        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()
