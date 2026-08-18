import os
import re
import sys
import json
import time
import socket
import ipaddress
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from scapy.all import *
import psutil
import nmap

HISTORY_FILE = "scan_history.json"

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    return []


def save_to_history(scan_type, target, results):
    history = load_history()
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": scan_type,
        "target": target,
        "results": results,
    }
    history.append(entry)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def show_banner():
    clear_screen()
    print("========================================================")
    print()
    print(" ▗▄▄▖▗▖  ▗▖▗▄▄▖ ▗▄▄▄▖▗▄▄▖ ▗▄▄▖ ▗▖ ▗▖▗▖  ▗▖")
    print("▐▌    ▝▚▞▘ ▐▌ ▐▌▐▌   ▐▌ ▐▌▐▌ ▐▌▐▌ ▐▌ ▝▚▞▘ ")
    print("▐▌     ▐▌  ▐▛▀▚▖▐▛▀▀▘▐▛▀▚▖▐▛▀▘ ▐▛▀▜▌  ▐▌  ")
    print("▝▚▄▄▖  ▐▌  ▐▙▄▞▘▐▙▄▄▖▐▌ ▐▌▐▌   ▐▌ ▐▌  ▐▌  ")
    print("                                          ")
    print("========================================================")


def show_menu():
    print()
    print("  1. Descoberta de Hosts")
    print("  2. Escaneamento de Portas")
    print("  3. Captura de Pacotes")
    print("  4. Scan Completo (tudo junto)")
    print("  5. Ver Interfaces de Rede")
    print("  6. Histórico de Scans")
    print()
    print("  0. Sair")
    print()
    print("========================================================")


def validate_ip(ip):
    pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    return bool(re.match(pattern, ip))


def parse_ip_input(raw):
    raw = raw.strip()
    if "/" in raw:
        try:
            ipaddress.ip_network(raw, strict=False)
            return raw
        except ValueError:
            logging.error(f"Rede CIDR invalida: {raw}")
            return None
    else:
        ip_list = [ip.strip() for ip in raw.split() if ip.strip()]
        for ip in ip_list:
            if not validate_ip(ip):
                logging.error(f"Formato de IP invalido: {ip}")
                return None
        return ip_list


def get_input_ips():
    raw = input("  IP ou sub-rede CIDR (ex: 192.168.1.0/24): ")
    return parse_ip_input(raw)


def get_input_port():
    port = input("  Rango de portas (deixe vazio para todas): ").strip()
    if port:
        if "-" in port:
            return port
        if not port.isdigit() or int(port) < 1 or int(port) > 65535:
            logging.error("Rango de portas invalido.")
            return None
        return f"{port}-{port}"
    return "1-65535"


def get_input_nmap():
    nmap_options = input("  Opcoes Nmap (deixe vazio para padrao): ").strip()
    return nmap_options if nmap_options else "-sS"


def iso_iec_27002_security_checks(ip):
    nm_scanner = nmap.PortScanner()
    nm_scanner.scan(hosts=ip, arguments="-sn")
    alive_hosts = []
    for host in nm_scanner.all_hosts():
        if nm_scanner[host].state() == "up":
            alive_hosts.append(host)
    return alive_hosts


def scan_open_ports(ip, port_range, nmap_options):
    nm_scanner = nmap.PortScanner()
    arguments = f"{nmap_options} -p {port_range}"
    nm_scanner.scan(ip, arguments=arguments)
    open_ports = []
    for host in nm_scanner.all_hosts():
        for proto in nm_scanner[host].all_protocols():
            open_ports.extend(
                [
                    p
                    for p, state in nm_scanner[host][proto].items()
                    if state["state"] == "open"
                ]
            )
    return open_ports


def get_available_interfaces():
    interfaces = []
    for interface, interface_data in psutil.net_if_addrs().items():
        for address in interface_data:
            if address.family == socket.AF_INET:
                interfaces.append(interface)
                break
    return interfaces


def select_interface():
    interfaces = get_available_interfaces()
    if not interfaces:
        logging.error("Nao ha interfaces de rede disponiveis.")
        return None
    print()
    print("  Interfaces disponiveis:")
    for i, iface in enumerate(interfaces, start=1):
        print(f"    {i}. {iface}")
    print()
    try:
        idx = int(input("  Selecionar interface (numero): ")) - 1
        if idx < 0 or idx >= len(interfaces):
            logging.error("Numero de interface invalido.")
            return None
        return interfaces[idx]
    except ValueError:
        logging.error("Input invalido.")
        return None


def capture_packets(interface, timeout=None):
    packets = []
    if timeout:
        start_time = time.time()
        stop_filter = lambda x: time.time() - start_time > timeout
        sniff(
            prn=lambda x: packets.append(x),
            filter="",
            iface=interface,
            stop_filter=stop_filter,
        )
        elapsed_time = time.time() - start_time
        logging.info(
            f"Capturados {len(packets)} pacotes em {elapsed_time:.2f} segundos"
        )
    else:
        sniff(prn=lambda x: packets.append(x), filter="", iface=interface, store=0)
    return packets


def save_packets(packets, pcap_filename):
    wrpcap(pcap_filename, packets)
    logging.info(f"✔️ Pacotes guardados em: {pcap_filename}")


def print_results(ip_list, port_range, open_ports, nmap_options):
    print()
    print("  ───────────── Resultados ─────────────")
    print(f"  Alvo: {', '.join(ip_list) if isinstance(ip_list, list) else ip_list}")
    print(f"  Portas: {port_range}")
    print(f"  Opcoes Nmap: {nmap_options}")
    print("  Portas Abertas:")
    if open_ports:
        for port in open_ports:
            print(f"    → {port}")
    else:
        print("    Nenhuma porta aberta encontrada.")
    print("  ──────────────────────────────────────")


def get_target(ip_list):
    if isinstance(ip_list, str):
        return ip_list
    return ip_list[0] if len(ip_list) == 1 else ",".join(ip_list)


def scan_hosts(ip_list, port_range, nmap_options):
    open_ports = []
    target = get_target(ip_list)
    security_check = iso_iec_27002_security_checks(target)
    if isinstance(ip_list, list):
        with ThreadPoolExecutor() as executor:
            port_scan_futures = [
                executor.submit(scan_open_ports, ip, port_range, nmap_options)
                for ip in ip_list
            ]
            for future in port_scan_futures:
                open_ports.extend(future.result())
    else:
        open_ports = scan_open_ports(target, port_range, nmap_options)
    return open_ports, security_check


def opt_discover_hosts():
    show_banner()
    print("  ── Descoberta de Hosts ──")
    print()
    ip_list = get_input_ips()
    if not ip_list:
        return
    print()
    logging.info("A descobrir hosts...")
    target = get_target(ip_list)
    alive = iso_iec_27002_security_checks(target)
    if alive:
        print(f"\n  Hosts ativos encontrados ({len(alive)}):")
        for host in alive:
            print(f"    ✔️  {host}")
        save_to_history("Descoberta de Hosts", target, {"alive_hosts": alive})
    else:
        print("\n  ❌ Nenhum host ativo encontrado.")
    input("\n  Prima Enter para voltar ao menu...")


def opt_port_scan():
    show_banner()
    print("  ── Escaneamento de Portas ──")
    print()
    ip_list = get_input_ips()
    if not ip_list:
        return
    port_range = get_input_port()
    if not port_range:
        return
    nmap_options = get_input_nmap()
    print()
    logging.info("A escanear portas...")
    open_ports, alive_hosts = scan_hosts(ip_list, port_range, nmap_options)
    print(f"\n  Hosts ativos: {', '.join(alive_hosts) if alive_hosts else 'Nenhum'}")
    print_results(ip_list, port_range, open_ports, nmap_options)
    target = get_target(ip_list)
    save_to_history("Escaneamento de Portas", target, {
        "alive_hosts": alive_hosts,
        "open_ports": open_ports,
        "port_range": port_range,
        "nmap_options": nmap_options,
    })
    input("\n  Prima Enter para voltar ao menu...")


def opt_packet_capture():
    show_banner()
    print("  ── Captura de Pacotes ──")
    print()
    interface = select_interface()
    if not interface:
        return
    try:
        timeout = int(
            input("  Tempo de captura em segundos (0 = padrao 60s): ")
        )
    except ValueError:
        logging.error("Tempo invalido.")
        input("\n  Prima Enter para voltar ao menu...")
        return
    if timeout <= 0:
        timeout = 60
        print("  A usar tempo padrao: 60 segundos")
    print()
    logging.info(f"A capturar pacotes em {interface}...")
    packets = capture_packets(interface, timeout)
    print(f"\n  Total de pacotes capturados: {len(packets)}")
    save = input("  Guardar em .pcap? (s/n): ").lower()
    if save == "s":
        filename = input("  Nome do ficheiro: ")
        save_packets(packets, filename)
    input("\n  Prima Enter para voltar ao menu...")


def opt_full_scan():
    show_banner()
    print("  ── Scan Completo ──")
    print()
    ip_list = get_input_ips()
    if not ip_list:
        return
    port_range = get_input_port()
    if not port_range:
        return
    nmap_options = get_input_nmap()
    interface = select_interface()
    if not interface:
        return
    try:
        timeout = int(
            input("  Tempo de captura em segundos (0 = padrao 60s): ")
        )
    except ValueError:
        logging.error("Tempo invalido.")
        input("\n  Prima Enter para voltar ao menu...")
        return
    if timeout <= 0:
        timeout = 60
        print("  A usar tempo padrao: 60 segundos")
    print()
    logging.info("A executar scan completo...")
    open_ports, alive_hosts = scan_hosts(ip_list, port_range, nmap_options)
    print(f"\n  Hosts ativos: {', '.join(alive_hosts) if alive_hosts else 'Nenhum'}")
    print_results(ip_list, port_range, open_ports, nmap_options)
    logging.info(f"A capturar pacotes em {interface}...")
    packets = capture_packets(interface, timeout)
    print(f"\n  Total de pacotes capturados: {len(packets)}")
    save = input("  Guardar pacotes em .pcap? (s/n): ").lower()
    if save == "s":
        filename = input("  Nome do ficheiro: ")
        save_packets(packets, filename)
    target = get_target(ip_list)
    save_to_history("Scan Completo", target, {
        "alive_hosts": alive_hosts,
        "open_ports": open_ports,
        "port_range": port_range,
        "nmap_options": nmap_options,
        "packets_captured": len(packets),
    })
    input("\n  Prima Enter para voltar ao menu...")


def opt_show_interfaces():
    show_banner()
    print("  ── Interfaces de Rede ──")
    print()
    interfaces = get_available_interfaces()
    if not interfaces:
        print("  Nenhuma interface encontrada.")
    else:
        for i, iface in enumerate(interfaces, start=1):
            print(f"    {i}. {iface}")
    input("\n  Prima Enter para voltar ao menu...")


def opt_history():
    show_banner()
    print("  ── Histórico de Scans ──")
    print()
    history = load_history()
    if not history:
        print("  Nenhum scan registado ainda.")
    else:
        for i, entry in enumerate(history, 1):
            print(f"  {i}. [{entry['timestamp']}] {entry['type']}")
            print(f"     Alvo: {entry['target']}")
            if "open_ports" in entry["results"]:
                ports = entry["results"]["open_ports"]
                print(f"     Portas abertas: {', '.join(str(p) for p in ports) if ports else 'Nenhuma'}")
            if "alive_hosts" in entry["results"]:
                hosts = entry["results"]["alive_hosts"]
                print(f"     Hosts ativos: {', '.join(hosts) if hosts else 'Nenhum'}")
            print()
    input("\n  Prima Enter para voltar ao menu...")


def main_menu():
    while True:
        show_banner()
        show_menu()
        choice = input("  Selecionar opcao: ").strip()
        if choice == "1":
            opt_discover_hosts()
        elif choice == "2":
            opt_port_scan()
        elif choice == "3":
            opt_packet_capture()
        elif choice == "4":
            opt_full_scan()
        elif choice == "5":
            opt_show_interfaces()
        elif choice == "6":
            opt_history()
        elif choice == "0":
            show_banner()
            print("  A sair... Ate a proxima!")
            print()
            break
        else:
            logging.error("Opcao invalida.")
            time.sleep(1)


def check_sudo():
    if os.geteuid() != 0:
        print("\n  Nmap precisa de permissoes root. A reiniciar com sudo...")
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)


if __name__ == "__main__":
    try:
        check_sudo()
        main_menu()
    except KeyboardInterrupt:
        print("\n  Interrompido pelo utilizador.")
