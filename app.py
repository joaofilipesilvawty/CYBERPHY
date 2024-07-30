import re
import time
import socket
import logging
from concurrent.futures import ThreadPoolExecutor
from scapy.all import *
import psutil

# Configuración del registro de logs
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def validate_ip(ip):
    # Valida si una dirección IP es válida utilizando una expresión regular
    pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    return bool(re.match(pattern, ip))


def iso_iec_27002_security_checks(ip):
    # Realiza chequeos de seguridad basados en la norma ISO/IEC 27002 utilizando nmap
    nm_scanner = nmap.PortScanner()
    nm_scanner.scan(ip, arguments="-sn")
    for host in nm_scanner.all_hosts():
        if nm_scanner[host].state() == "up":
            return "✔️ ¡Host detectado!"
    return "❌ Host no detectado"


def scan_open_ports(ip, port_range, nmap_options):
    # Escanea los puertos abiertos en una IP específica dentro de un rango dado
    nm_scanner = nmap.PortScanner()
    nm_scanner.scan(ip, port_range, arguments=nmap_options)
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


def capture_packets(interface, timeout=None):
    # Captura paquetes en una interfaz de red específica por un tiempo determinado
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
            f"Capturados {len(packets)} paquetes en {elapsed_time:.2f} segundos"
        )
    else:
        sniff(prn=lambda x: packets.append(x), filter="", iface=interface, store=0)
    return packets


def save_packets(packets, pcap_filename):
    # Guarda los paquetes capturados en un archivo .pcap
    wrpcap(pcap_filename, packets)
    logging.info(f"✔️ Paquetes capturados guardados en: {pcap_filename}")


def print_results(ip, port_range, open_ports, security_checks, nmap_options, capture):
    # Imprime los resultados del escaneo de puertos y chequeos de seguridad
    logging.info("Resultados:")
    logging.info(f"Dirección IP: {ip}")
    logging.info(f"Rango de Puertos: {port_range}")
    logging.info("Puertos Abiertos:")
    if open_ports:
        for open_port in open_ports:
            logging.info(open_port)
    else:
        logging.info("❌ No se encontraron puertos abiertos.")
    logging.info(f"Chequeos de Seguridad: {security_checks}")
    logging.info(f"Opciones de Nmap: {nmap_options}")


def get_available_interfaces():
    # Obtiene una lista de interfaces de red disponibles en el sistema
    interfaces = []
    for interface, interface_data in psutil.net_if_addrs().items():
        for address in interface_data:
            if address.family == socket.AF_INET:
                interfaces.append(interface)
                break
    return interfaces


def scan_hosts(ip_list, port_range, nmap_options):
    # Escanea múltiples hosts para puertos abiertos y realiza chequeos de seguridad
    open_ports = []
    security_checks = []
    with ThreadPoolExecutor() as executor:
        security_check_futures = [
            executor.submit(iso_iec_27002_security_checks, ip) for ip in ip_list
        ]
        port_scan_futures = [
            executor.submit(scan_open_ports, ip, port_range, nmap_options)
            for ip in ip_list
        ]

        for future in security_check_futures:
            security_checks.append(future.result())

        for future in port_scan_futures:
            open_ports.extend(future.result())

    return open_ports, security_checks


if __name__ == "__main__":
    try:
        # Solicita al usuario que ingrese las direcciones IP y valida el formato
        ip_list = (
            input("Ingrese las direcciones IP (separadas por comas): ")
            .replace(" ", "")
            .split(",")
        )
        for ip in ip_list:
            if not validate_ip(ip):
                raise ValueError(f"Formato de dirección IP inválido: {ip}")
        logging.info("✔️ Dirección(es) IP válidas")

        # Solicita al usuario que ingrese el rango de puertos a escanear
        port = input(
            "Ingrese el rango de puertos (deje en blanco para escanear todos los puertos): "
        ).strip()
        if port:
            if "-" in port:
                port_range = port
            else:
                if not port.isdigit() or int(port) < 1 or int(port) > 65535:
                    raise ValueError("Rango de puertos inválido.")
                port_range = f"{port}-{port}"
        else:
            port_range = "1-65535"
        logging.info("✔️ Rango de puertos válido")

        # Solicita al usuario que ingrese opciones de Nmap
        nmap_options = input(
            "Ingrese las opciones de Nmap (deje en blanco para las predeterminadas): "
        ).strip()
        if not nmap_options:
            nmap_options = "-sS -p " + port_range

        # Obtiene las interfaces de red disponibles y solicita al usuario que seleccione una
        interfaces = get_available_interfaces()
        if not interfaces:
            raise ValueError("❌ No hay interfaces de red disponibles.")

        logging.info("Interfaces disponibles:")
        for i, iface in enumerate(interfaces, start=1):
            logging.info(f"{i}. {iface}")

        interface_select = input("Seleccione la interfaz de red por número: ").strip()
        interface_index = int(interface_select) - 1
        if interface_index < 0 or interface_index >= len(interfaces):
            raise ValueError("❌ Número de interfaz inválido.")

        selected_interface = interfaces[interface_index]

        # Solicita el tiempo de espera para la captura de paquetes
        timeout = int(
            input(
                "Ingrese el tiempo de espera para la captura de paquetes en segundos (0 para captura continua): "
            )
        )

        # Realiza el escaneo de hosts y la captura de paquetes
        open_ports, security_checks = scan_hosts(ip_list, port_range, nmap_options)
        capture = capture_packets(selected_interface, timeout)

        for ip, security_check in zip(ip_list, security_checks):
            print_results(
                ip, port_range, open_ports, security_check, nmap_options, capture
            )

        # Solicita al usuario si desea guardar los paquetes capturados
        save_capture = input(
            "¿Guardar los paquetes capturados en un archivo .pcap? (s/n): "
        ).lower()
        if save_capture == "s":
            pcap_filename = input("Ingrese el nombre del archivo .pcap: ")
            save_packets(capture, pcap_filename)

    except Exception as e:
        logging.error(f"Error: {e}")
    except KeyboardInterrupt:
        logging.info("\nCaptura de paquetes interrumpida por el usuario.")
        if capture:
            save_capture = input(
                "¿Guardar los paquetes capturados en un archivo .pcap? (s/n): "
            ).lower()
            if save_capture == "s":
                pcap_filename = input("Ingrese el nombre del archivo .pcap: ")
                save_packets(capture, pcap_filename)
