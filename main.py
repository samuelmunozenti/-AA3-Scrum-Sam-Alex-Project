from scapy.all import sniff, conf, get_if_list, IP, TCP, UDP
import logging
from datetime import datetime

# Configuración del logger para registrar eventos en un archivo
logging.basicConfig(
    filename="network_traffic.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def list_interfaces():
    """
    Lista todas las interfaces de red disponibles en el sistema.
    """
    print("Interfaces de red disponibles:")
    interfaces = get_if_list()
    for idx, iface in enumerate(interfaces):
        print(f"{idx + 1}. {iface}")
    return interfaces

def packet_callback(packet):
    """
    Función que procesa cada paquete capturado y extrae metadatos clave.
    """
    try:
        # Verifica si el paquete tiene capa IP
        if IP in packet:
            src_ip = packet[IP].src  # Dirección IP de origen
            dst_ip = packet[IP].dst  # Dirección IP de destino
            protocol = packet[IP].proto  # Protocolo utilizado

            # Verifica si es un paquete TCP o UDP para capturar puertos
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol_name = "TCP"
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol_name = "UDP"
            else:
                src_port = dst_port = "N/A"
                protocol_name = "Otros"

            # Registro de los metadatos del paquete
            log_message = (
                f"Protocolo: {protocol_name}, "
                f"IP Origen: {src_ip}, Puerto Origen: {src_port}, "
                f"IP Destino: {dst_ip}, Puerto Destino: {dst_port}, "
                f"Protocolo Numérico: {protocol}"
            )
            logging.info(log_message)
            print(log_message)

    except Exception as e:
        logging.error(f"Error procesando paquete: {e}")

def start_sniffing(interface):
    """
    Función para iniciar la captura de paquetes en la interfaz especificada.
    """
    print(f"Iniciando la captura de paquetes en la interfaz: {interface}")
    logging.info(f"Captura de paquetes iniciada en la interfaz: {interface}")

    try:
        # Captura de paquetes con un callback para procesarlos
        sniff(iface=interface, prn=packet_callback, store=False)
    except PermissionError:
        logging.error("Permisos insuficientes para capturar paquetes. Ejecuta como administrador.")
        print("Error: Permisos insuficientes. Por favor, ejecuta este script como administrador.")
    except Exception as e:
        logging.error(f"Error al iniciar la captura: {e}")
        print(f"Error al iniciar la captura: {e}")

if __name__ == "__main__":
    import argparse

    # Parser para obtener la interfaz de red
    parser = argparse.ArgumentParser(description="Sistema de Detección de Intrusiones (IDS) - Captura de paquetes")
    parser.add_argument(
        "--interface",
        help="Interfaz de red donde se capturarán los paquetes (e.g., eth0, wlan0). Si no se especifica, se solicitará al usuario elegir una.",
    )

    args = parser.parse_args()

    # Listar interfaces si no se especifica una
    if not args.interface:
        interfaces = list_interfaces()
        selected_index = int(input("Selecciona el número de la interfaz que deseas monitorizar: ")) - 1

        if selected_index < 0 or selected_index >= len(interfaces):
            print("Selección inválida. Finalizando el programa.")
            exit(1)

        selected_interface = interfaces[selected_index]
    else:
        selected_interface = args.interface

    # Iniciar la captura en la interfaz seleccionada
    start_sniffing(selected_interface)
