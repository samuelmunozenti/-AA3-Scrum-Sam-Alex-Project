from scapy.all import sniff, conf, get_if_list, IP, TCP, UDP
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify
import threading

# Configuración del logger para registrar eventos en un archivo
logging.basicConfig(
    filename="network_traffic.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Diccionario para rastrear conexiones por IP
connection_tracker = defaultdict(list)
port_scan_tracker = defaultdict(set)  # Rastrear escaneos de puertos
syn_flood_tracker = defaultdict(int)  # Contador para posibles ataques SYN Flood
traffic_stats = []  # Lista para estadísticas en tiempo real

alert_threshold = 10  # Número de paquetes desde una misma IP en un intervalo
time_window = timedelta(seconds=10)  # Ventana de tiempo para análisis
syn_flood_threshold = 50  # Umbral de paquetes SYN en un tiempo corto

# Flask App para el panel de control
app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/stats")
def stats():
    return jsonify(traffic_stats)


def generate_alert(alert_type, src_ip, details):
    """
    Genera una alerta detallada con tipo de ataque, IP de origen y detalles adicionales.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_message = (
        f"[ALERTA] Tipo: {alert_type} | IP Origen: {src_ip} | Timestamp: {timestamp} | Detalles: {details}"
    )
    logging.warning(alert_message)
    print(alert_message)
    traffic_stats.append({"tipo": alert_type, "ip": src_ip, "timestamp": timestamp, "detalles": details})


def detect_anomalies(src_ip, timestamp):
    """
    Detecta patrones anómalos como múltiples solicitudes desde la misma IP.
    """
    # Agregar la marca de tiempo al registro de la IP
    connection_tracker[src_ip].append(timestamp)

    # Filtrar registros antiguos fuera de la ventana de tiempo
    recent_timestamps = [
        ts for ts in connection_tracker[src_ip]
        if ts >= timestamp - time_window
    ]
    connection_tracker[src_ip] = recent_timestamps

    # Verificar si supera el umbral
    if len(recent_timestamps) > alert_threshold:
        details = f"{len(recent_timestamps)} solicitudes en los últimos {time_window.seconds} segundos"
        generate_alert("Patrón anómalo", src_ip, details)


def detect_port_scan(src_ip, dst_port):
    """
    Detecta patrones de escaneo de puertos desde una misma IP.
    """
    port_scan_tracker[src_ip].add(dst_port)

    if len(port_scan_tracker[src_ip]) > 5:  # Umbral para detección de escaneo
        details = f"{len(port_scan_tracker[src_ip])} puertos escaneados"
        generate_alert("Escaneo de puertos", src_ip, details)


def detect_syn_flood(src_ip, flag):
    """
    Detecta patrones de SYN Flood basados en paquetes SYN repetidos.
    """
    if flag == 0x02:  # Verifica si el paquete tiene solo la bandera SYN activa
        syn_flood_tracker[src_ip] += 1

        if syn_flood_tracker[src_ip] > syn_flood_threshold:
            details = f"{syn_flood_tracker[src_ip]} paquetes SYN detectados"
            generate_alert("SYN Flood", src_ip, details)


def packet_callback(packet):
    """
    Procesa cada paquete capturado y extrae metadatos clave.
    """
    try:
        # Verifica si el paquete tiene capa IP
        if IP in packet:
            src_ip = packet[IP].src  # Dirección IP de origen
            dst_ip = packet[IP].dst  # Dirección IP de destino
            protocol = packet[IP].proto  # Protocolo utilizado
            timestamp = datetime.now()  # Marca de tiempo del paquete

            # Verifica si es un paquete TCP o UDP para capturar puertos
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol_name = "TCP"
                tcp_flags = packet[TCP].flags

                # Detectar SYN Flood
                detect_syn_flood(src_ip, tcp_flags)

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

            # Detectar patrones anómalos
            detect_anomalies(src_ip, timestamp)

            # Detectar escaneo de puertos
            if dst_port != "N/A":
                detect_port_scan(src_ip, dst_port)

    except Exception as e:
        logging.error(f"Error procesando paquete: {e}")


def start_sniffing(interface):
    """
    Inicia la captura de paquetes en la interfaz especificada.
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


def run_flask():
    """
    Ejecuta la aplicación Flask en un hilo separado.
    """
    app.run(host="0.0.0.0", port=5000, debug=False)


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
        interfaces = get_if_list()
        print("Interfaces de red disponibles:")
        for idx, iface in enumerate(interfaces):
            print(f"{idx + 1}. {iface}")
        selected_index = int(input("Selecciona el número de la interfaz que deseas monitorizar: ")) - 1

        if selected_index < 0 or selected_index >= len(interfaces):
            print("Selección inválida. Finalizando el programa.")
            exit(1)

        selected_interface = interfaces[selected_index]
    else:
        selected_interface = args.interface

    # Iniciar Flask en un hilo separado
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()

    # Iniciar la captura en la interfaz seleccionada
    start_sniffing(selected_interface)



