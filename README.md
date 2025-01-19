# Sistema de Detección de Intrusiones (IDS) - Proyecto en Python

## Descripción del Proyecto
Este proyecto tiene como objetivo desarrollar un **Sistema de Detección de Intrusiones (IDS)** básico utilizando Python. Un IDS es una herramienta crítica en ciberseguridad que permite monitorizar el tráfico de red y detectar actividades maliciosas o anómalas que puedan comprometer la seguridad de un sistema o red.

El proyecto incluye la investigación, desarrollo y optimización de un IDS capaz de detectar diversos tipos de ataques comunes y proporcionar alertas en tiempo real sobre posibles intrusiones.

---

## Objetivos Clave
1. **Estudiar los sistemas IDS y sus características principales:**
   - Comprender cómo funcionan los IDS, su arquitectura y los métodos utilizados para detectar intrusiones.
   - Analizar las diferencias entre IDS basados en firmas y en anomalías, así como sus ventajas y desventajas.

2. **Relevancia de un IDS en el entorno actual:**
   - En un mundo cada vez más digitalizado, las amenazas cibernéticas están en constante evolución.
   - Un IDS permite identificar intentos de acceso no autorizado, proteger datos críticos y mejorar la postura de seguridad general de una organización.

3. **Ataques detectados por el IDS:**
   - Identificar y configurar el IDS para detectar ataques específicos como:
     - **Escaneos de puertos:** Actividad común que los atacantes utilizan para mapear servicios abiertos en un sistema.
     - **SYN Flood:** Ataques de denegación de servicio (DoS) que saturan recursos del servidor con solicitudes incompletas.
     - **Ataques de fuerza bruta:** Intentos repetidos de acceder mediante combinaciones de contraseñas.

4. **Evaluación de la relevancia de intrusiones según el entorno:**
   - Analizar el impacto de cada tipo de ataque en diferentes escenarios, como redes corporativas, personales o industriales.
   - Priorizar la implementación de reglas en función del riesgo y frecuencia de los ataques.

---

## Características del Sistema IDS
- **Captura en tiempo real:** Escucha el tráfico de red y captura paquetes.
- **Análisis detallado:** Identifica patrones maliciosos basados en reglas predefinidas.
- **Alertas en tiempo real:** Notificaciones automáticas cuando se detectan posibles intrusiones.
- **Modularidad:** Capacidad para agregar nuevos tipos de detección fácilmente.

---

## Requisitos del Proyecto
- **Lenguaje:** Python 3.8+
- **Bibliotecas utilizadas:**
  - `scapy` para captura y análisis de paquetes.
  - `logging` para registro de eventos.
  - `argparse` para opciones de configuración.

---

## Instalación
1. Clona este repositorio:
   ```bash
   git clone https://github.com/tu-usuario/tu-repositorio.git
   ```
2. Instala las dependencias:
   ```bash
   pip install -r requirements.txt
   ```
3. Ejecuta el sistema IDS:
   ```bash
   python ids.py --interface eth0
   ```

---

## Cómo Contribuir
Las contribuciones son bienvenidas. Por favor, sigue los pasos a continuación:
1. Haz un fork del repositorio.
2. Crea una nueva rama:
   ```bash
   git checkout -b feature/nueva-funcionalidad
   ```
3. Realiza tus cambios y haz un commit:
   ```bash
   git commit -m "Añadir nueva funcionalidad"
   ```
4. Envía tus cambios al repositorio:
   ```bash
   git push origin feature/nueva-funcionalidad
   ```
5. Crea un Pull Request.

---

## Desarrolladores
Para preguntas o sugerencias, puedes contactar en:
- **Àlex Domènech:** [alexdomno](https://github.com/alexdomno)
- **Samuel Munoz:**
