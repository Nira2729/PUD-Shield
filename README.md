# PUD-Shield
Escáner modular para sistemas locales. Detecta puertos activos, valida procesos, consulta reputación OSINT y permite bloquear IPs sospechosas. Incluye modo silencioso, simulador de incidentes y persistencia de decisiones.

# PUDShield

**PUDShield** es una herramienta modular de análisis y respuesta ante amenazas en sistemas locales. Diseñada para usuarios técnicos, desarrolladores y entusiastas de la ciberseguridad, permite escanear puertos activos, validar procesos, consultar reputación OSINT de IPs remotas y ejecutar bloqueos estratégicos en tiempo real.

## Funcionalidades principales

- Escaneo de puertos y servicios en escucha
- Validación de procesos y firma digital (Windows)
- Reputación OSINT integrada vía `ipinfo.io`
- Bloqueo de IPs sospechosas mediante firewall
- Persistencia de puertos validados por el analista
- Modo silencioso para escaneo automatizado
- Simulador de incidentes para pruebas defensivas
- Visualización de recursos del sistema (RAM, CPU, disco)
- Identificación de puertos libres para despliegue seguro

## Instalación

```bash
git clone https://github.com/tuusuario/PUDShield.git
cd PUDShield
pip install -r requirements.txt
python EscaneoP.py

Requiere Python 3.8+ y privilegios de administrador para bloqueo de IPs en Windows.

Uso básico
Al ejecutar el script, se presenta un menú interactivo con opciones para escanear, analizar, validar y responder ante conexiones sospechosas. Las decisiones del analista se registran en archivos persistentes (puertos_seguro.txt, escaneo_logs.txt).

Estructura del Proyecto
PUDShield/
├── EscaneoP.py              # Script principal
├── puertos_seguro.txt       # Puertos marcados como seguros
├── escaneo_logs.txt         # Registro de eventos
├── README.md                # Documentación

Licencia
Este proyecto se dsitribuye bajo la licencia MIT.
