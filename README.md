# PUD-Shield
PUD-Shield es una herramienta modular para sistemas locales. Escanea puertos activos, valida procesos, consulta reputación OSINT y permite bloquear IPs sospechosas. Incluye modo silencioso, visualización de recursos y persistencia de decisiones.

# PUD-Shield

PUD-Shield es una herramienta modular de análisis y respuesta ante amenazas en sistemas locales. Diseñada para usuarios técnicos, desarrolladores y entusiastas de la ciberseguridad, permite escanear puertos activos, validar procesos, consultar reputación OSINT de IPs remotas y ejecutar bloqueos estratégicos en tiempo real.

## Funcionalidades principales

- Escaneo de puertos y servicios en escucha
- Validación de procesos y firma digital (Windows)
- Reputación OSINT integrada vía ipinfo.io
- Bloqueo de IPs sospechosas mediante firewall
- Persistencia de puertos validados por el usuario
- Modo silencioso para escaneo automatizado
- Respuesta directa ante incidentes detectados
- Visualización de recursos del sistema (RAM, CPU, disco)

## Instalación y ejecución

### Requisitos

- Python 3.8 o superior  
- Sistema operativo compatible (Windows recomendado para bloqueo de IPs)  
- Acceso a terminal o consola con permisos de ejecución

### Instalación

1. Clona el repositorio o descarga el archivo directamente:
   ```bash
   git clone https://github.com/Nira2729/PUDShield.git
   cd PUDShield
   ```

   O descarga el archivo `EscaneoP.py` desde la pestaña **Code > Download ZIP** y extrae el contenido.

2. Instala las dependencias necesarias:
   ```bash
   pip install psutil requests
   ```

3. Ejecuta el programa:
   ```bash
   python EscaneoP.py
   ```

> Si estás en Windows, ejecuta la terminal como administrador para habilitar el bloqueo de IPs.

---

### Archivos generados automáticamente

- `escaneo_logs.txt`: registro de eventos y decisiones tomadas
- `puetos_seguros.txt`: puertos validados como seguros por el usuario

Licencia
Este proyecto se dsitribuye bajo la licencia MIT.
