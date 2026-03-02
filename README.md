PUD-Shield

Herramienta modular de análisis y respuesta ante amenazas en sistemas locales — para entusiastas de la ciberseguridad y el hardening.

¿Qué es PUD-Shield?
PUD-Shield es una herramienta de terminal diseñada para usuarios técnicos, desarrolladores y entusiastas de la ciberseguridad que quieren tener visibilidad y control sobre lo que ocurre en su sistema a nivel de red y procesos.
Permite escanear puertos activos, validar procesos y firmas digitales, consultar reputación OSINT de IPs remotas y ejecutar bloqueos estratégicos en tiempo real, todo desde una interfaz de menú simple en la terminal.

Funcionalidades:
Escaneo de conexiones: Muestra todas las conexiones activas clasificadas por estado.
Servicios en escucha: Detecta puertos en estado LISTEN y valida sus procesos.
Reputación OSINT: Consulta ipinfo.io con caché local persistente. 
Bloqueo de IPs: Bloquea IPs directamente en el firewall de Windows.
Lista blanca editable: Archivo .txt editable sin tocar el código.
Logging persistente: Registro automático de todas las acciones con timestamp.
Modo silenciosoEscaneo automatizado sin interacción, solo reporta anomalías.
Recursos del sistema: Snapshot de RAM, CPU y disco en tiempo real.

Requisitos
Python 3.8 o superior
Windows 10 / 11
Terminal con permisos de administrador (necesario para bloqueo de IPs)


Instalación
1. Clona el repositorio
bashgit clone https://github.com/tu-usuario/pud-shield.git
cd pud-shield
2. Instala las dependencias
bashpip install -r requirements.txt
3. Ejecuta como administrador
bashpython EscaneoP.py

Para que el bloqueo de IPs funcione, ejecuta la terminal como Administrador.

Uso
Al ejecutar el script verás el menú principal:
════════════════════════════════════════
          Menú PUD-Shield
════════════════════════════════════════
  1. Ver conexiones activas
  2. Ver servicios en escucha
  3. Bloquear IP sospechosa
  4. Ver puertos abiertos
  5. Mostrar recursos del sistema
  6. Analizar puerto sospechoso
  7. Ejecutar modo silencioso
  8. Editar lista blanca de procesos
  9. Salir
════════════════════════════════════════
Flujo recomendado
Opción 7 (modo silencioso)
    └─▶ Detecta anomalías
         └─▶ Opción 6 (analizar puerto específico)
              └─▶ Confirmar proceso sospechoso
                   └─▶ Opción 3 (bloquear IP)
                        └─▶ Todo queda en escaneo_logs.txt

Archivos generados
escaneo_logs.txt: Registro completo de eventos y decisiones con timestamp.
puertos_seguros.txt: Puertos validados manualmente como confiables.
osint_cache.json: Caché local de consultas OSINT para no repetir requests.
procesos_legitimos.txt: Lista blanca de procesos editada por el usuario.

Personalización
Lista blanca de procesos
Al ejecutar por primera vez se genera automáticamente procesos_legitimos.txt con procesos comunes de Windows. Puedes editarlo directamente desde la opción 8 del menú o abrirlo manualmente:
# Agrega o elimina procesos legítimos (uno por línea)
# Las líneas que empiezan con # son comentarios

svchost.exe
explorer.exe
chrome.exe
Caché OSINT
Las consultas a ipinfo.io se guardan en osint_cache.json. Si quieres forzar una consulta fresca de una IP, simplemente elimina su entrada del archivo o borra el archivo completo.

Consideraciones de seguridad

PUD-Shield no envía ningún dato tuyo a servicios externos, solo consulta la reputación de IPs remotas que ya están conectadas a tu sistema.
El bloqueo de IPs usa netsh advfirewall nativo de Windows, sin dependencias de terceros.
Toda acción queda registrada localmente en escaneo_logs.txt.
La herramienta avisa si se ejecuta sin permisos de administrador pero no bloquea su uso.


Roadmap

 Escaneo de puertos y servicios
 Validación de firma digital
 Reputación OSINT con caché persistente
 Lista blanca editable
 Logging centralizado
 Verificación de permisos de administrador
 Soporte Linux (iptables / ufw)
 Argumentos de línea de comandos (--silent, --block, --scan)
 Módulos separados por funcionalidad
 Exportación de reportes en PDF/HTML


Contribuciones
Las contribuciones son bienvenidas. Si quieres mejorar PUD-Shield:

Haz fork del repositorio
Crea una rama para tu feature (git checkout -b feature/nueva-funcionalidad)
Haz commit de tus cambios (git commit -m 'Agrega nueva funcionalidad')
Haz push a la rama (git push origin feature/nueva-funcionalidad)
Abre un Pull Request


Aviso legal
PUD-Shield está diseñado exclusivamente para uso en sistemas propios o en sistemas donde tienes autorización explícita. El uso de esta herramienta en sistemas ajenos sin permiso puede ser ilegal. Como autor no me responsabilizo del mal uso de la herramienta.

Licencia
Este proyecto está bajo la licencia MIT. Consulta el archivo LICENSE para más detalles.


