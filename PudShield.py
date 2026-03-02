"""
PUD-Shield — Herramienta de análisis y respuesta ante amenazas en sistemas locales.
Versión mejorada: seguridad, caché OSINT, lista blanca editable, logging robusto.
"""

import psutil
import platform
import ipaddress
import subprocess
import datetime
import ctypes
import json
import logging
import os
import urllib.request
from functools import lru_cache

# ─────────────────────────────────────────────
#  Constantes y archivos persistentes
# ─────────────────────────────────────────────
LOG_FILE                = "escaneo_logs.txt"
PUERTOS_VALIDADOS_FILE  = "puertos_seguros.txt"       
OSINT_CACHE_FILE        = "osint_cache.json"
PROCESOS_LEGITIMOS_FILE = "procesos_legitimos.txt"

# ─────────────────────────────────────────────
#  Logging centralizado (reemplaza log manual)
# ─────────────────────────────────────────────
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    encoding="utf-8",
)

def log(mensaje: str) -> None:
    logging.info(mensaje)


# ─────────────────────────────────────────────
#  Verificación de permisos de administrador
# ─────────────────────────────────────────────
def es_administrador() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except AttributeError:
        # Linux/macOS
        return os.geteuid() == 0
    except Exception:
        return False


# ─────────────────────────────────────────────
#  Caché OSINT persistente (JSON local)
# ─────────────────────────────────────────────
def _cargar_cache_osint() -> dict:
    try:
        with open(OSINT_CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def _guardar_cache_osint(cache: dict) -> None:
    try:
        with open(OSINT_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
    except OSError as e:
        print(f" No se pudo guardar caché OSINT: {e}")


# ─────────────────────────────────────────────
#  Lista blanca de procesos legítimos (editable)
# ─────────────────────────────────────────────
_DEFAULTS_WINDOWS = [
    "System", "svchost.exe", "explorer.exe",
    "msedge.exe", "chrome.exe", "mysqld.exe",
    "lsass.exe", "services.exe", "wininit.exe",
]
_DEFAULTS_LINUX = [
    "sshd", "systemd", "nginx", "apache2",
    "postgres", "python3", "bash",
]

def _crear_lista_blanca_si_no_existe() -> None:
    if not os.path.exists(PROCESOS_LEGITIMOS_FILE):
        sistema = platform.system().lower()
        defaults = _DEFAULTS_WINDOWS if sistema == "windows" else _DEFAULTS_LINUX
        try:
            with open(PROCESOS_LEGITIMOS_FILE, "w", encoding="utf-8") as f:
                f.write("# Agrega o elimina procesos legítimos (uno por línea)\n")
                f.write("# Las líneas que empiezan con # son comentarios\n\n")
                for p in defaults:
                    f.write(f"{p}\n")
        except OSError as e:
            print(f"  No se pudo crear lista blanca: {e}")

def cargar_procesos_legitimos() -> list:
    _crear_lista_blanca_si_no_existe()
    try:
        with open(PROCESOS_LEGITIMOS_FILE, "r", encoding="utf-8") as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            ]
    except OSError:
        return _DEFAULTS_WINDOWS


# ─────────────────────────────────────────────
#  Puertos validados
# ─────────────────────────────────────────────
def cargar_puertos_validados() -> list:
    try:
        with open(PUERTOS_VALIDADOS_FILE, "r", encoding="utf-8") as f:
            return [int(line.strip()) for line in f if line.strip().isdigit()]
    except FileNotFoundError:
        return []

def guardar_puerto_validado(puerto: int) -> None:
    try:
        with open(PUERTOS_VALIDADOS_FILE, "a", encoding="utf-8") as f:
            f.write(f"{puerto}\n")
    except OSError as e:
        print(f"  Error al guardar puerto validado: {e}")


# ─────────────────────────────────────────────
#  Verificación de firma digital (cacheada)
# ─────────────────────────────────────────────
@lru_cache(maxsize=256)
def verificar_firma(ruta: str) -> str:
    """Cacheada por ruta para evitar lanzar múltiples subprocesos de PowerShell."""
    sistema = platform.system().lower()
    if sistema != "windows":
        return " Verificación de firma no disponible en este Sistema Operativo"
    try:
        resultado = subprocess.check_output(
            ["powershell", "-Command",
             f"Get-AuthenticodeSignature '{ruta}' | Select-Object -ExpandProperty Status"],
            shell=False,          # ← sin shell=True
            text=True,
            timeout=5,
            stderr=subprocess.DEVNULL,
        )
        return " Firma digital válida" if "Valid" in resultado else "  Firma no válida o ausente"
    except subprocess.TimeoutExpired:
        return "  Tiempo agotado al verificar firma"
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        return f"  No se pudo verificar firma: {e}"


# ─────────────────────────────────────────────
#  Clase principal
# ─────────────────────────────────────────────
class PUDShield:
    def __init__(self):
        self.sistema            = platform.system()
        self.puertos_validados  = cargar_puertos_validados()
        self.procesos_legitimos = cargar_procesos_legitimos()
        self._osint_cache       = _cargar_cache_osint()

        log(f"  Sistema operativo detectado: {self.sistema}")

        # ── Advertencia de permisos (no bloquea, solo avisa) ──
        if not es_administrador():
            print(
                "\n  ADVERTENCIA: PUD-Shield no se está ejecutando como administrador.\n"
                "   El bloqueo de IPs y algunas verificaciones pueden no funcionar.\n"
                "   Se recomienda ejecutar con privilegios elevados.\n"
            )
            log("  Iniciado sin privilegios de administrador.")

    # ── OSINT con caché JSON ─────────────────────────────────
    def reputacion_ip_profunda(self, ip: str) -> str:
        """Consulta ipinfo.io solo si la IP no está en caché local."""
        if ip in self._osint_cache:
            return self._osint_cache[ip]

        try:
            url = f"https://ipinfo.io/{ip}/json"
            with urllib.request.urlopen(url, timeout=5) as response:   # sin requests
                data = json.loads(response.read().decode())
            org      = data.get("org",      "Sin datos")
            country  = data.get("country",  "Desconocido")
            hostname = data.get("hostname", "N/A")
            resultado = f"Org: {org} | País: {country} | Host: {hostname}"
        except Exception as e:
            resultado = f"No se pudo obtener reputación OSINT ({e})"

        self._osint_cache[ip] = resultado
        _guardar_cache_osint(self._osint_cache)
        return resultado

    # ── Validación de IPs ────────────────────────────────────
    def es_ip_sospechosa(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return (
                ip_obj.is_reserved or ip_obj.is_loopback
                or ip_obj.is_unspecified or ip_obj.is_multicast
            )
        except ValueError:
            return False

    def _validar_ip_formato(self, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    # ── Validación de servicios ──────────────────────────────
    def validar_servicio(self, pid, puerto: int) -> str:
        if puerto in self.puertos_validados:
            return f" Puerto {puerto} validado manualmente por el usuario"
        if pid is None:
            return "  Sin PID asociado"
        try:
            proc   = psutil.Process(pid)
            nombre = proc.name()
            ruta   = proc.exe()
            firma  = verificar_firma(ruta)   # cacheada con lru_cache

            if nombre in self.procesos_legitimos:
                return f" Servicio legítimo: {nombre} | Ruta: {ruta} | {firma}"
            else:
                return f"  Proceso no estándar: {nombre} | Ruta: {ruta} | {firma}"

        except psutil.NoSuchProcess:
            return f"  Proceso no encontrado para PID {pid}"
        except psutil.AccessDenied:
            return f"  Acceso denegado al proceso PID {pid}"
        except Exception as e:
            return f" Error al validar PID {pid}: {e}"

    # ── Bloqueo de IPs ───────────────────────────────────────
    def bloquear_ip(self, ip: str) -> None:
        if not self._validar_ip_formato(ip):
            print(f" '{ip}' no es una IP válida. Operación cancelada.")
            return

        if self.sistema.lower() == "windows":
            try:
                subprocess.run(
                    [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name=Bloqueo_{ip}",
                        "dir=in", "action=block",
                        f"remoteip={ip}",
                    ],
                    shell=False,           # ← sin shell=True
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                print(f" IP {ip} bloqueada exitosamente.")
                log(f"IP bloqueada: {ip}")
            except subprocess.CalledProcessError as e:
                print(f" Error al bloquear IP (¿permisos de admin?): {e.stderr.strip()}")
            except subprocess.TimeoutExpired:
                print(" Tiempo de espera agotado al ejecutar netsh.")
            except FileNotFoundError:
                print(" netsh no encontrado. ¿Estás en Windows?")
        else:
            print("ℹ  Bloqueo automático solo disponible en Windows por ahora.")

    # ── Respuesta ante incidentes ────────────────────────────
    def respuesta_ante_incidente(self, ip: str, puerto: int, pid) -> None:
        reputacion = self.reputacion_ip_profunda(ip)
        keywords   = ("hosting", "vpn", "tor", "proxy", "datacenter")
        if any(kw in reputacion.lower() for kw in keywords) or self.es_ip_sospechosa(ip):
            print(f"\n  IP sospechosa detectada: {ip}")
            print(f"   Reputación: {reputacion}")
            confirmar = input("   ¿Deseas bloquear esta IP? (s/n): ").strip().lower()
            if confirmar == "s":
                self.bloquear_ip(ip)
                log(f"IP bloqueada por respuesta ante incidente: {ip}")

    # ── Análisis de puerto específico ────────────────────────
    def analizar_puerto_sospechoso(self) -> None:
        print("\n Análisis de puerto sospechoso")
        try:
            puerto = int(input("Ingresa el número de puerto a analizar: ").strip())
            if not (0 <= puerto <= 65535):
                raise ValueError
        except ValueError:
            print(" Puerto inválido. Debe ser un número entre 0 y 65535.")
            return

        conexiones  = psutil.net_connections(kind="inet")
        encontrados = [
            c for c in conexiones
            if (c.laddr and c.laddr.port == puerto)
            or (c.raddr and c.raddr.port == puerto)
        ]

        if not encontrados:
            print(f" No se encontró ningún proceso usando el puerto {puerto}.")
            return

        for conn in encontrados:
            pid = conn.pid
            try:
                if pid is None:
                    print(f"  Puerto {puerto} en uso pero sin PID asociado.")
                    continue

                proc   = psutil.Process(pid)
                nombre = proc.name()
                ruta   = proc.exe()
                inicio = datetime.datetime.fromtimestamp(
                    proc.create_time()
                ).strftime("%Y-%m-%d %H:%M:%S")

                print(f"\n Proceso en puerto {puerto}:")
                print(f"   Nombre : {nombre}")
                print(f"   Ruta   : {ruta}")
                print(f"   Inicio : {inicio}")
                print(f"   Estado : {self.validar_servicio(pid, puerto)}")

                if conn.raddr and hasattr(conn.raddr, "ip"):
                    ip_remota  = conn.raddr.ip
                    reputacion = self.reputacion_ip_profunda(ip_remota)
                    sospechosa = self.es_ip_sospechosa(ip_remota)
                    print(f"   IP remota  : {ip_remota}")
                    print(f"   Reputación : {reputacion}")
                    print(f"   {' Sospechosa' if sospechosa else ' IP válida'}")
                    self.respuesta_ante_incidente(ip_remota, puerto, pid)

                confirmar = input("\n¿Marcar este puerto como válido y seguro? (s/n): ").strip().lower()
                if confirmar == "s":
                    guardar_puerto_validado(puerto)
                    self.puertos_validados.append(puerto)
                    log(f" Puerto {puerto} marcado como válido por el analista.")
                    print(f" Puerto {puerto} tratado como seguro de ahora en adelante.")

            except psutil.NoSuchProcess:
                print(" Proceso no encontrado.")
            except psutil.AccessDenied:
                print(f" Acceso denegado al proceso PID {pid}.")
            except Exception as e:
                print(f" Error al analizar el puerto: {e}")

    # ── Modo silencioso ──────────────────────────────────────
    def modo_silencioso(self) -> None:
        print("\n  Ejecutando escaneo en modo silencioso...")
        anomalias = 0
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN":
                puerto     = conn.laddr.port
                pid        = conn.pid
                validacion = self.validar_servicio(pid, puerto)
                log(f"[Silencioso] Puerto {puerto} | PID: {pid} | {validacion}")
                if "⚠️" in validacion or "❌" in validacion:
                    print(f"  Anomalía en puerto {puerto}: {validacion}")
                    anomalias += 1
        print(f"\n Escaneo completado. Anomalías detectadas: {anomalias}")

    # ── Ver conexiones activas ───────────────────────────────
    def ver_conexiones(self) -> None:
        print("\n🔍 Conexiones activas:")
        log("🔍 Conexiones activas:")

        validados, sospechosos, established = [], [], []

        for conn in psutil.net_connections(kind="inet"):
            laddr  = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr  = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            pid    = conn.pid
            estado = conn.status

            try:
                proceso = psutil.Process(pid).name() if pid else "N/A"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proceso = "Desconocido"

            sospechosa = self.es_ip_sospechosa(conn.raddr.ip) if conn.raddr else False
            validacion = self.validar_servicio(pid, conn.laddr.port if conn.laddr else 0)
            marca      = "  Sospechosa" if sospechosa else ""
            mensaje    = f"[{estado}] {laddr} → {raddr} | PID: {pid} ({proceso}) {marca} | {validacion}"

            if "✅" in validacion:
                validados.append(mensaje)
            elif "⚠️" in validacion or "❌" in validacion:
                sospechosos.append(mensaje)
            elif estado == "ESTABLISHED":
                established.append(mensaje)

        print(f"\n Puertos seguros validados ({len(validados)}):")
        for m in validados:
            print(f"  {m}"); log(m)

        print(f"\n  Puertos con procesos no estándar ({len(sospechosos)}):")
        for m in sospechosos:
            print(f"  {m}"); log(m)

        print(f"\n Conexiones establecidas ({len(established)}):")
        for m in established:
            print(f"  {m}"); log(m)

    # ── Ver servicios en escucha ─────────────────────────────
    def ver_servicios_escucha(self) -> None:
        print("\n Servicios en escucha:")
        log(" Servicios en escucha:")

        validados, sospechosos = [], []

        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN":
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                pid   = conn.pid
                try:
                    proceso = psutil.Process(pid).name() if pid else "N/A"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proceso = "Desconocido"

                validacion = self.validar_servicio(pid, conn.laddr.port if conn.laddr else 0)
                mensaje    = f"[LISTEN] {laddr} | PID: {pid} ({proceso}) | {validacion}"

                if "✅" in validacion:
                    validados.append(mensaje)
                else:
                    sospechosos.append(mensaje)

        print(f"\n Puertos seguros en escucha ({len(validados)}):")
        for m in validados: print(f"  {m}"); log(m)

        print(f"\n  Puertos sospechosos en escucha ({len(sospechosos)}):")
        for m in sospechosos: print(f"  {m}"); log(m)

    # ── Ver puertos abiertos ─────────────────────────────────
    def ver_puertos_abiertos(self) -> None:
        print("\nPuertos abiertos:")
        log("Puertos abiertos:")
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN":
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                pid   = conn.pid
                try:
                    proceso = psutil.Process(pid).name() if pid else "N/A"
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proceso = "Desconocido"
                validacion = self.validar_servicio(pid, conn.laddr.port if conn.laddr else 0)
                mensaje    = f"{laddr} | PID: {pid} ({proceso}) | {validacion}"
                print(mensaje); log(mensaje)

    # ── Recursos del sistema ─────────────────────────────────
    def mostrar_recursos(self) -> None:
        print("\n Recursos del sistema:")
        log(" Recursos del sistema:")

        ruta_disco = "C:\\" if self.sistema.lower() == "windows" else "/"   
        try:
            disco = psutil.disk_usage(ruta_disco).percent
        except OSError:
            disco = "N/A"

        ram = psutil.virtual_memory().percent
        cpu = psutil.cpu_percent(interval=1)
        print(f"   RAM usada  : {ram}%")
        print(f"   CPU usada  : {cpu}%")
        print(f"   Disco usado: {disco}%")
        log(f"RAM: {ram}%, CPU: {cpu}%, Disco: {disco}%")

    # ── Editar lista blanca ──────────────────────────────────
    def editar_lista_blanca(self) -> None:
        """Abre procesos_legitimos.txt con el editor predeterminado."""
        print(f"\n Abriendo '{PROCESOS_LEGITIMOS_FILE}' para edición...")
        try:
            if self.sistema.lower() == "windows":
                os.startfile(PROCESOS_LEGITIMOS_FILE)
            else:
                editor = os.environ.get("EDITOR", "nano")
                subprocess.run([editor, PROCESOS_LEGITIMOS_FILE], shell=False)
            print("   Recarga la herramienta para aplicar los cambios.")
        except Exception as e:
            print(f" No se pudo abrir el archivo: {e}")
            print(f"   Edítalo manualmente en: {os.path.abspath(PROCESOS_LEGITIMOS_FILE)}")


# ─────────────────────────────────────────────
#  Menú principal
# ─────────────────────────────────────────────
def menu() -> None:
    shield = PUDShield()

    opciones = {
        "1": ("Ver conexiones activas",          shield.ver_conexiones),
        "2": ("Ver servicios en escucha",         shield.ver_servicios_escucha),
        "3": ("Bloquear IP sospechosa",           None),
        "4": ("Ver puertos abiertos",             shield.ver_puertos_abiertos),
        "5": ("Mostrar recursos del sistema",     shield.mostrar_recursos),
        "6": ("Analizar puerto sospechoso",       shield.analizar_puerto_sospechoso),
        "7": ("Ejecutar modo silencioso",         shield.modo_silencioso),
        "8": ("Editar lista blanca de procesos",  shield.editar_lista_blanca),
        "9": ("Salir",                            None),
    }

    while True:
        print("\n" + "═" * 40)
        print("         Menú PUD-Shield")
        print("═" * 40)
        for k, (desc, _) in opciones.items():
            print(f"  {k}. {desc}")
        print("═" * 40)

        opcion = input("Selecciona una opción: ").strip()

        if opcion == "3":
            print("\n Bloqueo de IP")
            ip = input("IP a bloquear (o 'salir'): ").strip()
            if ip.lower() not in ("salir", ""):
                shield.bloquear_ip(ip)
            else:
                print("Volviendo al menú principal...")

        elif opcion == "9":
            print(" Saliendo de PUD-Shield...")
            break

        elif opcion in opciones:
            opciones[opcion][1]()

        else:
            print(" Opción inválida.")


if __name__ == "__main__":
    menu()