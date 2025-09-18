import psutil
import platform
import ipaddress
import subprocess
import datetime
import requests

LOG_FILE = "escaneo_logs.txt"
PUERTOS_VALIDADOS_FILE = "puertos_seguro.txt"

def cargar_puertos_validados():
    try:
        with open(PUERTOS_VALIDADOS_FILE, "r") as f:
            return [int(line.strip()) for line in f if line.strip().isdigit()]
    except FileNotFoundError:
        return []

def guardar_puerto_validado(puerto):
    try:
        with open(PUERTOS_VALIDADOS_FILE, "a") as f:
            f.write(f"{puerto}\n")
    except Exception as e:
        print(f"Error al guardar puerto validado: {e}")

def verificar_firma(ruta):
    comando = f'powershell "Get-AuthenticodeSignature \'{ruta}\' | Select-Object Status"'
    try:
        resultado = subprocess.check_output(comando, shell=True, text=True)
        if "Valid" in resultado:
            return "Firma digital válida"
        else:
            return "Firma no válida o ausente"
    except:
        return "No se pudo verificar la firma"
    
class PUDShield:
    def __init__(self):
        self.sistema = platform.system()
        self.puertos_validados = cargar_puertos_validados()
        self.log(f"🛡️ Sistema operativo detectado: {self.sistema}")

    def log(self, mensaje):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {mensaje}\n")

    def es_ip_sospechosa(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_reserved or ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_multicast
        except ValueError:
            return False

    def reputacion_ip_profunda(self, ip):
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            data = response.json()
            org = data.get("org", "Sin datos")
            country = data.get("country", "Desconocido")
            hostname = data.get("hostname", "N/A")
            return f"Org: {org} | País: {country} | Host: {hostname}"
        except:
            return "No se pudo obtener reputación OSINT"

    def validar_servicio(self, pid, puerto):
        try:
            proc = psutil.Process(pid)
            nombre = proc.name()
            ruta = proc.exe()
            firma = verificar_firma(ruta) if self.sistema.lower() == "windows" else "🔒 Verificación no disponible"

            if puerto in self.puertos_validados:
                return f"✅ Puerto {puerto} validado manualmente | {firma}"

            legitimos_windows = ["System", "svchost.exe", "explorer.exe", "msedge.exe", "chrome.exe", "mysqld.exe"]
            legitimos_linux = ["sshd", "systemd", "nginx", "apache2", "postgres"]
            sistema = self.sistema.lower()

            if sistema == "windows" and nombre not in legitimos_windows:
                return f"⚠️ Proceso no estándar: {nombre} | Ruta: {ruta} | {firma}"
            elif sistema == "linux" and nombre not in legitimos_linux:
                return f"⚠️ Proceso no estándar: {nombre} | Ruta: {ruta}"
            else:
                return f"✅ Servicio legítimo: {nombre} | Ruta: {ruta} | {firma}"
        except psutil.NoSuchProcess:
            return f"Proceso no encontrado para PID {pid}"
        except Exception as e:
            return f"Error al validar PID {pid}: {e}"
    def analizar_puerto_sospechoso(self):
        print("\n🔎 Análisis de puerto sospechoso")

        try:
            puerto = int(input("Ingresa el número de puerto a analizar: ").strip())
        except ValueError:
            print("Puerto inválido.")
            return

        conexiones = psutil.net_connections(kind='all')
        encontrados = False

        for conn in conexiones:
            if conn.laddr and hasattr(conn.laddr, 'port') and conn.laddr.port == puerto:
                encontrados = True
                pid = conn.pid

                try:
                    if pid is None:
                        print(f"⚠️ Puerto {puerto} está en uso pero no tiene PID asociado.")
                        continue

                    proc = psutil.Process(pid)
                    nombre = proc.name()
                    ruta = proc.exe()
                    tiempo = datetime.datetime.fromtimestamp(proc.create_time()).strftime("%Y-%m-%d %H:%M:%S")

                    print(f"\n🔍 Proceso en puerto {puerto}:")
                    print(f"Nombre: {nombre}")
                    print(f"Ruta: {ruta}")
                    print(f"Inicio: {tiempo}")

                    validacion = self.validar_servicio(pid, puerto)
                    print(f"🔎 Validación: {validacion}")

                    if conn.raddr and hasattr(conn.raddr, 'ip'):
                        ip_remota = conn.raddr.ip
                        print(f"IP remota: {ip_remota}")
                        reputacion = self.reputacion_ip_profunda(ip_remota)
                        print(f"Reputación: {reputacion}")
                        print(f"{'⚠️ Sospechosa' if self.es_ip_sospechosa(ip_remota) else '✅ IP válida'}")

                        self.respuesta_ante_incidente(ip_remota, puerto, pid)

                    confirmar = input("\n¿Deseas marcar este puerto como válido y seguro? (s/n): ").strip().lower()
                    if confirmar == "s":
                        guardar_puerto_validado(puerto)
                        self.puertos_validados.append(puerto)
                        self.log(f"✅ Puerto {puerto} marcado como válido por el analista.")
                        print(f"✅ Puerto {puerto} ahora será tratado como seguro.")

                except psutil.NoSuchProcess:
                    print("❌ Proceso no encontrado.")
                except Exception as e:
                    print(f"❌ Error al analizar el puerto: {e}")

        if not encontrados:
            print(" No se encontró ningún proceso usando ese puerto.")

    def modo_silencioso(self):
        print("\n🕶️ Ejecutando escaneo en modo silencioso...")
        conexiones = psutil.net_connections(kind='inet')
        for conn in conexiones:
            if conn.status == 'LISTEN':
                puerto = conn.laddr.port
                pid = conn.pid
                validacion = self.validar_servicio(pid, puerto)
                self.log(f"[Silencioso] Puerto {puerto} | PID: {pid} | {validacion}")
                if "⚠️" in validacion or "❌" in validacion:
                    print(f"⚠️ Posible anomalía en puerto {puerto}: {validacion}")

    def respuesta_ante_incidente(self, ip, puerto, pid):
        reputacion = self.reputacion_ip_profunda(ip)
        if "hosting" in reputacion.lower() or "vpn" in reputacion.lower() or self.es_ip_sospechosa(ip):
            print(f"\nIP sospechosa detectada: {ip}")
            print(f"Reputación: {reputacion}")
            confirmar = input("¿Deseas bloquear esta IP? (s/n): ").strip().lower()
            if confirmar == "s":
                self.bloquear_ip(ip)
                self.log(f"IP bloqueada por respuesta ante incidente: {ip}")
    def ver_conexiones(self):
        # Muestra todas las conexiones activas con IP remota, PID y proceso
        print("\n🔍 Conexiones activas:")
        self.log("🔍 Conexiones activas:")
        conexiones = psutil.net_connections(kind='inet')
        for conn in conexiones:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
            pid = conn.pid
            estado = conn.status
            try:
                proceso = psutil.Process(pid).name() if pid else "N/A"
            except psutil.NoSuchProcess:
                proceso = "Desconocido"
            sospechosa = self.es_ip_sospechosa(conn.raddr.ip) if conn.raddr else False
            validacion = self.validar_servicio(pid, conn.laddr.port) if pid else "N/A"
            mensaje = f"[{estado}] {laddr} → {raddr} | PID: {pid} ({proceso}) {'⚠️ Sospechosa' if sospechosa else ''} | {validacion}"
            print(mensaje)
            self.log(mensaje)

    def ver_servicios_escucha(self):
        # Muestra todos los puertos en estado LISTEN y el proceso que los usa
        print("\nServicios en escucha:")
        self.log("Servicios en escucha:")
        conexiones = psutil.net_connections(kind='inet')
        for conn in conexiones:
            if conn.status == 'LISTEN':
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                pid = conn.pid
                try:
                    proceso = psutil.Process(pid).name() if pid else "N/A"
                except psutil.NoSuchProcess:
                    proceso = "Desconocido"
                validacion = self.validar_servicio(pid, conn.laddr.port) if pid else "N/A"
                mensaje = f"[LISTEN] {laddr} | PID: {pid} ({proceso}) | {validacion}"
                print(mensaje)
                self.log(mensaje)

    def ver_puertos_abiertos(self):
        # Muestra puertos abiertos y el proceso que los usa
        print("\nPuertos abiertos:")
        self.log("Puertos abiertos:")
        conexiones = psutil.net_connections(kind='inet')
        for conn in conexiones:
            if conn.status == 'LISTEN':
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                pid = conn.pid
                try:
                    proceso = psutil.Process(pid).name() if pid else "N/A"
                except psutil.NoSuchProcess:
                    proceso = "Desconocido"
                validacion = self.validar_servicio(pid, conn.laddr.port) if pid else "N/A"
                mensaje = f"{laddr} | PID: {pid} ({proceso}) | {validacion}"
                print(mensaje)
                self.log(mensaje)

    def mostrar_recursos(self):
        # Muestra uso actual de RAM, CPU y disco
        print("\nRecursos del sistema:")
        self.log("Recursos del sistema:")
        ram = psutil.virtual_memory().percent
        cpu = psutil.cpu_percent(interval=1)
        disco = psutil.disk_usage('/').percent
        print(f"RAM usada: {ram}%")
        print(f"CPU usada: {cpu}%")
        print(f"Disco usado: {disco}%")
        self.log(f"RAM: {ram}%, CPU: {cpu}%, Disco: {disco}%")

    def bloquear_ip(self, ip):
        # Bloquea una IP usando el firewall de Windows
        if self.sistema.lower() == "windows":
            comando = f'netsh advfirewall firewall add rule name="Bloqueo_{ip}" dir=in action=block remoteip={ip}'
            try:
                subprocess.run(comando, shell=True)
                print(f"IP {ip} bloqueada exitosamente.")
                self.log(f"IP bloqueada: {ip}")
            except Exception as e:
                print(f"Error al bloquear IP: {e}")
        else:
            print("Bloqueo automático solo disponible en Windows.")
            
def menu():
    shield = PUDShield()

    while True:
        print("\nMenú Escaneo PUD-Shield")
        print("1. Ver conexiones activas")
        print("2. Ver servicios en escucha")
        print("3. Bloquear IP sospechosa")
        print("4. Ver puertos abiertos")
        print("5. Mostrar recursos del sistema")
        print("6. Analizar puerto sospechoso")
        print("7. Ejecutar modo silencioso")
        print("8. Salir")

        opcion = input("Selecciona una opción: ").strip()

        if opcion == "1":
            shield.ver_conexiones()
        elif opcion == "2":
            shield.ver_servicios_escucha()
        elif opcion == "3":
            print("\nBloqueo de IP")
            print("Escribe la IP a bloquear o escribe 'salir' para volver al menú.")
            ip = input("IP: ").strip()
            if ip.lower() == "salir" or ip == "":
                print("Volviendo al menú principal...")
            else:
                shield.bloquear_ip(ip)
        elif opcion == "4":
            shield.ver_puertos_abiertos()
        elif opcion == "5":
            shield.mostrar_recursos()
        elif opcion == "6":
            shield.analizar_puerto_sospechoso()
        elif opcion == "7":
            shield.modo_silencioso()
        elif opcion == "8":
            print("Saliendo...")
            break
        else:
            print("Opción inválida.")

# Ejecuta el menú si el script se corre directamente
if __name__ == "__main__":
    menu()
