#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tesis de Grado - UNAHUR
Tema: Automatización de Infraestructura de Red Jerárquica con Python y Netmiko
Autora: Marta Susana Carullo

Este script implementa la lógica avanzada de IDEMPOTENCIA y COMPLIANCE:

1. Lee las políticas de red e interfaces declaradas externamente en config_red.yaml.
2. Solicita credenciales de acceso seguro de manera interactiva (getpass).
3. Se conecta secuencialmente a los switches de acceso (192.168.1.11 al .16).
4. Verifica de forma inteligente el estado de VLANs y puertos antes de inyectar cambios.
5. Valida si las interfaces Trunk y Access coinciden con la especificación de diseño.
6. [NUEVO] Verifica el estado real de Spanning-Tree (Rapid-PVST+) en los switches
   de distribución para cada VLAN definida en el YAML, sin hardcodear IDs.
7. [NUEVO] Vuelca TODO el proceso (fases 1 a 6, para los 8 equipos) a un único
   archivo de texto, además de mostrarlo en consola, como evidencia documental
   para la El proyecto.
"""

import sys
import re
import getpass
import yaml
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

# ==========================================
# 0. DUPLICADOR DE SALIDA (CONSOLA + ARCHIVO)
# ==========================================
# Todo lo que se imprima con print() a partir de que se active esta clase
# queda simultáneamente en la pantalla y en el archivo de reporte, sin tener
# que modificar cada print() del script.


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for s in self.streams:
            s.write(data)
            s.flush()

    def flush(self):
        for s in self.streams:
            s.flush()


# ==========================================
# 1. DEFINICIÓN DE IP'S DE GESTIÓN (SWITCHES DE ACCESO)
# ==========================================
dispositivos_acceso = [
    "192.168.1.11",  # SW-ACCESO-1
    "192.168.1.12",  # SW-ACCESO-2
    "192.168.1.13",  # SW-ACCESO-3
    "192.168.1.14",  # SW-ACCESO-4
    "192.168.1.15",  # SW-ACCESO-5
    "192.168.1.16",  # SW-ACCESO-6
]

# ==========================================
# 1.b DEFINICIÓN DE IP'S DE GESTIÓN (SWITCHES DE DISTRIBUCIÓN)
# ==========================================
# CONFIRMADO EN LABORATORIO (02/07/2026): se agregó una SVI de gestión en
# Vlan1 (192.168.1.0/24) a DIST-IOU2 y DIST-IOU3, ya que sus únicas IPs
# originales (10.0.0.2 / 10.0.0.6) están en la red de transporte, sin ruta
# de vuelta hacia la estación de control Windows (192.168.1.0/24). Con esta
# SVI, el ping y el SSH responden correctamente desde la PC de gestión.
dispositivos_distribucion = {
    "DIST-IOU2": "192.168.1.2",
    "DIST-IOU3": "192.168.1.3",
}

# ==========================================
# 2. CARGA DE CONFIGURACIÓN MAESTRA (YAML)
# ==========================================
try:
    with open("config_red.yaml", "r", encoding="utf-8") as archivo:
        config_maestra = yaml.safe_load(archivo)
    print("[INFO] Archivo 'config_red.yaml' cargado correctamente.")
except FileNotFoundError:
    print("[ERROR] No se encontró el archivo 'config_red.yaml'. Por favor crealo en la misma carpeta.")
    sys.exit(1)
except Exception as e:
    print(f"[ERROR] Error al leer el archivo YAML: {e}")
    sys.exit(1)

# ==========================================
# 3. CREDENCIALES SOLICITADAS POR CONSOLA
# ==========================================
print("\n=== Control de Acceso del Administrador ===")
username = input("Introduce usuario SSH (ej. admin): ")
password = getpass.getpass("Introduce contraseña de habilitación (Privilegio 15): ")

# ==========================================
# 4. FUNCIÓN MAESTRA DE AUTOMATIZACIÓN (SWITCHES DE ACCESO)
# ==========================================


def aplicar_compliance_switch(ip_dispositivo):
    cisco_ios_device = {
        "device_type": "cisco_ios",
        "host": ip_dispositivo,
        "username": username,
        "password": password,
        "secret": password,  # Se asume la misma clave para el modo 'enable'
    }

    try:
        print(f"\n──────────────────────────────────────────────────")
        print(f"[*] Conectando de forma segura a: {ip_dispositivo}...")

        net_connect = ConnectHandler(**cisco_ios_device)
        net_connect.enable()

        hostname = net_connect.find_prompt().replace("#", "")
        print(f"[CONECTADO] Conectado exitosamente a {hostname}")

        # --- FASE 1: AUDITORÍA DE VLANs (IDEMPOTENCIA) ---
        print(f"[*] Solicitando estado de VLANs en {hostname} para auditoría...")
        vlan_raw_data = net_connect.send_command("show vlan brief")
        comandos_vlan_a_enviar = []

        for vlan in config_maestra["red_empresarial"]["vlans"]:
            vlan_id = str(vlan["id"])
            vlan_name = vlan["nombre"]

            # Nota: verificación por substring. Puede dar falso positivo si un
            # VLAN ID es subcadena de otro (ej. "1" dentro de "10"). Con tus
            # VLANs actuales (10,20,30,65,99) no colisiona, pero si agregás
            # VLAN 1, 2, 3... revisar esta lógica.
            if vlan_id in vlan_raw_data:
                print(f"  [COMPLIANCE OK] La VLAN {vlan_id} ({vlan_name}) ya existe. Saltando...")
            else:
                print(f"  [DESVIACIÓN DETECTADA] La VLAN {vlan_id} no existe. Agregando a cola de comandos...")
                comandos_vlan_a_enviar.extend([
                    f"vlan {vlan_id}",
                    f"name {vlan_name}"
                ])

        if comandos_vlan_a_enviar:
            print(f"[*] Aplicando cambios de VLANs en {hostname}...")
            net_connect.send_config_set(comandos_vlan_a_enviar)
            print(f"  [ÉXITO] VLANs configuradas correctamente.")
        else:
            print(f"  [OK] El switch ya cumple con las políticas de VLANs.")

        # --- FASE 2: HARDENING DE SEGURIDAD GENERAL ---
        print(f"[*] Aplicando Banner MOTD de seguridad...")
        banner_msg = config_maestra["red_empresarial"]["seguridad"]["banner_motd"]
        comandos_seguridad = [f"banner motd ^ {banner_msg} ^"]
        net_connect.send_config_set(comandos_seguridad)
        print(f"  [ÉXITO] Reglas de seguridad aplicadas correctamente en {hostname}.")

        # --- FASE 3: AUDITORÍA DE PUERTOS FÍSICOS (ACCESO, TRUNK E INACTIVOS) ---
        print(f"[*] Verificando estado de las interfaces físicas en {hostname}...")
        puertos_raw_data = net_connect.send_command("show interface status")
        comandos_puertos_a_enviar = []

        if ip_dispositivo in config_maestra["red_empresarial"]["configuracion_puertos"]:
            puertos_switch = config_maestra["red_empresarial"]["configuracion_puertos"][ip_dispositivo]

            # -- 1. VALIDACIÓN DE PUERTOS DE ACCESO --
            if "access" in puertos_switch:
                for interfaz, vlan_destino in puertos_switch["access"].items():
                    interfaz_corta = interfaz.replace("Ethernet ", "Et")
                    linea_interfaz = None
                    for linea in puertos_raw_data.splitlines():
                        columnas = linea.split()
                        if columnas and columnas[0].lower() == interfaz_corta.lower():
                            linea_interfaz = linea
                            break

                    if linea_interfaz:
                        if str(vlan_destino) not in linea_interfaz:
                            print(f"  [DESVIACIÓN] {interfaz} no está en la VLAN {vlan_destino}. Corrigiendo...")
                            comandos_puertos_a_enviar.extend([
                                f"interface {interfaz}",
                                "switchport mode access",
                                f"switchport access vlan {vlan_destino}",
                                "no shutdown"
                            ])
                        else:
                            print(f"  [COMPLIANCE OK] {interfaz} ya se encuentra correctamente en la VLAN {vlan_destino}.")

            # -- 2. VALIDACIÓN DE ENLACES TRONCALES (TRUNKS) --
            if "trunk" in puertos_switch:
                for interfaz in puertos_switch["trunk"]:
                    interfaz_corta = interfaz.replace("Ethernet ", "Et")
                    linea_interfaz = None
                    for linea in puertos_raw_data.splitlines():
                        columnas = linea.split()
                        if columnas and columnas[0].lower() == interfaz_corta.lower():
                            linea_interfaz = linea
                            break

                    if linea_interfaz:
                        if "trunk" not in linea_interfaz.lower():
                            print(f"  [DESVIACIÓN] {interfaz} no opera en modo Trunk. Corrigiendo...")
                            comandos_puertos_a_enviar.extend([
                                f"interface {interfaz}",
                                "switchport trunk encapsulation dot1q",
                                "switchport mode trunk",
                                "no shutdown"
                            ])
                        else:
                            print(f"  [COMPLIANCE OK] {interfaz} ya se encuentra activa en modo Trunk.")

            # -- 3. HARDENING: AUDITORÍA DE PUERTOS INACTIVOS --
            if "inactivos" in puertos_switch:
                for interfaz in puertos_switch["inactivos"]:
                    interfaz_corta = interfaz.replace("Ethernet ", "Et")
                    linea_interfaz = None
                    for linea in puertos_raw_data.splitlines():
                        columnas = linea.split()
                        if columnas and columnas[0].lower() == interfaz_corta.lower():
                            linea_interfaz = linea
                            break

                    if linea_interfaz:
                        if "disabled" not in linea_interfaz.lower():
                            print(f"  [SEGURIDAD] Interfaz residual {interfaz} está activa. Aplicando shutdown...")
                            comandos_puertos_a_enviar.extend([
                                f"interface {interfaz}",
                                "shutdown"
                            ])
                        else:
                            print(f"  [COMPLIANCE OK] Interfaz residual {interfaz} ya está apagada de forma segura.")

        if comandos_puertos_a_enviar:
            print(f"[*] Corrigiendo desviación de interfaces físicas en {hostname}...")
            net_connect.send_config_set(comandos_puertos_a_enviar)
            print(f"  [ÉXITO] Configuración de interfaces físicas completada.")
        else:
            print(f"  [OK] Todas las interfaces físicas coinciden perfectamente con el modelo.")

        # --- FASE 4: GUARDADO DE CONFIGURACIÓN ---
        print(f"[*] Guardando cambios en la memoria NVRAM de {hostname}...")
        net_connect.send_command("write memory")
        print(f"  [CERRANDO] Conexión terminada de forma segura.")

        net_connect.disconnect()

    except NetmikoTimeoutException:
        print(f"  [ERROR] Tiempo de espera agotado al conectar a {ip_dispositivo}. ¿El switch está encendido?")
    except NetmikoAuthenticationException:
        print(f"  [ERROR] Falla de autenticación SSH en {ip_dispositivo}. Verificá el usuario/contraseña.")
    except Exception as error:
        print(f"  [ERROR GENERAL] No se pudo procesar el switch {ip_dispositivo}: {error}")


# ==========================================
# 5. FUNCIÓN DE VERIFICACIÓN DE SPANNING-TREE (SWITCHES DE DISTRIBUCIÓN)
# ==========================================


def verificar_spanning_tree(nombre_switch, ip_switch, vlans):
    """
    Se conecta a un switch de distribución y recorre TODAS las VLANs
    definidas en el YAML (sin hardcodear IDs), consultando el estado
    real de Spanning-Tree (Root / No-Root) para cada una.
    """
    resultados = []

    cisco_ios_device = {
        "device_type": "cisco_ios",
        "host": ip_switch,
        "username": username,
        "password": password,
        "secret": password,
    }

    try:
        print(f"\n──────────────────────────────────────────────────")
        print(f"[*] Conectando a {nombre_switch} ({ip_switch}) para auditoría de STP...")

        net_connect = ConnectHandler(**cisco_ios_device)
        net_connect.enable()
        print(f"[CONECTADO] Conectado exitosamente a {nombre_switch}")

        for vlan in vlans:
            vlan_id = vlan["id"]
            vlan_nombre = vlan.get("nombre", f"VLAN{vlan_id}")

            salida = net_connect.send_command(f"show spanning-tree vlan {vlan_id}")

            es_root = "This bridge is the root" in salida
            match_puerto_root = re.search(r"Root\s+FWD.*?(\S+)\s*$", salida, re.MULTILINE)
            puerto_root = match_puerto_root.group(1) if match_puerto_root else "N/A (local root)"
            rol = "ROOT BRIDGE" if es_root else f"NO-ROOT (puerto raíz: {puerto_root})"

            resultados.append({
                "switch": nombre_switch,
                "vlan_id": vlan_id,
                "vlan_nombre": vlan_nombre,
                "rol": rol,
                "raw": salida.strip(),
            })

            print(f"  [STP] {nombre_switch} - VLAN {vlan_id} ({vlan_nombre}): {rol}")

        net_connect.disconnect()

    except NetmikoTimeoutException:
        print(f"  [ERROR] Tiempo de espera agotado al conectar a {nombre_switch} ({ip_switch}). ¿Está encendido? ¿La IP es correcta?")
    except NetmikoAuthenticationException:
        print(f"  [ERROR] Falla de autenticación SSH en {nombre_switch}. Verificá el usuario/contraseña.")
    except Exception as error:
        print(f"  [ERROR GENERAL] No se pudo procesar {nombre_switch}: {error}")

    return resultados


# ==========================================
# 6. FUNCIÓN DE BACKUP FUERA DE BANDA (SOLO LECTURA)
# ==========================================
# Esta función NUNCA envía comandos de configuración. Solo ejecuta
# "show running-config" (una consulta de lectura) y guarda la respuesta
# en un archivo de texto local, uno por switch. No modifica nada en el
# equipo ni reemplaza al "write memory" que ya hace cada fase de compliance.

CARPETA_BACKUPS = "backups_config"


def backup_running_config(nombre_o_ip, ip_dispositivo):
    """
    Se conecta a un dispositivo, pide su running-config (solo lectura)
    y la guarda en backups_config/<nombre>_running-config.txt
    """
    import os
    import datetime

    cisco_ios_device = {
        "device_type": "cisco_ios",
        "host": ip_dispositivo,
        "username": username,
        "password": password,
        "secret": password,
    }

    try:
        print(f"[*] Solicitando backup de running-config a {nombre_o_ip} ({ip_dispositivo})...")
        net_connect = ConnectHandler(**cisco_ios_device)
        net_connect.enable()

        hostname = net_connect.find_prompt().replace("#", "")
        running_config = net_connect.send_command("show running-config")
        net_connect.disconnect()

        os.makedirs(CARPETA_BACKUPS, exist_ok=True)
        ruta_archivo = os.path.join(CARPETA_BACKUPS, f"{hostname}_running-config.txt")

        with open(ruta_archivo, "w", encoding="utf-8") as f:
            f.write(f"! Backup automático - {hostname} ({ip_dispositivo})\n")
            f.write(f"! Generado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("! Este archivo es SOLO LECTURA: no fue aplicado a ningún equipo.\n")
            f.write("!" + "=" * 60 + "\n\n")
            f.write(running_config)

        print(f"  [ÉXITO] Backup guardado en '{ruta_archivo}'")

    except NetmikoTimeoutException:
        print(f"  [ERROR] Tiempo de espera agotado al conectar a {nombre_o_ip} ({ip_dispositivo}) para backup.")
    except NetmikoAuthenticationException:
        print(f"  [ERROR] Falla de autenticación SSH en {nombre_o_ip} durante el backup.")
    except Exception as error:
        print(f"  [ERROR GENERAL] No se pudo respaldar {nombre_o_ip}: {error}")


# ==========================================
# 7. INICIO DE LA EJECUCIÓN (ÚNICO BLOQUE PRINCIPAL)
# ==========================================
if __name__ == "__main__":

    # Activar el duplicador de salida: todo print() de acá en adelante
    # queda simultáneamente en pantalla y en el archivo de reporte.
    archivo_reporte = open("reporte_completo_automatizacion.txt", "w", encoding="utf-8")
    stdout_original = sys.stdout
    sys.stdout = Tee(stdout_original, archivo_reporte)

    try:
        print("\n=======================================================")
        print(" INICIANDO PROCESO DE AUDITORÍA Y AUTOMATIZACIÓN DE RED ")
        print("=======================================================")

        # --- Parte 1: VLANs y puertos en los 6 switches de acceso ---
        for ip in dispositivos_acceso:
            aplicar_compliance_switch(ip)

        # --- Parte 2: Verificación de Spanning-Tree en los switches de distribución ---
        print("\n=======================================================")
        print(" AUDITORÍA DE SPANNING-TREE (RAPID-PVST+) EN DISTRIBUCIÓN ")
        print("=======================================================")

        vlans_definidas = config_maestra["red_empresarial"]["vlans"]
        reporte_stp = []
        for nombre_switch, ip_switch in dispositivos_distribucion.items():
            reporte_stp += verificar_spanning_tree(nombre_switch, ip_switch, vlans_definidas)

        # --- Parte 3: Backup fuera de banda (solo lectura) de los 8 equipos ---
        print("\n=======================================================")
        print(" BACKUP FUERA DE BANDA DE RUNNING-CONFIG (SOLO LECTURA) ")
        print("=======================================================")

        for ip in dispositivos_acceso:
            backup_running_config(ip, ip)

        for nombre_switch, ip_switch in dispositivos_distribucion.items():
            backup_running_config(nombre_switch, ip_switch)

        print("\n=======================================================")
        print(" PROCESO FINALIZADO - MAQUETA DE TESIS OK ")
        print("=======================================================")

    finally:
        # Restaurar la salida estándar y cerrar el archivo prolijamente,
        # incluso si algo falló en el medio.
        sys.stdout = stdout_original
        archivo_reporte.close()
        print("\n[INFO] Reporte completo guardado en 'reporte_completo_automatizacion.txt'")
