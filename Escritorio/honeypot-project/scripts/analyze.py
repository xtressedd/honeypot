import json
import os
import time
import subprocess
import smtplib
from email.mime.text import MIMEText
import requests
from dotenv import load_dotenv

# Cargar las variables de entorno desde el archivo .env
load_dotenv()

# Variables de entorno
LOG_PATH = "/logs/eve.json"
BANNED_IPS = set()

# Configuración del correo
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_FROM = os.getenv("EMAIL_FROM")
EMAIL_TO = os.getenv("EMAIL_TO")
EMAIL_SUBJECT = "Alerta de intrusión en el honeypot"
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

# API de AbuseIPDB
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Espera a que el archivo de logs exista
while not os.path.exists(LOG_PATH):
    print("[*] Esperando que se genere el archivo de logs...")
    time.sleep(2)

print("[*] Analizando logs en tiempo real...")

def enviar_correo(ip, motivo):
    try:
        cuerpo = f"Se ha detectado una intrusión:\n\nIP: {ip}\nMotivo: {motivo}"
        msg = MIMEText(cuerpo)
        msg["Subject"] = EMAIL_SUBJECT
        msg["From"] = EMAIL_FROM
        msg["To"] = EMAIL_TO

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_FROM, [EMAIL_TO], msg.as_string())
        server.quit()

        print(f"[+] Correo enviado sobre la IP {ip}")
    except Exception as e:
        print(f"[!] Error al enviar el correo: {e}")

def consultar_abuseipdb(ip):
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90"
    }
    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
        if data.get("data") and data["data"].get("abuseConfidenceScore", 0) > 50:
            return True, data["data"]["abuseConfidenceScore"]
        else:
            return False, 0
    except requests.exceptions.RequestException as e:
        print(f"[!] Error al consultar AbuseIPDB: {e}")
        return False, 0

with open(LOG_PATH, "r") as f:
    f.seek(0, os.SEEK_END)  # Saltar al final del archivo

    while True:
        line = f.readline()
        if not line:
            time.sleep(1)
            continue

        try:
            data = json.loads(line)
            src_ip = data.get("src_ip", "")
            alert = data.get("alert", {})
            signature = alert.get("signature", "")

            if src_ip and signature and src_ip not in BANNED_IPS:
                print(f"[!] IP sospechosa detectada: {src_ip} - Motivo: {signature}")

                # Consultar AbuseIPDB
                es_maliciosa, abuso_score = consultar_abuseipdb(src_ip)
                if es_maliciosa:
                    motivo = f"IP reportada con abuso (Score: {abuso_score}) - Motivo: {signature}"
                else:
                    motivo = f"Alerta de Suricata - Motivo: {signature}"

                # Bloquear la IP
                subprocess.run(["iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"])
                print(f"[+] IP bloqueada: {src_ip}")

                # Enviar correo
                enviar_correo(src_ip, motivo)

                # Añadir la IP a la lista de bloqueadas
                BANNED_IPS.add(src_ip)

        except json.JSONDecodeError:
            continue
