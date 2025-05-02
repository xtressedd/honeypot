#!/bin/bash

IP="$1"
REASON="$2"
LOG_FILE="/logs/blocked_ips.log"
MAILTO="scriptpruebas017@gmail.com"

if [[ -z "$IP" || -z "$REASON" ]]; then
    echo "Uso: $0 <IP> <REASON>"
    exit 1
fi

# Detectar si la IP es IPv6 (contiene ':')
if [[ "$IP" == *:* ]]; then
    # IPv6 -> usar ip6tables
    if ! ip6tables -C INPUT -s "$IP" -j DROP 2>/dev/null; then
        ip6tables -A INPUT -s "$IP" -j DROP
        echo "[+] IP IPv6 bloqueada: $IP - Motivo: $REASON"
        echo "$IP | $REASON | $(date) | IPv6" >> "$LOG_FILE"
    else
        echo "[-] La IP IPv6 $IP ya estaba bloqueada"
    fi
else
    # IPv4
    if ! iptables -C INPUT -s "$IP" -j DROP 2>/dev/null; then
        iptables -A INPUT -s "$IP" -j DROP
        echo "[+] IP IPv4 bloqueada: $IP - Motivo: $REASON"
        echo "$IP | $REASON | $(date) | IPv4" >> "$LOG_FILE"
    else
        echo "[-] La IP IPv4 $IP ya estaba bloqueada"
    fi
fi

# Enviar correo si msmtp está disponible
if command -v msmtp > /dev/null; then
    echo -e "Asunto: IP Bloqueada: $IP\n\nSe ha bloqueado la IP $IP por el siguiente motivo:\n$REASON\nFecha: $(date)" \
        | msmtp "$MAILTO"
fi
