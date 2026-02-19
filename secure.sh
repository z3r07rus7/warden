#!/bin/bash
# Automatically find the active Wi-Fi connection name
WIFI=$(nmcli -t -f NAME,TYPE con show --active | grep 802-11-wireless | head -n1 | cut -d: -f1)
TUN=$(ip addr | grep -o 'tun[0-9]*' | head -n1)

case "$1" in
  lock)
    echo "[*] TARGETING NETWORK: $WIFI"
    if [ -z "$WIFI" ]; then
        echo "[!] No active Wi-Fi found!"
    else
        sudo nmcli connection modify "$WIFI" ipv4.ignore-auto-dns yes
        sudo nmcli connection modify "$WIFI" ipv4.dns "1.1.1.1 9.9.9.9"
        sudo resolvectl dns wlan0 1.1.1.1 9.9.9.9
    fi
    
    if [ -n "$TUN" ]; then
        sudo resolvectl dns "$TUN" 1.1.1.1 9.9.9.9
        sudo resolvectl domain "$TUN" "~."
        sudo resolvectl default-route "$TUN" yes
        echo "[+] Security applied to $WIFI and $TUN."
    else
        echo "[!] VPN offline. Wi-Fi locked to Cloudflare."
    fi
    sudo resolvectl flush-caches
    ;;
  portal)
    sudo nmcli connection modify "$WIFI" ipv4.ignore-auto-dns no
    sudo resolvectl default-route wlan0 yes
    echo "[+] Portal Mode Active for $WIFI."
    ;;
esac
