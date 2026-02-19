#!/usr/bin/env python3
import subprocess
import requests
import re
import time
import threading
import uuid
import signal
import sys
import os
import json
from datetime import datetime, timedelta

# ---------------------------
# CONFIG & COLORS
# ---------------------------
LOCAL_IP_RANGES = ('127.', '169.254.', '0.0.0.0', '::1')
IGNORE_PROGS = ('networkmanager', 'dhclient') 
API_URL = 'http://ip-api.com/json/'
SLEEP = 0.3 

C = {
    'RED': "\033[91m", 'GREEN': "\033[92m", 'YELLOW': "\033[93m",
    'PURPLE': "\033[95m", 'CYAN': "\033[96m", 'RESET': "\033[0m"
}

# ---------------------------
# GLOBALS & CACHE
# ---------------------------
connection_counter = 0
ip_cache = {}        
hop_results = {}     
pending_redraws = set() 
active_connections = {} 
last_states = {}         
api_calls = [] 
log_file = None
stop_event = threading.Event()

# ---------------------------
# UTILITIES
# ---------------------------
def run_cmd(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
    except Exception:
        return "Command Failed"

def write_log(text):
    if log_file:
        clean = re.sub(r'\033\[[0-9;]*m', '', text)
        with open(log_file, 'a') as f:
            f.write(clean + "\n")

# ---------------------------
# ASYNC GEO & HOPS
# ---------------------------
def query_ip_api(ip):
    if ip in ip_cache and ip_cache[ip].get('status') == 'success':
        return ip_cache[ip]
    
    now = datetime.now()
    global api_calls
    api_calls = [t for t in api_calls if t > now - timedelta(seconds=60)]
    if len(api_calls) >= 44:
        return {'status': 'throttled', 'city': 'RateLimited', 'country': '??', 'lat': 0, 'lon': 0}

    try:
        api_calls.append(now)
        r = requests.get(API_URL + ip, timeout=2)
        data = r.json()
        if data.get('status') == 'success':
            ip_cache[ip] = data
            return data
    except: pass
    return ip_cache.get(ip, {'status': 'fail', 'city': '??', 'country': '??', 'lat': 0, 'lon': 0})

def resolve_hops_background(target_ip, cid):
    try:
        raw = run_cmd(['mtr', '--report', '--report-cycles', '1', '--json', target_ip])
        data = json.loads(raw)
        resolved = []
        for h in data.get('report', {}).get('hubs', []):
            hip = h.get('host')
            if not hip or hip in ('???', '*'): continue
            
            g = query_ip_api(hip)
            city = g.get('city', '??')
            country = g.get('country', '??')
            lat, lon = g.get('lat', 0), g.get('lon', 0)
            resolved.append(f"{hip} | {city}, {country} [{lat}, {lon}]")
        
        hop_results[target_ip] = resolved if resolved else ["No Hops"]
        pending_redraws.add(cid) 
    except:
        hop_results[target_ip] = ["MTR Error"]

def trigger_hop_scan(ip, cid):
    hop_results[ip] = ["Scanning..."]
    threading.Thread(target=resolve_hops_background, args=(ip, cid), daemon=True).start()

# ---------------------------
# DISPLAY LOGIC
# ---------------------------
def display_block(cid, ip, port, pid, prog, open_ts, close_ts=None, closed=False):
    info = query_ip_api(ip)
    hops = hop_results.get(ip, ["Pending..."])
    p = C['RED'] if closed else C['GREEN']
    res = C['RESET']
    
    isp_asn = f"{info.get('isp', 'N/A')} ({info.get('as', 'ASN?')})"
    coords = f"{info.get('lat', 0)}, {info.get('lon', 0)}"
    status = f"{C['RED']}CLOSED {close_ts}" if closed else f"{C['GREEN']}ACTIVE {open_ts}"
    
    block = [
        f"\n{p}ID: {res}{cid} | {status}",
        f"{p}Prog: {res}{prog} | PID: {pid}",
        f"{p}IP: {res}{C['PURPLE']}{ip}{res} | Port: {C['YELLOW']}{port}{res}",
        f"{p}Country: {res}{C['CYAN']}{info.get('country', 'N/A')}{res}",
        f"{p}ISP/ASN: {res}{C['CYAN']}{isp_asn}{res}",
        f"{p}City/Loc: {res}{C['CYAN']}{info.get('city', 'N/A')} ({coords}){res}",
        f"{p}Hops:{res}"
    ]
    for h in hops:
        h_color = C['PURPLE'] if "Scanning" not in h and not closed else C['CYAN']
        block.append(f"  {h_color}↳ {h}{res}")
    block.append(f"{p}{'-' * 45}{res}")
    
    output = "\n".join(block)
    print(output)
    write_log(output)
    
    if not closed: 
        last_states[cid] = "-".join(hops)

# ---------------------------
# MAIN
# ---------------------------
def main():
    global connection_counter, log_file
    
    # 1. Initialize variables with defaults to prevent NameErrors
    bssid = "unknown"
    public_ip_geo = "Unknown"  # <--- CRITICAL FIX
    bssid_geo = "BSSID not in public database"

    if input("Generate log? (y/n): ").lower() == 'y':
        wifi_data = run_cmd(['nmcli', '-t', '-f', 'ACTIVE,SSID,BSSID', 'dev', 'wifi'])
        active_line = next((line for line in wifi_data.splitlines() if line.startswith('yes')), None)
        
        if active_line:
            parts = active_line.split(':')
            ssid = parts[1].strip().replace(' ', '_') if len(parts) > 1 else "unknown"
            raw_bssid = ":".join(parts[2:]) if len(parts) > 2 else "unknown"
            bssid = raw_bssid.replace('\\', '').strip()
            log_file = f"{datetime.now().strftime('%Y%m%d.%H%M%S')}.{ssid}.log"
        else:
            log_file = f"{datetime.now().strftime('%Y%m%d.%H%M%S')}.no_wifi.log"

    os.system('clear')
    
    # 2. Geolocation Logic
    if bssid != "unknown":
        try:
            geo_r = requests.get(f"https://api.mylnikov.org/geolocation/wifi?bssid={bssid}", timeout=3)
            if geo_r.status_code == 200:
                data = geo_r.json().get('data', {})
                if data:
                    bssid_geo = f"LAT: {data.get('lat')}, LON: {data.get('lon')}"
        except: pass

    try:
        # This will show VPN location if VPN is active
        ip_r = requests.get('http://ip-api.com/json/', timeout=3).json()
        public_ip_geo = f"{ip_r.get('city')}, {ip_r.get('country')} ({ip_r.get('lat')}, {ip_r.get('lon')})"
    except: 
        public_ip_geo = "Offline/API Error"

    # 3. Forensic Header
    report_uuid = uuid.uuid4()
    header_text = (
        f"{'='*65}\n"
        f"FORENSIC REPORT | UUID: {report_uuid}\n"
        f"TIMESTAMP: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"PHYSICAL AP (BSSID): {bssid}\n"
        f"BSSID LOCATION: {bssid_geo}\n"
        f"NETWORK LOCATION: {public_ip_geo}\n"
        f"{'='*65}"
    )
    print(header_text)
    write_log(header_text)

    os.system('clear')
    
    # NEW FORENSIC HEADER ORDER
    print(f"FORENSIC REPORT | UUID: {uuid.uuid4()} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 65)
    
    # 1. WIFI FIRST WITH BSSID
    print(f"{C['CYAN']}=== WIFI STATUS (nmcli) ==={C['RESET']}")
    print(run_cmd(['nmcli', '-f', 'IN-USE,BSSID,SSID,BARS,RATE,SECURITY', 'dev', 'wifi']))
    
    # 2. ARP SCAN FOR LAN NEIGHBORS
    print(f"\n{C['CYAN']}=== LAN NEIGHBORS (arp-scan -l) ==={C['RESET']}")
    # Note: Requires sudo/root privileges for arp-scan
    print(run_cmd(['sudo', 'arp-scan', '-l']))
    
    # 3. ROUTEL
    print(f"\n{C['CYAN']}=== ROUTING TABLE (routel) ==={C['RESET']}")
    print(run_cmd(['routel']))
    
    # 4. IP ADDRESSES
    print(f"\n{C['CYAN']}=== IP ADDRESSES (ip addr) ==={C['RESET']}")
    print(run_cmd(['ip', '-br', 'addr']))
    
    print("\n" + "="*65 + "\nLIVE FORENSIC FEED\n" + "="*65)

    active_ips = set()

    while not stop_event.is_set():
        out = run_cmd(['netstat', '-tunp'])
        pattern = re.compile(r'\s+(?P<rip>[\d\.]+):(?P<port>\d+)\s+ESTABLISHED\s+(?P<pidprog>\d+/\S+|-)')
        
        current_remotes = []
        for line in out.splitlines():
            m = pattern.search(line)
            if m:
                rip = m.group('rip')
                pidprog = m.group('pidprog').lower()
                if not any(rip.startswith(r) for r in LOCAL_IP_RANGES) and not any(ign in pidprog for ign in IGNORE_PROGS):
                    pid, prog = pidprog.split('/') if '/' in pidprog else ('?', 'Unknown')
                    current_remotes.append((rip, m.group('port'), pid, prog))

        current_ip_map = {r[0]: r for r in current_remotes}
        current_ips = set(current_ip_map.keys())
        closure_occurred = False

        for ip in list(active_ips - current_ips):
            cid = next((c for c, d in active_connections.items() if d[1] == ip), None)
            if cid:
                d = active_connections[cid]
                display_block(cid, d[1], d[2], d[3], d[4], d[5], close_ts=datetime.now().strftime('%H:%M:%S'), closed=True)
                del active_connections[cid]
                active_ips.remove(ip)
                closure_occurred = True

        for ip in current_ips:
            rip, port, pid, prog = current_ip_map[ip]
            if ip not in active_ips:
                connection_counter += 1
                cid = connection_counter
                o_ts = datetime.now().strftime('%H:%M:%S')
                active_connections[cid] = (None, rip, port, pid, prog, o_ts)
                active_ips.add(ip)
                trigger_hop_scan(rip, cid)
                display_block(cid, rip, port, pid, prog, o_ts)
            else:
                cid = next(c for c, d in active_connections.items() if d[1] == ip)
                if closure_occurred or cid in pending_redraws:
                    display_block(cid, rip, port, pid, prog, active_connections[cid][5])
                    if cid in pending_redraws: 
                        pending_redraws.remove(cid)

        time.sleep(SLEEP)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    main()
