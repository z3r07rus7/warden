import subprocess
import os
import time
import signal
import sys
import threading
import ipaddress
from datetime import datetime

# --- CONFIGURATION ---
EXCLUDE = ["NetworkManager"]
SUBNET_MASK = "/24"  # Banning the entire /24 range
REFRESH_RATE = 4     # 4 seconds to allow time for typing commands

connection_registry = {}
closed_history = []
banned_subnets = set()
ip_map = {}  # Maps ID -> IP
next_ip_id = 1
status_message = "Ready"

def signal_handler(sig, frame):
    print("\n\033[1;33m[!] Monitor shutting down...\033[0m")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def get_subnet_string(ip):
    """Calculates the subnet string from a host IP."""
    try:
        net = ipaddress.ip_network(f"{ip}{SUBNET_MASK}", strict=False)
        return str(net)
    except ValueError:
        return ip

def apply_firewall(action, target_ip):
    """Applies iptables rules to the calculated subnet of the target IP."""
    subnet = get_subnet_string(target_ip)
    try:
        subprocess.run(["sudo", "iptables", action, "INPUT", "-s", subnet, "-j", "DROP"], check=True, capture_output=True)
        subprocess.run(["sudo", "iptables", action, "OUTPUT", "-d", subnet, "-j", "DROP"], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False

def flush_all_rules():
    """Wipes all iptables rules and clears local registry."""
    try:
        subprocess.run(["sudo", "iptables", "-F", "INPUT"], check=True)
        subprocess.run(["sudo", "iptables", "-F", "OUTPUT"], check=True)
        banned_subnets.clear()
        return True
    except Exception:
        return False

def command_listener():
    global status_message
    while True:
        cmd = input().strip().lower()
        if not cmd: continue
        
        try:
            if cmd == "f":
                if flush_all_rules():
                    status_message = "ALL RULES FLUSHED"
                else:
                    status_message = "FAILED TO FLUSH RULES"
                continue

            parts = cmd.split()
            if len(parts) < 2: raise ValueError
            
            action = parts[0]
            target_id = int(parts[1])
            target_ip = ip_map.get(target_id)

            if not target_ip:
                status_message = f"ERROR: ID {target_id} not found"
                continue

            target_subnet = get_subnet_string(target_ip)

            if action == "b":
                if apply_firewall("-A", target_ip):
                    banned_subnets.add(target_subnet)
                    status_message = f"BANNED RANGE: {target_subnet} (ID: {target_id})"
                    subprocess.run(["sudo", "ss", "-K", "dst", target_subnet], capture_output=True)
                else:
                    status_message = f"FAILED TO BAN: {target_subnet}"
            
            elif action == "r":
                if target_subnet in banned_subnets:
                    if apply_firewall("-D", target_ip):
                        banned_subnets.remove(target_subnet)
                        status_message = f"RESTORED: {target_subnet}"
                    else:
                        status_message = f"FAILED TO RESTORE: {target_subnet}"
                else:
                    status_message = f"ERROR: Subnet {target_subnet} not in ban list"
        except Exception:
            status_message = "USAGE: b [ID] | r [ID] | f (Flush)"

threading.Thread(target=command_listener, daemon=True).start()

def run_monitor():
    global next_ip_id, status_message
    while True:
        try:
            raw = subprocess.check_output(["sudo", "ss", "-ntupi", "state", "established"], timeout=1).decode().splitlines()
            current_batch = {}
            
            for line in raw:
                if any(x in line for x in ["tcp", "udp"]) and "127.0.0.1" not in line:
                    parts = line.split()
                    raw_ip_port = parts[4]
                    ip = raw_ip_port.rsplit(':', 1)[0].strip('[]')
                    
                    found_id = next((k for k, v in ip_map.items() if v == ip), None)
                    if not found_id:
                        found_id = next_ip_id
                        ip_map[found_id] = ip
                        next_ip_id += 1

                    prog = line.split('"')[1] if '"' in line else "unknown"
                    if prog in EXCLUDE: continue

                    current_batch[raw_ip_port] = {"prog": prog, "ip_only": ip, "id": found_id}
                    
                    if raw_ip_port not in connection_registry:
                        connection_registry[raw_ip_port] = {
                            "start": time.time(), 
                            "meta": {"prog": prog, "ip_only": ip, "id": found_id}
                        }

            for ip_port in list(connection_registry.keys()):
                if ip_port not in current_batch:
                    data = connection_registry[ip_port]
                    ts = datetime.now().strftime("%H:%M:%S")
                    closed_history.append(f"\033[31m{ts:<10} [{data['meta']['id']}] {ip_port:<25} {data['meta']['prog']:<15} CLOSED\033[0m")
                    del connection_registry[ip_port]

            # --- UI RENDERING ---
            os.system('clear')
            print("\033[1;37;44m" + " WARDEN SUBNET MONITOR ".center(80) + "\033[0m")
            print("\033[1;34m> BAN SUBNET: b [ID]  RESTORE: r [ID]  FLUSH ALL: f  EXIT: Ctrl+C\033[0m")
            print("-" * 80)
            
            print(f"\033[1;33m--- STATUS: {status_message} | TIME: {datetime.now().strftime('%H:%M:%S')} ---\033[0m")
            print(f"{'ID':<4} {'UPTIME':<8} {'REMOTE ADDR':<25} {'PROG':<15} {'STATUS'}")
            print("-" * 80)
            
            for ip_port, data in sorted(connection_registry.items(), key=lambda x: x[1]['meta']['id']):
                uptime = f"{int(time.time() - data['start']) // 60:02d}:{int(time.time() - data['start']) % 60:02d}"
                print(f"[{data['meta']['id']}]".ljust(4), f"{uptime:<8} {ip_port:<25} {data['meta']['prog']:<15} \033[92mACTIVE\033[0m")
            
            print(f"\n\033[1;31m--- BANNED RANGES (/24) ---\033[0m")
            if banned_subnets:
                for subnet in banned_subnets: print(f"\033[1;31mBLOCKING: {subnet}\033[0m")
            else:
                print("\033[1;30m(No active range bans)\033[0m")

            print("\n\033[1;30m" + "-" * 20 + " CLOSED HISTORY " + "-" * 44 + "\033[0m")
            for entry in closed_history[-6:]: print(entry)
            
            print("\nCOMMAND: ", end="", flush=True)
            
        except Exception:
            pass
        
        time.sleep(REFRESH_RATE)

if __name__ == "__main__":
    run_monitor()

