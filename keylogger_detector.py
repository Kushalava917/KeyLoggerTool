import psutil
import win32api
import win32con
import win32gui
import win32process
import os
import socket

def is_system_process(process_name, process_path):
    """Check if the process is a known system process running from a valid location."""
    system_processes = {
        "winlogon.exe": "C:\\Windows\\System32\\winlogon.exe",
        "csrss.exe": "C:\\Windows\\System32\\csrss.exe",
        "lsass.exe": "C:\\Windows\\System32\\lsass.exe",
        "explorer.exe": "C:\\Windows\\explorer.exe"
    }
    return system_processes.get(process_name.lower()) == process_path

def get_suspicious_processes():
    suspicious_processes = []
    for proc in psutil.process_iter(attrs=['pid', 'name', 'exe', 'ppid']):
        try:
            pid = proc.info['pid']
            name = proc.info['name']
            exe = proc.info['exe'] or "Unknown"
            ppid = proc.info['ppid']
            parent = psutil.Process(ppid).name() if psutil.pid_exists(ppid) else "Unknown"
            
            if exe != "Unknown" and not is_system_process(name, exe):
                # Flag processes running from unexpected locations
                if "C:\\Windows\\System32" not in exe:
                    suspicious_processes.append((name, pid, exe, parent))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return suspicious_processes

def get_suspicious_network_activity():
    suspicious_connections = []
    trusted_apps = {"chrome.exe", "firefox.exe", "edge.exe", "zoom.exe", "teams.exe", "code.exe"}
    for conn in psutil.net_connections(kind='inet'):
        try:
            if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                pid = conn.pid
                if pid:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    if name.lower() not in trusted_apps:
                        suspicious_connections.append((name, pid, conn.raddr[0], conn.raddr[1]))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return suspicious_connections

def get_active_window():
    hwnd = win32gui.GetForegroundWindow()
    _, pid = win32process.GetWindowThreadProcessId(hwnd)
    try:
        proc = psutil.Process(pid)
        return proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "Unknown"

def main():
    print("Scanning for Keyloggers...")
    suspicious_processes = get_suspicious_processes()
    suspicious_network_activity = get_suspicious_network_activity()
    
    if suspicious_processes:
        print("\n[!] Suspicious Processes Detected:")
        for name, pid, exe, parent in suspicious_processes:
            print(f"  - {name} (PID: {pid}) | Path: {exe} | Parent: {parent}")
    else:
        print("[+] No suspicious processes found.")
    
    if suspicious_network_activity:
        print("\n[!] Suspicious Network Activity Detected:")
        for name, pid, ip, port in suspicious_network_activity:
            print(f"  - {name} (PID: {pid}) communicating with {ip}:{port}")
    else:
        print("[+] No suspicious network activity detected.")
    
    active_window = get_active_window()
    print(f"\n[+] Active Window: {active_window}")
    print("\nScan Complete.")
    
if __name__ == "__main__":
    main()
