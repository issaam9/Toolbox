import subprocess

def run_nmap_scan(ip):
    command = f"nmap -sV -T4 {ip}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout