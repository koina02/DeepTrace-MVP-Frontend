import os

def scan_network(target):
    print(f"Scanning {target} for open ports...")
    os.system(f"nmap -Pn -p 1-65535 {target}")

if __name__ == "__main__":
    target_ip = input("Enter target IP or domain: ")
    scan_network(target_ip)
