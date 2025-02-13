import nmap
import requests
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# Function to scan open ports and detect services
def scan_ports(target_ip, output_text):
    nm = nmap.PortScanner()
    try:
        nm.scan(target_ip, arguments='-p 1-1024 -sV')  # Scan ports 1-1024 with service detection
        
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    if nm[host][proto][port]['state'] == 'open':
                        service = nm[host][proto][port]['name']
                        version = nm[host][proto][port]['version']
                        open_ports.append((port, service, version))
        return open_ports
    except Exception as e:
        messagebox.showerror("Error", f"Nmap scan failed: {e}")
        return []

# Function to check for vulnerabilities using CVE database
def check_vulnerabilities(service, version):
    base_url = "https://cve.circl.lu/api/search/"
    query = f"{service}/{version}".strip()
    
    try:
        response = requests.get(base_url + query)
        response.raise_for_status()
    except requests.RequestException as e:
        return [f"Error fetching CVE data: {e}"]
    
    vulnerabilities = []
    data = response.json() if response.status_code == 200 else []
    
    if data:
        for vuln in data:
            vulnerabilities.append(f"CVE ID: {vuln['id']}\nSummary: {vuln['summary']}\nCVSS Score: {vuln.get('cvss', 'N/A')}\n")
    else:
        vulnerabilities.append("No known vulnerabilities found.")
    
    return vulnerabilities

# Function to start scan in a separate thread
def start_scan():
    target_ip = entry_ip.get().strip()
    if not target_ip:
        messagebox.showerror("Error", "Please enter a target IP address.")
        return
    
    output_text.delete(1.0, tk.END)  # Clear previous results
    output_text.insert(tk.END, f"Scanning {target_ip}...\n")
    
    def scan():
        try:
            open_ports = scan_ports(target_ip, output_text)
            
            if open_ports:
                output_text.insert(tk.END, "Open Ports Found:\n")
                for port, service, version in open_ports:
                    output_text.insert(tk.END, f"Port {port}: {service} {version}\n")
                    vulnerabilities = check_vulnerabilities(service, version)
                    output_text.insert(tk.END, "Vulnerabilities:\n" + "\n".join(vulnerabilities) + "\n")
            else:
                output_text.insert(tk.END, "No open ports found.\n")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
    
    threading.Thread(target=scan, daemon=True).start()

# GUI Setup
root = tk.Tk()
root.title("Advanced Port Scanner")
root.geometry("700x450")
root.resizable(False, False)

# IP Address Input Frame
frame_input = ttk.Frame(root)
frame_input.pack(pady=10)

label_ip = ttk.Label(frame_input, text="Enter Target IP:")
label_ip.pack(side=tk.LEFT, padx=5)

entry_ip = ttk.Entry(frame_input, width=30)
entry_ip.pack(side=tk.LEFT, padx=5)

button_scan = ttk.Button(frame_input, text="Start Scan", command=start_scan)
button_scan.pack(side=tk.LEFT, padx=5)

# Output Display
output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=85, height=20)
output_text.pack(padx=10, pady=10)

# Run the GUI
root.mainloop()
