import subprocess
import socket
import ipaddress
import threading
import platform
import re
import time
import os
import sys
import nmap
from scapy.all import conf, arping
from concurrent.futures import ThreadPoolExecutor
from fingerprint_manager import FingerprintManager
from utils import get_app_path

# Monkey patch subprocess.Popen to suppress console window for nmap on Windows
if sys.platform == 'win32':
    _original_Popen = subprocess.Popen

    class _CustomPopen(_original_Popen):
        def __init__(self, *args, **kwargs):
            if 'creationflags' not in kwargs:
                # Check if command involves nmap
                cmd_args = args[0] if args else kwargs.get('args', [])
                if isinstance(cmd_args, list) and len(cmd_args) > 0:
                    exe = cmd_args[0]
                    # Check if it is nmap executable
                    if 'nmap' in str(exe).lower():
                        kwargs['creationflags'] = 0x08000000  # CREATE_NO_WINDOW
            super().__init__(*args, **kwargs)

    subprocess.Popen = _CustomPopen

class NetworkScanner:
    def __init__(self):
        self.os_name = platform.system()
        self.fingerprinter = FingerprintManager()
        # Load scapy manuf db if not loaded
        if not conf.manufdb:
            try:
                conf.manufdb.reload()
            except:
                pass
        
        # Add local nmap folder to PATH
        app_path = get_app_path()
        local_nmap = os.path.join(app_path, "nmap")
        if os.path.exists(local_nmap):
            os.environ["PATH"] += os.pathsep + local_nmap

        try:
            self.nm = nmap.PortScanner()
            self.use_nmap = True
        except Exception as e:
            print(f"Nmap not available: {e}")
            self.use_nmap = False

    def get_vendor(self, mac):
        try:
            vendor = conf.manufdb._get_manuf(mac)
            if vendor == mac:
                return ""
            return vendor if vendor else ""
        except:
            return ""

    def ping_host(self, ip):
        """
        Pings a host to check if it is reachable.
        Returns (True, ttl) if reachable, (False, None) otherwise.
        """
        param = '-n' if self.os_name.lower() == 'windows' else '-c'
        command = ['ping', param, '1', str(ip)]
        
        creationflags = 0
        if self.os_name.lower() == 'windows':
            creationflags = 0x08000000  # CREATE_NO_WINDOW

        # Suppress output
        try:
            output = subprocess.check_output(command, stderr=subprocess.DEVNULL, creationflags=creationflags).decode()
            
            ttl = None
            # Parse TTL
            if "TTL=" in output: # Windows
                match = re.search(r"TTL=(\d+)", output, re.IGNORECASE)
                if match:
                    ttl = int(match.group(1))
            elif "ttl=" in output.lower(): # Linux/Unix
                match = re.search(r"ttl=(\d+)", output, re.IGNORECASE)
                if match:
                    ttl = int(match.group(1))
            
            return True, ttl
        except subprocess.CalledProcessError:
            return False, None

    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(str(ip))[0]
        except socket.herror:
            return ""

    def get_open_ports(self, ip):
        open_ports = []
        # Expanded list of common ports for better identification
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 443, 445, 
            548, 587, 993, 995, 3306, 3389, 5060, 5432, 5555, 5900, 
            6379, 8008, 8080, 8443, 9100, 62078
        ]
        
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.1) # Short timeout for speed
                    if s.connect_ex((str(ip), port)) == 0:
                        open_ports.append(port)
            except:
                pass
        return open_ports

    def scan_network(self, network_cidr, result_callback, stop_event, use_nmap=True):
        """
        Scans the given network CIDR using Scapy for discovery and Nmap for fingerprinting.
        """
        try:
            # 1. Scapy ARP Discovery (Fast)
            # print(f"Starting ARP scan on {network_cidr}...")
            ans, unans = arping(network_cidr, verbose=0, timeout=2)
            
            live_hosts = []
            for sent, received in ans:
                if stop_event.is_set():
                    break
                live_hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
            
            # print(f"ARP scan found {len(live_hosts)} hosts.")

            # 2. Detailed Scan
            # Use ThreadPool for Nmap scans to speed up
            max_threads = 10
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for host in live_hosts:
                    if stop_event.is_set():
                        break
                    futures.append(executor.submit(self._scan_host_details, host['ip'], host['mac'], result_callback, stop_event, use_nmap))
                
                for future in futures:
                    if stop_event.is_set():
                        break
                    future.result()
                    
        except Exception as e:
            print(f"Scan error: {e}")

    def _scan_host_details(self, ip, mac, result_callback, stop_event, use_nmap=True):
        if stop_event.is_set():
            return

        hostname = ""
        vendor = self.get_vendor(mac)
        host_type = "Unknown"
        os_info = "Unknown"
        open_ports = []

        if self.use_nmap and use_nmap:
            try:
                # -O: OS detection
                # -sV: Version detection
                # -T4: Aggressive timing
                self.nm.scan(ip, arguments='-O -sV -T4')
                
                if ip in self.nm.all_hosts():
                    host_data = self.nm[ip]
                    
                    # Hostname
                    if host_data.hostnames():
                        hostname = host_data.hostnames()[0]['name']
                    
                    # Ports
                    if 'tcp' in host_data:
                        open_ports = list(host_data['tcp'].keys())
                    
                    # OS Detection
                    if 'osmatch' in host_data and host_data['osmatch']:
                        # Get the best match
                        best_match = host_data['osmatch'][0]
                        os_info = best_match['name']
                        
                        # Try to infer type from osclass
                        if 'osclass' in best_match and best_match['osclass']:
                            type_guess = best_match['osclass'][0].get('type', 'unknown')
                            if type_guess != 'unknown':
                                host_type = type_guess.capitalize()
            except Exception as e:
                print(f"Nmap error for {ip}: {e}")
        
        # Fallback / Augment with existing methods if Nmap failed or returned incomplete data
        if not hostname:
            hostname = self.get_hostname(ip)
        
        if not open_ports and (not self.use_nmap or not use_nmap):
             open_ports = self.get_open_ports(ip)

        # Use FingerprintManager to refine or fill gaps
        # We pass a dummy TTL if we didn't ping, or we can ping to get it.
        is_reachable, ttl = self.ping_host(ip)
        inferred_type, inferred_os = self.fingerprinter.identify(mac, open_ports, ttl)
             
        if host_type == "Unknown" or host_type == "General purpose":
             host_type = inferred_type
             
        if os_info == "Unknown":
             os_info = inferred_os

        # Normalize MAC to uppercase
        if mac:
            mac = mac.upper()

        result = {
            "IP Address": ip,
            "Hostname": hostname,
            "MAC Address": mac,
            "Vendor": vendor,
            "Host Type": host_type,
            "Operating System": os_info,
            "Open Ports": open_ports
        }
        result_callback(result)
