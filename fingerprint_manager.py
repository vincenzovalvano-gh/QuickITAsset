import json
import os
import threading
from utils import get_config_path

class FingerprintManager:
    def __init__(self, db_path=None):
        if db_path is None:
            self.db_path = get_config_path("fingerprints.json")
        else:
            self.db_path = db_path
            
        self.lock = threading.RLock()
        self.data = self._load_db()

    def reload(self):
        """Reloads the database from disk."""
        with self.lock:
            self.data = self._load_db()

    def _load_db(self):
        default_data = {
            "known_hosts": {}, 
            "ouis": {}, 
            "signatures": [
                {"required_ports": [9100], "forbidden_ports": [], "type": "Printer", "os": ""},
                {"required_ports": [3389], "forbidden_ports": [], "type": "Computer", "os": "Windows"},
                {"required_ports": [5900], "forbidden_ports": [], "type": "Computer", "os": ""},
                {"required_ports": [548], "forbidden_ports": [], "type": "Server", "os": "macOS"},
                {"required_ports": [22, 80], "forbidden_ports": [], "type": "Server", "os": "Linux"},
                {"required_ports": [53], "forbidden_ports": [], "type": "Router", "os": ""},
                {"required_ports": [161], "forbidden_ports": [], "type": "Network Device", "os": ""},
                {"required_ports": [5060], "forbidden_ports": [], "type": "IP Phone", "os": ""},
                {"required_ports": [62078], "forbidden_ports": [], "type": "Mobile Device", "os": "iOS"},
                {"required_ports": [5555], "forbidden_ports": [], "type": "Mobile Device", "os": "Android"}
            ]
        }
        
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r') as f:
                    data = json.load(f)
                    # Merge defaults if signatures are missing
                    if "signatures" not in data or not data["signatures"]:
                        data["signatures"] = default_data["signatures"]
                    return data
            except Exception as e:
                print(f"Error loading fingerprints: {e}")
        
        return default_data

    def save_db(self):
        with self.lock:
            try:
                with open(self.db_path, 'w') as f:
                    json.dump(self.data, f, indent=4)
            except Exception as e:
                print(f"Error saving fingerprints: {e}")

    def get_known_hosts(self):
        with self.lock:
            return self.data.get("known_hosts", {}).copy()

    def update_known_host(self, mac, host_type, os_info="", vendor="", ports=None):
        mac = mac.upper().replace("-", ":")
        with self.lock:
            if "known_hosts" not in self.data:
                self.data["known_hosts"] = {}
            
            # Preserve existing ports if not provided
            current_data = self.data["known_hosts"].get(mac, {})
            if ports is None and "ports" in current_data:
                ports = current_data["ports"]
            elif ports is None:
                ports = []

            self.data["known_hosts"][mac] = {
                "type": host_type,
                "os": os_info,
                "vendor": vendor,
                "ports": ports
            }
            self.save_db()

    def delete_known_host(self, mac):
        mac = mac.upper().replace("-", ":")
        with self.lock:
            if "known_hosts" in self.data and mac in self.data["known_hosts"]:
                del self.data["known_hosts"][mac]
                self.save_db()

    def identify(self, mac, open_ports, ttl):
        """
        Identifies a host based on MAC, ports, and TTL.
        Returns (type, os_guess)
        """
        mac = mac.upper().replace("-", ":")
        
        with self.lock:
            # 1. Check Known Hosts (Exact MAC match)
            if mac in self.data.get("known_hosts", {}):
                entry = self.data["known_hosts"][mac]
                return entry.get("type", "Unknown"), entry.get("os", "Unknown")

            # 1.5 Check Similar Known Hosts (Aggressive Port Matching)
            # If we have a known host with the EXACT same open ports, assume same type.
            # Only if we have some ports open.
            if open_ports:
                open_set = set(open_ports)
                for known_mac, data in self.data.get("known_hosts", {}).items():
                    known_ports = set(data.get("ports", []))
                    if known_ports and known_ports == open_set:
                        # Found a match!
                        return data.get("type", "Unknown"), data.get("os", "")

            # 2. Check Signatures (Ports)
            # We look for the best match. For now, first match wins.
            for sig in self.data.get("signatures", []):
                required = set(sig.get("required_ports", []))
                forbidden = set(sig.get("forbidden_ports", []))
                open_set = set(open_ports)

                if required.issubset(open_set) and not forbidden.intersection(open_set):
                    return sig.get("type", "Unknown"), sig.get("os", "")

            # 3. Check OUI (Manufacturer)
            mac_prefix = mac.replace(":", "")[:6]
            # Format OUI as XX:XX:XX in DB? The DB has XX:XX:XX
            oui_formatted = f"{mac_prefix[:2]}:{mac_prefix[2:4]}:{mac_prefix[4:]}"
            
            if oui_formatted in self.data.get("ouis", {}):
                # OUI match gives us a hint, but maybe not the full type.
                # For VMs it's good. For "Qnap" it implies Server/NAS.
                return self.data["ouis"][oui_formatted], ""

            # 4. Fallback Heuristics (TTL)
            os_guess = ""
            host_type = "Computer" # Default fallback

            if ttl:
                if ttl <= 64:
                    os_guess = "Linux/Unix"
                    # Could be a mobile device if it's Linux/Android/iOS?
                    # Hard to tell without more info.
                elif ttl <= 128:
                    os_guess = "Windows"
                elif ttl > 128:
                    os_guess = ""
                    host_type = "Switch/Router" # Good guess for high TTL

            return host_type, os_guess
