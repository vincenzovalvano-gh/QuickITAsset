import json
import os
import ipaddress
import pandas as pd
import datetime
from utils import get_app_path

class StorageManager:
    def __init__(self, data_dir=None):
        if data_dir is None:
            self.data_dir = get_app_path()
        else:
            self.data_dir = data_dir
            
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
            
        self.history_dir = os.path.join(self.data_dir, "history")
        if not os.path.exists(self.history_dir):
            os.makedirs(self.history_dir)
            
        self.history_file = os.path.join(self.data_dir, "scan_history.json")

    def _get_filename(self, network):
        # Sanitize network string to be a valid filename
        safe_network = network.replace("/", "_").replace("\\", "_").replace(":", "_")
        return os.path.join(self.data_dir, f"results_{safe_network}.json")

    def save_results(self, network, results, label=None, history_filename=None):
        """
        Saves the list of results to a JSON file (latest state) AND creates/updates a history entry.
        If history_filename is provided, it updates that specific history file instead of creating a new one.
        """
        # 1. Save Latest State
        filename = self._get_filename(network)
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=4)
        except Exception as e:
            print(f"Error saving results: {e}")

        # 2. Save History Snapshot
        try:
            if not history_filename:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                safe_network = network.replace("/", "_").replace("\\", "_").replace(":", "_")
                
                if label:
                    safe_label = "".join(c for c in label if c.isalnum() or c in (' ', '_', '-')).strip().replace(" ", "_")
                    history_filename = f"scan_{timestamp}_{safe_network}_{safe_label}.json"
                else:
                    history_filename = f"scan_{timestamp}_{safe_network}.json"
            
            history_path = os.path.join(self.history_dir, history_filename)
            
            with open(history_path, 'w') as f:
                json.dump(results, f, indent=4)
                
            # 3. Update History Index
            history_list = self.get_history()
            
            # Check if entry already exists
            existing_entry = next((item for item in history_list if item["file"] == history_filename), None)
            
            if existing_entry:
                # Update existing entry
                existing_entry["count"] = len(results)
                # Optionally update timestamp to last modified? Or keep start time?
                # Let's update timestamp to show last update time
                existing_entry["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            else:
                # Create new entry
                history_entry = {
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "network": network,
                    "label": label if label else "",
                    "file": history_filename,
                    "count": len(results)
                }
                history_list.insert(0, history_entry) # Prepend
            
            with open(self.history_file, 'w') as f:
                json.dump(history_list, f, indent=4)
                
            return history_filename
                
        except Exception as e:
            print(f"Error saving history: {e}")
            return None

    def get_history(self):
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []

    def delete_history_entry(self, filename):
        """
        Deletes a history entry and its associated file.
        """
        # 1. Remove from history index
        history_list = self.get_history()
        new_history_list = [entry for entry in history_list if entry.get("file") != filename]
        
        if len(history_list) != len(new_history_list):
            try:
                with open(self.history_file, 'w') as f:
                    json.dump(new_history_list, f, indent=4)
            except Exception as e:
                print(f"Error updating history index: {e}")
                return False

        # 2. Delete the file
        file_path = os.path.join(self.history_dir, filename)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"Error deleting history file: {e}")
                # We continue even if file deletion fails, as index is updated
        
        return True

    def load_history_results(self, filename):
        path = os.path.join(self.history_dir, filename)
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []

    def load_results(self, network):
        """
        Loads results from a JSON file.
        Returns a list of dicts.
        """
        filename = self._get_filename(network)
        if os.path.exists(filename):
            try:
                with open(filename, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading results: {e}")
        return []

    def export_data_to_excel(self, results, output_path, known_hosts=None):
        if not results:
            return False
        
        # Update results with known_hosts data if available
        if known_hosts:
            for res in results:
                mac = res.get("MAC Address")
                if mac:
                    mac_lookup = mac.upper()
                    if mac_lookup in known_hosts:
                        data = known_hosts[mac_lookup]
                        # Update fields if they exist in known_hosts
                        if "type" in data and data["type"]:
                            res["Host Type"] = data["type"]
                        if "os" in data and data["os"]:
                            res["Operating System"] = data["os"]
                        if "vendor" in data and data["vendor"]:
                            res["Vendor"] = data["vendor"]

        # Sort by IP
        def ip_sort_key(item):
            try:
                return ipaddress.ip_address(item.get("IP Address", "0.0.0.0"))
            except:
                return ipaddress.ip_address("0.0.0.0")
        
        results.sort(key=ip_sort_key)
        
        try:
            df = pd.DataFrame(results)
            
            # Ensure column order
            desired_columns = ["IP Address", "Hostname", "MAC Address", "Vendor", "Host Type", "Operating System", "Open Ports"]
            # Filter to only columns that exist
            existing_columns = [c for c in desired_columns if c in df.columns]
            # Add any other columns
            other_columns = [c for c in df.columns if c not in existing_columns]
            
            df = df[existing_columns + other_columns]
            
            # Create a Pandas Excel writer using Openpyxl as the engine
            with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
                df.to_excel(writer, index=False, sheet_name='Scan Results')
                
                # Access the workbook and sheet
                workbook = writer.book
                worksheet = writer.sheets['Scan Results']
                
                # Set column widths
                column_widths = {
                    'A': 14, # IP Address
                    'B': 21, # Hostname
                    'C': 18, # MAC Address
                    'D': 42, # Vendor
                    'E': 22, # Host Type
                    'F': 17, # Operating System
                    'G': 15  # Open Ports
                }
                
                for col_letter, width in column_widths.items():
                    worksheet.column_dimensions[col_letter].width = width

            return True
        except Exception as e:
            print(f"Error exporting to Excel: {e}")
            return False

    def export_data_to_csv(self, results, output_path, known_hosts=None):
        if not results:
            return False
        
        # Update results with known_hosts data if available
        if known_hosts:
            for res in results:
                mac = res.get("MAC Address")
                if mac:
                    mac_lookup = mac.upper()
                    if mac_lookup in known_hosts:
                        data = known_hosts[mac_lookup]
                        # Update fields if they exist in known_hosts
                        if "type" in data and data["type"]:
                            res["Host Type"] = data["type"]
                        if "os" in data and data["os"]:
                            res["Operating System"] = data["os"]
                        if "vendor" in data and data["vendor"]:
                            res["Vendor"] = data["vendor"]

        # Sort by IP
        def ip_sort_key(item):
            try:
                return ipaddress.ip_address(item.get("IP Address", "0.0.0.0"))
            except:
                return ipaddress.ip_address("0.0.0.0")
        
        results.sort(key=ip_sort_key)
        
        try:
            df = pd.DataFrame(results)
            
            # Ensure column order
            desired_columns = ["IP Address", "Hostname", "MAC Address", "Vendor", "Host Type", "Operating System", "Open Ports"]
            # Filter to only columns that exist
            existing_columns = [c for c in desired_columns if c in df.columns]
            # Add any other columns
            other_columns = [c for c in df.columns if c not in existing_columns]
            
            df = df[existing_columns + other_columns]
            
            df.to_csv(output_path, index=False)
            return True
        except Exception as e:
            print(f"Error exporting to CSV: {e}")
            return False

    def export_to_excel(self, network, output_path, known_hosts=None):
        """
        Exports the results for a given network to an Excel file.
        If known_hosts is provided (dict of mac -> info), it updates the results with the latest info.
        """
        results = self.load_results(network)
        return self.export_data_to_excel(results, output_path, known_hosts)

    def export_history_to_excel(self, history_filename, output_path, known_hosts=None):
        results = self.load_history_results(history_filename)
        return self.export_data_to_excel(results, output_path, known_hosts)

    def export_history_to_csv(self, history_filename, output_path, known_hosts=None):
        results = self.load_history_results(history_filename)
        return self.export_data_to_csv(results, output_path, known_hosts)
