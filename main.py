import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import time
import datetime
import json
import os
import ipaddress
from scanner import NetworkScanner
from storage import StorageManager
from fingerprint_manager import FingerprintManager
from utils import get_config_path, resource_path

class QuickAssetApp:
    def __init__(self, root):
        self.root = root
        self.version = "1.0"
        self.root.title(f"QuickAsset v{self.version} - ©Vincenzo Valvano")
        self._center_window(self.root, 800, 600)
        
        # Set window icon
        try:
            self.root.iconbitmap(resource_path("app.ico"))
        except Exception as e:
            print(f"Could not load icon: {e}")

        self.scanner = NetworkScanner()
        self.storage = StorageManager()
        self.fingerprint_manager = FingerprintManager()
        
        self.scanning = False
        self.continuous_mode = False
        self.stop_event = threading.Event()
        self.scan_thread = None
        self.current_network = ""
        self.scan_results = []
        
        # Settings
        self.scan_interval = 5 # minutes
        self.use_nmap_setting = False
        self.launch_excel = True
        self._load_config()

        self._create_widgets()

    def _center_window(self, window, width, height):
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        window.geometry(f"{width}x{height}+{x}+{y}")

    def _load_config(self):
        config_path = get_config_path("config.json")
        try:
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    config = json.load(f)
                    self.scan_interval = config.get("scan_interval", 5)
                    self.use_nmap_setting = config.get("use_nmap", False)
                    self.launch_excel = config.get("launch_excel", True)
                    return config.get("last_network", "192.168.1.0/24")
        except Exception:
            pass
        return "192.168.1.0/24"

    def _save_config(self):
        config_path = get_config_path("config.json")
        try:
            config = {
                "last_network": self.network_entry.get().strip(),
                "scan_interval": self.scan_interval,
                "use_nmap": self.use_nmap_setting,
                "launch_excel": self.launch_excel
            }
            with open(config_path, "w") as f:
                json.dump(config, f)
        except Exception:
            pass

    def _create_widgets(self):
        # Input Frame
        input_frame = ttk.Frame(self.root, padding="10")
        input_frame.pack(fill=tk.X)

        ttk.Label(input_frame, text="Network (CIDR):").pack(side=tk.LEFT)
        self.network_entry = ttk.Entry(input_frame, width=30)
        self.network_entry.pack(side=tk.LEFT, padx=5)
        self.network_entry.insert(0, self._load_config())

        ttk.Label(input_frame, text="Label (Optional):").pack(side=tk.LEFT, padx=(10, 0))
        self.label_entry = ttk.Entry(input_frame, width=20)
        self.label_entry.pack(side=tk.LEFT, padx=5)

        # Buttons Frame
        btn_frame = ttk.Frame(self.root, padding="10")
        btn_frame.pack(fill=tk.X)

        self.btn_scan = ttk.Button(btn_frame, text="Scan (Immediate)", command=self.start_immediate_scan)
        self.btn_scan.pack(side=tk.LEFT, padx=5)

        self.btn_start_cont = ttk.Button(btn_frame, text="Start Scan (Continuous)", command=self.start_continuous_scan)
        self.btn_start_cont.pack(side=tk.LEFT, padx=5)

        self.btn_stop = ttk.Button(btn_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        # self.btn_export = ttk.Button(btn_frame, text="Export to Excel", command=self.export_excel)
        # self.btn_export.pack(side=tk.RIGHT, padx=5)

        self.btn_history = ttk.Button(btn_frame, text="Scan History", command=self.open_history_window)
        self.btn_history.pack(side=tk.RIGHT, padx=5)

        self.btn_manage_fp = ttk.Button(btn_frame, text="Manage Fingerprints", command=self.open_fingerprint_manager)
        self.btn_manage_fp.pack(side=tk.RIGHT, padx=5)

        self.btn_settings = ttk.Button(btn_frame, text="Settings", command=self.open_settings_window)
        self.btn_settings.pack(side=tk.RIGHT, padx=5)

        # Results Area
        self.log_area = scrolledtext.ScrolledText(self.root, state='disabled', height=20)
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def log(self, message):
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {message}\n")
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')

    def clear_log(self):
        self.log_area.config(state='normal')
        self.log_area.delete('1.0', tk.END)
        self.log_area.config(state='disabled')

    def start_immediate_scan(self):
        network = self.network_entry.get().strip()
        label = self.label_entry.get().strip()
        if not network:
            messagebox.showerror("Error", "Please enter a network CIDR.")
            return
        
        self._save_config()
        self.current_network = network
        self.current_label = label
        self.continuous_mode = False
        self._start_scan_thread()

    def start_continuous_scan(self):
        network = self.network_entry.get().strip()
        label = self.label_entry.get().strip()
        if not network:
            messagebox.showerror("Error", "Please enter a network CIDR.")
            return
        
        self._save_config()
        self.current_network = network
        self.current_label = label
        self.continuous_mode = True
        self._start_scan_thread()

    def _start_scan_thread(self):
        self.scanning = True
        self.stop_event.clear()
        self.btn_scan.config(state=tk.DISABLED)
        self.btn_start_cont.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.network_entry.config(state=tk.DISABLED)
        
        # Initialize continuous scan variables
        self.continuous_history_file = None
        self.run_count = 0

        self.scan_thread = threading.Thread(target=self._scan_process)
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def stop_scan(self):
        if self.scanning:
            self.log("Stopping scan...")
            self.stop_event.set()
            # The thread will clean up when it finishes the current loop or waits

    def _scan_process(self):
        while True:
            if self.stop_event.is_set():
                break
            
            self.run_count += 1
            
            # Reload fingerprints before scanning
            self.fingerprint_manager.reload()

            # Clear log area for new scan
            self.root.after(0, self.clear_log)

            status_text = f"Scanning (Continuous #{self.run_count})..." if self.continuous_mode else "Scanning (Single)..."
            self.root.after(0, self.log, f"Starting scan for {self.current_network}...")
            self.root.after(0, self.status_var.set, status_text)
            
            # Load existing results to merge later
            existing_results = self.storage.load_results(self.current_network)
            results_map = {}
            for h in existing_results:
                mac = h.get('MAC Address')
                if mac:
                    results_map[mac.upper()] = h

            self.scan_results = [] # Clear previous results for this run
            
            self.scanner.scan_network(self.current_network, self._on_host_found, self.stop_event, use_nmap=self.use_nmap_setting)
            
            if self.stop_event.is_set():
                self.root.after(0, self.log, "Scan stopped by user.")
                break

            # Merge results
            for host in self.scan_results:
                mac = host.get('MAC Address')
                if mac:
                    results_map[mac.upper()] = host
            
            merged_results = list(results_map.values())

            # Save results
            # If continuous mode, reuse the history file
            if self.continuous_mode:
                self.continuous_history_file = self.storage.save_results(
                    self.current_network, 
                    merged_results, 
                    getattr(self, 'current_label', None),
                    history_filename=self.continuous_history_file
                )
            else:
                self.storage.save_results(self.current_network, merged_results, getattr(self, 'current_label', None))

            self.root.after(0, self.log, f"Scan complete. Found {len(self.scan_results)} hosts. Saved to JSON.")

            if not self.continuous_mode:
                break
            
            # Wait interval
            wait_minutes = self.scan_interval
            self.root.after(0, self.log, f"Waiting {wait_minutes} minutes for next scan...")
            self.root.after(0, self.status_var.set, f"Waiting (Next: #{self.run_count + 1})...")
            
            # Wait loop to allow responsive stop
            wait_seconds = wait_minutes * 60
            for i in range(wait_seconds, 0, -1):
                if self.stop_event.is_set():
                    break
                
                mins, secs = divmod(i, 60)
                countdown_text = f"Next scan: {mins:02d}:{secs:02d}"
                self.root.after(0, lambda t=countdown_text: self.btn_start_cont.config(text=t))
                
                time.sleep(1)
            
            # Reset text before next scan or exit
            self.root.after(0, lambda: self.btn_start_cont.config(text="Start Scan (Continuous)"))
            
            if self.stop_event.is_set():
                break

        self.scanning = False
        self.root.after(0, self._reset_ui)

    def _on_host_found(self, result):
        self.scan_results.append(result)
        
        # Auto-add to Fingerprint DB if not exists
        mac = result.get('MAC Address')
        if mac:
            known = self.fingerprint_manager.get_known_hosts()
            if mac not in known:
                self.fingerprint_manager.update_known_host(
                    mac, 
                    result.get('Host Type', 'Unknown'), 
                    result.get('Operating System', 'Unknown'), 
                    vendor=result.get('Vendor', ''),
                    ports=result.get('Open Ports', [])
                )
            else:
                # Update ports if known host is found again
                current = known[mac]
                self.fingerprint_manager.update_known_host(
                    mac,
                    current.get('type', 'Unknown'),
                    current.get('os', 'Unknown'),
                    vendor=current.get('vendor', ''),
                    ports=result.get('Open Ports', [])
                )

        # Update UI

        # Update UI
        msg = f"Found: {result['IP Address']} ({result['Hostname']}) - {result['MAC Address']} - Type: {result.get('Host Type', 'Unknown')}"
        self.root.after(0, self.log, msg)

    def _reset_ui(self):
        self.btn_scan.config(state=tk.NORMAL)
        self.btn_start_cont.config(state=tk.NORMAL, text="Start Scan (Continuous)")
        self.btn_stop.config(state=tk.DISABLED)
        self.network_entry.config(state=tk.NORMAL)
        self.status_var.set("Ready")
        self.log("Ready.")

    def export_excel(self):
        network = self.network_entry.get().strip()
        if not network:
            messagebox.showerror("Error", "Please enter a network CIDR to export.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
        if file_path:
            # Reload fingerprints to ensure we have the latest data
            self.fingerprint_manager.reload()
            known_hosts = self.fingerprint_manager.get_known_hosts()
            
            if self.storage.export_to_excel(network, file_path, known_hosts):
                messagebox.showinfo("Success", f"Exported to {file_path}")
            else:
                messagebox.showerror("Error", "Failed to export. Make sure a scan has been performed for this network.")

    def open_fingerprint_manager(self):
        fp_window = tk.Toplevel(self.root)
        fp_window.title("Manage Fingerprints")
        self._center_window(fp_window, 800, 500)
        try:
            fp_window.iconbitmap(resource_path("app.ico"))
        except Exception:
            pass

        # Frame for List
        list_frame = ttk.Frame(fp_window, padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("ip", "hostname", "mac", "type", "os", "vendor")
        tree = ttk.Treeview(list_frame, columns=columns, show="headings")
        tree.heading("ip", text="IP Address")
        tree.heading("hostname", text="Hostname")
        tree.heading("mac", text="MAC Address")
        tree.heading("type", text="Type")
        tree.heading("os", text="OS")
        tree.heading("vendor", text="Vendor")
        
        tree.column("ip", width=100)
        tree.column("hostname", width=150)
        tree.column("mac", width=120)
        tree.column("type", width=100)
        tree.column("os", width=100)
        tree.column("vendor", width=200)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Frame for Editing
        edit_frame = ttk.LabelFrame(fp_window, text="Edit Fingerprint", padding="10")
        edit_frame.pack(fill=tk.X, padx=10, pady=10)

        # MAC
        ttk.Label(edit_frame, text="MAC Address:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        mac_entry = ttk.Entry(edit_frame, width=20)
        mac_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        # Type
        ttk.Label(edit_frame, text="Type:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        type_combo = ttk.Combobox(edit_frame, values=[
            "Access Point", "Badge Reader", "Camera Server", "Computer", "Firewall", 
            "IP Phone", "Media Device", "Mobile Device", "Nas", "Printer", 
            "Router", "Server", "Soundbar", "Switch", 
            "UPS", "Virtual Machine"
        ], width=18)
        type_combo.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)

        # OS
        ttk.Label(edit_frame, text="OS:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        os_entry = ttk.Entry(edit_frame, width=20)
        os_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        # Vendor
        ttk.Label(edit_frame, text="Vendor:").grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)
        vendor_entry = ttk.Entry(edit_frame, width=25)
        vendor_entry.grid(row=1, column=3, padx=5, pady=5, sticky=tk.W)

        # Buttons
        btn_frame = ttk.Frame(edit_frame)
        btn_frame.grid(row=2, column=0, columnspan=4, pady=10)

        def load_data():
            for item in tree.get_children():
                tree.delete(item)
            
            # Load scan results for current network to map MAC -> IP and Hostname
            current_network = self.network_entry.get().strip()
            scan_results = self.storage.load_results(current_network)
            mac_info = {}
            if scan_results:
                for res in scan_results:
                    m = res.get("MAC Address")
                    i = res.get("IP Address")
                    h = res.get("Hostname", "")
                    if m:
                        # Normalize MAC to uppercase for consistent lookup
                        mac_info[m.upper()] = {"ip": i, "hostname": h}

            hosts = self.fingerprint_manager.get_known_hosts()
            
            # Prepare list for sorting
            display_list = []
            for mac, data in hosts.items():
                # Ensure mac is uppercase for lookup (though keys in hosts should already be upper)
                info = mac_info.get(mac.upper(), {"ip": "", "hostname": ""})
                display_list.append({
                    "ip": info["ip"],
                    "hostname": info["hostname"],
                    "mac": mac,
                    "type": data.get("type", ""),
                    "os": data.get("os", ""),
                    "vendor": data.get("vendor", "")
                })

            # Sort by IP Address
            def ip_sort_key(item):
                ip = item["ip"]
                if ip:
                    try:
                        return ipaddress.ip_address(ip)
                    except ValueError:
                        pass
                # Return a value that sorts after valid IPs (e.g., max possible IP or just a high number/string)
                # Using a dummy high IP for sorting empty/invalid IPs at the end
                return ipaddress.ip_address("255.255.255.255")

            display_list.sort(key=ip_sort_key)

            for item in display_list:
                tree.insert("", tk.END, values=(item["ip"], item["hostname"], item["mac"], item["type"], item["os"], item["vendor"]))

        def on_select(event):
            selected_item = tree.selection()
            if selected_item:
                item = tree.item(selected_item)
                vals = item['values']
                if vals:
                    mac_entry.delete(0, tk.END)
                    mac_entry.insert(0, vals[2])
                    type_combo.set(vals[3])
                    os_entry.delete(0, tk.END)
                    os_entry.insert(0, vals[4])
                    vendor_entry.delete(0, tk.END)
                    vendor_entry.insert(0, vals[5])

        tree.bind("<<TreeviewSelect>>", on_select)

        def save_entry():
            mac = mac_entry.get().strip()
            host_type = type_combo.get().strip()
            os_info = os_entry.get().strip()
            vendor = vendor_entry.get().strip()

            if not mac:
                messagebox.showerror("Error", "MAC Address is required.", parent=fp_window)
                return

            self.fingerprint_manager.update_known_host(mac, host_type, os_info, vendor=vendor)
            load_data()
            messagebox.showinfo("Success", "Fingerprint saved.", parent=fp_window)
            
            # Clear entries
            mac_entry.delete(0, tk.END)
            type_combo.set("")
            os_entry.delete(0, tk.END)
            vendor_entry.delete(0, tk.END)

        def delete_entry():
            mac = mac_entry.get().strip()
            if not mac:
                messagebox.showerror("Error", "MAC Address is required to delete.", parent=fp_window)
                return
            
            if messagebox.askyesno("Confirm", f"Delete fingerprint for {mac}?", parent=fp_window):
                self.fingerprint_manager.delete_known_host(mac)
                load_data()
                # Clear entries
                mac_entry.delete(0, tk.END)
                type_combo.set("")
                os_entry.delete(0, tk.END)
                vendor_entry.delete(0, tk.END)

        ttk.Button(btn_frame, text="Save / Update", command=save_entry).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Delete", command=delete_entry).pack(side=tk.LEFT, padx=5)

        load_data()

    def open_history_window(self):
        hist_window = tk.Toplevel(self.root)
        hist_window.title("Scan History")
        self._center_window(hist_window, 750, 400)
        try:
            hist_window.iconbitmap(resource_path("app.ico"))
        except Exception:
            pass

        # List Frame
        list_frame = ttk.Frame(hist_window, padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("timestamp", "network", "label", "count")
        tree = ttk.Treeview(list_frame, columns=columns, show="headings")
        tree.heading("timestamp", text="Date/Time")
        tree.heading("network", text="Network CIDR")
        tree.heading("label", text="Label")
        tree.heading("count", text="Hosts Found")
        
        tree.column("timestamp", width=150)
        tree.column("network", width=150)
        tree.column("label", width=150)
        tree.column("count", width=100)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscroll=scrollbar.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Buttons
        btn_frame = ttk.Frame(hist_window, padding="10")
        btn_frame.pack(fill=tk.X)

        item_map = {}

        def load_history_mapped():
            item_map.clear()
            for item in tree.get_children():
                tree.delete(item)
            
            history = self.storage.get_history()
            for entry in history:
                item_id = tree.insert("", tk.END, values=(entry.get("timestamp"), entry.get("network"), entry.get("label", ""), entry.get("count")))
                item_map[item_id] = entry.get("file")

        def delete_selected_mapped():
            selected_items = tree.selection()
            if not selected_items:
                messagebox.showwarning("Warning", "Please select at least one scan to delete.", parent=hist_window)
                return
            
            if not messagebox.askyesno("Confirm", f"Delete {len(selected_items)} selected scan(s)?", parent=hist_window):
                return

            deleted_count = 0
            for item_id in selected_items:
                filename = item_map.get(item_id)
                if filename:
                    if self.storage.delete_history_entry(filename):
                        deleted_count += 1
            
            if deleted_count > 0:
                load_history_mapped()
                messagebox.showinfo("Success", f"Deleted {deleted_count} scan(s).", parent=hist_window)
            else:
                messagebox.showerror("Error", "Failed to delete selected scan(s).", parent=hist_window)

        def export_selected_mapped():
            selected_item = tree.selection()
            if not selected_item:
                messagebox.showwarning("Warning", "Please select a scan to export.", parent=hist_window)
                return
            
            item_id = selected_item[0]
            filename = item_map.get(item_id)
            
            if not filename:
                return

            default_name = filename.replace(".json", ".xlsx")

            file_path = filedialog.asksaveasfilename(
                defaultextension=".xlsx", 
                filetypes=[("Excel files", "*.xlsx")], 
                parent=hist_window,
                initialfile=default_name
            )
            if file_path:
                # Reload fingerprints
                self.fingerprint_manager.reload()
                known_hosts = self.fingerprint_manager.get_known_hosts()
                
                if self.storage.export_history_to_excel(filename, file_path, known_hosts):
                    messagebox.showinfo("Success", f"Exported to {file_path}", parent=hist_window)
                    if self.launch_excel:
                        try:
                            os.startfile(file_path)
                        except Exception as e:
                            messagebox.showerror("Error", f"Could not open file: {e}", parent=hist_window)
                else:
                    messagebox.showerror("Error", "Failed to export.", parent=hist_window)

        def export_selected_csv_mapped():
            selected_item = tree.selection()
            if not selected_item:
                messagebox.showwarning("Warning", "Please select a scan to export.", parent=hist_window)
                return
            
            item_id = selected_item[0]
            filename = item_map.get(item_id)
            
            if not filename:
                return

            default_name = filename.replace(".json", ".csv")

            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv", 
                filetypes=[("CSV files", "*.csv")], 
                parent=hist_window,
                initialfile=default_name
            )
            if file_path:
                # Reload fingerprints
                self.fingerprint_manager.reload()
                known_hosts = self.fingerprint_manager.get_known_hosts()
                
                if self.storage.export_history_to_csv(filename, file_path, known_hosts):
                    messagebox.showinfo("Success", f"Exported to {file_path}", parent=hist_window)
                    # Do NOT launch file for CSV
                else:
                    messagebox.showerror("Error", "Failed to export.", parent=hist_window)

        ttk.Button(btn_frame, text="Export to Excel", command=export_selected_mapped).pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="Export to CSV", command=export_selected_csv_mapped).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Delete", command=delete_selected_mapped).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Refresh", command=load_history_mapped).pack(side=tk.LEFT)

        load_history_mapped()

    def open_settings_window(self):
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")
        self._center_window(settings_window, 400, 200)
        try:
            settings_window.iconbitmap(resource_path("app.ico"))
        except Exception:
            pass

        # Interval
        ttk.Label(settings_window, text="Continuous Scan Interval (minutes):").pack(pady=(20, 5))
        interval_var = tk.IntVar(value=self.scan_interval)
        interval_spin = ttk.Spinbox(settings_window, from_=1, to=1440, textvariable=interval_var, width=10)
        interval_spin.pack()

        # Nmap
        use_nmap_var = tk.BooleanVar(value=self.use_nmap_setting)
        ttk.Checkbutton(settings_window, text="Use Nmap", variable=use_nmap_var).pack(pady=5)

        # Launch Excel
        launch_excel_var = tk.BooleanVar(value=self.launch_excel)
        ttk.Checkbutton(settings_window, text="Launch Spreadsheet After Export", variable=launch_excel_var).pack(pady=5)

        def save_settings():
            try:
                new_interval = int(interval_var.get())
                if new_interval < 1:
                    raise ValueError
                self.scan_interval = new_interval
                self.use_nmap_setting = use_nmap_var.get()
                self.launch_excel = launch_excel_var.get()
                self._save_config()
                messagebox.showinfo("Success", "Settings saved.", parent=settings_window)
                settings_window.destroy()
            except ValueError:
                messagebox.showerror("Error", "Invalid interval value.", parent=settings_window)

        ttk.Button(settings_window, text="Save", command=save_settings).pack(pady=10)

if __name__ == "__main__":
    root = tk.Tk()
    app = QuickAssetApp(root)
    
    # Close splash screen if it exists
    try:
        import pyi_splash
        pyi_splash.close()
    except ImportError:
        pass

    root.mainloop()
