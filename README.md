# QuickAsset

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.x-blue.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)

QuickAsset is a desktop application for scanning networks and collecting asset information.

## Screenshot

![QuickAsset Demo](screenshots/sshot.gif)

## Features

- **Immediate Scan**: Scan a network immediately.
- **Continuous Scan**: Scan a network repeatedly at configurable intervals.
- **Data Collection**: Collects IP, Hostname, MAC Address, Vendor, Host Type, and OS.
- **Scan Preview**: View detailed results in a dedicated window with sorting capabilities.
- **Print Reports**: Print professional scan reports directly from the application.
- **Export**: Export results to XLSX and CSV formats.
- **Scan History**: Automatically saves scan history; view, export, or delete past scans.
- **Fingerprint Management**: Customize and manage device identification (MAC/Vendor/OS mapping).
- **Clear Scan**: Quickly clear current results from the interface.
- **User Interface**: Clean UI with menu bar for easy access to tools and settings.

## Requirements

- Python 3.x
- Dependencies listed in `requirements.txt`
- **Npcap**: Required for Nmap scanning. Download and install npcap-installer.exe found in the Release
  **Nmap**: Required for Nmap scanning. Download nmap.zip found in the Release, unzip and place nmap folder in the same directory of the exe file.

## Installation

1. Clone the repository or copy the files to a directory of your choice
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```bash
   python main.py
   # or run the compiled executable in dist\QuickAsset.exe
   ```
2. Enter the network CIDR (e.g., `192.168.1.0/24`).
3. (Optional) Enter a label for the scan (e.g., "MyOffice").
4. Click "Scan (Immediate)" for a one-time scan or "Start Scan (Continuous)" for repeated scanning.
5. View results in the log area or click "View Scan" for a detailed table.
6. Use "Export to XLSX" or "Export to CSV" to save the results.
7. Access "Scan History" or "Manage Fingerprints" from the interface or Tools menu.

## Notes

- The application uses `ping` and `arp` commands, so it works best on local networks.
- MAC address retrieval relies on the ARP table.
- Nmap integration is available for enhanced detection (configurable in Settings).

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

