# QuickAsset

QuickAsset is a desktop application for scanning networks and collecting asset information.

## Features

- **Immediate Scan**: Scan a network immediately.
- **Continuous Scan**: Scan a network repeatedly every 5 minutes.
- **Data Collection**: Collects IP, Hostname, MAC Address, Host Type, and OS (if available).
- **Export**: Export results to Excel.
- **Storage**: Saves results to JSON files.

## Requirements

- Python 3.x
- Dependencies listed in `requirements.txt`

## Installation

1. Clone the repository or copy the files to `C:\Source\QuickAsset`.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```bash
   python main.py
   or find dist\QuickAsset.exe x64 Windows binary
   ```
2. Enter the network CIDR (e.g., `192.168.1.0/24`).
3. Click "Scan" for a one-time scan or "Start Scan" for continuous scanning.
4. View results in the log area.
5. Click "Export to Excel" to save the results.

## Notes

- The application uses `ping` and `arp` commands, so it works best on local networks.
- MAC address retrieval relies on the ARP table, which is populated by the ping command.
