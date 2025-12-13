# QuickAsset

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.x-blue.svg)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)

QuickAsset is a desktop application for scanning networks and collecting asset information.

## Screenshots

![Screenshot 1](screenshots/Screenshot%202025-12-13%20230814.png)
![Screenshot 2](screenshots/Screenshot%202025-12-13%20230842.png)
![Screenshot 3](screenshots/Screenshot%202025-12-13%20230914.png)
![Screenshot 4](screenshots/Screenshot%202025-12-13%20231036.png)

## Features

- **Immediate Scan**: Scan a network immediately.
- **Continuous Scan**: Scan a network repeatedly every 5 minutes.
- **Data Collection**: Collects IP, Hostname, MAC Address, Host Type, and OS (if available).
- **Export**: Export results to Excel.
- **Storage**: Saves results to JSON files.

## Requirements

- Python 3.x
- Dependencies listed in `requirements.txt`
- **Npcap**: Required for Nmap scanning. The installer can be found in the `dist` directory.

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

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
