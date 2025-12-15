# Changelog

## \[1.2] - 2025-12-15

### Added

* **Resume Scan**: Added ability to resume a previous scan from the "Scan History" window.
* **Tooltip for Open Ports**: Added a tooltip in "Manage Fingerprints" that shows open ports when hovering over a selected host.
* **In-Place Editing**: Added ability to edit the "Type" field directly in the "Manage Fingerprints" list by double-clicking.
* **System Tray Integration**: The application now minimizes to the system tray instead of closing.
* **Tray Context Menu**: Added "Restore" and "Exit" options to the tray icon context menu.
* **Exit Splash Screen**: Added a "Goodbye" splash screen when exiting the application.
* **Exit Confirmation**: Added a confirmation dialog when exiting if a scan is currently in progress.

### Changed

* **Project Rename**: Renamed application from "QuickAsset" to "QuickITAsset".

### Fixed

* **Splash Screen**: Fixed issue where splash screen was not showing up in the compiled executable.
* **Tray Exit**: Fixed issue where the application process remained active if exit was cancelled from the tray menu.
