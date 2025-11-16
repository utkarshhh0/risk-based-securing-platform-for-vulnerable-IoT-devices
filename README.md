# Risk-Based Securing Platform for Vulnerable IoT Devices (Streamlit MVP)

## Project Overview
A lightweight, Streamlit-based web application that rapidly scans IoT devices on a local subnet, identifies common vulnerabilities (default/weak credentials, risky open ports, outdated firmware), computes risk scores to prioritize remediation, and offers one-click simulated remediation actions. Perfect for hackathon demos and rapid prototyping.

## Key Features
- **Multi-Vulnerability Scanner**: Scans local subnet for IoT devices and detects vulnerabilities
- **Risk-Based Prioritization**: Calculates risk scores (0-100) to prioritize remediation efforts
- **One-Click Simulated Fixes**: Generate strong passwords and simulate port closures
- **Lifecycle Security Warnings**: Flags devices with EOL (End-of-Life) firmware
- **User-Definable Security Policies**: Customize password complexity and allowed ports
- **Interactive Dashboard**: Real-time alerts, device overview, and detailed vulnerability views
- **Extensible Device Management**: Add/edit/remove fake devices for testing and demos
- **CSV Export**: Export device inventory and remediation logs

## Installation

### Prerequisites
- Python 3.9 or higher
- Windows 11 (or any system supporting Python and Streamlit)
- Network access to local subnet

### Setup Steps

1. **Clone or download this repository**
   ```bash
   cd risk-based-securing-platform-for-vulnerable-IoT-devices
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   streamlit run app.py
   ```

4. **Access the dashboard**
   - The app will automatically open in your default web browser
   - Default URL: `http://localhost:8501`

## Usage Guide

### 1. Network Scanning
- Use the sidebar to enter a subnet (e.g., `192.168.1.0/24`) or single IP address
- Enable "Simulation Mode" for demo purposes (uses fake devices)
- Click "🔍 Scan Network" to discover devices
- The scan will automatically analyze vulnerabilities and calculate risk scores

### 2. Dashboard Overview
- View summary statistics: total devices, critical/high risk counts, total vulnerabilities
- See color-coded device table sorted by risk category
- Use "Fix All Critical Devices" for bulk remediation

### 3. Device Details
- Select a device from the dropdown to view detailed information
- See all vulnerabilities with severity levels
- Apply individual fixes or use "Fix All Vulnerabilities" button
- View generated passwords for credential fixes

### 4. Remediation Logs
- Track all remediation actions with timestamps
- Filter by device IP or action type
- Review fix history and generated credentials

### 5. Security Policy
- Click "⚙️ Edit Policy" in sidebar to customize:
  - Password length and complexity requirements
  - Allowed ports (default: only HTTPS/443)
  - Risk score thresholds (Critical/High/Medium)

### 6. Device Management
- Add fake devices for testing/demos using "➕ Add Fake Device"
- Specify IP, hostname, and open ports
- Fake devices are automatically included in scans

### 7. Export Data
- Export device inventory as CSV
- Export remediation logs as CSV
- Files saved to `exports/` directory with timestamps

## Project Structure

```
.
├── app.py                 # Main Streamlit application
├── scanner.py             # Network scanning and device discovery
├── vulnerability.py       # Vulnerability detection and risk scoring
├── remediation.py         # Simulated fix operations
├── device_manager.py      # Device management (add/edit/remove)
├── policy.py              # Security policy management
├── utils.py               # Utility functions (password gen, CSV export)
├── requirements.txt       # Python dependencies
├── data/                  # Data storage (devices, policies, EOL DB)
└── exports/               # CSV export directory
```

## Features in Detail

### Vulnerability Detection
- **Default Credentials**: Checks against common default username/password combinations
- **Risky Ports**: Identifies open ports that violate security policy (Telnet, FTP, unencrypted HTTP)
- **Firmware Status**: Detects EOL firmware and outdated versions

### Risk Scoring Algorithm
- Base score calculated from vulnerability severity (Critical: 40, High: 25, Medium: 15, Low: 5)
- Bonus points for multiple vulnerabilities
- Risk categories: Critical (≥70), High (≥40), Medium (≥20), Low (<20)

### Simulated Remediation
- **Password Generation**: Creates strong random passwords based on policy
- **Port Closure**: Simulates closing risky ports
- **Firmware Warnings**: Provides recommendations for EOL devices (requires vendor support)

## Limitations (MVP)

- **Simulation Mode**: All fixes are simulated - no actual device modifications
- **No Real Firmware Updates**: EOL firmware warnings only, no automatic updates
- **Local Network Only**: Scans local subnet only, no cloud integration
- **No Vendor Integration**: No direct API connections to device manufacturers

## Security & Privacy

- **Fully Offline**: No data sent to external servers
- **Local Storage**: All data stored locally in `data/` directory
- **No Credential Storage**: Generated passwords shown in UI only (not saved to disk)
- **Export Encryption**: Consider encrypting exported CSV files for sensitive environments

## Troubleshooting

### Port Scanning Issues
- Ensure you have network access to the target subnet
- Some firewalls may block port scans
- Use Simulation Mode for demos if network access is restricted

### Import Errors
- Verify all dependencies are installed: `pip install -r requirements.txt`
- Check Python version: `python --version` (should be 3.9+)

### Streamlit Not Starting
- Check if port 8501 is already in use
- Try: `streamlit run app.py --server.port 8502`

## Development Roadmap

- [ ] Real device credential testing (with proper authorization)
- [ ] Integration with vendor APIs for firmware updates
- [ ] Advanced vulnerability database (CVE integration)
- [ ] Scheduled scanning and automated alerts
- [ ] Multi-user support with authentication
- [ ] Dark/light theme toggle (Streamlit native)

## Disclaimer

**Use responsibly and only scan devices you own or have permission to assess.** Unauthorized network scanning or device modification may be illegal and violate terms of service. This tool is for educational and authorized security testing purposes only.

## License

See LICENSE file for details.

---

*For detailed software requirements and development roadmap, see the Software Requirements Specification (SRS) document.*
