# Software Requirements Specification (SRS) for IoT Risk Defender Platform

## 1. Introduction

### 1.1 Purpose of the Document
This Software Requirements Specification (SRS) outlines the functional and non-functional requirements for the IoT Risk Defender Platform. It serves as a foundational document for understanding the system's capabilities, design, and implementation, and is intended to guide development, testing, and stakeholder communication.

### 1.2 Scope of the Project
The IoT Risk Defender Platform is a lightweight, Streamlit-based web application designed to identify, assess, and simulate remediation of security vulnerabilities in IoT devices on a local network. It focuses on rapid prototyping and demonstration of risk-based security principles for vulnerable IoT devices.

### 1.3 Target Audience
This document is intended for project stakeholders, developers, testers, product managers, and anyone interested in understanding the technical and functional aspects of the IoT Risk Defender Platform.

## 2. Overall Description

### 2.1 Product Vision
The IoT Risk Defender Platform aims to provide a rapid, interactive, and intuitive tool for individuals and organizations to assess the security posture of their IoT devices. By prioritizing remediation efforts based on calculated risk scores and offering simulated fixes, it educates users on common IoT vulnerabilities and their mitigation, serving as an excellent hackathon demo or rapid prototyping solution.

### 2.2 Key Features
*   **Multi-Vulnerability Scanner**: Scans local subnets for IoT devices and detects common vulnerabilities (default/weak credentials, risky open ports, outdated firmware).
*   **Risk-Based Prioritization**: Calculates deterministic risk scores (0-100) for devices and categorizes them (Critical, High, Medium, Low) to prioritize remediation efforts.
*   **Simulated Remediation Actions**: Offers one-click simulated fixes, including generating strong passwords, closing risky ports, and simulating firmware updates.
*   **Lifecycle Security Warnings**: Identifies devices with End-of-Life (EOL) or outdated firmware.
*   **User-Definable Security Policies**: Allows customization of password complexity, allowed network ports, and risk score thresholds.
*   **Interactive Dashboard**: Provides real-time alerts, summary statistics, device overviews, and detailed vulnerability views with charts and metrics.
*   **Extensible Device Management**: Enables adding, editing, and removing fake IoT devices for testing and demonstration purposes.
*   **Data Export**: Supports exporting device inventory and remediation logs to CSV format.
*   **Session Persistence**: Saves and loads the application state across browser refreshes.

### 2.3 User Classes and Characteristics
*   **Security Enthusiasts/Students**: Interested in learning about IoT security, vulnerabilities, and remediation techniques.
*   **Developers/Prototypers**: Utilizing the platform for rapid prototyping or demonstrating IoT security concepts.
*   **Small Business/Home Users**: Seeking a basic understanding and assessment of their local IoT device security.

### 2.4 Operating Environment
*   **Operating System**: Windows 11 (or any OS supporting Python and Streamlit).
*   **Python Version**: Python 3.9 or higher.
*   **Network**: Requires network access to the local subnet for real device scanning (or operates in a simulation mode).
*   **Browser**: Modern web browser for accessing the Streamlit application.

### 2.5 Assumptions and Dependencies
*   Python 3.9+ and pip are installed.
*   Required Python libraries (`requirements.txt`) are installed.
*   User has basic networking knowledge for subnet configuration.
*   Simulated fixes do not make actual changes to physical devices.
*   Data is stored locally; no cloud integration.

## 3. Specific Requirements

### 3.1 Functional Requirements

#### 3.1.1 Network Scanning
*   **REQ-SCAN-001**: The system SHALL allow users to input a subnet (e.g., `192.168.1.0/24`) or a single IP address for scanning.
*   **REQ-SCAN-002**: The system SHALL provide a "Realistic Simulation Mode" to use a deterministic dataset of IoT devices for demonstration.
*   **REQ-SCAN-003**: The system SHALL provide a "Real Device Scan Mode" to scan actual devices on the local network.
*   **REQ-SCAN-004**: The system SHALL discover devices and their open ports during a scan.
*   **REQ-SCAN-005**: The system SHALL attempt to retrieve basic device information (e.g., HTTP server banners, hostnames) during a scan.

#### 3.1.2 Vulnerability Detection & Risk Scoring
*   **REQ-VULN-001**: The system SHALL analyze discovered devices for common vulnerabilities including:
    *   Default/weak credentials
    *   Risky open ports (e.g., Telnet, FTP, unencrypted HTTP)
    *   Outdated or End-of-Life (EOL) firmware
    *   Simulated CVEs (for simulated devices)
*   **REQ-VULN-002**: The system SHALL calculate a deterministic risk score (0-100) for each analyzed device based on identified vulnerabilities and device type.
*   **REQ-VULN-003**: The system SHALL categorize devices into risk levels (Critical, High, Medium, Low) based on policy-defined thresholds.
*   **REQ-VULN-004**: The system SHALL provide a human-readable explanation of why a device received a particular risk score.

#### 3.1.3 Remediation (Simulated)
*   **REQ-REM-001**: The system SHALL offer simulated one-click fixes for detected vulnerabilities.
*   **REQ-REM-002**: The system SHALL simulate fixing default credentials by generating a strong password (displayed to the user).
*   **REQ-REM-003**: The system SHALL simulate closing risky ports.
*   **REQ-REM-004**: The system SHALL simulate updating firmware to the current year.
*   **REQ-REM-005**: The system SHALL allow applying all available fixes for a single device with one action.
*   **REQ-REM-006**: The system SHALL allow applying fixes to all Critical devices with one action.
*   **REQ-REM-007**: The system SHALL log all remediation actions with timestamps and details.

#### 3.1.4 Device Management
*   **REQ-DEV-001**: The system SHALL allow users to set up new custom IoT devices with configurable IP, hostname, ports, device type, manufacturer, firmware details, and default credential status.
*   **REQ-DEV-002**: The system SHALL store user-defined devices persistently.
*   **REQ-DEV-003**: The system SHALL merge user-defined devices with discovered devices during a scan.
*   **REQ-DEV-004**: The system SHALL allow restoring the original default vulnerable device dataset.

#### 3.1.5 Security Policy Management
*   **REQ-POL-001**: The system SHALL allow users to define and customize security policies, including:
    *   Minimum password length and required characters.
    *   A list of allowed open ports.
    *   Risk score thresholds for Critical, High, and Medium categories.
*   **REQ-POL-002**: The system SHALL validate user-defined policies for correctness (e.g., valid port numbers, password length).
*   **REQ-POL-003**: The system SHALL persist security policies across sessions.
*   **REQ-POL-004**: The system SHALL dynamically recalculate risk scores based on updated policies.

#### 3.1.6 Dashboard & Reporting
*   **REQ-DASH-001**: The system SHALL display a main dashboard summarizing:
    *   Total devices, critical/high/medium/low risk counts.
    *   Total number of vulnerabilities.
    *   Average risk score.
    *   Overall security posture score.
*   **REQ-DASH-002**: The system SHALL visualize risk distribution and vulnerability types using interactive charts.
*   **REQ-DASH-003**: The system SHALL list top vulnerable devices.
*   **REQ-DASH-004**: The system SHALL display a complete device inventory table, color-coded by risk category.
*   **REQ-DASH-005**: The system SHALL provide a detailed view for individual devices, showing all discovered information and vulnerabilities.
*   **REQ-DASH-006**: The system SHALL display remediation logs.
*   **REQ-DASH-007**: The system SHALL allow exporting device inventory and remediation logs to CSV files.

#### 3.1.7 Session Management
*   **REQ-SESS-001**: The system SHALL save the current state of scanned devices and applied policies to ensure persistence across browser refreshes.
*   **REQ-SESS-002**: The system SHALL load the saved session state upon application startup.

### 3.2 Non-Functional Requirements

#### 3.2.1 Performance
*   **NFR-PERF-001**: The system SHALL complete a simulated network scan for 10-15 devices within 5 seconds.
*   **NFR-PERF-002**: The system SHALL update the dashboard and device details view within 2 seconds after a scan or remediation action.

#### 3.2.2 Security
*   **NFR-SEC-001**: The system SHALL operate entirely offline; no data will be transmitted to external servers.
*   **NFR-SEC-002**: All data (devices, policies, session state) SHALL be stored locally in designated data files.
*   **NFR-SEC-003**: Generated passwords for simulated credential fixes SHALL be displayed in the UI only and NOT persistently stored.

#### 3.2.3 Usability (UI/UX)
*   **NFR-USAB-001**: The user interface SHALL be intuitive and easy to navigate for users with basic technical understanding.
*   **NFR-USAB-002**: The application SHALL provide clear feedback to the user on ongoing operations (e.g., "Scanning network...", "Applying fixes...").
*   **NFR-USAB-003**: The UI SHALL incorporate a dark, cybersecurity-themed purple color scheme.

#### 3.2.4 Maintainability
*   **NFR-MAINT-001**: The codebase SHALL be modular, with clear separation of concerns for scanning, analysis, remediation, and UI.
*   **NFR-MAINT-002**: The code SHALL adhere to Python best practices (e.g., PEP 8).

#### 3.2.5 Scalability (Limitations)
*   **NFR-SCAL-001**: The system is designed for local network scanning and is not intended for large-scale enterprise deployments or cloud integration.
*   **NFR-SCAL-002**: The real device scan mode's performance may degrade with a high number of concurrent workers or large subnets due to network latency and firewall restrictions.

## 4. Technical Architecture (High-Level)

### 4.1 Technology Stack
*   **Frontend/UI**: Streamlit (Python web framework)
*   **Backend/Logic**: Python 3.9+
*   **Data Visualization**: Plotly Express
*   **Networking**: `socket` module (for port scanning), `requests` library (for HTTP checks)
*   **IP Address Handling**: `ipaddress` module
*   **Concurrency**: `concurrent.futures.ThreadPoolExecutor`
*   **Data Storage**: JSON files for devices, policies, and session state.

### 4.2 Module Breakdown and Responsibilities
*   **`app.py`**: Main Streamlit application, UI orchestration, session state management.
*   **`scanner.py`**: Network discovery (real/simulated), port scanning, basic service identification.
*   **`vulnerability.py`**: High-level vulnerability analysis, integration with risk engine.
*   **`risk_engine.py`**: Core deterministic risk scoring logic, rule-based vulnerability assessment.
*   **`remediation.py`**: Wrapper for simulated fix actions, integrates with `fix_engine.py`.
*   **`fix_engine.py`**: Implements the logic for simulated fixes (credentials, ports, firmware), manages fix history.
*   **`device_manager.py`**: Manages user-defined/custom IoT devices, persistence to `data/devices.json`.
*   **`policy.py`**: Manages security policies, persistence to `data/policy.json`, policy validation.
*   **`iot_simulator.py`**: Provides a deterministic dataset of simulated IoT devices, manages `data/iot_vulnerable_devices.json`.
*   **`session_manager.py`**: Saves and loads the overall application session state (`data/session_state.json`).
*   **`utils.py`**: General utility functions (password generation, CSV export, JSON file handling).

### 4.3 Data Storage
*   **`data/iot_vulnerable_devices.json`**: Stores the default or modified simulated IoT device dataset.
*   **`data/devices.json`**: Stores user-added custom IoT devices.
*   **`data/policy.json`**: Stores the user-defined security policy.
*   **`data/session_state.json`**: Stores the application's runtime state (e.g., scanned devices, active policy).
*   **`exports/` directory**: Stores exported CSV reports (device inventory, remediation logs).
