"""
Deterministic IoT Device Simulation Engine
Provides realistic IoT device dataset with static, rule-based properties
"""
import json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime


# Realistic IoT device dataset - completely static, no randomness
DEFAULT_DEVICES = [
    {
        "device_id": "cam_001",
        "device_type": "camera",
        "ip": "192.168.1.101",
        "hostname": "Hikvision-IPC-001",
        "open_ports": [80, 554, 8000],
        "default_creds": True,
        "last_update_year": 2018,
        "services": {
            "rtsp": True,
            "http_admin": True,
            "telnet": False,
            "ssh": False
        },
        "manufacturer": "Hikvision",
        "model": "DS-2CD2142FWD-I",
        "firmware_version": "V5.4.5",
        "simulated_cves": [
            {"cve_id": "CVE-2017-7921", "severity": "high", "description": "Authentication bypass"},
            {"cve_id": "CVE-2016-6261", "severity": "medium", "description": "Command injection"},
            {"cve_id": "CVE-2015-3629", "severity": "low", "description": "Information disclosure"}
        ],
        "banner": "Server: Hikvision-Webs/3.0"
    },
    {
        "device_id": "router_001",
        "device_type": "router",
        "ip": "192.168.1.1",
        "hostname": "TP-Link-AC1750",
        "open_ports": [80, 443, 23],
        "default_creds": True,
        "last_update_year": 2019,
        "services": {
            "rtsp": False,
            "http_admin": True,
            "telnet": True,
            "ssh": False
        },
        "manufacturer": "TP-Link",
        "model": "Archer C7",
        "firmware_version": "3.15.1",
        "simulated_cves": [
            {"cve_id": "CVE-2020-12116", "severity": "high", "description": "Remote code execution"},
            {"cve_id": "CVE-2019-13316", "severity": "medium", "description": "Authentication bypass"}
        ],
        "banner": "Server: TP-Link Router HTTP Server"
    },
    {
        "device_id": "plug_001",
        "device_type": "plug",
        "ip": "192.168.1.102",
        "hostname": "TP-Link-SmartPlug",
        "open_ports": [80, 9999],
        "default_creds": True,
        "last_update_year": 2020,
        "services": {
            "rtsp": False,
            "http_admin": True,
            "telnet": False,
            "ssh": False
        },
        "manufacturer": "TP-Link",
        "model": "HS110",
        "firmware_version": "1.2.8",
        "simulated_cves": [
            {"cve_id": "CVE-2020-12116", "severity": "medium", "description": "Command injection"},
            {"cve_id": "CVE-2019-7398", "severity": "low", "description": "Information disclosure"}
        ],
        "banner": "Server: TP-Link Smart Plug"
    },
    {
        "device_id": "cam_002",
        "device_type": "camera",
        "ip": "192.168.1.103",
        "hostname": "Dahua-IPC-002",
        "open_ports": [80, 554, 37777],
        "default_creds": False,
        "last_update_year": 2021,
        "services": {
            "rtsp": True,
            "http_admin": True,
            "telnet": False,
            "ssh": False
        },
        "manufacturer": "Dahua",
        "model": "IPC-HDW2431T",
        "firmware_version": "2.800.0000.28.R",
        "simulated_cves": [
            {"cve_id": "CVE-2021-44228", "severity": "high", "description": "Log4j vulnerability"},
            {"cve_id": "CVE-2020-25078", "severity": "medium", "description": "Command injection"}
        ],
        "banner": "Server: Dahua-Webs/3.0"
    },
    {
        "device_id": "router_002",
        "device_type": "router",
        "ip": "192.168.1.104",
        "hostname": "Netgear-R7000",
        "open_ports": [80, 443],
        "default_creds": False,
        "last_update_year": 2022,
        "services": {
            "rtsp": False,
            "http_admin": True,
            "telnet": False,
            "ssh": True
        },
        "manufacturer": "Netgear",
        "model": "R7000",
        "firmware_version": "1.0.11.130",
        "simulated_cves": [
            {"cve_id": "CVE-2021-45046", "severity": "medium", "description": "Authentication bypass"}
        ],
        "banner": "Server: Netgear HTTP Server"
    },
    {
        "device_id": "sensor_001",
        "device_type": "sensor",
        "ip": "192.168.1.105",
        "hostname": "ESP8266-Sensor",
        "open_ports": [80, 23],
        "default_creds": True,
        "last_update_year": 2017,
        "services": {
            "rtsp": False,
            "http_admin": True,
            "telnet": True,
            "ssh": False
        },
        "manufacturer": "Espressif",
        "model": "ESP8266",
        "firmware_version": "1.0.0",
        "simulated_cves": [
            {"cve_id": "CVE-2017-17215", "severity": "high", "description": "Remote code execution"},
            {"cve_id": "CVE-2016-10372", "severity": "medium", "description": "Buffer overflow"}
        ],
        "banner": "Server: ESP8266 WebServer"
    },
    {
        "device_id": "cam_003",
        "device_type": "camera",
        "ip": "192.168.1.106",
        "hostname": "Foscam-FI9821P",
        "open_ports": [80, 554, 88],
        "default_creds": True,
        "last_update_year": 2016,
        "services": {
            "rtsp": True,
            "http_admin": True,
            "telnet": False,
            "ssh": False
        },
        "manufacturer": "Foscam",
        "model": "FI9821P",
        "firmware_version": "2.21.1.128",
        "simulated_cves": [
            {"cve_id": "CVE-2017-5674", "severity": "critical", "description": "Remote code execution"},
            {"cve_id": "CVE-2016-5673", "severity": "high", "description": "Authentication bypass"},
            {"cve_id": "CVE-2015-5672", "severity": "medium", "description": "Command injection"}
        ],
        "banner": "Server: Foscam-Webs/2.0"
    },
    {
        "device_id": "bulb_001",
        "device_type": "bulb",
        "ip": "192.168.1.107",
        "hostname": "Philips-Hue-Bulb",
        "open_ports": [80],
        "default_creds": False,
        "last_update_year": 2023,
        "services": {
            "rtsp": False,
            "http_admin": True,
            "telnet": False,
            "ssh": False
        },
        "manufacturer": "Philips",
        "model": "Hue White",
        "firmware_version": "1.88.2",
        "simulated_cves": [],
        "banner": "Server: Philips Hue Bridge"
    },
    {
        "device_id": "router_003",
        "device_type": "router",
        "ip": "192.168.1.108",
        "hostname": "Linksys-EA7500",
        "open_ports": [80, 443, 23, 21],
        "default_creds": True,
        "last_update_year": 2018,
        "services": {
            "rtsp": False,
            "http_admin": True,
            "telnet": True,
            "ssh": False,
            "ftp": True
        },
        "manufacturer": "Linksys",
        "model": "EA7500",
        "firmware_version": "1.1.10.200080",
        "simulated_cves": [
            {"cve_id": "CVE-2019-13316", "severity": "high", "description": "Remote code execution"},
            {"cve_id": "CVE-2018-13315", "severity": "medium", "description": "Command injection"},
            {"cve_id": "CVE-2017-13314", "severity": "low", "description": "Information disclosure"}
        ],
        "banner": "Server: Linksys HTTP Server"
    },
    {
        "device_id": "cam_004",
        "device_type": "camera",
        "ip": "192.168.1.109",
        "hostname": "Axis-M3046-V",
        "open_ports": [80, 443, 554],
        "default_creds": False,
        "last_update_year": 2022,
        "services": {
            "rtsp": True,
            "http_admin": True,
            "telnet": False,
            "ssh": True
        },
        "manufacturer": "Axis",
        "model": "M3046-V",
        "firmware_version": "9.80.3.5",
        "simulated_cves": [
            {"cve_id": "CVE-2022-30571", "severity": "medium", "description": "Authentication bypass"}
        ],
        "banner": "Server: Axis Network Camera"
    },
    {
        "device_id": "plug_002",
        "device_type": "plug",
        "ip": "192.168.1.110",
        "hostname": "Wemo-SmartPlug",
        "open_ports": [49153],
        "default_creds": False,
        "last_update_year": 2021,
        "services": {
            "rtsp": False,
            "http_admin": False,
            "telnet": False,
            "ssh": False,
            "upnp": True
        },
        "manufacturer": "Belkin",
        "model": "Wemo Insight",
        "firmware_version": "WeMo_WW_2.00.11408.PVT-OWRT-SNS",
        "simulated_cves": [
            {"cve_id": "CVE-2020-12695", "severity": "high", "description": "UPnP vulnerability"},
            {"cve_id": "CVE-2019-12694", "severity": "medium", "description": "Command injection"}
        ],
        "banner": "Server: Unspecified, no response"
    },
    {
        "device_id": "thermostat_001",
        "device_type": "thermostat",
        "ip": "192.168.1.111",
        "hostname": "Nest-Thermostat",
        "open_ports": [80, 443],
        "default_creds": False,
        "last_update_year": 2023,
        "services": {
            "rtsp": False,
            "http_admin": True,
            "telnet": False,
            "ssh": False
        },
        "manufacturer": "Google",
        "model": "Nest Learning",
        "firmware_version": "6.2-6",
        "simulated_cves": [],
        "banner": "Server: Nest Thermostat"
    },
    {
        "device_id": "cam_005",
        "device_type": "camera",
        "ip": "192.168.1.112",
        "hostname": "Reolink-RLC-410",
        "open_ports": [80, 554, 8000],
        "default_creds": True,
        "last_update_year": 2019,
        "services": {
            "rtsp": True,
            "http_admin": True,
            "telnet": False,
            "ssh": False
        },
        "manufacturer": "Reolink",
        "model": "RLC-410",
        "firmware_version": "v2.0.0.494_20190516",
        "simulated_cves": [
            {"cve_id": "CVE-2019-19824", "severity": "high", "description": "Authentication bypass"},
            {"cve_id": "CVE-2018-19823", "severity": "medium", "description": "Command injection"}
        ],
        "banner": "Server: Reolink-Webs/1.0"
    },
    {
        "device_id": "router_004",
        "device_type": "router",
        "ip": "192.168.1.113",
        "hostname": "ASUS-RT-AC68U",
        "open_ports": [80, 443, 22],
        "default_creds": False,
        "last_update_year": 2021,
        "services": {
            "rtsp": False,
            "http_admin": True,
            "telnet": False,
            "ssh": True
        },
        "manufacturer": "ASUS",
        "model": "RT-AC68U",
        "firmware_version": "3.0.0.4.386.41634",
        "simulated_cves": [
            {"cve_id": "CVE-2021-32030", "severity": "medium", "description": "Authentication bypass"}
        ],
        "banner": "Server: ASUS Router HTTP Server"
    },
    {
        "device_id": "doorbell_001",
        "device_type": "doorbell",
        "ip": "192.168.1.114",
        "hostname": "Ring-Doorbell",
        "open_ports": [80, 443],
        "default_creds": False,
        "last_update_year": 2022,
        "services": {
            "rtsp": False,
            "http_admin": True,
            "telnet": False,
            "ssh": False
        },
        "manufacturer": "Ring",
        "model": "Video Doorbell Pro",
        "firmware_version": "1.9.8",
        "simulated_cves": [
            {"cve_id": "CVE-2022-32784", "severity": "low", "description": "Information disclosure"}
        ],
        "banner": "Server: Ring Device"
    },
    {
        "device_id": "cam_006",
        "device_type": "camera",
        "ip": "192.168.1.115",
        "hostname": "Wyze-Cam-Pan",
        "open_ports": [80, 554],
        "default_creds": True,
        "last_update_year": 2020,
        "services": {
            "rtsp": True,
            "http_admin": True,
            "telnet": False,
            "ssh": False
        },
        "manufacturer": "Wyze",
        "model": "Cam Pan",
        "firmware_version": "4.10.8.1002",
        "simulated_cves": [
            {"cve_id": "CVE-2020-27870", "severity": "high", "description": "Authentication bypass"},
            {"cve_id": "CVE-2019-27869", "severity": "medium", "description": "Command injection"}
        ],
        "banner": "Server: Wyze-Webs/1.0"
    }
]


def get_data_dir() -> Path:
    """Get or create data directory."""
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    return data_dir


def load_simulated_devices() -> List[Dict]:
    """Load simulated devices from JSON file or return defaults."""
    # Try to load from editable vulnerable devices dataset first
    vulnerable_devices_file = get_data_dir() / "iot_vulnerable_devices.json"
    if vulnerable_devices_file.exists():
        try:
            with open(vulnerable_devices_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                devices = data.get('devices', [])
                if devices:
                    return devices
        except Exception:
            pass  # Fall through to default
    
    # Fallback to simulated_devices.json
    devices_file = get_data_dir() / "simulated_devices.json"
    if devices_file.exists():
        try:
            with open(devices_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                devices = data.get('devices', [])
                if devices:
                    return devices
        except Exception:
            pass  # Fall through to default
    
    # Save defaults to both files
    save_simulated_devices(DEFAULT_DEVICES)
    # Also save to vulnerable devices file
    try:
        vulnerable_data = {
            'description': 'Real IoT Vulnerable Device Dataset',
            'version': '1.0',
            'last_updated': datetime.now().isoformat(),
            'devices': DEFAULT_DEVICES
        }
        with open(vulnerable_devices_file, 'w', encoding='utf-8') as f:
            json.dump(vulnerable_data, f, indent=2, ensure_ascii=False)
    except Exception:
        pass
    
    return DEFAULT_DEVICES


def save_simulated_devices(devices: List[Dict], target_file: str = None) -> None:
    """Save simulated devices to JSON file. Saves to iot_vulnerable_devices.json by default."""
    data_dir = get_data_dir()
    
    # Determine which file to save to
    if target_file is None:
        # Default to vulnerable devices file (primary dataset)
        devices_file = data_dir / "iot_vulnerable_devices.json"
    else:
        devices_file = data_dir / target_file
    
    # Save with proper structure
    if devices_file.name == "iot_vulnerable_devices.json":
        data = {
            'description': 'Real IoT Vulnerable Device Dataset - Editable configuration file',
            'version': '1.0',
            'last_updated': datetime.now().isoformat(),
            'devices': devices
        }
    else:
        data = {'devices': devices, 'last_updated': datetime.now().isoformat()}
    
    with open(devices_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def get_device_by_ip(ip: str) -> Optional[Dict]:
    """Get a device by IP address."""
    devices = load_simulated_devices()
    for device in devices:
        if device.get('ip') == ip:
            return device.copy()  # Return copy to avoid mutations
    return None


def get_all_devices() -> List[Dict]:
    """Get all simulated devices."""
    return load_simulated_devices()


def update_device(ip: str, updates: Dict) -> bool:
    """Update a device's properties. Returns True if device was found and updated."""
    data_dir = get_data_dir()
    
    # Try to update in vulnerable devices file first (primary dataset)
    vulnerable_file = data_dir / "iot_vulnerable_devices.json"
    if vulnerable_file.exists():
        try:
            with open(vulnerable_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                devices = data.get('devices', [])
                
                for device in devices:
                    if device.get('ip') == ip:
                        device.update(updates)
                        data['devices'] = devices
                        data['last_updated'] = datetime.now().isoformat()
                        with open(vulnerable_file, 'w', encoding='utf-8') as f:
                            json.dump(data, f, indent=2, ensure_ascii=False)
                        return True
        except Exception:
            pass
    
    # Fallback to simulated_devices.json
    devices_file = data_dir / "simulated_devices.json"
    if devices_file.exists():
        try:
            with open(devices_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                devices = data.get('devices', [])
                
                for device in devices:
                    if device.get('ip') == ip:
                        device.update(updates)
                        data['devices'] = devices
                        data['last_updated'] = datetime.now().isoformat()
                        with open(devices_file, 'w', encoding='utf-8') as f:
                            json.dump(data, f, indent=2, ensure_ascii=False)
                        return True
        except Exception:
            pass
    
    # If file doesn't exist, load from defaults and save
    devices = load_simulated_devices()
    for device in devices:
        if device.get('ip') == ip:
            device.update(updates)
            save_simulated_devices(devices)  # Will save to vulnerable_devices.json
            return True
    
    return False


def convert_to_scan_format(device: Dict) -> Dict:
    """Convert simulator device format to scanner format."""
    return {
        'ip': device.get('ip'),
        'hostname': device.get('hostname', 'Unknown'),
        'open_ports': device.get('open_ports', []),
        'device_info': {
            'server': device.get('banner', 'Unknown'),
            'manufacturer': device.get('manufacturer'),
            'model': device.get('model')
        },
        'simulator_data': device  # Keep full device data for risk engine
    }

