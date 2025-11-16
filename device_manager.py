"""
Device management for adding/editing/removing fake and real devices
"""
from typing import Dict, List, Optional
from pathlib import Path
from utils import load_json_file, save_json_file
import json


def get_devices_file() -> Path:
    """Get path to devices storage file."""
    data_dir = Path("data")
    return data_dir / "devices.json"


def load_devices() -> List[Dict]:
    """Load all managed devices."""
    devices_file = get_devices_file()
    data = load_json_file(str(devices_file))
    return data.get('devices', [])


def save_devices(devices: List[Dict]) -> None:
    """Save devices to storage."""
    devices_file = get_devices_file()
    data = {'devices': devices}
    save_json_file(data, str(devices_file))


def setup_new_device(device_data: Dict) -> Dict:
    """
    Setup a new IoT device with full structure compatible with simulator.
    
    Expected device_data structure:
    {
        'ip': str (required),
        'hostname': str (required),
        'device_type': str (camera|router|plug|sensor|bulb|thermostat|doorbell|other),
        'open_ports': List[int] (required),
        'manufacturer': str (optional),
        'model': str (optional),
        'firmware_version': str (optional),
        'default_creds': bool (default: False),
        'last_update_year': int (default: current year),
        'services': Dict (optional),
        'simulated_cves': List[Dict] (optional)
    }
    """
    from datetime import datetime
    from iot_simulator import get_device_by_ip
    
    # Check if device with same IP already exists in simulator
    if get_device_by_ip(device_data.get('ip')):
        return {'success': False, 'message': f'Device with IP {device_data.get("ip")} already exists in simulator'}
    
    # Check if device with same IP already exists in managed devices
    devices = load_devices()
    for existing in devices:
        if existing.get('ip') == device_data.get('ip'):
            return {'success': False, 'message': f'Device with IP {device_data.get("ip")} already exists'}
    
    # Build complete IoT device structure
    current_year = datetime.now().year
    device_type = device_data.get('device_type', 'other')
    open_ports = device_data.get('open_ports', [])
    
    # Infer services from ports
    services = device_data.get('services', {})
    if not services:
        services = {
            'rtsp': 554 in open_ports,
            'http_admin': 80 in open_ports or 8080 in open_ports,
            'telnet': 23 in open_ports,
            'ssh': 22 in open_ports,
            'ftp': 21 in open_ports
        }
    
    # Create full device structure
    new_device = {
        'device_id': f"{device_type}_{device_data.get('ip', '').replace('.', '_')}",
        'device_type': device_type,
        'ip': device_data.get('ip'),
        'hostname': device_data.get('hostname', 'Unknown'),
        'open_ports': open_ports,
        'default_creds': device_data.get('default_creds', False),
        'last_update_year': device_data.get('last_update_year', current_year),
        'services': services,
        'manufacturer': device_data.get('manufacturer', 'Unknown'),
        'model': device_data.get('model', 'Unknown'),
        'firmware_version': device_data.get('firmware_version', '1.0.0'),
        'simulated_cves': device_data.get('simulated_cves', []),
        'banner': device_data.get('banner', f"Server: {device_data.get('manufacturer', 'Unknown')} Device"),
        'is_managed': True,
        'created_at': datetime.now().isoformat()
    }
    
    devices.append(new_device)
    save_devices(devices)
    
    return {
        'success': True,
        'message': f'Device {new_device.get("ip")} ({new_device.get("hostname")}) setup successfully',
        'device': new_device
    }


def add_fake_device(device: Dict) -> Dict:
    """
    Legacy function - redirects to setup_new_device for backward compatibility.
    """
    # Convert old format to new format
    device_data = {
        'ip': device.get('ip'),
        'hostname': device.get('hostname', 'Unknown'),
        'device_type': 'other',
        'open_ports': device.get('open_ports', []),
        'manufacturer': device.get('device_info', {}).get('server', 'Unknown').split('/')[0] if device.get('device_info') else 'Unknown',
        'model': 'Custom Device',
        'firmware_version': '1.0.0',
        'default_creds': False,
        'banner': device.get('device_info', {}).get('server', 'Unknown Device') if device.get('device_info') else 'Unknown Device'
    }
    return setup_new_device(device_data)


def update_device(ip: str, updates: Dict) -> Dict:
    """Update an existing device."""
    devices = load_devices()
    
    for i, device in enumerate(devices):
        if device.get('ip') == ip:
            devices[i].update(updates)
            devices[i]['updated_at'] = __import__('datetime').datetime.now().isoformat()
            save_devices(devices)
            return {'success': True, 'message': f'Device {ip} updated successfully', 'device': devices[i]}
    
    return {'success': False, 'message': f'Device with IP {ip} not found'}


def remove_device(ip: str) -> Dict:
    """Remove a device."""
    devices = load_devices()
    
    original_count = len(devices)
    devices = [d for d in devices if d.get('ip') != ip]
    
    if len(devices) < original_count:
        save_devices(devices)
        return {'success': True, 'message': f'Device {ip} removed successfully'}
    
    return {'success': False, 'message': f'Device with IP {ip} not found'}


def get_device_by_ip(ip: str) -> Optional[Dict]:
    """Get a device by IP address."""
    devices = load_devices()
    for device in devices:
        if device.get('ip') == ip:
            return device
    return None


def merge_managed_devices(discovered_devices: List[Dict]) -> List[Dict]:
    """Merge discovered devices with managed devices."""
    from iot_simulator import convert_to_scan_format
    
    managed_devices = load_devices()
    discovered_ips = {d.get('ip') for d in discovered_devices}
    
    # Add managed devices that weren't discovered, converting to scanner format
    for managed in managed_devices:
        if managed.get('ip') not in discovered_ips:
            # Convert managed device to scanner format
            scanner_device = convert_to_scan_format(managed)
            discovered_devices.append(scanner_device)
    
    return discovered_devices

