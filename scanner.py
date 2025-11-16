"""
Network scanner for IoT device discovery
"""
import socket
import ipaddress
import requests
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


# Common ports to scan for IoT devices
COMMON_IOT_PORTS = [22, 23, 80, 443, 554, 8080, 8443, 8888, 9000]


def scan_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a port is open on the given IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def check_http_service(ip: str, port: int = 80, timeout: float = 2.0) -> Optional[Dict]:
    """Check if HTTP service is running and try to get device info."""
    try:
        url = f"http://{ip}:{port}"
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        headers = dict(response.headers)
        
        # Try to extract device info from headers
        server = headers.get('Server', 'Unknown')
        return {
            'status_code': response.status_code,
            'server': server,
            'title': extract_title(response.text) if response.text else None
        }
    except Exception:
        return None


def extract_title(html: str) -> Optional[str]:
    """Extract title from HTML."""
    try:
        start = html.find('<title>')
        end = html.find('</title>')
        if start != -1 and end != -1:
            return html[start+7:end].strip()
    except Exception:
        pass
    return None


def discover_device(ip: str, ports: List[int] = None) -> Optional[Dict]:
    """Discover a single device and its open ports."""
    if ports is None:
        ports = COMMON_IOT_PORTS
    
    open_ports = []
    device_info = None
    
    # Quick port scan
    for port in ports:
        if scan_port(ip, port, timeout=0.5):
            open_ports.append(port)
            
            # Try to get HTTP info if port 80 or 8080 is open
            if port in [80, 8080] and device_info is None:
                device_info = check_http_service(ip, port)
    
    if open_ports:
        return {
            'ip': ip,
            'open_ports': open_ports,
            'device_info': device_info,
            'hostname': get_hostname(ip)
        }
    return None


def get_hostname(ip: str) -> Optional[str]:
    """Try to get hostname for IP."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return None


def scan_subnet(subnet: str, max_workers: int = 50) -> List[Dict]:
    """
    Scan a subnet for IoT devices.
    
    Args:
        subnet: CIDR notation (e.g., '192.168.1.0/24') or single IP
        max_workers: Maximum concurrent threads
    
    Returns:
        List of discovered devices
    """
    devices = []
    
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        ip_list = [str(ip) for ip in network.hosts()]
    except ValueError:
        # Single IP address
        ip_list = [subnet]
    
    # Limit scan size for performance
    if len(ip_list) > 254:
        ip_list = ip_list[:254]
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(discover_device, ip): ip for ip in ip_list}
        
        for future in as_completed(future_to_ip):
            try:
                device = future.result()
                if device:
                    devices.append(device)
            except Exception:
                pass
    
    return devices


def simulate_scan(subnet: str, use_realistic: bool = True) -> List[Dict]:
    """
    Simulate a scan using deterministic IoT simulator.
    
    Args:
        subnet: Subnet to scan (used for IP assignment)
        use_realistic: If True, use realistic device dataset; if False, use old random method
    
    Returns:
        List of discovered devices in scanner format
    """
    if use_realistic:
        # Use deterministic IoT simulator
        from iot_simulator import get_all_devices, convert_to_scan_format
        
        all_devices = get_all_devices()
        # Filter devices that match the subnet (if provided)
        base_ip = subnet.split('/')[0].rsplit('.', 1)[0] if '/' in subnet else subnet.rsplit('.', 1)[0]
        
        # Return devices that match the subnet base
        matching_devices = []
        for device in all_devices:
            device_ip_base = device['ip'].rsplit('.', 1)[0]
            if device_ip_base == base_ip:
                matching_devices.append(convert_to_scan_format(device))
        
        # If no matches, return first 5-8 devices (deterministic)
        if not matching_devices:
            matching_devices = [convert_to_scan_format(d) for d in all_devices[:8]]
        
        return matching_devices
    else:
        # Legacy random method (for backward compatibility)
        import random
        
        fake_devices = []
        base_ip = subnet.split('/')[0].rsplit('.', 1)[0]
        
        device_templates = [
            {'ports': [80, 443], 'hostname': 'IP-Camera-01', 'device_info': {'server': 'IPCam/1.0'}},
            {'ports': [22, 80], 'hostname': 'Smart-Router', 'device_info': {'server': 'RouterOS/6.0'}},
            {'ports': [8080], 'hostname': 'Smart-Plug-01', 'device_info': {'server': 'ESP8266'}},
            {'ports': [80, 554], 'hostname': 'Security-Camera', 'device_info': {'server': 'Hikvision'}},
            {'ports': [23, 80], 'hostname': 'IoT-Sensor', 'device_info': {'server': 'Arduino'}},
        ]
        
        num_devices = random.randint(2, 5)
        used_ips = set()
        
        for i in range(num_devices):
            template = random.choice(device_templates)
            last_octet = random.randint(10, 200)
            while last_octet in used_ips:
                last_octet = random.randint(10, 200)
            used_ips.add(last_octet)
            
            ip = f"{base_ip}.{last_octet}"
            fake_devices.append({
                'ip': ip,
                'open_ports': template['ports'],
                'hostname': template['hostname'],
                'device_info': template['device_info']
            })
        
        return fake_devices

