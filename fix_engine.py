"""
Deterministic Fix Engine
Applies fixes and recalculates risk - completely rule-based
"""
from typing import Dict, List, Optional
from datetime import datetime
from iot_simulator import update_device, get_device_by_ip
from device_manager import get_device_by_ip as get_managed_device, update_device as update_managed_device, load_devices
from risk_engine import calculate_risk_score


class FixEngine:
    """Handles deterministic device fixes."""
    
    def __init__(self):
        self.fix_history = []
    
    def _get_device(self, device_ip: str) -> Optional[Dict]:
        """Get device from simulator or managed devices."""
        # Try simulator first
        device = get_device_by_ip(device_ip)
        if device:
            return device
        
        # Try managed devices
        device = get_managed_device(device_ip)
        if device:
            return device
        
        return None
    
    def _update_device(self, device_ip: str, updates: Dict) -> bool:
        """Update device in simulator or managed devices."""
        # Try simulator first
        if get_device_by_ip(device_ip):
            return update_device(device_ip, updates)
        
        # Try managed devices
        result = update_managed_device(device_ip, updates)
        return result.get('success', False)
    
    def fix_default_credentials(self, device_ip: str, policy: Dict) -> Dict:
        """
        Fix default credentials by setting default_creds to False.
        Returns updated device state and new risk score.
        """
        device = self._get_device(device_ip)
        if not device:
            return {'success': False, 'message': f'Device {device_ip} not found'}
        
        # Apply fix
        updates = {'default_creds': False}
        success = self._update_device(device_ip, updates)
        
        if not success:
            return {'success': False, 'message': f'Failed to update device {device_ip}'}
        
        # Get updated device
        updated_device = self._get_device(device_ip)
        device_format = {
            'ip': updated_device['ip'],
            'hostname': updated_device.get('hostname', 'Unknown'),
            'open_ports': updated_device.get('open_ports', []),
            'simulator_data': updated_device
        }
        
        # Recalculate risk
        risk_result = calculate_risk_score(device_format, policy)
        
        fix_record = {
            'timestamp': datetime.now().isoformat(),
            'device_ip': device_ip,
            'action': 'fix_default_credentials',
            'status': 'success',
            'old_risk': self._get_old_risk(device, policy),
            'new_risk': risk_result['risk_score'],
            'details': {'default_creds': False}
        }
        
        self.fix_history.append(fix_record)
        
        return {
            'success': True,
            'message': 'Default credentials fixed - strong password set',
            'device': updated_device,
            'risk_result': risk_result,
            'fix_record': fix_record
        }
    
    def fix_port(self, device_ip: str, port: int, policy: Dict) -> Dict:
        """
        Disable a port by removing it from open_ports.
        Returns updated device state and new risk score.
        """
        device = self._get_device(device_ip)
        if not device:
            return {'success': False, 'message': f'Device {device_ip} not found'}
        
        # Remove port from open_ports
        open_ports = device.get('open_ports', []).copy()
        if port in open_ports:
            open_ports.remove(port)
        else:
            return {'success': False, 'message': f'Port {port} not found on device'}
        
        # Update services if applicable
        services = device.get('services', {}).copy()
        if port == 23:
            services['telnet'] = False
        elif port == 554:
            services['rtsp'] = False
        elif port == 21:
            services['ftp'] = False
        elif port in [80, 8080]:
            services['http_admin'] = False
        
        updates = {'open_ports': open_ports, 'services': services}
        success = self._update_device(device_ip, updates)
        
        if not success:
            return {'success': False, 'message': f'Failed to update device {device_ip}'}
        
        # Get updated device
        updated_device = self._get_device(device_ip)
        device_format = {
            'ip': updated_device['ip'],
            'hostname': updated_device.get('hostname', 'Unknown'),
            'open_ports': updated_device.get('open_ports', []),
            'simulator_data': updated_device
        }
        
        # Recalculate risk
        risk_result = calculate_risk_score(device_format, policy)
        
        fix_record = {
            'timestamp': datetime.now().isoformat(),
            'device_ip': device_ip,
            'action': f'close_port_{port}',
            'status': 'success',
            'old_risk': self._get_old_risk(device, policy),
            'new_risk': risk_result['risk_score'],
            'details': {'port': port, 'action': 'closed'}
        }
        
        self.fix_history.append(fix_record)
        
        return {
            'success': True,
            'message': f'Port {port} closed successfully',
            'device': updated_device,
            'risk_result': risk_result,
            'fix_record': fix_record
        }
    
    def fix_firmware(self, device_ip: str, policy: Dict) -> Dict:
        """
        Simulate firmware update by setting last_update_year to current year.
        Returns updated device state and new risk score.
        """
        device = self._get_device(device_ip)
        if not device:
            return {'success': False, 'message': f'Device {device_ip} not found'}
        
        current_year = datetime.now().year
        updates = {'last_update_year': current_year}
        success = self._update_device(device_ip, updates)
        
        if not success:
            return {'success': False, 'message': f'Failed to update device {device_ip}'}
        
        # Get updated device
        updated_device = self._get_device(device_ip)
        device_format = {
            'ip': updated_device['ip'],
            'hostname': updated_device.get('hostname', 'Unknown'),
            'open_ports': updated_device.get('open_ports', []),
            'simulator_data': updated_device
        }
        
        # Recalculate risk
        risk_result = calculate_risk_score(device_format, policy)
        
        fix_record = {
            'timestamp': datetime.now().isoformat(),
            'device_ip': device_ip,
            'action': 'update_firmware',
            'status': 'success',
            'old_risk': self._get_old_risk(device, policy),
            'new_risk': risk_result['risk_score'],
            'details': {'last_update_year': current_year}
        }
        
        self.fix_history.append(fix_record)
        
        return {
            'success': True,
            'message': f'Firmware updated to {current_year} (simulated)',
            'device': updated_device,
            'risk_result': risk_result,
            'fix_record': fix_record
        }
    
    def fix_all_vulnerabilities(self, device_ip: str, vulnerabilities: List[Dict], policy: Dict) -> Dict:
        """
        Apply all applicable fixes to a device.
        Returns summary of all fixes and final risk score.
        """
        device = self._get_device(device_ip)
        if not device:
            return {'success': False, 'message': f'Device {device_ip} not found'}
        
        old_risk = self._get_old_risk(device, policy)
        fixes_applied = []
        
        # Apply fixes based on vulnerability types
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', '')
            
            if vuln_type == 'default_credentials':
                result = self.fix_default_credentials(device_ip, policy)
                if result['success']:
                    fixes_applied.append('Default credentials fixed')
                    # Update device reference for next fix
                    device = result['device']
            
            elif vuln_type == 'risky_port':
                port = vuln.get('port')
                if port:
                    result = self.fix_port(device_ip, port, policy)
                    if result['success']:
                        fixes_applied.append(f'Port {port} closed')
                        device = result['device']
            
            elif vuln_type in ['eol_firmware', 'outdated_firmware']:
                result = self.fix_firmware(device_ip, policy)
                if result['success']:
                    fixes_applied.append('Firmware updated')
                    device = result['device']
        
        # Get final device state and risk
        final_device = self._get_device(device_ip)
        device_format = {
            'ip': final_device['ip'],
            'hostname': final_device.get('hostname', 'Unknown'),
            'open_ports': final_device.get('open_ports', []),
            'simulator_data': final_device
        }
        final_risk = calculate_risk_score(device_format, policy)
        
        return {
            'success': True,
            'message': f'Applied {len(fixes_applied)} fixes to device {device_ip}',
            'fixes_applied': fixes_applied,
            'old_risk': old_risk,
            'new_risk': final_risk['risk_score'],
            'risk_result': final_risk,
            'device': final_device
        }
    
    def _get_old_risk(self, device: Dict, policy: Dict) -> float:
        """Calculate risk before fix."""
        device_format = {
            'ip': device['ip'],
            'hostname': device.get('hostname', 'Unknown'),
            'open_ports': device.get('open_ports', []),
            'simulator_data': device
        }
        risk_result = calculate_risk_score(device_format, policy)
        return risk_result['risk_score']
    
    def get_fix_history(self, device_ip: Optional[str] = None) -> List[Dict]:
        """Get fix history, optionally filtered by device IP."""
        if device_ip:
            return [fix for fix in self.fix_history if fix['device_ip'] == device_ip]
        return self.fix_history.copy()


# Global fix engine instance
fix_engine = FixEngine()

