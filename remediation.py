"""
Remediation wrapper - uses deterministic fix_engine
"""
from typing import Dict, List, Optional
from fix_engine import fix_engine
from utils import generate_strong_password


def fix_default_credentials(device_ip: str, username: str, policy: Dict) -> Dict:
    """
    Fix default credentials using deterministic fix engine.
    Returns updated device state and new risk score.
    """
    result = fix_engine.fix_default_credentials(device_ip, policy)
    
    if result['success']:
        # Generate password for display (not stored)
        password_length = policy.get('password_length', 16)
        include_special = policy.get('password_special_chars', True)
        new_password = generate_strong_password(password_length, include_special)
        
        result['new_password'] = new_password
        result['message'] = f'Password updated for user "{username}"'
    
    return result


def fix_risky_port(device_ip: str, port: int, policy: Dict = None) -> Dict:
    """
    Fix risky port using deterministic fix engine.
    Returns updated device state and new risk score.
    """
    if policy is None:
        from policy import load_policy
        policy = load_policy()
    
    return fix_engine.fix_port(device_ip, port, policy)


def fix_firmware(device_ip: str, policy: Dict = None) -> Dict:
    """
    Fix firmware using deterministic fix engine.
    Returns updated device state and new risk score.
    """
    if policy is None:
        from policy import load_policy
        policy = load_policy()
    
    return fix_engine.fix_firmware(device_ip, policy)


def fix_all_vulnerabilities(device_ip: str, vulnerabilities: List[Dict], policy: Dict) -> Dict:
    """
    Fix all vulnerabilities using deterministic fix engine.
    Returns summary with old/new risk scores.
    """
    result = fix_engine.fix_all_vulnerabilities(device_ip, vulnerabilities, policy)
    
    if result['success']:
        # Generate passwords for display if credentials were fixed
        credentials_generated = {}
        for vuln in vulnerabilities:
            if vuln['type'] == 'default_credentials':
                username = vuln.get('username', 'admin')
                if username not in credentials_generated:
                    password_length = policy.get('password_length', 16)
                    include_special = policy.get('password_special_chars', True)
                    credentials_generated[username] = generate_strong_password(
                        password_length, include_special
                    )
        
        result['credentials'] = credentials_generated
    
    return result


def get_remediation_logs(device_ip: Optional[str] = None) -> List[Dict]:
    """Get remediation logs from fix engine."""
    return fix_engine.get_fix_history(device_ip)
