"""
Deterministic Risk Scoring Engine
Calculates risk scores based on fixed rules, no randomness
"""
from typing import Dict, List
from datetime import datetime


# Risk scoring constants - all deterministic
RISK_WEIGHTS = {
    'default_credentials': 40,
    'telnet_port': 25,
    'rtsp_port': 20,
    'ftp_port': 15,
    'http_port': 10,
    'http_alt_port': 10,
    'firmware_5_years': 20,
    'firmware_3_years': 10,
    'cve_critical': 20,
    'cve_high': 15,
    'cve_medium': 10,
    'cve_low': 5
}

# Device type multipliers
DEVICE_TYPE_MULTIPLIERS = {
    'camera': 1.4,
    'router': 1.2,
    'sensor': 1.1,
    'doorbell': 1.1,
    'thermostat': 1.0,
    'plug': 0.8,
    'bulb': 0.8,
    'other': 1.0
}


def calculate_risk_score(device: Dict, policy: Dict = None) -> Dict:
    """
    Calculate deterministic risk score for a device.
    
    Args:
        device: Device dictionary with simulator data
        policy: Security policy (optional)
    
    Returns:
        Dict with risk_score, risk_category, and triggered_rules
    """
    if policy is None:
        policy = {}
    
    risk = 0.0
    triggered_rules = []
    current_year = datetime.now().year
    
    # Get device data
    simulator_data = device.get('simulator_data', device)
    open_ports = device.get('open_ports', simulator_data.get('open_ports', []))
    default_creds = simulator_data.get('default_creds', False)
    last_update_year = simulator_data.get('last_update_year', current_year)
    device_type = simulator_data.get('device_type', 'other')
    services = simulator_data.get('services', {})
    simulated_cves = simulator_data.get('simulated_cves', [])
    
    # Rule 1: Default credentials (CRITICAL)
    if default_creds:
        risk += RISK_WEIGHTS['default_credentials']
        triggered_rules.append({
            'rule': 'default_credentials',
            'severity': 'critical',
            'description': 'Device uses default/weak credentials',
            'risk_added': RISK_WEIGHTS['default_credentials']
        })
    
    # Rule 2: Dangerous ports
    if 23 in open_ports or services.get('telnet', False):
        risk += RISK_WEIGHTS['telnet_port']
        triggered_rules.append({
            'rule': 'telnet_enabled',
            'severity': 'high',
            'description': 'Telnet service enabled (unencrypted)',
            'risk_added': RISK_WEIGHTS['telnet_port']
        })
    
    if 554 in open_ports or services.get('rtsp', False):
        risk += RISK_WEIGHTS['rtsp_port']
        triggered_rules.append({
            'rule': 'rtsp_enabled',
            'severity': 'high',
            'description': 'RTSP streaming enabled (often unauthenticated)',
            'risk_added': RISK_WEIGHTS['rtsp_port']
        })
    
    if 21 in open_ports or services.get('ftp', False):
        risk += RISK_WEIGHTS['ftp_port']
        triggered_rules.append({
            'rule': 'ftp_enabled',
            'severity': 'high',
            'description': 'FTP service enabled (unencrypted)',
            'risk_added': RISK_WEIGHTS['ftp_port']
        })
    
    # Rule 3: HTTP admin interfaces (check policy)
    allowed_ports = policy.get('allowed_ports', [443])
    if 80 in open_ports and 80 not in allowed_ports:
        risk += RISK_WEIGHTS['http_port']
        triggered_rules.append({
            'rule': 'http_admin',
            'severity': 'medium',
            'description': 'Unencrypted HTTP admin interface',
            'risk_added': RISK_WEIGHTS['http_port']
        })
    
    if 8080 in open_ports and 8080 not in allowed_ports:
        risk += RISK_WEIGHTS['http_alt_port']
        triggered_rules.append({
            'rule': 'http_alt_admin',
            'severity': 'medium',
            'description': 'Unencrypted HTTP admin on alternate port',
            'risk_added': RISK_WEIGHTS['http_alt_port']
        })
    
    # Rule 4: Firmware age
    years_old = current_year - last_update_year
    if years_old >= 5:
        risk += RISK_WEIGHTS['firmware_5_years']
        triggered_rules.append({
            'rule': 'firmware_5_years',
            'severity': 'high',
            'description': f'Firmware last updated {years_old} years ago (>=5 years)',
            'risk_added': RISK_WEIGHTS['firmware_5_years']
        })
    elif years_old >= 3:
        risk += RISK_WEIGHTS['firmware_3_years']
        triggered_rules.append({
            'rule': 'firmware_3_years',
            'severity': 'medium',
            'description': f'Firmware last updated {years_old} years ago (>=3 years)',
            'risk_added': RISK_WEIGHTS['firmware_3_years']
        })
    
    # Rule 5: CVEs
    for cve in simulated_cves:
        severity = cve.get('severity', 'low').lower()
        if severity == 'critical':
            risk += RISK_WEIGHTS['cve_critical']
            triggered_rules.append({
                'rule': f'cve_{cve.get("cve_id")}',
                'severity': 'critical',
                'description': f'{cve.get("cve_id")}: {cve.get("description", "")}',
                'risk_added': RISK_WEIGHTS['cve_critical']
            })
        elif severity == 'high':
            risk += RISK_WEIGHTS['cve_high']
            triggered_rules.append({
                'rule': f'cve_{cve.get("cve_id")}',
                'severity': 'high',
                'description': f'{cve.get("cve_id")}: {cve.get("description", "")}',
                'risk_added': RISK_WEIGHTS['cve_high']
            })
        elif severity == 'medium':
            risk += RISK_WEIGHTS['cve_medium']
            triggered_rules.append({
                'rule': f'cve_{cve.get("cve_id")}',
                'severity': 'medium',
                'description': f'{cve.get("cve_id")}: {cve.get("description", "")}',
                'risk_added': RISK_WEIGHTS['cve_medium']
            })
        elif severity == 'low':
            risk += RISK_WEIGHTS['cve_low']
            triggered_rules.append({
                'rule': f'cve_{cve.get("cve_id")}',
                'severity': 'low',
                'description': f'{cve.get("cve_id")}: {cve.get("description", "")}',
                'risk_added': RISK_WEIGHTS['cve_low']
            })
    
    # Apply device type multiplier
    multiplier = DEVICE_TYPE_MULTIPLIERS.get(device_type, 1.0)
    base_risk = risk
    risk = risk * multiplier
    
    # Cap at 100
    risk = min(risk, 100.0)
    
    # Determine risk category
    if risk >= 70:
        risk_category = 'Critical'
    elif risk >= 40:
        risk_category = 'High'
    elif risk >= 20:
        risk_category = 'Medium'
    else:
        risk_category = 'Low'
    
    return {
        'risk_score': round(risk, 1),
        'base_risk': round(base_risk, 1),
        'multiplier': multiplier,
        'risk_category': risk_category,
        'triggered_rules': triggered_rules,
        'device_type': device_type,
        'years_old_firmware': years_old
    }


def explain_risk(device: Dict, risk_result: Dict) -> str:
    """Generate human-readable explanation of why device is risky."""
    explanations = []
    
    if risk_result['risk_score'] == 0:
        return "✅ Device appears secure - no significant vulnerabilities detected."
    
    explanations.append(f"**Risk Score: {risk_result['risk_score']}/100** ({risk_result['risk_category']} Risk)")
    explanations.append(f"Device Type: {risk_result['device_type'].title()} (multiplier: {risk_result['multiplier']}x)")
    
    if risk_result['triggered_rules']:
        explanations.append("\n**Vulnerabilities Detected:**")
        for rule in risk_result['triggered_rules']:
            severity_icon = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }.get(rule['severity'], '⚪')
            explanations.append(f"- {severity_icon} {rule['description']} (+{rule['risk_added']} risk)")
    
    return "\n".join(explanations)

