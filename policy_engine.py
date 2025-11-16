"""
Policy Engine for Security Policy Management
Extends policy.py with enhanced policy validation and enforcement
"""
from pathlib import Path
from typing import Dict, Tuple
from policy import load_policy, save_policy, get_default_policy, validate_policy


def get_security_policy() -> Dict:
    """Get current security policy."""
    return load_policy()


def update_security_policy(updates: Dict) -> Tuple[bool, str]:
    """
    Update security policy with validation.
    Returns (success, message)
    """
    policy = get_security_policy()
    policy.update(updates)
    
    is_valid, message = validate_policy(policy)
    if is_valid:
        save_policy(policy)
        return True, "Policy updated successfully"
    else:
        return False, f"Policy validation failed: {message}"


def get_allowed_ports(policy: Dict = None) -> List[int]:
    """Get list of allowed ports from policy."""
    if policy is None:
        policy = get_security_policy()
    return policy.get('allowed_ports', [443])


def get_password_policy(policy: Dict = None) -> Dict:
    """Get password policy settings."""
    if policy is None:
        policy = get_security_policy()
    return {
        'length': policy.get('password_length', 16),
        'special_chars': policy.get('password_special_chars', True),
        'uppercase': policy.get('password_require_uppercase', True),
        'lowercase': policy.get('password_require_lowercase', True),
        'numbers': policy.get('password_require_numbers', True)
    }


def get_risk_thresholds(policy: Dict = None) -> Dict:
    """Get risk score thresholds."""
    if policy is None:
        policy = get_security_policy()
    return {
        'critical': policy.get('risk_threshold_critical', 70),
        'high': policy.get('risk_threshold_high', 40),
        'medium': policy.get('risk_threshold_medium', 20)
    }

