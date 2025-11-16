"""
Security policy management
"""
from pathlib import Path
from utils import load_json_file, save_json_file
from typing import Dict, Tuple


def get_policy_file() -> Path:
    """Get path to policy storage file."""
    data_dir = Path("data")
    return data_dir / "policy.json"


def get_default_policy() -> Dict:
    """Get default security policy."""
    return {
        'password_length': 16,
        'password_special_chars': True,
        'password_require_uppercase': True,
        'password_require_lowercase': True,
        'password_require_numbers': True,
        'allowed_ports': [443],  # Only HTTPS allowed by default
        'risk_threshold_critical': 70,
        'risk_threshold_high': 40,
        'risk_threshold_medium': 20,
        'auto_fix_enabled': False,
        'notify_on_critical': True
    }


def load_policy() -> Dict:
    """Load security policy from storage."""
    policy_file = get_policy_file()
    policy = load_json_file(str(policy_file))
    
    if not policy:
        # Create default policy
        policy = get_default_policy()
        save_policy(policy)
    
    # Merge with defaults to ensure all keys exist
    default = get_default_policy()
    default.update(policy)
    return default


def save_policy(policy: Dict) -> None:
    """Save security policy to storage."""
    policy_file = get_policy_file()
    save_json_file(policy, str(policy_file))


def validate_policy(policy: Dict) -> Tuple[bool, str]:
    """Validate policy settings."""
    if policy.get('password_length', 0) < 8:
        return False, "Password length must be at least 8 characters"
    
    if policy.get('password_length', 0) > 128:
        return False, "Password length must not exceed 128 characters"
    
    if not isinstance(policy.get('allowed_ports', []), list):
        return False, "Allowed ports must be a list"
    
    for port in policy.get('allowed_ports', []):
        if not isinstance(port, int) or port < 1 or port > 65535:
            return False, f"Invalid port number: {port}"
    
    return True, "Policy is valid"

