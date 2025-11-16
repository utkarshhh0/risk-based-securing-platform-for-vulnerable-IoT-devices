"""
Utility functions for the IoT Security Platform
"""
import secrets
import string
import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any


def generate_strong_password(length: int = 16, include_special: bool = True) -> str:
    """Generate a strong random password."""
    alphabet = string.ascii_letters + string.digits
    if include_special:
        alphabet += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def export_to_csv(data: List[Dict[str, Any]], filename: str) -> str:
    """Export data to CSV file."""
    if not data:
        return ""
    
    filepath = Path("exports") / f"{filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath.parent.mkdir(exist_ok=True)
    
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
    
    return str(filepath)


def load_json_file(filepath: str) -> Dict:
    """Load JSON file, return empty dict if file doesn't exist."""
    path = Path(filepath)
    if path.exists():
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}


def save_json_file(data: Dict, filepath: str) -> None:
    """Save data to JSON file."""
    path = Path(filepath)
    path.parent.mkdir(exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def get_data_dir() -> Path:
    """Get or create data directory."""
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    return data_dir

