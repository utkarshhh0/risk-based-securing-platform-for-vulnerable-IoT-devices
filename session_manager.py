"""
Session state persistence manager
Saves/loads device analysis state to persist across browser refreshes
"""
import json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime


def get_session_file() -> Path:
    """Get path to session state file."""
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    return data_dir / "session_state.json"


def save_session_state(devices: List[Dict], policy: Dict) -> None:
    """Save current session state (device analysis results) to file."""
    session_file = get_session_file()
    data = {
        'devices': devices,
        'policy': policy,
        'saved_at': datetime.now().isoformat()
    }
    with open(session_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def load_session_state() -> Optional[Dict]:
    """Load saved session state from file."""
    session_file = get_session_file()
    if session_file.exists():
        try:
            with open(session_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data
        except Exception:
            return None
    return None


def clear_session_state() -> None:
    """Clear saved session state."""
    session_file = get_session_file()
    if session_file.exists():
        session_file.unlink()


def restore_default_dataset() -> bool:
    """Restore the default vulnerable dataset from iot_simulator."""
    from iot_simulator import DEFAULT_DEVICES, save_simulated_devices
    try:
        save_simulated_devices(DEFAULT_DEVICES)
        return True
    except Exception:
        return False

