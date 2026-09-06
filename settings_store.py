"""
settings_store.py

Tiny local JSON store for email alert settings, so they persist across
dashboard restarts without needing a database. The file is gitignored -
credentials never leave your machine / get committed.
"""

import json
import os

SETTINGS_FILE = "email_settings.json"


def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None
    return None


def save_settings(data):
    """`data` should be a dict with host/port/user/password/from_addr/to_addr,
    or None to disable and clear saved settings."""
    if data is None:
        if os.path.exists(SETTINGS_FILE):
            os.remove(SETTINGS_FILE)
        return
    with open(SETTINGS_FILE, "w") as f:
        json.dump(data, f)