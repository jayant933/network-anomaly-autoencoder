"""
whitelist.py

Trusted hosts. Traffic INITIATED by a trusted IP (or anything inside a trusted
CIDR range) is tagged "trusted" and never raises alerts. Persisted in a small
local JSON file (gitignored).
"""

import ipaddress
import json
import os
import threading

WHITELIST_FILE = "whitelist.json"


class Whitelist:
    def __init__(self, path=WHITELIST_FILE):
        self.path = path
        self._lock = threading.Lock()
        self._entries = []
        self._nets = []
        self._load()

    @staticmethod
    def _parse(entries):
        """Validate + normalise. Raises ValueError naming the bad entry."""
        clean, nets = [], []
        for raw in entries:
            text = str(raw).strip()
            if not text:
                continue
            try:
                net = ipaddress.ip_network(text, strict=False)
            except ValueError:
                raise ValueError(f"'{text}' is not a valid IP address or CIDR range")
            norm = str(net.network_address) if net.num_addresses == 1 else str(net)
            if norm not in clean:
                clean.append(norm)
                nets.append(net)
        return clean, nets

    def _load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path) as f:
                data = json.load(f)
            self._entries, self._nets = self._parse(data if isinstance(data, list) else [])
        except (json.JSONDecodeError, OSError, ValueError):
            self._entries, self._nets = [], []

    def entries(self):
        with self._lock:
            return list(self._entries)

    def set_entries(self, entries):
        clean, nets = self._parse(entries)      # validate everything first
        with self._lock:
            self._entries, self._nets = clean, nets
            with open(self.path, "w") as f:
                json.dump(clean, f)
        return list(clean)

    def contains(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        with self._lock:
            return any(addr in net for net in self._nets)