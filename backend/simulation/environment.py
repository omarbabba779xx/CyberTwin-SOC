"""
Simulation environment builder for the CyberTwin SOC platform.

Loads network assets and user definitions from JSON data files and
provides a queryable in-memory representation of the simulated
corporate environment.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


class EnvironmentBuilder:
    """Builds and manages a simulated corporate network environment.

    The environment is constructed from two JSON data files:
      - data/assets.json  (hosts, network segments, topology)
      - data/users.json   (user accounts, roles, access rights)
    """

    def __init__(self, data_dir: Optional[Path] = None):
        self._data_dir = data_dir or PROJECT_ROOT / "data"
        self._assets_raw: Dict = {}
        self._users_raw: Dict = {}
        self._hosts: Dict[str, Dict] = {}
        self._users: Dict[str, Dict] = {}
        self._network: Dict = {}
        self._segments: List[Dict] = []
        self._loaded = False

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_assets(self) -> None:
        """Load host and network topology data from data/assets.json."""
        path = self._data_dir / "assets.json"
        with open(path, "r", encoding="utf-8") as fh:
            self._assets_raw = json.load(fh)

        self._network = self._assets_raw.get("network", {})
        self._segments = self._assets_raw.get("network_segments", [])

        self._hosts = {}
        for host in self._assets_raw.get("hosts", []):
            self._hosts[host["id"]] = host

    def load_users(self) -> None:
        """Load user account data from data/users.json."""
        path = self._data_dir / "users.json"
        with open(path, "r", encoding="utf-8") as fh:
            self._users_raw = json.load(fh)

        self._users = {}
        for user in self._users_raw.get("users", []):
            self._users[user["id"]] = user

    def load(self) -> "EnvironmentBuilder":
        """Convenience method: load both assets and users at once.

        Returns *self* so the call can be chained::

            env = EnvironmentBuilder().load()
        """
        self.load_assets()
        self.load_users()
        self._loaded = True
        return self

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_host(self, host_id: str) -> Optional[Dict]:
        """Return the host definition for *host_id*, or ``None``."""
        return self._hosts.get(host_id)

    def get_user(self, user_id: str) -> Optional[Dict]:
        """Return the user definition for *user_id*, or ``None``."""
        return self._users.get(user_id)

    def get_hosts(self) -> Dict[str, Dict]:
        """Return the full host dictionary keyed by host id."""
        return dict(self._hosts)

    def get_users(self) -> Dict[str, Dict]:
        """Return the full user dictionary keyed by user id."""
        return dict(self._users)

    def get_workstations(self) -> List[Dict]:
        """Return only hosts whose type is 'workstation'."""
        return [h for h in self._hosts.values() if h.get("type") == "workstation"]

    def get_servers(self) -> List[Dict]:
        """Return only hosts whose type is 'server'."""
        return [h for h in self._hosts.values() if h.get("type") == "server"]

    def get_topology(self) -> Dict:
        """Return the full network topology as a dictionary.

        The result contains:
          - ``network``: top-level network metadata (name, subnet, gateway)
          - ``segments``: list of network segment definitions
          - ``hosts``: list of all host definitions
        """
        return {
            "network": dict(self._network),
            "segments": list(self._segments),
            "hosts": list(self._hosts.values()),
        }

    def get_host_ip(self, host_id: str) -> Optional[str]:
        """Return the IP address for *host_id*, or ``None``."""
        host = self.get_host(host_id)
        return host["ip"] if host else None

    def get_user_host(self, user_id: str) -> Optional[Dict]:
        """Return the host assigned to *user_id*, or ``None``."""
        user = self.get_user(user_id)
        if user and user.get("assigned_host"):
            return self.get_host(user["assigned_host"])
        return None

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict:
        """Serialise the entire environment to a plain dictionary."""
        return {
            "network": dict(self._network),
            "segments": list(self._segments),
            "hosts": {hid: dict(h) for hid, h in self._hosts.items()},
            "users": {uid: dict(u) for uid, u in self._users.items()},
        }

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"<EnvironmentBuilder hosts={len(self._hosts)} "
            f"users={len(self._users)} loaded={self._loaded}>"
        )
