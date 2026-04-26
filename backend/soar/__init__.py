"""
CyberTwin SOC — SOAR Integration Module
=========================================
Provides clients for TheHive v5 and Cortex v3 to push simulation
incidents and trigger automated analysis responders.
"""
from .thehive import TheHiveClient
from .cortex import CortexClient

__all__ = ["TheHiveClient", "CortexClient"]
