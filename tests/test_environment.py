"""
Tests for the CyberTwin SOC EnvironmentBuilder.
"""

import pytest
from backend.simulation.environment import EnvironmentBuilder


@pytest.fixture
def env():
    builder = EnvironmentBuilder()
    builder.load()
    return builder


class TestEnvironmentBuilder:

    def test_load_assets(self, env):
        """load_assets should populate the hosts dictionary."""
        hosts = env.get_hosts()
        assert len(hosts) > 0

    def test_load_users(self, env):
        """load_users should populate the users dictionary."""
        users = env.get_users()
        assert len(users) > 0

    def test_hosts_have_required_fields(self, env):
        """Each host should have id, hostname, ip, type, and os fields."""
        hosts = env.get_hosts()
        for host_id, host in hosts.items():
            assert "id" in host
            assert "hostname" in host or "id" in host
            assert "ip" in host
            assert "type" in host
            assert "os" in host

    def test_network_segments_exist(self, env):
        """The environment topology should contain network segments."""
        topology = env.get_topology()
        assert "segments" in topology
        assert len(topology["segments"]) > 0

    def test_get_host_by_id(self, env):
        """get_host should return a host dict for a valid ID."""
        hosts = env.get_hosts()
        first_id = next(iter(hosts))
        host = env.get_host(first_id)
        assert host is not None
        assert host["id"] == first_id

    def test_get_host_unknown_returns_none(self, env):
        """get_host for an unknown ID should return None."""
        assert env.get_host("nonexistent-host-999") is None

    def test_get_workstations(self, env):
        """get_workstations should return only hosts with type=workstation."""
        workstations = env.get_workstations()
        for ws in workstations:
            assert ws["type"] == "workstation"

    def test_get_servers(self, env):
        """get_servers should return only hosts with type=server."""
        servers = env.get_servers()
        for srv in servers:
            assert srv["type"] == "server"

    def test_topology_has_network_info(self, env):
        """get_topology should return network metadata."""
        topology = env.get_topology()
        assert "network" in topology
        assert "hosts" in topology

    def test_to_dict_serialisation(self, env):
        """to_dict should return a complete dictionary representation."""
        d = env.to_dict()
        assert "network" in d
        assert "segments" in d
        assert "hosts" in d
        assert "users" in d

    def test_users_have_department(self, env):
        """Each user should have a department field."""
        users = env.get_users()
        for uid, user in users.items():
            assert "department" in user

    def test_repr_string(self, env):
        """The repr should indicate loaded=True."""
        r = repr(env)
        assert "loaded=True" in r
