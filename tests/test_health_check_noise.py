"""'cabled_without_ip' only makes sense where an IP is EXPECTED. 

Regression observed over a topology of 47 devices: the scan listed access ports 
of each 2960, the two ports of the AP and the Ethernet6 of the cloud as 
"IP-free cabling". None of those ever carry IP -- a Layer 2 switch has no address 
by definition -- so noise covered up the real cases, which are the hosts to which 
the DHCP did not arrive.
"""

import pytest

from src.packet_tracer_mcp.domain.services.topology_diff import health_check


def _port(name, ip="", linked=True, up=True):
    return {"name": name, "ip": ip, "linked": linked, "up": up}


class TestLayer2PortsAreNotFlagged:
    def test_switch_access_ports_are_not_reported(self):
        live = [{
            "name": "SW1", "model": "2960-24TT",
            "ports": [_port("FastEthernet0/1"), _port("FastEthernet0/2"),
                      _port("GigabitEthernet0/1")],
        }]
        result = health_check(live)
        assert result["cabled_without_ip"] == []

    def test_access_point_ports_are_not_reported(self):
        live = [{"name": "WAP1", "model": "AccessPoint-PT",
                 "ports": [_port("Port 0"), _port("Port 1")]}]
        assert health_check(live)["cabled_without_ip"] == []

    def test_cloud_ports_are_not_reported(self):
        live = [{"name": "WAN", "model": "Cloud-PT",
                 "ports": [_port("Ethernet6")]}]
        assert health_check(live)["cabled_without_ip"] == []


class TestRealCasesStillReported:
    def test_host_without_ip_is_still_reported(self):
        """A wired PC without IP is DHCP that didn't arrive: that does matter."""
        live = [{"name": "PC1", "model": "PC-PT",
                 "ports": [_port("FastEthernet0")]}]
        flagged = health_check(live)["cabled_without_ip"]
        assert flagged == [{"device": "PC1", "port": "FastEthernet0"}]

    def test_router_interface_without_ip_is_still_reported(self):
        live = [{"name": "R1", "model": "2911",
                 "ports": [_port("GigabitEthernet0/0")]}]
        flagged = health_check(live)["cabled_without_ip"]
        assert flagged == [{"device": "R1", "port": "GigabitEthernet0/0"}]

    def test_unknown_model_is_still_reported(self):
        """If the model cannot be resolved, it is better to warn of more than less."""
        live = [{"name": "X1", "model": "modelo-que-no-existe",
                 "ports": [_port("FastEthernet0")]}]
        assert health_check(live)["cabled_without_ip"] != []


class TestOtherChecksUnaffected:
    def test_down_link_on_a_switch_is_still_reported(self):
        live = [{"name": "SW1", "model": "2960-24TT",
                 "ports": [_port("FastEthernet0/1", linked=True, up=False)]}]
        result = health_check(live)
        assert result["down_links"] == [{"device": "SW1", "port": "FastEthernet0/1"}]
        assert not result["healthy"]

    def test_duplicate_ips_still_detected(self):
        live = [
            {"name": "PC1", "model": "PC-PT", "ports": [_port("FastEthernet0", ip="192.168.0.5")]},
            {"name": "PC2", "model": "PC-PT", "ports": [_port("FastEthernet0", ip="192.168.0.5")]},
        ]
        assert "192.168.0.5" in health_check(live)["duplicate_ips"]
