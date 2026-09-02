"""
Unit tests for multi-AZ / multi-region deployment topology.
"""
from reliability.topology import MultiRegionTopology


def test_topology_routing_and_failover():
    topo = MultiRegionTopology(primary_region="us-east-1", secondary_regions=["us-west-2"], mode="active-passive")
    assert topo.get_active_region() == "us-east-1"
    assert topo.is_primary_healthy() is True

    # Mark primary unhealthy -> automatic failover to secondary
    topo.set_region_health("us-east-1", is_healthy=False)
    assert topo.is_primary_healthy() is False
    assert topo.get_active_region() == "us-west-2"

    # Manual failover
    success = topo.trigger_failover("us-west-2")
    assert success is True

    status = topo.get_topology_status()
    assert status["mode"] == "active-passive"
    assert status["active_region"] == "us-west-2"
