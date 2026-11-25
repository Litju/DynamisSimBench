"""The production canary drains last-instant events before the supervisor reads it."""

from __future__ import annotations

import socket

import pytest

from dynamisbench.execution.protected_canary import ProtectedNetworkCanary


def test_udp_sent_immediately_before_drain_is_observed() -> None:
    canary = ProtectedNetworkCanary()
    try:
        control = canary.self_check()
        assert control["udp"] is True
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.sendto(b"DYNAMISBENCH-DRAIN-PROBE", ("127.0.0.1", canary.udp_port))
        finally:
            probe.close()

        canary.drain()

        assert canary.udp_datagrams == 1
    finally:
        canary.close()


def test_tcp_sent_immediately_before_drain_is_observed() -> None:
    canary = ProtectedNetworkCanary()
    try:
        control = canary.self_check()
        assert control["tcp"] is True
        with socket.create_connection(("127.0.0.1", canary.port), timeout=1.0):
            pass

        canary.drain()

        assert canary.tcp_connections == 1
    finally:
        canary.close()


def test_unix_sent_immediately_before_drain_is_observed() -> None:
    canary = ProtectedNetworkCanary()
    try:
        if canary.unix_path is None:
            pytest.skip("AF_UNIX is unavailable in this interpreter")
        control = canary.self_check()
        if not control["unix"]:
            pytest.skip("the Unix canary did not receive its control")
        family = getattr(socket, "AF_UNIX", None)
        assert family is not None
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.connect(canary.unix_path)

        canary.drain()

        assert canary.unix_connections == 1
    finally:
        canary.close()


def test_drain_is_bounded_when_there_is_no_event() -> None:
    canary = ProtectedNetworkCanary()
    try:
        assert all(canary.self_check().values())
        canary.drain(timeout=0.1)
        assert canary.tcp_connections == 0
        assert canary.udp_datagrams == 0
    finally:
        canary.close()
