"""Minimal conftest for VM-side isolation tests.

These tests run inside the microVM. No sinkhole, no admin API,
no host-side fixtures. Only stdlib + pytest.
"""
