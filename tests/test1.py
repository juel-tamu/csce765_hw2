import fixture
import pytest

def test_valid_handshake_bidirectional_messaging(create_handshake):
    gateway_keys, node_keys = create_handshake
    print(gateway_keys, node_keys)