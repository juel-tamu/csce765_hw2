"""Task 4 tests 1-5: the encrypt-then-MAC record layer (secure_record.py)."""

import pytest

from conftest import COMMAND
from secure_record import open_record, seal

HEADER_LEN = 15
TAG_LEN = 32


def flip(record, index):
    """Return a copy of record with one bit flipped at index."""
    modified = bytearray(record)
    modified[index] ^= 0x01
    return bytes(modified)


# 1. Valid handshake and bidirectional messages

def test_valid_handshake_derives_matching_keys(session_keys):
    gateway_keys, node_keys = session_keys
    assert gateway_keys == node_keys
    assert len(gateway_keys["session_id"]) == 8


def test_bidirectional_messages(channel):
    gateway, node = channel
    assert open_record(node, seal(gateway, 1, COMMAND)) == COMMAND.decode()
    assert open_record(gateway, seal(node, 1, b'{"response":"Done"}')) == '{"response":"Done"}'
    assert open_record(node, seal(gateway, 1, b"second")) == "second"
    assert (gateway.send_seq, node.recv_seq) == (2, 2)
    assert (node.send_seq, gateway.recv_seq) == (1, 1)


def test_sender_never_reuses_iv(channel):
    gateway, _ = channel
    first, second = seal(gateway, 1, COMMAND), seal(gateway, 1, COMMAND)
    # same plaintext, different sequence number -> different IV -> different ciphertext
    assert first[HEADER_LEN:-TAG_LEN] != second[HEADER_LEN:-TAG_LEN]


# 2. Modified ciphertext

def test_modified_ciphertext_rejected(channel):
    gateway, node = channel
    record = flip(seal(gateway, 1, COMMAND), HEADER_LEN)
    with pytest.raises(ValueError, match="Tag signature is invalid"):
        open_record(node, record)
    assert node.recv_seq == 0


def test_modified_tag_rejected(channel):
    gateway, node = channel
    record = flip(seal(gateway, 1, COMMAND), -1)
    with pytest.raises(ValueError, match="Tag signature is invalid"):
        open_record(node, record)


def test_ctr_bit_flip_attack_rejected(channel):
    """The Task 1 attack (READ -> EXEC by XOR) no longer works."""
    gateway, node = channel
    record = bytearray(seal(gateway, 1, COMMAND))
    offset = HEADER_LEN + COMMAND.index(b"READ")
    for i, (a, b) in enumerate(zip(b"READ", b"EXEC")):
        record[offset + i] ^= a ^ b
    with pytest.raises(ValueError, match="Tag signature is invalid"):
        open_record(node, bytes(record))


# 3. Modified authenticated header

@pytest.mark.parametrize("index, field", [
    (0, "version"),
    (1, "direction"),
    (9, "sequence"),
    (10, "message_type"),
])
def test_modified_header_rejected(channel, index, field):
    gateway, node = channel
    record = flip(seal(gateway, 1, COMMAND), index)
    with pytest.raises(ValueError, match="Header structure is incorrect"):
        open_record(node, record)
    assert node.recv_seq == 0


def test_modified_length_field_rejected(channel):
    gateway, node = channel
    record = flip(seal(gateway, 1, COMMAND), 14)
    with pytest.raises(ValueError, match="Ciphertext length is incorrect"):
        open_record(node, record)


def test_truncated_record_rejected(channel):
    gateway, node = channel
    with pytest.raises(ValueError, match="not of sufficient length"):
        open_record(node, seal(gateway, 1, COMMAND)[:HEADER_LEN + TAG_LEN - 1])


# 4. Replayed record

def test_replayed_record_rejected(channel):
    gateway, node = channel
    record = seal(gateway, 1, COMMAND)
    open_record(node, record)
    with pytest.raises(ValueError, match="Header structure is incorrect"):
        open_record(node, record)
    assert node.recv_seq == 1


def test_reordered_record_rejected(channel):
    gateway, node = channel
    seal(gateway, 1, b"first")            # sequence 0, never delivered
    skipped = seal(gateway, 1, b"second")  # sequence 1
    with pytest.raises(ValueError, match="Header structure is incorrect"):
        open_record(node, skipped)


# 5. Record reflected into the opposite direction

def test_reflected_record_rejected(channel):
    gateway, _ = channel
    record = seal(gateway, 1, COMMAND)    # gateway -> node record
    with pytest.raises(ValueError, match="Header structure is incorrect"):
        open_record(gateway, record)       # bounced back to the gateway
    assert gateway.recv_seq == 0


# Errors leave state untouched, so the real record still opens afterward

def test_failed_record_does_not_desync_channel(channel):
    gateway, node = channel
    record = seal(gateway, 1, COMMAND)
    with pytest.raises(ValueError):
        open_record(node, flip(record, HEADER_LEN))
    assert open_record(node, record) == COMMAND.decode()
