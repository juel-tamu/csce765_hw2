import os
import sys

import pytest

# handshake.py opens "ffdhe3072.pem" relative to the working directory,
# so run from the project root and make its modules importable.
PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
os.chdir(PROJECT_DIR)
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

import handshake
import secure_record

COMMAND = b'{"action":"READ","path":"notes.txt"}'


@pytest.fixture
def session_keys():
    """Run a full handshake; returns (gateway_keys, node_keys)."""
    return handshake.main()


@pytest.fixture
def channel(session_keys):
    """Record-layer state for both ends of a freshly established session."""
    gateway_keys, node_keys = session_keys
    gateway = secure_record.Record(handshake.TRANSCRIPT_ROLE_GATEWAY, gateway_keys)
    node = secure_record.Record(handshake.TRANSCRIPT_ROLE_NODE, node_keys)
    return gateway, node


@pytest.fixture
def transcript_hash():
    """TH for a well-formed transcript built from fresh values."""
    transcript = handshake.assemble_transcript(
        handshake.TRANSCRIPT_ROLE_GATEWAY, handshake.TRANSCRIPT_ROLE_NODE,
        os.urandom(384), os.urandom(384), os.urandom(16), os.urandom(16))
    return handshake.hash_transcript(transcript)
