"""Task 4 test 6, plus Task 2 requirements from the spec, for handshake.py."""

import hashlib
import os

import pytest
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa

import handshake
from handshake import TRANSCRIPT_ROLE_GATEWAY as GATEWAY, TRANSCRIPT_ROLE_NODE as NODE


def _hmac(key, data):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


# 6. Incorrect RSA public key, invalid signature, reflected handshake message

def test_invalid_transcript_signature_rejected(transcript_hash):
    sig = bytearray(handshake.sign_transcript(transcript_hash, NODE))
    sig[0] ^= 0x01
    with pytest.raises(ValueError, match="Peer signature could not be verified"):
        handshake.verify_signature(bytes(sig), transcript_hash, NODE)


def test_signature_over_different_transcript_rejected(transcript_hash):
    """A changed nonce or DH value changes TH, so the old signature fails."""
    sig = handshake.sign_transcript(transcript_hash, NODE)
    other_th = hashlib.sha256(b"tampered transcript").digest()
    with pytest.raises(ValueError, match="Peer signature could not be verified"):
        handshake.verify_signature(sig, other_th, NODE)


def test_incorrect_rsa_public_key_rejected(transcript_hash, monkeypatch):
    sig = handshake.sign_transcript(transcript_hash, NODE)
    impostor = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    monkeypatch.setattr(handshake, "RSA_PUBLIC_KEY_NODE", impostor.public_key())
    monkeypatch.setattr(handshake, "RSA_PUBLIC_KEY_GATEWAY", impostor.public_key())
    with pytest.raises(ValueError, match="Peer signature could not be verified"):
        handshake.verify_signature(sig, transcript_hash, NODE)


def test_reflected_signature_rejected(transcript_hash):
    """The gateway's own signature, sent back as if it were the node's."""
    gateway_sig = handshake.sign_transcript(transcript_hash, GATEWAY)
    with pytest.raises(ValueError, match="Peer signature could not be verified"):
        handshake.verify_signature(gateway_sig, transcript_hash, NODE)


def test_reflected_handshake_message_rejected():
    """The gateway's first message bounced back to the gateway as the 'node reply'."""
    gateway_msg = {"role": "Gateway", "identity": GATEWAY}
    with pytest.raises(ValueError, match="Message role does not match expected"):
        handshake.verify_message_role_and_iden(gateway_msg, "Node")


def test_unexpected_peer_identity_rejected(transcript_hash):
    sig = handshake.sign_transcript(transcript_hash, NODE)
    with pytest.raises(ValueError, match="Received and expected peer id does not match"):
        handshake.accept_session(sig, transcript_hash, NODE, b"evil-node", NODE)


# Transcript encoding (length-prefixed)

def _transcript():
    return handshake.assemble_transcript(GATEWAY, NODE, os.urandom(384), os.urandom(384),
                                         os.urandom(16), os.urandom(16))


def test_overlong_declared_length_rejected():
    t = bytearray(_transcript())
    t[3] += 1                              # label length 13 -> 14
    with pytest.raises(ValueError, match="Incorrectly declared length"):
        handshake.hash_transcript(bytes(t))


def test_declared_length_past_end_rejected():
    t = _transcript()
    with pytest.raises(ValueError, match="Incorrectly declared length"):
        handshake.hash_transcript(t[:-1])


def test_extra_transcript_field_rejected():
    t = _transcript() + (1).to_bytes(4, "big") + b"x"
    with pytest.raises(ValueError, match="Incorrect number of fields"):
        handshake.decode_transcript(t)


# Task 2 requirements the record tests depend on

def test_signature_made_with_signers_own_key(transcript_hash):
    """Each party signs with its OWN long-term key."""
    pss, sha = handshake.PSS_PADDING, hashes.SHA256()
    gateway_sig = handshake.sign_transcript(transcript_hash, GATEWAY)
    handshake.RSA_PUBLIC_KEY_GATEWAY.verify(gateway_sig, GATEWAY + transcript_hash, pss, sha)
    node_sig = handshake.sign_transcript(transcript_hash, NODE)
    handshake.RSA_PUBLIC_KEY_NODE.verify(node_sig, NODE + transcript_hash, pss, sha)


def test_fresh_dh_values_and_nonces_per_session():
    a, b = handshake.FreshCredentials(), handshake.FreshCredentials()
    assert a.nonce != b.nonce
    assert a.public_key != b.public_key


def test_dh_public_value_belongs_to_private_key():
    c = handshake.FreshCredentials()
    expected = c.private_key.public_key().public_numbers().y.to_bytes(384, "big")
    assert c.public_key == expected


@pytest.mark.parametrize("y", [0, 1])
def test_trivial_dh_public_value_rejected(y):
    with pytest.raises(ValueError):
        handshake.verify_public_key(y.to_bytes(384, "big"))


def test_kdf_uses_spec_labels():
    z, th = os.urandom(384), os.urandom(32)
    k_master = hashlib.sha256(b"CSCE465-KDF-v1" + z + th).digest()
    keys = handshake.generate_kdf(z, th)
    assert keys["K_g2n_enc"] == _hmac(k_master, b"gateway-to-node encryption" + th)
    assert keys["K_g2n_mac"] == _hmac(k_master, b"gateway-to-node MAC" + th)
    assert keys["K_n2g_enc"] == _hmac(k_master, b"node-to-gateway encryption" + th)
    assert keys["K_n2g_mac"] == _hmac(k_master, b"node-to-gateway MAC" + th)
    assert keys["session_id"] == _hmac(k_master, b"session identifier" + th)[:8]
