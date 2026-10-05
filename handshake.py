import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.serialization import load_pem_parameters
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa

# Global Variables
TRANSCRIPT_LABEL = b"CSCE465-HS-v2"
TRANSCRIPT_GROUP = b"ffdhe3072"
TRANSCRIPT_ROLE_GATEWAY = b"gateway"
TRANSCRIPT_ROLE_NODE = b"node"

# Generate RSA keys
RSA_PRIVATE_KEY_GATEWAY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=3072,
)
RSA_PRIVATE_KEY_NODE = rsa.generate_private_key(
    public_exponent=65537,
    key_size=3072,
)
RSA_PUBLIC_KEY_GATEWAY = RSA_PRIVATE_KEY_GATEWAY.public_key()
RSA_PUBLIC_KEY_NODE = RSA_PRIVATE_KEY_NODE.public_key()

# Define PSS padding configuration
PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
)

# Load load parameters
with open("ffdhe3072.pem", "rb") as f:
    DIFFIE_PARAMETERS = load_pem_parameters(f.read())

def _hmac(key, data):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

# Classes
class FreshCredentials:
    def __init__(self):
        self.private_key = DIFFIE_PARAMETERS.generate_private_key()
        self.public_key = self.private_key.public_key().public_numbers().y.to_bytes(384, "big")
        self.nonce = os.urandom(16)

# Functions
def assemble_transcript(idnetity_1, identity_2, gateway_pubk, node_pubk, gateway_nonce, node_nonce):
    fields = [TRANSCRIPT_LABEL, TRANSCRIPT_GROUP, idnetity_1, identity_2, 
              gateway_pubk, node_pubk, gateway_nonce, node_nonce]
    return b"".join(len(v).to_bytes(4, byteorder="big") + v for v in fields)

def decode_transcript(transcript: bytes):
    fields, i = [], 0
    while i < len(transcript):
        if i + 4 > len(transcript):
            raise ValueError("Incorrectly declared length")
        
        size = int.from_bytes(transcript[i: i+4], byteorder="big")
        i += 4

        if size + i > len(transcript):
            raise ValueError("Incorrectly declared length")
        
        fields.append(transcript[i: i + size])
        i += size

    if len(fields) != 8:
        raise ValueError("Incorrect number of fields in transcript declared")
    return fields

def hash_transcript(transcript: bytes):
    label, group, _, _, gateway_pubk, node_pubk, nonce_g, nonce_n = decode_transcript(transcript)
    if label != TRANSCRIPT_LABEL or group != TRANSCRIPT_GROUP or len(gateway_pubk) != 384 or len(node_pubk) != 384 or len(nonce_g) != 16 or len(nonce_n) != 16:
        raise ValueError("Malformed transcript")
    return hashlib.sha256(transcript).digest()

def sign_transcript(transcript: bytes, role: bytes):
    signing_key = RSA_PRIVATE_KEY_GATEWAY if role == TRANSCRIPT_ROLE_GATEWAY else RSA_PRIVATE_KEY_NODE
    return signing_key.sign(
        role + transcript,
        PSS_PADDING,
        hashes.SHA256()
    )

def generate_kdf(Z, TH: bytes):
    K_master = hashlib.sha256(b"CSCE465-KDF-v1" + Z + TH).digest()

    return {
        "K_g2n_enc": _hmac(K_master, b"gateway-to-node encryption" + TH),
        "K_g2n_mac": _hmac(K_master, b"gateway-to-node MAC" + TH),
        "K_n2g_enc": _hmac(K_master, b"node-to-gateway encryption" + TH),
        "K_n2g_mac": _hmac(K_master, b"node-to-gateway MAC" + TH),
        "session_id": _hmac(K_master, b"session identifier" + TH)[:8]
    }

def generate_keys(credentials: FreshCredentials, peer_pubk, transcript: bytes):
    Z = credentials.private_key.exchange(peer_pubk).rjust(384, b"\x00")
    credentials.private_key = None
    return generate_kdf(Z, transcript)

def verify_signature(signature: bytes, transcript: bytes, role: bytes):
    public_key = RSA_PUBLIC_KEY_GATEWAY if role == TRANSCRIPT_ROLE_GATEWAY else RSA_PUBLIC_KEY_NODE

    try:
        public_key.verify(
            signature,
            role + transcript,
            PSS_PADDING,
            hashes.SHA256()
        )
    except:
        raise ValueError("Peer signature could not be verified")

def verify_message_role_and_iden(msg, expected_role):
    identity = TRANSCRIPT_ROLE_GATEWAY if expected_role == "Gateway" else TRANSCRIPT_ROLE_NODE
    if msg['role'] != expected_role:
        raise ValueError("Message role does not match expected")
    if msg["identity"] != identity:
        raise ValueError("Message identity does not match expected")

def verify_public_key(pubkey_bytes: bytes):
    if len(pubkey_bytes) != 384:
        raise ValueError("Public key length does not match expected")
    pubkey = int.from_bytes(pubkey_bytes, "big")
    p = DIFFIE_PARAMETERS.parameter_numbers().p
    if not 1 < pubkey < p - 1:
        raise ValueError("Public key is out of range")
    return dh.DHPublicNumbers(pubkey, DIFFIE_PARAMETERS.parameter_numbers()).public_key()

def accept_session(signature: bytes, transcript: bytes, role: str, received_peer_id, expected_peer_id):
    if received_peer_id != expected_peer_id:
        raise ValueError("Received and expected peer id does not match")
    verify_signature(signature, transcript, role)

def main():
    # Initial Message
    gateway_credentials = FreshCredentials()
    initial_message = {"role": "Gateway", "identity": TRANSCRIPT_ROLE_GATEWAY, "nonce": gateway_credentials.nonce, "pub_key": gateway_credentials.public_key}

    # Sent to node
    verify_message_role_and_iden(initial_message, "Gateway")
    gateway_pubk = verify_public_key(initial_message["pub_key"])

    node_credentials = FreshCredentials()
    transcript_hash = assemble_transcript(initial_message["identity"], TRANSCRIPT_ROLE_NODE, initial_message["pub_key"], node_credentials.public_key, initial_message["nonce"], node_credentials.nonce)
    node_th = hash_transcript(transcript_hash)
    signature = sign_transcript(node_th, TRANSCRIPT_ROLE_NODE)
    initial_response = {"role": "Node", "identity": TRANSCRIPT_ROLE_NODE, "nonce": node_credentials.nonce, "pub_key": node_credentials.public_key, "signature": signature}

    # Gateway responds for final part of handshake
    verify_message_role_and_iden(initial_response, "Node")
    node_pubk = verify_public_key(initial_response["pub_key"])

    transcript_hash = assemble_transcript(TRANSCRIPT_ROLE_GATEWAY, initial_response["identity"], gateway_credentials.public_key, initial_response["pub_key"], gateway_credentials.nonce, initial_response["nonce"])
    gateway_th = hash_transcript(transcript_hash)
    accept_session(initial_response["signature"], gateway_th, TRANSCRIPT_ROLE_NODE, initial_response["identity"], TRANSCRIPT_ROLE_NODE)

    signature = sign_transcript(gateway_th, TRANSCRIPT_ROLE_GATEWAY)
    keys = generate_keys(gateway_credentials, node_pubk, gateway_th)
    final_response, gateway_keys = {"role": "Gateway", "identity": TRANSCRIPT_ROLE_GATEWAY, "signature": signature}, keys

    # Node responds for final part of handshake
    verify_message_role_and_iden(final_response, "Gateway")
    accept_session(final_response["signature"], node_th, TRANSCRIPT_ROLE_GATEWAY, final_response["identity"], TRANSCRIPT_ROLE_GATEWAY)
    node_keys = generate_keys(node_credentials, gateway_pubk, node_th)

    # Handshake complete
    return gateway_keys, node_keys

if __name__ == "__main__":
    main()
