import handshake
import struct
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DIRECTION_G2N, DIRECTION_N2G = 0, 1

class Record():
    def __init__(self, role, keys: dict[str, bytes]):
        self.session_id = keys['session_id']
        if role == handshake.TRANSCRIPT_ROLE_GATEWAY:
            self.send_enc, self.send_mac, self.send_direction = keys["K_g2n_enc"], keys["K_g2n_mac"], DIRECTION_G2N
            self.recv_enc, self.recv_mac, self.recv_direction = keys["K_n2g_enc"], keys["K_n2g_mac"], DIRECTION_N2G
        else:
            self.send_enc, self.send_mac, self.send_direction = keys["K_n2g_enc"], keys["K_n2g_mac"], DIRECTION_N2G
            self.recv_enc, self.recv_mac, self.recv_direction = keys["K_g2n_enc"], keys["K_g2n_mac"], DIRECTION_G2N

        self.send_seq = 0
        self.recv_seq = 0

def seal(state: Record, msg_type: str, plaintext: str):
    seq = state.send_seq
    iv = state.session_id + seq.to_bytes(8, "big")
    encryptor = Cipher(algorithms.AES(state.send_enc), modes.CTR(iv)).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Craft header structure
    header = bytearray(15)
    struct.pack_into('>B', header, 0, 1)
    struct.pack_into('>B', header, 1, state.send_direction)
    struct.pack_into('>Q', header, 2, seq)
    struct.pack_into('>B', header, 10, msg_type)
    struct.pack_into('>I', header, 11, len(ciphertext))

    tag = handshake._hmac(state.send_mac, header + iv + ciphertext)
 
    state.send_seq += 1
    return header + ciphertext + tag

def open_record(state: Record, header_record: bytearray):
    seq = state.recv_seq
    if 15 + 32 > len(header_record):
        raise ValueError("Header record is not of sufficient length")
    
    header = header_record[:15]
    tag = bytes(header_record[-32:])
    ciphertext = header_record[15:-32]

    if struct.unpack('>I', header[11:15])[0] != len(ciphertext):
        raise ValueError("Ciphertext length is incorrect")

    if header[0] != 1 or header[10] != 1 or header[1] != state.recv_direction or struct.unpack('>Q', header[2:10])[0] != seq:
        raise ValueError("Header structure is incorrect")
    
    iv = state.session_id + seq.to_bytes(8, "big")

    mac = hmac.HMAC(state.recv_mac, hashes.SHA256())
    mac.update(header + iv + ciphertext)

    try:
        mac.verify(tag)
    except:
        raise ValueError("Tag signature is invalid")

    decryptor = Cipher(algorithms.AES(state.recv_enc), modes.CTR(iv)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    state.recv_seq += 1

    return plaintext.decode()

def main():
    gateway_keys, node_keys = handshake.main()

    gateway_state = Record(handshake.TRANSCRIPT_ROLE_GATEWAY, gateway_keys)
    node_state = Record(handshake.TRANSCRIPT_ROLE_NODE, node_keys)

    request = seal(gateway_state, 1, b'{"action":"READ","path":"notes.txt"}')
    print(open_record(node_state, request))

    request = seal(node_state, 1, b'{"response":"Done"}')
    print(open_record(gateway_state, request))

if __name__ == "__main__":
    main()