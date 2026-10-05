# CSCE 465/765 Homework 2: Protect Agent Messages with Classic Cryptography

| File               | Task                                                                             |
| ------------------ | -------------------------------------------------------------------------------- |
| `baseline_ctr.py`  | Task 1: AES-CTR without a MAC; bit-flip and replay demonstration                 |
| `handshake.py`     | Task 2: authenticated finite-field Diffie–Hellman handshake (RSA-PSS, ffdhe3072) |
| `secure_record.py` | Task 3: encrypt-then-MAC record layer (`seal` / `open_record`)                   |
| `tests/`           | Task 4: adversarial tests                                                        |
| `ffdhe3072.pem`    | DH group parameters generated in Lab Preparation                                 |
| `report.pdf`       | The report                                                                       |
| `AI_USAGE.md`      | AI-use record                                                                    |

## Setup

Requires Python 3 and OpenSSL 3.0 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install cryptography==49.0.0 pytest==9.1.1
```

`ffdhe3072.pem` is included. To regenerate it:

```bash
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem
openssl dhparam -in ffdhe3072.pem -text -noout | head -3   # DH Parameters: (3072 bit), GROUP: ffdhe3072
```

Run every command below from this directory: `handshake.py` loads `ffdhe3072.pem` from the working directory.

## Task 1: CTR bit-flip and replay

```bash
python3 baseline_ctr.py
```

The sender encrypts the command with AES-CTR and sends it through a local relay (127.0.0.1, ports 8888 → 8889). The relay XORs `READ` into `OPEN` without the key, then forwards the modified ciphertext twice. The receiver decrypts and prints both copies. Press Ctrl+C to stop.

## Task 2: handshake

```bash
python3 handshake.py
```

Runs the gateway/node handshake in-process and derives the session keys.

## Task 3: record layer

```bash
python3 secure_record.py
```

Runs a handshake, then sends one record gateway → node and one node → gateway, printing the decrypted plaintexts.

## Task 4: tests

```bash
python3 -m pytest -v
```

- `tests/test_records.py`: valid bidirectional messages, modified ciphertext/tag, modified header fields, truncated records, replayed and reordered records, reflected records, and channel state after a failure.
- `tests/test_handshake.py`: invalid RSA-PSS signature, wrong RSA public key, reflected signature, reflected handshake message, unexpected peer identity, malformed transcripts, and checks of the Task 2 requirements (fresh DH values and nonces, signing keys, DH value validation, KDF labels).

Each failure test asserts the specific error that is raised.
