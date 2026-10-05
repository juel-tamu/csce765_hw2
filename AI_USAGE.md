# AI Usage

AI was used for this assignment. Details listed below.

## Entry 1 — Claude Code

**Tool/model and date:** Claude Code (Claude Opus 5.5, Anthropic), October 1–4, 2026

**Purpose:** Understanding the assignment, explaining concepts, outlining the code structure for Tasks 1–3, reviewing my code, and writing the Task 4 tests.

**AI Conversation Log file:** `AI_LOGS.md`

**What I used:**

- Explanations of Task 1 (CTR malleability, the XOR relation, replay), Task 2 (canonical length-prefixed transcript, role-tagged RSA-PSS signatures, reflection, the KDF), and Task 3 (per-direction record state, the order of checks in `open_record`).
- Outlines and partial code snippets, using them as a reference.
- The Task 4 test suite (`tests/conftest.py`, `tests/test_records.py`, `tests/test_handshake.py`) was written by the AI against my code. I reviewed each test.
- `README.md` was drafted by the AI from my code.

**What I changed:**

- Almost all of the code was hand-written aside from the tests, I mostly utilized AI for understanding the instructions and give me hints on how to continue when I was stuck.

**How I tested it:**

- Ran `python -m pytest -v` from the main directory. The tests cover valid bidirectional messaging, modified ciphertext and tags, modified header fields, replayed and reordered records, reflected records, invalid and reflected signatures, a wrong RSA public key, a reflected handshake message, an unexpected peer identity, and malformed transcripts.
- Checked that every failure case raises a specific error and leaves the receiver's sequence number unchanged.

**One error, limitation, or rejected suggestion:**

- One of the AI's tests initially expected the wrong error message for a transcript with an over-long declared length (`"Malformed transcript"` instead of `"Incorrectly declared length"`). My code was correct, and the test was fixed.
- I didn't agree with most of the code when I asked for minor code snippets so I used those as a reference and rewrote the code myself once I understood the problem.
