import time
import secrets
from cryptography.hazmat.primitives.asymmetric import ed25519

from echo_protocol.core import create_seal, EchoChain, sha256, Constraint


# --- SPEC FROZEN VALUES ---
FIXED_SK_AUTH = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)

FIXED_SK_EXEC = bytes.fromhex(
    "202122232425262728292a2b2c2d2e2f"
    "303132333435363738393a3b3c3d3e3f"
)

# Unix timestamp in milliseconds
FIXED_TIME_MS = 1717200000000  # 2024-06-01T00:00:00Z

# Spec: 16-byte nonce
FIXED_NONCE = b"\x11" * 16

# Canonical rule
RULE = "1:collect;2:analyze;3:report"


# --- Deterministic environment ---
time.time = lambda: FIXED_TIME_MS / 1000.0
secrets.token_bytes = lambda n: FIXED_NONCE[:n]


auth_sk = ed25519.Ed25519PrivateKey.from_private_bytes(FIXED_SK_AUTH)
exec_sk = ed25519.Ed25519PrivateKey.from_private_bytes(FIXED_SK_EXEC)


# --- Seal ---
seal = create_seal(
    auth_sk,
    RULE,
    constraints={Constraint.MAX_STEPS: 3},
)

print("FROZEN_SEAL_HEX =")
print(f'"{seal.hex()}"')
print("LEN:", len(seal))


# --- Chain ---
chain = EchoChain(seal)

chain.add_step(
    exec_sk,
    "1:collect",
    b"\x01" + sha256(b"data.csv"),
)

chain.add_step(
    exec_sk,
    "2:analyze",
    b"\x00",
)

chain.add_step(
    exec_sk,
    "3:report",
    b"",
)

chain_bytes = chain.finalize(b"final_report.pdf")

print("\nFROZEN_CHAIN_HEX =")
print(f'"{chain_bytes.hex()}"')
print("LEN:", len(chain_bytes))