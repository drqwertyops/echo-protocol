import pytest
import struct
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from echo_protocol.core import (
    create_seal, EchoChain, verify_chain,
    Constraint, sha256
)

# --- FROZEN VALUES FOR v0.1.0 ---
# If any of these change, CI must fail. This is the compliance gate.

FIXED_SK_AUTH = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
FIXED_SK_EXEC = bytes.fromhex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
FIXED_TIME_MS = 1717200000000 # 2024-06-01T00:00:00Z
FIXED_NONCE = bytes.fromhex("11111111111111111111111111111111")
RULE = "1:collect;2:analyze;3:report"

# Precomputed frozen bytes. Generated once with the fixed inputs above
FROZEN_SEAL_HEX = "010100007f56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c4f8b917f32bce1b613355673ea40cd68d3b7fefef90db7698e49c012739cb3770000018fd11894000000000000000000ac1e09f32f912c626e29bba3731d5a11848567bb5e2c8b7461727267ca1198390003a10103111111111111111111118cb90be1eb5b5defb2692592df078ee790208df9213eb89411a14039012f75ab0f400579065d63e736e7bbff5a406d01684f53460c352472f5485adbee6ec901"



FROZEN_CHAIN_HEX = "1e00f2b43407112690ab6a9ba2f8fc0eb390857dce0c0ad160ea1592c1485e1500030000000000000000000000000000000000000000000000000000000000000000000000001bf509ab74e8164c34a7bd1a464038daeecd085fea5ce58c12b624a4f01c4e5eadbe004468c9f780d4deec69c4da1d475d69ea4ed57633ac0b664a09b289a3eba7d60b677b6c3a376f16d908a1932c9e26fc9c0a132bae2f4a86fa5a8d29c9090c3b93d618b12909bbfe7995cc18e2cb6eddbde81ceb5deb440f48860c9f782c000000013f2e8cda8fc729568198133a6ee84738f76e896f792bbd33377be1d617ab191f80e54a5a1a16514572cfa617dac396778df66a5df7813aa27debc5edcbdaf20023587516e3ac2dbfa2db5c8a129ce39bf2ff5858d96daeb787fe2aa74ee30d0ebb758175b6fe5071e2e107fac9498c08d53fd594cf25c671a9b738c5f90a756b00000002bb555a66c26afaf3ff7bcc1e294cc23b46da286c5eac6fd33ce8698b16853bf66047627fd586b0872245c05a2a8ce2e2cbeed81f0a293dfda11191f06a7eb6bf2460a2291116f4ad2a68375739ebd98c2137a8166642065108cb7dd786870905d39f633d0ab2abaff7781e955c6250dbeffbf3738207010b90a537f56ff69035"

     

def _monkeypatch_time_and_secrets(monkeypatch):
    """Freeze time and nonce so output is deterministic"""
    monkeypatch.setattr(time, "time", lambda: FIXED_TIME_MS / 1000.0)
    monkeypatch.setattr("echo_protocol.core.secrets.token_bytes", lambda n: FIXED_NONCE[:n])

def test_vector_1_seal_is_frozen(monkeypatch):
    """Vector 1: Authority issues seal. Must match bytes exactly."""
    _monkeypatch_time_and_secrets(monkeypatch)
    auth_sk = ed25519.Ed25519PrivateKey.from_private_bytes(FIXED_SK_AUTH)

    seal = create_seal(auth_sk, RULE, constraints={Constraint.MAX_STEPS: 3})

    assert seal.hex() == FROZEN_SEAL_HEX
    assert len(seal) == 200

def test_vector_2_chain_3_steps_is_frozen(monkeypatch):
    """Vector 2: Executor builds 3-step chain. Must match bytes exactly."""
    _monkeypatch_time_and_secrets(monkeypatch)
    auth_sk = ed25519.Ed25519PrivateKey.from_private_bytes(FIXED_SK_AUTH)
    exec_sk = ed25519.Ed25519PrivateKey.from_private_bytes(FIXED_SK_EXEC)

    seal = create_seal(auth_sk, RULE, constraints={Constraint.MAX_STEPS: 3})
    chain = EchoChain(seal)

    chain.add_step(exec_sk, "1:collect", b"\x01" + sha256(b"data.csv"))
    chain.add_step(exec_sk, "2:analyze", b"\x00")
    chain.add_step(exec_sk, "3:report", b"")

    chain_bytes = chain.finalize(b"final_report.pdf")
    assert chain_bytes.hex() == FROZEN_CHAIN_HEX
    assert len(chain_bytes) == 32 + 2 + 132*3 + 32 # 430

def test_vector_3_verify_passes():
    """Vector 3: Registry verifies valid seal+chain"""
    auth_sk = ed25519.Ed25519PrivateKey.from_private_bytes(FIXED_SK_AUTH)
    exec_sk = ed25519.Ed25519PrivateKey.from_private_bytes(FIXED_SK_EXEC)
    auth_pk = auth_sk.public_key()
    exec_pk = exec_sk.public_key()

    seal = bytes.fromhex(FROZEN_SEAL_HEX)
    chain = bytes.fromhex(FROZEN_CHAIN_HEX)

    assert verify_chain(seal, chain, auth_pk, exec_pk) is True

def test_vector_4_max_steps_constraint():
    """Vector 4: Adding 4th step with MAX_STEPS=3 must fail"""
    auth_sk = ed25519.Ed25519PrivateKey.from_private_bytes(FIXED_SK_AUTH)
    exec_sk = ed25519.Ed25519PrivateKey.from_private_bytes(FIXED_SK_EXEC)

    seal = create_seal(auth_sk, RULE, constraints={Constraint.MAX_STEPS: 3})
    chain = EchoChain(seal)
    for i in range(3): chain.add_step(exec_sk, f"{i}:x", b"")
    chain.add_step(exec_sk, "3:x", b"") # 4th step

    with pytest.raises(ValueError, match="Max steps exceeded"):
        verify_chain(seal, chain.finalize(b""), auth_sk.public_key(), exec_sk.public_key())

def test_vector_5_bad_signature_fails():
    """Vector 5: Tampering 1 byte in chain must fail"""
    auth_sk = ed25519.Ed25519PrivateKey.from_private_bytes(FIXED_SK_AUTH)
    exec_sk = ed25519.Ed25519PrivateKey.from_private_bytes(FIXED_SK_EXEC)

    seal = bytes.fromhex(FROZEN_SEAL_HEX)
    chain = bytearray(bytes.fromhex(FROZEN_CHAIN_HEX))
    chain[100] ^= 0x01 # flip 1 bit

    with pytest.raises(Exception): # signature verify will fail
        verify_chain(seal, bytes(chain), auth_sk.public_key(), exec_sk.public_key())