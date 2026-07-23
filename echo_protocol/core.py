import hashlib
import secrets
import struct
import time
import unicodedata
from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, Optional

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# # --- Protocol constants ---
# HEADER_VERSION = b"\x01\x01"
# HEADER_LEN = 5
# SIG_LEN = 64
# HASH_LEN = 32
# STEP_LEN = 132 # 32 prev_hash + 4 idx + 32 step_hash + 64 signature
# NONCE_LEN = 16

# --- Protocol constants ---
HEADER_VERSION = b"\x01\x01"
HEADER_LEN = 5
SIG_LEN = 64
HASH_LEN = 32
STEP_LEN = 132
NONCE_LEN = 16
PAYLOAD_FIXED_LEN = 133 # 200 - 5 - 64
SEAL_LEN = 200

class Constraint(IntEnum):
    """Constraint keys used inside the CBOR constraints map.
    Using IntEnum keeps the wire format as small ints but makes code readable."""
    MAX_STEPS = 1
    EVIDENCE_REQUIRED = 4

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def canonicalize_rule(rule: str) -> bytes:
    """
    Turn a human rule into a canonical byte string.
    Rules are case-insensitive, order-insensitive, and unicode-normalized.
    "a;b;c" == "C ; b; A"
    """
    rule = unicodedata.normalize("NFKC", rule)
    steps = [s.strip().lower() for s in rule.split(";") if s.strip()]
    steps.sort()
    return ";".join(steps).encode("utf-8")

def hash_rule(rule: str) -> bytes:
    return sha256(canonicalize_rule(rule))

def encode_constraints(constraints: Dict[Constraint, object]) -> bytes:
    """Deterministic CBOR so the same dict always hashes the same."""
    # CBOR canonical=True sorts map keys
    return cbor2.dumps(dict(constraints), canonical=True)

def decode_constraints(data: bytes) -> Dict[Constraint, object]:
    raw = cbor2.loads(data)
    # cast int keys back to Constraint enum for type safety
    return {Constraint(k): v for k, v in raw.items()}

@dataclass(frozen=True)
class Seal:
    """In-memory representation of a verified seal payload."""
    authority_id: bytes
    seal_id: bytes
    timestamp_ms: int
    expiry_ms: int
    rule_hash: bytes
    constraints: Dict[Constraint, object]
    nonce: bytes

def _parse_seal_payload(payload: bytes) -> Seal:
    """Parse payload bytes into a Seal. Raises ValueError if malformed."""
    ptr = 0
    authority_id = payload[ptr:ptr+HASH_LEN]; ptr += HASH_LEN
    seal_id = payload[ptr:ptr+HASH_LEN]; ptr += HASH_LEN
    timestamp_ms = struct.unpack(">Q", payload[ptr:ptr+8])[0]; ptr += 8
    expiry_ms = struct.unpack(">Q", payload[ptr:ptr+8])[0]; ptr += 8
    rule_hash = payload[ptr:ptr+HASH_LEN]; ptr += HASH_LEN

    c_len = int.from_bytes(payload[ptr:ptr+2], "big"); ptr += 2
    c_bytes = payload[ptr:ptr+c_len]; ptr += c_len
    constraints = decode_constraints(c_bytes)

    nonce = payload[ptr:ptr+NONCE_LEN]
    return Seal(authority_id, seal_id, timestamp_ms, expiry_ms, rule_hash, constraints, nonce)


def _split_seal(seal: bytes) -> tuple[bytes, bytes, bytes]:
    if len(seal) != SEAL_LEN:
        raise ValueError(f"Seal must be {SEAL_LEN} bytes, got {len(seal)}")

    header = seal[:HEADER_LEN]
    if header[:2] != HEADER_VERSION:
        raise ValueError("Bad header version")

    payload_len = int.from_bytes(header[2:5], "big")
    payload_end = HEADER_LEN + payload_len
    payload_with_pad = seal[HEADER_LEN:payload_end]
    signature = seal[payload_end:payload_end + SIG_LEN]

    # Strip trailing 0x00 before hashing/sig verify
    payload = payload_with_pad.rstrip(b'\x00')
    return header, payload, signature

# def _split_seal(seal: bytes) -> tuple[bytes, bytes, bytes]:
#     """Return header, payload, signature. Validates lengths."""
#     if len(seal) < HEADER_LEN + SIG_LEN:
#         raise ValueError("Seal too short")

#     header = seal[:HEADER_LEN]
#     payload_len = int.from_bytes(header[3:6], "big")

#     payload_end = HEADER_LEN + payload_len

#     if len(seal) < payload_end + SIG_LEN:
#         raise ValueError("Seal truncated")

#     payload = seal[HEADER_LEN:payload_end]
#     signature = seal[payload_end:payload_end+SIG_LEN]
#     return header, payload, signature

def verify_seal(seal: bytes, authority_pk: ed25519.Ed25519PublicKey) -> Seal:
    """
    Verify the authority's signature and check expiry.
    Returns the parsed Seal if valid, otherwise raises.
    """
    header, payload, signature = _split_seal(seal)
    authority_pk.verify(signature, header + payload)

    parsed = _parse_seal_payload(payload)

    if parsed.expiry_ms!= 0 and int(time.time() * 1000) > parsed.expiry_ms:
        raise ValueError("Seal has expired")

    return parsed

def create_seal(
    authority_sk: ed25519.Ed25519PrivateKey,
    rule: str,
    constraints: Optional[Dict[Constraint, object]] = None,
    expiry_ms: int = 0
) -> bytes:
    constraints = constraints or {}
    authority_pk = authority_sk.public_key()
    authority_id = sha256(authority_pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    nonce = secrets.token_bytes(NONCE_LEN)
    timestamp_ms = int(time.time() * 1000)

    seal_id = sha256(authority_id + nonce + struct.pack(">Q", timestamp_ms))
    r_hash = hash_rule(rule)
    c_bytes = encode_constraints(constraints)

    payload = (
        authority_id +                          # 32
        seal_id +                               # 32
        struct.pack(">Q", timestamp_ms) +       # 8
        struct.pack(">Q", expiry_ms) +          # 8
        r_hash +                                # 32
        len(c_bytes).to_bytes(2, "big") +       # 2
        c_bytes +                               # var
        nonce                                   # 16
        # = 130 + len(c_bytes) so far
    )

    # PAD TO FIXED 131 BYTES
    if len(payload) > PAYLOAD_FIXED_LEN:
        raise ValueError(f"Payload too large: {len(payload)} > {PAYLOAD_FIXED_LEN}")
    payload = payload + b'\x00' * (PAYLOAD_FIXED_LEN - len(payload))

    payload_len_bytes = len(payload).to_bytes(3, "big") # u24
    header = HEADER_VERSION + payload_len_bytes
    assert len(header) == HEADER_LEN

    signature = authority_sk.sign(header + payload)
    seal = header + payload + signature
    assert len(seal) == SEAL_LEN # 200
    return seal


# def create_seal(
#     authority_sk: ed25519.Ed25519PrivateKey,
#     rule: str,
#     constraints: Optional[Dict[Constraint, object]] = None,
#     expiry_ms: int = 0,
#     nonce: Optional[bytes] = None,
#     timestamp_ms: Optional[int] = None
# ) -> bytes:
#     """Create a new signed seal for a rule."""
#     constraints = constraints or {}
#     nonce = nonce or secrets.token_bytes(NONCE_LEN)
#     timestamp_ms = timestamp_ms or int(time.time() * 1000)
#     authority_pk = authority_sk.public_key()
#     authority_id = sha256(
#         authority_pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
#     )
#     # nonce = secrets.token_bytes(NONCE_LEN)
#     # timestamp_ms = int(time.time() * 1000)
#     seal_id = sha256(authority_id + nonce + struct.pack(">Q", timestamp_ms))

#     r_hash = hash_rule(rule)
#     c_bytes = encode_constraints(constraints)

#     payload = (
#         authority_id +
#         seal_id +
#         struct.pack(">Q", timestamp_ms) +
#         struct.pack(">Q", expiry_ms) +
#         r_hash +
#         len(c_bytes).to_bytes(2, "big") +
#         c_bytes +
#         nonce
#     )

#     header = HEADER_VERSION + len(payload).to_bytes(3, "big")
#     signature = authority_sk.sign(header + payload)

#     return header + payload + signature

class EchoChain:
    """Append-only chain. Each step is signed and chained to the previous."""

    def __init__(self, seal: bytes):
        self.seal_ref = sha256(seal)
        self._steps: list[bytes] = []
        self._prev_hash = b"\x00" * HASH_LEN

    def add_step(self, executor_sk: ed25519.Ed25519PrivateKey, step_desc: str, evidence: bytes):
        """Append a step. Evidence can be anything: hash, log, file bytes."""
        idx = len(self._steps)
        step_hash = sha256(step_desc.encode("utf-8") + evidence)

        to_sign = self._prev_hash + struct.pack(">I", idx) + step_hash
        attestation = executor_sk.sign(to_sign)

        step = self._prev_hash + struct.pack(">I", idx) + step_hash + attestation
        self._steps.append(step)
        self._prev_hash = sha256(step)

    def finalize(self, output_data: bytes) -> bytes:
        """Seal the chain with a final commitment to output_data."""
        output_commit = sha256(output_data)
        output_seal = sha256(self.seal_ref + self._prev_hash + output_commit)

        header = self.seal_ref + len(self._steps).to_bytes(2, "big")
        return header + b"".join(self._steps) + output_seal

def verify_chain(
    seal: bytes,
    chain: bytes,
    authority_pk: ed25519.Ed25519PublicKey,
    executor_pk: ed25519.Ed25519PublicKey
) -> bool:
    """
    Full verification of a chain against a seal.
    Checks: signature, expiry, linkage, per-step signatures, and constraints.
    """
    parsed_seal = verify_seal(seal, authority_pk)
    seal_ref = sha256(seal)

    if chain[:HASH_LEN]!= seal_ref:
        raise ValueError("Chain does not reference this seal")

    step_count = int.from_bytes(chain[HASH_LEN:HASH_LEN+2], "big")

    # Enforce constraints
    max_steps = parsed_seal.constraints.get(Constraint.MAX_STEPS)
    if max_steps is not None and step_count > max_steps:
        raise ValueError(f"Max steps exceeded: {step_count} > {max_steps}")

    ptr = HASH_LEN + 2
    prev_hash = b"\x00" * HASH_LEN

    for i in range(step_count):
        step = chain[ptr:ptr+STEP_LEN]
        if len(step)!= STEP_LEN:
            raise ValueError(f"Step {i} is truncated")
        ptr += STEP_LEN

        p_hash = step[0:HASH_LEN]
        idx = struct.unpack(">I", step[HASH_LEN:HASH_LEN+4])[0]
        s_hash = step[HASH_LEN+4:HASH_LEN+4+HASH_LEN]
        att = step[HASH_LEN+4+HASH_LEN:]

        if p_hash!= prev_hash:
            raise ValueError(f"Step {i} breaks chain link")
        if idx!= i:
            raise ValueError(f"Step {i} has wrong index")

        executor_pk.verify(att, p_hash + struct.pack(">I", idx) + s_hash)
        prev_hash = sha256(step)


    if parsed_seal.constraints.get(Constraint.EVIDENCE_REQUIRED):
        # TODO: parse evidence type from step_hash and ensure!= 0x00
        pass

    return True