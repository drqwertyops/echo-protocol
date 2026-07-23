# README.md

# Echo Protocol

**Reference implementation of the Echo Protocol Specification v0.1**

`Echo-protocol` is the official Python reference implementation of the Echo Protocol. It generates deterministic **Authority Seals** and **Echo Chains** that can be verified by any compliant implementation, regardless of programming language or runtime.

The project is designed as the canonical implementation for developers building compatible clients, libraries, or services.

---

## What is Echo Protocol?

Echo Protocol is a cryptographic framework for **Attested Conservation of Intent** across independent systems.

In simple terms, it allows one party to define *what should happen*, another party to prove *what actually happened*, and a third party to verify that the two match.

The protocol is built around three roles:

* **Authority** — defines the intended rule and signs it.
* **Executor** — performs the work and records an immutable sequence of attestations.
* **Registry** — verifies that the recorded execution matches the original rule.

The protocol is:

* Deterministic
* Offline-first
* Tamper-evident
* Content-agnostic
* Language independent

---

## Installation

```bash
pip install echo-protocol
```

### Requirements

* `cryptography`
* `cbor2`

---

## Command Line Usage

### 1. Generate keys

```bash
echo keygen --out-sk authority.sk --out-pk authority.pk
echo keygen --out-sk executor.sk --out-pk executor.pk
```

---

### 2. Issue an Authority Seal

```bash
echo issue \
  --sk authority.sk \
  --rule "1:collect;2:analyze;3:report" \
  --constraints '{"1":3,"4":true}' \
  --out task.seal
```

This produces a signed, immutable description of the intended workflow.

---

### 3. Record execution

```bash
echo attest \
  --sk executor.sk \
  --seal task.seal \
  --step "1:collect" \
  --evidence data.csv \
  --out work.chain
```

Each attestation extends the Echo Chain with cryptographic proof that a specific step was completed.

---

### 4. Verify the result

```bash
echo verify \
  --seal task.seal \
  --chain work.chain \
  --auth-pk authority.pk \
  --exec-pk executor.pk
```

Expected output:

```text
VERIFIED
```

---

## Python Example

```python
from echo_protocol import make_seal, EchoChain, registry_verify
from cryptography.hazmat.primitives.asymmetric import ed25519

auth_sk = ed25519.Ed25519PrivateKey.generate()
exec_sk = ed25519.Ed25519PrivateKey.generate()

seal = make_seal(
    auth_sk,
    "1:a;2:b",
    constraints={1: 2},
)

chain = EchoChain(seal)

chain.add_step(
    exec_sk,
    "1:a",
    b"evidence",
)

chain_bytes = chain.finalize(b"output")

assert registry_verify(
    seal,
    chain_bytes,
    auth_sk.public_key(),
    exec_sk.public_key(),
)
```

---

## Compliance

This implementation targets **Echo Protocol Specification v0.1.0**.

Run the compliance suite with:

```bash
pip install -e ".[test]"
pytest
```

All frozen test vectors in `tests/test_vectors.py` must pass. These vectors are intended for validating compatible implementations written in Rust, Go, JavaScript, or other languages.

---

## Data Sizes

Approximate serialized sizes:

| Object         | Size                          |
| -------------- | ----------------------------- |
| Authority Seal | 200 bytes + constraints       |
| Echo Chain     | 34 + (132 × steps) + 32 bytes |

---

## Specification

The complete protocol specification is available in `SPEC.md`.

---

## License

The Echo Protocol reference implementation is licensed under the MIT License.

The Echo Protocol Specification (`SPEC.md`) is licensed under
Creative Commons Attribution 4.0 International (CC BY 4.0).

See:
- `LICENSE` for software licensing.
- `SPEC-LICENSE` for specification licensing.
