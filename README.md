# Echo Protocol

**Reference implementation of the Echo Protocol Specification v0.1.0**

`echo-protocol` is the official Python reference implementation of the Echo Protocol Specification. It provides a deterministic implementation for generating and verifying **Authority Seals** and **Echo Chains**, producing byte-for-byte identical protocol artifacts across compliant implementations.

The project serves as the canonical implementation for developers building compatible libraries, applications, and services.

---

## What is Echo Protocol?

Echo Protocol is a cryptographic framework for **Attested Conservation of Intent** across independent systems.

It separates authorization, execution, and verification into independent cryptographic roles, allowing any implementation to verify that work was performed according to an authorized rule without relying on trust in the executing system.

The protocol defines three core roles:

* **Authority** — defines a Rule and authorizes it by issuing an Authority Seal.
* **Executor** — performs the authorized work and records an immutable Echo Chain.
* **Registry** — independently verifies that execution matches the original authorization.

Echo Protocol is designed for AI agents, automation platforms, distributed software systems, and any workflow that requires verifiable preservation of intent.

### Key Properties

* Deterministic
* Deterministic verification
* Offline-first
* Tamper-evident
* Content-agnostic
* Language independent

---

## Why Echo?

As AI systems become more autonomous, work is increasingly delegated across multiple agents, tools, and services. While this makes systems more capable, it also makes it harder to verify that the original intent was preserved throughout execution.

Echo Protocol provides a standardized way to cryptographically prove that delegated work followed an authorized rule. Instead of trusting the execution environment, verification is based entirely on signatures, hashes, and deterministic protocol rules.

The protocol does not attempt to determine whether the work itself is "correct." Its purpose is to prove that the recorded execution faithfully corresponds to an authorized intent.

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

### 1. Generate key pairs

```bash
echo keygen --out-sk authority.sk --out-pk authority.pk
echo keygen --out-sk executor.sk --out-pk executor.pk
```

Generate separate key pairs for the Authority and the Executor.

---

### 2. Issue an Authority Seal

```bash
echo issue \
  --sk authority.sk \
  --rule "1:collect;2:analyze;3:report" \
  --constraints '{"1":3,"4":true}' \
  --out task.seal
```

This creates a signed Authority Seal containing the authorized Rule and any execution constraints.

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

Each invocation appends a signed attestation to the Echo Chain, creating an immutable execution history.

---

### 4. Verify execution

```bash
echo verify \
  --seal task.seal \
  --chain work.chain \
  --auth-pk authority.pk \
  --exec-pk executor.pk
```

Successful verification returns:

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

Run the compliance suite:

```bash
pip install -e ".[test]"
pytest
```

All frozen test vectors in `tests/test_vectors.py` must pass. These vectors are intended for validating compatible implementations in Rust, Go, JavaScript, and other languages.

---

## Serialized Sizes

Approximate serialized sizes for protocol artifacts:

| Artifact       | Size                          |
| -------------- | ----------------------------- |
| Authority Seal | 200 bytes + constraints       |
| Echo Chain     | 34 + (132 × steps) + 32 bytes |

---

## Specification

The complete protocol specification is available in `SPEC.md`.

---

## Roadmap

Current development priorities include:

* ✅ Echo Protocol Specification v0.1.0
* ✅ Python reference implementation
* ⬜ Rust implementation
* ⬜ Cross-language compliance test suite
* ⬜ Echo Protocol v1.0

Contributions, feedback, and independent implementations are welcome.

---

## License

The Echo Protocol reference implementation is licensed under the MIT License.

The Echo Protocol Specification (`SPEC.md`) is licensed under
Creative Commons Attribution 4.0 International (CC BY 4.0).

See:
- `LICENSE` for software licensing.
- `SPEC-LICENSE` for specification licensing.
