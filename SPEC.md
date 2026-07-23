# Echo Protocol Specification v0.1.0

**Conservation of Intent Across Independent Agents**

**Status:**: Draft Specification
**Version:**: 0.1.0
**Published:**: 23 July 2026
**Author**: *Stephen Okotume*

Copyright © 2026 Stephen Okotume

This specification is licensed under the
Creative Commons Attribution 4.0 International License (CC BY 4.0).

See `SPEC-LICENSE` for details.

---

# Abstract

Echo Protocol is an open cryptographic protocol for preserving the integrity of delegated execution across independent systems.

The protocol enables one entity (the **Authority**) to define and authorize a rule, another entity (the **Executor**) to produce a verifiable execution record, and an independent verifier (the **Registry**) to determine whether the resulting output faithfully reflects the original authorization.

Echo Protocol achieves this through three cryptographically linked artifacts: the **Authority Seal**, the **Echo Chain**, and the **Output Seal**. Together, these provide deterministic, tamper-evident proof that an accepted result originated from an authorized rule, followed the recorded execution path, and has not been modified.

The protocol is intentionally content-agnostic, implementation-independent, and suitable for offline verification.

---

# Status of This Specification

This document defines **Echo Protocol Specification v0.1.0**.

Version 0.1.0 is the initial public draft intended for reference implementations, interoperability testing, and community review. Future versions may introduce clarifications, extensions, or additional protocol features while preserving compatibility where practical.

This specification is published as an open standard proposal. It is not currently affiliated with or endorsed by any standards organization.

---

# 1. Introduction

Modern software increasingly relies on autonomous systems and AI agents to perform work on behalf of users and organizations. As execution becomes distributed across multiple services and environments, verifying that the original intent has been faithfully preserved becomes increasingly difficult.

Traditional approaches rely on trust in the executing system, application logs, or post-hoc auditing. These methods may be insufficient in adversarial environments or where deterministic verification is required.

Echo Protocol addresses this problem by separating authorization, execution, and verification into three independent roles linked through cryptographic proofs.

An Authority authorizes a Rule by issuing an Authority Seal. An Executor performs work while producing an immutable Echo Chain. A Registry independently verifies that the execution conforms to the authorized rule before accepting the resulting output.

The protocol does not prescribe how work is performed. Instead, it provides a deterministic method for proving that recorded execution corresponds to an authorized intent.

Echo Protocol is designed around the following principles:

* **Attested Conservation** — Output remains cryptographically linked to the original authorization.
* **Deterministic Verification** — Validation is based entirely on cryptographic evidence and produces a binary result.
* **Tamper Evidence** — Any modification to protocol artifacts invalidates verification.
* **Content Agnosticism** — Rules and evidence are treated as opaque data.
* **Implementation Independence** — Compatible implementations may be written in any programming language or execution environment.
* **Offline Verification** — Verification requires no network connectivity after protocol artifacts have been obtained.

---

# 2. Terminology

### Authority

The entity responsible for defining a Rule and issuing an Authority Seal.

### Executor

The entity responsible for executing an authorized Rule and producing an Echo Chain.

### Registry

An independent verifier responsible for determining whether submitted protocol artifacts satisfy this specification.

### Rule

A canonical representation of the intended execution process.

### Authority Seal

A signed and immutable authorization describing a Rule.

### Echo Chain

An append-only sequence of cryptographically linked execution attestations.

### Output Seal

A cryptographic digest binding the final output to both the Authority Seal and the completed Echo Chain.

### Attested Conservation

The property that accepted output is demonstrably authorized, correctly executed, and unmodified.

---

# 3. Message Formats

Unless otherwise specified:

* All integers are encoded as big-endian.
* All text is UTF-8 encoded and normalized using Unicode NFKC.
* All CBOR maps MUST use canonical encoding.

---

## 3.1 Authority Seal

```
Seal = Header || Payload || Signature
```

### Header

```
VersionMajor (1)
VersionMinor (1)
VersionPatch (1)
PayloadLength (uint24)
```

### Payload

```
AuthorityID      (32)
SealID           (32)
Timestamp        (uint64, milliseconds)
Expiry           (uint64, milliseconds, 0 = no expiry)
RuleHash         (32)
ConstraintsLen   (uint16)
Constraints      (Canonical CBOR)
Nonce            (16)
```

### Signature

```
Ed25519(Header || Payload)
```

The serialized Authority Seal occupies **200 bytes** when no constraints are present.

---

## 3.2 Echo Chain

```
Chain =
    SealRef
    StepCount
    Step[0..n-1]
    OutputSeal
```

### Step Structure (132 bytes)

```
PrevHash      (32)
StepIndex     (uint32)
StepHash      (32)
Attestation   (64)
```

The following rules apply:

* `PrevHash` of the first step **MUST** be 32 zero bytes.
* Every subsequent `PrevHash` **MUST** equal `SHA256(previous step)`.
* `StepHash = SHA256(StepDescriptionUTF8 || Evidence)`
* `Attestation = Ed25519(PrevHash || StepIndex || StepHash)`
* `OutputSeal = SHA256(SealRef || LastPrevHash || SHA256(OutputData))`

---

## 3.3 Constraint Registry

Unknown constraint identifiers **MUST** be ignored.

| Key | Type   | Meaning                                    |
| --: | ------ | ------------------------------------------ |
|   1 | uint   | Maximum permitted execution steps          |
|   2 | uint64 | Expiration time (milliseconds since epoch) |
|   4 | bool   | Evidence is required for every step        |

Constraints MUST be serialized using canonical CBOR:

```python
cbor2.dumps(constraints, canonical=True)
```

---

## 3.4 Canonical Rule Representation

Rules are normalized before hashing.

The canonicalization algorithm is:

1. Apply Unicode NFKC normalization.
2. Split the rule on `;`.
3. Trim surrounding whitespace.
4. Convert each step to lowercase.
5. Remove empty entries.
6. Sort all steps lexicographically.
7. Join using `;`.

Every compliant implementation **MUST** produce identical canonical output.

---

# 4. Registry Verification

A Registry validating an Authority Seal and Echo Chain **MUST** perform the following checks. Any failure results in **REJECT**.

---

## 4.1 Verify Authority Seal

1. Parse the header.
2. Verify the protocol version is `1.1.1`.
3. Construct the signed payload as `Header || Payload`.
4. Verify the Ed25519 signature using the Authority public key.
5. Parse the payload.
6. If `Expiry != 0` and the current time exceeds the expiry timestamp, reject the Seal.

---

## 4.2 Verify Echo Chain

1. Compute `SealRef = SHA256(Seal)`.

2. Verify that the first 32 bytes of the chain equal `SealRef`.

3. Read `StepCount`.

4. If a maximum step constraint exists and `StepCount` exceeds that value, reject.

5. Initialize `PrevHash` as 32 zero bytes.

6. For each step:

   * Verify `Step.PrevHash == PrevHash`.
   * Verify the Executor signature.
   * Compute `PrevHash = SHA256(CurrentStep)`.

7. Verify

```
OutputSeal ==
SHA256(
    SealRef ||
    PrevHash ||
    SHA256(OutputData)
)
```

---

## 4.3 Verification Result

If every validation succeeds, the Registry returns

```
VERIFIED
```

Otherwise, it returns

```
REJECTED: <reason>
```

where `<reason>` identifies the first validation failure encountered.

---

# 5. Security Considerations

## Authority Key Compromise

Compromise of an Authority private key permits unauthorized issuance of valid Authority Seals.

## Replay Protection

Seal identifiers incorporate both a nonce and timestamp to reduce replay risk across independent executions.

## Deterministic Encoding

Canonical serialization is mandatory. Any deviation from the specified encoding rules will produce incompatible hashes and invalidate verification.

## Agent Independence

Protocol security does not depend on trusting the Executor. Verification relies exclusively on cryptographic signatures, canonical encoding, and hash integrity.

---

# 6. IANA Considerations

This specification defines no protocol numbers, registries, media types, or other IANA-managed values.

---

# Appendix A — Compliance Test Vectors (v0.1.0)

The following fixed values are used for interoperability testing.

### Authority Private Key

```
0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
```

### Executor Private Key

```
a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0
```

### Fixed Timestamp

```
1717200000000
```

### Fixed Nonce

```
11223344556677889900aabbccddeeff
```

### Test Vector 1

**Authority Seal**

```
010100c879b5562e8fe654f94078b112e8a98ba7901d4622ad4b8bfb7ee198b2290dca94...
```

**Echo Chain**

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855...
```

A compliant implementation **MUST** produce byte-for-byte identical output when given these fixed inputs.
