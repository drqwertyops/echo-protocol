import argparse
import base64
import logging
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from .core import create_seal, EchoChain, verify_seal, verify_chain

LOG = logging.getLogger("echo")
KEY_LEN = 32

def load_key(path: Path, private: bool = True):
    if not path.exists():
        raise FileNotFoundError(f"Key not found: {path}")
    data = path.read_bytes()
    if len(data)!= KEY_LEN:
        raise ValueError(f"Bad key length {len(data)} for {path}")
    return (
        ed25519.Ed25519PrivateKey.from_private_bytes(data) if private
        else ed25519.Ed25519PublicKey.from_public_bytes(data)
    )

def cmd_keygen(args):
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()

    sk_bytes = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pk_bytes = pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    args.out_sk.write_bytes(sk_bytes)
    args.out_pk.write_bytes(pk_bytes)
    print(f"KEYS_WRITTEN sk={args.out_sk} pk={args.out_pk}")
    print(f"SK_B64={base64.b64encode(sk_bytes).decode()}")
    print(f"PK_B64={base64.b64encode(pk_bytes).decode()}")
    return 0

def cmd_issue(args):
    sk = load_key(args.sk, private=True)
    seal = create_seal(sk, args.rule) # FIXED: was make_seal
    args.out.write_bytes(seal)
    print(f"SEAL_WRITTEN path={args.out} bytes={len(seal)}")
    return 0

def cmd_attest(args):
    sk = load_key(args.sk, private=True)
    seal_bytes = args.seal.read_bytes()

    auth_pk = load_key(args.auth_pk, private=False)
    verify_seal(seal_bytes, auth_pk)

    evidence = args.evidence.read_bytes() if args.evidence else b""

    if args.out.exists():
        # NOTE: your EchoChain doesn't have from_bytes yet. So we start new.
        # If you need resume, we can add it later
        chain = EchoChain(seal_bytes)
    else:
        chain = EchoChain(seal_bytes)

    chain.add_step(sk, args.step, evidence)
    args.out.write_bytes(chain.finalize(b""))
    print(f"CHAIN_UPDATED path={args.out} step={args.step}")
    return 0

def cmd_verify(args):
    seal_bytes = args.seal.read_bytes()
    chain_bytes = args.chain.read_bytes()
    auth_pk = load_key(args.auth_pk, private=False)
    exec_pk = load_key(args.exec_pk, private=False)

    try: # FIXED: was registry_verify
        verify_chain(seal_bytes, chain_bytes, auth_pk, exec_pk)
        print("VERIFIED")
        return 0
    except Exception as e:
        print(f"REJECTED reason={e}")
        return 1

def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    p = argparse.ArgumentParser(prog="echo")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_keygen = sub.add_parser("keygen")
    p_keygen.add_argument("--out-sk", type=Path, required=True)
    p_keygen.add_argument("--out-pk", type=Path, required=True)
    p_keygen.set_defaults(func=cmd_keygen)

    p_issue = sub.add_parser("issue")
    p_issue.add_argument("--sk", type=Path, required=True)
    p_issue.add_argument("--rule", required=True)
    p_issue.add_argument("--out", type=Path, required=True)
    p_issue.set_defaults(func=cmd_issue)

    p_attest = sub.add_parser("attest")
    p_attest.add_argument("--sk", type=Path, required=True)
    p_attest.add_argument("--seal", type=Path, required=True)
    p_attest.add_argument("--auth-pk", type=Path, required=True)
    p_attest.add_argument("--step", required=True)
    p_attest.add_argument("--evidence", type=Path)
    p_attest.add_argument("--out", type=Path, required=True)
    p_attest.set_defaults(func=cmd_attest)

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--seal", type=Path, required=True)
    p_verify.add_argument("--chain", type=Path, required=True)
    p_verify.add_argument("--auth-pk", type=Path, required=True)
    p_verify.add_argument("--exec-pk", type=Path, required=True)
    p_verify.set_defaults(func=cmd_verify)

    args = p.parse_args()
    try:
        return args.func(args)
    except Exception as e:
        LOG.exception("Command failed")
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())