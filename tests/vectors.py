def test_basic_seal_and_chain(fixed_time, fixed_nonce, keys):
    auth_sk = keys["auth_sk"]
    exec_sk = keys["exec_sk"]

    seal = make_seal(auth_sk, "1:do;2:work")
    
    chain = EchoChain(seal)
    chain.add_step(exec_sk, "1:do", b"\x00")
    chain_bytes = chain.finalize(b"output")

    # ADD THESE 2 LINES
    print("\nSEAL:", seal.hex())
    print("CHAIN:", chain_bytes.hex())
    # END ADD

    assert len(seal) == 200
    assert len(chain_bytes) == 198
    assert registry_verify(seal, chain_bytes, keys["auth_pk"], keys["exec_pk"]) is True