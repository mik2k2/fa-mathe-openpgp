"""OpenPGP CFB mode for AES (don't actually use this)"""
from . import aes_ll2

BLOCK_SIZE = 16


def seq_xor(seq_a, seq_b):
    return [a ^ b for a, b in zip(seq_a, seq_b)]


def encrypt(data, key, resync):
    def single_step(plaintext):
        temp = aes_ll2.encrypt_block(ciphertexts[-1], key)
        ciphertexts.append(seq_xor(temp, plaintext))

    ciphertexts = [bytes(BLOCK_SIZE)]
    if resync:
        single_step(data[:BLOCK_SIZE])
        single_step(data[BLOCK_SIZE:BLOCK_SIZE+2])
        ciphertexts = [None, ciphertexts[1][:2], ciphertexts[1][2:] + ciphertexts[2]]
        initial = BLOCK_SIZE + 2
    else:
        initial = 0

    for i in range(initial, len(data), BLOCK_SIZE):
        assert len(b''.join(map(bytes, ciphertexts[1:]))) == i
        single_step(data[i:i+BLOCK_SIZE])
    del ciphertexts[0]
    return b''.join(map(bytes, ciphertexts))


def decrypt(data, key, resync):
    def single_step(ciphertext):
        nonlocal last_ciphertext
        temp = aes_ll2.encrypt_block(last_ciphertext, key)
        last_ciphertext = ciphertext
        plaintexts.append(seq_xor(ciphertext, temp))

    plaintexts = []
    last_ciphertext = bytes(BLOCK_SIZE)
    if resync:
        single_step(data[:BLOCK_SIZE])
        pre_ciphertext = last_ciphertext
        single_step(data[BLOCK_SIZE:BLOCK_SIZE+2])
        last_ciphertext = pre_ciphertext[2:] + last_ciphertext
        initial = BLOCK_SIZE + 2
    else:
        initial = 0

    for i in range(initial, len(data), BLOCK_SIZE):
        assert len(b''.join(map(bytes, plaintexts))) == i
        single_step(data[i:i+BLOCK_SIZE])
    return b''.join(map(bytes, plaintexts))
