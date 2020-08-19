"""RSA PKCS #1"""
import math
import secrets
import itertools
import operator


def find_prime(bitsize, secbits=256):
    rounds = secbits // 2
    while True:
        pot_prime = secrets.randbits(bitsize)
        if miller_rabin(pot_prime, rounds):
            return pot_prime


def miller_rabin(n, k):
    r = 1
    d = (n-1) // 2**r
    for __ in range(k):
        a = secrets.randbelow(n-2)
        x = pow(a, d, n)
        if x in (1, n-1):
            continue
        for __ in range(r-1):
            x = pow(x, 2, n)
            if x == n-1:
                continue
        return False
    return True


def generate_key(prime_bits):
    p, q = find_prime(prime_bits+5), find_prime(prime_bits-5)
    n = p*q
    e = 65537

    lambda_n = least_common_multiple(p-1, q-1)
    assert e < lambda_n and greatest_common_divisor(e, lambda_n) == 1
    __, d, __ = extended_euclid(e, lambda_n)
    if d < 0:
        d += lambda_n
    assert d*e % lambda_n == 1
    assert d > 0

    return (d, n), (e, n)


def basic_crypt(key, text):
    assert 0 <= text < key[1] - 1
    return pow(text, *key)


def crypt_bytes(key, text):
    return (basic_crypt(key, int.from_bytes(text, 'big'))
            .to_bytes(math.ceil(key[1].bit_length() / 8), 'big'))


def xor_bytes(a_bytes, b_bytes):
    return bytes(a ^ b for a, b in zip(a_bytes, b_bytes))


def rsaes_oaep_encrypt(key, message, label=b'', *, hash_func):
    mod_length = math.ceil(key[1].bit_length() / 8)
    encoded = eme_oaep_encode(message, label, hash_func, mod_length)
    return crypt_bytes(key, encoded)


def rsaes_oaep_decrypt(key, message, label=b'', *, hash_func):
    mod_length = math.ceil(math.log2(key[1]) / 8)
    decrypted = crypt_bytes(key, message)
    return eme_oaep_decode(decrypted, label, hash_func, mod_length)


def eme_oaep_encode(message, label, hash_func, mod_length):
    label_hash = hash_func(label)
    len_hash = len(label_hash)
    data_block = b''.join((
        label_hash,
        bytes(mod_length - len(message) - 2*len_hash - 2),
        b'\x01',
        message
    ))
    seed = secrets.token_bytes(len_hash)
    db_masked = xor_bytes(data_block, mask_gen(hash_func, seed, mod_length - len_hash - 1))
    seed_masked = xor_bytes(seed, mask_gen(hash_func, db_masked, len_hash))
    return b''.join((b'\x00', seed_masked, db_masked))


def eme_oaep_decode(message, label, hash_func, mod_length):
    label_hash = hash_func(label)
    len_hash = len(label_hash)
    message = message[1:]
    seed_masked = message[:len_hash]
    db_masked = message[len_hash:]
    seed = xor_bytes(seed_masked, mask_gen(hash_func, db_masked, len_hash))
    data_block = xor_bytes(db_masked, mask_gen(hash_func, seed, mod_length - len_hash - 1))
    return bytes(itertools.dropwhile(operator.not_, data_block[len_hash:]))[1:]


def mask_gen(hash_func, seed, mask_len):
    return b''.join(hash_func(seed + i.to_bytes(4, 'big'))
                    for i in range(math.ceil(mask_len / len(hash_func(b''))))
                    )[:mask_len]


def rsaes_pkcs1_v1_5_encrypt(key, message):
    mod_length = math.ceil(math.log2(key[1]) / 8)
    encoded = eme_pkcs1_v1_5_encode(message, mod_length)
    return crypt_bytes(key, encoded)


def rsaes_pkcs1_v1_5_decrypt(key, message):
    decrypted = crypt_bytes(key, message)
    return eme_pkcs1_v1_5_decode(decrypted)


def eme_pkcs1_v1_5_encode(message, mod_length):
    infinite_bytes = (f() for f in itertools.cycle([lambda: secrets.randbelow(256)]))
    random_nonzero, __ = zip(*zip(filter(int, infinite_bytes), range(mod_length - len(message) - 3)))
    return b''.join((b'\x00\x02', bytes(random_nonzero), b'\x00', message))


def eme_pkcs1_v1_5_decode(message):
    return bytes(itertools.dropwhile(int, message[2:]))[1:]


def rsassa_pss_sign(message, key):
    mod_length = math.ceil(key[1].bit_length() / 8)
    encoded = emsa_pss_encode(message, mod_length)
    return crypt_bytes(key, encoded)


def rsassa_pss_verify(signature, message, key):
    mod_length = math.ceil(key[1].bit_length() / 8)
    decrypted = crypt_bytes(key, signature)
    return emsa_pss_verify(decrypted, message, key)


def emsa_pkcs1_v1_5(message_hash, out_length):
    return b''.join((
        b'\x00\x01',
        bytes([0xff]*(out_length-len(message_hash)-3)),
        b'\x00',
        message_hash,
    ))


def rsassa_pkcs1_v1_5_sign(message_hash, key):
    encoded = emsa_pkcs1_v1_5(message_hash, math.ceil(key[1].bit_length() / 8))
    return crypt_bytes(key, encoded)


def rsassa_pkcs1_v1_5_verify(message_hash, signature, key):
    encoded = emsa_pkcs1_v1_5(message_hash, math.ceil(key[1].bit_length() / 8))
    return encoded == crypt_bytes(key, signature)


def least_common_multiple(a, b):
    return a*b // greatest_common_divisor(a, b)


def greatest_common_divisor(a, b):
    while True:
        if a == 0:
            return b
        elif b == 0:
            return a
        elif a > b:
            a %= b
        elif b > a:
            b %= a


def extended_euclid(a, b):
    """implement the extended Euclidean algorithm"""
    r_old = a
    s_old = 1
    t_old = 0
    r_new = b
    s_new = 0
    t_new = 1
    while r_new:
        r_old, (q, r_new) = r_new, divmod(r_old, r_new)
        s_old, s_new = s_new, s_old - q*s_new
        t_old, t_new = t_new, t_old - q*t_new
    return r_old, s_old, t_old
